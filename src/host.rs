//! Host daemon: one proxy, a project registry, and the control socket.
//!
//! Real secrets stay in this process. The wrapper receives a plan of decoys
//! and bind paths, and only then starts the agent.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use arkham_compose::{
  RegisterResponse, cgroup_is_confined, decode_request, encode_response, ensure_socket_dir, host_cgroup, peer_uid_allowed, prepare_session,
  project_root, read_cgroup, read_line, read_starttime, release_session, session_cgroup, write_line,
};
use arkham_config::config::ProxyCfg;
use arkham_config::grants::ResolvedConfig;
use arkham_config::require_loopback_listen;
use arkham_pki::ca::{CertAuthority, load_or_generate};
use arkham_proxy::{ProxyState, bind_explicit, serve};
use confique::Config as _;
use eyre::WrapErr as _;
use tokio::io::AsyncReadExt as _;
use tokio::net::{UnixListener, UnixStream};

/// Run the host daemon until the process is stopped.
///
/// # Errors
///
/// Returns an error when the listen address is not loopback, the control
/// socket cannot be bound, or the CA cannot be loaded. Capture failure is
/// logged and does not stop the daemon: the agent still holds decoys only.
pub async fn run(version: &str) -> eyre::Result<()> {
  let proxy = ProxyCfg::builder().env().load().wrap_err("reading the listen address")?;
  require_loopback_listen(proxy.listen)?;
  let socket_path = ensure_socket_dir()?;
  if socket_path.exists() {
    match UnixStream::connect(&socket_path).await {
      Ok(_) => eyre::bail!("host daemon is already running"),
      Err(_) => std::fs::remove_file(&socket_path)?,
    }
  }
  let listener = UnixListener::bind(&socket_path)?;
  std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
  let ca_file = crate::ca_path(&proxy)?;
  let ca = Arc::new(load_or_generate(&ca_file)?);
  let state = Arc::new(ProxyState::new(
    ResolvedConfig {
      proxy: proxy.clone(),
      grants: Vec::new(),
      plugins: Vec::new(),
    },
    &ca,
  )?);
  let registered = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
  let explicit = bind_explicit(proxy.listen).await?;
  let serve_state = Arc::clone(&state);
  tokio::spawn(async move {
    serve(explicit, serve_state).await;
  });
  let capture_state = Arc::clone(&state);
  tokio::spawn(async move {
    match host_cgroup() {
      Ok(cgroup) => {
        if let Err(err) = arkham_ebpf::run_ebpf(capture_state, cgroup, Vec::new(), None).await {
          tracing::error!(%err, "ebpf capture stopped");
        }
      }
      Err(err) => tracing::error!(%err, "ebpf cgroup unavailable"),
    }
  });
  tracing::info!(listen = %proxy.listen, socket = %socket_path.display(), "host daemon ready");
  eprintln!("daemon: ready");
  accept_loop(listener, state, ca, registered, version).await
}

async fn accept_loop(
  listener: UnixListener,
  state: Arc<ProxyState>,
  ca: Arc<CertAuthority>,
  registered: Arc<Mutex<Vec<PathBuf>>>,
  version: &str,
) -> eyre::Result<()> {
  let version = version.to_string();
  loop {
    let (stream, _) = listener.accept().await?;
    let state = Arc::clone(&state);
    let ca = Arc::clone(&ca);
    let registered = Arc::clone(&registered);
    let version = version.clone();
    tokio::spawn(async move {
      if let Err(err) = one_client(stream, &state, &ca, &registered, &version).await {
        tracing::debug!(%err, "session ended");
      }
    });
  }
}

async fn one_client(
  mut stream: UnixStream,
  state: &ProxyState,
  ca: &CertAuthority,
  registered: &Mutex<Vec<PathBuf>>,
  version: &str,
) -> eyre::Result<()> {
  let cred = stream.peer_cred()?;
  // SAFETY: `getuid` takes no arguments and cannot fail.
  let daemon_uid = unsafe { libc::getuid() };
  if !peer_uid_allowed(cred.uid(), daemon_uid) {
    reject(&mut stream, "control client is not the daemon user").await?;
    return Ok(());
  }
  let Some(pid) = cred.pid() else {
    reject(&mut stream, "control peer has no pid").await?;
    return Ok(());
  };
  let Ok(pid) = u32::try_from(pid) else {
    reject(&mut stream, "control peer has no pid").await?;
    return Ok(());
  };
  if pid == 0 {
    reject(&mut stream, "control peer has no pid").await?;
    return Ok(());
  }
  let started = match read_starttime(pid) {
    Ok(value) => value,
    Err(err) => {
      reject_logged(&mut stream, &err, &wrapper_detail(&err)).await?;
      return Ok(());
    }
  };
  let cgroup = match read_cgroup(pid) {
    Ok(path) => path,
    Err(err) => {
      reject_logged(&mut stream, &err, &wrapper_detail(&err)).await?;
      return Ok(());
    }
  };
  if cgroup_is_confined(&cgroup) {
    reject(&mut stream, "a confined process cannot register").await?;
    return Ok(());
  }
  let line = read_line(&mut stream).await?;
  let request = decode_request(&line)?;
  let roots = registered.lock().unwrap_or_else(PoisonError::into_inner).clone();
  let Some(root) = project_root(&request.cwd, &roots) else {
    reject(&mut stream, "no project").await?;
    return Ok(());
  };
  let scratch = session_dir()?.join(format!("{pid}-{started}"));
  std::fs::create_dir_all(&scratch)?;
  let cert = scratch.join("ca.pem");
  std::fs::write(&cert, ca.cert_pem())?;
  let prepared = match prepare_session(&root, &scratch, request.profile, &cert, version).await {
    Ok(prepared) => prepared,
    Err(err) => {
      let _ = std::fs::remove_dir_all(&scratch);
      reject_logged(&mut stream, &err, &wrapper_detail(&err)).await?;
      return Ok(());
    }
  };
  let slot = match session_cgroup(pid, started) {
    Ok(slot) => slot,
    Err(err) => {
      let _ = std::fs::remove_dir_all(&scratch);
      reject_logged(&mut stream, &err, &wrapper_detail(&err)).await?;
      return Ok(());
    }
  };
  if let Err(err) = state.register_project(slot.id, prepared.resolved, ca) {
    release_session(&slot.path);
    let _ = std::fs::remove_dir_all(&scratch);
    reject_logged(&mut stream, &err, REGISTRATION_FAILED).await?;
    return Ok(());
  }
  registered.lock().unwrap_or_else(PoisonError::into_inner).push(root.clone());
  let response = RegisterResponse {
    plan: Some(prepared.plan),
    error: None,
  };
  let bytes = encode_response(&response)?;
  write_line(&mut stream, &bytes).await?;
  let mut byte = [0u8; 1];
  loop {
    match stream.read(&mut byte).await {
      Ok(0) | Err(_) => break,
      Ok(_) => {}
    }
  }
  state.unregister_project(slot.id);
  release_session(&slot.path);
  {
    let mut roots = registered.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(position) = roots.iter().position(|path| path == &root) {
      roots.remove(position);
    }
  }
  let _ = std::fs::remove_dir_all(&scratch);
  Ok(())
}

const REGISTRATION_FAILED: &str = "registration failed";

fn wrapper_detail(err: &arkham_compose::Error) -> String {
  err.registration_detail()
}

async fn reject_logged(stream: &mut UnixStream, err: &impl std::fmt::Debug, detail: &str) -> eyre::Result<()> {
  tracing::error!(error = ?err, "registration failed");
  reject(stream, detail).await
}

async fn reject(stream: &mut UnixStream, detail: impl Into<String>) -> eyre::Result<()> {
  let response = RegisterResponse {
    plan: None,
    error: Some(detail.into()),
  };
  let bytes = encode_response(&response)?;
  write_line(stream, &bytes).await?;
  Ok(())
}

fn session_dir() -> eyre::Result<PathBuf> {
  let sock = ensure_socket_dir()?;
  let Some(parent) = sock.parent() else {
    eyre::bail!("daemon socket has no directory");
  };
  Ok(parent.join("sessions"))
}
