//! `arkham`: grant-scoped MITM proxy.
//!
//! Terminates client TLS with per-domain leaf certificates, swaps
//! format-valid decoy fakes for real secret values only on URI-grant
//! match, and redacts real values back to fakes on responses. Everything
//! else splices through byte-identical.

mod commands;
#[cfg(target_os = "linux")]
mod fwd;
#[cfg(target_os = "linux")]
mod host;

use std::path::{Path, PathBuf};

use arkham_config::cli::{Cli, CliCommand, ProxyBackend};
use arkham_fnox::FnoxSource;
use clap::{Parser, Subcommand};

use arkham_compose::{AgentArgs, DownArgs, ExposeArgs, InitArgs, LogsArgs, UpArgs};
use commands::{CaArgs, ConfigArgs, DaemonArgs, FakeArgs, FwdArgs, RegistryArgs, RulesArgs, SchemesArgs, ServeArgs};

#[derive(Parser, Debug)]
#[command(name = "arkham", about = "grant-scoped MITM proxy", version)]
struct ArkhamCli {
  /// Global flags: the highest-precedence config layer.
  #[command(flatten)]
  globals: Cli,
  /// Subcommand; absent means `serve`.
  #[command(subcommand)]
  command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
  /// Serve the proxy: the explicit listener, plus transparent capture when
  /// `--proxy-backend` selects one.
  Serve(ServeArgs),
  /// Print the deterministic fake for an env var name.
  Fake(FakeArgs),
  /// Print each supported URL scheme, one per line.
  Schemes(SchemesArgs),
  /// Generate (or load) the CA, print its certificate PEM to stdout, and write
  /// the certificate and the key beside the CA file as `ca.crt` and `ca.key`.
  ///
  /// The printed PEM is the trust anchor to install into workload
  /// containers; the private key stays in the CA file and in `ca.key`.
  Ca(CaArgs),
  /// Print what this workspace's proxy substitutes (fnox ∩ registry): derived
  /// rules, names still needing a host, and uncovered fnox declarations.
  Rules(RulesArgs),
  /// Print a reference config: every setting, its default, and the doc
  /// comment explaining it. Load errors surface first, so this doubles as a
  /// config check. Secrets never appear: the template is derived from the
  /// config schema, never from values.
  Config(ConfigArgs),
  /// Curate an `oauth2` registry fragment from a discovery or `OpenAPI`
  /// document. Reads a local file; prints TOML to stdout. Never touches
  /// the bundled registry or runtime config.
  Registry(RegistryArgs),
  /// Generate this workspace's stack as an editable file: a stub workspace
  /// config when it has none (rules derive at serve time), the CA, the agent
  /// entrypoint, and the compose file. Existing files are left untouched; the
  /// stack is regenerated when the workspace config changed since it was generated.
  Init(InitArgs),
  /// Enter the confined agent environment in one go: generate what is missing,
  /// start the stack, then run the configured shell (or the command after
  /// `--`). The stack keeps running when that exits, unless `--rm` stops it.
  Agent(AgentArgs),
  /// Forward agent-owned loopback listeners to the wildcard interface.
  ///
  /// A sidecar of the generated compose stack, not a user command: it shares
  /// the agent's PID namespace and arkham's network namespace, so it sees every
  /// listener of the shared namespace and can attribute the ones the agent's
  /// own processes hold. Anything else — arkham's capture and explicit-proxy
  /// listeners, docker's embedded DNS — is never attributable from here and
  /// is never forwarded. Raw bytes only: payloads are never inspected.
  Fwd(FwdArgs),
  /// Start the layered compose project `arkham init` generated.
  Up(UpArgs),
  /// Publish an agent port on the host, claiming the host port across
  /// workspaces: `arkham expose <port> [--host <host-port>]` appends the
  /// `[[workspace.expose]]` mapping, regenerates, and `up`s (recreating the
  /// arkham service, so exec sessions drop). A host port another workspace
  /// claimed fails naming that workspace. `arkham expose --list` reports
  /// this workspace's publishings plus every workspace's claims.
  Expose(ExposeArgs),
  /// Stop the layered compose project.
  Down(DownArgs),
  /// Read the stack's logs.
  Logs(LogsArgs),
  /// Run the host daemon: one proxy, the project registry, and the control socket.
  Daemon(DaemonArgs),
}

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Resolve the CA file path: config `ca_file` if set, else `/certs/ca.pem`
/// when the generated stack mounted it there, else the default
/// `<config-dir>/arkham/ca.pem`.
fn ca_path(proxy: &arkham_config::config::ProxyCfg) -> eyre::Result<PathBuf> {
  if let Some(path) = proxy.ca_file.clone() {
    return Ok(path);
  }
  let mounted = Path::new("/certs/ca.pem");
  if mounted.is_file() {
    return Ok(mounted.to_path_buf());
  }
  arkham_config::config::user_config_file(Path::new("arkham").join("ca.pem"))
    .ok_or_else(|| eyre::eyre!("unable to resolve user config directory"))
}

fn main() -> eyre::Result<()> {
  if std::env::args().nth(1).as_deref() == Some("--landlock-exec") {
    #[cfg(target_os = "linux")]
    {
      if let Err(err) = arkham_compose::landlock_exec() {
        eprintln!("{}", err.registration_detail());
        std::process::exit(1);
      }
      return Ok(());
    }
    #[cfg(not(target_os = "linux"))]
    {
      eyre::bail!("the landlock launcher runs on Linux");
    }
  }
  runtime_main()
}

#[tokio::main]
async fn runtime_main() -> eyre::Result<()> {
  arkham_pki::ca::install_crypto_provider();
  tracing_subscriber::fmt()
    .pretty()
    .with_line_number(true)
    .with_thread_names(true)
    .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
    .init();
  let ArkhamCli { globals: cli, command } = ArkhamCli::parse();
  let command = command.unwrap_or(Command::Serve(ServeArgs::default()));
  let arkham_version = env!("CARGO_PKG_VERSION");
  match command {
    Command::Serve(args) => args.run(&cli, arkham_version).await?,
    Command::Fake(args) => args.run(&cli, arkham_version).await?,
    Command::Schemes(args) => args.run(&cli, arkham_version).await?,
    Command::Ca(args) => args.run(&cli, arkham_version).await?,
    Command::Rules(args) => args.run(&cli, arkham_version).await?,
    Command::Config(args) => args.run(&cli, arkham_version).await?,
    Command::Registry(args) => args.run(&cli, arkham_version).await?,
    Command::Init(args) => args.run(&cli, arkham_version).await?,
    Command::Agent(args) => args.run(&cli, arkham_version).await?,
    Command::Fwd(args) => args.run(&cli, arkham_version).await?,
    Command::Up(args) => args.run(&cli, arkham_version).await?,
    Command::Expose(args) => args.run(&cli, arkham_version).await?,
    Command::Down(args) => args.run(&cli, arkham_version).await?,
    Command::Logs(args) => args.run(&cli, arkham_version).await?,
    Command::Daemon(args) => args.run(&cli, arkham_version).await?,
  }
  Ok(())
}

/// The registry the value-resolving commands run with: the bundled table,
/// the global `rules.d`, then the workspace's own when one encloses the
/// working directory.
fn generation_registry() -> eyre::Result<arkham_config::registry::Registry> {
  Ok(arkham_config::registry::Registry::load_union(
    arkham_config::config::rules_dir().as_deref(),
    arkham_config::config::cwd_project_rules_dir().as_deref(),
  )?)
}

/// `arkham serve`: bind the explicit listener and the Unix-socket PROXY
/// handoff, then run the selected capture backend alongside them.
async fn serve(cli: &Cli, args: ServeArgs) -> eyre::Result<()> {
  #[cfg(not(target_os = "linux"))]
  if args.proxy_backend != ProxyBackend::None {
    eyre::bail!("transparent capture (--proxy-backend) is only supported on Linux");
  }
  // No default cgroup: attaching to the root cgroup would capture every
  // process on the machine, arkham's own upstream dials included.
  if args.proxy_backend == ProxyBackend::Ebpf && args.ebpf_cgroup.is_none() {
    eyre::bail!("--ebpf-cgroup is required for --proxy-backend ebpf");
  }
  let (mut config, workspace) = arkham_config::config::load(cli, Some(&args.proxy))?;
  let registry = generation_registry()?;
  // fnox always opens: it is the value source and the rule catalog —
  // derivation needs the declared names even with no config rule — and
  // `open()` is `None` when no fnox configuration exists. Every credential
  // resolves from fnox, age-encrypted secrets included, never from the
  // environment that started this process.
  let fnox = FnoxSource::open()?;
  if let Some(source) = &fnox {
    for name in arkham_fnox::export_provider_env(source).await {
      tracing::debug!(name, "provider credential taken from fnox");
    }
  }
  arkham_fnox::resolve(&mut config, &registry, fnox).await?;
  let resolved = arkham_config::grants::resolve(&config)?;
  if let Some(ws) = &workspace {
    tracing::info!(
      root = %ws.root().display(),
      kind = ?ws.kind(),
      ecosystems = %ws.ecosystem_label(),
      "workspace"
    );
  } else {
    tracing::debug!("no workspace root, global config only");
  }
  let ca = arkham_pki::ca::load_or_generate(&ca_path(&resolved.proxy)?)?;
  let listen_addr = resolved.proxy.listen;
  let (handoff_path, handoff_uid) = resolve_handoff_endpoint(&resolved.proxy)?;
  let grant_count = resolved.grants.len();
  #[cfg(target_os = "linux")]
  let fwmark = match args.proxy_backend {
    // eBPF needs no fwmark: exclusion is cgroup membership plus the proxy PID
    // the programs compare against, not a routing loop to break.
    ProxyBackend::None | ProxyBackend::Ebpf => None,
    ProxyBackend::Tproxy => Some(arkham_tproxy::EGRESS_MARK),
    ProxyBackend::Tun => Some(arkham_tun::FWMARK),
  };
  #[cfg(target_os = "linux")]
  let state = std::sync::Arc::new(match fwmark {
    Some(mark) => arkham_proxy::ProxyState::new(resolved, &ca)?.with_fwmark(mark),
    None => arkham_proxy::ProxyState::new(resolved, &ca)?,
  });
  #[cfg(not(target_os = "linux"))]
  let state = std::sync::Arc::new(arkham_proxy::ProxyState::new(resolved, &ca)?);
  // Bind before capture side effects: a bad listen addr must fail
  // before nft rules and routes touch the host.
  let listener = arkham_proxy::bind_explicit(listen_addr).await?;
  let handoff = bind_handoff_listener(&handoff_path, handoff_uid).await?;
  if !listen_addr.ip().is_loopback() {
    tracing::warn!(listen = %listen_addr, "listening on a non-loopback address: anyone reaching this port can trigger real-secret substitution");
  }
  tracing::info!(
    listen = %listen_addr,
    handoff = %handoff_path.display(),
    uid = handoff_uid,
    grants = grant_count,
    "serving"
  );
  #[cfg(target_os = "linux")]
  if args.proxy_backend == ProxyBackend::Tun {
    let capture = std::sync::Arc::clone(&state);
    // Dropping the task runs its teardown guard, which removes the policy
    // routes; a leaked default route in the capture table blackholes all egress.
    return with_capture(listener, handoff, state, "TUN", async move {
      arkham_tun::run_tun(capture).await.map_err(eyre::Report::from)
    })
    .await;
  }
  #[cfg(target_os = "linux")]
  if args.proxy_backend == ProxyBackend::Tproxy {
    let capture = std::sync::Arc::clone(&state);
    let allow_root_netns = args.tproxy_allow_root_netns;
    return with_capture(listener, handoff, state, "TPROXY", async move {
      arkham_tproxy::run_tproxy(capture, allow_root_netns)
        .await
        .map_err(eyre::Report::from)
    })
    .await;
  }
  #[cfg(target_os = "linux")]
  if args.proxy_backend == ProxyBackend::Ebpf {
    let cgroup = args
      .ebpf_cgroup
      .clone()
      .ok_or_else(|| eyre::eyre!("--ebpf-cgroup is required for --proxy-backend ebpf"))?;
    let capture = std::sync::Arc::clone(&state);
    let bypass = args.ebpf_bypass.clone();
    let bypass_file = args.ebpf_bypass_file.clone();
    return with_capture(listener, handoff, state, "eBPF", async move {
      arkham_ebpf::run_ebpf(capture, cgroup, bypass, bypass_file)
        .await
        .map_err(eyre::Report::from)
    })
    .await;
  }
  serve_explicit_and_handoff(listener, handoff, state).await;
  Ok(())
}

fn resolve_handoff_endpoint(proxy: &arkham_config::config::ProxyCfg) -> eyre::Result<(PathBuf, u32)> {
  let path = proxy
    .handoff_socket
    .clone()
    .or_else(|| arkham_config::config::user_config_file(Path::new("arkham").join("handoff.sock")))
    .ok_or_else(|| eyre::eyre!("unable to resolve handoff socket path"))?;
  let uid = proxy.handoff_uid.unwrap_or_else(|| rustix::process::getuid().as_raw());
  Ok((path, uid))
}

async fn bind_handoff_listener(path: &Path, uid: u32) -> eyre::Result<arkham_proxy::HandoffListener> {
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent)?;
  }
  Ok(arkham_proxy::bind_handoff(path, uid).await?)
}

/// Serve the explicit TCP listener and the authenticated Unix-socket handoff
/// together. Either future running forever is the process; they stop together
/// when the process exits.
async fn serve_explicit_and_handoff(
  listener: arkham_proxy::RamaTcpListener,
  handoff: arkham_proxy::HandoffListener,
  state: std::sync::Arc<arkham_proxy::ProxyState>,
) {
  tokio::join!(
    arkham_proxy::serve(listener, std::sync::Arc::clone(&state)),
    arkham_proxy::serve_handoff(handoff, state),
  );
}

/// Serve the explicit listener while a capture backend runs beside it, failing
/// closed.
///
/// Capture was explicitly requested, so a backend that dies ends the process
/// instead of silently degrading to explicit-proxy only. The signal handler
/// lives here, at process level, never inside the capture task: aborting the
/// task is what runs its teardown, and every backend has host state to unwind.
#[cfg(target_os = "linux")]
async fn with_capture<F>(
  listener: arkham_proxy::RamaTcpListener,
  handoff: arkham_proxy::HandoffListener,
  state: std::sync::Arc<arkham_proxy::ProxyState>,
  name: &'static str,
  capture: F,
) -> eyre::Result<()>
where
  F: Future<Output = eyre::Result<()>> + Send + 'static,
{
  let mut handle = tokio::spawn(capture);
  tokio::select! {
    () = serve_explicit_and_handoff(listener, handoff, state) => Ok(()),
    capture_result = &mut handle => match capture_result {
      Ok(inner) => inner.map_err(|err| eyre::eyre!("{name} capture failed: {err:?}")),
      Err(err) => Err(eyre::eyre!("{name} task failed: {err}")),
    },
    _ = tokio::signal::ctrl_c() => {
      handle.abort();
      Ok(())
    }
  }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
  use arkham_config::cli::{Cli, ProxyBackend};

  use super::{ServeArgs, serve};

  #[tokio::test]
  async fn ebpf_without_a_cgroup_is_rejected() {
    let cli = Cli { config: None };
    let args = ServeArgs {
      proxy_backend: ProxyBackend::Ebpf,
      ..Default::default()
    };
    let err = tokio::time::timeout(std::time::Duration::from_secs(5), serve(&cli, args))
      .await
      .expect("ebpf without a cgroup served the explicit listener")
      .unwrap_err();
    assert_eq!(err.to_string(), "--ebpf-cgroup is required for --proxy-backend ebpf");
  }
}

#[cfg(all(test, unix))]
mod serve_handoff_tests {
  use std::os::unix::fs::PermissionsExt as _;
  use std::path::{Path, PathBuf};
  use std::time::Duration;

  use arkham_config::cli::Cli;
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
  use tokio::net::{TcpListener, UnixStream};

  use super::{ServeArgs, serve};

  fn write_serve_config(work: &Path, listen: &str) -> PathBuf {
    let path = work.join("arkham.toml");
    let ca = work.join("ca.pem");
    std::fs::write(&path, format!("[proxy]\nlisten = \"{listen}\"\nca_file = \"{}\"\n", ca.display())).unwrap();
    path
  }

  fn isolate_serve_env(home: &Path, handoff: &Path) {
    // SAFETY: nextest runs this test in its own process. HOME and overlay env
    // must not touch the operator's real config directory.
    unsafe {
      std::env::set_var("HOME", home);
      std::env::set_var("XDG_CONFIG_HOME", home.join("xdg-config"));
      std::env::set_var("XDG_STATE_HOME", home.join("xdg-state"));
      std::env::remove_var("ARKHAM_CONFIG");
      std::env::remove_var("ARKHAM_LISTEN");
      std::env::remove_var("ARKHAM_CA_FILE");
      std::env::set_var("ARKHAM_HANDOFF_SOCKET", handoff);
      std::env::remove_var("ARKHAM_HANDOFF_UID");
    }
  }

  async fn wait_for_handoff_socket(path: &Path, serve_task: &tokio::task::JoinHandle<eyre::Result<()>>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
      if path.exists() {
        return;
      }
      assert!(
        !serve_task.is_finished(),
        "serve exited before binding the handoff socket at {}",
        path.display()
      );
      assert!(
        tokio::time::Instant::now() < deadline,
        "handoff socket was not bound at {}",
        path.display()
      );
      tokio::time::sleep(Duration::from_millis(20)).await;
    }
  }

  /// `arkham serve` must expose the Unix-socket PROXY handoff the Network
  /// Extension connects to, not only the explicit TCP listener.
  #[tokio::test]
  async fn serve_binds_the_configured_handoff_socket_and_relays_proxy_v1() {
    arkham_pki::ca::install_crypto_provider();
    let work = tempfile::tempdir().unwrap();
    let handoff = work.path().join("handoff.sock");
    let config = write_serve_config(work.path(), "127.0.0.1:0");

    isolate_serve_env(work.path(), &handoff);

    let cli = Cli { config: Some(config) };
    let serve_task = tokio::spawn(async move { serve(&cli, ServeArgs::default()).await });

    wait_for_handoff_socket(&handoff, &serve_task).await;
    assert!(!serve_task.is_finished(), "serve exited after binding the handoff socket");

    let mode = std::fs::metadata(&handoff).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "handoff socket must be mode 0600");

    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = tokio::time::timeout(Duration::from_secs(5), stub.accept())
        .await
        .expect("stub accept timed out")
        .unwrap();
      let mut got = vec![0u8; 4];
      conn.read_exact(&mut got).await.unwrap();
      assert_eq!(&got, b"ping");
      conn.write_all(b"pong").await.unwrap();
    });

    let mut client = UnixStream::connect(&handoff).await.expect("connect to serve handoff socket");
    let header = format!("PROXY TCP4 203.0.113.9 127.0.0.1 9 {stub_port}\r\n");
    client.write_all(header.as_bytes()).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut reply = vec![0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply))
      .await
      .expect("handoff reply timed out")
      .unwrap();
    assert_eq!(&reply, b"pong");
    stub_task.await.unwrap();

    serve_task.abort();
  }
}
