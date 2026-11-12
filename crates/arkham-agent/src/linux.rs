use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use arkham_config::WriteProfile;
use arkham_sandbox::{peer_uid_allowed, read_cgroup};
use arkham_session_protocol::{RegisterRequest, RegisterResponse, daemon_socket_path, read_line, trusted_socket, write_line};

use crate::{Error, Result};

pub(crate) async fn agent(profile: WriteProfile, workspace: Option<&Path>, command: &[OsString]) -> Result<()> {
  let socket = daemon_socket_path()?;
  trusted_socket(&socket)?;
  let mut stream = tokio::net::UnixStream::connect(&socket).await.map_err(|source| {
    tracing::debug!(%source, "no host daemon");
    arkham_session_protocol::Error::NoDaemon
  })?;
  let cred = stream.peer_cred().map_err(|source| {
    tracing::debug!(%source, "daemon peer credentials");
    arkham_session_protocol::Error::SocketOwner
  })?;
  if !peer_uid_allowed(cred.uid(), rustix::process::getuid().as_raw()) {
    return Err(arkham_session_protocol::Error::SocketOwner.into());
  }
  let cwd = canonical_workspace(workspace)?;
  let env = std::env::vars_os()
    .map(|(key, value)| {
      let Ok(key) = key.into_string() else {
        return Err(Error::NonUnicodeEnvironment);
      };
      let Ok(value) = value.into_string() else {
        return Err(Error::NonUnicodeEnvironment);
      };
      Ok((key, value))
    })
    .collect::<Result<_>>()?;
  let request = RegisterRequest { cwd, profile, env };
  let bytes = serde_json::to_vec(&request).map_err(|source| arkham_session_protocol::Error::ControlMessage { source })?;
  write_line(&mut stream, &bytes).await?;
  let line = read_line(&mut stream).await?;
  let response: RegisterResponse =
    serde_json::from_slice(&line).map_err(|source| arkham_session_protocol::Error::ControlMessage { source })?;
  let cgroup = match response {
    RegisterResponse::Join { cgroup } => cgroup,
    RegisterResponse::Rejected { error } => return Err(Error::DaemonRejected { detail: error }),
    RegisterResponse::Ready { .. } => return Err(arkham_session_protocol::Error::NoDaemon.into()),
  };
  let original = read_cgroup(std::process::id())?;
  let original = Path::new("/sys/fs/cgroup")
    .join(original.trim_start_matches('/'))
    .join("cgroup.procs");
  let restore = std::fs::OpenOptions::new().write(true).open(original)?;
  std::fs::write(cgroup.join("cgroup.procs"), "0").map_err(|source| arkham_sandbox::Error::SessionCgroup {
    path: cgroup.clone(),
    source,
  })?;
  let mut placement = SelfPlacement(Some(restore));
  write_line(&mut stream, b"activate").await?;
  let line = read_line(&mut stream).await?;
  let response: RegisterResponse =
    serde_json::from_slice(&line).map_err(|source| arkham_session_protocol::Error::ControlMessage { source })?;
  let plan = match response {
    RegisterResponse::Ready { plan } => plan,
    RegisterResponse::Rejected { error } => return Err(Error::DaemonRejected { detail: error }),
    RegisterResponse::Join { .. } => return Err(arkham_session_protocol::Error::NoDaemon.into()),
  };
  let executable = std::env::current_exe()?;
  let mut child = arkham_sandbox::spawn(&plan, command, &executable).await?;
  let status = child.wait().await?;
  placement.restore()?;
  drop(stream);
  std::process::exit(status.code().unwrap_or(1));
}

struct SelfPlacement(Option<std::fs::File>);

impl SelfPlacement {
  fn restore(&mut self) -> Result<()> {
    if let Some(file) = &mut self.0 {
      file.write_all(b"0")?;
      self.0 = None;
    }
    Ok(())
  }
}

impl Drop for SelfPlacement {
  fn drop(&mut self) {
    let _ = self.restore();
  }
}

fn canonical_workspace(workspace: Option<&Path>) -> Result<PathBuf> {
  let path = match workspace {
    Some(path) if path.is_absolute() => path.to_path_buf(),
    Some(path) => match std::env::current_dir() {
      Ok(cwd) => cwd.join(path),
      Err(source) => {
        return Err(Error::ResolveWorkspace {
          path: path.to_path_buf(),
          source,
        });
      }
    },
    None => std::env::current_dir().map_err(|source| Error::ResolveWorkspace {
      path: PathBuf::from("."),
      source,
    })?,
  };
  arkham_paths::canonicalize_dir(&path).map_err(|source| Error::ResolveWorkspace { path, source })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn a_workspace_symlink_enlists_the_real_target() {
    let base = tempfile::tempdir().unwrap();
    let base = base.path().canonicalize().unwrap();
    let parent = base.join("home");
    let target = base.join("proj");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir(target.join(".git")).unwrap();
    std::fs::write(parent.join("fnox.toml"), "[providers]\n").unwrap();
    let link = parent.join("work");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let cwd = canonical_workspace(Some(&link)).unwrap();
    assert_eq!(cwd, target);
    assert_eq!(arkham_workspace::project_root(&cwd, &[]), Some(target.clone()));
    assert_eq!(arkham_workspace::project_root(&link, &[]), Some(target));
  }

  #[test]
  fn launch_cwd_without_a_workspace_is_the_canonical_current_directory() {
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    assert_eq!(canonical_workspace(None).unwrap(), cwd);
  }
}
