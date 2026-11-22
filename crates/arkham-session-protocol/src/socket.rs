use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crate::{Error, daemon_socket_path};

/// Create `$XDG_RUNTIME_DIR/arkham` mode `0700` and return the socket path.
///
/// `$XDG_RUNTIME_DIR` must already exist, be owned by this user, and not be
/// writable by the group or by others. This function does not change its
/// mode. The `arkham` directory is created mode `0700` when it is missing.
///
/// # Errors
///
/// Returns [`Error::RuntimeDir`] when the runtime directory is unset,
/// missing, a symlink, owned by someone else, or group/other writable.
/// Returns [`Error::SocketOwner`] when `arkham` is a symlink or not owned
/// by this user. Returns an I/O error when creation fails for another reason.
pub fn ensure_socket_dir() -> Result<PathBuf, Error> {
  let path = daemon_socket_path()?;
  let uid = rustix::process::getuid().as_raw();
  let Some(socket_dir) = path.parent() else {
    return Err(Error::RuntimeDir);
  };
  let Some(runtime) = socket_dir.parent() else {
    return Err(Error::RuntimeDir);
  };
  require_private_runtime(runtime, uid)?;
  ensure_private_dir(socket_dir, uid)?;
  Ok(path)
}

fn require_private_runtime(path: &Path, uid: u32) -> Result<(), Error> {
  let meta = match std::fs::symlink_metadata(path) {
    Ok(meta) => meta,
    Err(source) => {
      tracing::debug!(%source, path = %path.display(), "runtime directory");
      return Err(Error::RuntimeDir);
    }
  };
  if meta.file_type().is_symlink() || !meta.is_dir() || meta.uid() != uid || meta.permissions().mode() & 0o022 != 0 {
    return Err(Error::RuntimeDir);
  }
  Ok(())
}

fn ensure_private_dir(path: &Path, uid: u32) -> Result<(), Error> {
  match std::fs::symlink_metadata(path) {
    Ok(meta) => owned_dir(path, uid, &meta),
    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
      std::fs::DirBuilder::new().mode(0o700).create(path).or_else(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
          Ok(())
        } else {
          Err(err)
        }
      })?;
      let meta = std::fs::symlink_metadata(path)?;
      owned_dir(path, uid, &meta)
    }
    Err(source) => Err(source.into()),
  }
}

fn owned_dir(path: &Path, uid: u32, meta: &std::fs::Metadata) -> Result<(), Error> {
  if meta.file_type().is_symlink() || !meta.is_dir() || meta.uid() != uid {
    return Err(Error::SocketOwner);
  }
  std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
  let after = std::fs::symlink_metadata(path)?;
  if after.file_type().is_symlink() || after.uid() != uid || after.permissions().mode() & 0o077 != 0 {
    return Err(Error::SocketOwner);
  }
  Ok(())
}

/// Check that the daemon socket and its parent directories are trusted.
///
/// # Errors
///
/// Returns an error if the socket is missing or its ownership is unsafe.
pub fn trusted_socket(path: &Path) -> Result<(), Error> {
  let uid = rustix::process::getuid().as_raw();
  let meta = match std::fs::symlink_metadata(path) {
    Ok(meta) => meta,
    Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Err(Error::NoDaemon),
    Err(source) => return Err(source.into()),
  };
  if meta.file_type().is_symlink() || meta.uid() != uid || meta.permissions().mode() & 0o077 != 0 {
    return Err(Error::SocketOwner);
  }
  let Some(parent) = path.parent() else {
    return Err(Error::SocketOwner);
  };
  let parent_meta = std::fs::symlink_metadata(parent)?;
  if parent_meta.file_type().is_symlink()
    || !parent_meta.is_dir()
    || parent_meta.uid() != uid
    || parent_meta.permissions().mode() & 0o022 != 0
  {
    return Err(Error::SocketOwner);
  }
  let Some(runtime) = parent.parent() else {
    return Err(Error::RuntimeDir);
  };
  require_private_runtime(runtime, uid)
}

#[cfg(test)]
mod tests {
  use std::fs::Permissions;

  use super::*;

  #[test]
  fn a_world_writable_runtime_dir_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = require_private_runtime(dir.path(), rustix::process::getuid().as_raw()).unwrap_err();
    assert!(matches!(err, Error::RuntimeDir));
    assert_eq!(std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777, 0o777);
    assert!(!dir.path().join("arkham").exists());
  }

  #[test]
  fn missing_and_untrusted_sockets_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("arkham");
    std::fs::create_dir(&parent).unwrap();
    // Directories follow the process umask; a login umask of 002 makes them group-writable.
    std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&parent, Permissions::from_mode(0o700)).unwrap();
    let socket = parent.join("daemon.sock");
    assert!(matches!(trusted_socket(&socket), Err(Error::NoDaemon)));
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    trusted_socket(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(trusted_socket(&socket), Err(Error::SocketOwner)));
    drop(listener);
  }
}
