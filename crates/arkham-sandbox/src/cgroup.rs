//! Linux session cgroup authority.

use crate::Error;
use crate::identity::parse_starttime;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// Directory under the daemon's cgroup that holds session cgroups.
const HOST: &str = "arkham-host";

/// A cgroup directory created for one registered session.
#[derive(Debug)]
pub struct SessionSlot {
  /// Directory whose inode is the cgroup id.
  pub path: PathBuf,
  /// Inode of `path`.
  pub id: u64,
  pidfd: PidFd,
  pid: u32,
  starttime: u64,
}

/// Create an empty session cgroup for the authenticated control peer.
///
/// # Errors
///
/// Returns an error when the peer has exited or the cgroup cannot be created.
pub fn session_cgroup(pid: u32, starttime: u64) -> Result<SessionSlot, Error> {
  let pidfd = PidFd::open(pid)?;
  if !identity_holds(&pidfd, pid, starttime)? {
    return Err(Error::SessionReused);
  }
  let path = host_dir()?.join(format!("{pid}-{starttime}"));
  std::fs::create_dir(&path).map_err(|source| session_cgroup_io(&path, source))?;
  let id = match std::fs::metadata(&path) {
    Ok(meta) => meta.ino(),
    Err(source) => {
      let _ = std::fs::remove_dir(&path);
      return Err(session_cgroup_io(&path, source));
    }
  };
  Ok(SessionSlot {
    path,
    id,
    pidfd,
    pid,
    starttime,
  })
}

impl SessionSlot {
  /// Confirm the original peer placed itself in this cgroup.
  ///
  /// # Errors
  ///
  /// Returns an error if the peer exited or its identity or placement changed.
  pub fn confirm(&self) -> Result<(), Error> {
    if identity_holds(&self.pidfd, self.pid, self.starttime)?
      && placement_holds(self.pid, self.starttime, &self.path)?
      && identity_holds(&self.pidfd, self.pid, self.starttime)?
    {
      Ok(())
    } else {
      Err(Error::SessionReused)
    }
  }
}

/// Stable handle used to authenticate the peer during activation.
#[derive(Debug)]
struct PidFd(i32);

impl PidFd {
  fn open(pid: u32) -> Result<Self, Error> {
    let Ok(target) = libc::pid_t::try_from(pid) else {
      return Err(Error::SessionReused);
    };
    // SAFETY: pidfd_open accepts a process id and a zero flags word.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, target, 0u32) };
    if fd < 0 {
      let err = std::io::Error::last_os_error();
      return if err.raw_os_error() == Some(libc::ESRCH) {
        Err(Error::SessionReused)
      } else {
        Err(err.into())
      };
    }
    let Ok(fd) = i32::try_from(fd) else {
      return Err(Error::SessionReused);
    };
    Ok(Self(fd))
  }

  fn alive(&self) -> bool {
    // SAFETY: signal 0 checks that this pidfd still names a process and sends
    // nothing. A null `siginfo_t` is the documented form of that check.
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.0, 0, std::ptr::null::<libc::c_void>(), 0u32) };
    rc == 0
  }
}

impl Drop for PidFd {
  fn drop(&mut self) {
    if self.0 >= 0 {
      // SAFETY: the descriptor came from pidfd_open and is closed once.
      unsafe { libc::close(self.0) };
    }
  }
}

fn identity_holds(pidfd: &PidFd, pid: u32, starttime: u64) -> Result<bool, Error> {
  if !pidfd.alive() {
    return Ok(false);
  }
  match read_starttime(pid) {
    Ok(found) => Ok(found == starttime),
    Err(Error::NoStarttime { .. }) => Ok(false),
    Err(Error::Io(source)) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
    Err(err) => Err(err),
  }
}

pub(crate) fn session_cgroup_io(path: &Path, source: std::io::Error) -> Error {
  Error::SessionCgroup {
    path: path.to_path_buf(),
    source,
  }
}

fn placement_holds(pid: u32, starttime: u64, session: &Path) -> Result<bool, Error> {
  if read_starttime(pid)? != starttime {
    return Ok(false);
  }
  let cgroup = read_cgroup(pid)?;
  let actual = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
  let actual = std::fs::metadata(actual)?;
  let expected = std::fs::metadata(session)?;
  Ok(actual.dev() == expected.dev() && actual.ino() == expected.ino())
}

/// Directory sessions are created under. Capture attaches here.
///
/// When this process's cgroup is not writable, the user's systemd manager
/// first moves the process into a scope delegated to it.
///
/// # Errors
///
/// Returns an error when this process's cgroup cannot be read, delegation
/// fails, or the directory cannot be created.
pub async fn host_cgroup() -> Result<PathBuf, Error> {
  match host_dir() {
    Err(Error::SessionCgroup { source, .. }) if source.kind() == ErrorKind::PermissionDenied => {
      crate::systemd::delegate_self().await?;
      host_dir()
    }
    result => result,
  }
}

fn host_dir() -> Result<PathBuf, Error> {
  let rel = read_cgroup(std::process::id())?;
  let parent = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')).join(HOST);
  std::fs::create_dir_all(&parent).map_err(|source| session_cgroup_io(&parent, source))?;
  Ok(parent)
}

/// Move this process into `session`. When the cgroup it leaves is not
/// writable, the user's systemd manager moves it into the daemon's unit.
///
/// # Errors
///
/// Returns an error when neither the direct move nor the systemd move succeeds.
pub async fn join_session(session: &Path) -> Result<(), Error> {
  let source = match std::fs::write(session.join("cgroup.procs"), "0") {
    Ok(()) => return Ok(()),
    Err(source) if source.kind() == ErrorKind::PermissionDenied => source,
    Err(source) => return Err(session_cgroup_io(session, source)),
  };
  let Some((unit, subcgroup)) = session_unit(session) else {
    return Err(session_cgroup_io(session, source));
  };
  crate::systemd::attach_self(unit, &subcgroup).await
}

/// Open the `cgroup.procs` this process returns to when its session ends:
/// its current cgroup, or the daemon's unit cgroup when the current one is
/// not writable.
///
/// # Errors
///
/// Returns an error when neither cgroup can be opened for writing.
pub fn session_exit(session: &Path) -> Result<File, Error> {
  let current = Path::new("/sys/fs/cgroup").join(read_cgroup(std::process::id())?.trim_start_matches('/'));
  match open_procs(&current) {
    Ok(file) => Ok(file),
    Err(source) if source.kind() == ErrorKind::PermissionDenied => {
      let Some(unit) = session.parent().and_then(Path::parent) else {
        return Err(session_cgroup_io(&current, source));
      };
      open_procs(unit).map_err(|source| session_cgroup_io(unit, source))
    }
    Err(source) => Err(session_cgroup_io(&current, source)),
  }
}

fn open_procs(cgroup: &Path) -> std::io::Result<File> {
  OpenOptions::new().write(true).open(cgroup.join("cgroup.procs"))
}

/// Unit name and unit-relative subcgroup for `<unit>/arkham-host/<session>`.
fn session_unit(session: &Path) -> Option<(&str, String)> {
  let name = session.file_name()?.to_str()?;
  let host = session.parent()?;
  if host.file_name()? != HOST {
    return None;
  }
  let unit = host.parent()?.file_name()?.to_str()?;
  Some((unit, format!("/{HOST}/{name}")))
}

/// Kill remaining members and wait until the cgroup can be removed.
///
/// # Errors
///
/// Returns an error if the cgroup cannot be killed or removed.
pub async fn release_session(path: &Path) -> Result<(), Error> {
  match std::fs::remove_dir(path) {
    Ok(()) => return Ok(()),
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
    Err(err) if err.raw_os_error() == Some(libc::EBUSY) => {}
    Err(source) => return Err(session_cgroup_io(path, source)),
  }
  std::fs::write(path.join("cgroup.kill"), "1").map_err(|source| session_cgroup_io(path, source))?;
  loop {
    match std::fs::remove_dir(path) {
      Ok(()) => return Ok(()),
      Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
      Err(err) if err.raw_os_error() == Some(libc::EBUSY) => {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
      }
      Err(source) => return Err(session_cgroup_io(path, source)),
    }
  }
}

/// `starttime` for `pid`.
///
/// # Errors
///
/// Returns an error when `/proc/<pid>/stat` cannot be read or parsed.
pub fn read_starttime(pid: u32) -> Result<u64, Error> {
  let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
  parse_starttime(&text).ok_or(Error::NoStarttime { pid })
}

/// Relative cgroup path from the `0::` line.
///
/// # Errors
///
/// Returns an error when the file cannot be read or has no cgroup v2 line.
pub fn read_cgroup(pid: u32) -> Result<String, Error> {
  let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
  text
    .lines()
    .find_map(|line| line.strip_prefix("0::"))
    .map(str::to_string)
    .ok_or(Error::NoCgroup { pid })
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use super::session_unit;

  #[test]
  fn a_session_path_names_its_unit_and_subcgroup() {
    let session = Path::new("/sys/fs/cgroup/user.slice/user@1000.service/app.slice/arkham.service/arkham-host/12-99");
    assert_eq!(session_unit(session), Some(("arkham.service", "/arkham-host/12-99".to_string())));
  }

  #[test]
  fn a_path_outside_the_host_directory_has_no_unit() {
    assert_eq!(session_unit(Path::new("/sys/fs/cgroup/arkham.service/other/12-99")), None);
  }
}
