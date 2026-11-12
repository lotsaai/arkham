//! Linux session cgroup authority.

use crate::Error;
use crate::identity::parse_starttime;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

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
  let path = host_cgroup()?.join(format!("{pid}-{starttime}"));
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
/// # Errors
///
/// Returns an error when this process's cgroup cannot be read or the
/// directory cannot be created.
pub fn host_cgroup() -> Result<PathBuf, Error> {
  let rel = read_cgroup(std::process::id())?;
  let parent = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')).join("arkham-host");
  std::fs::create_dir_all(&parent).map_err(|source| session_cgroup_io(&parent, source))?;
  Ok(parent)
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
