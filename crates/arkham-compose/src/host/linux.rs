//! Linux launcher. Bubblewrap is the only runner. Landlock adds restrictions
//! inside that sandbox and never starts a process of its own.
//!
//! This module also owns the session cgroup. The daemon calls it before
//! handing the plan back. The start time is read again after the process is
//! moved, and the cgroup path has to name the session directory.

use std::ffi::OsString;
use std::io::{Seek as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};

use arkham_config::{Enforcement, FsPolicy, RunnerKind, WriteProfile, choose_runner, fs_policy};
use landlock::{ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus};
use tokio::process::Command;

use crate::Error;
use crate::host::discover::{parse_starttime, peer_uid_allowed};
use crate::host::plan::{LaunchPlan, TEMP_DIR, bwrap_argv};
use crate::host::protocol::{RegisterRequest, RegisterResponse, daemon_socket_path, read_line, write_line};

/// Path of the plan inside the sandbox. The bytes come from a memfd.
const PLAN_DEST: &str = "/arkham/plan.json";

/// A cgroup directory created for one registered session.
#[derive(Debug)]
pub struct SessionSlot {
  /// Directory whose inode is the cgroup id.
  pub path: PathBuf,
  /// Inode of `path`.
  pub id: u64,
}

/// Create `arkham-host/<pid>-<starttime>` under this process's cgroup and
/// move `pid` into it.
///
/// The start time and the cgroup path are read again after the write. A
/// mismatch moves the process back when it entered the session, removes the
/// directory, and returns [`Error::SessionReused`].
///
/// # Errors
///
/// Returns [`Error::SessionCgroup`] when the directory cannot be created or
/// the process cannot be moved, [`Error::SessionReused`] when the process
/// identity does not match the directory, and [`Error::NoStarttime`] or
/// [`Error::NoCgroup`] when `/proc` cannot be read.
pub fn create_session(pid: u32, starttime: u64) -> Result<SessionSlot, Error> {
  let parent = host_cgroup()?;
  let path = parent.join(format!("{pid}-{starttime}"));
  std::fs::create_dir(&path).map_err(|source| session_cgroup_io(&path, source))?;
  if read_starttime(pid)? != starttime {
    let _ = std::fs::remove_dir(&path);
    return Err(Error::SessionReused);
  }
  std::fs::write(path.join("cgroup.procs"), pid.to_string()).map_err(|source| session_cgroup_io(&path, source))?;
  match placement_holds(pid, starttime, &path) {
    Ok(true) => {}
    Ok(false) => {
      undo_session(&path, pid);
      return Err(Error::SessionReused);
    }
    Err(err) => {
      undo_session(&path, pid);
      return Err(err);
    }
  }
  let id = std::fs::metadata(&path).map_err(|source| session_cgroup_io(&path, source))?.ino();
  Ok(SessionSlot { path, id })
}

fn session_cgroup_io(path: &Path, source: std::io::Error) -> Error {
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
  let Some(name) = session.file_name().and_then(|name| name.to_str()) else {
    return Ok(false);
  };
  Ok(cgroup.split('/').any(|part| part == name))
}

fn undo_session(path: &Path, pid: u32) {
  let entered = path.file_name().and_then(|name| name.to_str()).is_some_and(|name| {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup")).is_ok_and(|text| text.split(['/', '\n']).any(|part| part == name))
  });
  if entered && let Some(parent) = path.parent() {
    let _ = std::fs::write(parent.join("cgroup.procs"), pid.to_string());
  }
  let _ = std::fs::remove_dir(path);
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

/// Move any remaining members to the parent and remove `path`.
pub fn release_session(path: &Path) {
  if let Some(parent) = path.parent()
    && let Ok(procs) = std::fs::read_to_string(path.join("cgroup.procs"))
  {
    for pid in procs.split_whitespace() {
      let _ = std::fs::write(parent.join("cgroup.procs"), pid);
    }
  }
  let _ = std::fs::remove_dir(path);
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

/// Create the socket directory mode `0700` and return the socket path.
///
/// Every directory this function creates is mode `0700`. An existing
/// directory is refused when it is a symlink or owned by another user.
/// `$XDG_RUNTIME_DIR`, when set, must already exist and be owned by this user.
///
/// # Errors
///
/// Returns [`Error::SocketOwner`] when a directory is missing, is a symlink,
/// or is not owned by this user. Returns an I/O error when creation fails
/// for another reason.
pub fn ensure_socket_dir() -> Result<PathBuf, Error> {
  let path = daemon_socket_path();
  let uid = crate::stack::current_uid();
  let Some(socket_dir) = path.parent() else {
    return Err(Error::SocketOwner);
  };
  if std::env::var_os("XDG_RUNTIME_DIR").is_some() {
    let Some(runtime) = socket_dir.parent() else {
      return Err(Error::SocketOwner);
    };
    require_existing_dir(runtime, uid)?;
  } else if let Some(fallback) = socket_dir.parent() {
    ensure_private_dir(fallback, uid)?;
  }
  ensure_private_dir(socket_dir, uid)?;
  Ok(path)
}

fn require_existing_dir(path: &Path, uid: u32) -> Result<(), Error> {
  let meta = match std::fs::symlink_metadata(path) {
    Ok(meta) => meta,
    Err(source) => {
      tracing::debug!(%source, path = %path.display(), "runtime directory");
      return Err(Error::SocketOwner);
    }
  };
  owned_dir(path, uid, &meta)
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
  if after.file_type().is_symlink() || after.uid() != uid {
    return Err(Error::SocketOwner);
  }
  Ok(())
}

/// Connect to the daemon, register `workspace`, and run `command` under bubblewrap.
///
/// The process exits with the child's status. No child is started when the
/// daemon is absent, the socket is not owned by this user, or bubblewrap
/// does not accept the profile.
///
/// # Errors
///
/// Returns an error when registration or the bubblewrap probe fails. A
/// running child replaces this return with [`std::process::exit`].
pub async fn agent(profile: WriteProfile, workspace: Option<&Path>, command: &[OsString]) -> Result<(), Error> {
  let socket = daemon_socket_path();
  trusted_socket(&socket)?;
  let mut stream = tokio::net::UnixStream::connect(&socket).await.map_err(|source| {
    tracing::debug!(%source, "no host daemon");
    Error::NoDaemon
  })?;
  let cred = match stream.peer_cred() {
    Ok(cred) => cred,
    Err(source) => {
      tracing::debug!(%source, "daemon peer credentials");
      return Err(Error::SocketOwner);
    }
  };
  if !peer_uid_allowed(cred.uid(), crate::stack::current_uid()) {
    return Err(Error::SocketOwner);
  }
  let cwd = match workspace {
    Some(path) => std::fs::canonicalize(path)?,
    None => std::env::current_dir()?,
  };
  let request = RegisterRequest { cwd, profile };
  let bytes = serde_json::to_vec(&request).map_err(|source| Error::ControlMessage { source })?;
  write_line(&mut stream, &bytes).await?;
  let line = read_line(&mut stream).await?;
  let response: RegisterResponse = serde_json::from_slice(&line).map_err(|source| Error::ControlMessage { source })?;
  if let Some(detail) = response.error {
    return Err(Error::DaemonRejected { detail });
  }
  let Some(plan) = response.plan else {
    return Err(Error::NoDaemon);
  };
  let choice = probe(&plan).await?;
  let RunnerKind::Bwrap = choice.runner;
  let word = match choice.enforcement {
    Enforcement::Full => "full",
    Enforcement::Partial => "partial",
  };
  eprintln!("runner: bwrap");
  eprintln!("enforcement: {word}");
  let plan_file = plan_memfd(&plan)?;
  let plan_fd = plan_file.as_raw_fd();
  let inner = sandboxed_command(&plan, command)?;
  let mut child_cmd = Command::new("bwrap");
  child_cmd.args(insert_plan(bwrap_argv(&plan, &inner), plan_fd));
  // SAFETY: `pre_exec` runs in the forked child, before exec, and the closure
  // only calls `fcntl` on the memfd this process still owns. `fcntl` is
  // async-signal-safe, and the parent keeps the `File` until after `spawn`.
  unsafe { child_cmd.pre_exec(move || clear_cloexec(plan_fd)) };
  let mut child = child_cmd.spawn()?;
  drop(plan_file);
  let status = child.wait().await?;
  drop(stream);
  std::process::exit(status.code().unwrap_or(1));
}

fn trusted_socket(path: &Path) -> Result<(), Error> {
  let meta = match std::fs::symlink_metadata(path) {
    Ok(meta) => meta,
    Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Err(Error::NoDaemon),
    Err(source) => return Err(source.into()),
  };
  if meta.file_type().is_symlink() || meta.uid() != crate::stack::current_uid() {
    return Err(Error::SocketOwner);
  }
  Ok(())
}

fn sandboxed_command(plan: &LaunchPlan, command: &[OsString]) -> Result<Vec<OsString>, Error> {
  let mut inner = vec![
    std::env::current_exe()?.into_os_string(),
    OsString::from("--landlock-exec"),
    OsString::from(PLAN_DEST),
    OsString::from("--"),
  ];
  inner.extend(command_or_shell(command, plan));
  Ok(inner)
}

fn insert_plan(mut args: Vec<OsString>, fd: i32) -> Vec<OsString> {
  let at = args.iter().position(|arg| arg == "--remount-ro").unwrap_or(args.len());
  let plan = [
    OsString::from("--ro-bind-data"),
    OsString::from(fd.to_string()),
    OsString::from(PLAN_DEST),
  ];
  args.splice(at..at, plan);
  args
}

fn plan_memfd(plan: &LaunchPlan) -> Result<std::fs::File, Error> {
  let bytes = serde_json::to_vec(plan).map_err(|source| Error::ControlMessage { source })?;
  // SAFETY: `memfd_create` is a syscall with a nul-terminated name and a flag.
  // A negative return is an error and is not turned into a `File`.
  let fd = unsafe { libc::memfd_create(c"arkham-plan".as_ptr(), libc::MFD_CLOEXEC) };
  if fd < 0 {
    return Err(std::io::Error::last_os_error().into());
  }
  // SAFETY: `fd` was just returned by `memfd_create` and no other owner exists.
  let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
  file.write_all(&bytes)?;
  file.seek(std::io::SeekFrom::Start(0))?;
  Ok(file)
}

fn clear_cloexec(fd: i32) -> std::io::Result<()> {
  // SAFETY: `fd` is the memfd created for this launch. `fcntl` with `F_GETFD`
  // and `F_SETFD` only changes the close-on-exec flag of that descriptor.
  let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
  if flags < 0 {
    return Err(std::io::Error::last_os_error());
  }
  let updated = flags & !libc::FD_CLOEXEC;
  // SAFETY: same descriptor as the `F_GETFD` above.
  let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, updated) };
  if rc < 0 {
    return Err(std::io::Error::last_os_error());
  }
  Ok(())
}

/// Apply the plan's Landlock rules and replace this process with the command.
///
/// Invoked as `arkham --landlock-exec <plan> [--report] -- <command>` from
/// inside bubblewrap. A Landlock failure still execs the command: bubblewrap
/// is the runner, and Landlock only adds to it.
///
/// # Errors
///
/// Returns an error when the plan cannot be read or the command cannot be
/// exec'd. A successful exec does not return.
pub fn landlock_exec() -> Result<(), Error> {
  let args: Vec<OsString> = std::env::args_os().collect();
  let mut plan_path = None;
  let mut report = false;
  let mut command = Vec::new();
  let mut index = 0;
  while index < args.len() {
    let arg = &args[index];
    if arg == "--landlock-exec" {
      index = index.saturating_add(1);
      plan_path = args.get(index).cloned();
    } else if arg == "--report" {
      report = true;
    } else if arg == "--" {
      command.extend(args.iter().skip(index.saturating_add(1)).cloned());
      break;
    }
    index = index.saturating_add(1);
  }
  let Some(plan_path) = plan_path else {
    return Err(Error::ControlLimit);
  };
  let text = std::fs::read(&plan_path)?;
  let plan: LaunchPlan = serde_json::from_slice(&text).map_err(|source| Error::ControlMessage { source })?;
  match apply_landlock(&plan) {
    Ok(enforcement) if report => {
      let word = match enforcement {
        Enforcement::Full => "full",
        Enforcement::Partial => "partial",
      };
      eprintln!("enforcement: {word}");
    }
    Ok(_) => {}
    Err(err) => tracing::debug!(%err, "landlock did not add a restriction"),
  }
  let command = if command.is_empty() {
    vec![OsString::from(plan.shell)]
  } else {
    command
  };
  let Some(program) = command.first() else {
    return Err(Error::ControlLimit);
  };
  let error = std::process::Command::new(program).args(command.iter().skip(1)).exec();
  Err(error.into())
}

fn apply_landlock(plan: &LaunchPlan) -> Result<Enforcement, Error> {
  let policy = fs_policy(plan.profile, &plan.workspace, Path::new(TEMP_DIR));
  if matches!(policy, FsPolicy::Unrestricted) {
    return Ok(Enforcement::Partial);
  }
  let abi = ABI::V1;
  let read = AccessFs::from_read(abi);
  let all = AccessFs::from_all(abi);
  let mut ruleset = Ruleset::default()
    .handle_access(all)
    .map_err(|source| Error::Landlock { source })?
    .create()
    .map_err(|source| Error::Landlock { source })?;
  ruleset = add_path(ruleset, Path::new("/"), read)?;
  // `/` is read-only. Shells still open `/dev/null` for writing, and the
  // read-only profile's sink is that same device.
  ruleset = add_path(ruleset, Path::new("/dev/null"), AccessFs::from_file(abi))?;
  match policy {
    FsPolicy::ReadOnly { sink } => ruleset = add_path(ruleset, &sink, all)?,
    FsPolicy::WorkspaceWrite { roots } => {
      for root in &roots {
        ruleset = add_path(ruleset, root, all)?;
      }
    }
    FsPolicy::Unrestricted => {}
  }
  let status = ruleset.restrict_self().map_err(|source| Error::Landlock { source })?;
  match status.ruleset {
    RulesetStatus::FullyEnforced => Ok(Enforcement::Full),
    RulesetStatus::PartiallyEnforced | RulesetStatus::NotEnforced => Ok(Enforcement::Partial),
  }
}

fn add_path(ruleset: RulesetCreated, path: &Path, access: landlock::BitFlags<AccessFs>) -> Result<RulesetCreated, Error> {
  let fd = PathFd::new(path).map_err(|source| Error::LandlockPath {
    path: path.to_path_buf(),
    source,
  })?;
  ruleset
    .add_rule(PathBeneath::new(fd, access))
    .map_err(|source| Error::Landlock { source })
}

async fn probe(plan: &LaunchPlan) -> Result<arkham_config::RunnerChoice, Error> {
  choose_runner(probe_bwrap(plan).await, None).map_err(Error::from)
}

async fn probe_bwrap(plan: &LaunchPlan) -> bool {
  let Ok(status) = Command::new("bwrap")
    .args(bwrap_argv(plan, &[OsString::from("true")]))
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .status()
    .await
  else {
    return false;
  };
  status.success()
}

fn command_or_shell(command: &[OsString], plan: &LaunchPlan) -> Vec<OsString> {
  if command.is_empty() {
    vec![OsString::from(&plan.shell)]
  } else {
    command.to_vec()
  }
}

/// Re-export so the binary can name the slot without reaching into this file's private helpers.
///
/// # Errors
///
/// Returns the same errors as [`create_session`].
pub fn session_cgroup(pid: u32, starttime: u64) -> Result<SessionSlot, Error> {
  create_session(pid, starttime)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_plan() -> LaunchPlan {
    LaunchPlan {
      profile: WriteProfile::ReadOnly,
      workspace: PathBuf::from("/work"),
      binds: Vec::new(),
      ca_host: PathBuf::from("/scratch/ca.pem"),
      ca_dest: PathBuf::from("/arkham/ca.pem"),
      env: Vec::new(),
      workdir: PathBuf::from("/work"),
      shell: "sh".into(),
    }
  }

  struct Kill(std::process::Child);

  impl Drop for Kill {
    fn drop(&mut self) {
      let _ = self.0.kill();
      let _ = self.0.wait();
    }
  }

  #[test]
  fn the_plan_is_a_memfd_and_not_a_temp_file() {
    let file = plan_memfd(&sample_plan()).unwrap();
    let link = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    assert!(link.to_string_lossy().contains("memfd"), "{link:?}");
    let leaked = std::env::temp_dir().join(format!("arkham-plan-{}.json", std::process::id()));
    assert!(!leaked.exists(), "{}", leaked.display());
  }

  #[test]
  fn the_plan_fd_is_inserted_before_the_root_is_remounted() {
    let args = insert_plan(bwrap_argv(&sample_plan(), &[]), 7);
    let data = args.iter().position(|arg| arg == "--ro-bind-data").unwrap();
    let remount = args.iter().position(|arg| arg == "--remount-ro").unwrap();
    assert!(data < remount);
    assert_eq!(args[data + 1], "7");
    assert_eq!(args[data + 2], PLAN_DEST);
  }

  #[test]
  fn a_cgroup_permission_error_names_the_directory_and_the_denial() {
    let dir = tempfile::tempdir().unwrap();
    let blocked = dir.path().join("cgroup");
    std::fs::create_dir(&blocked).unwrap();
    let mut perms = std::fs::metadata(&blocked).unwrap().permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&blocked, perms).unwrap();
    let source = std::fs::create_dir(blocked.join("arkham-host")).unwrap_err();
    let err = session_cgroup_io(&blocked.join("arkham-host"), source);
    let text = err.to_string();
    assert!(text.contains(blocked.join("arkham-host").to_str().unwrap()), "{text}");
    assert!(text.to_ascii_lowercase().contains("permission denied"), "{text}");
  }

  #[test]
  fn create_session_refuses_a_pid_whose_start_time_does_not_match() {
    let child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let mut child = Kill(child);
    let pid = child.0.id();
    let start = read_starttime(pid).unwrap();
    let err = create_session(pid, start.wrapping_add(1)).unwrap_err();
    assert!(matches!(err, Error::SessionReused), "{err:?}");
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    assert!(!cgroup.contains("arkham-host"), "{cgroup}");
    let _ = child.0.kill();
  }

  #[test]
  fn a_confirmed_session_names_its_directory_and_a_stale_start_time_does_not() {
    let child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let mut child = Kill(child);
    let pid = child.0.id();
    let start = read_starttime(pid).unwrap();
    let slot = create_session(pid, start).unwrap();
    assert!(placement_holds(pid, start, &slot.path).unwrap());
    assert!(!placement_holds(pid, start.wrapping_add(1), &slot.path).unwrap());
    release_session(&slot.path);
    assert!(!placement_holds(pid, start, &slot.path).unwrap());
    let _ = child.0.kill();
  }
}
