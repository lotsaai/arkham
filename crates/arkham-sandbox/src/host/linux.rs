//! Linux launcher. Bubblewrap is the only runner. Landlock adds restrictions
//! inside that sandbox and never starts a process of its own.
//!
//! This module also owns the session cgroup. The wrapper joins itself and
//! waits for the daemon to authenticate placement before launching.

use std::ffi::OsString;
use std::io::{Seek as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};

use arkham_config::{FsPolicy, WriteProfile, choose_runner, fs_policy};
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
  let uid = crate::stack::current_uid();
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
  let socket = daemon_socket_path()?;
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
  let cwd = launch_cwd(workspace)?;
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
    .collect::<Result<_, Error>>()?;
  let request = RegisterRequest { cwd, profile, env };
  let bytes = serde_json::to_vec(&request).map_err(|source| Error::ControlMessage { source })?;
  write_line(&mut stream, &bytes).await?;
  let line = read_line(&mut stream).await?;
  let response: RegisterResponse = serde_json::from_slice(&line).map_err(|source| Error::ControlMessage { source })?;
  let cgroup = match response {
    RegisterResponse::Join { cgroup } => cgroup,
    RegisterResponse::Rejected { error } => return Err(Error::DaemonRejected { detail: error }),
    RegisterResponse::Ready { .. } => return Err(Error::NoDaemon),
  };
  let original = read_cgroup(std::process::id())?;
  let original = Path::new("/sys/fs/cgroup")
    .join(original.trim_start_matches('/'))
    .join("cgroup.procs");
  let restore = std::fs::OpenOptions::new().write(true).open(original)?;
  std::fs::write(cgroup.join("cgroup.procs"), "0").map_err(|source| session_cgroup_io(&cgroup, source))?;
  let mut placement = SelfPlacement(Some(restore));
  write_line(&mut stream, b"activate").await?;
  let line = read_line(&mut stream).await?;
  let response: RegisterResponse = serde_json::from_slice(&line).map_err(|source| Error::ControlMessage { source })?;
  let plan = match response {
    RegisterResponse::Ready { plan } => plan,
    RegisterResponse::Rejected { error } => return Err(Error::DaemonRejected { detail: error }),
    RegisterResponse::Join { .. } => return Err(Error::NoDaemon),
  };
  let inner = sandboxed_command(&plan, command)?;
  let argv = bwrap_argv(&plan, &inner)?;
  probe(&plan).await?;
  eprintln!("runner: bwrap");
  eprintln!("enforcement: full");
  let plan_file = plan_memfd(&plan)?;
  let plan_fd = plan_file.as_raw_fd();
  let mut child_cmd = Command::new("bwrap");
  child_cmd.args(insert_plan(argv, plan_fd));
  // SAFETY: `pre_exec` runs in the forked child, before exec, and the closure
  // only calls `fcntl` on the memfd this process still owns. `fcntl` is
  // async-signal-safe, and the parent keeps the `File` until after `spawn`.
  unsafe { child_cmd.pre_exec(move || clear_cloexec(plan_fd)) };
  let mut child = child_cmd.spawn()?;
  drop(plan_file);
  let status = child.wait().await?;
  placement.restore()?;
  drop(stream);
  std::process::exit(status.code().unwrap_or(1));
}

struct SelfPlacement(Option<std::fs::File>);

impl SelfPlacement {
  fn restore(&mut self) -> Result<(), Error> {
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

fn launch_cwd(workspace: Option<&Path>) -> Result<PathBuf, Error> {
  super::discover::canonical_workspace(workspace)
}

fn trusted_socket(path: &Path) -> Result<(), Error> {
  let uid = crate::stack::current_uid();
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
/// Invoked as `arkham --landlock-exec <plan> -- <command>` from inside
/// bubblewrap. [`WriteProfile::DangerFullAccess`] does not apply Landlock.
/// Every other profile returns before exec unless the ruleset is fully
/// enforced.
///
/// # Errors
///
/// Returns an error when the plan cannot be read, Landlock does not fully
/// enforce the profile, or the command cannot be exec'd. A successful exec
/// does not return.
pub fn landlock_exec() -> Result<(), Error> {
  let args: Vec<OsString> = std::env::args_os().collect();
  let mut plan_path = None;
  let mut command = Vec::new();
  let mut index = 0;
  while index < args.len() {
    let arg = &args[index];
    if arg == "--landlock-exec" {
      index = index.saturating_add(1);
      plan_path = args.get(index).cloned();
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
  if plan.profile != WriteProfile::DangerFullAccess {
    apply_landlock(&plan)?;
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

/// Accept only a fully enforced Landlock status.
///
/// # Errors
///
/// Returns [`Error::LandlockIncomplete`] when the kernel did not enforce
/// every requested restriction.
fn require_full_enforcement(status: &RulesetStatus) -> Result<(), Error> {
  match status {
    RulesetStatus::FullyEnforced => Ok(()),
    RulesetStatus::PartiallyEnforced | RulesetStatus::NotEnforced => Err(Error::LandlockIncomplete),
  }
}

fn apply_landlock(plan: &LaunchPlan) -> Result<(), Error> {
  let policy = fs_policy(plan.profile, &plan.workspace, Path::new(TEMP_DIR));
  let abi = ABI::V1;
  let read = AccessFs::from_read(abi);
  let all = AccessFs::from_all(abi);
  let mut ruleset = Ruleset::default()
    .handle_access(all)
    .map_err(|source| Error::Landlock { source })?
    .create()
    .map_err(|source| Error::Landlock { source })?;
  ruleset = add_path(ruleset, Path::new("/"), read)?;
  match policy {
    FsPolicy::ReadOnly { sink } => ruleset = add_path(ruleset, &sink, AccessFs::from_file(abi))?,
    FsPolicy::WorkspaceWrite { roots } => {
      ruleset = add_path(ruleset, Path::new("/dev/null"), AccessFs::from_file(abi))?;
      let mut seen = Vec::new();
      for root in &roots {
        if seen.iter().any(|existing: &PathBuf| existing == root) {
          continue;
        }
        seen.push(root.clone());
        ruleset = add_path(ruleset, root, all)?;
      }
    }
    FsPolicy::Unrestricted => {}
  }
  let status = ruleset.restrict_self().map_err(|source| Error::Landlock { source })?;
  require_full_enforcement(&status.ruleset)
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

async fn probe(plan: &LaunchPlan) -> Result<(), Error> {
  choose_runner(probe_bwrap(plan).await).map_err(Error::from)
}

async fn probe_bwrap(plan: &LaunchPlan) -> bool {
  let Ok(args) = bwrap_argv(plan, &[OsString::from("true")]) else {
    return false;
  };
  let Ok(status) = Command::new("bwrap")
    .args(args)
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

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_plan() -> LaunchPlan {
    LaunchPlan {
      profile: WriteProfile::ReadOnly,
      workspace: PathBuf::from("/work"),
      binds: Vec::new(),
      protected: Vec::new(),
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
  fn a_partial_or_unenforced_landlock_status_refuses_the_command() {
    let partial = require_full_enforcement(&RulesetStatus::PartiallyEnforced).unwrap_err();
    assert_eq!(partial.registration_detail(), "landlock did not enforce the profile");
    let absent = require_full_enforcement(&RulesetStatus::NotEnforced).unwrap_err();
    assert_eq!(absent.registration_detail(), "landlock did not enforce the profile");
    require_full_enforcement(&RulesetStatus::FullyEnforced).unwrap();
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
    let args = insert_plan(bwrap_argv(&sample_plan(), &[]).unwrap(), 7);
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
    let pid = std::process::id();
    let start = read_starttime(pid).unwrap();
    let err = session_cgroup(pid, start.wrapping_add(1)).unwrap_err();
    assert!(matches!(err, Error::SessionReused), "{err:?}");
  }

  #[tokio::test]
  async fn an_unplaced_peer_is_not_migrated_or_activated() {
    let pid = std::process::id();
    let before = read_cgroup(pid).unwrap();
    let start = read_starttime(pid).unwrap();
    let slot = session_cgroup(pid, start).unwrap();
    assert!(matches!(slot.confirm(), Err(Error::SessionReused)));
    release_session(&slot.path).await.unwrap();
    assert_eq!(read_cgroup(pid).unwrap(), before);
  }

  #[tokio::test]
  async fn a_live_unplaced_process_is_never_migrated() {
    let child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let mut child = Kill(child);
    let pid = child.0.id();
    let before = read_cgroup(pid).unwrap();
    let start = read_starttime(pid).unwrap();
    let slot = session_cgroup(pid, start).unwrap();
    assert!(matches!(slot.confirm(), Err(Error::SessionReused)));
    release_session(&slot.path).await.unwrap();
    assert_eq!(read_cgroup(pid).unwrap(), before);
    assert!(child.0.try_wait().unwrap().is_none());
  }

  #[tokio::test]
  async fn releasing_a_session_kills_its_members_without_moving_other_processes() {
    use std::io::BufRead as _;

    let pid = std::process::id();
    let slot = session_cgroup(pid, read_starttime(pid).unwrap()).unwrap();
    let mut unrelated = Kill(
      std::process::Command::new("cat")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap(),
    );
    let before = read_cgroup(unrelated.0.id()).unwrap();
    let mut member = Kill(
      std::process::Command::new("sh")
        .arg("-c")
        .arg("printf 0 > \"$1/cgroup.procs\" || exit 1; echo ready; read done")
        .arg("member")
        .arg(&slot.path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap(),
    );
    let mut line = String::new();
    std::io::BufReader::new(member.0.stdout.take().unwrap())
      .read_line(&mut line)
      .unwrap();
    assert_eq!(line, "ready\n");
    release_session(&slot.path).await.unwrap();
    assert!(!member.0.wait().unwrap().success());
    assert!(unrelated.0.try_wait().unwrap().is_none());
    assert_eq!(read_cgroup(unrelated.0.id()).unwrap(), before);
  }

  #[test]
  fn a_world_writable_runtime_dir_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
    perms.set_mode(0o777);
    std::fs::set_permissions(dir.path(), perms).unwrap();
    // SAFETY: this test process does not share its environment with another test.
    unsafe { std::env::set_var("XDG_RUNTIME_DIR", dir.path()) };
    let err = ensure_socket_dir().unwrap_err();
    let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o777, "the runtime dir was repaired instead of refused");
    assert_eq!(err.to_string(), "XDG_RUNTIME_DIR is unset or not private");
    assert!(!dir.path().join("arkham").exists());
  }

  #[test]
  fn an_unset_runtime_dir_is_refused() {
    // SAFETY: this test process does not share its environment with another test.
    unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
    let err = ensure_socket_dir().unwrap_err();
    assert_eq!(err.to_string(), "XDG_RUNTIME_DIR is unset or not private");
  }

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

    let cwd = launch_cwd(Some(&link)).unwrap();
    assert_eq!(cwd, target);
    assert_eq!(crate::project_root(&cwd, &[]), Some(target.clone()));
    assert_eq!(crate::project_root(&link, &[]), Some(target));
  }

  #[test]
  fn launch_cwd_without_a_workspace_is_the_canonical_current_directory() {
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    assert_eq!(launch_cwd(None).unwrap(), cwd);
  }
}
