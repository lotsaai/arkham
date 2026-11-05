//! Linux launcher: probe bubblewrap, then Landlock, then exec.
//!
//! This module also owns the session cgroup. The daemon calls it before
//! handing the plan back, and re-reads the start time immediately before
//! writing `cgroup.procs`.

use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};

use arkham_config::{Enforcement, FsPolicy, RunnerKind, WriteProfile, choose_runner, fs_policy};
use landlock::{ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus};
use tokio::process::Command;

use crate::Error;
use crate::host::discover::parse_starttime;
use crate::host::plan::{LaunchPlan, TEMP_DIR, bwrap_argv};
use crate::host::protocol::{RegisterRequest, RegisterResponse, daemon_socket_path, read_line, write_line};

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
/// The start time is read again immediately before the write.
///
/// # Errors
///
/// Returns an error when the cgroup cannot be created, the start time
/// changed, or the process cannot be moved.
pub fn create_session(pid: u32, starttime: u64) -> Result<SessionSlot, Error> {
  let parent = host_cgroup()?;
  let path = parent.join(format!("{pid}-{starttime}"));
  std::fs::create_dir(&path)?;
  let now = read_starttime(pid)?;
  if now != starttime {
    let _ = std::fs::remove_dir(&path);
    return Err(Error::SessionReused);
  }
  std::fs::write(path.join("cgroup.procs"), pid.to_string())?;
  let id = std::fs::metadata(&path)?.ino();
  Ok(SessionSlot { path, id })
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
  std::fs::create_dir_all(&parent)?;
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
/// # Errors
///
/// Returns an error when the directory cannot be created.
pub fn ensure_socket_dir() -> Result<PathBuf, Error> {
  let path = daemon_socket_path();
  if let Some(dir) = path.parent() {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
  }
  Ok(path)
}

/// Connect to the daemon, register, probe, and run `command`.
///
/// The process exits with the child's status. No child is started when the
/// daemon is absent or no runner accepts the profile.
///
/// # Errors
///
/// Returns an error when registration or the probe fails. A running child
/// replaces this return with [`std::process::exit`].
pub async fn agent(profile: WriteProfile, command: &[OsString]) -> Result<(), Error> {
  let mut stream = tokio::net::UnixStream::connect(daemon_socket_path()).await.map_err(|source| {
    tracing::debug!(%source, "no host daemon");
    Error::NoDaemon
  })?;
  let request = RegisterRequest {
    cwd: std::env::current_dir()?,
    profile,
  };
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
  let word = match choice.enforcement {
    Enforcement::Full => "full",
    Enforcement::Partial => "partial",
  };
  eprintln!("enforcement: {word}");
  let mut child = match choice.runner {
    RunnerKind::Bwrap => Command::new("bwrap").args(bwrap_argv(&plan, command)).spawn()?,
    RunnerKind::Landlock => {
      let path = plan_file(&plan)?;
      Command::new(std::env::current_exe()?)
        .arg("--landlock-exec")
        .arg(&path)
        .arg("--")
        .args(command_or_shell(command, &plan))
        .spawn()?
    }
  };
  let status = child.wait().await?;
  drop(stream);
  std::process::exit(status.code().unwrap_or(1));
}

/// Apply the plan's Landlock rules and replace this process with the command.
///
/// Invoked as `arkham --landlock-exec <plan> [--report] -- <command>`.
///
/// # Errors
///
/// Returns an error when the plan cannot be read or Landlock rejects it.
/// A successful call does not return: it execs the command.
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
  let enforcement = apply_landlock(&plan)?;
  if report {
    let word = match enforcement {
      Enforcement::Full => "full",
      Enforcement::Partial => "partial",
    };
    eprintln!("enforcement: {word}");
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
    RulesetStatus::PartiallyEnforced => Ok(Enforcement::Partial),
    RulesetStatus::NotEnforced => {
      std::process::exit(1);
    }
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
  let bwrap = probe_bwrap(plan).await;
  let landlock = probe_landlock(plan).await;
  choose_runner(bwrap, landlock).map_err(Error::from)
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

async fn probe_landlock(plan: &LaunchPlan) -> Option<Enforcement> {
  let path = plan_file(plan).ok()?;
  let output = Command::new(std::env::current_exe().ok()?)
    .arg("--landlock-exec")
    .arg(&path)
    .arg("--report")
    .arg("--")
    .arg("true")
    .output()
    .await
    .ok()?;
  let _ = std::fs::remove_file(&path);
  if !output.status.success() {
    return None;
  }
  let text = String::from_utf8_lossy(&output.stderr);
  if text.contains("enforcement: full") {
    Some(Enforcement::Full)
  } else if text.contains("enforcement: partial") {
    Some(Enforcement::Partial)
  } else {
    None
  }
}

fn plan_file(plan: &LaunchPlan) -> Result<PathBuf, Error> {
  let path = std::env::temp_dir().join(format!("arkham-plan-{}.json", std::process::id()));
  std::fs::write(&path, serde_json::to_vec(plan).map_err(|source| Error::ControlMessage { source })?)?;
  Ok(path)
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
