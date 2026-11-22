//! Linux launcher. Bubblewrap is the only runner. Landlock adds restrictions
//! inside that sandbox and never starts a process of its own.
//!
//! This module also owns the session cgroup. The wrapper joins itself and
//! waits for the daemon to authenticate placement before launching.

use std::ffi::OsString;
use std::io::{Seek as _, Write as _};
#[cfg(test)]
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};

use arkham_config::{FsPolicy, WriteProfile, choose_runner, fs_policy};
use landlock::{ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus};
use tokio::process::Command;

use crate::Error;
#[cfg(test)]
use crate::cgroup::{read_cgroup, read_starttime, release_session, session_cgroup, session_cgroup_io};
use crate::plan::bwrap_argv;
use arkham_launch_plan::{LaunchPlan, PRIVATE_SESSION_ROOT};

/// Path of the plan inside the sandbox. The bytes come from a memfd.
const PLAN_DEST: &str = "/arkham/plan.json";

/// Spawn the confined command using the supplied executable for Landlock.
///
/// # Errors
/// Returns an error if the runner probe, plan handoff, or spawn fails.
pub async fn spawn(plan: &LaunchPlan, command: &[OsString], executable: &Path) -> Result<tokio::process::Child, Error> {
  let inner = sandboxed_command(plan, command, executable);
  let argv = bwrap_argv(plan, &inner)?;
  probe(plan).await?;
  eprintln!("runner: bwrap");
  eprintln!("enforcement: full");
  let plan_file = plan_memfd(plan)?;
  let plan_fd = plan_file.as_raw_fd();
  let mut child_cmd = Command::new("bwrap");
  child_cmd.args(insert_plan(argv, plan_fd));
  // SAFETY: fcntl runs in the forked child while the parent retains the memfd.
  unsafe { child_cmd.pre_exec(move || clear_cloexec(plan_fd)) };
  Ok(child_cmd.spawn()?)
}

fn sandboxed_command(plan: &LaunchPlan, command: &[OsString], executable: &Path) -> Vec<OsString> {
  let mut inner = vec![
    executable.as_os_str().to_os_string(),
    OsString::from("--landlock-exec"),
    OsString::from(PLAN_DEST),
    OsString::from("--"),
  ];
  inner.extend(command_or_shell(command, plan));
  inner
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
pub fn landlock_exec(plan_path: &Path, command: &[OsString]) -> Result<(), Error> {
  let text = std::fs::read(plan_path)?;
  let plan: LaunchPlan = serde_json::from_slice(&text).map_err(|source| Error::ControlMessage { source })?;
  if plan.profile != WriteProfile::DangerFullAccess {
    apply_landlock(&plan)?;
  }
  let command = if command.is_empty() {
    vec![OsString::from(plan.shell)]
  } else {
    command.to_vec()
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
  let policy = fs_policy(plan.profile, &plan.workspace, Path::new(PRIVATE_SESSION_ROOT));
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
    crate::host_cgroup().await.unwrap();
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
    crate::host_cgroup().await.unwrap();
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

    crate::host_cgroup().await.unwrap();
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
}
