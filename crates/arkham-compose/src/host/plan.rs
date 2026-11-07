//! Bubblewrap argv from one launch plan.
//!
//! The writable set comes from [`arkham_config::fs_policy`]. This renderer
//! does not invent roots. The sandbox root is a tmpfs. System directories
//! and the enlisted workspace are mounted onto it. `$HOME` is not. A bind of
//! the host root cannot hold `/arkham`, because creating that directory
//! would write the host filesystem or fail on the read-only mount.

#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;

use arkham_config::WriteProfile;
#[cfg(target_os = "linux")]
use arkham_config::{FsPolicy, fs_policy};

#[cfg(target_os = "linux")]
use crate::Error;
use serde::{Deserialize, Serialize};

/// One bind the agent sees. `source` is the file the daemon wrote. `dest`
/// is the path inside the sandbox, which for a host session is the real path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bind {
  /// Host path of the projected bytes.
  pub source: PathBuf,
  /// Path the agent opens.
  pub dest: PathBuf,
  /// When set, the bind is read-only even if the profile allows writes.
  pub read_only: bool,
}

/// What the wrapper needs to launch. Real secrets never appear here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchPlan {
  /// Write profile the operator asked for.
  pub profile: WriteProfile,
  /// Workspace root.
  pub workspace: PathBuf,
  /// Projected files and the mounts compose would have made.
  pub binds: Vec<Bind>,
  /// Existing configuration paths and aliases hidden from the agent.
  pub protected: Vec<PathBuf>,
  /// Certificate PEM, without the CA key.
  pub ca_host: PathBuf,
  /// Where the certificate is mounted.
  pub ca_dest: PathBuf,
  /// Environment after `clearenv`: decoys, CA paths, and the kept names.
  pub env: Vec<(String, String)>,
  /// Working directory.
  pub workdir: PathBuf,
  /// Shell used when the wrapper was given no command.
  pub shell: String,
}

/// Container path of the CA certificate.
pub const CA_DEST: &str = "/arkham/ca.pem";

/// Temp directory the workspace-write profile passes to [`fs_policy`].
#[cfg(target_os = "linux")]
pub const TEMP_DIR: &str = super::discover::PRIVATE_SESSION_ROOT;

/// Argv for `bwrap`, not including the `bwrap` program name.
///
/// `/` is remounted read-only after the mounts are in place. Mounts created
/// before that keep the flags they were given. A workspace-write session
/// gets a fresh tmpfs at `/tmp`. Host directories under `/tmp` are not
/// mounted. The daemon has already moved this process into its session
/// cgroup. `--unshare-cgroup` makes that cgroup the namespace root, and the
/// host `/sys/fs/cgroup` tree is not mounted, so another session's cgroup
/// is not a path in the sandbox. The launch probe runs this argv. A kernel
/// that refuses the cgroup namespace fails the probe, and the agent does
/// not start.
///
/// # Errors
///
/// Returns [`Error::SessionTmp`] when a bind source is a directory under
/// the host `/tmp`. A workspace of `/tmp` is the private session tmpfs and
/// is not a host bind.
#[cfg(target_os = "linux")]
pub fn bwrap_argv(plan: &LaunchPlan, command: &[OsString]) -> Result<Vec<OsString>, Error> {
  reject_host_tmp(plan)?;
  let policy = fs_policy(plan.profile, &plan.workspace, Path::new(TEMP_DIR));
  let workspace_write = matches!(policy, FsPolicy::WorkspaceWrite { .. });
  let mut args = Vec::new();
  args.extend(["--tmpfs".into(), "/".into()]);
  let mut bound = Vec::new();
  let mut anchors = Vec::new();
  push_host_entries(&mut args, &mut bound, matches!(policy, FsPolicy::Unrestricted));
  args.extend(["--dev".into(), "/dev".into(), "--proc".into(), "/proc".into()]);
  args.extend([
    "--unshare-user".into(),
    "--unshare-pid".into(),
    "--unshare-uts".into(),
    "--unshare-ipc".into(),
    "--unshare-cgroup".into(),
    "--cap-drop".into(),
    "ALL".into(),
  ]);
  let private_session = plan.workspace == Path::new(TEMP_DIR);
  if workspace_write || private_session {
    args.extend(["--tmpfs".into(), TEMP_DIR.into()]);
    anchors.push(PathBuf::from(TEMP_DIR));
  }
  let workspace_flag = if workspace_write || matches!(policy, FsPolicy::Unrestricted) {
    "--bind"
  } else {
    "--ro-bind"
  };
  let mut created = BTreeSet::new();
  if !private_session {
    push_missing_parents(&mut args, &bound, &anchors, &plan.workspace, &mut created);
    args.extend([workspace_flag.into(), plan.workspace.clone().into(), plan.workspace.clone().into()]);
    bound.push(plan.workspace.clone());
  }
  for bind in &plan.binds {
    if bind.dest == plan.workspace {
      continue;
    }
    push_missing_parents(&mut args, &bound, &anchors, &bind.dest, &mut created);
    let flag = bind_flag(plan.profile, bind.read_only);
    args.extend([flag.into(), bind.source.clone().into(), bind.dest.clone().into()]);
    bound.push(bind.dest.clone());
  }
  args.extend(["--dir".into(), "/arkham".into()]);
  args.extend(["--ro-bind".into(), plan.ca_host.clone().into(), plan.ca_dest.clone().into()]);
  push_program(&mut args, &bound, &anchors, command, &mut created);
  push_config_masks(&mut args, plan, &bound, &anchors);
  push_secret_masks(&mut args, plan, &bound, &anchors);
  if private_session && matches!(policy, FsPolicy::ReadOnly { .. }) {
    args.extend(["--remount-ro".into(), TEMP_DIR.into()]);
  }
  args.extend(["--remount-ro".into(), "/".into()]);
  args.extend(["--die-with-parent".into(), "--new-session".into(), "--clearenv".into()]);
  for (key, value) in &plan.env {
    args.extend(["--setenv".into(), key.into(), value.into()]);
  }
  args.extend(["--chdir".into(), plan.workdir.clone().into()]);
  args.push("--".into());
  if command.is_empty() {
    args.push(plan.shell.clone().into());
  } else {
    args.extend(command.iter().cloned());
  }
  Ok(args)
}

/// System directories the sandbox can see.
///
/// The enlisted workspace is mounted on its own. `$HOME`, `/root`, and every
/// other top-level directory stay on the tmpfs, so a credential or the CA
/// key that lives there is not a path the agent can open.
#[cfg(target_os = "linux")]
pub(super) const SYSTEM_ROOTS: &[&str] = &["bin", "etc", "lib", "lib64", "opt", "sbin", "usr"];

/// Host files under `/etc` that stay hidden when `/etc` itself is mounted.
#[cfg(target_os = "linux")]
const ETC_SECRET_FILES: &[&str] = &["/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/security/opasswd"];

/// Host directories under `/etc` replaced with an empty tmpfs.
#[cfg(target_os = "linux")]
const ETC_SECRET_DIRS: &[&str] = &["/etc/ssh", "/etc/ssl/private", "/etc/sudoers.d"];

/// Mount the system directories the session needs.
///
/// Symlinks such as `/bin` -> `usr/bin` are recreated. A missing name is
/// skipped. Real directories are recorded in `bound` so later masks can tell
/// which host files are actually visible.
#[cfg(target_os = "linux")]
fn push_host_entries(args: &mut Vec<OsString>, bound: &mut Vec<PathBuf>, writable: bool) {
  for name in SYSTEM_ROOTS {
    let dest = PathBuf::from("/").join(name);
    let Ok(meta) = std::fs::symlink_metadata(&dest) else {
      continue;
    };
    if meta.file_type().is_symlink() {
      let Ok(target) = std::fs::read_link(&dest) else {
        continue;
      };
      args.extend(["--symlink".into(), target.into_os_string(), dest.into_os_string()]);
      continue;
    }
    if meta.is_dir() || meta.is_file() {
      let flag = if writable { "--bind" } else { "--ro-bind" };
      let path = dest.clone().into_os_string();
      args.extend([flag.into(), path.clone(), path]);
      bound.push(dest);
    }
  }
}

/// Create parents of `dest` that are not already inside a mounted directory.
///
/// A file bind whose parent was never mounted otherwise fails, or bubblewrap
/// refuses the mount. The created directories are empty, so siblings of the
/// bound file are not part of the sandbox.
#[cfg(target_os = "linux")]
fn push_missing_parents(args: &mut Vec<OsString>, bound: &[PathBuf], anchors: &[PathBuf], dest: &Path, created: &mut BTreeSet<PathBuf>) {
  let Some(parent) = dest.parent() else {
    return;
  };
  if parent == Path::new("/") || is_mounted(parent, bound, anchors) {
    return;
  }
  let mut chain = Vec::new();
  let mut cursor = Some(parent);
  while let Some(dir) = cursor {
    if dir == Path::new("/") || is_mounted(dir, bound, anchors) || created.contains(dir) {
      break;
    }
    chain.push(dir.to_path_buf());
    cursor = dir.parent();
  }
  for dir in chain.iter().rev() {
    if created.insert(dir.clone()) {
      args.extend(["--dir".into(), dir.clone().into()]);
    }
  }
}

/// `anchors` are mounted exactly. A path under an anchor is not covered, so
/// its parents are created empty inside that mount.
#[cfg(target_os = "linux")]
fn is_mounted(path: &Path, bound: &[PathBuf], anchors: &[PathBuf]) -> bool {
  if anchors.iter().any(|anchor| path == anchor) {
    return true;
  }
  bound.iter().any(|root| path == root || path.starts_with(root))
}

#[cfg(target_os = "linux")]
fn host_path<'a>(path: &'a Path, binds: &'a [Bind]) -> std::borrow::Cow<'a, Path> {
  match binds
    .iter()
    .filter(|bind| path.starts_with(&bind.dest))
    .max_by_key(|bind| bind.dest.components().count())
  {
    Some(bind) => match path.strip_prefix(&bind.dest) {
      Ok(relative) => std::borrow::Cow::Owned(bind.source.join(relative)),
      Err(_) => std::borrow::Cow::Borrowed(path),
    },
    None => std::borrow::Cow::Borrowed(path),
  }
}

#[cfg(target_os = "linux")]
fn push_config_masks(args: &mut Vec<OsString>, plan: &LaunchPlan, bound: &[PathBuf], anchors: &[PathBuf]) {
  let mut masked_dirs = Vec::new();
  let mut targets = Vec::new();
  for path in &plan.protected {
    if !is_mounted(path, bound, anchors) || masked_dirs.iter().any(|dir: &PathBuf| path.starts_with(dir)) {
      continue;
    }
    if host_path(path, &plan.binds).is_dir() {
      masked_dirs.push(path.clone());
    }
    targets.push(path);
  }

  let mut parents = BTreeSet::new();
  for target in &targets {
    for parent in target.ancestors().skip(1) {
      if !is_mounted(parent, bound, anchors) || bound.iter().any(|root| root == parent) {
        break;
      }
      if host_path(parent, &plan.binds).is_dir() {
        parents.insert(parent.to_path_buf());
      }
    }
  }
  for parent in &parents {
    let read_only = plan
      .binds
      .iter()
      .filter(|bind| parent.starts_with(&bind.dest))
      .max_by_key(|bind| bind.dest.components().count())
      .map_or(
        !parent.starts_with(&plan.workspace) && plan.profile != WriteProfile::DangerFullAccess,
        |bind| bind.read_only,
      );
    let flag = bind_flag(plan.profile, read_only);
    args.extend([
      flag.into(),
      host_path(parent, &plan.binds).into_owned().into(),
      parent.clone().into(),
    ]);
  }
  for bind in &plan.binds {
    if parents.iter().any(|parent| bind.dest.starts_with(parent)) {
      let flag = bind_flag(plan.profile, bind.read_only);
      args.extend([flag.into(), bind.source.clone().into(), bind.dest.clone().into()]);
    }
  }
  for path in targets {
    if host_path(path, &plan.binds).is_dir() {
      args.extend(["--tmpfs".into(), path.clone().into(), "--remount-ro".into(), path.clone().into()]);
    } else if host_path(path, &plan.binds).is_file() {
      args.extend(["--ro-bind".into(), "/dev/null".into(), path.clone().into()]);
    }
  }
}

/// Hide host secret files that sit inside a directory the sandbox mounted.
///
/// `/etc` is one of those directories. The CA key beside the certificate is
/// too, when its directory was mounted. A key outside every mount is already
/// absent and must not be named: bubblewrap rejects a bind whose parent does
/// not exist.
#[cfg(target_os = "linux")]
fn push_secret_masks(args: &mut Vec<OsString>, plan: &LaunchPlan, bound: &[PathBuf], anchors: &[PathBuf]) {
  for path in ETC_SECRET_FILES {
    mask_file(args, Path::new(path), bound, anchors);
  }
  for path in ETC_SECRET_DIRS {
    let path = Path::new(path);
    if path.is_dir() && is_mounted(path, bound, anchors) {
      args.extend(["--tmpfs".into(), path.into()]);
    }
  }
  mask_file(args, &plan.ca_host.with_extension("key"), bound, anchors);
}

/// Mount the absolute program the sandbox execs, when it is not already
/// inside a mounted directory.
///
/// The runner re-execs this binary to apply Landlock. Binding the file,
/// not its parent tree, keeps the rest of that tree out of the sandbox.
#[cfg(target_os = "linux")]
fn push_program(args: &mut Vec<OsString>, bound: &[PathBuf], anchors: &[PathBuf], command: &[OsString], created: &mut BTreeSet<PathBuf>) {
  let Some(program) = command.first() else {
    return;
  };
  let path = Path::new(program);
  if !path.is_absolute() || !path.is_file() || is_mounted(path, bound, anchors) {
    return;
  }
  push_missing_parents(args, bound, anchors, path, created);
  let program = path.as_os_str().to_os_string();
  args.extend(["--ro-bind".into(), program.clone(), program]);
}

#[cfg(target_os = "linux")]
fn mask_file(args: &mut Vec<OsString>, path: &Path, bound: &[PathBuf], anchors: &[PathBuf]) {
  if !path.is_file() {
    return;
  }
  let Some(parent) = path.parent() else {
    return;
  };
  if !is_mounted(parent, bound, anchors) {
    return;
  }
  args.extend(["--ro-bind".into(), "/dev/null".into(), path.into()]);
}

#[cfg(target_os = "linux")]
fn reject_host_tmp(plan: &LaunchPlan) -> Result<(), Error> {
  for bind in &plan.binds {
    if host_tmp_directory(&bind.source, &plan.workspace) {
      return Err(session_tmp_error());
    }
  }
  Ok(())
}

/// A directory under the host `/tmp`, other than the workspace. A missing
/// path fails closed. A regular file does not.
#[cfg(target_os = "linux")]
fn host_tmp_directory(source: &Path, workspace: &Path) -> bool {
  if source.as_os_str().is_empty() || (source == workspace && workspace != Path::new(TEMP_DIR)) {
    return false;
  }
  let tmp = Path::new(TEMP_DIR);
  if source != tmp && !source.starts_with(tmp) {
    return false;
  }
  !matches!(std::fs::symlink_metadata(source), Ok(meta) if meta.file_type().is_file())
}

#[cfg(target_os = "linux")]
fn session_tmp_error() -> Error {
  Error::SessionTmp {
    source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "session tmp is not a private directory"),
  }
}

#[cfg(target_os = "linux")]
fn bind_flag(profile: WriteProfile, read_only: bool) -> &'static str {
  if read_only || profile == WriteProfile::ReadOnly {
    "--ro-bind"
  } else {
    "--bind"
  }
}

/// Whether `name` is a proxy variable the sandbox must not carry.
#[must_use]
pub fn is_proxy_env(name: &str) -> bool {
  matches!(name.to_ascii_lowercase().as_str(), "http_proxy" | "https_proxy" | "all_proxy")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
  use super::*;

  fn plan(profile: WriteProfile) -> LaunchPlan {
    LaunchPlan {
      profile,
      workspace: PathBuf::from("/work"),
      binds: vec![Bind {
        source: PathBuf::from("/scratch/fnox.toml"),
        dest: PathBuf::from("/work/fnox.toml"),
        read_only: true,
      }],
      protected: Vec::new(),
      ca_host: PathBuf::from("/scratch/ca.pem"),
      ca_dest: PathBuf::from(CA_DEST),
      env: vec![("SSL_CERT_FILE".into(), CA_DEST.into()), ("GITHUB_TOKEN".into(), "decoy".into())],
      workdir: PathBuf::from("/work"),
      shell: "sh".into(),
    }
  }

  fn argv(plan: &LaunchPlan, command: &[OsString]) -> Vec<OsString> {
    bwrap_argv(plan, command).unwrap()
  }

  fn joined(args: &[OsString]) -> String {
    args.iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>().join(" ")
  }

  fn has_pair(args: &[OsString], flag: &str, value: &str) -> bool {
    args.windows(2).any(|window| window[0] == flag && window[1] == value)
  }

  fn has_triple(args: &[OsString], flag: &str, source: &str, dest: &str) -> bool {
    args
      .windows(3)
      .any(|window| window[0] == flag && window[1] == source && window[2] == dest)
  }

  #[test]
  fn workspace_write_matches_the_profile_and_omits_proxy_env() {
    let args = argv(&plan(WriteProfile::WorkspaceWrite), &["cargo".into(), "test".into()]);
    let text = joined(&args);
    assert!(has_pair(&args, "--tmpfs", "/"));
    assert!(has_pair(&args, "--remount-ro", "/"));
    assert!(!has_triple(&args, "--ro-bind", "/", "/"));
    assert!(!has_triple(&args, "--bind", "/", "/"));
    assert!(text.contains("--dev /dev --proc /proc"));
    assert!(text.contains("--unshare-pid --unshare-uts --unshare-ipc --unshare-cgroup"));
    assert!(has_pair(&args, "--tmpfs", "/tmp"));
    assert!(text.contains("--bind /work /work"));
    assert!(text.contains("--ro-bind /scratch/fnox.toml /work/fnox.toml"));
    assert!(text.contains("--dir /arkham"));
    assert!(text.contains("--ro-bind /scratch/ca.pem /arkham/ca.pem"));
    assert!(text.contains("--die-with-parent --new-session --clearenv"));
    assert!(text.contains("--setenv SSL_CERT_FILE /arkham/ca.pem"));
    assert!(text.contains("--setenv GITHUB_TOKEN decoy"));
    assert!(text.contains("--chdir /work -- cargo test"));
    assert!(!text.contains("--unshare-net"));
    assert!(!text.to_ascii_lowercase().contains("http_proxy"));
    assert!(!text.contains("/sys/fs/cgroup"));
    let dir = args.iter().position(|arg| arg == "--dir").unwrap();
    let remount = args.iter().position(|arg| arg == "--remount-ro").unwrap();
    assert!(dir < remount);
  }

  #[test]
  fn read_only_drops_the_workspace_bind_and_the_tmpfs() {
    let args = argv(&plan(WriteProfile::ReadOnly), &[]);
    let text = joined(&args);
    assert!(has_pair(&args, "--tmpfs", "/"));
    assert!(!has_pair(&args, "--tmpfs", "/tmp"));
    assert!(!has_triple(&args, "--bind", "/work", "/work"));
    assert!(has_triple(&args, "--ro-bind", "/work", "/work"));
    assert!(text.contains("-- sh"));
    assert!(text.contains("--ro-bind /scratch/fnox.toml /work/fnox.toml"));
  }

  #[test]
  fn a_sandbox_does_not_expose_another_sessions_cgroup() {
    use std::io::Write as _;

    for profile in [WriteProfile::ReadOnly, WriteProfile::WorkspaceWrite, WriteProfile::DangerFullAccess] {
      let args = argv(&plan(profile), &[]);
      assert!(
        !args.windows(3).any(|window| {
          (window[0] == "--bind" || window[0] == "--ro-bind") && (window[1] == "/sys/fs/cgroup" || window[2] == "/sys/fs/cgroup")
        }),
        "host cgroup tree is mounted\n{}",
        joined(&args)
      );
      assert!(args.iter().any(|arg| arg == "--unshare-cgroup"), "{}", joined(&args));
    }

    let scratch = tempfile::tempdir().unwrap();
    let ca = scratch.path().join("ca.pem");
    std::fs::write(&ca, "CERT\n").unwrap();
    let mut launched = plan(WriteProfile::WorkspaceWrite);
    launched.workspace = PathBuf::from("/tmp");
    launched.workdir = PathBuf::from("/tmp");
    launched.binds.clear();
    launched.ca_host = ca;
    let parent = super::super::linux::host_cgroup().unwrap();
    let sibling = parent.join(format!("other-session-{}", std::process::id()));
    let _sibling = RemoveDir(sibling.clone());
    std::fs::create_dir(&sibling).unwrap();
    let script = format!(
      "if [ -e '{}' ]; then echo SIBLING:visible; else echo SIBLING:hidden; fi; printf '%s\\n' \"PROC:$(tr '\\n' ' ' < /proc/self/cgroup)\"; sleep 1",
      sibling.display()
    );
    let ran_args = argv(&launched, &["sh".into(), "-c".into(), script.into()]);
    let mut child = StopChild(Some(
      std::process::Command::new("sh")
        .arg("-c")
        .arg("read _; exec \"$@\"")
        .arg("bwrap")
        .arg("bwrap")
        .args(&ran_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap(),
    ));
    let pid = child.0.as_ref().unwrap().id();
    let start = super::super::linux::read_starttime(pid).unwrap();
    let slot = super::super::linux::session_cgroup(pid, start).unwrap();
    let _session = ReleaseSession(slot.path.clone());
    child.0.as_mut().unwrap().stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    drop(child.0.as_mut().unwrap().stdin.take());
    std::thread::sleep(std::time::Duration::from_millis(400));
    let seen = host_cgroup_id(pid);
    assert_eq!(seen, slot.id, "sandbox cgroup id diverged from the session directory");
    let children = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap();
    let mut descendants = 0u32;
    for child_pid in children.split_whitespace() {
      let child_pid: u32 = child_pid.parse().unwrap();
      assert_eq!(host_cgroup_id(child_pid), slot.id, "sandboxed command left the session cgroup");
      descendants = descendants.saturating_add(1);
    }
    assert!(descendants > 0, "bwrap started no child in the session cgroup");
    let ran = child.wait();
    let stdout = String::from_utf8_lossy(&ran.stdout);
    let stderr = String::from_utf8_lossy(&ran.stderr);
    assert!(ran.status.success(), "{stdout}{stderr}\n{}", joined(&ran_args));
    assert_eq!(line_of(&stdout, "SIBLING"), "hidden", "{stdout}{stderr}");
    assert_eq!(line_of(&stdout, "PROC").trim(), "0::/", "{stdout}{stderr}");
  }

  /// Inode `bpf_get_current_cgroup_id` reports: the host view of `/proc/<pid>/cgroup`.
  fn host_cgroup_id(pid: u32) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    let own = text.lines().find_map(|line| line.strip_prefix("0::")).unwrap();
    std::fs::metadata(Path::new("/sys/fs/cgroup").join(own.trim_start_matches('/')))
      .unwrap()
      .ino()
  }

  struct RemoveDir(PathBuf);

  impl Drop for RemoveDir {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir(&self.0);
    }
  }

  struct ReleaseSession(PathBuf);

  impl Drop for ReleaseSession {
    fn drop(&mut self) {
      super::super::linux::release_session(&self.0);
    }
  }

  struct StopChild(Option<std::process::Child>);

  impl StopChild {
    fn wait(mut self) -> std::process::Output {
      self.0.take().unwrap().wait_with_output().unwrap()
    }
  }

  impl Drop for StopChild {
    fn drop(&mut self) {
      if let Some(child) = self.0.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
      }
    }
  }

  #[test]
  fn the_sandbox_drops_every_capability() {
    let args = argv(&plan(WriteProfile::WorkspaceWrite), &[]);
    let text = joined(&args);
    assert!(text.contains("--unshare-user"), "{text}");
    assert!(text.contains("--cap-drop ALL"), "{text}");
    assert!(!text.contains("--unshare-net"), "{text}");
  }

  #[test]
  fn the_sandbox_does_not_bind_the_home_directory_or_the_ca_key() {
    let root = tempfile::tempdir().unwrap();
    let ca = root.path().join("ca.pem");
    let key = root.path().join("ca.key");
    std::fs::write(&ca, "CERT\n").unwrap();
    std::fs::write(&key, "CA_KEY_MARKER\n").unwrap();
    let mut plan = plan(WriteProfile::WorkspaceWrite);
    plan.ca_host = ca;
    let args = argv(&plan, &[]);
    assert!(!has_triple(&args, "--ro-bind", "/home", "/home"), "{}", joined(&args));
    assert!(!has_triple(&args, "--bind", "/home", "/home"), "{}", joined(&args));
    assert!(!has_triple(&args, "--ro-bind", "/root", "/root"), "{}", joined(&args));
    assert!(!has_triple(&args, "--bind", "/root", "/root"), "{}", joined(&args));
    assert!(
      !args
        .windows(3)
        .any(|window| { (window[0] == "--ro-bind" || window[0] == "--bind") && window[1] == key.as_os_str() }),
      "the CA key is a bind source\n{}",
      joined(&args)
    );
  }

  #[test]
  fn translated_bind_masks_use_host_sources_and_sandbox_destinations() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let dest = root.path().join("destination");
    std::fs::create_dir_all(source.join("inner")).unwrap();
    std::fs::create_dir(&dest).unwrap();
    std::fs::write(source.join("inner/secret"), "PRIVATE_CONTENT").unwrap();
    let mut plan = plan(WriteProfile::WorkspaceWrite);
    plan.binds = vec![Bind {
      source: source.clone(),
      dest: dest.clone(),
      read_only: false,
    }];
    plan.protected = vec![dest.join("inner/secret")];
    let mut args = vec![
      OsString::from("--unshare-user"),
      OsString::from("--ro-bind"),
      OsString::from("/"),
      OsString::from("/"),
      OsString::from("--bind"),
      source.clone().into(),
      dest.clone().into(),
    ];
    push_config_masks(&mut args, &plan, std::slice::from_ref(&dest), &[]);
    let script = format!(
      "if cat '{0}/inner/secret' 2>/dev/null | grep -q PRIVATE_CONTENT; then exit 1; fi; \
       if rm '{0}/inner/secret' 2>/dev/null; then exit 2; fi; \
       if mv '{0}/inner' '{0}/moved' 2>/dev/null; then exit 3; fi; \
       echo sibling > '{0}/inner/unrelated'",
      dest.display()
    );
    let output = std::process::Command::new("bwrap")
      .args(args)
      .args(["--", "sh", "-c", &script])
      .output()
      .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(std::fs::read_to_string(source.join("inner/secret")).unwrap(), "PRIVATE_CONTENT");
    assert_eq!(std::fs::read_to_string(source.join("inner/unrelated")).unwrap(), "sibling\n");
  }

  #[test]
  fn a_privileged_sandbox_cannot_unmount_an_overlay() {
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("work");
    std::fs::create_dir(&workspace).unwrap();
    let secret = workspace.join("fnox.toml");
    std::fs::write(&secret, "REAL_SECRET_VALUE\n").unwrap();
    let forged = root.path().join("forged.toml");
    std::fs::write(&forged, "# arkham projection\nvalue = \"arkham-decoy\"\n").unwrap();
    let ca = root.path().join("ca.pem");
    std::fs::write(&ca, "CERT\n").unwrap();
    let plan = LaunchPlan {
      profile: WriteProfile::WorkspaceWrite,
      workspace: workspace.clone(),
      binds: vec![Bind {
        source: forged,
        dest: secret.clone(),
        read_only: true,
      }],
      protected: Vec::new(),
      ca_host: ca,
      ca_dest: PathBuf::from(CA_DEST),
      env: vec![("PATH".into(), "/usr/bin:/bin".into())],
      workdir: workspace,
      shell: "sh".into(),
    };
    let script = format!(
      "umount '{}'; echo UMOUNT:$?; mount -o remount,rw /; echo REMOUNT:$?; echo CAP:$(awk '/CapEff/ {{print $2}}' /proc/self/status); echo FILE:$(cat '{}' | tr '\\n' ' ')",
      secret.display(),
      secret.display()
    );
    let args = argv(&plan, &["sh".into(), "-c".into(), script.into()]);
    let output = std::process::Command::new("sudo")
      .arg("-n")
      .arg("bwrap")
      .args(&args)
      .output()
      .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}{stderr}\n{}", joined(&args));
    assert_ne!(line_of(&stdout, "UMOUNT"), "0", "{stdout}{stderr}");
    assert_ne!(line_of(&stdout, "REMOUNT"), "0", "{stdout}{stderr}");
    assert_eq!(line_of(&stdout, "CAP"), "0000000000000000", "{stdout}");
    assert!(line_of(&stdout, "FILE").contains("arkham-decoy"), "{stdout}");
    assert!(!stdout.contains("REAL_SECRET_VALUE"), "{stdout}");
  }

  fn line_of(output: &str, label: &str) -> String {
    output
      .lines()
      .find_map(|line| line.strip_prefix(&format!("{label}:")))
      .unwrap_or("")
      .to_string()
  }

  #[test]
  fn a_nested_workspace_does_not_bind_the_host_tmp_parent() {
    let parent = tempfile::tempdir().unwrap();
    std::fs::write(parent.path().join("sibling-secret"), "SIBLING_SECRET\n").unwrap();
    let project = parent.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let mut plan = plan(WriteProfile::WorkspaceWrite);
    plan.workspace = project.clone();
    plan.workdir = project.clone();
    plan.binds.clear();
    let ca = project.join("ca.pem");
    std::fs::write(&ca, "CERT\n").unwrap();
    plan.ca_host = ca;
    let args = argv(&plan, &[]);
    let parent_path = parent.path().as_os_str();
    let sibling = parent.path().join("sibling-secret");
    assert!(
      !args
        .windows(3)
        .any(|window| (window[0] == "--ro-bind" || window[0] == "--bind") && window[1] == parent_path),
      "host tmp parent was rebound\n{}",
      joined(&args)
    );
    assert!(
      !args
        .windows(3)
        .any(|window| (window[0] == "--ro-bind" || window[0] == "--bind") && window[1] == sibling.as_os_str()),
      "sibling was a bind source\n{}",
      joined(&args)
    );
    assert!(has_pair(&args, "--tmpfs", "/tmp"), "{}", joined(&args));
    assert!(has_pair(&args, "--dir", parent.path().to_str().unwrap()), "{}", joined(&args));
    assert!(
      has_triple(&args, "--bind", project.to_str().unwrap(), project.to_str().unwrap()),
      "{}",
      joined(&args)
    );
    let script = format!("cat '{}'; echo CAT:$?", sibling.display());
    let ran_args = argv(&plan, &["sh".into(), "-c".into(), script.into()]);
    let ran = std::process::Command::new("sudo")
      .arg("-n")
      .arg("bwrap")
      .args(&ran_args)
      .output()
      .unwrap();
    let ran_out = String::from_utf8_lossy(&ran.stdout);
    let ran_err = String::from_utf8_lossy(&ran.stderr);
    assert!(ran.status.success(), "{ran_out}{ran_err}\n{}", joined(&ran_args));
    assert!(!ran_out.contains("SIBLING_SECRET"), "{ran_out}");
    assert_ne!(line_of(&ran_out, "CAT"), "0", "{ran_out}{ran_err}");
    plan.binds.push(Bind {
      source: parent.path().to_path_buf(),
      dest: parent.path().to_path_buf(),
      read_only: true,
    });
    let err = bwrap_argv(&plan, &[]).unwrap_err();
    assert_eq!(err.registration_detail(), "session tmp is not a private directory");
  }

  #[test]
  fn a_private_tmp_workspace_is_the_session_tmpfs() {
    let scratch = tempfile::tempdir().unwrap();
    let ca = scratch.path().join("ca.pem");
    std::fs::write(&ca, "CERT\n").unwrap();
    let marker = PathBuf::from("/tmp/arkham-host-tmp-marker");
    std::fs::write(&marker, "HOST_TMP_MARKER\n").unwrap();
    let mut plan = plan(WriteProfile::WorkspaceWrite);
    plan.workspace = PathBuf::from("/tmp");
    plan.workdir = PathBuf::from("/tmp");
    plan.binds.clear();
    plan.ca_host = ca;
    let args = argv(&plan, &[]);
    assert!(has_pair(&args, "--tmpfs", "/tmp"), "{}", joined(&args));
    assert!(has_pair(&args, "--chdir", "/tmp"), "{}", joined(&args));
    assert!(!has_triple(&args, "--bind", "/tmp", "/tmp"), "{}", joined(&args));
    assert!(!has_triple(&args, "--ro-bind", "/tmp", "/tmp"), "{}", joined(&args));
    let script = "pwd; ls /tmp; touch /tmp/from-sandbox; echo TOUCH:$?";
    let ran_args = argv(&plan, &["sh".into(), "-c".into(), script.into()]);
    let ran = std::process::Command::new("sudo")
      .arg("-n")
      .arg("bwrap")
      .args(&ran_args)
      .output()
      .unwrap();
    let stdout = String::from_utf8_lossy(&ran.stdout);
    let stderr = String::from_utf8_lossy(&ran.stderr);
    assert!(ran.status.success(), "{stdout}{stderr}\n{}", joined(&ran_args));
    assert!(stdout.contains("/tmp"), "{stdout}");
    assert!(!stdout.contains("HOST_TMP_MARKER"), "{stdout}");
    assert!(!Path::new("/tmp/from-sandbox").exists(), "sandbox write landed on the host tmp");
    let _ = std::fs::remove_file(&marker);

    plan.profile = WriteProfile::ReadOnly;
    let args = argv(&plan, &[]);
    assert!(has_pair(&args, "--tmpfs", "/tmp"), "{}", joined(&args));
    assert!(has_pair(&args, "--remount-ro", "/tmp"), "{}", joined(&args));
    assert!(!has_triple(&args, "--bind", "/tmp", "/tmp"), "{}", joined(&args));
    assert!(!has_triple(&args, "--ro-bind", "/tmp", "/tmp"), "{}", joined(&args));

    plan.profile = WriteProfile::DangerFullAccess;
    let args = argv(&plan, &[]);
    assert!(has_pair(&args, "--tmpfs", "/tmp"), "{}", joined(&args));
    assert!(!has_triple(&args, "--bind", "/tmp", "/tmp"), "{}", joined(&args));

    plan.profile = WriteProfile::WorkspaceWrite;
    plan.binds.push(Bind {
      source: scratch.path().to_path_buf(),
      dest: scratch.path().to_path_buf(),
      read_only: true,
    });
    let err = bwrap_argv(&plan, &[]).unwrap_err();
    assert_eq!(err.registration_detail(), "session tmp is not a private directory");
  }

  #[test]
  fn danger_full_access_binds_host_entries_writable_and_keeps_secret_overlays() {
    let args = argv(&plan(WriteProfile::DangerFullAccess), &[]);
    let text = joined(&args);
    assert!(text.starts_with("--tmpfs / "));
    assert!(!has_pair(&args, "--tmpfs", "/tmp"));
    assert!(!has_triple(&args, "--bind", "/", "/"));
    assert!(text.contains("--ro-bind /scratch/fnox.toml /work/fnox.toml"));
    assert!(text.contains("--unshare-cgroup"));
    assert!(!text.contains("/sys/fs/cgroup"));
  }
}
