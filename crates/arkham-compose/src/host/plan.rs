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
pub const TEMP_DIR: &str = "/tmp";

/// Cgroup mount the agent must not be able to write. A writable
/// `cgroup.procs` would let the agent leave its session.
#[cfg(target_os = "linux")]
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

/// Argv for `bwrap`, not including the `bwrap` program name.
///
/// `/` is remounted read-only after the mounts are in place. Mounts created
/// before that keep the flags they were given.
#[cfg(target_os = "linux")]
#[must_use]
pub fn bwrap_argv(plan: &LaunchPlan, command: &[OsString]) -> Vec<OsString> {
  let policy = fs_policy(plan.profile, &plan.workspace, Path::new(TEMP_DIR));
  let workspace_write = matches!(policy, FsPolicy::WorkspaceWrite { .. });
  let mut args = Vec::new();
  args.extend(["--tmpfs".into(), "/".into()]);
  let mut bound = Vec::new();
  push_host_entries(&mut args, &mut bound, matches!(policy, FsPolicy::Unrestricted));
  args.extend(["--dev".into(), "/dev".into(), "--proc".into(), "/proc".into()]);
  args.extend([
    "--unshare-user".into(),
    "--unshare-pid".into(),
    "--unshare-uts".into(),
    "--unshare-ipc".into(),
    "--cap-drop".into(),
    "ALL".into(),
  ]);
  if workspace_write {
    args.extend(["--tmpfs".into(), TEMP_DIR.into()]);
    bound.push(PathBuf::from(TEMP_DIR));
    push_tmp_restores(&mut args, plan, &mut bound);
  }
  let workspace_flag = if workspace_write || matches!(policy, FsPolicy::Unrestricted) {
    "--bind"
  } else {
    "--ro-bind"
  };
  let mut created = BTreeSet::new();
  push_missing_parents(&mut args, &bound, &plan.workspace, &mut created);
  args.extend([workspace_flag.into(), plan.workspace.clone().into(), plan.workspace.clone().into()]);
  bound.push(plan.workspace.clone());
  for bind in &plan.binds {
    if bind.dest == plan.workspace {
      continue;
    }
    push_missing_parents(&mut args, &bound, &bind.dest, &mut created);
    let flag = bind_flag(plan.profile, bind.read_only);
    args.extend([flag.into(), bind.source.clone().into(), bind.dest.clone().into()]);
  }
  args.extend(["--dir".into(), "/arkham".into()]);
  args.extend(["--ro-bind".into(), plan.ca_host.clone().into(), plan.ca_dest.clone().into()]);
  push_secret_masks(&mut args, plan, &bound);
  push_program(&mut args, &bound, command, &mut created);
  args.extend(["--ro-bind".into(), CGROUP_MOUNT.into(), CGROUP_MOUNT.into()]);
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
  args
}

/// System directories the sandbox can see.
///
/// The enlisted workspace is mounted on its own. `$HOME`, `/root`, and every
/// other top-level directory stay on the tmpfs, so a credential or the CA
/// key that lives there is not a path the agent can open.
#[cfg(target_os = "linux")]
const SYSTEM_ROOTS: &[&str] = &["bin", "etc", "lib", "lib64", "opt", "sbin", "usr"];

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
fn push_missing_parents(args: &mut Vec<OsString>, bound: &[PathBuf], dest: &Path, created: &mut BTreeSet<PathBuf>) {
  let Some(parent) = dest.parent() else {
    return;
  };
  if parent == Path::new("/") || is_mounted(parent, bound) {
    return;
  }
  let mut chain = Vec::new();
  let mut cursor = Some(parent);
  while let Some(dir) = cursor {
    if dir == Path::new("/") || is_mounted(dir, bound) || created.contains(dir) {
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

#[cfg(target_os = "linux")]
fn is_mounted(path: &Path, bound: &[PathBuf]) -> bool {
  bound.iter().any(|root| path == root || path.starts_with(root))
}

/// Hide host secret files that sit inside a directory the sandbox mounted.
///
/// `/etc` is one of those directories. The CA key beside the certificate is
/// too, when its directory was mounted. A key outside every mount is already
/// absent and must not be named: bubblewrap rejects a bind whose parent does
/// not exist.
#[cfg(target_os = "linux")]
fn push_secret_masks(args: &mut Vec<OsString>, plan: &LaunchPlan, bound: &[PathBuf]) {
  for path in ETC_SECRET_FILES {
    mask_file(args, Path::new(path), bound);
  }
  for path in ETC_SECRET_DIRS {
    let path = Path::new(path);
    if path.is_dir() && is_mounted(path, bound) {
      args.extend(["--tmpfs".into(), path.into()]);
    }
  }
  mask_file(args, &plan.ca_host.with_extension("key"), bound);
}

/// Mount the absolute program the sandbox execs, when it is not already
/// inside a mounted directory.
///
/// The runner re-execs this binary to apply Landlock. Binding the file,
/// not its parent tree, keeps the rest of that tree out of the sandbox.
#[cfg(target_os = "linux")]
fn push_program(args: &mut Vec<OsString>, bound: &[PathBuf], command: &[OsString], created: &mut BTreeSet<PathBuf>) {
  let Some(program) = command.first() else {
    return;
  };
  let path = Path::new(program);
  if !path.is_absolute() || !path.is_file() || is_mounted(path, bound) {
    return;
  }
  push_missing_parents(args, bound, path, created);
  let program = path.as_os_str().to_os_string();
  args.extend(["--ro-bind".into(), program.clone(), program]);
}

#[cfg(target_os = "linux")]
fn mask_file(args: &mut Vec<OsString>, path: &Path, bound: &[PathBuf]) {
  if !path.is_file() {
    return;
  }
  let Some(parent) = path.parent() else {
    return;
  };
  if !is_mounted(parent, bound) {
    return;
  }
  args.extend(["--ro-bind".into(), "/dev/null".into(), path.into()]);
}

/// Put back directories under the workspace-write tmpfs that hold a projected file.
///
/// `--tmpfs /tmp` hides the host directory, including symlinks that point at
/// a projected file. Binding each wiped top-level directory read-only keeps
/// those links, and the per-file binds that follow replace the secret files.
#[cfg(target_os = "linux")]
fn push_tmp_restores(args: &mut Vec<OsString>, plan: &LaunchPlan, bound: &mut Vec<PathBuf>) {
  let tmp = Path::new(TEMP_DIR);
  let mut restored = BTreeSet::new();
  let destinations = std::iter::once(plan.workspace.as_path()).chain(plan.binds.iter().map(|bind| bind.dest.as_path()));
  for dest in destinations {
    let Some(top) = tmp_tree(dest, tmp) else {
      continue;
    };
    if top == plan.workspace || !restored.insert(top.clone()) {
      continue;
    }
    bound.push(top.clone());
    let path = top.into_os_string();
    args.extend(["--ro-bind".into(), path.clone(), path]);
  }
}

/// `/tmp/<name>` for a path nested under the temp directory, when that
/// directory exists on the host.
#[cfg(target_os = "linux")]
fn tmp_tree(dest: &Path, tmp: &Path) -> Option<PathBuf> {
  let rest = dest.strip_prefix(tmp).ok()?;
  let first = rest.components().next()?;
  let top = tmp.join(first);
  if top == dest || !top.is_dir() { None } else { Some(top) }
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
      ca_host: PathBuf::from("/scratch/ca.pem"),
      ca_dest: PathBuf::from(CA_DEST),
      env: vec![("SSL_CERT_FILE".into(), CA_DEST.into()), ("GITHUB_TOKEN".into(), "decoy".into())],
      workdir: PathBuf::from("/work"),
      shell: "sh".into(),
    }
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
    let args = bwrap_argv(&plan(WriteProfile::WorkspaceWrite), &["cargo".into(), "test".into()]);
    let text = joined(&args);
    assert!(has_pair(&args, "--tmpfs", "/"));
    assert!(has_pair(&args, "--remount-ro", "/"));
    assert!(!has_triple(&args, "--ro-bind", "/", "/"));
    assert!(!has_triple(&args, "--bind", "/", "/"));
    assert!(text.contains("--dev /dev --proc /proc"));
    assert!(text.contains("--unshare-pid --unshare-uts --unshare-ipc"));
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
    assert!(text.contains("--ro-bind /sys/fs/cgroup /sys/fs/cgroup"));
    let dir = args.iter().position(|arg| arg == "--dir").unwrap();
    let remount = args.iter().position(|arg| arg == "--remount-ro").unwrap();
    assert!(dir < remount);
  }

  #[test]
  fn read_only_drops_the_workspace_bind_and_the_tmpfs() {
    let args = bwrap_argv(&plan(WriteProfile::ReadOnly), &[]);
    let text = joined(&args);
    assert!(has_pair(&args, "--tmpfs", "/"));
    assert!(!has_pair(&args, "--tmpfs", "/tmp"));
    assert!(!has_triple(&args, "--bind", "/work", "/work"));
    assert!(has_triple(&args, "--ro-bind", "/work", "/work"));
    assert!(text.contains("-- sh"));
    assert!(text.contains("--ro-bind /scratch/fnox.toml /work/fnox.toml"));
  }

  #[test]
  fn the_sandbox_drops_every_capability() {
    let args = bwrap_argv(&plan(WriteProfile::WorkspaceWrite), &[]);
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
    let args = bwrap_argv(&plan, &[]);
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
    let args = bwrap_argv(&plan, &["sh".into(), "-c".into(), script.into()]);
    let output = std::process::Command::new("sudo")
      .arg("-n")
      .arg("bwrap")
      .args(args)
      .output()
      .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}{stderr}");
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
  fn danger_full_access_binds_host_entries_writable_and_keeps_secret_overlays() {
    let args = bwrap_argv(&plan(WriteProfile::DangerFullAccess), &[]);
    let text = joined(&args);
    assert!(text.starts_with("--tmpfs / "));
    assert!(!has_pair(&args, "--tmpfs", "/tmp"));
    assert!(!has_triple(&args, "--bind", "/", "/"));
    assert!(text.contains("--ro-bind /scratch/fnox.toml /work/fnox.toml"));
    assert!(text.contains("--ro-bind /sys/fs/cgroup /sys/fs/cgroup"));
  }
}
