//! Bubblewrap argv from one launch plan.
//!
//! The writable set comes from [`arkham_config::fs_policy`]. This renderer
//! does not invent roots. The sandbox root is a tmpfs with each host entry
//! mounted onto it: a bind of the host root cannot hold `/arkham`, because
//! creating that directory would write the host filesystem or fail on the
//! read-only mount.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use arkham_config::{FsPolicy, WriteProfile, fs_policy};
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
pub const TEMP_DIR: &str = "/tmp";

/// Cgroup mount the agent must not be able to write. A writable
/// `cgroup.procs` would let the agent leave its session.
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

/// Argv for `bwrap`, not including the `bwrap` program name.
///
/// `/` is remounted read-only after the mounts are in place. Mounts created
/// before that keep the flags they were given.
#[must_use]
pub fn bwrap_argv(plan: &LaunchPlan, command: &[OsString]) -> Vec<OsString> {
  let policy = fs_policy(plan.profile, &plan.workspace, Path::new(TEMP_DIR));
  let workspace_write = matches!(policy, FsPolicy::WorkspaceWrite { .. });
  let mut args = Vec::new();
  args.extend(["--tmpfs".into(), "/".into()]);
  push_host_entries(&mut args, matches!(policy, FsPolicy::Unrestricted));
  args.extend(["--dev".into(), "/dev".into(), "--proc".into(), "/proc".into()]);
  args.extend(["--unshare-pid".into(), "--unshare-uts".into(), "--unshare-ipc".into()]);
  if workspace_write {
    args.extend(["--tmpfs".into(), TEMP_DIR.into()]);
    push_tmp_restores(&mut args, plan);
    args.extend(["--bind".into(), plan.workspace.clone().into(), plan.workspace.clone().into()]);
  }
  for bind in &plan.binds {
    if bind.dest == plan.workspace && workspace_write {
      continue;
    }
    let flag = bind_flag(plan.profile, bind.read_only);
    args.extend([flag.into(), bind.source.clone().into(), bind.dest.clone().into()]);
  }
  args.extend(["--dir".into(), "/arkham".into()]);
  args.extend(["--ro-bind".into(), plan.ca_host.clone().into(), plan.ca_dest.clone().into()]);
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

/// Mount every host entry the agent can open.
///
/// `dev` and `proc` are left out because `--dev` and `--proc` create them.
/// `arkham` is left out so [`bwrap_argv`] can create that directory itself.
fn push_host_entries(args: &mut Vec<OsString>, writable: bool) {
  let Ok(entries) = std::fs::read_dir("/") else {
    return;
  };
  for entry in entries.flatten() {
    let name = entry.file_name();
    if skipped_root(&name) {
      continue;
    }
    let dest = PathBuf::from("/").join(&name);
    let Ok(kind) = entry.file_type() else {
      continue;
    };
    if kind.is_symlink() {
      let Ok(target) = std::fs::read_link(&dest) else {
        continue;
      };
      args.extend(["--symlink".into(), target.into_os_string(), dest.into_os_string()]);
      continue;
    }
    if kind.is_dir() || kind.is_file() {
      let flag = if writable { "--bind" } else { "--ro-bind" };
      let path = dest.into_os_string();
      args.extend([flag.into(), path.clone(), path]);
    }
  }
}

fn skipped_root(name: &OsStr) -> bool {
  name == "dev" || name == "proc" || name == "arkham"
}

/// Put back directories under the workspace-write tmpfs that hold a projected file.
///
/// `--tmpfs /tmp` hides the host directory, including symlinks that point at
/// a projected file. Binding each wiped top-level directory read-only keeps
/// those links, and the per-file binds that follow replace the secret files.
fn push_tmp_restores(args: &mut Vec<OsString>, plan: &LaunchPlan) {
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
    let path = top.into_os_string();
    args.extend(["--ro-bind".into(), path.clone(), path]);
  }
}

/// `/tmp/<name>` for a path nested under the temp directory, when that
/// directory exists on the host.
fn tmp_tree(dest: &Path, tmp: &Path) -> Option<PathBuf> {
  let rest = dest.strip_prefix(tmp).ok()?;
  let first = rest.components().next()?;
  let top = tmp.join(first);
  if top == dest || !top.is_dir() { None } else { Some(top) }
}

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

#[cfg(test)]
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
    assert!(!text.contains("--bind /work /work"));
    assert!(text.contains("-- sh"));
    assert!(text.contains("--ro-bind /scratch/fnox.toml /work/fnox.toml"));
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
