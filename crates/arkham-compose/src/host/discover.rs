//! Project discovery and the pure checks the control plane applies.
//!
//! The cwd names a project. It does not authorize one. A session's project
//! is fixed at registration.

use std::path::{Path, PathBuf};

use arkham_config::config::workspace_root;
use arkham_config::is_fnox_config_name;

/// Field index of `starttime` in `/proc/<pid>/stat` after the `comm` field.
const STARTTIME_AFTER_COMM: usize = 19;

/// Parse `starttime` from a `/proc/<pid>/stat` line.
///
/// `comm` is wrapped in parentheses and may contain spaces, so the clock
/// tick is the 20th whitespace field after the last `)`.
#[must_use]
pub fn parse_starttime(stat: &str) -> Option<u64> {
  let rest = stat.rsplit_once(')')?.1;
  rest.split_whitespace().nth(STARTTIME_AFTER_COMM)?.parse().ok()
}

/// Whether a control peer's uid is the daemon's uid.
#[must_use]
pub fn peer_uid_allowed(peer: u32, daemon: u32) -> bool {
  peer == daemon
}

/// Whether `path` is already inside a daemon-managed cgroup.
///
/// A process there must not register again: the agent would be able to open
/// a second session.
#[must_use]
pub fn cgroup_is_confined(path: &str) -> bool {
  path.split('/').any(|part| part == "arkham-host")
}

/// Resolve the project root for a wrapper that started in `start`.
///
/// Walks ancestors for a fnox config file, then resolves that directory
/// through the workspace root. With no fnox file, the nearest registered
/// root that contains `start` wins, then the workspace root, then `start`.
#[must_use]
pub fn project_root(start: &Path, registered: &[PathBuf]) -> PathBuf {
  if let Some(marker) = nearest_fnox_dir(start) {
    return workspace_root(&marker).unwrap_or(marker);
  }
  if let Some(root) = nearest_registered(start, registered) {
    return root;
  }
  workspace_root(start).unwrap_or_else(|| start.to_path_buf())
}

fn nearest_fnox_dir(start: &Path) -> Option<PathBuf> {
  let mut dir = Some(start.to_path_buf());
  while let Some(current) = dir {
    if dir_has_fnox(&current) {
      return Some(current);
    }
    dir = current.parent().map(Path::to_path_buf);
  }
  None
}

fn dir_has_fnox(dir: &Path) -> bool {
  let Ok(entries) = std::fs::read_dir(dir) else {
    return false;
  };
  for entry in entries.flatten() {
    let name = entry.file_name();
    let Some(name) = name.to_str() else {
      continue;
    };
    if is_fnox_config_name(name) {
      return true;
    }
    if name == ".config" && entry.path().is_dir() && dir_has_fnox_shallow(&entry.path()) {
      return true;
    }
  }
  false
}

fn dir_has_fnox_shallow(dir: &Path) -> bool {
  let Ok(entries) = std::fs::read_dir(dir) else {
    return false;
  };
  entries
    .flatten()
    .any(|entry| entry.file_name().to_str().is_some_and(is_fnox_config_name))
}

fn nearest_registered(start: &Path, registered: &[PathBuf]) -> Option<PathBuf> {
  registered
    .iter()
    .filter(|root| start.starts_with(root))
    .max_by_key(|root| root.components().count())
    .cloned()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn starttime_is_the_field_after_comm() {
    let stat = "123 (agent proc) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 999 0\n";
    assert_eq!(parse_starttime(stat), Some(999));
    assert_eq!(parse_starttime("no-paren"), None);
  }

  #[test]
  fn a_different_starttime_does_not_match() {
    let first = parse_starttime("1 (a) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 10 0").unwrap();
    let reused = parse_starttime("1 (b) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 11 0").unwrap();
    assert_ne!(first, reused);
  }

  #[test]
  fn only_the_daemon_uid_may_register() {
    assert!(peer_uid_allowed(1000, 1000));
    assert!(!peer_uid_allowed(1001, 1000));
  }

  #[test]
  fn a_session_cgroup_is_already_confined() {
    assert!(cgroup_is_confined("/user.slice/arkham-host/12-99"));
    assert!(!cgroup_is_confined("/user.slice/workload"));
  }

  #[test]
  fn discovery_prefers_the_fnox_directory_then_a_registered_root() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("work");
    let nested = project.join("sub");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(project.join("fnox.toml"), "[providers]\n").unwrap();
    let found = project_root(&nested, &[]);
    assert_eq!(found, project);

    let other = root.path().join("other");
    std::fs::create_dir_all(other.join("nested")).unwrap();
    let registered = vec![other.clone()];
    assert_eq!(project_root(&other.join("nested"), &registered), other);
  }
}
