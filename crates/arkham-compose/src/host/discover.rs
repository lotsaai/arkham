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
/// The walk stops at the nearest registered root and never returns `/`.
/// A directory symlink is not entered, so a link cannot move the project
/// onto its target. `None` means there is no project.
#[must_use]
pub fn project_root(start: &Path, registered: &[PathBuf]) -> Option<PathBuf> {
  if start == Path::new("/") {
    return None;
  }
  let ceiling = nearest_registered(start, registered).filter(|root| root.as_path() != Path::new("/"));
  let found = nearest_fnox_dir(start, ceiling.as_deref()).map(|marker| {
    let resolved = workspace_root(&marker).unwrap_or_else(|| marker.clone());
    if resolved.as_path() != Path::new("/") && ceiling.as_ref().is_none_or(|limit| resolved.starts_with(limit)) {
      resolved
    } else {
      marker
    }
  });
  let chosen = found.or(ceiling).or_else(|| {
    let anchored = lexical_anchor(start);
    let resolved = workspace_root(&anchored).unwrap_or(anchored);
    (resolved.as_path() != Path::new("/")).then_some(resolved)
  });
  chosen.filter(|path| path.as_path() != Path::new("/"))
}

fn nearest_fnox_dir(start: &Path, ceiling: Option<&Path>) -> Option<PathBuf> {
  let mut dir = Some(start.to_path_buf());
  while let Some(current) = dir {
    if current.as_path() == Path::new("/") {
      return None;
    }
    if is_dir_symlink(&current) {
      dir = current.parent().map(Path::to_path_buf);
      continue;
    }
    if dir_has_fnox(&current) {
      return Some(current);
    }
    if ceiling.is_some_and(|ceiling| current == ceiling) {
      return None;
    }
    dir = current.parent().map(Path::to_path_buf);
  }
  None
}

fn is_dir_symlink(path: &Path) -> bool {
  std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// Directory that contains `start` after skipping directory symlinks.
fn lexical_anchor(start: &Path) -> PathBuf {
  let mut current = start.to_path_buf();
  while current.as_path() != Path::new("/") && is_dir_symlink(&current) {
    let Some(parent) = current.parent() else {
      break;
    };
    current = parent.to_path_buf();
  }
  if current.as_path() == Path::new("/") {
    start.to_path_buf()
  } else {
    current
  }
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
    assert_eq!(found, Some(project));

    let other = root.path().join("other");
    std::fs::create_dir_all(other.join("nested")).unwrap();
    let registered = vec![other.clone()];
    assert_eq!(project_root(&other.join("nested"), &registered), Some(other));
  }

  #[test]
  fn a_fnox_file_above_the_registered_root_does_not_move_the_project() {
    let base = tempfile::tempdir().unwrap();
    let project = base.path().join("project");
    let nested = project.join("sub");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(base.path().join("fnox.toml"), "secret = true\n").unwrap();
    assert_eq!(project_root(&nested, std::slice::from_ref(&project)), Some(project));
  }

  #[test]
  fn a_symlinked_directory_does_not_become_the_project() {
    let base = tempfile::tempdir().unwrap();
    let base = base.path().canonicalize().unwrap();
    let project = base.join("project");
    let outside = base.join("outside");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("fnox.toml"), "secret = true\n").unwrap();
    let link = project.join("link");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    let found = project_root(&link, std::slice::from_ref(&project)).unwrap();
    assert_eq!(found, project);
    assert!(found.canonicalize().unwrap().starts_with(&project));
    let unregistered = project_root(&link, &[]).unwrap();
    assert_eq!(unregistered, project);
    assert!(unregistered.canonicalize().unwrap().starts_with(&project));
  }

  #[test]
  fn the_filesystem_root_is_not_a_project() {
    assert!(project_root(std::path::Path::new("/"), &[]).is_none());
  }
}
