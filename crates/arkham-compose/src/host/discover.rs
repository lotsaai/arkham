//! Project discovery and the pure checks the control plane applies.
//!
//! The cwd names a project. It does not authorize one. A session's project
//! is fixed at registration.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use arkham_config::config::workspace_root;
use arkham_config::is_fnox_config_name;

#[cfg(target_os = "linux")]
use crate::Error;

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
/// `start` is canonicalized before the walk, so a directory symlink is the
/// target tree. The walk stops at the nearest registered root and never
/// returns `/`. The result contains that canonical path.
#[must_use]
pub fn project_root(start: &Path, registered: &[PathBuf]) -> Option<PathBuf> {
  let canonical = canonicalize_dir(start).ok()?;
  if canonical.as_path() == Path::new("/") {
    return None;
  }
  let registered = canonical_roots(registered);
  let ceiling = nearest_registered(&canonical, &registered);
  let found = nearest_fnox_dir(&canonical, ceiling.as_deref()).and_then(|marker| {
    let resolved = workspace_root(&marker).unwrap_or_else(|| marker.clone());
    root_containing(resolved, &canonical, ceiling.as_deref()).or_else(|| root_containing(marker, &canonical, ceiling.as_deref()))
  });
  found
    .or(ceiling)
    .and_then(|chosen| root_containing(chosen, &canonical, None))
    .or_else(|| {
      let resolved = workspace_root(&canonical).unwrap_or_else(|| canonical.clone());
      root_containing(resolved, &canonical, None).or_else(|| root_containing(canonical.clone(), &canonical, None))
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn canonical_workspace(workspace: Option<&Path>) -> Result<PathBuf, Error> {
  let path = match workspace {
    Some(path) if path.is_absolute() => path.to_path_buf(),
    Some(path) => match std::env::current_dir() {
      Ok(cwd) => cwd.join(path),
      Err(source) => {
        return Err(Error::ResolveWorkspace {
          path: path.to_path_buf(),
          source,
        });
      }
    },
    None => std::env::current_dir().map_err(|source| Error::ResolveWorkspace {
      path: PathBuf::from("."),
      source,
    })?,
  };
  canonicalize_dir(&path).map_err(|source| Error::ResolveWorkspace { path, source })
}

fn canonicalize_dir(path: &Path) -> std::io::Result<PathBuf> {
  let canonical = std::fs::canonicalize(path)?;
  if canonical.is_dir() {
    Ok(canonical)
  } else {
    Err(std::io::Error::new(ErrorKind::NotADirectory, "not a directory"))
  }
}

fn canonical_roots(registered: &[PathBuf]) -> Vec<PathBuf> {
  registered
    .iter()
    .filter_map(|root| canonicalize_dir(root).ok())
    .filter(|root| root.as_path() != Path::new("/"))
    .collect()
}

fn root_containing(candidate: PathBuf, canonical: &Path, ceiling: Option<&Path>) -> Option<PathBuf> {
  let resolved = canonicalize_dir(&candidate).unwrap_or(candidate);
  if resolved.as_path() == Path::new("/") || ceiling.is_some_and(|limit| !resolved.starts_with(limit)) {
    return None;
  }
  canonical.starts_with(&resolved).then_some(resolved)
}

fn nearest_fnox_dir(start: &Path, ceiling: Option<&Path>) -> Option<PathBuf> {
  let mut dir = Some(start.to_path_buf());
  while let Some(current) = dir {
    if current.as_path() == Path::new("/") {
      return None;
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
    let root_path = root.path().canonicalize().unwrap();
    let project = root_path.join("work");
    let nested = project.join("sub");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(project.join("fnox.toml"), "[providers]\n").unwrap();
    let found = project_root(&nested, &[]);
    assert_eq!(found, Some(project));

    let other = root_path.join("other");
    std::fs::create_dir_all(other.join("nested")).unwrap();
    let registered = vec![other.clone()];
    assert_eq!(project_root(&other.join("nested"), &registered), Some(other));
  }

  #[test]
  fn a_fnox_file_above_the_registered_root_does_not_move_the_project() {
    let base = tempfile::tempdir().unwrap();
    let base_path = base.path().canonicalize().unwrap();
    let project = base_path.join("project");
    let nested = project.join("sub");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(base_path.join("fnox.toml"), "secret = true\n").unwrap();
    assert_eq!(project_root(&nested, std::slice::from_ref(&project)), Some(project));
  }

  #[test]
  fn a_registered_root_does_not_pull_a_symlink_back_to_its_lexical_parent() {
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
    assert_eq!(found, outside);
    assert!(!found.starts_with(&project));
    assert_eq!(project_root(&link, &[]), Some(outside));
  }

  #[test]
  fn the_filesystem_root_is_not_a_project() {
    assert!(project_root(std::path::Path::new("/"), &[]).is_none());
  }

  #[test]
  fn a_directory_symlink_with_fnox_in_the_target_enlists_the_target() {
    let base = tempfile::tempdir().unwrap();
    let base = base.path().canonicalize().unwrap();
    let parent = base.join("home");
    let target = base.join("proj");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("fnox.toml"), "[providers]\n").unwrap();
    std::fs::write(parent.join("credentials"), "host-only\n").unwrap();
    let link = parent.join("work");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let found = project_root(&link, &[]).unwrap();
    assert_eq!(found, target);
    assert!(!found.starts_with(&parent), "enlisted {found:?} widens over {parent:?}");
  }

  #[test]
  fn a_directory_without_a_marker_enlists_itself() {
    let base = tempfile::tempdir().unwrap();
    let base = base.path().canonicalize().unwrap();
    let project = base.join("plain");
    std::fs::create_dir(&project).unwrap();
    assert_eq!(project_root(&project, &[]), Some(project));
  }

  #[test]
  fn a_symlink_with_no_project_marker_does_not_enlist_its_parent() {
    let base = tempfile::tempdir().unwrap();
    let base = base.path().canonicalize().unwrap();
    let parent = base.join("home");
    let target = base.join("empty");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::create_dir_all(&target).unwrap();
    let link = parent.join("work");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let found = project_root(&link, &[]).unwrap();
    assert_eq!(found, target);
    assert!(!found.starts_with(&parent), "enlisted {found:?} widens over {parent:?}");
  }

  #[test]
  fn a_dangling_directory_symlink_does_not_enlist_its_parent() {
    let base = tempfile::tempdir().unwrap();
    let base = base.path().canonicalize().unwrap();
    let parent = base.join("home");
    std::fs::create_dir_all(&parent).unwrap();
    let link = parent.join("work");
    std::os::unix::fs::symlink(base.join("missing"), &link).unwrap();

    assert_eq!(project_root(&link, &[]), None);
  }
}
