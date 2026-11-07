//! Project discovery and the pure checks the control plane applies.
//!
//! The cwd names a project. It does not authorize one. A session's project
//! is fixed at registration.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use arkham_config::config::workspace_root;

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

/// Sandbox path used when the resolved project would be the user's home.
///
/// Bubblewrap mounts a fresh tmpfs here. The host directory of the same
/// path is not a project and is not mounted.
pub const PRIVATE_SESSION_ROOT: &str = "/tmp";

/// Resolve the project root for a wrapper that started in `start`.
///
/// `start` is canonicalized before the walk, so a directory symlink is the
/// target tree. The project is the code-workspace root that contains that
/// path. A registered root is the ceiling and the fallback when no marker
/// is found. A fnox file does not choose the root. The result contains the
/// canonical path and is never `/`. When that root is the user's home
/// directory, nothing from home is enlisted and the result is the private
/// session directory.
#[must_use]
pub fn project_root(start: &Path, registered: &[PathBuf]) -> Option<PathBuf> {
  let canonical = canonicalize_dir(start).ok()?;
  if canonical.as_path() == Path::new("/") {
    return None;
  }
  let registered = canonical_roots(registered);
  let ceiling = nearest_registered(&canonical, &registered);
  let project = workspace_root(&canonical).and_then(|root| root_containing(root, &canonical, ceiling.as_deref()));
  let chosen = project
    .or(ceiling)
    .and_then(|chosen| root_containing(chosen, &canonical, None))
    .or_else(|| root_containing(canonical.clone(), &canonical, None))?;
  if is_user_home(&chosen) {
    return Some(PathBuf::from(PRIVATE_SESSION_ROOT));
  }
  Some(chosen)
}

/// Whether `path` is the private session directory rather than a host project.
#[must_use]
pub(crate) fn is_private_session(path: &Path) -> bool {
  path == Path::new(PRIVATE_SESSION_ROOT)
}

fn is_user_home(root: &Path) -> bool {
  let Some(home) = dirs::home_dir() else {
    return false;
  };
  let Ok(home) = std::fs::canonicalize(&home) else {
    return false;
  };
  root == home
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
  fn discovery_uses_the_project_marker_then_a_registered_root() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let project = root_path.join("work");
    let nested = project.join("crate").join("src");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::create_dir(project.join(".git")).unwrap();
    assert_eq!(project_root(&nested, &[]), Some(project.clone()));

    let cargo = root_path.join("cargo");
    let member = cargo.join("member");
    std::fs::create_dir_all(&member).unwrap();
    std::fs::write(cargo.join("Cargo.toml"), "[workspace]\nmembers = [\"member\"]\n").unwrap();
    assert_eq!(project_root(&member, &[]), Some(cargo));

    let other = root_path.join("other");
    std::fs::create_dir_all(other.join("nested")).unwrap();
    let registered = vec![other.clone()];
    assert_eq!(project_root(&other.join("nested"), &registered), Some(other));
  }

  #[test]
  fn a_fnox_file_does_not_move_the_project_root() {
    let base = tempfile::tempdir().unwrap();
    let base = base.path().canonicalize().unwrap();
    let project = base.join("repo");
    let nested = project.join("crate").join("src");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::create_dir(project.join(".git")).unwrap();
    std::fs::write(project.join("crate").join("fnox.toml"), "[providers]\n").unwrap();
    std::fs::write(base.join("fnox.toml"), "[providers]\n").unwrap();
    assert_eq!(project_root(&nested, &[]), Some(project.clone()));

    let outer = base.join("outer");
    let inner = outer.join("proj").join("src");
    std::fs::create_dir_all(&inner).unwrap();
    std::fs::create_dir(outer.join("proj").join(".git")).unwrap();
    std::fs::write(outer.join("fnox.toml"), "[providers]\n").unwrap();
    assert_eq!(project_root(&inner, &[]), Some(outer.join("proj")));

    let parent = base.join("app");
    let child = parent.join("src");
    std::fs::create_dir_all(&child).unwrap();
    std::fs::write(parent.join("fnox.toml"), "[providers]\n").unwrap();
    assert_eq!(project_root(&child, &[]), Some(child));
  }

  #[test]
  fn a_fnox_file_above_the_registered_root_does_not_move_the_project() {
    let base = tempfile::tempdir().unwrap();
    let base_path = base.path().canonicalize().unwrap();
    let project = base_path.join("project");
    let nested = project.join("sub");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::create_dir(project.join(".git")).unwrap();
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
    std::fs::create_dir(project.join(".git")).unwrap();
    std::fs::write(project.join("fnox.toml"), "[providers]\n").unwrap();
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
    std::fs::create_dir(parent.join(".git")).unwrap();
    std::fs::create_dir(target.join(".git")).unwrap();
    std::fs::write(parent.join("fnox.toml"), "[providers]\n").unwrap();
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

  /// A start at the home directory, including through a symlink, enlists
  /// nothing from that directory. The session workspace is the private `/tmp`.
  #[test]
  fn a_home_directory_is_not_enlisted_and_uses_the_private_tmp() {
    let real = tempfile::tempdir().unwrap();
    let real = real.path().canonicalize().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let elsewhere = elsewhere.path().canonicalize().unwrap();
    let link = elsewhere.join("home");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let private_tmp = PathBuf::from("/tmp");

    let home_env = HomeVar::set(&real);
    let from_home = project_root(&real, &[]).unwrap();
    let from_link = project_root(&link, &[]).unwrap();
    assert_eq!(from_home, private_tmp);
    assert_eq!(from_link, private_tmp);
    assert_ne!(from_home, real);
    drop(home_env);

    let home_env = HomeVar::set(&link);
    assert_eq!(project_root(&real, &[]).unwrap(), private_tmp);
    drop(home_env);

    std::fs::create_dir(real.join(".git")).unwrap();
    let child = real.join("notes");
    std::fs::create_dir(&child).unwrap();
    let home_env = HomeVar::set(&real);
    assert_eq!(project_root(&real, &[]).unwrap(), private_tmp);
    assert_eq!(project_root(&child, std::slice::from_ref(&real)).unwrap(), private_tmp);
    drop(home_env);
  }

  /// A project whose own marker sits under home stays that project.
  #[test]
  fn a_project_under_home_stays_that_project() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path().canonicalize().unwrap();
    let project = home.join("app");
    let nested = project.join("src");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::create_dir(project.join(".git")).unwrap();
    let _home_env = HomeVar::set(&home);
    assert_eq!(project_root(&nested, &[]), Some(project.clone()));
    assert_eq!(project_root(&nested, std::slice::from_ref(&home)), Some(project));
  }

  /// Restore `HOME` when the test ends, including on panic.
  struct HomeVar {
    saved: Option<std::ffi::OsString>,
  }

  impl HomeVar {
    fn set(path: &Path) -> Self {
      let saved = std::env::var_os("HOME");
      // SAFETY: test-only mutation of HOME. The previous value is restored on drop.
      unsafe {
        std::env::set_var("HOME", path);
      };
      Self { saved }
    }
  }

  impl Drop for HomeVar {
    fn drop(&mut self) {
      // SAFETY: test-only restore of the HOME value captured in `set`.
      unsafe {
        match self.saved.take() {
          Some(value) => std::env::set_var("HOME", value),
          None => std::env::remove_var("HOME"),
        }
      }
    }
  }
}
