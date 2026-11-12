//! Git configuration discovery and byte-string conversion.

use std::fs;
use std::path::{Path, PathBuf};

/// An error loading a discovered Git configuration.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// Git configuration loading failed.
  #[error("gitconfig resolution failed: {source}")]
  Resolve {
    /// The original Git configuration error.
    #[source]
    source: gix_error::Error,
  },
}

/// Result of loading Git configuration.
pub type Result<T> = std::result::Result<T, Error>;

/// Resolve the configuration Git sees from `root`, including linked worktrees.
/// Returns `None` when no repository is found.
///
/// # Errors
///
/// Returns an error when a discovered repository's configuration cannot be loaded.
pub fn resolve(root: &Path) -> Result<Option<gix_config::File>> {
  let Some((path, _)) = gix_discover::upwards(root).ok() else {
    return Ok(None);
  };
  let (git_dir, _) = path.into_repository_and_work_tree_directories();
  gix_config::File::from_git_dir(common_dir(&git_dir))
    .map(Some)
    .map_err(|source| Error::Resolve { source })
}

/// Linked worktrees keep the repository config in the dir `commondir`
/// names; plain repositories are their own common dir.
fn common_dir(git_dir: &Path) -> PathBuf {
  fs::read_to_string(git_dir.join("commondir")).map_or_else(|_| git_dir.to_path_buf(), |raw| git_dir.join(raw.trim()))
}

/// Convert a Git configuration byte string to lossy UTF-8.
pub fn text(value: impl AsRef<[u8]>) -> String {
  String::from_utf8_lossy(value.as_ref()).into_owned()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn missing_repository_has_no_configuration() {
    let dir = tempfile::tempdir().unwrap();
    assert!(resolve(dir.path()).unwrap().is_none());
  }

  #[test]
  fn linked_worktree_uses_common_directory() {
    let dir = tempfile::tempdir().unwrap();
    let worktree = dir.path().join("worktrees/feature");
    fs::create_dir_all(&worktree).unwrap();
    fs::write(worktree.join("commondir"), "../..\n").unwrap();
    assert_eq!(common_dir(&worktree), worktree.join("../.."));
    assert_eq!(common_dir(dir.path()), dir.path());
  }

  #[test]
  fn config_bytes_are_lossily_decoded() {
    assert_eq!(text(b"a\xffb"), "a\u{fffd}b");
  }
}
