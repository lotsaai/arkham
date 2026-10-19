//! Host-path expansion, normalization, and translation.

/// One generated mount: host path, translated container path, read-only flag.
#[derive(Clone, Debug)]
pub(crate) struct Mount {
  /// Host path as configured.
  pub(crate) host: PathBuf,
  /// Translated path inside the containers.
  pub(crate) container: PathBuf,
  /// Whether the mount is read-only.
  pub(crate) ro: bool,
}

use std::path::{Path, PathBuf};

/// Expand `~` against the host home and relative paths against the root,
/// normalizing `..` lexically.
pub(crate) fn expand(path: &Path, root: &Path, host_home: Option<&Path>) -> PathBuf {
  if path == Path::new("~") {
    return host_home.map_or_else(|| root.join(path), Path::to_path_buf);
  }
  if let Ok(rest) = path.strip_prefix("~/")
    && let Some(home) = host_home
  {
    return normalize(&home.join(rest));
  }
  if path.is_absolute() {
    normalize(path)
  } else {
    normalize(&root.join(path))
  }
}

/// Lexically remove `.` and resolve `..` without touching the filesystem.
pub(crate) fn normalize(path: &Path) -> PathBuf {
  let mut out = PathBuf::new();
  for component in path.components() {
    match component {
      std::path::Component::ParentDir => {
        out.pop();
      }
      std::path::Component::CurDir => {}
      other => out.push(other.as_os_str()),
    }
  }
  out
}

/// The path under `host_home`, with `\` folded to `/`. `None` when `path`
/// is not strictly inside that home. `..` and empty segments are rejected
/// after the caller has normalized.
pub(crate) fn path_under_home(path: &Path, host_home: &Path) -> Option<String> {
  let rest = path.strip_prefix(host_home).ok()?;
  if rest.as_os_str().is_empty() {
    return None;
  }
  let rel = rest.to_string_lossy().replace('\\', "/");
  if rel.split('/').any(|part| part.is_empty() || part == "..") {
    return None;
  }
  Some(rel)
}

/// Host path to container path: under-home paths translate into the
/// container home prefix, everything else mounts at its own path.
pub(crate) fn translate(path: &Path, host_home: Option<&Path>, home: &str) -> PathBuf {
  match host_home.and_then(|hh| path.strip_prefix(hh).ok()) {
    Some(rest) => Path::new(home).join(rest),
    None => path.to_path_buf(),
  }
}

/// Drop every mount whose host path is covered by another mount; the
/// covering mount serves the same files at its translated path.
pub(crate) fn covering(mounts: Vec<Mount>) -> Vec<Mount> {
  let mut out: Vec<Mount> = Vec::new();
  for mount in mounts {
    if out.iter().any(|kept| mount.host.starts_with(&kept.host)) {
      continue;
    }
    out.retain(|kept| !kept.host.starts_with(&mount.host));
    out.push(mount);
  }
  out
}
