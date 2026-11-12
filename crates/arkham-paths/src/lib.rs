//! Host-path expansion, normalization, and translation.

/// One generated mount: host path, translated container path, read-only flag.
#[derive(Clone, Debug)]
pub struct Mount {
  /// Host path as configured.
  pub host: PathBuf,
  /// Translated path inside the containers.
  pub container: PathBuf,
  /// Whether the mount is read-only.
  pub ro: bool,
}

use std::path::{Path, PathBuf};

/// Expand `~` against the host home and relative paths against the root,
/// normalizing `..` lexically.
pub fn expand(path: &Path, root: &Path, host_home: Option<&Path>) -> PathBuf {
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
#[must_use]
pub fn normalize(path: &Path) -> PathBuf {
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
#[must_use]
pub fn path_under_home(path: &Path, host_home: &Path) -> Option<String> {
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
#[must_use]
pub fn translate(path: &Path, host_home: Option<&Path>, home: &str) -> PathBuf {
  match host_home.and_then(|hh| path.strip_prefix(hh).ok()) {
    Some(rest) => Path::new(home).join(rest),
    None => path.to_path_buf(),
  }
}

/// Drop every mount whose host path is covered by another mount; the
/// covering mount serves the same files at its translated path.
#[must_use]
pub fn covering(mounts: Vec<Mount>) -> Vec<Mount> {
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

/// Where the real identity lives on the host: `~` expands, relative paths
/// resolve against `~/.ssh` the way ssh itself resolves them.
#[must_use]
pub fn host_identity_path(identity: &str, host_home: &Path) -> PathBuf {
  if let Some(rest) = identity.strip_prefix("~/") {
    host_home.join(rest)
  } else if Path::new(identity).is_absolute() {
    PathBuf::from(identity)
  } else {
    host_home.join(".ssh").join(identity)
  }
}

/// The container path the decoy identity mounts at, mirroring the source
/// layout under the container home. `~`-relative and home-relative paths
/// mirror; anything else off the host home does not.
#[must_use]
pub fn mirror_container_path(identity: &str, host_home: &Path, home: &str) -> Option<String> {
  let host_path = if let Some(rest) = identity.strip_prefix("~/") {
    host_home.join(rest)
  } else if Path::new(identity).is_absolute() {
    PathBuf::from(identity)
  } else {
    host_home.join(".ssh").join(identity)
  };
  let host_path = normalize(&host_path);
  let rel = path_under_home(&host_path, host_home)?;
  Some(format!("{home}/{rel}"))
}

/// Stable directory slug for an arbitrary path: lowercase segments joined
/// with dashes. Workspace identity and grant labels share it, so the helper
/// lives here rather than beside either caller.
#[must_use]
pub fn slug(path: &Path) -> String {
  let slug: Vec<String> = path
    .components()
    .filter_map(|component| match component {
      std::path::Component::Normal(part) => {
        let text = part.to_string_lossy().to_lowercase();
        let cleaned: String = text.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
        (!cleaned.trim_matches('-').is_empty()).then(|| cleaned.trim_matches('-').to_string())
      }
      _ => None,
    })
    .collect();
  slug.join("-")
}

/// Canonicalize an existing directory.
///
/// # Errors
/// Returns an I/O error when the path cannot be resolved or is not a directory.
pub fn canonicalize_dir(path: &Path) -> std::io::Result<PathBuf> {
  let canonical = std::fs::canonicalize(path)?;
  if canonical.is_dir() {
    Ok(canonical)
  } else {
    Err(std::io::Error::new(std::io::ErrorKind::NotADirectory, "not a directory"))
  }
}
