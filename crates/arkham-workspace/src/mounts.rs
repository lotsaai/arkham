//! Mount layout: host paths resolved against one workspace root, home pair,
//! and state directory. Generation builds one layout and resolves every
//! mount through it instead of threading the three paths through free
//! functions.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use arkham_config::config::{HostTlsCfg, RuleCfg};
use arkham_config::grants::GuestTlsMode;
use arkham_pki::ca::{CertAuthority, load_or_generate_client_pair};

use crate::workspace::Workspace;
use crate::{Error, Result};
use arkham_paths::{Mount, covering, expand, translate};

/// Resolved mount context for one generation run: the workspace root, the
/// container home, and the host home. Mount resolution reads through this
/// owner.
#[derive(Debug)]
pub struct Layout {
  /// Workspace root, absolute.
  root: PathBuf,
  /// The expanded container home.
  home: String,
  /// The host home, when resolvable.
  host_home: Option<PathBuf>,
  /// Directory rewritten files are written under. `None` uses the compose
  /// state directory. Host sessions pass a scratch directory that is removed
  /// when the session ends.
  scratch: Option<PathBuf>,
}

/// Split a trailing `:ro` or `:rw` off an include entry; bare paths are rw.
/// A single-caller string split, kept beside its caller instead of attached
/// to the layout it never reads.
fn split_mode(entry: &Path) -> (PathBuf, bool) {
  let text = entry.as_os_str().to_str().unwrap_or_default();
  if let Some(rest) = text.strip_suffix(":ro") {
    return (PathBuf::from(rest), true);
  }
  if let Some(rest) = text.strip_suffix(":rw") {
    return (PathBuf::from(rest), false);
  }
  (entry.to_path_buf(), false)
}

impl Layout {
  /// Resolve mount context over an absolute root.
  #[must_use]
  pub fn new(root: &Path, home: String, host_home: Option<PathBuf>) -> Self {
    Self {
      root: root.to_path_buf(),
      home,
      host_home,
      scratch: None,
    }
  }

  /// Write rewritten files under `scratch` instead of the compose state directory.
  #[must_use]
  pub fn with_scratch(mut self, scratch: PathBuf) -> Self {
    self.scratch = Some(scratch);
    self
  }

  /// Directory material for this run lives in.
  fn material_dir(&self) -> PathBuf {
    self.scratch.clone().unwrap_or_else(|| self.state_dir())
  }

  /// The absolute workspace root.
  #[must_use]
  pub fn root(&self) -> &Path {
    &self.root
  }

  /// The expanded container home.
  #[must_use]
  pub fn home(&self) -> &str {
    &self.home
  }

  /// The host home, when resolvable.
  #[must_use]
  pub fn host_home(&self) -> Option<&Path> {
    self.host_home.as_deref()
  }

  /// The workspace's state directory.
  #[must_use]
  pub fn state_dir(&self) -> PathBuf {
    Workspace::new(&self.root).state_dir()
  }

  /// State directory the rewritten files land in.
  #[must_use]
  pub fn files_dir(&self) -> PathBuf {
    self.material_dir().join("files")
  }

  /// Guest pairs mint here; the adapters read them back for the decoy.
  #[must_use]
  pub fn guests_dir(&self) -> PathBuf {
    self.material_dir().join("guests")
  }

  /// Mounts for the workspace root and `[workspace] include`, deepest path
  /// first with overlaps absorbed: a covering mount serves the same files at
  /// its translated path, so covered paths drop out. A path that is not
  /// there is an error rather than a warning, because docker mounts an empty
  /// directory in its place.
  ///
  /// # Errors
  ///
  /// Returns an error when an include names a path that does not exist, or
  /// when that path is `/`, the home directory, or an ancestor of the
  /// workspace or the home directory.
  pub fn include_mounts(&self, includes: &[PathBuf]) -> Result<Vec<Mount>> {
    let workspace = std::fs::canonicalize(&self.root).unwrap_or_else(|_| self.root.clone());
    let home = self.host_home.as_deref().and_then(|path| std::fs::canonicalize(path).ok());
    let mut entries = vec![(self.root.clone(), false)];
    for entry in includes {
      let (path, ro) = split_mode(entry);
      let host = expand(&path, &self.root, self.host_home.as_deref());
      if !host.exists() {
        return Err(Error::IncludeMissing { entry: entry.clone() });
      }
      let canonical = std::fs::canonicalize(&host)?;
      if include_widens(&canonical, &workspace, home.as_deref()) {
        return Err(Error::IncludeWidens { entry: entry.clone() });
      }
      entries.push((host, ro));
    }
    entries.sort_by_key(|(path, _)| Reverse(path.components().count()));
    Ok(covering(
      entries
        .into_iter()
        .map(|(host, ro)| Mount {
          container: translate(&host, self.host_home.as_deref(), &self.home),
          host,
          ro,
        })
        .collect(),
    ))
  }

  /// The agent-side mounts carrying each mtls rule's guest identity: one pair
  /// minted per rule (`<guests-dir>/<label>.pem` plus `.key`,
  /// load-or-generate), mounted read-only at the container paths the rule's
  /// entries declare, or `{home}/.config/arkham/guest/<label>.pem` and `.key`
  /// when an entry states none. Compose is a placement consumer only:
  /// arkham-proxy reads the mode, the agent holds the identity files.
  ///
  /// # Errors
  ///
  /// Returns an error when a pair cannot be minted or written.
  pub fn guest_identity_mounts(&self, rules: &BTreeMap<String, RuleCfg>, ca: &CertAuthority, guests_dir: &Path) -> Result<Vec<Mount>> {
    let mut mounts = Vec::new();
    for (label, rule) in rules {
      let mtls: Vec<&HostTlsCfg> = rule.tls.values().filter(|tls| tls.guest_tls_mode == GuestTlsMode::Mtls).collect();
      if mtls.is_empty() {
        continue;
      }
      let (cert, key) = load_or_generate_client_pair(ca, guests_dir, label)?;
      for tls in mtls {
        let cert_container = tls
          .guest_cert
          .clone()
          .unwrap_or_else(|| PathBuf::from(format!("{home}/.config/arkham/guest/{label}.pem", home = self.home())));
        let key_container = tls
          .guest_key
          .clone()
          .unwrap_or_else(|| PathBuf::from(format!("{home}/.config/arkham/guest/{label}.key", home = self.home())));
        mounts.push(Mount {
          host: cert.clone(),
          container: cert_container,
          ro: true,
        });
        mounts.push(Mount {
          host: key.clone(),
          container: key_container,
          ro: true,
        });
      }
    }
    Ok(mounts)
  }
}

/// Whether `include` would replace the sandbox root, the home directory, or
/// an ancestor of either. `include`, `workspace`, and `home` are canonical.
fn include_widens(include: &Path, workspace: &Path, home: Option<&Path>) -> bool {
  if include == Path::new("/") {
    return true;
  }
  if home.is_some_and(|home| include == home) {
    return true;
  }
  if workspace.starts_with(include) && include != workspace {
    return true;
  }
  home.is_some_and(|home| home.starts_with(include) && include != home)
}

#[cfg(test)]
mod tests {
  use super::*;
  fn mount(host: &str, container: &str, ro: bool) -> Mount {
    Mount {
      host: PathBuf::from(host),
      container: PathBuf::from(container),
      ro,
    }
  }

  #[test]
  fn under_home_paths_translate_into_the_container_home() {
    let host_home = Path::new("/home/ivan");
    assert_eq!(
      translate(Path::new("/home/ivan/github/arkham"), Some(host_home), "/home/eng"),
      PathBuf::from("/home/eng/github/arkham")
    );
    assert_eq!(translate(Path::new("/data"), Some(host_home), "/home/eng"), PathBuf::from("/data"));
    assert_eq!(
      translate(Path::new("/home/ivan"), Some(host_home), "/home/eng"),
      PathBuf::from("/home/eng")
    );
  }

  #[test]
  fn covering_mounts_absorb_overlaps() {
    let mounts = vec![
      mount("/home/ivan/github/arkham", "/home/eng/github/arkham", false),
      mount("/home/ivan/github", "/home/eng/github", false),
      mount("/home/ivan/.config/mise", "/home/eng/.config/mise", true),
      mount("/opt/data", "/opt/data", false),
    ];
    let kept = covering(mounts);
    let hosts: Vec<String> = kept.iter().map(|m| m.host.display().to_string()).collect();
    assert_eq!(hosts, vec!["/home/ivan/github", "/home/ivan/.config/mise", "/opt/data"], "{kept:?}");
    assert!(kept[1].ro, "the surviving mount keeps its own mode");
  }

  #[test]
  fn an_include_of_root_home_or_an_ancestor_is_refused() {
    let base = tempfile::tempdir().unwrap();
    let base = base.path().canonicalize().unwrap();
    let home = base.join("home");
    let root = base.join("mid").join("proj");
    let sibling = base.join("mid").join("sibling");
    let mise = home.join(".config").join("mise");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&sibling).unwrap();
    std::fs::create_dir_all(&mise).unwrap();
    let layout = Layout::new(&root, "/home/eng".to_string(), Some(home.clone()));
    for entry in [
      PathBuf::from("/"),
      PathBuf::from("~"),
      PathBuf::from(".."),
      PathBuf::from("../.."),
      home.clone(),
    ] {
      let err = layout.include_mounts(std::slice::from_ref(&entry)).unwrap_err();
      assert!(err.to_string().contains("widens"), "{entry:?}: {err}");
    }
    let link = root.join("escape");
    std::os::unix::fs::symlink("/", &link).unwrap();
    let err = layout.include_mounts(&[PathBuf::from("escape")]).unwrap_err();
    assert!(err.to_string().contains("widens"), "{err}");
    let mounts = layout
      .include_mounts(&[PathBuf::from("../sibling"), PathBuf::from("~/.config/mise:ro")])
      .unwrap();
    assert!(mounts.iter().any(|mount| mount.host == sibling), "{mounts:?}");
    assert!(mounts.iter().any(|mount| mount.host == mise && mount.ro), "{mounts:?}");
  }

  #[test]
  fn include_entries_split_their_mount_mode() {
    assert_eq!(split_mode(Path::new("~/.config/mise:ro")), (PathBuf::from("~/.config/mise"), true));
    assert_eq!(split_mode(Path::new("/data/cache:rw")), (PathBuf::from("/data/cache"), false));
    assert_eq!(split_mode(Path::new("/data/cache")), (PathBuf::from("/data/cache"), false));
  }

  #[test]
  fn tilde_and_relative_includes_expand_against_root_and_home() {
    let root = Path::new("/home/ivan/github/arkham");
    let host_home = Some(Path::new("/home/ivan"));
    assert_eq!(
      expand(Path::new("~/.config/mise"), root, host_home),
      PathBuf::from("/home/ivan/.config/mise")
    );
    assert_eq!(
      expand(Path::new("../sibling"), root, host_home),
      PathBuf::from("/home/ivan/github/sibling")
    );
    assert_eq!(expand(Path::new("/opt/data"), root, host_home), PathBuf::from("/opt/data"));
  }
}
