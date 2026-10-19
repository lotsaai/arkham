//! Mount layout: host paths resolved against one workspace root, home pair,
//! and state directory. Generation builds one layout and resolves every
//! mount through it instead of threading the three paths through free
//! functions.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use arkham_config::config::WorkspaceBuild;
use arkham_config::config::{HostTlsCfg, RuleCfg};
use arkham_config::grants::GuestTlsMode;
use arkham_pki::ca::{CertAuthority, load_or_generate_client_pair};
use dirs::config_dir as dirs_config_dir;

use crate::error::Error;
use crate::paths::{Mount, covering, expand, translate};
use crate::workspace::Workspace;

/// Container path both services mount the runtime bypass file at: the agent
/// entrypoint rewrites it from `podman network inspect`, and arkham's eBPF
/// loader reloads it live into the programs' bypass list. The host side is
/// `<workspace-state>/ebpf-bypass`, created at generation and never
/// overwritten — the agent owns its contents at runtime.
pub(crate) const BYPASS_CONTAINER_PATH: &str = "/arkham/ebpf-bypass";

/// What the arkham service mounts and forwards so the container's fnox resolves
/// what the host's does: its config directory (identity, providers, config),
/// arkham's own fnox level.
#[derive(Default)]
pub(crate) struct FnoxBinds {
  pub(crate) mounts: Vec<Mount>,
}

impl FnoxBinds {
  /// Bind mounts for the fnox and arkham config levels that exist on the
  /// host. Every mount is conditional on the host path existing: docker turns
  /// a bind of a missing path into a directory, which is never what we want.
  /// Container paths are what fnox and arkham look at inside, where the home
  /// is `/root`.
  pub(crate) fn resolve(fnox_dir: Option<&Path>, config_dir: Option<&Path>) -> Self {
    let mut binds = Self { mounts: Vec::new() };
    if let Some(dir) = fnox_dir.filter(|dir| dir.is_dir()) {
      binds.mounts.push(Mount {
        host: dir.to_path_buf(),
        container: PathBuf::from("/root/.config/fnox"),
        ro: true,
      });
    }
    let mut levels = config_dir
      .and_then(|dir| std::fs::read_dir(dir).ok())
      .into_iter()
      .flatten()
      .flatten()
      .map(|entry| entry.path())
      .filter(|path| {
        path.is_file()
          && path.file_name().is_some_and(|name| {
            let name = name.to_string_lossy();
            name.starts_with("fnox") && name.ends_with(".toml")
          })
      })
      .collect::<Vec<_>>();
    levels.sort();
    for path in levels {
      binds.mounts.push(Mount {
        container: Path::new("/root/.config/arkham").join(path.file_name().unwrap_or_default()),
        host: path,
        ro: true,
      });
    }
    let rules_d = config_dir.map(|dir| dir.join("rules.d")).filter(|dir| dir.is_dir());
    if let Some(dir) = rules_d {
      binds.mounts.push(Mount {
        host: dir,
        container: PathBuf::from("/root/.config/arkham/rules.d"),
        ro: true,
      });
    }
    binds
  }
}

/// Resolved mount context for one generation run: the workspace root, the
/// container home, and the host home. Mount resolution reads through this
/// owner.
pub(crate) struct Layout {
  /// Workspace root, absolute.
  root: PathBuf,
  /// The expanded container home.
  home: String,
  /// The host home, when resolvable.
  host_home: Option<PathBuf>,
}

/// Split a trailing `:ro` or `:rw` off an include entry; bare paths are rw.
/// A single-caller string split, kept beside its caller instead of attached
/// to the layout it never reads.
pub(crate) fn split_mode(entry: &Path) -> (PathBuf, bool) {
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
  pub(crate) fn new(root: &Path, home: String, host_home: Option<PathBuf>) -> Self {
    Self {
      root: root.to_path_buf(),
      home,
      host_home,
    }
  }

  /// The absolute workspace root.
  pub(crate) fn root(&self) -> &Path {
    &self.root
  }

  /// The expanded container home.
  pub(crate) fn home(&self) -> &str {
    &self.home
  }

  /// The host home, when resolvable.
  pub(crate) fn host_home(&self) -> Option<&Path> {
    self.host_home.as_deref()
  }

  /// The workspace's state directory.
  pub(crate) fn state_dir(&self) -> PathBuf {
    Workspace::new(&self.root).state_dir()
  }

  /// State directory the rewritten files land in.
  pub(crate) fn files_dir(&self) -> PathBuf {
    self.state_dir().join("files")
  }

  /// Guest pairs mint here; the adapters read them back for the decoy.
  pub(crate) fn guests_dir(&self) -> PathBuf {
    self.state_dir().join("guests")
  }

  /// Mounts for the workspace root and `[workspace] include`, deepest path
  /// first with overlaps absorbed: a covering mount serves the same files at
  /// its translated path, so covered paths drop out. A path that is not
  /// there is an error rather than a warning, because docker mounts an empty
  /// directory in its place.
  ///
  /// # Errors
  ///
  /// Returns an error when an include names a path that does not exist.
  pub(crate) fn include_mounts(&self, includes: &[PathBuf]) -> Result<Vec<Mount>, Error> {
    let mut entries = vec![(self.root.clone(), false)];
    for entry in includes {
      let (path, ro) = split_mode(entry);
      let host = expand(&path, &self.root, self.host_home.as_deref());
      if !host.exists() {
        return Err(Error::IncludeMissing { entry: entry.clone() });
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

  /// Resolve `[workspace.build]` to absolute host paths for compose, failing
  /// loudly on a missing dockerfile or context: compose would fail without
  /// naming the setting.
  ///
  /// # Errors
  ///
  /// Returns an error when the dockerfile is not a file or the context is
  /// not a directory.
  pub(crate) fn resolve_build(&self, build: &WorkspaceBuild) -> Result<(PathBuf, PathBuf), Error> {
    let dockerfile = expand(&build.dockerfile, &self.root, self.host_home.as_deref());
    if !dockerfile.is_file() {
      return Err(Error::BuildDockerfileMissing {
        path: build.dockerfile.clone(),
      });
    }
    let context = expand(&build.context, &self.root, self.host_home.as_deref());
    if !context.is_dir() {
      return Err(Error::BuildContextMissing {
        path: build.context.clone(),
      });
    }
    Ok((context, dockerfile))
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
  pub(crate) fn guest_identity_mounts(
    &self,
    rules: &BTreeMap<String, RuleCfg>,
    ca: &CertAuthority,
    guests_dir: &Path,
  ) -> Result<Vec<Mount>, Error> {
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

  /// The shared bypass-file mount for ebpf stacks, rendered into both
  /// services: the agent entrypoint writes it, arkham only reads, and one
  /// read-write entry serves both because the `mounts` vec renders as-is in
  /// each service.
  pub(crate) fn bypass_mount(&self) -> Mount {
    Mount {
      host: self.state_dir().join("ebpf-bypass"),
      container: PathBuf::from(BYPASS_CONTAINER_PATH),
      ro: false,
    }
  }

  /// The fnox config directory fnox itself resolves: `FNOX_CONFIG_DIR`, else
  /// `<config-dir>/fnox`.
  pub(crate) fn fnox_config_dir(&self) -> Option<PathBuf> {
    if let Some(dir) = env::var_os("FNOX_CONFIG_DIR") {
      return Some(PathBuf::from(dir));
    }
    dirs_config_dir()
      .or_else(|| self.host_home.as_deref().map(|home| home.join(".config")))
      .map(|dir| dir.join("fnox"))
  }
}

#[cfg(test)]
mod moved_suite {

  use crate::mounts::*;

  use crate::test_support::*;

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
