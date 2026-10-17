//! Ambient-source pass: the authentication sources every workspace carries —
//! gitconfig, jj, ssh, nats, kubectl, talosctl — mapped onto grants plus the
//! agent's decoy twin at each tool's default path.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::decoys::Decoy;
use crate::error::Error;
use crate::expand::expand_path;
use crate::git;
use crate::jj;
use crate::kube;
use crate::nats;
use crate::paths::{Mount, expand};
use crate::rewrites::{RewriteCollector, RewriteOutputs};
use crate::ssh;
use crate::talos;
use arkham_config::config::{FileRewrite, config_dir};
use arkham_config::registry::Registry;
use arkham_pki::ca::{CertAuthority, load_or_generate};
use dirs::config_dir as dirs_config_dir;
use xpanda::Xpanda;

/// Inputs for [`derive_sources`]: the generation context the ambient
/// sources read.
pub(crate) struct DeriveInputs<'a> {
  /// State directory the decoy twins land in.
  pub(crate) files_dir: &'a Path,
  /// Workspace root git resolution starts from.
  pub(crate) root: &'a Path,
  /// Host-known registry joining forge hosts to env names.
  pub(crate) registry: &'a Registry,
  /// Selected decoys supplying the replacement values.
  pub(crate) decoys: &'a [Decoy],
  /// Xpanda expander for comparing declared sources.
  pub(crate) expander: &'a Xpanda,
  /// Container home the twins mount under.
  pub(crate) home: &'a str,
  /// Host home the default source paths live under.
  pub(crate) host_home: Option<&'a Path>,
  /// Guest-identity directory the kube and talos adapters mint into.
  pub(crate) guests_dir: &'a Path,
  /// Declared rewrites: an explicitly-declared source stays with its
  /// declaration, not the ambient default.
  pub(crate) rewrites: &'a [FileRewrite],
}

/// Read the ambient authentication sources every workspace carries — no
/// declaration, like fnox's own chain — and map each onto grants plus the
/// agent's decoy twin at the tool's default path. The gitconfig resolves
/// from the workspace root the way `git` there resolves it; jj reads its
/// user chain; the ssh, nats, kubectl, and talosctl configs come from their
/// default paths. An absent source derives nothing; a present one that
/// does not map fails closed naming the file.
///
/// # Errors
///
/// Returns an error naming the source when it cannot be read or does not
/// map, when the guest CA cannot be loaded, or when an output cannot be
/// written.
///
/// ponytail: no opt-out exists yet; none has been asked for.
/// `KUBECONFIG`/`TALOSCONFIG` honor a single path — a list warns and falls
/// back to the default.
pub(crate) fn derive_sources(inputs: &DeriveInputs<'_>) -> Result<RewriteOutputs, Error> {
  let DeriveInputs {
    files_dir,
    root,
    registry,
    decoys,
    expander,
    home,
    host_home,
    guests_dir,
    rewrites,
  } = *inputs;
  let Some(host_home) = host_home else {
    return Ok(RewriteOutputs {
      mounts: Vec::new(),
      grants: Vec::new(),
    });
  };
  let declared = rewrites
    .iter()
    .map(|rewrite| {
      let expanded = PathBuf::from(expand_path(expander, &rewrite.source.to_string_lossy())?);
      Ok(expand(&expanded, root, Some(host_home)))
    })
    .collect::<Result<Vec<_>, Error>>()?;
  let mut deriver = AmbientDeriver {
    root,
    registry,
    decoys,
    home,
    host_home,
    guests_dir,
    declared,
    ca: None,
    collector: RewriteCollector::new(files_dir)?,
  };
  deriver.git()?;
  deriver.jj()?;
  deriver.ssh()?;
  deriver.nats()?;
  deriver.kube_and_talos()?;
  Ok(deriver.collector.outputs())
}

/// One workspace's ambient-source pass: the authentication sources every
/// workspace carries — gitconfig, jj, ssh, nats, kubectl, talosctl — map onto
/// grants plus the agent's decoy twin at the tool's default path. A source
/// the workspace declared explicitly stays with its declaration; a present
/// source that does not map warns, and one whose guest CA is unavailable
/// skips.
struct AmbientDeriver<'a> {
  /// Workspace root git resolution starts from.
  root: &'a Path,
  /// Host-known registry joining forge hosts to env names.
  registry: &'a Registry,
  /// Selected decoys supplying the replacement values.
  decoys: &'a [Decoy],
  /// Container home the twins mount under.
  home: &'a str,
  /// Host home the default source paths live under.
  host_home: &'a Path,
  /// Guest-identity directory the kube and talos adapters mint into.
  guests_dir: &'a Path,
  /// Sources the workspace declared explicitly; the ambient pass leaves
  /// them to their declarations.
  declared: Vec<PathBuf>,
  /// The guest CA, loaded on first use.
  ca: Option<CertAuthority>,
  /// Grants and decoy mounts collected along the way.
  collector: RewriteCollector,
}

impl AmbientDeriver<'_> {
  /// The gitconfig chain `git` at the workspace root resolves.
  ///
  /// # Errors
  ///
  /// Returns an error when the twin output cannot be written.
  fn git(&mut self) -> Result<(), Error> {
    let mut git_sources = vec![self.host_home.join(".gitconfig")];
    if let Some(dir) = dirs_config_dir() {
      git_sources.push(dir.join("git").join("config"));
    }
    if let Some(path) = env::var_os("GIT_CONFIG_GLOBAL") {
      git_sources.push(PathBuf::from(path));
    }
    if git_sources.iter().any(|path| self.declared.contains(path)) {
      return Ok(());
    }
    let first = &git_sources[0];
    match git::adapt(first, self.root, self.registry, self.decoys, self.home, self.host_home) {
      Ok(adapted) => self.collector.twin(adapted, "gitconfig", &format!("{}/.gitconfig", self.home)),
      Err(err) => {
        tracing::warn!(source = %first.display(), %err, "gitconfig source skipped");
        Ok(())
      }
    }
  }

  /// The full host jj config dir, mounted writable.
  ///
  /// # Errors
  ///
  /// Returns an error when the twin output cannot be written.
  fn jj(&mut self) -> Result<(), Error> {
    if jj::chain_paths().iter().any(|path| self.declared.contains(path)) {
      return Ok(());
    }
    let host_jj = jj::config_path().parent().map(Path::to_path_buf).unwrap_or_default();
    if !host_jj.as_os_str().is_empty() {
      if self.declared.iter().any(|path| path == &host_jj || path.starts_with(&host_jj)) {
        return Ok(());
      }
      if host_jj.is_dir() {
        self.collector.mounts.push(Mount {
          host: host_jj,
          container: PathBuf::from(format!("{}/.config/jj", self.home)),
          ro: false,
        });
        return Ok(());
      }
    }
    if let Some(adapted) = jj::adapt(self.root) {
      let dest = format!("{}/.config/jj/config.toml", self.home);
      return self.collector.twin(vec![adapted], "jj-config", &dest);
    }
    Ok(())
  }

  /// The ssh config at its default path.
  ///
  /// # Errors
  ///
  /// Returns an error when the config cannot be read or the twin output
  /// cannot be written.
  fn ssh(&mut self) -> Result<(), Error> {
    let ssh_config = self.host_home.join(".ssh").join("config");
    if self.declared.contains(&ssh_config) || !ssh_config.is_file() {
      return Ok(());
    }
    let content = fs::read(&ssh_config).map_err(|source| Error::ReadFile {
      path: ssh_config.clone(),
      source,
    })?;
    let dest = format!("{}/.ssh/config", self.home);
    match ssh::adapt(&ssh_config, &content, self.home, self.host_home) {
      Ok(adapted) => self.collector.twin(adapted, "ssh-config", &dest),
      Err(err) => {
        tracing::warn!(source = %ssh_config.display(), %err, "ssh source skipped");
        Ok(())
      }
    }
  }

  /// The selected NATS CLI context under `~/.config/nats`.
  ///
  /// # Errors
  ///
  /// Returns an error when the twin output cannot be written. A context
  /// that does not map warns and derives nothing.
  fn nats(&mut self) -> Result<(), Error> {
    let root = self.host_home.join(".config").join("nats");
    let selected = root.join("context.txt");
    if self.declared.iter().any(|path| path == &root || path.starts_with(&root)) || !selected.is_file() {
      return Ok(());
    }
    match nats::adapt(&root, self.home, self.host_home) {
      Ok(Some(found)) => self.collector.twin(found.adapted, "nats-context", &found.context_dest),
      Ok(None) => Ok(()),
      Err(err) => {
        tracing::warn!(source = %root.display(), %err, "nats source skipped");
        Ok(())
      }
    }
  }

  /// The kubeconfig and talosconfig at their default paths, honoring a
  /// single-path `KUBECONFIG`/`TALOSCONFIG` override.
  ///
  /// # Errors
  ///
  /// Returns an error when a twin output cannot be written.
  fn kube_and_talos(&mut self) -> Result<(), Error> {
    for (name, env_name, default, twin_name, twin_dest) in [
      ("kubeconfig", "KUBECONFIG", ".kube/config", "kube-config", ".kube/config"),
      ("talosconfig", "TALOSCONFIG", ".talos/config", "talos-config", ".talos/config"),
    ] {
      let path = env_source(env_name, default, self.host_home);
      if self.declared.contains(&path) || !path.is_file() {
        continue;
      }
      let Ok(content) = fs::read(&path) else {
        tracing::warn!(source = %path.display(), "{name} source skipped: it cannot be read");
        continue;
      };
      let guests_dir = self.guests_dir;
      let ca = match self.ca() {
        Ok(ca) => ca,
        Err(err) => {
          tracing::warn!(source = %path.display(), %err, "{name} source skipped: the guest CA is unavailable");
          continue;
        }
      };
      let adapted = match name {
        "kubeconfig" => kube::adapt(&path, &content, ca, guests_dir)
          .ok()
          .flatten()
          .map(|adapted| vec![adapted])
          .unwrap_or_default(),
        _ => talos::adapt(&path, &content, ca, guests_dir)
          .map(|adapted| vec![adapted])
          .ok()
          .unwrap_or_default(),
      };
      if adapted.is_empty() {
        tracing::warn!(source = %path.display(), "{name} source skipped: it does not map onto a grant");
        continue;
      }
      self.collector.twin(adapted, twin_name, &format!("{}/{twin_dest}", self.home))?;
    }
    Ok(())
  }

  /// The guest CA for the kubeconfig and talosconfig adapters, loaded on
  /// first use.
  ///
  /// # Errors
  ///
  /// Returns an error when the arkham config directory or the CA cannot be
  /// loaded.
  fn ca(&mut self) -> Result<&CertAuthority, Error> {
    if self.ca.is_none() {
      let ca_path = config_dir()
        .ok_or_else(|| Error::ConfigDir {
          detail: "ambient kubeconfig derivation needs the arkham config directory to load the CA from".to_string(),
        })?
        .join("ca.pem");
      self.ca = Some(load_or_generate(&ca_path).map_err(|source| Error::GuestCa { path: ca_path, source })?);
    }
    match self.ca.as_ref() {
      Some(ca) => Ok(ca),
      None => Err(Error::ConfigDir {
        detail: "the ambient guest CA slot is empty after loading it".to_string(),
      }),
    }
  }
}

/// The source path one `KUBECONFIG`-style override names, or the default
/// under the host home.
fn env_source(env_name: &str, default: &str, host_home: &Path) -> PathBuf {
  match env::var(env_name) {
    Ok(value) if !value.contains(':') => PathBuf::from(value),
    Ok(value) => {
      tracing::warn!(env_name, value, "names multiple paths; using the default location instead");
      host_home.join(default)
    }
    Err(_) => host_home.join(default),
  }
}
