//! Prepare projected files and grants for host sessions.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use arkham_config::config::{AppConfig, config_dir, project_profiles_dir};
use arkham_config::grants::GuestTlsMode;
use dirs::home_dir;
use rustix::process::getuid;
use xpanda::Xpanda;

use crate::adapt::{RewriteAdapted, load_guest_ca};
use crate::ambient::{DeriveInputs, derive_sources};
use crate::decoys::{Decoy, Selection, validate_passthrough};
use crate::error::Error;
use crate::expand::{build_expander, expand_path, expand_value, resolution_env};
use crate::mounts::Layout;
use crate::paths::Mount;
use crate::profiles::{ProfileRoots, profile_mounts};
use crate::rewrites::{RewriteInputs, write_rewrites};
use crate::workspace::Workspace;

/// What a host session needs from the compose pipeline, without a rendered stack.
pub(crate) struct HostMaterial {
  /// Workspace config, before grant fragments are merged.
  pub config: AppConfig,
  /// Fnox source discovered from the project root.
  pub fnox: Option<arkham_fnox::FnoxSource>,
  /// Registry joined against that source.
  pub registry: arkham_config::registry::Registry,
  /// Decoy env values.
  pub decoys: Vec<Decoy>,
  /// Adapter grants, real fragments still in memory.
  pub grants: Vec<RewriteAdapted>,
  /// Include mounts, workspace root included.
  pub mounts: Vec<Mount>,
  /// Rewritten file mounts.
  pub file_mounts: Vec<Mount>,
  /// Tool profile mounts.
  pub tool_mounts: Vec<Mount>,
  /// Guest identity mounts.
  pub guest: Vec<Mount>,
  /// Names copied through from the operator environment.
  pub passthrough: Vec<String>,
  /// Configured shell, when one is set.
  pub shell: Option<String>,
  /// Workspace root.
  pub workspace: PathBuf,
}

struct StackBuilder {
  /// Mount layout: root, container home, and host home every mount resolves
  /// against.
  layout: Layout,
  /// Secret selection: fnox discovery joined against the registry.
  selection: Selection,
  /// The workspace's merged config.
  config: AppConfig,
  /// Expansion environment: the process env plus fnox-resolved names.
  env: HashMap<String, String>,
  /// Xpanda expander built over `env`.
  expander: Xpanda,
  /// Include-derived mounts, deepest path first.
  mounts: Vec<Mount>,
  /// Decoys for the agent environment, from [`StackBuilder::secrets`].
  decoys: Vec<Decoy>,
  /// Adapter grants from rewrites and ambient sources.
  grants: Vec<RewriteAdapted>,
  /// Rewritten-file mounts, from [`StackBuilder::rewrites`] and
  /// [`StackBuilder::ambient`].
  file_mounts: Vec<Mount>,
  /// Tool-profile mounts, from [`StackBuilder::profiles`].
  tool_mounts: Vec<Mount>,
  /// Guest-identity mounts, from [`StackBuilder::guest_identities`].
  guest: Vec<Mount>,
}

impl StackBuilder {
  /// Resolve the workspace config, registry, fnox, and include mounts.
  ///
  /// # Errors
  ///
  /// Returns an error when the registry or config fails to load, when value
  /// resolution fails, or when a path fails to expand.
  async fn resolve(root: &Path, scratch: &Path) -> Result<Self, Error> {
    let workspace = Workspace::new(root);
    let config = workspace.config()?;
    let selection = Selection::load_from(root)?;
    let host = home_dir();
    let raw_home = host.clone().ok_or(Error::NoHome)?.to_string_lossy().into_owned();
    let referenced = config.workspace.referenced_variables(&[raw_home.as_str()]);
    let env = resolution_env(&selection.registry, selection.fnox.as_ref(), &referenced).await?;
    let expander = build_expander(env.clone());
    let home = expand_value(&expander, &raw_home)?;
    let layout = Layout::new(root, home, host).with_scratch(scratch.to_path_buf());
    let includes: Vec<PathBuf> = config
      .workspace
      .include
      .iter()
      .map(|entry| expand_path(&expander, &entry.to_string_lossy()).map(PathBuf::from))
      .collect::<Result<_, Error>>()?;
    let mounts = layout.include_mounts(&includes)?;
    Ok(Self {
      layout,
      selection,
      config,
      env,
      expander,
      mounts,
      decoys: Vec::new(),
      grants: Vec::new(),
      file_mounts: Vec::new(),
      tool_mounts: Vec::new(),
      guest: Vec::new(),
    })
  }

  /// Select the decoys the agent environment holds, reshaped by each rule's
  /// own pattern — serve-time substitution derives its fake from
  /// `rule.pattern`, so a registry default would never match — and check the
  /// passthrough names against them.
  ///
  /// # Errors
  ///
  /// Returns an error when a passthrough name overlaps a rule env or a
  /// selected decoy.
  fn secrets(mut self) -> Result<Self, Error> {
    self.decoys = self.selection.apply_rule_patterns(self.selection.select(), &self.config.rules);
    validate_passthrough(&self.config.rules, &self.decoys, &self.config.workspace.passthrough)?;
    if let Some(warning) = self.selection.coverage_warning(&self.config.workspace.passthrough) {
      tracing::warn!("{warning}");
    }
    Ok(self)
  }

  /// The declared `[workspace] file_rewrite` entries: decoy twins written
  /// under the state directory and mounted read-only into the agent, plus
  /// the grants their adapters derive.
  ///
  /// # Errors
  ///
  /// Returns an error when a rewrite names an env with no known value or no
  /// decoy, or its dest does not expand to an absolute container path.
  async fn rewrites(mut self) -> Result<Self, Error> {
    let files_dir = self.layout.files_dir();
    let guests_dir = self.layout.guests_dir();
    let rewritten = write_rewrites(&RewriteInputs {
      files_dir: &files_dir,
      root: self.layout.root(),
      rewrites: &self.config.workspace.file_rewrite,
      decoys: &self.decoys,
      env: &self.env,
      expander: &self.expander,
      home: self.layout.home(),
      host_home: self.layout.host_home(),
      guests_dir: &guests_dir,
    })
    .await?;
    self.grants = rewritten.grants;
    self.file_mounts = rewritten.mounts;
    Ok(self)
  }

  /// The ambient sources — gitconfig, jj, ssh, nats, kube, talos from their
  /// default locations: decoy twins mounted read-only plus the grants they
  /// derive, joined onto the declared rewrites.
  ///
  /// # Errors
  ///
  /// Returns an error when a source does not map onto grants or a decoy
  /// twin.
  async fn ambient(mut self) -> Result<Self, Error> {
    let files_dir = self.layout.files_dir();
    let guests_dir = self.layout.guests_dir();
    let derived = derive_sources(&DeriveInputs {
      files_dir: &files_dir,
      root: self.layout.root(),
      registry: &self.selection.registry,
      decoys: &self.decoys,
      expander: &self.expander,
      home: self.layout.home(),
      host_home: self.layout.host_home(),
      guests_dir: &guests_dir,
      rewrites: &self.config.workspace.file_rewrite,
    })
    .await?;
    self.grants.extend(derived.grants);
    self.file_mounts.extend(derived.mounts);
    Ok(self)
  }

  /// The tool-config mounts for the selected profile.
  ///
  /// # Errors
  ///
  /// Returns an error when a `[tools.*]` name or `config_dir` is invalid, or
  /// a profile directory cannot be created.
  fn profiles(mut self) -> Result<Self, Error> {
    let global_profiles = config_dir().map(|dir| dir.join("profiles"));
    let project_profiles = project_profiles_dir(self.layout.root());
    let roots = ProfileRoots {
      project: Some(project_profiles.as_path()),
      global: global_profiles.as_deref(),
    };
    self.tool_mounts = profile_mounts(&roots, self.config.workspace.profile_name(), &self.config.tools, self.layout.home())?;
    Ok(self)
  }

  /// Guest identity pairs for rules that request mTLS, minted from the CA
  /// and mounted read-only at their declared container paths; none when no
  /// rule requests one.
  ///
  /// # Errors
  ///
  /// Returns an error when the config directory does not resolve, the CA
  /// cannot load, or a pair cannot be written.
  fn guest_identities(mut self) -> Result<Self, Error> {
    let mtls = self
      .config
      .rules
      .values()
      .any(|rule| rule.tls.values().any(|tls| tls.guest_tls_mode == GuestTlsMode::Mtls));
    if mtls {
      let ca = load_guest_ca("a guest identity needs the arkham config directory to load the CA from")?;
      let guests_dir = self.layout.guests_dir();
      self.guest = self.layout.guest_identity_mounts(&self.config.rules, &ca, &guests_dir)?;
    }
    Ok(self)
  }
}

/// Prepare host session material while keeping real grant fragments in memory.
///
/// # Errors
///
/// Returns whatever step fails: config, discovery, rewrites, ambient
/// derivation, profiles, or guest identities.
pub(crate) async fn host_material(root: &Path, scratch: &Path, _version: &str) -> Result<HostMaterial, Error> {
  let built = StackBuilder::resolve(root, scratch)
    .await?
    .secrets()?
    .rewrites()
    .await?
    .ambient()
    .await?
    .profiles()?
    .guest_identities()?;
  Ok(HostMaterial {
    passthrough: built.config.workspace.passthrough.clone(),
    shell: built.config.workspace.shell.clone(),
    workspace: root.to_path_buf(),
    config: built.config,
    fnox: built.selection.fnox,
    registry: built.selection.registry,
    decoys: built.decoys,
    grants: built.grants,
    mounts: built.mounts,
    file_mounts: built.file_mounts,
    tool_mounts: built.tool_mounts,
    guest: built.guest,
  })
}

/// The process's user id, from the kernel: the same value `id -u` prints,
/// without the subprocess.
pub(crate) fn current_uid() -> u32 {
  getuid().as_raw()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::decoys::{uncovered_names, uncovered_warning};
  use arkham_config::config::{HostTlsCfg, IfMissing, RuleCfg};
  use arkham_pki::ca::CertAuthority;
  use std::collections::{BTreeMap, BTreeSet};
  use std::fs;

  fn mtls_rule(guest_cert: Option<&str>, guest_key: Option<&str>) -> BTreeMap<String, RuleCfg> {
    let mut tls = BTreeMap::new();
    tls.insert(
      "https://api.github.com".to_string(),
      HostTlsCfg {
        client_cert: None,
        client_key: None,
        root_cert: None,
        guest_tls_mode: GuestTlsMode::Mtls,
        guest_cert: guest_cert.map(PathBuf::from),
        guest_key: guest_key.map(PathBuf::from),
      },
    );
    let rule = RuleCfg {
      env: "GITHUB_TOKEN".into(),
      value: None,
      real: None,
      generated: false,
      fnox_key: None,
      allow: vec!["https://api.github.com".to_string()],
      pattern: None,
      registry: None,
      oauth2: None,
      tls,
      ssh: BTreeMap::new(),
      if_missing: IfMissing::default(),
    };
    let mut rules = BTreeMap::new();
    rules.insert("github".to_string(), rule);
    rules
  }

  /// One minted pair per rule, mounted read-only at the declared container
  /// paths, and the second call is a no-op: the pair on disk is kept.
  #[test]
  fn guest_identity_mounts_declared_paths_and_keeps_an_existing_pair() {
    let ca = CertAuthority::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::new(dir.path(), "/root".to_string(), None);
    let guests = dir.path().join("guests");
    let rules = mtls_rule(Some("/safe/cert.pem"), Some("/safe/cert.key"));
    let mounts = layout.guest_identity_mounts(&rules, &ca, &guests).unwrap();
    assert_eq!(mounts.len(), 2);
    assert_eq!(mounts[0].container, PathBuf::from("/safe/cert.pem"));
    assert_eq!(mounts[1].container, PathBuf::from("/safe/cert.key"));
    assert!(mounts.iter().all(|mount| mount.ro));
    assert!(mounts[0].host.is_file() && mounts[1].host.is_file());
    let cert_before = fs::read(&mounts[0].host).unwrap();
    let again = layout.guest_identity_mounts(&rules, &ca, &guests).unwrap();
    assert_eq!(again[0].host, mounts[0].host);
    assert_eq!(fs::read(&mounts[0].host).unwrap(), cert_before);
  }

  /// An entry that declares no container paths gets the per-rule default
  /// under the agent's home.
  #[test]
  fn guest_identity_defaults_the_container_paths_when_none_declared() {
    let ca = CertAuthority::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::new(dir.path(), "/root".to_string(), None);
    let rules = mtls_rule(None, None);
    let mounts = layout.guest_identity_mounts(&rules, &ca, &dir.path().join("guests")).unwrap();
    assert_eq!(mounts[0].container, PathBuf::from("/root/.config/arkham/guest/github.pem"));
    assert_eq!(mounts[1].container, PathBuf::from("/root/.config/arkham/guest/github.key"));
  }

  /// A passthrough name that is also a rule env or a decoy fails, naming
  /// the name; disjoint names pass.
  #[test]
  fn passthrough_overlapping_a_rule_or_decoy_fails() {
    let rules = mtls_rule(None, None);
    let decoys = vec![Decoy {
      env: "ANTHROPIC_API_KEY".to_string(),
      value: "decoy".to_string(),
    }];
    let error = validate_passthrough(&rules, &[], &["GITHUB_TOKEN".to_string()])
      .unwrap_err()
      .to_string();
    assert!(error.contains("GITHUB_TOKEN"), "{error}");
    let error = validate_passthrough(&rules, &decoys, &["ANTHROPIC_API_KEY".to_string()])
      .unwrap_err()
      .to_string();
    assert!(error.contains("ANTHROPIC_API_KEY"), "{error}");
    validate_passthrough(&rules, &decoys, &["DISPLAY".to_string()]).unwrap();
  }

  /// Uncovered keeps declared names minus selection, passthrough, and
  /// fnox's own wiring; the warning sorts and names them with a fix.
  #[test]
  fn uncovered_diff_excludes_selected_passthrough_and_fnox_wiring() {
    let declared = BTreeSet::from([
      "GITHUB_TOKEN".to_string(),
      "WAYLAND_DISPLAY".to_string(),
      "DISPLAY".to_string(),
      "FNOX_PROFILE".to_string(),
    ]);
    let uncovered = uncovered_names(&declared, &["GITHUB_TOKEN".to_string()], &["WAYLAND_DISPLAY".to_string()]);
    assert_eq!(uncovered, vec!["DISPLAY".to_string()]);
    let warning = uncovered_warning(&["B".to_string(), "A".to_string()]).unwrap();
    assert!(warning.contains("A, B"), "{warning}");
    assert!(warning.contains("[workspace] passthrough"), "{warning}");
    assert_eq!(uncovered_warning(&[]), None);
  }
}
