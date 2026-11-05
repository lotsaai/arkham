//! Live project registry for host backends.
//!
//! One proxy process holds every registered project. Capture attributes a
//! flow to a cgroup id, and that id selects the project's secret set. An
//! unknown id, including zero, uses the process snapshot the proxy was built
//! with. A host daemon builds that snapshot empty, so an unknown flow splices.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use arkham_config::grants::ResolvedConfig;
use arkham_pki::ca::CertAuthority;

use crate::connection::trust_anchors;
use crate::mint::MintStore;
use crate::{Error, HttpsRelay, ProxyState, entry_anchors, https_relay};

/// One registered project: its resolved config and the relays that config's
/// trust bundles need. The mint store is per project so issued pairs do not
/// cross projects.
pub(crate) struct Project {
  config: Arc<ResolvedConfig>,
  plugins: Arc<arkham_plugin::Registry>,
  mint_store: MintStore,
  relay: HttpsRelay,
  extra_relays: HashMap<PathBuf, HttpsRelay>,
}

/// Projects keyed by cgroup id. The lock is held only around the map.
pub(crate) struct Projects {
  inner: Mutex<HashMap<u64, Project>>,
}

impl Projects {
  pub(crate) fn new() -> Self {
    Self {
      inner: Mutex::new(HashMap::new()),
    }
  }

  fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Project>> {
    self.inner.lock().unwrap_or_else(PoisonError::into_inner)
  }
}

/// The HTTPS relay plus one relay per distinct `root_cert` bundle.
pub(crate) fn build_relays(resolved: &ResolvedConfig, ca: &CertAuthority) -> Result<(HttpsRelay, HashMap<PathBuf, HttpsRelay>), Error> {
  let mut global = Vec::new();
  for path in &resolved.proxy.root_certs {
    global.extend(trust_anchors(path)?);
  }
  let relay = https_relay(ca, &global)?;
  let mut extra_relays = HashMap::new();
  for path in entry_anchors(resolved) {
    let mut anchors = global.clone();
    anchors.extend(trust_anchors(&path)?);
    let extra_relay = https_relay(ca, &anchors).map_err(|source| Error::EntryTrustBundle {
      path: path.clone(),
      source: Box::new(source),
    })?;
    extra_relays.insert(path, extra_relay);
  }
  Ok((relay, extra_relays))
}

impl ProxyState {
  /// Register `resolved` under `cgroup_id`.
  ///
  /// The id is the cgroup directory inode capture records. Zero is not a
  /// cgroup, and registering it would make every unattributed flow use this
  /// project.
  ///
  /// # Errors
  ///
  /// Returns an error when `cgroup_id` is zero, a plugin cannot be loaded,
  /// or a trust bundle cannot be read.
  pub fn register_project(&self, cgroup_id: u64, resolved: ResolvedConfig, ca: &CertAuthority) -> Result<(), Error> {
    if cgroup_id == 0 {
      return Err(Error::ProjectCgroup);
    }
    let plugins = Arc::new(arkham_plugin::Registry::load(&resolved.plugins)?);
    let (relay, extra_relays) = build_relays(&resolved, ca)?;
    let project = Project {
      config: Arc::new(resolved),
      plugins,
      mint_store: MintStore::default(),
      relay,
      extra_relays,
    };
    self.projects.lock().insert(cgroup_id, project);
    Ok(())
  }

  /// Drop the project registered at `cgroup_id`. A missing id is the session
  /// already being gone.
  pub fn unregister_project(&self, cgroup_id: u64) {
    self.projects.lock().remove(&cgroup_id);
  }

  /// Config for `cgroup_id`, or the process snapshot when the id is unknown.
  #[must_use]
  pub fn snapshot_for(&self, cgroup_id: u64) -> Arc<ResolvedConfig> {
    if cgroup_id != 0
      && let Some(project) = self.projects.lock().get(&cgroup_id)
    {
      return Arc::clone(&project.config);
    }
    Arc::clone(&self.config)
  }

  /// Plugin registry for `cgroup_id`, or the process registry when unknown.
  #[must_use]
  pub(crate) fn plugins_for(&self, cgroup_id: u64) -> Arc<arkham_plugin::Registry> {
    if cgroup_id != 0
      && let Some(project) = self.projects.lock().get(&cgroup_id)
    {
      return Arc::clone(&project.plugins);
    }
    Arc::clone(&self.plugins)
  }

  /// Mint store for `cgroup_id`. An unknown id uses the process store.
  #[must_use]
  pub(crate) fn mint_for(&self, cgroup_id: u64) -> MintStore {
    if cgroup_id != 0
      && let Some(project) = self.projects.lock().get(&cgroup_id)
    {
      return project.mint_store.clone();
    }
    self.mint_store.clone()
  }

  /// Relay for this flow's project and optional per-entry trust bundle.
  ///
  /// # Errors
  ///
  /// Returns [`Error::UnknownTrustBundle`] when the entry names a bundle the
  /// project's relays do not contain.
  pub(crate) fn relay_for(&self, cgroup_id: u64, root_cert: Option<&Path>) -> Result<HttpsRelay, Error> {
    let projects = self.projects.lock();
    let project = (cgroup_id != 0).then(|| projects.get(&cgroup_id)).flatten();
    let relay = match &project {
      Some(item) => &item.relay,
      None => &self.relay,
    };
    let extra = match &project {
      Some(item) => &item.extra_relays,
      None => &self.extra_relays,
    };
    match root_cert {
      None => Ok(relay.clone()),
      Some(path) => extra
        .get(path)
        .cloned()
        .ok_or_else(|| Error::UnknownTrustBundle { path: path.to_path_buf() }),
    }
  }
}

#[cfg(test)]
mod tests {
  use std::net::{Ipv4Addr, SocketAddr};

  use arkham_config::config::ProxyCfg;
  use arkham_config::grants::{Credential, EndpointScope, Grant, Scheme};
  use secrecy::SecretString;

  use super::*;

  fn proxy() -> ProxyCfg {
    ProxyCfg {
      listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
      ca_file: None,
      ssh_host_key: None,
      ssh_known_hosts: None,
      root_certs: Vec::new(),
      handshake_timeout_secs: 10,
    }
  }

  fn resolved(label: &str) -> ResolvedConfig {
    ResolvedConfig {
      proxy: proxy(),
      grants: vec![Grant::Token {
        credential: Credential {
          label: label.into(),
          fake: format!("fake-{label}"),
          value: SecretString::from(format!("real-{label}")),
        },
        allow: vec![EndpointScope {
          scheme: Scheme::Https,
          host: "example.com".parse().expect("host"),
          port: 443,
          client_cert: None,
          client_key: None,
          root_cert: None,
          guest_tls: arkham_config::grants::GuestTlsMode::Tls,
        }],
        pattern: None,
        oauth2: None,
      }],
      plugins: Vec::new(),
    }
  }

  fn state(ca: &CertAuthority) -> ProxyState {
    ProxyState::new(
      ResolvedConfig {
        proxy: proxy(),
        grants: Vec::new(),
        plugins: Vec::new(),
      },
      ca,
    )
    .expect("state")
  }

  #[test]
  fn registered_cgroup_selects_its_project_and_unknown_keeps_the_base() {
    arkham_pki::ca::install_crypto_provider();
    let ca = CertAuthority::generate().expect("ca");
    let state = state(&ca);
    let base = state.snapshot();
    assert!(base.grants.is_empty());
    state.register_project(7, resolved("one"), &ca).expect("register");
    assert!(state.snapshot().grants.is_empty(), "the base snapshot stays empty");
    assert_eq!(state.snapshot_for(0).grants.len(), 0);
    assert_eq!(state.snapshot_for(99).grants.len(), 0);
    let selected = state.snapshot_for(7);
    assert_eq!(selected.grants.len(), 1);
    state.unregister_project(7);
    assert!(state.snapshot_for(7).grants.is_empty());
    let err = state.register_project(0, resolved("zero"), &ca).expect_err("zero");
    assert!(matches!(err, Error::ProjectCgroup));
    let _ = Arc::new(state);
  }
}
