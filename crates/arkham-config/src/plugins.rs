//! WASM plugin config: `[plugins.<name>]` table plus grant resolution.
//!
//! Each plugin names a component path, an `allow` list parsed exactly like
//! rule grants, and a direction gate. Empty or unparsable `allow` fails
//! startup, same posture as rules.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::error::Error;
use crate::grants::EndpointScope;

/// Which direction a plugin rewrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginDirection {
  /// Rewrite request and response legs.
  #[default]
  Both,
  /// Rewrite requests only.
  Request,
  /// Rewrite responses only.
  Response,
}

/// One `[plugins.<name>]` entry: component path, grant-shaped allow list,
///
/// direction gate.
#[derive(confique::Config, Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginCfg {
  /// Filesystem path to the component (`.wasm`).
  pub path: PathBuf,
  /// Raw `scheme://host[:port]` allow entries; parsed like rule grants.
  #[serde(default)]
  pub allow: Vec<String>,
  /// Direction gate; defaults to both legs.
  #[serde(default)]
  pub direction: PluginDirection,
}

/// One resolved plugin: parsed grants plus load path.
#[derive(Debug, Clone)]
pub struct ResolvedPlugin {
  /// Config label (`[plugins.<name>]`).
  pub name: String,
  /// Component path as configured.
  pub path: PathBuf,
  /// Parsed allow entries. A plugin matches on scheme, host and port, so a
  /// database entry scopes it to that endpoint and carries no extra meaning.
  pub allow: Vec<EndpointScope>,
  /// Direction gate.
  pub direction: PluginDirection,
}

/// Parse every plugin's `allow` entries into grants.
///
/// # Errors
///
/// Returns an error when a plugin has an empty `allow` list or an entry
/// is not a valid URI grant.
pub fn resolve_plugins(cfg: &AppConfig) -> Result<Vec<ResolvedPlugin>, Error> {
  let mut plugins = Vec::with_capacity(cfg.plugins.len());
  for (name, plugin) in &cfg.plugins {
    if plugin.allow.is_empty() {
      return Err(Error::PluginEmptyAllow { name: name.clone() });
    }
    let mut allow = Vec::with_capacity(plugin.allow.len());
    for entry in &plugin.allow {
      let uri: EndpointScope = entry.parse().map_err(|err| Error::PluginBadAllow {
        name: name.clone(),
        entry: entry.clone(),
        detail: err,
      })?;
      allow.push(uri);
    }
    plugins.push(ResolvedPlugin {
      name: name.clone(),
      path: plugin.path.clone(),
      allow,
      direction: plugin.direction,
    });
  }
  Ok(plugins)
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeMap;

  use super::*;
  use crate::config::{ProxyCfg, WorkspaceCfg};
  use crate::grants::Scheme;

  fn endpoint(scope: &EndpointScope) -> &EndpointScope {
    scope
  }
  fn cfg_with(name: &str, path: &str, allow: Vec<&str>, direction: Option<PluginDirection>) -> AppConfig {
    let mut plugins = BTreeMap::new();
    plugins.insert(
      name.to_string(),
      PluginCfg {
        path: PathBuf::from(path),
        allow: allow.into_iter().map(str::to_string).collect(),
        direction: direction.unwrap_or_default(),
      },
    );
    AppConfig {
      proxy: ProxyCfg {
        listen: "127.0.0.1:8080".parse().unwrap(),
        handoff_socket: None,
        handoff_uid: None,
        ca_file: None,
        ssh_host_key: None,
        ssh_known_hosts: None,
        root_certs: Vec::new(),
        handshake_timeout_secs: 10,
      },
      workspace: WorkspaceCfg::default(),
      rules: BTreeMap::new(),
      plugins,
      tools: BTreeMap::new(),
    }
  }

  #[test]
  fn plugin_allow_parses_like_rules() {
    let cfg = cfg_with(
      "sigv4",
      "/tmp/sigv4.wasm",
      vec!["https://api.example.com", "https://*.example.com:8443"],
      None,
    );
    let resolved = resolve_plugins(&cfg).unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].name, "sigv4");
    assert_eq!(endpoint(&resolved[0].allow[0]).scheme, Scheme::Https);
    assert_eq!(endpoint(&resolved[0].allow[0]).port, 443);
    assert_eq!(endpoint(&resolved[0].allow[1]).port, 8443);
  }

  #[test]
  fn plugin_empty_allow_fails_startup() {
    let cfg = cfg_with("sigv4", "/tmp/sigv4.wasm", vec![], None);
    let _ = resolve_plugins(&cfg).unwrap_err();
  }

  #[test]
  fn plugin_direction_defaults_to_both() {
    let cfg = cfg_with("sigv4", "/tmp/sigv4.wasm", vec!["https://api.example.com"], None);
    let resolved = resolve_plugins(&cfg).unwrap();
    assert_eq!(resolved[0].direction, PluginDirection::Both);
  }

  #[test]
  fn plugin_invalid_allow_entry_fails_startup() {
    let cfg = cfg_with("sigv4", "/tmp/sigv4.wasm", vec!["not-a-grant"], None);
    let _ = resolve_plugins(&cfg).unwrap_err();
  }
}
