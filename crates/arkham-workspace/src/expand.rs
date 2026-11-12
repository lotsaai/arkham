//! Xpanda expansion for generation-time config values, mirroring tin.
//!
//! Values referencing `$VAR` resolve from the process environment first, then
//! from fnox for declared names the environment lacks. The expander runs with
//! `no_unset`, so a name found in neither is an error naming the variable —
//! never a silent empty string that turns `$HOME/bin/x` into `/bin/x`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::net::SocketAddr;

use secrecy::ExposeSecret as _;
use xpanda::Xpanda;

use crate::{Error, Result};
use arkham_config::config::{AppConfig, IfMissing, ProxyCfg, RuleCfg, WorkspaceCfg};
use arkham_config::registry::Registry;
use arkham_fnox::{FnoxSource, resolve};

/// Build the expander over the process environment plus fnox-resolved values.
#[must_use]
pub fn build_expander(env: HashMap<String, String, std::hash::RandomState>) -> Xpanda {
  Xpanda::builder().no_unset(true).with_named_vars(env).build()
}

/// Expand one config value; an unset variable errors naming the variable.
///
/// # Errors
///
/// Returns an error if expansion fails, including when a variable is unset.
pub fn expand_value(expander: &Xpanda, value: &str) -> Result<String> {
  expander.expand(value).map_err(|error| Error::ExpandValue {
    detail: format!("{error:?}"),
  })
}

/// Expand a config value naming a path: `${VAR}` references first, then a
/// leading `~`. Both halves matter where a user writes a path by hand —
/// `$HOME/.cargo/bin/x` and `~/.cargo/bin/x` are equally natural and neither
/// expanded before.
///
/// # Errors
///
/// Returns an error if variable expansion fails.
pub fn expand_path(expander: &Xpanda, value: &str) -> Result<String> {
  Ok(shellexpand::tilde(&expand_value(expander, value)?).into_owned())
}

/// Values for `names`: the process environment first, overlaid with fnox for
/// declared names the environment lacks. Names found in neither are left out
/// so the `no_unset` expander errors naming them.
///
/// # Errors
///
/// Returns an error if fnox resolution fails or a resolved secret has no value.
pub async fn resolution_env(registry: &Registry, fnox: Option<&FnoxSource>, names: &BTreeSet<String>) -> Result<HashMap<String, String>> {
  let mut env: HashMap<String, String> = env::vars().collect();
  let Some(fnox) = fnox else {
    return Ok(env);
  };
  let missing: Vec<String> = names.iter().filter(|name| !env.contains_key(name.as_str())).cloned().collect();
  let declared: Vec<String> = missing.into_iter().filter(|name| fnox.declared().contains(name.as_str())).collect();
  if declared.is_empty() {
    return Ok(env);
  }
  let mut synthetic = synthetic_config(&declared);
  resolve(&mut synthetic, registry, Some(fnox.clone())).await?;
  for (label, rule) in &synthetic.rules {
    if let Some(value) = rule.value.as_ref() {
      env.insert(rule.env.clone(), value.expose_secret().to_owned());
    } else {
      return Err(Error::SecretNoValue { name: label.clone() });
    }
  }
  Ok(env)
}

/// A throwaway config whose only job is reading arbitrary fnox names through
/// the existing [`arkham_fnox::resolve`]: one endpoint rule per name with a
/// dummy `allow` so the rule survives host resolution. Only `value` is read
/// back; the rest is discarded.
fn synthetic_config(names: &[String]) -> AppConfig {
  AppConfig {
    proxy: ProxyCfg {
      listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
      handoff_socket: None,
      handoff_uid: None,
      ca_file: None,
      ssh_host_key: None,
      ssh_known_hosts: None,
      root_certs: Vec::new(),
      handshake_timeout_secs: 10,
    },
    workspace: WorkspaceCfg::default(),
    rules: names
      .iter()
      .map(|name| {
        (
          name.clone(),
          RuleCfg {
            env: name.clone(),
            value: None,
            real: None,
            generated: false,
            fnox_key: None,
            allow: vec!["https://localhost.invalid".to_string()],
            pattern: None,
            oauth2: None,
            registry: None,
            if_missing: IfMissing::Error,
            tls: BTreeMap::new(),
            ssh: BTreeMap::new(),
          },
        )
      })
      .collect(),
    plugins: BTreeMap::new(),
    tools: BTreeMap::new(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// `${VAR}` expands from the env, `${VAR:-default}` falls back, and an
  /// unset var errors naming the var.
  #[test]
  fn expands_values_and_names_unset_vars() {
    let expander = build_expander(HashMap::from([("HOME".to_string(), "/root".to_string())]));
    assert_eq!(expand_value(&expander, "$HOME/bin").unwrap(), "/root/bin");
    assert_eq!(expand_value(&expander, "${MISSING:-dflt}").unwrap(), "dflt");
    let error = expand_value(&expander, "${MISSING_NO_DEFAULT}").unwrap_err().to_string();
    assert!(error.contains("MISSING_NO_DEFAULT"), "{error}");
  }

  /// Paths expand vars then tilde.
  #[test]
  fn expands_paths_with_tilde_after_vars() {
    let expander = build_expander(HashMap::from([("TOP".to_string(), "/srv".to_string())]));
    assert_eq!(expand_path(&expander, "$TOP/x").unwrap(), "/srv/x");
    assert_eq!(
      expand_path(&expander, "~/.npmrc").unwrap(),
      shellexpand::tilde("~/.npmrc").into_owned()
    );
  }
}
