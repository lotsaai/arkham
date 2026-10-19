//! Xpanda expansion for generation-time config values, mirroring tin.
//!
//! Values referencing `$VAR` resolve from the process environment first, then
//! from fnox for declared names the environment lacks. The expander runs with
//! `no_unset`, so a name found in neither is an error naming the variable —
//! never a silent empty string that turns `$HOME/bin/x` into `/bin/x`.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use secrecy::ExposeSecret as _;
use xpanda::Xpanda;

use crate::error::Error;
use arkham_config::config::{AppConfig, IfMissing, ProxyCfg, RuleCfg, WorkspaceCfg};
use arkham_config::registry::Registry;
use arkham_fnox::{FnoxSource, resolve};

/// Build the expander over the process environment plus fnox-resolved values.
pub(crate) fn build_expander(env: HashMap<String, String>) -> Xpanda {
  Xpanda::builder().no_unset(true).with_named_vars(env).build()
}

/// Expand one config value; an unset variable errors naming the variable.
pub(crate) fn expand_value(expander: &Xpanda, value: &str) -> Result<String, Error> {
  expander.expand(value).map_err(|error| Error::ExpandValue {
    detail: format!("{error:?}"),
  })
}

/// Expand a config value naming a path: `${VAR}` references first, then a
/// leading `~`. Both halves matter where a user writes a path by hand —
/// `$HOME/.cargo/bin/x` and `~/.cargo/bin/x` are equally natural and neither
/// expanded before.
pub(crate) fn expand_path(expander: &Xpanda, value: &str) -> Result<String, Error> {
  Ok(shellexpand::tilde(&expand_value(expander, value)?).into_owned())
}

/// Run an async fnox lookup from sync generation code. The binary runs on a
/// multi-thread runtime, so `block_in_place` lets the lookup use it; anywhere
/// else (tests, one-shot sync contexts) a fresh current-thread runtime serves.
pub(crate) fn block_on<Fut: Future>(future: Fut) -> Result<Fut::Output, Error> {
  match tokio::runtime::Handle::try_current() {
    Ok(handle) => Ok(tokio::task::block_in_place(|| handle.block_on(future))),
    Err(_) => Ok(
      tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|source| Error::BlockOn { source })?
        .block_on(future),
    ),
  }
}

/// Values for `names`: the process environment first, overlaid with fnox for
/// declared names the environment lacks. Names found in neither are left out
/// so the `no_unset` expander errors naming them.
pub(crate) async fn resolution_env(
  registry: &Registry,
  fnox: Option<&FnoxSource>,
  names: &BTreeSet<String>,
) -> Result<HashMap<String, String>, Error> {
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

/// Byte-replace every real value with its decoy, longest reals first so a
/// real that contains a shorter one cannot partially shadow it.
pub(crate) fn apply_rewrites(content: &[u8], pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
  let mut ordered: Vec<&(Vec<u8>, Vec<u8>)> = pairs.iter().collect();
  ordered.sort_by_key(|(real, _)| Reverse(real.len()));
  let mut out = content.to_vec();
  for (real, decoy) in ordered {
    if real.is_empty() {
      continue;
    }
    let mut replaced = Vec::with_capacity(out.len());
    let mut rest = out.as_slice();
    while let Some(at) = rest.windows(real.len()).position(|window| window == real.as_slice()) {
      replaced.extend_from_slice(&rest[..at]);
      replaced.extend_from_slice(decoy);
      rest = &rest[at + real.len()..];
    }
    replaced.extend_from_slice(rest);
    out = replaced;
  }
  out
}

/// Output file name for a rewrite inside the state `files/` directory:
/// index-prefixed basename so two sources with the same file name cannot
/// collide.
pub(crate) fn rewrite_file_name(index: usize, source: &Path) -> PathBuf {
  let base = source.file_name().and_then(|name| name.to_str()).unwrap_or("rewrite");
  PathBuf::from(format!("{index:02}-{base}"))
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

  /// Reals swap for decoys, longest first; empty reals never match.
  #[test]
  fn rewrites_bytes_longest_real_first() {
    let out = apply_rewrites(
      b"token=abc12345 user=abc",
      &[(b"abc".to_vec(), b"X".to_vec()), (b"abc12345".to_vec(), b"DECOY".to_vec())],
    );
    assert_eq!(out, b"token=DECOY user=X");
    assert_eq!(apply_rewrites(b"abc", &[(Vec::new(), b"X".to_vec())]), b"abc");
  }

  /// Index-prefixed basenames; files without a name fall back.
  #[test]
  fn names_rewrite_outputs_stably() {
    assert_eq!(rewrite_file_name(3, Path::new("/home/u/.npmrc")), PathBuf::from("03-.npmrc"));
  }
}
