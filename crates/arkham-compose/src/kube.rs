//! Kubeconfig adapter for `file_rewrite`: a kubectl config file is a
//! differently structured form of the same information a rule holds, so the
//! adapter derives the grant from the file instead of asking the operator to
//! state it twice. Only the `current-context` maps; the file is the secret
//! source, so a kube entry stating `envs` is an error rather than a second
//! source.
//!
//! Detection is structural: a YAML mapping with `kind: Config` and a
//! `clusters:` table takes the adapter path, everything else keeps the raw
//! byte-swap. The decoy twin keeps the server (transparent capture makes the
//! destination the identity) and swaps the trust and identity: arkham's CA,
//! the minted guest pair, and the decoy token.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use arkham_config::config::{HostTlsCfg, RewriteFormat, fake_for};
use arkham_config::grants::{EndpointScope, GuestTlsMode, Scheme, decoy_for_rule};
use arkham_pki::ca::{CertAuthority, load_or_generate_client_pair};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_yaml::{Mapping, Value, from_str};

use crate::adapt::{GrantFragment, RewriteAdapted, decode, materialize_client_tls, render_decoy, render_fragment, rewrite_label};
use crate::error::Error;

/// A kubeconfig document; unknown fields ignored.
#[derive(Debug, Deserialize, Default)]
struct KubeDoc {
  /// Document kind: `Config` for kubeconfigs.
  #[serde(default)]
  kind: String,
  /// Active context name.
  #[serde(rename = "current-context", default)]
  current_context: String,
  /// Named context refs.
  #[serde(default)]
  contexts: Vec<KubeContextEntry>,
  /// Named clusters.
  #[serde(default)]
  clusters: Vec<KubeClusterEntry>,
  /// Named users.
  #[serde(default)]
  users: Vec<KubeUserEntry>,
}

/// One `contexts` entry: a name over a cluster/user pair.
#[derive(Debug, Deserialize, Default)]
struct KubeContextEntry {
  /// Entry name, matched against `current-context`.
  #[serde(default)]
  name: String,
  /// The referenced cluster and user.
  #[serde(default)]
  context: KubeContextRef,
}

/// The cluster/user a context points at.
#[derive(Debug, Deserialize, Default)]
struct KubeContextRef {
  /// Referenced cluster name.
  #[serde(default)]
  cluster: String,
  /// Referenced user name.
  #[serde(default)]
  user: String,
}

/// One `clusters` entry.
#[derive(Debug, Deserialize, Default)]
struct KubeClusterEntry {
  /// Entry name, matched against the context's `cluster`.
  #[serde(default)]
  name: String,
  /// The server and its trust anchor.
  #[serde(default)]
  cluster: KubeCluster,
}

/// A cluster's server and CA, inline or by file.
#[derive(Debug, Deserialize, Default)]
struct KubeCluster {
  /// API server URL.
  #[serde(default)]
  server: String,
  /// Inline base64 CA bundle.
  #[serde(rename = "certificate-authority-data", default)]
  ca_data: Option<String>,
  /// CA bundle file path: inline it first, the container cannot see it.
  #[serde(rename = "certificate-authority", default)]
  ca_file: Option<String>,
}

/// One `users` entry.
#[derive(Debug, Deserialize, Default)]
struct KubeUserEntry {
  /// Entry name, matched against the context's `user`.
  #[serde(default)]
  name: String,
  /// The credential.
  #[serde(default)]
  user: KubeUser,
}

/// A user's credential: bearer token and/or client pair, inline or by file.
#[derive(Debug, Deserialize, Default)]
struct KubeUser {
  /// Bearer token.
  #[serde(default)]
  token: Option<String>,
  /// Cloud auth-provider token.
  #[serde(rename = "auth-provider", default)]
  auth_provider: Option<KubeAuthProvider>,
  /// Exec credential plugin: unsupported, detected so it errors clearly.
  #[serde(default)]
  exec: Option<Mapping>,
  /// Inline base64 client certificate.
  #[serde(rename = "client-certificate-data", default)]
  cert_data: Option<String>,
  /// Client certificate file path: inline it first.
  #[serde(rename = "client-certificate", default)]
  cert_file: Option<String>,
  /// Inline base64 client key.
  #[serde(rename = "client-key-data", default)]
  key_data: Option<String>,
  /// Client key file path: inline it first.
  #[serde(rename = "client-key", default)]
  key_file: Option<String>,
}

/// A cloud auth provider block.
#[derive(Debug, Deserialize, Default)]
struct KubeAuthProvider {
  /// Provider config holding the token.
  #[serde(default)]
  config: KubeProviderConfig,
}

/// Auth provider config.
#[derive(Debug, Deserialize, Default)]
struct KubeProviderConfig {
  /// Bearer token.
  #[serde(rename = "access-token", default)]
  access_token: Option<String>,
}

/// The selection `current-context` resolves to, validated: its cluster and
/// user, the server scope, and the bearer token if any.
struct Selected<'a> {
  cluster: &'a KubeClusterEntry,
  user: &'a KubeUserEntry,
  scope: EndpointScope,
  token: Option<&'a str>,
}

impl KubeDoc {
  /// Resolve and validate the `current-context` selection: known context,
  /// known cluster with an HTTPS server, known user.
  ///
  /// # Errors
  ///
  /// Returns an error when the context is missing or unknown, names no
  /// cluster or user, the cluster states no server or a non-HTTPS one, or
  /// the user is unknown.
  fn selected(&self, invalid: impl Fn(String) -> Error) -> Result<Selected<'_>, Error> {
    if self.current_context.is_empty() {
      return Err(invalid("missing `current-context`".to_string()));
    }
    let context = self
      .contexts
      .iter()
      .find(|entry| entry.name == self.current_context)
      .ok_or_else(|| invalid(format!("unknown context `{}`", self.current_context)))?;
    if context.context.cluster.is_empty() || context.context.user.is_empty() {
      return Err(invalid(format!("context `{}` names no `cluster` or no `user`", context.name)));
    }
    let cluster = self
      .clusters
      .iter()
      .find(|entry| entry.name == context.context.cluster)
      .ok_or_else(|| invalid(format!("unknown cluster `{}`", context.context.cluster)))?;
    if cluster.cluster.server.is_empty() {
      return Err(invalid(format!("cluster `{}` states no `server`", cluster.name)));
    }
    let scope: EndpointScope = cluster
      .cluster
      .server
      .parse()
      .map_err(|detail| invalid(format!("server `{}` is not an allow entry: {detail}", cluster.cluster.server)))?;
    if scope.scheme != Scheme::Https {
      return Err(invalid(format!(
        "server `{}` is plain HTTP: the API server is TLS-only",
        cluster.cluster.server
      )));
    }
    let user = self
      .users
      .iter()
      .find(|entry| entry.name == context.context.user)
      .ok_or_else(|| invalid(format!("unknown user `{}`", context.context.user)))?;
    let token = user
      .user
      .token
      .as_deref()
      .or_else(|| {
        user
          .user
          .auth_provider
          .as_ref()
          .and_then(|provider| provider.config.access_token.as_deref())
      })
      .filter(|token| !token.is_empty());
    Ok(Selected {
      cluster,
      user,
      scope,
      token,
    })
  }
}

/// Map a kubeconfig onto its grant fragment and decoy twin. Returns `None`
/// when the document is not a kubeconfig after all, leaving the caller on
/// the raw path.
///
/// # Errors
///
/// Returns an error when the document does not parse, names no usable
/// current context, states a non-HTTPS server, or carries no substitutable
/// credential.
pub(crate) fn adapt(source: &Path, content: &[u8], ca: &CertAuthority, guests_dir: &Path) -> Result<Option<RewriteAdapted>, Error> {
  let text = String::from_utf8_lossy(content);
  let doc: KubeDoc = from_str(&text).map_err(|err| Error::RewriteYaml {
    file: source.to_path_buf(),
    source: err,
  })?;
  if doc.kind != "Config" {
    return Ok(None);
  }
  let invalid = |detail: String| Error::RewriteInvalid {
    file: source.to_path_buf(),
    format: RewriteFormat::Kubeconfig,
    detail,
  };
  let Selected {
    cluster,
    user,
    scope,
    token,
  } = doc.selected(invalid)?;
  if user.user.cert_file.is_some() || user.user.key_file.is_some() || cluster.cluster.ca_file.is_some() {
    return Err(invalid(
      "uses file references; inline them first: `kubectl config view --flatten --minify`".to_string(),
    ));
  }
  if user.user.exec.is_some() && token.is_none() && user.user.cert_data.is_none() && user.user.key_data.is_none() {
    return Err(invalid("exec credential plugins are not supported".to_string()));
  }
  let cert = decode(
    source,
    RewriteFormat::Kubeconfig,
    user.user.cert_data.as_deref(),
    "client-certificate-data",
  )?;
  let key = decode(source, RewriteFormat::Kubeconfig, user.user.key_data.as_deref(), "client-key-data")?;
  if cert.is_some() != key.is_some() {
    return Err(invalid(format!("user `{}` carries half of the client pair", user.name)));
  }
  if token.is_none() && cert.is_none() {
    return Err(invalid(format!(
      "user `{}` carries neither `token` nor a client pair: nothing to substitute",
      user.name
    )));
  }
  let ca_bundle = decode(
    source,
    RewriteFormat::Kubeconfig,
    cluster.cluster.ca_data.as_deref(),
    "certificate-authority-data",
  )?;
  let label = rewrite_label(source, &doc.current_context)?;
  let env = label.to_uppercase().replace('-', "_");
  // Identity-only grants (cert auth, no bearer) still need a value to
  // resolve; the certificate never reaches the wire as application data, so
  // it can never match the swap.
  let value = token.map_or_else(
    || String::from_utf8_lossy(&cert.clone().unwrap_or_default()).into_owned(),
    str::to_string,
  );
  let (decoy_token, _) = decoy_for_rule(&env, None, &[scope], value.len());
  let blobs = kube_blobs(&label, cert, key, ca_bundle, ca, guests_dir)?;
  let fragment = render_fragment(
    source,
    &label,
    &GrantFragment {
      env,
      registry: false,
      allow: vec![cluster.cluster.server.clone()],
      value: Some(value),
      real: None,
      generated: false,
      if_missing: None,
      tls: BTreeMap::from([(cluster.cluster.server.clone(), blobs.tls)]),
      ssh: BTreeMap::new(),
    },
  )?;
  let decoy = decoy_doc(
    &text,
    source,
    ca,
    &blobs.guest_cert,
    &blobs.guest_key,
    &user.name,
    token.map(|_| decoy_token.as_str()),
  )?;
  Ok(Some(RewriteAdapted {
    fragment,
    decoy,
    materialized: blobs.materialized,
    decoy_files: Vec::new(),
  }))
}

/// The per-rule TLS identity and the blobs that back it, plus the guest pair
/// the decoy embeds.
struct KubeBlobs {
  tls: HostTlsCfg,
  materialized: Vec<(String, Vec<u8>)>,
  guest_cert: Vec<u8>,
  guest_key: Vec<u8>,
}

/// Mint the guest pair, materialize the identity blobs, and assemble the
/// per-entry TLS identity for one derived rule.
///
/// # Errors
///
/// Returns an error when the guest pair cannot be minted or its files read.
fn kube_blobs(
  label: &str,
  cert: Option<Vec<u8>>,
  key: Option<Vec<u8>>,
  ca_bundle: Option<Vec<u8>>,
  ca: &CertAuthority,
  guests_dir: &Path,
) -> Result<KubeBlobs, Error> {
  let (guest_cert_path, guest_key_path) = load_or_generate_client_pair(ca, guests_dir, label)?;
  let guest_cert = fs::read(&guest_cert_path).map_err(|source| Error::ReadFile {
    path: guest_cert_path.clone(),
    source,
  })?;
  let guest_key = fs::read(&guest_key_path).map_err(|source| Error::ReadFile {
    path: guest_key_path.clone(),
    source,
  })?;
  // A client pair means mutual TLS both ways: the guest presents the
  // minted pair, the proxy the real one upstream. Token-only users carry
  // no client certificate, so asking for one fails their handshake with
  // `certificate required` before any bearer swap can happen.
  let (client_cert, client_key, guest_tls_mode) = match (cert, key) {
    (Some(cert), Some(key)) => (Some(cert), Some(key), GuestTlsMode::Mtls),
    _ => (None, None, GuestTlsMode::Tls),
  };
  let (tls, materialized) = materialize_client_tls(label, client_cert, client_key, ca_bundle, guest_tls_mode);
  Ok(KubeBlobs {
    tls,
    materialized,
    guest_cert,
    guest_key,
  })
}

/// The agent's decoy kubeconfig: the parsed document verbatim, with trust
/// and identity swapped in every entry — arkham's CA under every cluster,
/// the guest pair and a decoy token in every user — because only decoys may
/// cross into the agent. `exec` blocks and file-reference credentials are
/// dropped from every user: they run host binaries or point at host paths
/// the agent cannot see. Every other field, spec'd or not, round-trips
/// unchanged.
fn decoy_doc(
  text: &str,
  source: &Path,
  ca: &CertAuthority,
  guest_cert: &[u8],
  guest_key: &[u8],
  active_user: &str,
  active_decoy: Option<&str>,
) -> Result<String, Error> {
  let mut root: Value = from_str(text).map_err(|err| Error::RewriteYaml {
    file: source.to_path_buf(),
    source: err,
  })?;
  let guest_ca = Value::String(STANDARD.encode(ca.cert_pem()));
  let guest_cert = Value::String(STANDARD.encode(guest_cert));
  let guest_key = Value::String(STANDARD.encode(guest_key));
  for cluster in entries_mut(&mut root, "clusters") {
    let Some(inner) = cluster
      .get_mut(Value::String("cluster".to_string()))
      .and_then(Value::as_mapping_mut)
    else {
      continue;
    };
    let ca_data = Value::String("certificate-authority-data".to_string());
    if inner.contains_key(&ca_data) {
      inner.insert(ca_data, guest_ca.clone());
    }
    inner.remove(Value::String("certificate-authority".to_string()));
  }
  for user in entries_mut(&mut root, "users") {
    let name = user
      .get(Value::String("name".to_string()))
      .and_then(Value::as_str)
      .unwrap_or_default()
      .to_string();
    let Some(inner) = user.get_mut(Value::String("user".to_string())).and_then(Value::as_mapping_mut) else {
      continue;
    };
    let placeholder = || fake_for(&format!("KUBE_{}", name.to_uppercase().replace(['-', '.'], "_")), None);
    if inner.contains_key(Value::String("token".to_string())) {
      let decoy = if name == active_user {
        active_decoy.map(str::to_string)
      } else {
        None
      }
      .unwrap_or_else(placeholder);
      inner.insert(Value::String("token".to_string()), Value::String(decoy));
    }
    let cert_data = Value::String("client-certificate-data".to_string());
    let key_data = Value::String("client-key-data".to_string());
    if inner.contains_key(&cert_data) || inner.contains_key(&key_data) {
      inner.insert(cert_data, guest_cert.clone());
      inner.insert(key_data, guest_key.clone());
    }
    inner.remove(Value::String("client-certificate".to_string()));
    inner.remove(Value::String("client-key".to_string()));
    let auth_provider = Value::String("auth-provider".to_string());
    if let Some(config) = inner
      .get_mut(&auth_provider)
      .and_then(Value::as_mapping_mut)
      .and_then(|provider| provider.get_mut(Value::String("config".to_string())))
      .and_then(Value::as_mapping_mut)
      && config.contains_key(Value::String("access-token".to_string()))
    {
      config.insert(Value::String("access-token".to_string()), Value::String(placeholder()));
    }
    if inner.contains_key(Value::String("password".to_string())) {
      inner.insert(Value::String("password".to_string()), Value::String(placeholder()));
    }
    inner.remove(Value::String("exec".to_string()));
  }
  render_decoy(&root)
}

/// The `key` list of `root` as mutable mappings; entries that are not
/// mappings contribute nothing.
fn entries_mut<'a>(root: &'a mut Value, key: &str) -> Vec<&'a mut Mapping> {
  root
    .as_mapping_mut()
    .and_then(|map| map.get_mut(Value::String(key.to_string())))
    .and_then(Value::as_sequence_mut)
    .map_or_else(Vec::new, |seq| seq.iter_mut().filter_map(Value::as_mapping_mut).collect())
}

#[cfg(test)]
mod tests {
  use arkham_config::config::RuleCfg;
  use serde::Deserialize;

  use super::*;
  use crate::adapt::write_state;

  const BEARER_DOC: &str = r"apiVersion: v1
kind: Config
current-context: k3s-local
contexts:
- name: k3s-local
  context: {cluster: k3s, user: admin}
clusters:
- name: k3s
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: admin
  user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}
";

  const SOURCE: &str = "/home/ivan/.kube/k3s.yaml";

  fn test_ca() -> CertAuthority {
    CertAuthority::generate().unwrap()
  }

  fn adapt_doc(doc: &str) -> RewriteAdapted {
    let dir = tempfile::tempdir().unwrap();
    adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path())
      .expect("adapt parses")
      .expect("bearer doc is a kubeconfig")
  }

  #[derive(Debug, Deserialize)]
  struct RulesDoc {
    rules: BTreeMap<String, RuleCfg>,
  }

  fn rules_from(fragment: &str) -> BTreeMap<String, RuleCfg> {
    toml_edit::de::from_str::<RulesDoc>(fragment).expect("fragment parses").rules
  }

  #[test]
  fn foreign_content_is_not_a_kubeconfig() {
    let npmrc = "//registry.npmjs.org/:_authToken=secret";
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), npmrc.as_bytes(), &test_ca(), dir.path()).expect_err("plain text fails closed");
    assert!(err.to_string().contains("does not parse as YAML"), "{err}");
  }

  #[test]
  fn label_slugs_the_source_path_and_context() {
    let label = rewrite_label(Path::new(SOURCE), "k3s-local").expect("path slugs");
    assert_eq!(label, "home-ivan-kube-k3s-k3s-local");
    let adapted = adapt_doc(BEARER_DOC);
    assert!(
      adapted.fragment.contains("[rules.home-ivan-kube-k3s-k3s-local]"),
      "{}",
      adapted.fragment
    );
  }

  #[test]
  fn fragment_holds_the_grant_and_parses_as_a_rule() {
    let adapted = adapt_doc(BEARER_DOC);
    let rules = rules_from(&adapted.fragment);
    let rule = rules.get("home-ivan-kube-k3s-k3s-local").expect("rule present");
    assert_eq!(rule.env, "HOME_IVAN_KUBE_K3S_K3S_LOCAL");
    assert_eq!(rule.allow, vec!["https://10.0.0.1:6443".to_string()]);
    assert_eq!(rule.registry, Some(false));
    assert!(rule.value.is_some(), "bearer token is the inline real value");
    let tls = rule.tls.get("https://10.0.0.1:6443").expect("tls keyed by the allow entry");
    assert!(
      tls
        .client_cert
        .as_ref()
        .is_some_and(|path| path.ends_with("home-ivan-kube-k3s-k3s-local.client.crt"))
    );
    assert!(
      tls
        .root_cert
        .as_ref()
        .is_some_and(|path| path.ends_with("home-ivan-kube-k3s-k3s-local.ca.crt"))
    );
    assert_eq!(tls.guest_tls_mode, GuestTlsMode::Mtls);
    assert_eq!(adapted.materialized.len(), 3, "pair plus CA materialize beside the fragment");
  }

  #[test]
  fn decoy_keeps_the_server_and_swaps_trust_identity_and_token() {
    let adapted = adapt_doc(BEARER_DOC);
    assert!(adapted.decoy.contains("server: https://10.0.0.1:6443"), "{}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("k3s-token"),
      "no real credential survives: {}",
      adapted.decoy
    );
    assert!(!adapted.decoy.contains("Q0E="), "no real CA survives: {}", adapted.decoy);
    assert!(!adapted.decoy.contains("Q0VSVA=="), "no real pair survives: {}", adapted.decoy);
    assert!(adapted.decoy.contains("token: "), "decoy token present: {}", adapted.decoy);
    assert!(
      adapted.decoy.contains("client-certificate-data: "),
      "guest pair present: {}",
      adapted.decoy
    );
  }

  #[test]
  fn decoy_round_trips_spec_fields_and_all_entries() {
    let doc = "apiVersion: v1
kind: Config
preferences: {colors: true}
current-context: k3s-local
contexts:
- name: k3s-local
  context: {cluster: k3s, user: admin, namespace: platform}
- name: staging
  context: {cluster: stg, user: stg-user, namespace: stg-ns}
clusters:
- name: k3s
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=, tls-server-name: api.internal, insecure-skip-tls-verify: false}
- name: stg
  cluster: {server: https://10.1.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: admin
  user: {token: k3s-admin-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ, username: ivan, as: platform-sa}
- name: stg-user
  user: {token: stg-real-token}
";
    let adapted = adapt_doc(doc);
    let decoy = &adapted.decoy;
    assert!(decoy.contains("namespace: platform"), "{decoy}");
    assert!(decoy.contains("namespace: stg-ns"), "{decoy}");
    assert!(decoy.contains("tls-server-name: api.internal"), "{decoy}");
    assert!(decoy.contains("insecure-skip-tls-verify: false"), "{decoy}");
    assert!(decoy.contains("preferences"), "{decoy}");
    assert!(decoy.contains("server: https://10.1.0.1:6443"), "{decoy}");
    assert!(decoy.contains("username: ivan"), "{decoy}");
    assert!(decoy.contains("as: platform-sa"), "{decoy}");
    assert!(!decoy.contains("k3s-admin-token"), "no real token survives: {decoy}");
    assert!(!decoy.contains("stg-real-token"), "no real token survives in any user: {decoy}");
    assert!(
      !decoy.contains("Q0E=") && !decoy.contains("Q1RFU1Q="),
      "no real CA survives in any cluster: {decoy}"
    );
    assert!(!decoy.contains("Q0VSVA=="), "no real pair survives: {decoy}");
    assert_eq!(decoy.matches("token: ").count(), 2, "each user keeps a decoy token: {decoy}");
  }

  #[test]
  fn token_only_user_takes_plain_tls_while_pair_users_take_mtls() {
    // Only unmasked fixture text is touched here, so the bearer value never
    // appears in this test.
    let token_doc = BEARER_DOC.replace(", client-certificate-data: Q0VSVA==, client-key-data: S0VZ", "");
    let token_rules = rules_from(&adapt_doc(&token_doc).fragment);
    let token_rule = token_rules.get("home-ivan-kube-k3s-k3s-local").expect("rule present");
    let token_tls = token_rule.tls.get("https://10.0.0.1:6443").expect("tls keyed by the allow entry");
    assert_eq!(
      token_tls.guest_tls_mode,
      GuestTlsMode::Tls,
      "no client pair, so the proxy must not ask the guest for a client certificate"
    );
    let marker = "user: {";
    let fields_at = BEARER_DOC.find(marker).expect("user line") + marker.len();
    let pair_at = BEARER_DOC[fields_at..].find(", client-certificate-data").expect("pair fields") + fields_at + 2;
    let mut pair_doc = BEARER_DOC.to_string();
    pair_doc.replace_range(fields_at..pair_at, "");
    let pair_rules = rules_from(&adapt_doc(&pair_doc).fragment);
    let pair_rule = pair_rules.get("home-ivan-kube-k3s-k3s-local").expect("rule present");
    let pair_tls = pair_rule.tls.get("https://10.0.0.1:6443").expect("tls keyed by the allow entry");
    assert_eq!(
      pair_tls.guest_tls_mode,
      GuestTlsMode::Mtls,
      "pair users still swap the client certificate"
    );
  }

  #[test]
  fn cert_only_user_maps_to_an_identity_grant() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
    );
    let adapted = adapt_doc(&doc);
    assert!(!adapted.decoy.contains("token:"), "no bearer, no token line: {}", adapted.decoy);
    let rules = rules_from(&adapted.fragment);
    assert!(
      rules["home-ivan-kube-k3s-k3s-local"].value.is_some(),
      "identity grant still resolves"
    );
  }

  #[test]
  fn file_refs_are_an_error() {
    let doc = BEARER_DOC.replace("certificate-authority-data: Q0E=", "certificate-authority: ca.crt");
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("file refs fail closed");
    assert!(err.to_string().contains("inline them first"), "{err}");
  }

  #[test]
  fn exec_plugins_are_an_error() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {exec: {command: aws-iam-authenticator}}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("exec fails closed");
    assert!(err.to_string().contains("exec credential plugins"), "{err}");
  }

  #[test]
  fn unknown_context_is_an_error() {
    let doc = BEARER_DOC.replace("current-context: k3s-local", "current-context: nope");
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("unknown context fails closed");
    assert!(err.to_string().contains("unknown context"), "{err}");
  }

  #[test]
  fn half_pair_is_an_error() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("half pair fails closed");
    assert!(err.to_string().contains("half of the client pair"), "{err}");
  }

  #[test]
  fn plain_http_server_is_an_error() {
    let doc = BEARER_DOC.replace("https://10.0.0.1:6443", "http://10.0.0.1:8080");
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("plain HTTP fails closed");
    assert!(err.to_string().contains("plain HTTP"), "{err}");
  }

  #[test]
  fn credentialless_user_is_an_error() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("nothing to swap fails closed");
    assert!(err.to_string().contains("nothing to substitute"), "{err}");
  }

  #[test]
  fn state_writes_and_stale_ones_prune() {
    let adapted = adapt_doc(BEARER_DOC);
    let dir = tempfile::tempdir().unwrap();
    let grants = dir.path().join("grants");
    write_state(&grants, &[adapted]).unwrap();
    let rules = grants.join("rules.d");
    let marker = fs::read_to_string(grants.join("arkham.toml")).unwrap();
    assert!(marker.contains("[rules.home-ivan-kube-k3s-k3s-local]"), "{marker}");
    assert!(rules.join("home-ivan-kube-k3s-k3s-local.client.crt").is_file());
    let stale = rules.join("kube-gone.crt");
    fs::write(&stale, "stale").unwrap();
    write_state(&grants, &[]).unwrap();
    assert!(!stale.exists(), "removed rewrites stop granting");
  }
}

#[cfg(test)]
mod moved_suite {

  use std::collections::HashMap;
  use std::fs;

  use arkham_config::config::{FileRewrite, RewriteFormat};
  use tempfile::tempdir;

  use crate::expand::*;

  use crate::rewrites::*;

  use crate::test_support::*;

  /// Kubeconfig sources adapt with no `envs`, stated or sniffed.
  #[test]
  fn kube_rewrites_adapt_stated_or_sniffed() {
    let dir = tempdir().unwrap();
    let home = tempdir().unwrap();
    let xdg = tempdir().unwrap();
    let _env = AmbientEnv::isolate(home.path(), xdg.path());
    let source = dir.path().join("k3s.yaml");
    fs::write(&source, KUBE_DOC).unwrap();
    let expander = build_expander(HashMap::new());
    let files = dir.path().join("files");
    let guests = dir.path().join("guests");
    for format in [None, Some(RewriteFormat::Kubeconfig)] {
      let outputs = write_rewrites(&RewriteInputs {
        files_dir: &files,
        root: dir.path(),
        rewrites: &[FileRewrite {
          source: source.clone(),
          dest: "{home}/.kube/config".to_string(),
          envs: Vec::new(),
          format,
        }],
        decoys: &[],
        env: &HashMap::new(),
        expander: &expander,
        home: "/home/eng",
        host_home: None,
        guests_dir: &guests,
      })
      .unwrap();
      assert_eq!(outputs.mounts.len(), 1);
      assert_eq!(outputs.grants.len(), 1);
      assert!(
        outputs.grants[0].fragment.contains("https://10.0.0.1:6443"),
        "{}",
        outputs.grants[0].fragment
      );
      let body = fs::read_to_string(&outputs.mounts[0].host).unwrap();
      assert!(body.contains("current-context: k3s-local"), "{body}");
      assert!(!body.contains("probe-token"), "no real credential survives: {body}");
    }
  }

  /// A stated kubeconfig format on a foreign file fails closed.
  #[test]
  fn stated_kubeconfig_on_plain_text_is_an_error() {
    let dir = tempdir().unwrap();
    let home = tempdir().unwrap();
    let xdg = tempdir().unwrap();
    let _env = AmbientEnv::isolate(home.path(), xdg.path());
    let source = dir.path().join("npmrc");
    fs::write(&source, "//registry.npmjs.org/:_authToken=real-secret-1\n").unwrap();
    let guests = dir.path().join("guests");
    let expander = build_expander(HashMap::new());
    let error = write_rewrites(&RewriteInputs {
      files_dir: &dir.path().join("files"),
      root: dir.path(),
      rewrites: &[FileRewrite {
        source,
        dest: "{home}/.npmrc".to_string(),
        envs: Vec::new(),
        format: Some(RewriteFormat::Kubeconfig),
      }],
      decoys: &[],
      env: &HashMap::new(),
      expander: &expander,
      home: "/home/eng",
      host_home: None,
      guests_dir: &guests,
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("does not parse as YAML"), "{error}");
  }
}
