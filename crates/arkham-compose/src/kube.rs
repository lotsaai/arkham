//! Kubeconfig adapter for `file_rewrite`: a kubectl config file is a
//! differently structured form of the same information a rule holds, so the
//! adapter derives the grant from the file instead of asking the operator to
//! state it twice. Every derivable context maps onto one grant per user. The
//! file is the secret source, so a kube entry stating `envs` is an error
//! rather than a second source.
//!
//! Detection is structural: a YAML mapping with `kind: Config` and a
//! `clusters:` table takes the adapter path, everything else keeps the raw
//! byte-swap. The decoy twin keeps every context and the server (transparent
//! capture makes the destination the identity) and swaps the trust and
//! identity: arkham's CA, a minted guest pair per user, and that user's decoy
//! token. Two client-certificate users of one API server host and port fail
//! the file. Any other context that cannot be derived is skipped. The
//! `current-context` failing still fails the file.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::config::{HostTlsCfg, RewriteFormat, fake_for};
use arkham_config::grants::{EndpointScope, GuestTlsMode, HostPat, Scheme, decoy_for_rule};
use arkham_pki::ca::{CertAuthority, load_or_generate_client_pair};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_yaml::{Mapping, Value, from_str};

use crate::adapt::{GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, decode, render_decoy, render_fragment, rewrite_label};
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

impl KubeUser {
  fn bearer(&self) -> Option<&str> {
    self
      .token
      .as_deref()
      .or_else(|| {
        self
          .auth_provider
          .as_ref()
          .and_then(|provider| provider.config.access_token.as_deref())
      })
      .filter(|token| !token.is_empty())
  }
}

/// One context resolved to a server and a credential.
struct Derived<'a> {
  context: &'a str,
  user: &'a str,
  /// API server URL, as written.
  server: &'a str,
  /// Parsed server.
  scope: EndpointScope,
  /// Bearer, when the user has one.
  token: Option<&'a str>,
  /// Decoded client certificate.
  cert: Option<Vec<u8>>,
  /// Decoded client key.
  key: Option<Vec<u8>>,
  /// Decoded cluster CA.
  ca: Option<Vec<u8>>,
}

impl Derived<'_> {
  fn cert_endpoint(&self) -> Option<(&str, u16)> {
    self.cert.as_ref()?;
    match &self.scope.host {
      HostPat::Exact(host) => Some((host.as_str(), self.scope.port)),
      HostPat::Wildcard(_) | HostPat::Any => None,
    }
  }

  /// The https arm offers the first grant's client certificate during the
  /// upstream handshake, before it can read a bearer. Token users of one
  /// server stay distinct: the decoy bearer selects the real token.
  fn shared_client_cert(opened: &[Self]) -> Option<String> {
    let mut by_endpoint: BTreeMap<(String, u16), BTreeMap<&str, Vec<&str>>> = BTreeMap::new();
    for derived in opened {
      let Some((host, port)) = derived.cert_endpoint() else {
        continue;
      };
      by_endpoint
        .entry((host.to_string(), port))
        .or_default()
        .entry(derived.user)
        .or_default()
        .push(derived.context);
    }
    for ((host, port), users) in by_endpoint {
      if users.len() < 2 {
        continue;
      }
      let mut contexts: Vec<&str> = users.into_values().flatten().collect();
      contexts.sort_unstable();
      contexts.dedup();
      let listed = contexts.iter().map(|name| format!("`{name}`")).collect::<Vec<_>>().join(", ");
      return Some(format!("contexts {listed} at {host}:{port} present client certificates"));
    }
    None
  }
}

impl KubeContextEntry {
  fn derive<'a>(&'a self, doc: &'a KubeDoc, source: &Path) -> Result<Derived<'a>, Error> {
    let invalid = |detail: String| Error::RewriteInvalid {
      file: source.to_path_buf(),
      format: RewriteFormat::Kubeconfig,
      detail,
    };
    if self.context.cluster.is_empty() || self.context.user.is_empty() {
      return Err(invalid(format!("context `{}` names no `cluster` or no `user`", self.name)));
    }
    let cluster = doc
      .clusters
      .iter()
      .find(|entry| entry.name == self.context.cluster)
      .ok_or_else(|| invalid(format!("unknown cluster `{}`", self.context.cluster)))?;
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
    let user = doc
      .users
      .iter()
      .find(|entry| entry.name == self.context.user)
      .ok_or_else(|| invalid(format!("unknown user `{}`", self.context.user)))?;
    if user.user.cert_file.is_some() || user.user.key_file.is_some() || cluster.cluster.ca_file.is_some() {
      return Err(invalid(
        "uses file references; inline them first: `kubectl config view --flatten`".to_string(),
      ));
    }
    let token = user.user.bearer();
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
    let ca = decode(
      source,
      RewriteFormat::Kubeconfig,
      cluster.cluster.ca_data.as_deref(),
      "certificate-authority-data",
    )?;
    Ok(Derived {
      context: &self.name,
      user: &user.name,
      server: &cluster.cluster.server,
      scope,
      token,
      cert,
      key,
      ca,
    })
  }
}

/// One grant: every server a single user reaches, labeled by the first context.
struct UserGrant<'a> {
  /// First context name. The grant label is built from it.
  context: &'a str,
  user: &'a str,
  /// Bearer, when the user has one.
  token: Option<&'a str>,
  cert: Option<Vec<u8>>,
  key: Option<Vec<u8>>,
  /// Servers in first-seen order: URL, scope, and CA.
  servers: Vec<(&'a str, EndpointScope, Option<Vec<u8>>)>,
}

impl<'a> UserGrant<'a> {
  fn include(grants: &mut Vec<Self>, derived: Derived<'a>) {
    if let Some(grant) = grants.iter_mut().find(|grant| grant.user == derived.user) {
      if grant.servers.iter().all(|(server, _, _)| *server != derived.server) {
        grant.servers.push((derived.server, derived.scope, derived.ca));
      }
      return;
    }
    grants.push(Self {
      context: derived.context,
      user: derived.user,
      token: derived.token,
      cert: derived.cert,
      key: derived.key,
      servers: vec![(derived.server, derived.scope, derived.ca)],
    });
  }

  fn render(self, source: &Path, ca: &CertAuthority, guests_dir: &Path) -> Result<Rendered, Error> {
    let Self {
      context,
      user,
      token,
      cert,
      key,
      servers,
    } = self;
    let label = rewrite_label(source, context)?;
    let env = label.to_uppercase().replace('-', "_");
    // Identity-only grants (cert auth, no bearer) still need a value to
    // resolve; the certificate never reaches the wire as application data, so
    // it can never match the swap.
    let value = token.map_or_else(
      || String::from_utf8_lossy(cert.as_deref().unwrap_or_default()).into_owned(),
      str::to_string,
    );
    let mut servers = servers.into_iter();
    let Some((first_server, first_scope, first_ca)) = servers.next() else {
      return Err(Error::RewriteInvalid {
        file: source.to_path_buf(),
        format: RewriteFormat::Kubeconfig,
        detail: format!("user `{user}` has no server"),
      });
    };
    let mut scopes = vec![first_scope];
    let mut allow = vec![first_server.to_string()];
    let blobs = kube_blobs(&label, cert, key, first_ca, ca, guests_dir)?;
    let mut tls = BTreeMap::from([(first_server.to_string(), blobs.tls.clone())]);
    let mut materialized = blobs.materialized;
    for (index, (server, scope, bundle)) in servers.enumerate() {
      let n = index.checked_add(1).ok_or_else(|| Error::RewriteInvalid {
        file: source.to_path_buf(),
        format: RewriteFormat::Kubeconfig,
        detail: format!("user `{user}` has too many clusters"),
      })?;
      let mut entry = blobs.tls.clone();
      entry.root_cert = None;
      if let Some(bytes) = bundle {
        let name = format!("{label}-{n}.ca.crt");
        entry.root_cert = Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{name}")));
        materialized.push((name, bytes));
      }
      allow.push(server.to_string());
      tls.insert(server.to_string(), entry);
      scopes.push(scope);
    }
    let (decoy, _) = decoy_for_rule(&env, None, &scopes, value.len());
    let fragment = render_fragment(
      source,
      &label,
      &GrantFragment {
        env,
        registry: false,
        allow,
        value: Some(value),
        real: None,
        generated: false,
        if_missing: None,
        tls,
        ssh: BTreeMap::new(),
      },
    )?;
    Ok(Rendered {
      user: user.to_string(),
      fragment,
      materialized,
      guest: GuestUser {
        token: token.map(|_| decoy),
        cert: STANDARD.encode(blobs.guest_cert),
        key: STANDARD.encode(blobs.guest_key),
      },
    })
  }
}

/// Grant text plus the identity the guest file writes for one user.
struct Rendered {
  user: String,
  /// `[rules.{label}]` fragment.
  fragment: String,
  /// Blobs beside the fragment.
  materialized: Vec<(String, Vec<u8>)>,
  /// Decoy identity embedded in the guest kubeconfig.
  guest: GuestUser,
}

/// Decoy bearer and guest pair for one user in the guest kubeconfig.
struct GuestUser {
  /// Decoy bearer. Absent when the user has no token.
  token: Option<String>,
  /// Base64 guest certificate.
  cert: String,
  /// Base64 guest key.
  key: String,
}

/// Map a kubeconfig onto one fragment per derivable user and a decoy twin
/// that keeps every context. Returns `None` when the document is not a
/// kubeconfig after all, leaving the caller on the raw path.
///
/// # Errors
///
/// Returns an error when the document does not parse, the current context
/// cannot be derived, two client-certificate users share an API server host
/// and port, or a credential field is malformed.
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
  if doc.current_context.is_empty() {
    return Err(invalid("missing `current-context`".to_string()));
  }
  if !doc.contexts.iter().any(|entry| entry.name == doc.current_context) {
    return Err(invalid(format!("unknown context `{}`", doc.current_context)));
  }
  let mut opened = Vec::with_capacity(doc.contexts.len());
  for entry in &doc.contexts {
    match entry.derive(&doc, source) {
      Ok(derived) => opened.push(derived),
      Err(err) if entry.name == doc.current_context => return Err(err),
      Err(err) => tracing::warn!(context = %entry.name, %err, "kube context skipped"),
    }
  }
  if let Some(detail) = Derived::shared_client_cert(&opened) {
    tracing::warn!(%detail, "kube client certificates share one API server");
    return Err(invalid(detail));
  }
  let mut grants = Vec::with_capacity(opened.len());
  for derived in opened {
    UserGrant::include(&mut grants, derived);
  }
  let mut fragment = String::new();
  let mut materialized = Vec::new();
  let mut guests = BTreeMap::new();
  for grant in grants {
    let rendered = grant.render(source, ca, guests_dir)?;
    fragment.push_str(&rendered.fragment);
    materialized.extend(rendered.materialized);
    guests.insert(rendered.user, rendered.guest);
  }
  Ok(Some(RewriteAdapted {
    fragment,
    decoy: decoy_doc(&text, source, ca, &guests)?,
    materialized,
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
  let mut materialized = Vec::new();
  let mut tls = HostTlsCfg {
    client_cert: None,
    client_key: None,
    root_cert: None,
    // A client pair means mutual TLS both ways: the guest presents the
    // minted pair, the proxy the real one upstream. Token-only users carry
    // no client certificate, so asking for one fails their handshake with
    // `certificate required` before any bearer swap can happen.
    guest_tls_mode: GuestTlsMode::Tls,
    guest_cert: None,
    guest_key: None,
  };
  if let (Some(cert), Some(key)) = (cert, key) {
    tls.guest_tls_mode = GuestTlsMode::Mtls;
    let cert_name = format!("{label}.client.crt");
    let key_name = format!("{label}.client.key");
    tls.client_cert = Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{cert_name}")));
    tls.client_key = Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{key_name}")));
    materialized.push((cert_name, cert));
    materialized.push((key_name, key));
  }
  if let Some(ca_bundle) = ca_bundle {
    let ca_name = format!("{label}.ca.crt");
    tls.root_cert = Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{ca_name}")));
    materialized.push((ca_name, ca_bundle));
  }
  Ok(KubeBlobs {
    tls,
    materialized,
    guest_cert,
    guest_key,
  })
}

/// The agent's decoy kubeconfig: the parsed document verbatim, with trust
/// and identity swapped in every entry — arkham's CA under every cluster,
/// and each granted user's own guest pair and decoy token — because only
/// decoys may cross into the agent. A user with no grant gets placeholders,
/// never another user's pair. `exec` blocks and file-reference credentials
/// are dropped from every user: they run host binaries or point at host paths
/// the agent cannot see. Every other field, spec'd or not, round-trips
/// unchanged.
fn decoy_doc(text: &str, source: &Path, ca: &CertAuthority, guests: &BTreeMap<String, GuestUser>) -> Result<String, Error> {
  let mut root: Value = from_str(text).map_err(|err| Error::RewriteYaml {
    file: source.to_path_buf(),
    source: err,
  })?;
  let guest_ca = Value::String(STANDARD.encode(ca.cert_pem()));
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
    let guest = guests.get(&name);
    let placeholder = || fake_for(&format!("KUBE_{}", name.to_uppercase().replace(['-', '.'], "_")), None);
    let token_key = Value::String("token".to_string());
    if inner.contains_key(&token_key) {
      let decoy = guest.and_then(|guest| guest.token.clone()).unwrap_or_else(placeholder);
      inner.insert(token_key, Value::String(decoy));
    }
    let cert_data = Value::String("client-certificate-data".to_string());
    let key_data = Value::String("client-key-data".to_string());
    if inner.contains_key(&cert_data) || inner.contains_key(&key_data) {
      let (cert, key) = guest.map_or_else(
        || {
          let filler = placeholder();
          (filler.clone(), filler)
        },
        |guest| (guest.cert.clone(), guest.key.clone()),
      );
      inner.insert(cert_data, Value::String(cert));
      inner.insert(key_data, Value::String(key));
    }
    inner.remove(Value::String("client-certificate".to_string()));
    inner.remove(Value::String("client-key".to_string()));
    let token_present = inner.contains_key(Value::String("token".to_string()));
    let auth_provider = Value::String("auth-provider".to_string());
    if let Some(config) = inner
      .get_mut(&auth_provider)
      .and_then(Value::as_mapping_mut)
      .and_then(|provider| provider.get_mut(Value::String("config".to_string())))
      .and_then(Value::as_mapping_mut)
    {
      let access = Value::String("access-token".to_string());
      if config.contains_key(&access) {
        let decoy = if token_present {
          None
        } else {
          guest.and_then(|guest| guest.token.clone())
        }
        .unwrap_or_else(placeholder);
        config.insert(access, Value::String(decoy));
      }
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

  fn rule_decoy(rule: &RuleCfg) -> String {
    use secrecy::ExposeSecret as _;

    let value = rule.value.as_ref().expect("grant value").expose_secret();
    let scopes: Vec<EndpointScope> = rule.allow.iter().map(|entry| entry.parse().expect("allow entry")).collect();
    decoy_for_rule(&rule.env, None, &scopes, value.len()).0
  }

  #[test]
  fn two_contexts_on_different_servers_grant_each_user() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
- name: staging
  context: {cluster: staging, user: bob}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
- name: staging
  cluster: {server: https://10.2.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: alice
  user: {token: alice-token}
- name: bob
  user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZ}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 2, "one grant per user: {}", adapted.fragment);
    let mut modes = Vec::new();
    let mut decoys = Vec::new();
    for rule in rules.values() {
      let tls = rule.tls.values().next().expect("tls entry");
      modes.push(tls.guest_tls_mode);
      decoys.push(rule_decoy(rule));
    }
    assert!(modes.contains(&GuestTlsMode::Tls), "bearer user stays plain TLS: {modes:?}");
    assert!(modes.contains(&GuestTlsMode::Mtls), "client pair stays mutual TLS: {modes:?}");
    let allows: Vec<&str> = rules.values().flat_map(|rule| rule.allow.iter().map(String::as_str)).collect();
    assert!(allows.contains(&"https://10.0.0.1:6443"), "{allows:?}");
    assert!(allows.contains(&"https://10.2.0.1:6443"), "{allows:?}");
    assert_ne!(decoys[0], decoys[1], "each user has its own decoy");
    let token_decoy = rules
      .values()
      .find(|rule| rule.tls.values().any(|tls| tls.guest_tls_mode == GuestTlsMode::Tls))
      .map(rule_decoy)
      .expect("bearer grant");
    assert!(
      adapted.decoy.contains(&token_decoy),
      "guest file carries the bearer decoy: {}",
      adapted.decoy
    );
    assert!(adapted.decoy.contains("name: prod"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("alice-token"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("Q0VSVA=="), "{}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("Q0E=") && !adapted.decoy.contains("Q1RFU1Q="),
      "{}",
      adapted.decoy
    );
  }

  #[test]
  fn two_token_users_on_one_server_each_get_a_grant() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: shared, user: alice}
- name: staging
  context: {cluster: shared, user: bob}
clusters:
- name: shared
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: alice
  user: {token: alice-token}
- name: bob
  user: {token: bob-token}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 2, "token users on one server are two grants: {}", adapted.fragment);
    let decoys: Vec<String> = rules.values().map(rule_decoy).collect();
    assert_ne!(decoys[0], decoys[1]);
    assert!(decoys.iter().all(|decoy| adapted.decoy.contains(decoy)), "{}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("alice-token") && !adapted.decoy.contains("bob-token"),
      "{}",
      adapted.decoy
    );
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
  }

  #[test]
  fn token_user_beside_a_client_cert_on_one_server_is_granted() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: shared, user: alice}
- name: staging
  context: {cluster: shared, user: bob}
clusters:
- name: shared
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: alice
  user: {token: alice-token}
- name: bob
  user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZ}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(
      rules.len(),
      2,
      "a token user beside one client certificate is two grants: {}",
      adapted.fragment
    );
    let decoys: Vec<String> = rules.values().map(rule_decoy).collect();
    assert_ne!(decoys[0], decoys[1]);
    let bearer = rules
      .values()
      .find(|rule| rule.tls.values().any(|tls| tls.guest_tls_mode == GuestTlsMode::Tls))
      .map(rule_decoy)
      .expect("bearer grant");
    assert!(adapted.decoy.contains(&bearer), "{}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("alice-token") && !adapted.decoy.contains("Q0VSVA=="),
      "{}",
      adapted.decoy
    );
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
  }

  #[test]
  fn one_user_on_two_servers_is_one_grant() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: a, user: alice}
- name: staging
  context: {cluster: b, user: alice}
clusters:
- name: a
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
- name: b
  cluster: {server: https://10.2.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: alice
  user: {token: alice-token}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 1, "a shared user is one grant: {}", adapted.fragment);
    let rule = rules.values().next().expect("grant");
    assert!(rule.allow.iter().any(|entry| entry == "https://10.0.0.1:6443"), "{:?}", rule.allow);
    assert!(rule.allow.iter().any(|entry| entry == "https://10.2.0.1:6443"), "{:?}", rule.allow);
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("alice-token"), "{}", adapted.decoy);
  }

  #[test]
  fn two_client_cert_users_on_one_server_fail_closed() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: shared, user: alice}
- name: staging
  context: {cluster: shared, user: bob}
clusters:
- name: shared
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: alice
  user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZ}
- name: bob
  user: {client-certificate-data: Qk9C, client-key-data: S0VZ}
";
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("shared client certificates fail closed");
    let text = err.to_string();
    assert!(text.contains("prod") && text.contains("staging"), "{text}");
    assert!(text.contains("10.0.0.1") && text.contains("6443"), "{text}");
  }

  #[test]
  fn inactive_exec_context_is_skipped() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
- name: staging
  context: {cluster: staging, user: plugin}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
- name: staging
  cluster: {server: https://10.9.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: alice
  user: {token: alice-token}
- name: plugin
  user: {exec: {command: aws-iam-authenticator}}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 1, "the exec context is not a grant: {}", adapted.fragment);
    assert!(!adapted.fragment.contains("https://10.9.0.1:6443"), "{}", adapted.fragment);
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("aws-iam-authenticator"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("alice-token"), "{}", adapted.decoy);
  }

  #[test]
  fn access_token_is_a_bearer_grant() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
- name: staging
  context: {cluster: staging, user: gcp}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
- name: staging
  cluster: {server: https://10.2.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: alice
  user: {token: alice-token}
- name: gcp
  user: {auth-provider: {name: gcp, config: {access-token: gcp-token}}}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 2, "an access-token is a bearer: {}", adapted.fragment);
    assert!(
      !adapted.decoy.contains("gcp-token") && !adapted.decoy.contains("alice-token"),
      "{}",
      adapted.decoy
    );
    let gcp = rules
      .values()
      .find(|rule| rule.allow.iter().any(|entry| entry.contains("10.2.0.1")))
      .expect("gcp grant");
    assert!(
      adapted.decoy.contains(&rule_decoy(gcp)),
      "access-token carries its decoy: {}",
      adapted.decoy
    );
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
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
  fn empty_token_does_not_read_the_access_token() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {token: \"\", auth-provider: {config: {access-token: gcp-token}}}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("empty token is not a bearer");
    assert!(err.to_string().contains("nothing to substitute"), "{err}");
    assert!(!err.to_string().contains("gcp-token"), "{err}");
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

  use std::fs;

  use arkham_config::config::{FileRewrite, RewriteFormat};
  use tempfile::tempdir;

  use crate::expand::*;

  use crate::rewrites::*;

  use crate::test_support::*;

  /// Kubeconfig sources adapt with no `envs`, stated or sniffed.
  #[test]
  fn kube_rewrites_adapt_stated_or_sniffed() {
    use std::collections::HashMap;

    use arkham_pki::ca::CertAuthority;

    let dir = tempdir().unwrap();
    let source = dir.path().join("k3s.yaml");
    fs::write(&source, KUBE_DOC).unwrap();
    let ca = CertAuthority::generate().unwrap();
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
        kube_ca: Some(&ca),
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
    use std::collections::HashMap;

    use arkham_pki::ca::CertAuthority;

    let dir = tempdir().unwrap();
    let source = dir.path().join("npmrc");
    fs::write(&source, "//registry.npmjs.org/:_authToken=real-secret-1\n").unwrap();
    let ca = CertAuthority::generate().unwrap();
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
      kube_ca: Some(&ca),
      guests_dir: &guests,
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("does not parse as YAML"), "{error}");
  }
}
