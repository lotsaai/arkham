//! Kubeconfig adapter for `file_rewrite`: a kubectl config file is a
//! differently structured form of the same information a rule holds, so the
//! adapter derives one grant per distinct user instead of asking the operator
//! to state it twice. `current-context` is copied into the guest file and is
//! not how a credential is chosen. The decoy that user presents selects the
//! real credential. Contexts
//! that share a user share that grant. Contexts that share a cluster share
//! that cluster's CA file. The file is the secret source, so a kube entry
//! stating `envs` is an error rather than a second source.
//!
//! Detection is structural: a YAML mapping with `kind: Config` and a
//! `clusters:` table takes the adapter path, everything else keeps the raw
//! byte-swap. The decoy twin keeps each server (transparent capture makes the
//! destination the identity) and swaps the trust and identity: arkham's CA,
//! that user's minted guest pair, and that user's decoy token.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::config::{HostTlsCfg, RewriteFormat};
use arkham_config::context::{AmbientProtocol, ContextIdentity, ContextRef, Presented, identities, require_distinct};
use arkham_config::grants::{EndpointScope, GuestTlsMode, HostPat, Scheme};
use arkham_pki::ca::{CertAuthority, load_or_generate_client_pair};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_yaml::{Mapping, Value, from_str};

use crate::adapt::{GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, decode, render_decoy, render_fragment};
use crate::error::Error;

type GuestMaterial = (Vec<u8>, Vec<u8>);
type GuestPairs = BTreeMap<String, GuestMaterial>;

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
  /// Cloud auth-provider block. Detected so it is skipped, never granted.
  #[serde(rename = "auth-provider", default)]
  auth_provider: Option<Mapping>,
  /// Exec credential plugin. The active context fails the file. Any other context is skipped.
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

/// Why one context did not become a grant. The active context turns a skip
/// into [`Error::RewriteInvalid`]. Every other context is warned and omitted.
#[derive(Debug, thiserror::Error)]
pub(crate) enum KubeSkip {
  /// The context names no cluster or no user.
  #[error("context `{name}` names no `cluster` or no `user`")]
  Incomplete {
    /// Context name.
    name: String,
  },
  /// The context names a cluster the file does not define.
  #[error("context `{name}` names unknown cluster `{cluster}`")]
  UnknownCluster {
    /// Context name.
    name: String,
    /// Cluster name from the context.
    cluster: String,
  },
  /// The context names a user the file does not define.
  #[error("context `{name}` names unknown user `{user}`")]
  UnknownUser {
    /// Context name.
    name: String,
    /// User name from the context.
    user: String,
  },
  /// The cluster states no server.
  #[error("context `{name}` cluster `{cluster}` states no `server`")]
  NoServer {
    /// Context name.
    name: String,
    /// Cluster name.
    cluster: String,
  },
  /// The server is not an allow entry.
  #[error("context `{name}` server `{server}` is not an allow entry: {detail}")]
  BadServer {
    /// Context name.
    name: String,
    /// Server URL from the file.
    server: String,
    /// Parser detail.
    detail: String,
  },
  /// The server is not HTTPS.
  #[error("context `{name}` server `{server}` is plain HTTP: the API server is TLS-only")]
  NotTls {
    /// Context name.
    name: String,
    /// Server URL from the file.
    server: String,
  },
  /// The server host is not exact.
  #[error("context `{name}` server `{server}` is not an exact host")]
  NotExact {
    /// Context name.
    name: String,
    /// Server URL from the file.
    server: String,
  },
  /// A certificate, key, or CA is a host path.
  #[error("context `{name}` uses file references; inline them first: `kubectl config view --flatten --minify`")]
  FileRef {
    /// Context name.
    name: String,
  },
  /// Exec credential plugin, with no inline token or client pair.
  #[error("context `{name}` uses an exec credential plugin: exec credential plugins are not supported")]
  Exec {
    /// Context name.
    name: String,
  },
  /// Cloud auth-provider, with no inline token or client pair.
  #[error("context `{name}` uses an auth-provider: cloud auth providers are not supported")]
  AuthProvider {
    /// Context name.
    name: String,
  },
  /// One of the client certificate or key is missing.
  #[error("context `{name}` user `{user}` carries half of the client pair")]
  HalfPair {
    /// Context name.
    name: String,
    /// User name.
    user: String,
  },
  /// No token and no client pair.
  #[error("context `{name}` user `{user}` carries neither `token` nor a client pair: nothing to substitute")]
  NoCredential {
    /// Context name.
    name: String,
    /// User name.
    user: String,
  },
}

impl KubeSkip {
  fn name(&self) -> &str {
    match self {
      Self::Incomplete { name }
      | Self::UnknownCluster { name, .. }
      | Self::UnknownUser { name, .. }
      | Self::NoServer { name, .. }
      | Self::BadServer { name, .. }
      | Self::NotTls { name, .. }
      | Self::NotExact { name, .. }
      | Self::FileRef { name }
      | Self::Exec { name }
      | Self::AuthProvider { name }
      | Self::HalfPair { name, .. }
      | Self::NoCredential { name, .. } => name,
    }
  }
}

/// Grants derived from one kubeconfig, plus the contexts that were skipped.
#[derive(Debug)]
pub(crate) struct KubeAdapted {
  /// One grant per distinct user that carried a substitutable credential.
  pub(crate) grants: Vec<RewriteAdapted>,
  /// Contexts that were named and left out.
  pub(crate) skipped: Vec<KubeSkip>,
}

struct Prepared {
  user: String,
  cluster: String,
  server: String,
  host: String,
  port: u16,
  token: Option<String>,
  cert: Option<Vec<u8>>,
  key: Option<Vec<u8>>,
  ca: Option<Vec<u8>>,
}

struct UserGrant {
  token: Option<String>,
  cert: Option<Vec<u8>>,
  key: Option<Vec<u8>>,
  servers: BTreeMap<String, ServerUse>,
}

/// One allow entry for a user: the cluster that first named this server.
struct ServerUse {
  cluster: String,
  host: String,
  port: u16,
  ca: Option<Vec<u8>>,
}

enum Prep {
  Grant(Prepared),
  Skip(KubeSkip),
}

/// Map a kubeconfig onto one grant per distinct user and one decoy document.
/// Returns `None` when the document is not a kubeconfig, leaving the caller
/// on the raw path.
///
/// # Errors
///
/// Returns an error when the document does not parse, the active context is
/// missing, unknown, or itself skipped, a certificate field is not base64,
/// or a granted user would resolve to an empty value.
pub(crate) fn adapt(source: &Path, content: &[u8], ca: &CertAuthority, guests_dir: &Path) -> Result<Option<KubeAdapted>, Error> {
  let text = String::from_utf8_lossy(content);
  let doc: KubeDoc = from_str(&text).map_err(|err| Error::RewriteYaml {
    file: source.to_path_buf(),
    source: err,
  })?;
  if doc.kind != "Config" {
    return Ok(None);
  }
  if doc.current_context.is_empty() {
    return Err(invalid(source, "missing `current-context`".to_string()));
  }
  if !doc.contexts.iter().any(|entry| entry.name == doc.current_context) {
    return Err(invalid(source, format!("unknown context `{}`", doc.current_context)));
  }
  let mut prepared = Vec::new();
  let mut skipped = Vec::new();
  for entry in &doc.contexts {
    match classify(source, &doc, entry)? {
      Prep::Skip(skip) if skip.name() == doc.current_context => return Err(invalid(source, skip.to_string())),
      Prep::Skip(skip) => {
        tracing::warn!(%skip, "kube context skipped");
        skipped.push(skip);
      }
      Prep::Grant(item) => prepared.push(item),
    }
  }
  let users = group_users(prepared);
  if users.is_empty() {
    return Err(invalid(
      source,
      format!("context `{}` did not produce a grant", doc.current_context),
    ));
  }
  let ids = user_identities(source, &users)?;
  if ids.len() != users.len() {
    return Err(invalid(source, "kube user identities did not cover every granted user".to_string()));
  }
  let cluster_labels = cluster_labels(source, &users)?;
  let pairs = guest_pairs(ca, guests_dir, &users, &ids)?;
  distinct(&users, &ids)?;
  let decoy = decoy_doc(&text, source, ca, &users, &ids, &pairs)?;
  let mut grants = Vec::with_capacity(users.len());
  for ((name, user), id) in users.iter().zip(ids.iter()) {
    grants.push(one_grant(source, name, user, id, &cluster_labels, &decoy)?);
  }
  Ok(Some(KubeAdapted { grants, skipped }))
}

fn invalid(source: &Path, detail: String) -> Error {
  Error::RewriteInvalid {
    file: source.to_path_buf(),
    format: RewriteFormat::Kubeconfig,
    detail,
  }
}

/// Validate one context. A bad base64 field fails the file. Every other
/// problem is a skip the caller turns into an error only for the active name.
///
/// # Errors
///
/// Returns an error when an inline certificate field is present and not base64.
fn classify(source: &Path, doc: &KubeDoc, entry: &KubeContextEntry) -> Result<Prep, Error> {
  let name = entry.name.clone();
  let cluster_name = entry.context.cluster.clone();
  let user_name = entry.context.user.clone();
  if cluster_name.is_empty() || user_name.is_empty() {
    return Ok(Prep::Skip(KubeSkip::Incomplete { name }));
  }
  let Some(cluster) = doc.clusters.iter().find(|item| item.name == cluster_name) else {
    return Ok(Prep::Skip(KubeSkip::UnknownCluster {
      name,
      cluster: cluster_name,
    }));
  };
  let Some(user) = doc.users.iter().find(|item| item.name == user_name) else {
    return Ok(Prep::Skip(KubeSkip::UnknownUser { name, user: user_name }));
  };
  let server = cluster.cluster.server.clone();
  if server.is_empty() {
    return Ok(Prep::Skip(KubeSkip::NoServer {
      name,
      cluster: cluster_name,
    }));
  }
  let scope = match server.parse::<EndpointScope>() {
    Ok(scope) => scope,
    Err(detail) => return Ok(Prep::Skip(KubeSkip::BadServer { name, server, detail })),
  };
  if scope.scheme != Scheme::Https {
    return Ok(Prep::Skip(KubeSkip::NotTls { name, server }));
  }
  let HostPat::Exact(host) = scope.host else {
    return Ok(Prep::Skip(KubeSkip::NotExact { name, server }));
  };
  if user.user.cert_file.is_some() || user.user.key_file.is_some() || cluster.cluster.ca_file.is_some() {
    return Ok(Prep::Skip(KubeSkip::FileRef { name }));
  }
  let cert = decode(
    source,
    RewriteFormat::Kubeconfig,
    user.user.cert_data.as_deref(),
    "client-certificate-data",
  )?;
  let key = decode(source, RewriteFormat::Kubeconfig, user.user.key_data.as_deref(), "client-key-data")?;
  let ca = decode(
    source,
    RewriteFormat::Kubeconfig,
    cluster.cluster.ca_data.as_deref(),
    "certificate-authority-data",
  )?;
  if cert.is_some() != key.is_some() {
    return Ok(Prep::Skip(KubeSkip::HalfPair { name, user: user_name }));
  }
  let token = user.user.token.clone().filter(|token| !token.is_empty());
  if user.user.exec.is_some() && token.is_none() && cert.is_none() {
    return Ok(Prep::Skip(KubeSkip::Exec { name }));
  }
  if user.user.auth_provider.is_some() && token.is_none() && cert.is_none() {
    return Ok(Prep::Skip(KubeSkip::AuthProvider { name }));
  }
  if token.is_none() && cert.is_none() {
    return Ok(Prep::Skip(KubeSkip::NoCredential { name, user: user_name }));
  }
  Ok(Prep::Grant(Prepared {
    user: user_name,
    cluster: cluster_name,
    server,
    host,
    port: scope.port,
    token,
    cert,
    key,
    ca,
  }))
}

/// One user, every server that user talks to. The first context supplies the
/// credential. The first mention of a server string supplies that server's CA.
fn group_users(prepared: Vec<Prepared>) -> BTreeMap<String, UserGrant> {
  let mut users = BTreeMap::new();
  for item in prepared {
    let usage = ServerUse {
      cluster: item.cluster,
      host: item.host,
      port: item.port,
      ca: item.ca,
    };
    match users.entry(item.user) {
      Entry::Vacant(slot) => {
        let mut servers = BTreeMap::new();
        servers.insert(item.server, usage);
        slot.insert(UserGrant {
          token: item.token,
          cert: item.cert,
          key: item.key,
          servers,
        });
      }
      Entry::Occupied(mut slot) => {
        slot.get_mut().servers.entry(item.server).or_insert(usage);
      }
    }
  }
  users
}

fn user_identities(source: &Path, users: &BTreeMap<String, UserGrant>) -> Result<Vec<ContextIdentity>, Error> {
  let refs = users
    .keys()
    .map(|name| ContextRef {
      source,
      protocol: AmbientProtocol::KubernetesUser,
      name: name.as_str(),
    })
    .collect::<Vec<_>>();
  identities(&refs).map_err(Into::into)
}

fn cluster_labels(source: &Path, users: &BTreeMap<String, UserGrant>) -> Result<BTreeMap<String, String>, Error> {
  let mut names = BTreeSet::new();
  for user in users.values() {
    for server in user.servers.values() {
      if server.ca.is_some() {
        names.insert(server.cluster.as_str());
      }
    }
  }
  let refs = names
    .iter()
    .map(|name| ContextRef {
      source,
      protocol: AmbientProtocol::KubernetesCluster,
      name,
    })
    .collect::<Vec<_>>();
  let ids = identities(&refs)?;
  Ok(ids.into_iter().map(|id| (id.name, id.label)).collect())
}

fn guest_pairs(
  ca: &CertAuthority,
  guests_dir: &Path,
  users: &BTreeMap<String, UserGrant>,
  ids: &[ContextIdentity],
) -> Result<GuestPairs, Error> {
  let mut pairs = BTreeMap::new();
  for ((name, user), id) in users.iter().zip(ids) {
    if user.cert.is_none() {
      continue;
    }
    let (cert_path, key_path) = load_or_generate_client_pair(ca, guests_dir, &id.label)?;
    let cert = fs::read(&cert_path).map_err(|source| Error::ReadFile { path: cert_path, source })?;
    let key = fs::read(&key_path).map_err(|source| Error::ReadFile { path: key_path, source })?;
    pairs.insert(name.clone(), (cert, key));
  }
  Ok(pairs)
}

/// Two users of one apiserver stay distinct because each decoy differs.
///
/// # Errors
///
/// Returns an error when two identities present the same host, port, and decoy.
fn distinct(users: &BTreeMap<String, UserGrant>, ids: &[ContextIdentity]) -> Result<(), Error> {
  let decoys = ids.iter().map(ContextIdentity::secret).collect::<Vec<_>>();
  let mut presented = Vec::new();
  for (user, (id, decoy)) in users.values().zip(ids.iter().zip(decoys.iter())) {
    for server in user.servers.values() {
      presented.push(Presented {
        identity: id,
        host: server.host.as_str(),
        port: server.port,
        decoy: decoy.as_bytes(),
      });
    }
  }
  require_distinct(&presented)?;
  Ok(())
}

/// The agent's decoy kubeconfig. Every cluster trusts arkham's CA. A granted
/// user receives that user's decoy token and, when the user has a client pair,
/// that user's guest pair. Every other user loses token, certificate, and key.
/// `exec`, auth-provider, file paths, and passwords are removed from every user.
///
/// # Errors
///
/// Returns an error when the document does not reparse or fails to serialize.
fn decoy_doc(
  text: &str,
  source: &Path,
  ca: &CertAuthority,
  users: &BTreeMap<String, UserGrant>,
  ids: &[ContextIdentity],
  pairs: &GuestPairs,
) -> Result<String, Error> {
  let mut root: Value = from_str(text).map_err(|err| Error::RewriteYaml {
    file: source.to_path_buf(),
    source: err,
  })?;
  let guest_ca = Value::String(STANDARD.encode(ca.cert_pem()));
  for cluster in entries_mut(&mut root, "clusters") {
    let Some(inner) = cluster.get_mut(yaml_string("cluster")).and_then(Value::as_mapping_mut) else {
      continue;
    };
    inner.insert(yaml_string("certificate-authority-data"), guest_ca.clone());
    inner.remove(yaml_string("certificate-authority"));
  }
  let granted = users
    .iter()
    .zip(ids)
    .map(|((name, user), id)| (name.as_str(), (user, id)))
    .collect::<BTreeMap<_, _>>();
  for user in entries_mut(&mut root, "users") {
    let name = user.get(yaml_string("name")).and_then(Value::as_str).unwrap_or("").to_string();
    let Some(inner) = user.get_mut(yaml_string("user")).and_then(Value::as_mapping_mut) else {
      continue;
    };
    for field in ["exec", "auth-provider", "client-certificate", "client-key", "password"] {
      inner.remove(yaml_string(field));
    }
    match granted.get(name.as_str()) {
      Some((grant, id)) => write_user_decoy(inner, grant, id, pairs.get(&name)),
      None => clear_user_secrets(inner),
    }
  }
  render_decoy(&root)
}

fn write_user_decoy(inner: &mut Mapping, grant: &UserGrant, id: &ContextIdentity, pair: Option<&GuestMaterial>) {
  if grant.token.is_some() {
    inner.insert(yaml_string("token"), Value::String(id.secret()));
  } else {
    inner.remove(yaml_string("token"));
  }
  if let Some((cert, key)) = pair {
    inner.insert(yaml_string("client-certificate-data"), Value::String(STANDARD.encode(cert)));
    inner.insert(yaml_string("client-key-data"), Value::String(STANDARD.encode(key)));
  } else {
    inner.remove(yaml_string("client-certificate-data"));
    inner.remove(yaml_string("client-key-data"));
  }
}

fn clear_user_secrets(inner: &mut Mapping) {
  for field in ["token", "client-certificate-data", "client-key-data"] {
    inner.remove(yaml_string(field));
  }
}

fn yaml_string(text: &str) -> Value {
  Value::String(text.to_string())
}

/// # Errors
///
/// Returns an error when the grant value would be empty, a cluster CA has no
/// label, or the fragment fails to serialize.
fn one_grant(
  source: &Path,
  name: &str,
  user: &UserGrant,
  id: &ContextIdentity,
  cluster_labels: &BTreeMap<String, String>,
  decoy: &str,
) -> Result<RewriteAdapted, Error> {
  let value = match &user.token {
    Some(token) => token.clone(),
    None => String::from_utf8_lossy(user.cert.as_deref().unwrap_or(&[])).into_owned(),
  };
  if value.is_empty() {
    return Err(invalid(source, format!("user `{name}` produced an empty grant value")));
  }
  let label = &id.label;
  let mut materialized = Vec::new();
  let (client_cert, client_key, mode) = match user.cert.as_ref().zip(user.key.as_ref()) {
    Some((cert, key)) => {
      let cert_name = format!("{label}.client.crt");
      let key_name = format!("{label}.client.key");
      materialized.push((cert_name.clone(), cert.clone()));
      materialized.push((key_name.clone(), key.clone()));
      (
        Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{cert_name}"))),
        Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{key_name}"))),
        GuestTlsMode::Mtls,
      )
    }
    None => (None, None, GuestTlsMode::Tls),
  };
  let mut allow = Vec::with_capacity(user.servers.len());
  let mut tls = BTreeMap::new();
  let mut written_ca = BTreeSet::new();
  for (server, usage) in &user.servers {
    allow.push(server.clone());
    tls.insert(
      server.clone(),
      HostTlsCfg {
        client_cert: client_cert.clone(),
        client_key: client_key.clone(),
        root_cert: ca_path(source, usage, cluster_labels, &mut materialized, &mut written_ca)?,
        guest_tls_mode: mode,
        guest_cert: None,
        guest_key: None,
      },
    );
  }
  let fragment = render_fragment(
    source,
    label,
    &GrantFragment {
      env: id.env(),
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
  Ok(RewriteAdapted {
    fragment,
    decoy: decoy.to_string(),
    materialized,
    decoy_files: Vec::new(),
  })
}

fn ca_path(
  source: &Path,
  usage: &ServerUse,
  cluster_labels: &BTreeMap<String, String>,
  materialized: &mut Vec<(String, Vec<u8>)>,
  written: &mut BTreeSet<String>,
) -> Result<Option<PathBuf>, Error> {
  let Some(bytes) = &usage.ca else {
    return Ok(None);
  };
  let Some(label) = cluster_labels.get(&usage.cluster) else {
    return Err(invalid(source, format!("cluster `{}` has no CA file label", usage.cluster)));
  };
  let ca_name = format!("{label}.ca.crt");
  if written.insert(ca_name.clone()) {
    materialized.push((ca_name.clone(), bytes.clone()));
  }
  Ok(Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{ca_name}"))))
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
  use secrecy::ExposeSecret as _;
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

  struct Flat {
    fragment: String,
    decoy: String,
    materialized: Vec<(String, Vec<u8>)>,
    grants: Vec<RewriteAdapted>,
  }

  fn adapt_doc(doc: &str) -> Flat {
    let dir = tempfile::tempdir().unwrap();
    let found = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path())
      .expect("adapt parses")
      .expect("bearer doc is a kubeconfig");
    let fragment = found.grants.iter().map(|grant| grant.fragment.as_str()).collect::<String>();
    let decoy = found.grants.first().map(|grant| grant.decoy.clone()).unwrap_or_default();
    let materialized = found.grants.iter().flat_map(|grant| grant.materialized.iter().cloned()).collect();
    Flat {
      fragment,
      decoy,
      materialized,
      grants: found.grants,
    }
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
  fn grant_label_names_the_user() {
    let adapted = adapt_doc(BEARER_DOC);
    let (label, rule) = rules_from(&adapted.fragment).into_iter().next().expect("one rule");
    assert!(label.starts_with("kube-user-"), "{label}");
    assert!(!label.contains("ivan") && !label.contains("k3s-local"), "{label}");
    assert_eq!(rule.env, label.replace('-', "_").to_ascii_uppercase());
  }

  #[test]
  fn fragment_holds_the_grant_and_parses_as_a_rule() {
    let adapted = adapt_doc(BEARER_DOC);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 1, "one user is one grant");
    let (label, rule) = rules.iter().next().expect("rule present");
    assert_eq!(rule.env, label.replace('-', "_").to_ascii_uppercase());
    assert_eq!(rule.allow, vec!["https://10.0.0.1:6443".to_string()]);
    assert_eq!(rule.registry, Some(false));
    assert!(rule.value.is_some(), "bearer token is the inline real value");
    let tls = rule.tls.get("https://10.0.0.1:6443").expect("tls keyed by the allow entry");
    assert!(
      tls
        .client_cert
        .as_ref()
        .is_some_and(|path| path.ends_with(format!("{label}.client.crt")))
    );
    assert!(tls.root_cert.as_ref().is_some_and(|path| {
      path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("kube-cluster-") && name.ends_with(".ca.crt"))
    }));
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
    let token_rule = token_rules.values().next().expect("rule present");
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
    let pair_rule = pair_rules.values().next().expect("rule present");
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
    let value = rules.values().next().and_then(|rule| rule.value.as_ref());
    assert!(
      value.is_some_and(|secret| !secret.expose_secret().is_empty()),
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

  /// Two users of one apiserver each get a grant. The guest token is that
  /// grant's decoy, so the existing HTTPS swap can tell the users apart.
  #[test]
  fn every_context_user_gets_a_grant_and_a_distinct_decoy() {
    let ivan = "real-ivan-token";
    let eng = "real-eng-token";
    let doc = format!(
      "apiVersion: v1\nkind: Config\ncurrent-context: prod\ncontexts:\n- name: prod\n  context: {{cluster: c, user: ivan}}\n- name: staging\n  context: {{cluster: c, user: eng}}\nclusters:\n- name: c\n  cluster: {{server: https://k8s.example:6443, certificate-authority-data: Q0E=}}\nusers:\n- name: ivan\n  user: {{token: {ivan}}}\n- name: eng\n  user: {{token: {eng}}}\n"
    );
    let adapted = adapt_doc(&doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 2, "one grant per user, same host included: {}", adapted.fragment);
    for rule in rules.values() {
      assert_eq!(rule.allow, vec!["https://k8s.example:6443".to_string()], "{:?}", rule.allow);
      let value = rule.value.as_ref().expect("grant value").expose_secret();
      assert!(!value.is_empty(), "empty grant value crashes serve");
      assert!(
        !adapted.decoy.contains(value),
        "real credential in the guest file: {}",
        adapted.decoy
      );
      let decoy = arkham_config::config::fake_for(&rule.env, None);
      assert!(adapted.decoy.contains(&decoy), "guest token is the grant decoy: {}", adapted.decoy);
    }
    assert!(!adapted.decoy.contains(ivan) && !adapted.decoy.contains(eng), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("Q0E="), "real CA in the guest file: {}", adapted.decoy);
    assert!(adapted.decoy.contains("server: https://k8s.example:6443"), "{}", adapted.decoy);
    assert!(
      adapted.decoy.contains("name: prod") && adapted.decoy.contains("name: staging"),
      "{}",
      adapted.decoy
    );
    assert!(
      adapted.decoy.contains("certificate-authority-data:"),
      "cluster trusts arkham: {}",
      adapted.decoy
    );
    let cas: Vec<_> = rules
      .values()
      .filter_map(|rule| rule.tls.get("https://k8s.example:6443").and_then(|tls| tls.root_cert.clone()))
      .collect();
    assert_eq!(cas.len(), 2, "both users trust the shared cluster");
    assert_eq!(cas[0], cas[1], "one cluster is one CA file");
    let ca_name = cas[0].file_name().and_then(|name| name.to_str()).unwrap_or("");
    assert!(ca_name.starts_with("kube-cluster-") && ca_name.ends_with(".ca.crt"), "{ca_name}");
    let decoys: Vec<_> = rules
      .values()
      .map(|rule| arkham_config::config::fake_for(&rule.env, None))
      .collect();
    assert_ne!(decoys[0], decoys[1], "each user presents a distinct decoy");
  }

  #[test]
  fn shared_user_and_cluster_are_one_grant() {
    let doc = "apiVersion: v1\nkind: Config\ncurrent-context: prod\ncontexts:\n- name: prod\n  context: {cluster: prod-c, user: ivan}\n- name: staging\n  context: {cluster: stg-c, user: ivan}\n- name: prod-ns\n  context: {cluster: prod-c, user: ivan}\nclusters:\n- name: prod-c\n  cluster: {server: https://k8s.example:6443, certificate-authority-data: Q0E=}\n- name: stg-c\n  cluster: {server: https://stg.example:6443, certificate-authority-data: U1RH}\nusers:\n- name: ivan\n  user: {token: real-shared-token}\n";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 1, "one user is one grant: {}", adapted.fragment);
    let rule = rules.values().next().expect("grant");
    assert_eq!(
      rule.allow,
      vec!["https://k8s.example:6443".to_string(), "https://stg.example:6443".to_string()],
      "every server that user talks to: {:?}",
      rule.allow
    );
    let prod_ca = rule.tls.get("https://k8s.example:6443").and_then(|tls| tls.root_cert.clone());
    let stg_ca = rule.tls.get("https://stg.example:6443").and_then(|tls| tls.root_cert.clone());
    assert!(prod_ca.is_some() && stg_ca.is_some(), "each cluster keeps a CA blob");
    assert_ne!(prod_ca, stg_ca, "distinct clusters do not share a CA file");
    assert_eq!(
      adapted.decoy.matches("token: ").count(),
      1,
      "one user, one decoy: {}",
      adapted.decoy
    );
    assert!(!adapted.decoy.contains("real-shared-token"), "{}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("Q0E=") && !adapted.decoy.contains("U1RH"),
      "{}",
      adapted.decoy
    );
  }

  #[test]
  fn underivable_context_is_skipped_and_named() {
    let doc = "apiVersion: v1\nkind: Config\ncurrent-context: prod\ncontexts:\n- name: prod\n  context: {cluster: c, user: ivan}\n- name: plugin\n  context: {cluster: c, user: plugin-user}\nclusters:\n- name: c\n  cluster: {server: https://k8s.example:6443, certificate-authority-data: Q0E=}\nusers:\n- name: ivan\n  user: {token: real-ivan-token}\n- name: plugin-user\n  user: {exec: {command: aws-iam-authenticator, args: [token, -i, real-cluster]}}\n";
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let dir = tempfile::tempdir().unwrap();
    let adapted = tracing::subscriber::with_default(WarnCapture(std::sync::Arc::clone(&lines)), || {
      adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path())
        .expect("selected context grants")
        .expect("kubeconfig")
    });
    assert!(
      adapted
        .skipped
        .iter()
        .any(|skip| matches!(skip, KubeSkip::Exec { name } if name == "plugin")),
      "skip names the context: {:?}",
      adapted.skipped
    );
    let fragment = adapted.grants.iter().map(|grant| grant.fragment.as_str()).collect::<String>();
    let decoy = adapted.grants.first().map_or("", |grant| grant.decoy.as_str());
    let rules = rules_from(&fragment);
    assert_eq!(rules.len(), 1, "the exec context is not a grant: {fragment}");
    assert!(!decoy.contains("aws-iam-authenticator"), "exec command in the guest file: {decoy}");
    assert!(!decoy.contains("real-ivan-token"), "{decoy}");
    let warnings = lines.lock().unwrap();
    assert!(
      warnings.iter().any(|line| line.contains("plugin")),
      "skip names the context: {warnings:?}"
    );
  }

  /// A selected context that cannot grant still fails the file, even when another context could.
  #[test]
  fn selected_underivable_context_still_fails() {
    let doc = "apiVersion: v1\nkind: Config\ncurrent-context: plugin\ncontexts:\n- name: plugin\n  context: {cluster: c, user: plugin-user}\n- name: prod\n  context: {cluster: c, user: ivan}\nclusters:\n- name: c\n  cluster: {server: https://k8s.example:6443, certificate-authority-data: Q0E=}\nusers:\n- name: ivan\n  user: {token: real-ivan-token}\n- name: plugin-user\n  user: {exec: {command: aws-iam-authenticator}}\n";
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("selected exec fails closed");
    let text = err.to_string();
    assert!(text.contains("plugin"), "{text}");
    assert!(text.contains("exec credential plugins"), "{text}");
  }

  /// A selected auth-provider is not a credential. The cloud token stays out of the grant.
  #[test]
  fn selected_auth_provider_still_fails() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {auth-provider: {config: {access-token: real-cloud-token}}}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("selected auth-provider fails closed");
    let text = err.to_string();
    assert!(text.contains("auth-provider"), "{text}");
    assert!(text.contains("k3s-local"), "{text}");
    assert!(!text.contains("real-cloud-token"), "{text}");
  }

  struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

  impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
      *metadata.level() <= tracing::Level::WARN
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
      tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
      let mut message = String::new();
      event.record(&mut WarnVisit(&mut message));
      self.0.lock().unwrap().push(message);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
  }

  struct WarnVisit<'a>(&'a mut String);

  impl tracing::field::Visit for WarnVisit<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
      use std::fmt::Write as _;
      let _ = write!(self.0, "{}={value:?};", field.name());
    }
  }

  #[test]
  fn state_writes_and_stale_ones_prune() {
    let adapted = adapt_doc(BEARER_DOC);
    let dir = tempfile::tempdir().unwrap();
    let grants = dir.path().join("grants");
    write_state(&grants, &adapted.grants).unwrap();
    let rules = grants.join("rules.d");
    let marker = fs::read_to_string(grants.join("arkham.toml")).unwrap();
    assert!(marker.contains("[rules.kube-user-"), "{marker}");
    assert!(
      fs::read_dir(&rules)
        .unwrap()
        .flatten()
        .any(|entry| entry.file_name().to_string_lossy().ends_with(".client.crt")),
      "the client certificate materializes under rules.d"
    );
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
      assert!(!outputs.mounts[0].ro, "kube decoy is writable");
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
