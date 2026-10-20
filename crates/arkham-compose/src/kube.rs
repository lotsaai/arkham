//! Kubeconfig adapter for `file_rewrite`: a kubectl config file is a
//! differently structured form of the same information a rule holds, so the
//! adapter derives the grant from the file instead of asking the operator to
//! state it twice. Every derivable context maps. One user is one rule, and
//! one cluster is one CA file. `current-context` is copied into the decoy
//! and is not how a credential is chosen. The file is the secret source, so
//! a kube entry stating `envs` is an error rather than a second source.
//!
//! Detection is structural: a YAML mapping with `kind: Config` and a
//! `clusters:` table takes the adapter path, everything else keeps the raw
//! byte-swap. The decoy twin keeps every context, cluster, and user. Each
//! granted user gets its own decoy credential, and every cluster carries
//! arkham's CA.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::config::{HostTlsCfg, RewriteFormat, fake_for};
use arkham_config::context::{AmbientProtocol, ContextIdentity, ContextRef, Presented, guest_cert_file, identities, require_distinct};
use arkham_config::grants::{EndpointScope, GuestTlsMode, HostPat, Scheme};
use arkham_pki::ca::{CertAuthority, load_or_generate_client_pair};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_yaml::{Mapping, Value, from_str};

use crate::adapt::{GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, decode, render_decoy, render_fragment};
use crate::error::Error;

/// A kubeconfig document; unknown fields ignored.
///
/// `kind` is checked on the merged `kube_client` document before this parse.
#[derive(Debug, Deserialize, Default)]
struct KubeDoc {
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
  /// Cloud auth-provider block. Presence is enough: the token inside is not a grant.
  #[serde(rename = "auth-provider", default)]
  auth_provider: Option<Mapping>,
  /// Exec credential plugin. A user with only this block is skipped.
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

/// One named kubeconfig entry and the file that defined it.
struct Sourced<T> {
  source: PathBuf,
  item: T,
}

/// First-wins merge of every `kind: Config` document in a `KUBECONFIG` list.
struct Merged {
  /// File that held the first kubeconfig document.
  origin: PathBuf,
  /// First non-empty `current-context`. Empty when every file left it empty.
  current: String,
  contexts: Vec<Sourced<KubeContextEntry>>,
  clusters: Vec<Sourced<KubeClusterEntry>>,
  users: Vec<Sourced<KubeUserEntry>>,
  /// Merged document, unknown fields included, ready for the decoy pass.
  root: Value,
}

/// One derivable context: the user credential and one server it may call.
struct Pending {
  user_source: PathBuf,
  user_name: String,
  cluster_source: PathBuf,
  cluster_name: String,
  server: String,
  host: String,
  port: u16,
  token: Option<String>,
  cert: Option<Vec<u8>>,
  key: Option<Vec<u8>>,
  ca: Option<Vec<u8>>,
}

/// A context that cannot be granted. The selected context turns this into
/// [`Error::RewriteInvalid`]; every other context is a warning.
struct KubeSkip {
  context: String,
  detail: String,
}

impl fmt::Display for KubeSkip {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "context `{}`: {}", self.context, self.detail)
  }
}

/// Classification of one context.
enum Classified {
  Grant(Pending),
  Skip(KubeSkip),
}

/// Decoy material for one granted user, keyed by the kube user name.
struct UserFace {
  token: Option<String>,
  cert: Option<String>,
  key: Option<String>,
}

/// Map several kubeconfig files, in order, onto one grant fragment.
///
/// `KUBECONFIG` is a colon-separated list. Names already defined stay as
/// they are. `current-context` is the first non-empty value and is not how
/// a credential is chosen. A context that cannot be derived is skipped,
/// unless it is the selected context, which fails the file.
///
/// # Errors
///
/// Returns an error when a document does not parse, the selected context
/// cannot be granted, two users present the same decoy at one server, or a
/// guest pair cannot be minted.
pub(crate) fn adapt_sources(sources: &[(&Path, &[u8])], ca: &CertAuthority, guests_dir: &Path) -> Result<Option<RewriteAdapted>, Error> {
  let Some(merged) = merge_sources(sources)? else {
    return Ok(None);
  };
  let pending = classify_merged(&merged)?;
  let rendered = render_pending(&pending, ca, guests_dir)?;
  let decoy = decoy_document(merged.root, ca, &rendered.faces)?;
  Ok(Some(RewriteAdapted {
    fragment: rendered.fragment,
    decoy,
    materialized: rendered.materialized,
    decoy_files: Vec::new(),
  }))
}

/// Map one kubeconfig onto its grant fragment and decoy twin. Returns
/// `None` when the document is not a kubeconfig, leaving the caller on the
/// raw path.
///
/// # Errors
///
/// Returns an error when the document does not parse or the selected
/// context cannot be granted.
pub(crate) fn adapt(source: &Path, content: &[u8], ca: &CertAuthority, guests_dir: &Path) -> Result<Option<RewriteAdapted>, Error> {
  adapt_sources(&[(source, content)], ca, guests_dir)
}

fn merge_sources(sources: &[(&Path, &[u8])]) -> Result<Option<Merged>, Error> {
  let mut combined: Option<kube_client::config::Kubeconfig> = None;
  let mut origin = PathBuf::new();
  let mut context_paths = BTreeMap::new();
  let mut cluster_paths = BTreeMap::new();
  let mut user_paths = BTreeMap::new();
  for (path, bytes) in sources {
    let text = String::from_utf8_lossy(bytes);
    let doc: kube_client::config::Kubeconfig = from_str(&text).map_err(|source| Error::RewriteYaml {
      file: path.to_path_buf(),
      source,
    })?;
    if doc.kind.as_deref() != Some("Config") {
      continue;
    }
    remember(&mut context_paths, path, doc.contexts.iter().map(|entry| entry.name.as_str()));
    remember(&mut cluster_paths, path, doc.clusters.iter().map(|entry| entry.name.as_str()));
    remember(&mut user_paths, path, doc.auth_infos.iter().map(|entry| entry.name.as_str()));
    combined = Some(match combined {
      None => {
        origin = path.to_path_buf();
        doc
      }
      Some(existing) => existing.merge(doc).map_err(|source| Error::KubeconfigMerge {
        file: path.to_path_buf(),
        source,
      })?,
    });
  }
  let Some(combined) = combined else {
    return Ok(None);
  };
  let yaml = serde_yaml::to_string(&combined).map_err(|source| Error::RewriteYaml {
    file: origin.clone(),
    source,
  })?;
  let root: Value = from_str(&yaml).map_err(|source| Error::RewriteYaml {
    file: origin.clone(),
    source,
  })?;
  let doc: KubeDoc = from_str(&yaml).map_err(|source| Error::RewriteYaml {
    file: origin.clone(),
    source,
  })?;
  Ok(Some(Merged {
    current: doc.current_context,
    contexts: sourced(&origin, &context_paths, doc.contexts, |entry| &entry.name)?,
    clusters: sourced(&origin, &cluster_paths, doc.clusters, |entry| &entry.name)?,
    users: sourced(&origin, &user_paths, doc.users, |entry| &entry.name)?,
    origin,
    root,
  }))
}

fn remember<'a>(seen: &mut BTreeMap<String, PathBuf>, path: &Path, names: impl Iterator<Item = &'a str>) {
  for name in names {
    seen.entry(name.to_string()).or_insert_with(|| path.to_path_buf());
  }
}

fn sourced<T>(
  origin: &Path,
  paths: &BTreeMap<String, PathBuf>,
  items: Vec<T>,
  name_of: impl Fn(&T) -> &str,
) -> Result<Vec<Sourced<T>>, Error> {
  let mut out = Vec::with_capacity(items.len());
  for item in items {
    let name = name_of(&item);
    let Some(source) = paths.get(name) else {
      return Err(Error::RewriteInvalid {
        file: origin.to_path_buf(),
        format: RewriteFormat::Kubeconfig,
        detail: format!("merged entry `{name}` has no source file"),
      });
    };
    out.push(Sourced {
      source: source.clone(),
      item,
    });
  }
  Ok(out)
}

fn yaml_key(name: &str) -> Value {
  Value::String(name.to_string())
}

fn classify_merged(merged: &Merged) -> Result<Vec<Pending>, Error> {
  let invalid = |detail: String| Error::RewriteInvalid {
    file: merged.origin.clone(),
    format: RewriteFormat::Kubeconfig,
    detail,
  };
  if !merged.current.is_empty() && merged.contexts.iter().all(|entry| entry.item.name != merged.current) {
    return Err(invalid(format!("unknown context `{}`", merged.current)));
  }
  let mut pending = Vec::new();
  for context in &merged.contexts {
    match classify_context(context, &merged.clusters, &merged.users)? {
      Classified::Grant(row) => pending.push(row),
      Classified::Skip(skip) => {
        if !merged.current.is_empty() && context.item.name == merged.current {
          return Err(invalid(skip.to_string()));
        }
        tracing::warn!(%skip, "kubeconfig context skipped");
      }
    }
  }
  Ok(pending)
}

fn classify_context(
  context: &Sourced<KubeContextEntry>,
  clusters: &[Sourced<KubeClusterEntry>],
  users: &[Sourced<KubeUserEntry>],
) -> Result<Classified, Error> {
  let name = context.item.name.as_str();
  let fail = |detail: String| {
    Classified::Skip(KubeSkip {
      context: name.to_string(),
      detail,
    })
  };
  if context.item.context.cluster.is_empty() || context.item.context.user.is_empty() {
    return Ok(fail("names no `cluster` or no `user`".to_string()));
  }
  let Some(cluster) = clusters.iter().find(|entry| entry.item.name == context.item.context.cluster) else {
    return Ok(fail(format!("unknown cluster `{}`", context.item.context.cluster)));
  };
  let Some(user) = users.iter().find(|entry| entry.item.name == context.item.context.user) else {
    return Ok(fail(format!("unknown user `{}`", context.item.context.user)));
  };
  if user.item.user.cert_file.is_some() || user.item.user.key_file.is_some() || cluster.item.cluster.ca_file.is_some() {
    return Ok(fail(
      "uses file references; inline them first: `kubectl config view --flatten`".to_string(),
    ));
  }
  let token = user.item.user.token.clone().filter(|token| !token.is_empty());
  let pair_stated = stated(user.item.user.cert_data.as_ref()) || stated(user.item.user.key_data.as_ref());
  if user.item.user.exec.is_some() && token.is_none() && !pair_stated {
    return Ok(fail("exec credential plugins are not supported".to_string()));
  }
  if user.item.user.auth_provider.is_some() && token.is_none() && !pair_stated {
    return Ok(fail("auth-provider users are not supported".to_string()));
  }
  if cluster.item.cluster.server.is_empty() {
    return Ok(fail(format!("cluster `{}` states no `server`", cluster.item.name)));
  }
  let server = cluster.item.cluster.server.as_str();
  let scope: EndpointScope = match server.parse() {
    Ok(scope) => scope,
    Err(detail) => return Ok(fail(format!("server `{server}` is not an allow entry: {detail}"))),
  };
  if scope.scheme != Scheme::Https {
    return Ok(fail(format!("server `{server}` is plain HTTP: the API server is TLS-only")));
  }
  let HostPat::Exact(host) = scope.host else {
    return Ok(fail(format!("server `{server}` is not an allow entry: host is not exact")));
  };
  let cert = decode(
    &user.source,
    RewriteFormat::Kubeconfig,
    user.item.user.cert_data.as_deref(),
    "client-certificate-data",
  )?;
  let key = decode(
    &user.source,
    RewriteFormat::Kubeconfig,
    user.item.user.key_data.as_deref(),
    "client-key-data",
  )?;
  if cert.is_some() != key.is_some() {
    return Ok(fail(format!("user `{}` carries half of the client pair", user.item.name)));
  }
  if token.is_none() && cert.is_none() {
    return Ok(fail(format!(
      "user `{}` carries neither `token` nor a client pair: nothing to substitute",
      user.item.name
    )));
  }
  let ca = decode(
    &cluster.source,
    RewriteFormat::Kubeconfig,
    cluster.item.cluster.ca_data.as_deref(),
    "certificate-authority-data",
  )?;
  Ok(Classified::Grant(Pending {
    user_source: user.source.clone(),
    user_name: user.item.name.clone(),
    cluster_source: cluster.source.clone(),
    cluster_name: cluster.item.name.clone(),
    server: server.to_string(),
    host,
    port: scope.port,
    token,
    cert,
    key,
    ca,
  }))
}

fn stated(value: Option<&String>) -> bool {
  value.is_some_and(|text| !text.is_empty())
}

/// One granted user and the servers that user may call.
struct LiveUser {
  identity: ContextIdentity,
  token: Option<String>,
  cert: Option<Vec<u8>>,
  key: Option<Vec<u8>>,
  guest_cert: Vec<u8>,
  guest_key: Vec<u8>,
  servers: Vec<LiveServer>,
}

/// One server on a granted user's allow list.
struct LiveServer {
  url: String,
  host: String,
  port: u16,
  cluster_label: String,
  ca: Option<Vec<u8>>,
}

/// Grant text, blobs, and the decoy face for each granted user.
struct Rendered {
  fragment: String,
  materialized: Vec<(String, Vec<u8>)>,
  faces: BTreeMap<String, UserFace>,
}

fn render_pending(pending: &[Pending], ca: &CertAuthority, guests_dir: &Path) -> Result<Rendered, Error> {
  let users = live_users(pending, ca, guests_dir)?;
  require_user_servers(&users)?;
  let mut fragment = String::new();
  let mut materialized = Vec::new();
  let mut seen_blobs = BTreeSet::new();
  let mut faces = BTreeMap::new();
  for user in &users {
    fragment.push_str(&render_user(user)?);
    push_user_blobs(user, &mut materialized, &mut seen_blobs);
    faces.insert(
      user.identity.name.clone(),
      UserFace {
        token: user.token.as_ref().map(|_| user.identity.secret()),
        cert: pair_b64(&user.guest_cert, user.cert.is_some()),
        key: pair_b64(&user.guest_key, user.cert.is_some()),
      },
    );
  }
  Ok(Rendered {
    fragment,
    materialized,
    faces,
  })
}

fn pair_b64(bytes: &[u8], present: bool) -> Option<String> {
  present.then(|| STANDARD.encode(bytes))
}

fn live_users(pending: &[Pending], ca: &CertAuthority, guests_dir: &Path) -> Result<Vec<LiveUser>, Error> {
  let user_keys = distinct_keys(pending, |row| (&row.user_source, row.user_name.as_str()));
  let user_refs: Vec<ContextRef<'_>> = user_keys
    .iter()
    .map(|(source, name)| ContextRef {
      source,
      protocol: AmbientProtocol::KubernetesUser,
      name,
    })
    .collect();
  let user_ids = identities(&user_refs)?;
  let cluster_keys = distinct_keys(pending, |row| (&row.cluster_source, row.cluster_name.as_str()));
  let cluster_refs: Vec<ContextRef<'_>> = cluster_keys
    .iter()
    .map(|(source, name)| ContextRef {
      source,
      protocol: AmbientProtocol::KubernetesCluster,
      name,
    })
    .collect();
  let cluster_ids = identities(&cluster_refs)?;
  let mut users = Vec::with_capacity(user_ids.len());
  for identity in user_ids {
    let rows: Vec<&Pending> = pending
      .iter()
      .filter(|row| row.user_source == identity.source && row.user_name == identity.name)
      .collect();
    let Some(first) = rows.first() else {
      return Err(Error::RewriteInvalid {
        file: identity.source,
        format: RewriteFormat::Kubeconfig,
        detail: format!("user `{}` has no context", identity.name),
      });
    };
    let token = first.token.clone();
    let cert = first.cert.clone();
    let key = first.key.clone();
    let (guest_cert, guest_key) = if cert.is_some() {
      read_guest_pair(ca, guests_dir, &identity.label)?
    } else {
      (Vec::new(), Vec::new())
    };
    let mut servers = Vec::new();
    for row in &rows {
      if servers.iter().any(|server: &LiveServer| server.url == row.server) {
        continue;
      }
      let cluster_label = cluster_ids
        .iter()
        .find(|cluster| cluster.source == row.cluster_source && cluster.name == row.cluster_name)
        .map(|cluster| cluster.label.clone())
        .ok_or_else(|| Error::RewriteInvalid {
          file: row.cluster_source.clone(),
          format: RewriteFormat::Kubeconfig,
          detail: format!("cluster `{}` has no identity", row.cluster_name),
        })?;
      servers.push(LiveServer {
        url: row.server.clone(),
        host: row.host.clone(),
        port: row.port,
        cluster_label,
        ca: row.ca.clone(),
      });
    }
    users.push(LiveUser {
      identity,
      token,
      cert,
      key,
      guest_cert,
      guest_key,
      servers,
    });
  }
  Ok(users)
}

fn distinct_keys(pending: &[Pending], key: impl Fn(&Pending) -> (&Path, &str)) -> Vec<(PathBuf, String)> {
  let mut out = Vec::new();
  for row in pending {
    let (source, name) = key(row);
    if out
      .iter()
      .any(|(seen_source, seen_name)| seen_source == source && seen_name == name)
    {
      continue;
    }
    out.push((source.to_path_buf(), name.to_string()));
  }
  out
}

fn read_guest_pair(ca: &CertAuthority, guests_dir: &Path, label: &str) -> Result<(Vec<u8>, Vec<u8>), Error> {
  let (cert_path, key_path) = load_or_generate_client_pair(ca, guests_dir, label)?;
  let cert = fs::read(&cert_path).map_err(|source| Error::ReadFile { path: cert_path, source })?;
  let key = fs::read(&key_path).map_err(|source| Error::ReadFile { path: key_path, source })?;
  Ok((cert, key))
}

fn require_user_servers(users: &[LiveUser]) -> Result<(), Error> {
  let mut owned = Vec::new();
  for user in users {
    let decoy = if user.cert.is_some() {
      user.guest_cert.clone()
    } else {
      user.identity.secret().into_bytes()
    };
    for server in &user.servers {
      owned.push((user.identity.clone(), server.host.clone(), server.port, decoy.clone()));
    }
  }
  let presented: Vec<Presented<'_>> = owned
    .iter()
    .map(|(identity, host, port, decoy)| Presented {
      identity,
      host,
      port: *port,
      decoy,
    })
    .collect();
  require_distinct(&presented)?;
  Ok(())
}

fn render_user(user: &LiveUser) -> Result<String, Error> {
  let mut tls = BTreeMap::new();
  for server in &user.servers {
    tls.insert(server.url.clone(), server_tls(user, server));
  }
  let value = match &user.token {
    Some(token) => token.clone(),
    None => String::from_utf8_lossy(user.cert.as_deref().unwrap_or_default()).into_owned(),
  };
  render_fragment(
    &user.identity.source,
    &user.identity.label,
    &GrantFragment {
      env: user.identity.env(),
      registry: false,
      allow: user.servers.iter().map(|server| server.url.clone()).collect(),
      value: Some(value),
      real: None,
      generated: false,
      if_missing: None,
      tls,
      ssh: BTreeMap::new(),
    },
  )
}

fn server_tls(user: &LiveUser, server: &LiveServer) -> HostTlsCfg {
  let pair = user.cert.is_some();
  let label = &user.identity.label;
  HostTlsCfg {
    client_cert: pair.then(|| grant_path(&format!("{label}.client.crt"))),
    client_key: pair.then(|| grant_path(&format!("{label}.client.key"))),
    root_cert: server.ca.as_ref().map(|_| grant_path(&format!("{}.ca.crt", server.cluster_label))),
    guest_tls_mode: if pair { GuestTlsMode::Mtls } else { GuestTlsMode::Tls },
    guest_cert: None,
    guest_key: None,
  }
}

fn grant_path(name: &str) -> PathBuf {
  PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{name}"))
}

/// Write the upstream pair, the guest leaf, and the cluster CA.
///
/// `{label}.guest.crt` sits beside `{label}.client.crt`. The proxy compares
/// a presented client certificate with the first certificate in that file.
fn push_user_blobs(user: &LiveUser, materialized: &mut Vec<(String, Vec<u8>)>, seen: &mut BTreeSet<String>) {
  if let (Some(cert), Some(key)) = (&user.cert, &user.key) {
    push_blob(materialized, seen, format!("{}.client.crt", user.identity.label), cert.clone());
    push_blob(materialized, seen, format!("{}.client.key", user.identity.label), key.clone());
    push_blob(materialized, seen, guest_cert_file(&user.identity.label), user.guest_cert.clone());
  }
  for server in &user.servers {
    let Some(ca) = &server.ca else {
      continue;
    };
    push_blob(materialized, seen, format!("{}.ca.crt", server.cluster_label), ca.clone());
  }
}

fn push_blob(materialized: &mut Vec<(String, Vec<u8>)>, seen: &mut BTreeSet<String>, name: String, bytes: Vec<u8>) {
  if seen.insert(name.clone()) {
    materialized.push((name, bytes));
  }
}

/// The agent's decoy kubeconfig. Every cluster carries arkham's CA.
/// Every user loses `exec`, file paths, and the whole auth-provider block.
/// A granted user receives that user's decoy credential.
fn decoy_document(mut root: Value, ca: &CertAuthority, granted: &BTreeMap<String, UserFace>) -> Result<String, Error> {
  let guest_ca = Value::String(STANDARD.encode(ca.cert_pem()));
  for cluster in entries_mut(&mut root, "clusters") {
    let Some(inner) = cluster.get_mut(yaml_key("cluster")).and_then(Value::as_mapping_mut) else {
      continue;
    };
    inner.insert(yaml_key("certificate-authority-data"), guest_ca.clone());
    inner.remove(yaml_key("certificate-authority"));
  }
  for user in entries_mut(&mut root, "users") {
    let name = user.get(yaml_key("name")).and_then(Value::as_str).unwrap_or_default().to_string();
    let Some(inner) = user.get_mut(yaml_key("user")).and_then(Value::as_mapping_mut) else {
      continue;
    };
    let placeholder = skip_placeholder(&name);
    match granted.get(&name) {
      Some(face) => write_granted_user(inner, face),
      None => scrub_ungranted_user(inner, &placeholder),
    }
    scrub_user_secrets(inner, &placeholder);
  }
  render_decoy(&root)
}

fn write_granted_user(inner: &mut Mapping, face: &UserFace) {
  if let Some(token) = &face.token
    && inner.contains_key(yaml_key("token"))
  {
    inner.insert(yaml_key("token"), Value::String(token.clone()));
  }
  if let (Some(cert), Some(key)) = (&face.cert, &face.key) {
    let cert_key = yaml_key("client-certificate-data");
    let key_key = yaml_key("client-key-data");
    if inner.contains_key(&cert_key) || inner.contains_key(&key_key) {
      inner.insert(cert_key, Value::String(cert.clone()));
      inner.insert(key_key, Value::String(key.clone()));
    }
  }
}

fn scrub_ungranted_user(inner: &mut Mapping, placeholder: &str) {
  if inner.contains_key(yaml_key("token")) {
    inner.insert(yaml_key("token"), Value::String(placeholder.to_string()));
  }
  inner.remove(yaml_key("client-certificate-data"));
  inner.remove(yaml_key("client-key-data"));
}

fn scrub_user_secrets(inner: &mut Mapping, placeholder: &str) {
  inner.remove(yaml_key("client-certificate"));
  inner.remove(yaml_key("client-key"));
  inner.remove(yaml_key("exec"));
  inner.remove(yaml_key("auth-provider"));
  if inner.contains_key(yaml_key("password")) {
    inner.insert(yaml_key("password"), Value::String(placeholder.to_string()));
  }
}

fn skip_placeholder(name: &str) -> String {
  fake_for(&format!("KUBE_SKIP_{}", name.to_uppercase().replace(['-', '.'], "_")), None)
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

  const COMMENT_BREAKOUT: &str = "\n[rules.injected]\nallow = [\"https://evil.example:443\"]\nenv = \"INJECTED\"\nvalue = \"x\"\n#";

  fn text(value: &str) -> Value {
    Value::String(value.to_string())
  }

  fn named(slot: &str, name: &str, inner: &[(&str, Value)]) -> Value {
    let mut body = Mapping::new();
    for (field, value) in inner {
      body.insert(text(field), value.clone());
    }
    let mut entry = Mapping::new();
    entry.insert(text("name"), text(name));
    entry.insert(text(slot), Value::Mapping(body));
    Value::Mapping(entry)
  }

  fn kubeconfig(current: &str, contexts: Vec<Value>, clusters: Vec<Value>, users: Vec<Value>) -> String {
    let mut root = Mapping::new();
    root.insert(text("apiVersion"), text("v1"));
    root.insert(text("kind"), text("Config"));
    root.insert(text("current-context"), text(current));
    root.insert(text("contexts"), Value::Sequence(contexts));
    root.insert(text("clusters"), Value::Sequence(clusters));
    root.insert(text("users"), Value::Sequence(users));
    serde_yaml::to_string(&Value::Mapping(root)).expect("kubeconfig")
  }

  fn assert_fragment_is_only(adapted: &RewriteAdapted, label: &str) {
    let rules = rules_from(&adapted.fragment);
    assert_eq!(
      rules.keys().map(String::as_str).collect::<Vec<_>>(),
      vec![label],
      "{}",
      adapted.fragment
    );
  }

  #[test]
  fn foreign_content_is_not_a_kubeconfig() {
    let npmrc = "//registry.npmjs.org/:_authToken=secret";
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), npmrc.as_bytes(), &test_ca(), dir.path()).expect_err("plain text fails closed");
    assert!(err.to_string().contains("does not parse as YAML"), "{err}");
  }

  fn user_identity(name: &str) -> ContextIdentity {
    identities(&[ContextRef {
      source: Path::new(SOURCE),
      protocol: AmbientProtocol::KubernetesUser,
      name,
    }])
    .expect("user identity")
    .remove(0)
  }

  fn cluster_identity(name: &str) -> ContextIdentity {
    identities(&[ContextRef {
      source: Path::new(SOURCE),
      protocol: AmbientProtocol::KubernetesCluster,
      name,
    }])
    .expect("cluster identity")
    .remove(0)
  }

  #[test]
  fn label_names_the_user_not_the_context() {
    let user = user_identity("admin");
    assert!(user.label.starts_with("kube-user-"), "{}", user.label);
    let adapted = adapt_doc(BEARER_DOC);
    assert!(
      adapted.fragment.contains(&format!("[rules.{}]", user.label)),
      "{}",
      adapted.fragment
    );
  }

  #[test]
  fn fragment_holds_the_grant_and_parses_as_a_rule() {
    let user = user_identity("admin");
    let cluster = cluster_identity("k3s");
    let adapted = adapt_doc(BEARER_DOC);
    let rules = rules_from(&adapted.fragment);
    let rule = rules.get(&user.label).expect("rule present");
    assert_eq!(rule.env, user.env());
    assert_eq!(rule.allow, vec!["https://10.0.0.1:6443".to_string()]);
    assert_eq!(rule.registry, Some(false));
    assert!(rule.value.is_some(), "bearer token is the inline real value");
    let tls = rule.tls.get("https://10.0.0.1:6443").expect("tls keyed by the allow entry");
    assert!(
      tls
        .client_cert
        .as_ref()
        .is_some_and(|path| path.ends_with(format!("{}.client.crt", user.label)))
    );
    assert!(
      tls
        .root_cert
        .as_ref()
        .is_some_and(|path| path.ends_with(format!("{}.ca.crt", cluster.label)))
    );
    assert_eq!(tls.guest_tls_mode, GuestTlsMode::Mtls);
    assert_eq!(
      adapted.materialized.len(),
      4,
      "pair, guest leaf, and CA materialize beside the fragment"
    );
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

  /// A granted user that also carries an auth-provider keeps the token grant.
  /// The guest file still lists the user, and none of the provider's secrets,
  /// the password, or the real token appear in it.
  #[test]
  fn decoy_drops_auth_provider_secrets() {
    const ID_TOKEN: &str = "oidc-id-token-9f3c1a";
    const REFRESH: &str = "oidc-refresh-token-9f3c1a";
    const CLIENT_SECRET: &str = "oidc-client-secret-9f3c1a";
    const IDP_CA: &str = "oidc-idp-certificate-authority-data-9f3c1a";
    const PASSWORD: &str = "ivan-basic-password-9f3c1a";
    let mut config = Mapping::new();
    config.insert(text("id-token"), text(ID_TOKEN));
    config.insert(text("refresh-token"), text(REFRESH));
    config.insert(text("client-secret"), text(CLIENT_SECRET));
    config.insert(text("idp-certificate-authority-data"), text(IDP_CA));
    config.insert(text("access-token"), text("oidc-access-token-9f3c1a"));
    let mut provider = Mapping::new();
    provider.insert(text("name"), text("oidc"));
    provider.insert(text("config"), Value::Mapping(config));
    let doc = kubeconfig(
      "prod",
      vec![named("context", "prod", &[("cluster", text("prod")), ("user", text("ivan"))])],
      vec![named(
        "cluster",
        "prod",
        &[
          ("server", text("https://k8s.example:6443")),
          ("certificate-authority-data", text("Q0E=")),
        ],
      )],
      vec![named(
        "user",
        "ivan",
        &[
          ("token", text("ivan-real-token")),
          ("password", text(PASSWORD)),
          ("auth-provider", Value::Mapping(provider)),
        ],
      )],
    );
    let adapted = adapt_doc(&doc);
    for secret in [
      ID_TOKEN,
      REFRESH,
      CLIENT_SECRET,
      IDP_CA,
      "oidc-access-token-9f3c1a",
      PASSWORD,
      "ivan-real-token",
      "Q0E=",
    ] {
      assert!(!adapted.decoy.contains(secret), "{secret} in the guest file: {}", adapted.decoy);
    }
    for secret in [
      ID_TOKEN,
      REFRESH,
      CLIENT_SECRET,
      IDP_CA,
      "oidc-access-token-9f3c1a",
      PASSWORD,
      "Q0E=",
    ] {
      assert!(
        !adapted.fragment.contains(secret),
        "{secret} in the grant fragment: {}",
        adapted.fragment
      );
    }
    assert!(
      adapted.fragment.contains("ivan-real-token"),
      "the token grant keeps the real token: {}",
      adapted.fragment
    );
    assert!(adapted.decoy.contains("name: ivan"), "guest file lists the user: {}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("auth-provider"),
      "guest file keeps the provider block: {}",
      adapted.decoy
    );
  }

  #[test]
  fn token_only_user_takes_plain_tls_while_pair_users_take_mtls() {
    // Only unmasked fixture text is touched here, so the bearer value never
    // appears in this test.
    let token_doc = BEARER_DOC.replace(", client-certificate-data: Q0VSVA==, client-key-data: S0VZ", "");
    let token_rules = rules_from(&adapt_doc(&token_doc).fragment);
    let token_rule = token_rules.get(&user_identity("admin").label).expect("rule present");
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
    let pair_rule = pair_rules.get(&user_identity("admin").label).expect("rule present");
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
      rules[&user_identity("admin").label].value.is_some(),
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

  const THREE_CONTEXTS: &str = r"apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: ivan}
- name: staging
  context: {cluster: staging, user: ivan}
- name: prod-admin
  context: {cluster: prod, user: admin}
clusters:
- name: prod
  cluster: {server: https://k8s.example:6443, certificate-authority-data: Q0E=}
- name: staging
  cluster: {server: https://staging.example:6443, certificate-authority-data: U1RH}
users:
- name: ivan
  user: {token: ivan-real-token}
- name: admin
  user: {token: admin-real-token}
";

  /// Two clusters and one cluster shared by two users become one rule per
  /// user. The shared user lists both servers. The shared cluster names one
  /// CA file. `current-context` stays in the decoy and is not the rule name.
  #[test]
  fn three_contexts_grant_each_user_once_and_share_the_cluster_ca() {
    use arkham_config::context::{AmbientProtocol, ContextRef, identities};

    let source = Path::new(SOURCE);
    let users = identities(&[
      ContextRef {
        source,
        protocol: AmbientProtocol::KubernetesUser,
        name: "ivan",
      },
      ContextRef {
        source,
        protocol: AmbientProtocol::KubernetesUser,
        name: "admin",
      },
    ])
    .expect("user identities");
    let clusters = identities(&[
      ContextRef {
        source,
        protocol: AmbientProtocol::KubernetesCluster,
        name: "prod",
      },
      ContextRef {
        source,
        protocol: AmbientProtocol::KubernetesCluster,
        name: "staging",
      },
    ])
    .expect("cluster identities");
    let adapted = adapt_doc(THREE_CONTEXTS);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 2, "one rule per user, not per context: {}", adapted.fragment);
    let ivan = rules.get(&users[0].label).expect("ivan rule");
    let admin = rules.get(&users[1].label).expect("admin rule");
    assert_eq!(ivan.env, users[0].env());
    assert_eq!(
      ivan.allow,
      vec!["https://k8s.example:6443".to_string(), "https://staging.example:6443".to_string()]
    );
    assert_eq!(admin.allow, vec!["https://k8s.example:6443".to_string()]);
    let prod_ca = format!("{}.ca.crt", clusters[0].label);
    let staging_ca = format!("{}.ca.crt", clusters[1].label);
    let ivan_prod = ivan.tls.get("https://k8s.example:6443").expect("ivan prod tls");
    let ivan_staging = ivan.tls.get("https://staging.example:6443").expect("ivan staging tls");
    let admin_prod = admin.tls.get("https://k8s.example:6443").expect("admin prod tls");
    assert!(ivan_prod.root_cert.as_ref().is_some_and(|path| path.ends_with(&prod_ca)));
    assert!(ivan_staging.root_cert.as_ref().is_some_and(|path| path.ends_with(&staging_ca)));
    assert!(admin_prod.root_cert.as_ref().is_some_and(|path| path.ends_with(&prod_ca)));
    assert_eq!(adapted.materialized.iter().filter(|(name, _)| name == &prod_ca).count(), 1);
    assert_eq!(ivan_prod.guest_tls_mode, GuestTlsMode::Tls);
    assert!(adapted.decoy.contains("current-context: prod"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("name: prod-admin"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("ivan-real-token"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("admin-real-token"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("Q0E="), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("U1RH"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains(&users[0].secret()), "ivan decoy token");
    assert!(adapted.decoy.contains(&users[1].secret()), "admin decoy token");
    assert_ne!(users[0].secret(), users[1].secret());
  }

  /// An exec context that is not selected stays out of the grant file. The
  /// same context as `current-context` still errors, and that error names it.
  #[test]
  fn exec_context_is_skipped_unless_it_is_selected() {
    let doc = r"apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: ivan}
- name: eks
  context: {cluster: prod, user: exec-user}
clusters:
- name: prod
  cluster: {server: https://k8s.example:6443, certificate-authority-data: Q0E=}
users:
- name: ivan
  user: {token: ivan-real-token}
- name: exec-user
  user: {exec: {command: aws-iam-authenticator}}
";
    let adapted = adapt_doc(doc);
    assert_fragment_is_only(&adapted, &user_identity("ivan").label);
    assert!(!adapted.fragment.contains("eks"), "{}", adapted.fragment);
    assert!(!adapted.fragment.contains("exec"), "{}", adapted.fragment);
    assert!(!adapted.decoy.contains("aws-iam-authenticator"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("ivan-real-token"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("name: eks"), "the context stays in the decoy");

    let selected = doc.replace("current-context: prod", "current-context: eks");
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), selected.as_bytes(), &test_ca(), dir.path()).expect_err("selected exec still errors");
    assert!(err.to_string().contains("eks"), "{err}");
    assert!(err.to_string().contains("exec"), "{err}");
  }

  #[test]
  fn skipped_context_name_cannot_inject_a_rule() {
    let name = format!("eks{COMMENT_BREAKOUT}");
    let mut exec = Mapping::new();
    exec.insert(text("command"), text("aws-iam-authenticator"));
    let doc = kubeconfig(
      "prod",
      vec![
        named("context", &name, &[("cluster", text("prod")), ("user", text("exec-user"))]),
        named("context", "prod", &[("cluster", text("prod")), ("user", text("ivan"))]),
      ],
      vec![named(
        "cluster",
        "prod",
        &[
          ("server", text("https://k8s.example:6443")),
          ("certificate-authority-data", text("Q0E=")),
        ],
      )],
      vec![
        named("user", "ivan", &[("token", text("ivan-real-token"))]),
        named("user", "exec-user", &[("exec", Value::Mapping(exec))]),
      ],
    );
    assert_fragment_is_only(&adapt_doc(&doc), &user_identity("ivan").label);
  }

  #[test]
  fn skipped_user_name_cannot_inject_a_rule() {
    let user = format!("ghost{COMMENT_BREAKOUT}");
    let doc = kubeconfig(
      "prod",
      vec![
        named("context", "prod", &[("cluster", text("prod")), ("user", text("ivan"))]),
        named("context", "broken", &[("cluster", text("prod")), ("user", text(&user))]),
      ],
      vec![named(
        "cluster",
        "prod",
        &[
          ("server", text("https://k8s.example:6443")),
          ("certificate-authority-data", text("Q0E=")),
        ],
      )],
      vec![named("user", "ivan", &[("token", text("ivan-real-token"))])],
    );
    assert_fragment_is_only(&adapt_doc(&doc), &user_identity("ivan").label);
  }

  #[test]
  fn skipped_server_cannot_inject_a_rule() {
    let server = format!("https://k8s.example:6443{COMMENT_BREAKOUT}");
    let doc = kubeconfig(
      "prod",
      vec![
        named("context", "prod", &[("cluster", text("prod")), ("user", text("ivan"))]),
        named("context", "broken", &[("cluster", text("evil")), ("user", text("ivan"))]),
      ],
      vec![
        named(
          "cluster",
          "prod",
          &[
            ("server", text("https://k8s.example:6443")),
            ("certificate-authority-data", text("Q0E=")),
          ],
        ),
        named(
          "cluster",
          "evil",
          &[("server", text(&server)), ("certificate-authority-data", text("Q0E="))],
        ),
      ],
      vec![named("user", "ivan", &[("token", text("ivan-real-token"))])],
    );
    assert_fragment_is_only(&adapt_doc(&doc), &user_identity("ivan").label);
  }

  /// A later `KUBECONFIG` file does not replace a context, cluster, or user
  /// the earlier file already defined. Its new names are added. The identity
  /// path is the file that defined the name.
  #[test]
  fn kubeconfig_list_keeps_the_first_definition() {
    use arkham_config::context::{AmbientProtocol, ContextRef, identities};

    let first = Path::new("/home/ivan/.kube/config");
    let second = Path::new("/home/ivan/.kube/extra.yaml");
    let early = r"apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: ivan}
clusters:
- name: prod
  cluster: {server: https://k8s.example:6443, certificate-authority-data: Q0E=}
users:
- name: ivan
  user: {token: ivan-real-token}
";
    let late = r"apiVersion: v1
kind: Config
current-context: other
contexts:
- name: prod
  context: {cluster: replaced, user: replaced}
- name: extra
  context: {cluster: extra, user: extra-user}
clusters:
- name: prod
  cluster: {server: https://replaced.example:6443, certificate-authority-data: UkVQTACE=}
- name: extra
  cluster: {server: https://extra.example:6443, certificate-authority-data: RVhU}
users:
- name: ivan
  user: {token: replaced-token}
- name: extra-user
  user: {token: extra-real-token}
";
    let dir = tempfile::tempdir().unwrap();
    let adapted = adapt_sources(&[(first, early.as_bytes()), (second, late.as_bytes())], &test_ca(), dir.path())
      .expect("merge parses")
      .expect("kubeconfig");
    let ivan = identities(&[ContextRef {
      source: first,
      protocol: AmbientProtocol::KubernetesUser,
      name: "ivan",
    }])
    .expect("ivan")
    .remove(0);
    let extra = identities(&[ContextRef {
      source: second,
      protocol: AmbientProtocol::KubernetesUser,
      name: "extra-user",
    }])
    .expect("extra")
    .remove(0);
    let rules = rules_from(&adapted.fragment);
    assert!(rules.contains_key(&ivan.label), "{}", adapted.fragment);
    assert!(rules.contains_key(&extra.label), "{}", adapted.fragment);
    assert_eq!(rules[&ivan.label].allow, vec!["https://k8s.example:6443".to_string()]);
    assert_eq!(rules[&extra.label].allow, vec!["https://extra.example:6443".to_string()]);
    assert!(adapted.decoy.contains("current-context: prod"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("name: extra"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("replaced.example"), "first prod wins: {}", adapted.decoy);
    assert!(!adapted.decoy.contains("ivan-real-token"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("extra-real-token"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("replaced-token"), "{}", adapted.decoy);
  }

  #[test]
  fn state_writes_and_stale_ones_prune() {
    let adapted = adapt_doc(BEARER_DOC);
    let dir = tempfile::tempdir().unwrap();
    let grants = dir.path().join("grants");
    write_state(&grants, &[adapted]).unwrap();
    let rules = grants.join("rules.d");
    let label = user_identity("admin").label;
    let marker = fs::read_to_string(grants.join("arkham.toml")).unwrap();
    assert!(marker.contains(&format!("[rules.{label}]")), "{marker}");
    assert!(rules.join(format!("{label}.client.crt")).is_file());
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
