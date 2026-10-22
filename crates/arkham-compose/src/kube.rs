//! Kubeconfig adapter for `file_rewrite`: a kubectl config file is a
//! differently structured form of the same information a rule holds, so the
//! adapter derives the grant from the file instead of asking the operator to
//! state it twice. Every derivable context maps onto one grant per user. The
//! file is the secret source, so a kube entry stating `envs` is an error
//! rather than a second source.
//!
//! Detection is structural: a YAML mapping with `kind: Config` takes the
//! adapter path, everything else keeps the raw byte-swap. The grant label,
//! env, decoy, and guest pair come from [`AmbientProtocol::KubernetesUser`].
//! Each cluster CA blob is named by [`AmbientProtocol::KubernetesCluster`].
//! The decoy twin keeps every context and swaps trust and identity: arkham's
//! CA, a minted guest pair per user, and that user's decoy token. Two
//! client-certificate users of one API server host and port are
//! [`arkham_config::Error::AmbiguousContexts`]. The file fails when
//! `current-context` is in that group. Otherwise those contexts are skipped.
//! Any other context that cannot be derived is skipped. The `current-context`
//! failing still fails the file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::config::{HostTlsCfg, RewriteFormat, fake_for};
use arkham_config::context::{AmbientProtocol, AmbiguousContexts, ContextIdentity, ContextRef, Presented, identities, require_distinct};
use arkham_config::grants::{EndpointScope, GuestTlsMode, HostPat, Scheme};
use arkham_pki::ca::{CertAuthority, load_or_generate_client_pair};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_yaml::{Mapping, Value, from_str};

use crate::adapt::{GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, decode, render_decoy, render_fragment};
use crate::error::Error;

/// A kubeconfig document; unknown fields ignored.
#[derive(Debug, Clone, Deserialize, Default)]
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
#[derive(Debug, Clone, Deserialize, Default)]
struct KubeContextEntry {
  /// Entry name, matched against `current-context`.
  #[serde(default)]
  name: String,
  /// The referenced cluster and user.
  #[serde(default)]
  context: KubeContextRef,
  /// File that defined this context.
  #[serde(skip)]
  source: PathBuf,
}

/// The cluster/user a context points at.
#[derive(Debug, Clone, Deserialize, Default)]
struct KubeContextRef {
  /// Referenced cluster name.
  #[serde(default)]
  cluster: String,
  /// Referenced user name.
  #[serde(default)]
  user: String,
}

/// One `clusters` entry.
#[derive(Debug, Clone, Deserialize, Default)]
struct KubeClusterEntry {
  /// Entry name, matched against the context's `cluster`.
  #[serde(default)]
  name: String,
  /// The server and its trust anchor.
  #[serde(default)]
  cluster: KubeCluster,
  /// File that defined this cluster.
  #[serde(skip)]
  source: PathBuf,
}

/// A cluster's server and CA, inline or by file.
#[derive(Debug, Clone, Deserialize, Default)]
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
#[derive(Debug, Clone, Deserialize, Default)]
struct KubeUserEntry {
  /// Entry name, matched against the context's `user`.
  #[serde(default)]
  name: String,
  /// The credential.
  #[serde(default)]
  user: KubeUser,
  /// File that defined this user.
  #[serde(skip)]
  source: PathBuf,
}

/// A user's credential: bearer token and/or client pair, inline or by file.
#[derive(Debug, Clone, Deserialize, Default)]
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
#[derive(Debug, Clone, Deserialize, Default)]
struct KubeAuthProvider {
  /// Provider config holding the token.
  #[serde(default)]
  config: KubeProviderConfig,
}

/// Auth provider config.
#[derive(Debug, Clone, Deserialize, Default)]
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
struct Derived {
  context: String,
  user: String,
  user_source: PathBuf,
  cluster: String,
  cluster_source: PathBuf,
  /// API server URL, as written.
  server: String,
  scope: EndpointScope,
  token: Option<String>,
  cert: Option<Vec<u8>>,
  key: Option<Vec<u8>>,
  ca: Option<Vec<u8>>,
}

impl KubeContextEntry {
  fn derive(&self, doc: &KubeDoc) -> Result<Derived, Error> {
    let invalid = |detail: String| invalid_at(&self.source, detail);
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
    if !matches!(scope.host, HostPat::Exact(_)) {
      return Err(invalid(format!("server `{}` is not an exact host", cluster.cluster.server)));
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
      &self.source,
      RewriteFormat::Kubeconfig,
      user.user.cert_data.as_deref(),
      "client-certificate-data",
    )?;
    let key = decode(
      &self.source,
      RewriteFormat::Kubeconfig,
      user.user.key_data.as_deref(),
      "client-key-data",
    )?;
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
      &self.source,
      RewriteFormat::Kubeconfig,
      cluster.cluster.ca_data.as_deref(),
      "certificate-authority-data",
    )?;
    Ok(Derived {
      context: self.name.clone(),
      user: user.name.clone(),
      user_source: user.source.clone(),
      cluster: cluster.name.clone(),
      cluster_source: cluster.source.clone(),
      server: cluster.cluster.server.clone(),
      scope,
      token: token.map(str::to_string),
      cert,
      key,
      ca,
    })
  }
}

fn invalid_at(file: &Path, detail: String) -> Error {
  Error::RewriteInvalid {
    file: file.to_path_buf(),
    format: RewriteFormat::Kubeconfig,
    detail,
  }
}

/// Contexts that survived derivation.
struct DerivedContexts(Vec<Derived>);

impl DerivedContexts {
  fn user_refs(&self) -> Vec<ContextRef<'_>> {
    self
      .0
      .iter()
      .map(|derived| ContextRef {
        source: derived.user_source.as_path(),
        protocol: AmbientProtocol::KubernetesUser,
        name: derived.user.as_str(),
      })
      .collect()
  }

  fn cluster_refs(&self) -> Vec<ContextRef<'_>> {
    self
      .0
      .iter()
      .map(|derived| ContextRef {
        source: derived.cluster_source.as_path(),
        protocol: AmbientProtocol::KubernetesCluster,
        name: derived.cluster.as_str(),
      })
      .collect()
  }

  /// Certificate users that share a host and port cannot be told apart: the
  /// upstream handshake offers one client certificate before it reads a
  /// bearer. Token users are not part of that check. A group that includes
  /// `current` fails the file. Any other group is skipped.
  fn resolve_shared_certs(mut self, current: &str) -> Result<(Self, Vec<ContextIdentity>), Error> {
    let user_ids = identities(&self.user_refs())?;
    loop {
      let presented = self.presented(&user_ids)?;
      match require_distinct(&presented) {
        Ok(()) => return Ok((self, user_ids)),
        Err(arkham_config::Error::AmbiguousContexts(ambiguous)) => {
          let names = self.contexts_of(ambiguous.as_ref());
          if names.is_empty() || names.iter().any(|name| name == current) {
            return Err(arkham_config::Error::AmbiguousContexts(ambiguous).into());
          }
          let listed = names.join(", ");
          tracing::warn!(contexts = %listed, host = %ambiguous.host, port = ambiguous.port, "kube contexts skipped");
          self.0.retain(|derived| !names.iter().any(|name| name == &derived.context));
        }
        Err(err) => return Err(err.into()),
      }
    }
  }

  fn presented<'a>(&'a self, user_ids: &'a [ContextIdentity]) -> Result<Vec<Presented<'a>>, Error> {
    let mut presented = Vec::new();
    for derived in &self.0 {
      if derived.cert.is_none() {
        continue;
      }
      let host = match &derived.scope.host {
        HostPat::Exact(host) => host.as_str(),
        HostPat::Wildcard(_) | HostPat::Any => {
          return Err(invalid_at(
            &derived.user_source,
            format!("server `{}` is not an exact host", derived.server),
          ));
        }
      };
      let Some(identity) = identity_for(user_ids, &derived.user_source, &derived.user) else {
        return Err(invalid_at(&derived.user_source, format!("user `{}` has no identity", derived.user)));
      };
      presented.push(Presented {
        identity,
        host,
        port: derived.scope.port,
        decoy: b"",
      });
    }
    Ok(presented)
  }

  fn contexts_of(&self, ambiguous: &AmbiguousContexts) -> Vec<String> {
    let mut names: Vec<String> = self
      .0
      .iter()
      .filter(|derived| {
        derived.cert.is_some()
          && derived.scope.port == ambiguous.port
          && ambiguous
            .parties
            .iter()
            .any(|party| party.name == derived.user && party.source == derived.user_source)
          && matches!(&derived.scope.host, HostPat::Exact(host) if host.eq_ignore_ascii_case(&ambiguous.host))
      })
      .map(|derived| derived.context.clone())
      .collect();
    names.sort();
    names.dedup();
    names
  }

  fn into_grants(self) -> UserGrants {
    let mut grants = UserGrants(Vec::new());
    for derived in self.0 {
      grants.include(derived);
    }
    grants
  }
}

fn identity_for<'a>(ids: &'a [ContextIdentity], source: &Path, name: &str) -> Option<&'a ContextIdentity> {
  ids.iter().find(|id| id.name == name && id.source == source)
}

/// One API server a user reaches.
struct Server {
  url: String,
  scope: EndpointScope,
  cluster: String,
  cluster_source: PathBuf,
  ca: Option<Vec<u8>>,
}

/// One grant: every server a single user reaches.
struct UserGrant {
  user: String,
  user_source: PathBuf,
  token: Option<String>,
  cert: Option<Vec<u8>>,
  key: Option<Vec<u8>>,
  servers: Vec<Server>,
}

/// Grants keyed by user identity.
struct UserGrants(Vec<UserGrant>);

impl UserGrants {
  fn include(&mut self, derived: Derived) {
    let server = Server {
      url: derived.server,
      scope: derived.scope,
      cluster: derived.cluster,
      cluster_source: derived.cluster_source,
      ca: derived.ca,
    };
    if let Some(grant) = self
      .0
      .iter_mut()
      .find(|grant| grant.user == derived.user && grant.user_source == derived.user_source)
    {
      if grant.servers.iter().all(|existing| existing.url != server.url) {
        grant.servers.push(server);
      }
      return;
    }
    self.0.push(UserGrant {
      user: derived.user,
      user_source: derived.user_source,
      token: derived.token,
      cert: derived.cert,
      key: derived.key,
      servers: vec![server],
    });
  }

  fn render(
    self,
    users: &[ContextIdentity],
    clusters: &[ContextIdentity],
    ca: &CertAuthority,
    guests_dir: &Path,
  ) -> Result<RenderedBatch, Error> {
    let mut fragment = String::new();
    let mut materialized = Vec::new();
    let mut guests = BTreeMap::new();
    for grant in self.0 {
      let rendered = grant.render(users, clusters, ca, guests_dir)?;
      fragment.push_str(&rendered.fragment);
      materialized.extend(rendered.materialized);
      guests.insert(rendered.user, rendered.guest);
    }
    Ok(RenderedBatch {
      fragment,
      materialized,
      guests,
    })
  }
}

impl UserGrant {
  fn render(
    self,
    users: &[ContextIdentity],
    clusters: &[ContextIdentity],
    ca: &CertAuthority,
    guests_dir: &Path,
  ) -> Result<Rendered, Error> {
    let Some(user_id) = identity_for(users, &self.user_source, &self.user) else {
      return Err(invalid_at(&self.user_source, format!("user `{}` has no identity", self.user)));
    };
    if self.servers.is_empty() {
      return Err(invalid_at(&self.user_source, format!("user `{}` has no server", self.user)));
    }
    // Identity-only grants (cert auth, no bearer) still need a value to
    // resolve; the certificate never reaches the wire as application data, so
    // it can never match the swap.
    let value = self
      .token
      .clone()
      .unwrap_or_else(|| String::from_utf8_lossy(self.cert.as_deref().unwrap_or_default()).into_owned());
    // A client pair means mutual TLS both ways: the guest presents the minted
    // pair, the proxy the real one upstream. Token-only users carry no client
    // certificate, so asking for one fails their handshake with `certificate
    // required` before any bearer swap can happen.
    let mode = if self.cert.is_some() {
      GuestTlsMode::Mtls
    } else {
      GuestTlsMode::Tls
    };
    let (guest_cert_path, guest_key_path) = load_or_generate_client_pair(ca, guests_dir, &user_id.label)?;
    let guest_cert = fs::read(&guest_cert_path).map_err(|source| Error::ReadFile {
      path: guest_cert_path.clone(),
      source,
    })?;
    let guest_key = fs::read(&guest_key_path).map_err(|source| Error::ReadFile {
      path: guest_key_path.clone(),
      source,
    })?;
    let mut materialized = Vec::new();
    let (client_cert, client_key) = match (self.cert, self.key) {
      (Some(cert), Some(key)) => {
        let cert_name = format!("{}.client.crt", user_id.label);
        let key_name = format!("{}.client.key", user_id.label);
        let cert_path = PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{cert_name}"));
        let key_path = PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{key_name}"));
        materialized.push((cert_name, cert));
        materialized.push((key_name, key));
        (Some(cert_path), Some(key_path))
      }
      _ => (None, None),
    };
    let mut allow = Vec::new();
    let mut scopes = Vec::new();
    let mut tls = BTreeMap::new();
    let mut written_ca = BTreeSet::new();
    for server in self.servers {
      let Some(cluster_id) = identity_for(clusters, &server.cluster_source, &server.cluster) else {
        return Err(invalid_at(
          &server.cluster_source,
          format!("cluster `{}` has no identity", server.cluster),
        ));
      };
      let mut entry = HostTlsCfg {
        client_cert: client_cert.clone(),
        client_key: client_key.clone(),
        root_cert: None,
        guest_tls_mode: mode,
        guest_cert: None,
        guest_key: None,
      };
      if let Some(bytes) = server.ca {
        let ca_name = format!("{}.ca.crt", cluster_id.label);
        entry.root_cert = Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{ca_name}")));
        if written_ca.insert(ca_name.clone()) {
          materialized.push((ca_name, bytes));
        }
      }
      allow.push(server.url.clone());
      scopes.push(server.scope);
      tls.insert(server.url, entry);
    }
    let fragment = render_fragment(
      &self.user_source,
      &user_id.label,
      &GrantFragment {
        env: user_id.env(),
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
      user: self.user,
      fragment,
      materialized,
      guest: GuestUser {
        token: self.token.map(|_| user_id.secret()),
        cert: STANDARD.encode(guest_cert),
        key: STANDARD.encode(guest_key),
      },
    })
  }
}

/// Grant text plus the per-user guest identities.
struct RenderedBatch {
  fragment: String,
  materialized: Vec<(String, Vec<u8>)>,
  guests: BTreeMap<String, GuestUser>,
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

/// Map one kubeconfig onto grants. A file that is not a kubeconfig returns
/// `None`. A `KUBECONFIG` list uses [`adapt_sources`].
///
/// # Errors
///
/// Returns an error when the document does not parse, the current context
/// cannot be derived, the current context shares a client certificate with
/// another user on one API server, or a credential field is malformed.
pub(crate) fn adapt(source: &Path, content: &[u8], ca: &CertAuthority, guests_dir: &Path) -> Result<Option<RewriteAdapted>, Error> {
  adapt_sources(&[(source, content)], ca, guests_dir)
}

/// Map kubeconfig files, merged in order, onto one fragment per derivable user.
///
/// A context, cluster, or user name that is already defined stays. A new name
/// is added. `current-context` is the first non-empty value. The winning
/// entry keeps the path of the file that defined it, so identities from two
/// files stay distinct. A single file that is not a kubeconfig returns `None`.
///
/// # Errors
///
/// Returns an error when a document does not parse, a later file in a list is
/// not a kubeconfig, the current context cannot be derived, the current
/// context shares a client certificate with another user on one API server, or
/// a credential field is malformed.
pub(crate) fn adapt_sources(sources: &[(&Path, &[u8])], ca: &CertAuthority, guests_dir: &Path) -> Result<Option<RewriteAdapted>, Error> {
  let Some(merged) = MergedKube::load(sources)? else {
    return Ok(None);
  };
  let mut opened = Vec::new();
  for entry in &merged.doc.contexts {
    match entry.derive(&merged.doc) {
      Ok(derived) => opened.push(derived),
      Err(err) if entry.name == merged.doc.current_context => return Err(err),
      Err(err) => tracing::warn!(context = %entry.name, %err, "kube context skipped"),
    }
  }
  let (opened, user_ids) = DerivedContexts(opened).resolve_shared_certs(&merged.doc.current_context)?;
  let cluster_ids = identities(&opened.cluster_refs())?;
  let rendered = opened.into_grants().render(&user_ids, &cluster_ids, ca, guests_dir)?;
  Ok(Some(RewriteAdapted {
    fragment: rendered.fragment,
    decoy: decoy_doc(&merged.guest, ca, &rendered.guests)?,
    materialized: rendered.materialized,
    decoy_files: Vec::new(),
  }))
}

/// Merged kubeconfig: the typed document grants are derived from, and the raw
/// document the guest file is rewritten from.
struct MergedKube {
  doc: KubeDoc,
  guest: Value,
}

impl MergedKube {
  fn load(sources: &[(&Path, &[u8])]) -> Result<Option<Self>, Error> {
    let Some(&(first, _)) = sources.first() else {
      return Ok(None);
    };
    let mut merge = Merge::default();
    for &(path, content) in sources {
      let text = String::from_utf8_lossy(content);
      let raw: Value = from_str(&text).map_err(|source| Error::RewriteYaml {
        file: path.to_path_buf(),
        source,
      })?;
      let doc: KubeDoc = from_str(&text).map_err(|source| Error::RewriteYaml {
        file: path.to_path_buf(),
        source,
      })?;
      if doc.kind != "Config" {
        if sources.len() == 1 {
          return Ok(None);
        }
        return Err(invalid_at(path, "not a kubeconfig".to_string()));
      }
      merge.absorb(path, &doc, &raw);
    }
    merge.finish(first).map(Some)
  }
}

/// First-wins merge of kubeconfig files.
#[derive(Default)]
struct Merge {
  current: String,
  contexts: Vec<KubeContextEntry>,
  clusters: Vec<KubeClusterEntry>,
  users: Vec<KubeUserEntry>,
  seen_contexts: BTreeSet<String>,
  seen_clusters: BTreeSet<String>,
  seen_users: BTreeSet<String>,
  guest_contexts: Vec<Value>,
  guest_clusters: Vec<Value>,
  guest_users: Vec<Value>,
  root: Option<Value>,
}

impl Merge {
  fn absorb(&mut self, path: &Path, doc: &KubeDoc, raw: &Value) {
    if self.root.is_none() {
      self.root = Some(raw.clone());
    }
    if self.current.is_empty() {
      self.current.clone_from(&doc.current_context);
    }
    for (entry, raw_entry) in doc.contexts.iter().zip(sequence(raw, "contexts")) {
      if !self.seen_contexts.insert(entry.name.clone()) {
        continue;
      }
      let mut entry = entry.clone();
      entry.source = path.to_path_buf();
      self.contexts.push(entry);
      self.guest_contexts.push(raw_entry.clone());
    }
    for (entry, raw_entry) in doc.clusters.iter().zip(sequence(raw, "clusters")) {
      if !self.seen_clusters.insert(entry.name.clone()) {
        continue;
      }
      let mut entry = entry.clone();
      entry.source = path.to_path_buf();
      self.clusters.push(entry);
      self.guest_clusters.push(raw_entry.clone());
    }
    for (entry, raw_entry) in doc.users.iter().zip(sequence(raw, "users")) {
      if !self.seen_users.insert(entry.name.clone()) {
        continue;
      }
      let mut entry = entry.clone();
      entry.source = path.to_path_buf();
      self.users.push(entry);
      self.guest_users.push(raw_entry.clone());
    }
  }

  fn finish(self, first: &Path) -> Result<MergedKube, Error> {
    if self.current.is_empty() {
      return Err(invalid_at(first, "missing `current-context`".to_string()));
    }
    if !self.contexts.iter().any(|entry| entry.name == self.current) {
      return Err(invalid_at(first, format!("unknown context `{}`", self.current)));
    }
    let Some(mut guest) = self.root else {
      return Err(invalid_at(first, "kubeconfig is not a mapping".to_string()));
    };
    let Some(map) = guest.as_mapping_mut() else {
      return Err(invalid_at(first, "kubeconfig is not a mapping".to_string()));
    };
    map.insert(Value::String("current-context".to_string()), Value::String(self.current.clone()));
    map.insert(Value::String("contexts".to_string()), Value::Sequence(self.guest_contexts));
    map.insert(Value::String("clusters".to_string()), Value::Sequence(self.guest_clusters));
    map.insert(Value::String("users".to_string()), Value::Sequence(self.guest_users));
    Ok(MergedKube {
      doc: KubeDoc {
        kind: "Config".to_string(),
        current_context: self.current,
        contexts: self.contexts,
        clusters: self.clusters,
        users: self.users,
      },
      guest,
    })
  }
}

fn sequence<'a>(raw: &'a Value, key: &str) -> &'a [Value] {
  raw
    .as_mapping()
    .and_then(|map| map.get(Value::String(key.to_string())))
    .and_then(Value::as_sequence)
    .map_or(&[], Vec::as_slice)
}

/// The agent's decoy kubeconfig: the parsed document verbatim, with trust
/// and identity swapped in every entry. Arkham's CA replaces every inline
/// cluster CA. Each granted user's own guest pair and decoy token replace
/// that user's credentials, because only decoys may cross into the agent. A
/// user with no grant gets placeholders, never another user's pair. Every
/// string in `auth-provider.config` becomes a placeholder. `exec` blocks and
/// file-reference credentials are dropped from every user. Every other field,
/// spec'd or not, round-trips unchanged.
fn decoy_doc(root: &Value, ca: &CertAuthority, guests: &BTreeMap<String, GuestUser>) -> Result<String, Error> {
  let mut root = root.clone();
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
      let decoy = guest.and_then(|guest| guest.token.clone()).unwrap_or_else(&placeholder);
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
    if let Some(config) = inner
      .get_mut(Value::String("auth-provider".to_string()))
      .and_then(Value::as_mapping_mut)
      .and_then(|provider| provider.get_mut(Value::String("config".to_string())))
    {
      let filler = placeholder();
      scrub_secret_strings(config, &filler);
    }
    if inner.contains_key(Value::String("password".to_string())) {
      inner.insert(Value::String("password".to_string()), Value::String(placeholder()));
    }
    inner.remove(Value::String("exec".to_string()));
  }
  render_decoy(&root)
}

fn scrub_secret_strings(value: &mut Value, filler: &str) {
  match value {
    Value::Null | Value::Bool(_) | Value::Number(_) => {}
    Value::String(text) => *text = filler.to_string(),
    Value::Sequence(items) => {
      for item in items {
        scrub_secret_strings(item, filler);
      }
    }
    Value::Mapping(map) => {
      for child in map.values_mut() {
        scrub_secret_strings(child, filler);
      }
    }
    Value::Tagged(tagged) => scrub_secret_strings(&mut tagged.value, filler),
  }
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
  use arkham_config::grants::decoy_for_rule;
  use serde::Deserialize;

  use super::*;
  use crate::adapt::write_state;

  fn kube_identity(protocol: AmbientProtocol, name: &str) -> ContextIdentity {
    identities(&[ContextRef {
      source: Path::new(SOURCE),
      protocol,
      name,
    }])
    .expect("identity")
    .into_iter()
    .next()
    .expect("one identity")
  }

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
  fn label_is_the_user_identity() {
    let user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let adapted = adapt_doc(BEARER_DOC);
    assert!(
      adapted.fragment.contains(&format!("[rules.{}]", user.label)),
      "{}",
      adapted.fragment
    );
    assert!(adapted.fragment.contains(&user.env()), "{}", adapted.fragment);
  }

  #[test]
  fn fragment_holds_the_grant_and_parses_as_a_rule() {
    let adapted = adapt_doc(BEARER_DOC);
    let rules = rules_from(&adapted.fragment);
    let user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let cluster = kube_identity(AmbientProtocol::KubernetesCluster, "k3s");
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
    let token_user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let token_rule = token_rules.get(&token_user.label).expect("rule present");
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
    let pair_user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let pair_rule = pair_rules.get(&pair_user.label).expect("rule present");
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
    let user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    assert!(rules[&user.label].value.is_some(), "identity grant still resolves");
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
  fn merged_files_keep_the_defining_path_on_the_identity() {
    let first = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: alice
  user: {token: alice-token}
";
    let second = "apiVersion: v1
kind: Config
current-context: staging
contexts:
- name: prod
  context: {cluster: evil, user: mallory}
- name: staging
  context: {cluster: staging, user: bob}
clusters:
- name: evil
  cluster: {server: https://10.9.0.9:6443, certificate-authority-data: Q0E=}
- name: staging
  cluster: {server: https://10.2.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: mallory
  user: {token: mallory-token}
- name: bob
  user: {token: bob-token}
";
    let first_path = Path::new("/home/ivan/.kube/first.yaml");
    let second_path = Path::new("/home/ivan/.kube/second.yaml");
    let dir = tempfile::tempdir().unwrap();
    let adapted = adapt_sources(
      &[(first_path, first.as_bytes()), (second_path, second.as_bytes())],
      &test_ca(),
      dir.path(),
    )
    .expect("adapt parses")
    .expect("merged kubeconfig");
    let rules = rules_from(&adapted.fragment);
    let alice = identities(&[ContextRef {
      source: first_path,
      protocol: AmbientProtocol::KubernetesUser,
      name: "alice",
    }])
    .expect("alice identity")
    .into_iter()
    .next()
    .expect("alice");
    let bob = identities(&[ContextRef {
      source: second_path,
      protocol: AmbientProtocol::KubernetesUser,
      name: "bob",
    }])
    .expect("bob identity")
    .into_iter()
    .next()
    .expect("bob");
    assert!(rules.contains_key(&alice.label), "{}", adapted.fragment);
    assert!(rules.contains_key(&bob.label), "{}", adapted.fragment);
    assert_ne!(alice.label, bob.label);
    assert!(!adapted.fragment.contains("https://10.9.0.9:6443"), "{}", adapted.fragment);
    assert!(adapted.decoy.contains("name: evil"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("mallory-token"), "{}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("user: mallory"),
      "the first prod user stays alice: {}",
      adapted.decoy
    );
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
    let user = kube_identity(AmbientProtocol::KubernetesUser, "alice");
    let rule = rules.get(&user.label).expect("grant labeled by the user identity");
    assert!(rule.allow.iter().any(|entry| entry == "https://10.0.0.1:6443"), "{:?}", rule.allow);
    assert!(rule.allow.iter().any(|entry| entry == "https://10.2.0.1:6443"), "{:?}", rule.allow);
    let cluster_a = kube_identity(AmbientProtocol::KubernetesCluster, "a");
    let cluster_b = kube_identity(AmbientProtocol::KubernetesCluster, "b");
    let ca_name = |rule: &RuleCfg, server: &str, label: &str| {
      rule
        .tls
        .get(server)
        .and_then(|tls| tls.root_cert.as_ref())
        .is_some_and(|path| path.ends_with(format!("{label}.ca.crt")))
    };
    assert!(ca_name(rule, "https://10.0.0.1:6443", &cluster_a.label), "{:?}", rule.tls);
    assert!(ca_name(rule, "https://10.2.0.1:6443", &cluster_b.label), "{:?}", rule.tls);
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
    let Error::Config(source) = err else {
      panic!("expected AmbiguousContexts, got {err}");
    };
    let arkham_config::Error::AmbiguousContexts(ambiguous) = source.as_ref() else {
      panic!("expected AmbiguousContexts, got {source}");
    };
    let names: Vec<&str> = ambiguous.parties.iter().map(|party| party.name.as_str()).collect();
    assert!(names.contains(&"alice") && names.contains(&"bob"), "{names:?}");
    assert_eq!(ambiguous.host, "10.0.0.1");
    assert_eq!(ambiguous.port, 6443);
  }

  #[test]
  fn cert_users_off_the_current_context_are_skipped() {
    let doc = "apiVersion: v1
kind: Config
current-context: dev
contexts:
- name: dev
  context: {cluster: dev, user: carol}
- name: prod
  context: {cluster: shared, user: alice}
- name: staging
  context: {cluster: shared, user: bob}
clusters:
- name: dev
  cluster: {server: https://10.9.0.1:6443, certificate-authority-data: Q0E=}
- name: shared
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: carol
  user: {token: carol-token}
- name: alice
  user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZ}
- name: bob
  user: {client-certificate-data: Qk9C, client-key-data: S0VZ}
";
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let adapted = tracing::subscriber::with_default(WarnCapture(std::sync::Arc::clone(&lines)), || adapt_doc(doc));
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 1, "the side collision is not a grant: {}", adapted.fragment);
    assert!(!adapted.fragment.contains("https://10.0.0.1:6443"), "{}", adapted.fragment);
    assert!(adapted.fragment.contains("https://10.9.0.1:6443"), "{}", adapted.fragment);
    assert!(
      adapted.decoy.contains("name: prod") && adapted.decoy.contains("name: staging"),
      "{}",
      adapted.decoy
    );
    assert!(
      !adapted.decoy.contains("Q0VSVA==") && !adapted.decoy.contains("Qk9C"),
      "{}",
      adapted.decoy
    );
    assert!(!adapted.decoy.contains("carol-token"), "{}", adapted.decoy);
    let logged = lines.lock().unwrap().join("\n");
    assert!(logged.contains("prod") && logged.contains("staging"), "{logged}");
  }

  #[test]
  fn distinct_user_spellings_do_not_share_a_label() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod.eu
contexts:
- name: prod.eu
  context: {cluster: a, user: prod.eu}
- name: prod-eu
  context: {cluster: b, user: prod-eu}
clusters:
- name: a
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
- name: b
  cluster: {server: https://10.2.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: prod.eu
  user: {token: left-token}
- name: prod-eu
  user: {token: right-token}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    let left = kube_identity(AmbientProtocol::KubernetesUser, "prod.eu");
    let right = kube_identity(AmbientProtocol::KubernetesUser, "prod-eu");
    assert_ne!(left.label, right.label);
    assert!(rules.contains_key(&left.label), "{}", adapted.fragment);
    assert!(rules.contains_key(&right.label), "{}", adapted.fragment);
    assert_ne!(rule_decoy(&rules[&left.label]), rule_decoy(&rules[&right.label]));
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
  fn oidc_config_secrets_do_not_reach_the_guest() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
- name: staging
  context: {cluster: staging, user: oidc}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
- name: staging
  cluster: {server: https://10.2.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: alice
  user: {token: alice-token}
- name: oidc
  user: {auth-provider: {name: oidc, config: {access-token: oidc-access-token, id-token: oidc-id-token, refresh-token: oidc-refresh-token, client-secret: oidc-client-secret}}}
";
    let adapted = adapt_doc(doc);
    for secret in [
      "alice-token",
      "oidc-access-token",
      "oidc-id-token",
      "oidc-refresh-token",
      "oidc-client-secret",
    ] {
      assert!(!adapted.decoy.contains(secret), "{secret} survives: {}", adapted.decoy);
    }
    let oidc = kube_identity(AmbientProtocol::KubernetesUser, "oidc");
    assert!(
      !adapted.decoy.contains(&oidc.secret()),
      "auth-provider config does not carry the grant decoy: {}",
      adapted.decoy
    );
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("name: oidc"), "{}", adapted.decoy);
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
    let user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let cluster = kube_identity(AmbientProtocol::KubernetesCluster, "k3s");
    assert!(marker.contains(&format!("[rules.{}]", user.label)), "{marker}");
    assert!(rules.join(format!("{}.client.crt", user.label)).is_file());
    assert!(rules.join(format!("{}.ca.crt", cluster.label)).is_file());
    let stale = rules.join("kube-gone.crt");
    fs::write(&stale, "stale").unwrap();
    write_state(&grants, &[]).unwrap();
    assert!(!stale.exists(), "removed rewrites stop granting");
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
