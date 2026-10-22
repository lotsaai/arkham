//! NATS context adapter: `~/.config/nats/context/<name>.json` is one
//! connection string plus the credential the CLI reads from disk.
//! `context.txt` is copied when the host has one. It is not how a credential
//! is chosen.
//!
//! The guest tree is one writable directory at `{home}/.config/nats`, so
//! `nats context select` can rename `context.txt`. A creds or nkey file is
//! `decoy/<label>.<suffix>` inside that directory. The decoy seed comes from
//! that context's `key_seed()`. Identical TLS bytes share one blob path. A
//! selected context that does not map is a skip. A dial clash is a typed
//! error when `context.txt` names one of the contexts, and a typed skip
//! otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arkham_config::config::IfMissing;
use arkham_config::context::{AmbientProtocol, ContextIdentity, ContextRef, Presented, identities, require_distinct};
use arkham_config::grants::{NATS_DEFAULT_PORT, NatsPlain, NatsScope, NatsUriError};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

mod credential;

use crate::adapt::{BLOB_PREFIX_NATS, GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, render_fragment};
use crate::error::Error;
use crate::rewrites::RewriteCollector;

/// Context fields the CLI keeps that are not credentials. The decoy copies
/// these and the replacement auth fields, and leaves every other key out.
const KEPT_KEYS: &[&str] = &[
  "description",
  "url",
  "jetstream_domain",
  "jetstream_api_prefix",
  "jetstream_event_prefix",
  "inbox_prefix",
  "color_scheme",
  "tls_first",
];

/// One discovered context directory, ready for the ambient pass.
#[derive(Debug)]
pub(crate) struct AdaptedNats {
  /// Contexts that became grants, in file order.
  pub(crate) grants: Vec<RewriteAdapted>,
  /// Paths relative to [`Self::container`].
  pub(crate) files: Vec<(String, Vec<u8>)>,
  /// `{home}/.config/nats`. The directory mounts here, writable.
  pub(crate) container: String,
  /// Contexts that did not map. A dial clash on the selected context is an error instead.
  pub(crate) skipped: Vec<NatsSkip>,
}

impl AdaptedNats {
  /// Mount the decoy tree as one writable directory and record the grants.
  ///
  /// # Errors
  ///
  /// Returns an error when the directory cannot be written.
  pub(crate) fn install(self, collector: &mut RewriteCollector) -> Result<(), Error> {
    collector.mount_directory(NATS_HOME_DIR, &self.container, &self.files)?;
    collector.grants.extend(self.grants);
    Ok(())
  }
}

/// Guest-tree directory in the state folder. Main wrote that twin as a file named `nats-context`.
const NATS_HOME_DIR: &str = "nats-home";

/// # Errors
///
/// Returns an error when a seed sits outside the nkey or creds field, two
/// contexts on one server cannot be told apart, the selected context clashes
/// on the upstream dial, or a grant fragment cannot be serialized. A missing
/// `context.txt` still maps the directory.
pub(crate) fn adapt(root: &Path, home: &str, host_home: &Path) -> Result<Option<AdaptedNats>, Error> {
  NatsContextTree::new(root, home, host_home).adapt()
}

/// Why one context file did not become a grant.
#[derive(Debug, thiserror::Error)]
#[error("context `{name}` {cause}")]
pub struct NatsSkip {
  /// Context name.
  pub name: String,
  /// What kept the context out.
  #[source]
  pub cause: NatsSkipCause,
}

/// The reason a [`NatsSkip`] names.
#[derive(Debug, thiserror::Error)]
pub enum NatsSkipCause {
  /// `windows_cert_store` or `socks_proxy`.
  #[error("uses {0}")]
  Unsupported(NatsUnsupported),
  /// The server URL is not a `nats` or `tls` list.
  #[error("server url is not a nats or tls list")]
  ServerUrl,
  /// The credential does not map onto one auth method.
  /// `detail` is empty, or `: ` plus stderr from `op` or `nsc`.
  #[error("credential does not map onto one auth method{detail}")]
  Credential {
    /// Empty, or a colon and the host command's stderr.
    detail: String,
  },
  /// `cert` without `key`, or a TLS file that cannot be read.
  #[error("tls file cannot be read")]
  TlsFile,
  /// The file cannot be read as one JSON object.
  #[error("is not a context object")]
  Document,
  /// The connection strings were rejected, other than a misplaced seed.
  #[error("connection was rejected")]
  Rejected,
  /// This context and `other` share a server but not the upstream TLS dial.
  #[error("shares {host}:{port} with `{other}` but not the upstream tls")]
  Dial {
    /// The other context in the clash.
    other: String,
    /// Shared host.
    host: String,
    /// Shared port.
    port: u16,
  },
  /// `context.txt` names a file that is not in the directory.
  #[error("is not in the context directory")]
  Absent,
  /// The file name is not a context name the CLI can select.
  #[error("name is not a context name")]
  Name,
}

/// A field that has no substitute in the connection-string model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NatsUnsupported {
  /// `windows_cert_store`.
  #[error("windows_cert_store")]
  WindowsCertStore,
  /// `socks_proxy`.
  #[error("socks_proxy")]
  SocksProxy,
}

impl NatsSkip {
  fn new(name: &str, cause: NatsSkipCause) -> Self {
    Self {
      name: name.to_string(),
      cause,
    }
  }

  fn from_scope(name: &str, err: NatsUriError) -> Result<Self, Error> {
    if matches!(err, NatsUriError::MisplacedSeed) {
      return Err(Error::Config(Box::new(arkham_config::Error::NatsScope {
        label: name.to_string(),
        source: err,
      })));
    }
    Ok(Self::new(name, NatsSkipCause::Rejected))
  }
}

impl NatsUnsupported {
  fn of(doc: &Map<String, Value>) -> Option<Self> {
    if occupied(doc, "windows_cert_store") {
      return Some(Self::WindowsCertStore);
    }
    if occupied(doc, "socks_proxy") {
      return Some(Self::SocksProxy);
    }
    None
  }
}

impl NatsSkipCause {
  fn credential() -> Self {
    Self::Credential { detail: String::new() }
  }

  fn credential_output(stderr: &[u8]) -> Self {
    let text = String::from_utf8_lossy(stderr);
    let text = text.trim();
    if text.is_empty() {
      Self::credential()
    } else {
      Self::Credential {
        detail: format!(": {text}"),
      }
    }
  }
}

#[derive(Clone)]
struct GuestCred {
  tree_path: String,
  bytes: String,
}

impl GuestCred {
  fn written(&self) -> String {
    format!("~/.config/nats/{}", self.tree_path)
  }
}

/// TLS bytes read once for a context. Every server of that context shares them.
#[derive(PartialEq, Eq)]
struct TlsMaterial {
  handshake_first: bool,
  cert: Option<Arc<[u8]>>,
  key: Option<Arc<[u8]>>,
  ca: Option<Arc<[u8]>>,
}

/// Query pairs and grant blobs for one dial's TLS material.
struct TlsQuery {
  pairs: Vec<(&'static str, String)>,
  blobs: Vec<(String, Vec<u8>)>,
}

/// Upstream dial compared within one host and port.
#[derive(Clone)]
struct Dial {
  host: String,
  port: u16,
  real_tls: bool,
  tls: Arc<TlsMaterial>,
}

impl Dial {
  fn same_material(&self, other: &Self) -> bool {
    self.real_tls == other.real_tls && self.tls == other.tls
  }

  fn blob_name(bytes: &[u8], kind: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    format!("{BLOB_PREFIX_NATS}{}.{kind}", hex::encode(&digest[..16]))
  }

  fn tls_query(&self) -> TlsQuery {
    let mut pairs = Vec::new();
    let mut blobs = Vec::new();
    if !self.real_tls {
      return TlsQuery { pairs, blobs };
    }
    if self.tls.handshake_first {
      pairs.push(("handshake_first", "true".to_string()));
    }
    for (kind, field, bytes) in [
      ("crt", "sslcert", self.tls.cert.as_deref()),
      ("key", "sslkey", self.tls.key.as_deref()),
      ("ca", "sslrootcert", self.tls.ca.as_deref()),
    ] {
      let Some(bytes) = bytes else {
        continue;
      };
      let name = Self::blob_name(bytes, kind);
      pairs.push((field, format!("{GRANTS_STATE_DIR}/rules.d/{name}")));
      blobs.push((name, bytes.to_vec()));
    }
    TlsQuery { pairs, blobs }
  }
}

/// One context. The decoy and guest file are shared by every server.
struct ContextReady {
  identity: ContextIdentity,
  guest: Option<GuestCred>,
  decoy: String,
  servers: Vec<ServerReady>,
}

impl ContextReady {
  fn tree_files(&self) -> Vec<(String, Vec<u8>)> {
    let mut files = vec![(format!("context/{}.json", self.identity.name), self.decoy.as_bytes().to_vec())];
    if let Some(guest) = &self.guest {
      files.push((guest.tree_path.clone(), guest.bytes.as_bytes().to_vec()));
    }
    files
  }
}

/// One server of a [`ContextReady`]. Blobs travel with the server a clash keeps.
struct ServerReady {
  index: usize,
  dial: Dial,
  fake_url: String,
  real_url: String,
  blobs: Vec<(String, Vec<u8>)>,
}

fn decoy_doc(doc: &Map<String, Value>, public_url: &str, fake: &NatsPlain, guest: Option<&GuestCred>) -> Map<String, Value> {
  let mut out = kept_doc(doc, public_url);
  let written = guest.map(GuestCred::written);
  let auth = fake.context_auth(written.as_deref());
  if let Ok(Value::Object(fields)) = serde_json::to_value(auth) {
    out.extend(fields);
  }
  out
}

/// The context directory under `root`, read once.
pub(crate) struct NatsContextTree<'a> {
  root: &'a Path,
  home: &'a str,
  host_home: &'a Path,
}

impl<'a> NatsContextTree<'a> {
  /// Read `root` as a NATS context directory.
  pub(crate) fn new(root: &'a Path, home: &'a str, host_home: &'a Path) -> Self {
    Self { root, home, host_home }
  }

  /// # Errors
  ///
  /// Returns an error when a seed sits outside the nkey or creds field, two
  /// contexts on one server cannot be told apart, the selected context
  /// clashes on the upstream dial, or a grant fragment cannot be serialized.
  /// A context that does not map is a skip, including the selected one.
  pub(crate) fn adapt(self) -> Result<Option<AdaptedNats>, Error> {
    let (selected_text, mut skipped) = self.selection()?;
    let mut name_skips = Vec::new();
    let files = self.context_files(&mut name_skips)?;
    skipped.append(&mut name_skips);
    if files.is_empty() && selected_text.is_none() {
      return Ok(None);
    }
    let selected = selected_text.as_deref().filter(|name| context_name(name));
    if let Some(name) = selected
      && !files.iter().any(|(found, _)| found == name)
    {
      skipped.push(NatsSkip::new(name, NatsSkipCause::Absent));
    }
    let refs = files
      .iter()
      .map(|(name, path)| ContextRef {
        source: path.as_path(),
        protocol: AmbientProtocol::Nats,
        name: name.as_str(),
      })
      .collect::<Vec<_>>();
    let ids = identities(&refs)?;
    let mut contexts = Vec::new();
    let mut opens = Vec::new();
    for ((name, path), id) in files.iter().zip(ids.iter()) {
      match self.one_context(path, name, id)? {
        Ok(Built::Grants(ctx)) => contexts.push(ctx),
        Ok(Built::Open(decoy)) => opens.push((name.clone(), decoy)),
        Err(skip) => {
          tracing::warn!(%skip, "nats context skipped");
          skipped.push(skip);
        }
      }
    }
    let (contexts, dial_skips) = self.reconcile(selected, contexts)?;
    for skip in dial_skips {
      tracing::warn!(%skip, "nats context skipped");
      skipped.push(skip);
    }
    let (contexts, shared) = Self::collapse_same(contexts);
    let presented = contexts
      .iter()
      .flat_map(|ctx| {
        ctx.servers.iter().map(|server| Presented {
          identity: &ctx.identity,
          host: server.dial.host.as_str(),
          port: server.dial.port,
          decoy: server.fake_url.as_bytes(),
        })
      })
      .collect::<Vec<_>>();
    require_distinct(&presented)?;
    let mut tree = Vec::new();
    if let Some(name) = &selected_text {
      tree.push(("context.txt".to_string(), format!("{name}\n").into_bytes()));
    }
    for (name, decoy) in opens {
      tree.push((format!("context/{name}.json"), decoy.into_bytes()));
    }
    tree.extend(shared);
    let mut grants = Vec::new();
    for ctx in contexts {
      tree.extend(ctx.tree_files());
      for server in ctx.servers {
        grants.push(Self::grant_of(&ctx.identity, server)?);
      }
    }
    Ok(Some(AdaptedNats {
      grants,
      files: tree,
      container: format!("{}/.config/nats", self.home),
      skipped,
    }))
  }

  fn selection(&self) -> Result<(Option<String>, Vec<NatsSkip>), Error> {
    let path = self.root.join("context.txt");
    if !path.is_file() {
      return Ok((None, Vec::new()));
    }
    let text = fs::read_to_string(&path).map_err(|source| Error::ReadFile {
      path: path.clone(),
      source,
    })?;
    let name = text.trim().to_string();
    if context_name(&name) {
      return Ok((Some(name), Vec::new()));
    }
    let skip = NatsSkip::new(&name, NatsSkipCause::Name);
    Ok((Some(name), vec![skip]))
  }

  fn context_files(&self, skipped: &mut Vec<NatsSkip>) -> Result<Vec<(String, PathBuf)>, Error> {
    let dir = self.root.join("context");
    if !dir.is_dir() {
      return Ok(Vec::new());
    }
    let mut files = Vec::new();
    let entries = fs::read_dir(&dir).map_err(|source| Error::ReadFile { path: dir.clone(), source })?;
    for entry in entries {
      let entry = entry.map_err(|source| Error::ReadFile { path: dir.clone(), source })?;
      let path = entry.path();
      if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
        continue;
      }
      let Some(name) = path.file_stem().map(|stem| stem.to_string_lossy().into_owned()) else {
        continue;
      };
      if !context_name(&name) {
        skipped.push(NatsSkip::new(&name, NatsSkipCause::Name));
        continue;
      }
      files.push((name, path));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
  }

  fn one_context(&self, path: &Path, name: &str, id: &ContextIdentity) -> Result<Result<Built, NatsSkip>, Error> {
    let Ok(body) = fs::read_to_string(path) else {
      return Ok(Err(NatsSkip::new(name, NatsSkipCause::Document)));
    };
    let Ok(value) = serde_json::from_str::<Value>(&body) else {
      return Ok(Err(NatsSkip::new(name, NatsSkipCause::Document)));
    };
    let Some(mut doc) = value.as_object().cloned() else {
      return Ok(Err(NatsSkip::new(name, NatsSkipCause::Document)));
    };
    if let Some(feature) = NatsUnsupported::of(&doc) {
      return Ok(Err(NatsSkip::new(name, NatsSkipCause::Unsupported(feature))));
    }
    if let Err(cause) = self.apply_nsc(&mut doc) {
      return Ok(Err(NatsSkip::new(name, cause)));
    }
    let Some(servers) = ServerUrl::parse_list(text(&doc, "url")) else {
      return Ok(Err(NatsSkip::new(name, NatsSkipCause::ServerUrl)));
    };
    let public_url = ServerUrl::public_list(&servers);
    let real = match self.credential(&doc, &servers) {
      Ok(real) => real,
      Err(cause) => return Ok(Err(NatsSkip::new(name, cause))),
    };
    let Some(real) = real else {
      let Ok(decoy) = serde_json::to_string_pretty(&kept_doc(&doc, &public_url)) else {
        return Ok(Err(NatsSkip::new(name, NatsSkipCause::Rejected)));
      };
      return Ok(Ok(Built::Open(decoy)));
    };
    let (fake, guest) = Self::wire_auth(&real, &id.env(), &id.label, id.key_seed())?;
    let material = match self.tls_material(&doc) {
      Ok(material) => material,
      Err(cause) => return Ok(Err(NatsSkip::new(name, cause))),
    };
    let decoy_value = decoy_doc(&doc, &public_url, &fake, guest.as_ref());
    let Ok(decoy) = serde_json::to_string_pretty(&decoy_value) else {
      return Ok(Err(NatsSkip::new(name, NatsSkipCause::Rejected)));
    };
    let mut mapped = Vec::with_capacity(servers.len());
    for (index, server) in servers.iter().enumerate() {
      let dial = match Self::dial(server, &material) {
        Ok(dial) => dial,
        Err(cause) => return Ok(Err(NatsSkip::new(name, cause))),
      };
      let Some(fake_url) = server.auth_string(server.url.scheme(), &fake, &[]) else {
        return Ok(Err(NatsSkip::new(name, NatsSkipCause::Rejected)));
      };
      let query = dial.tls_query();
      let scheme = if dial.real_tls { "tls" } else { "nats" };
      let Some(real_url) = server.auth_string(scheme, &real, &query.pairs) else {
        return Ok(Err(NatsSkip::new(name, NatsSkipCause::Rejected)));
      };
      if let Err(err) = NatsScope::from_strings(&fake_url, &real_url) {
        return match NatsSkip::from_scope(name, err) {
          Ok(skip) => Ok(Err(skip)),
          Err(err) => Err(err),
        };
      }
      mapped.push(ServerReady {
        index,
        dial,
        fake_url,
        real_url,
        blobs: query.blobs,
      });
    }
    Ok(Ok(Built::Grants(ContextReady {
      identity: id.clone(),
      guest,
      decoy,
      servers: mapped,
    })))
  }

  fn reconcile(&self, selected: Option<&str>, mut contexts: Vec<ContextReady>) -> Result<(Vec<ContextReady>, Vec<NatsSkip>), Error> {
    let mut groups: BTreeMap<(String, u16), Vec<(usize, usize)>> = BTreeMap::new();
    for (ci, ctx) in contexts.iter().enumerate() {
      for (si, server) in ctx.servers.iter().enumerate() {
        groups
          .entry((server.dial.host.clone(), server.dial.port))
          .or_default()
          .push((ci, si));
      }
    }
    let mut skipped = Vec::new();
    let mut drop_at = Vec::new();
    for indexes in groups.into_values() {
      let at = indexes
        .iter()
        .position(|(ci, _)| selected.is_some_and(|name| contexts[*ci].identity.name == name))
        .unwrap_or(0);
      let (cci, csi) = indexes[at];
      let canonical_name = contexts[cci].identity.name.clone();
      let canonical_dial = contexts[cci].servers[csi].dial.clone();
      let selected_here = selected.is_some_and(|name| canonical_name == name);
      for &(ci, si) in &indexes {
        if contexts[ci].servers[si].dial.same_material(&canonical_dial) {
          continue;
        }
        let other = contexts[ci].identity.name.clone();
        let cause = NatsSkipCause::Dial {
          other: if selected_here { other.clone() } else { canonical_name.clone() },
          host: canonical_dial.host.clone(),
          port: canonical_dial.port,
        };
        if selected_here && let Some(name) = selected {
          return Err(self.selected_error(NatsSkip::new(name, cause)));
        }
        skipped.push(NatsSkip::new(&other, cause));
        drop_at.push((ci, si));
      }
    }
    drop_at.sort_unstable();
    drop_at.dedup();
    for (ci, si) in drop_at.into_iter().rev() {
      contexts[ci].servers.remove(si);
    }
    contexts.retain(|ctx| !ctx.servers.is_empty());
    Ok((contexts, skipped))
  }

  fn selected_error(&self, skip: NatsSkip) -> Error {
    Error::NatsSelected {
      file: self.root.join("context").join(format!("{}.json", skip.name)),
      skip,
    }
  }

  fn collapse_same(contexts: Vec<ContextReady>) -> (Vec<ContextReady>, Vec<(String, Vec<u8>)>) {
    let mut seen: BTreeSet<(String, u16, String, String)> = BTreeSet::new();
    let mut kept = Vec::new();
    let mut shared = Vec::new();
    for mut ctx in contexts {
      ctx.servers.retain(|server| {
        seen.insert((
          server.dial.host.clone(),
          server.dial.port,
          server.fake_url.clone(),
          server.real_url.clone(),
        ))
      });
      if ctx.servers.is_empty() {
        shared.extend(ctx.tree_files());
        continue;
      }
      kept.push(ctx);
    }
    (kept, shared)
  }

  fn grant_of(identity: &ContextIdentity, server: ServerReady) -> Result<RewriteAdapted, Error> {
    let label = if server.index == 0 {
      identity.label.clone()
    } else {
      format!("{}-{}", identity.label, server.index)
    };
    let fragment = GrantFragment {
      env: identity.env(),
      registry: false,
      allow: Vec::new(),
      value: Some(server.fake_url),
      real: Some(crate::adapt::Redacted(server.real_url)),
      generated: true,
      if_missing: Some(IfMissing::Ignore),
      tls: BTreeMap::new(),
      ssh: BTreeMap::new(),
    };
    Ok(RewriteAdapted {
      fragment: render_fragment(&identity.source, &label, &fragment)?,
      decoy: String::new(),
      materialized: server.blobs,
      decoy_files: Vec::new(),
    })
  }

  fn tls_material(&self, doc: &Map<String, Value>) -> Result<Arc<TlsMaterial>, NatsSkipCause> {
    let read = |raw: &str| self.tls_file(raw).map(|bytes| bytes.map(Arc::<[u8]>::from));
    let cert = text(doc, "cert");
    let key = text(doc, "key");
    let paired = !cert.is_empty() && !key.is_empty();
    Ok(Arc::new(TlsMaterial {
      handshake_first: doc.get("tls_first").and_then(Value::as_bool).unwrap_or(false),
      cert: if paired { read(cert)? } else { None },
      key: if paired { read(key)? } else { None },
      ca: read(text(doc, "ca"))?,
    }))
  }

  fn dial(server: &ServerUrl, material: &Arc<TlsMaterial>) -> Result<Dial, NatsSkipCause> {
    let real_tls = server.url.scheme() == "tls" || material.handshake_first || material.cert.is_some() || material.ca.is_some();
    let Some(host) = server.url.host_str() else {
      return Err(NatsSkipCause::ServerUrl);
    };
    Ok(Dial {
      host: host.to_ascii_lowercase(),
      port: server.url.port().unwrap_or(NATS_DEFAULT_PORT),
      real_tls,
      tls: Arc::clone(material),
    })
  }

  fn credential(&self, doc: &Map<String, Value>, servers: &[ServerUrl]) -> Result<Option<NatsPlain>, NatsSkipCause> {
    let user = text(doc, "user");
    let token_raw = text(doc, "token");
    let creds = text(doc, "creds");
    let nkey = text(doc, "nkey");
    let user_jwt = text(doc, "user_jwt");
    let user_seed = text(doc, "user_seed");
    let primary = if !user.is_empty() {
      let password = self.literal_text(text(doc, "password"))?;
      Some(NatsPlain::UserPass {
        user: user.to_string(),
        pass: password,
      })
    } else if !creds.is_empty() {
      Some(self.creds(creds)?)
    } else if !nkey.is_empty() {
      Some(NatsPlain::Nkey(self.nkey(nkey)?))
    } else if !user_jwt.is_empty() && !user_seed.is_empty() {
      Some(self.paired(user_seed, user_jwt)?)
    } else if !user_jwt.is_empty() {
      Some(NatsPlain::Jwt(self.literal_text(user_jwt)?))
    } else {
      None
    };
    let with_token = if token_raw.is_empty() {
      primary
    } else {
      let token = self.literal_text(token_raw)?;
      match primary {
        None => Some(NatsPlain::Token(token)),
        Some(NatsPlain::UserPass { user, pass }) => Some(NatsPlain::UserToken { user, pass, token }),
        Some(NatsPlain::Creds { .. } | NatsPlain::Nkey(_) | NatsPlain::Jwt(_) | NatsPlain::Token(_) | NatsPlain::UserToken { .. }) => {
          return Err(NatsSkipCause::credential());
        }
      }
    };
    if let Some(from_url) = servers.iter().find_map(ServerUrl::userinfo) {
      match &with_token {
        Some(NatsPlain::Creds { .. } | NatsPlain::Nkey(_) | NatsPlain::Jwt(_)) => return Ok(with_token),
        None | Some(NatsPlain::UserPass { .. } | NatsPlain::UserToken { .. } | NatsPlain::Token(_)) => return Ok(Some(from_url)),
      }
    }
    Ok(with_token)
  }

  fn apply_nsc(&self, doc: &mut Map<String, Value>) -> Result<(), NatsSkipCause> {
    let nsc = text(doc, "nsc");
    if nsc.is_empty() {
      return Ok(());
    }
    let (creds, service) = self.nsc_profile(nsc)?;
    if text(doc, "creds").is_empty() && !creds.is_empty() {
      doc.insert("creds".to_string(), Value::String(creds));
    }
    if text(doc, "url").is_empty() && !service.is_empty() {
      doc.insert("url".to_string(), Value::String(service));
    }
    Ok(())
  }

  fn wire_auth(real: &NatsPlain, env: &str, label: &str, key_seed: &[u8; 32]) -> Result<(NatsPlain, Option<GuestCred>), Error> {
    let prepared = real.prepare(env, key_seed).map_err(|_source| Error::NatsDecoy)?;
    let guest = prepared.file.map(|file| GuestCred {
      tree_path: format!("decoy/{label}.{}", file.suffix),
      bytes: file.body,
    });
    Ok((prepared.decoy, guest))
  }
}

enum Built {
  Grants(ContextReady),
  Open(String),
}

struct ServerUrl {
  url: Url,
}

impl ServerUrl {
  fn parse_list(raw: &str) -> Option<Vec<Self>> {
    let raw = if raw.is_empty() { "nats://localhost:4222" } else { raw };
    let mut out = Vec::new();
    for part in raw.split(',') {
      let part = part.trim().trim_end_matches('/');
      if part.is_empty() {
        continue;
      }
      let url = Url::parse(part).ok()?;
      if url.scheme() != "nats" && url.scheme() != "tls" {
        return None;
      }
      url.host_str()?;
      out.push(Self { url });
    }
    (!out.is_empty()).then_some(out)
  }

  fn userinfo(&self) -> Option<NatsPlain> {
    let user = self.url.username();
    if user.is_empty() {
      return None;
    }
    match self.url.password() {
      None => Some(NatsPlain::Token(user.to_string())),
      Some(pass) => Some(NatsPlain::UserPass {
        user: user.to_string(),
        pass: pass.to_string(),
      }),
    }
  }

  fn auth_string(&self, scheme: &str, auth: &NatsPlain, query: &[(&str, String)]) -> Option<String> {
    let host = match self.url.host()? {
      url::Host::Domain(host) => host.to_string(),
      url::Host::Ipv4(addr) => addr.to_string(),
      url::Host::Ipv6(addr) => addr.to_string(),
    };
    Some(auth.connection_string(scheme, &host, self.url.port(), query))
  }

  fn public(&self) -> String {
    let mut url = self.url.clone();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.to_string()
  }

  fn public_list(servers: &[Self]) -> String {
    servers.iter().map(Self::public).collect::<Vec<_>>().join(",")
  }
}

fn kept_doc(doc: &Map<String, Value>, public_url: &str) -> Map<String, Value> {
  let mut out = Map::new();
  for key in KEPT_KEYS {
    if *key == "url" {
      continue;
    }
    if let Some(value) = doc.get(*key) {
      out.insert((*key).to_string(), value.clone());
    }
  }
  out.insert("url".to_string(), Value::String(public_url.to_string()));
  out
}

fn context_name(name: &str) -> bool {
  !name.is_empty() && !name.contains(['/', '\\']) && !name.contains("..")
}

fn text<'a>(doc: &'a Map<String, Value>, key: &str) -> &'a str {
  doc.get(key).and_then(Value::as_str).unwrap_or("")
}

fn occupied(doc: &Map<String, Value>, key: &str) -> bool {
  match doc.get(key) {
    Some(Value::String(value)) => !value.is_empty(),
    Some(Value::Null) | None => false,
    Some(_) => true,
  }
}

#[cfg(test)]
mod tests {
  use std::os::unix::fs::MetadataExt as _;

  use arkham_config::config::RuleCfg;
  use base64::Engine as _;
  use base64::engine::general_purpose::URL_SAFE_NO_PAD;
  use pretty_assertions::assert_eq;
  use secrecy::ExposeSecret as _;
  use serde::Deserialize;
  use tempfile::tempdir;

  use super::*;

  use arkham_config::grants::NatsSeed;
  use secrecy::SecretString;

  const JWT_BEGIN: &str = "-----BEGIN NATS USER JWT-----";
  const JWT_END: &str = "------END NATS USER JWT------";
  const SEED_BEGIN: &str = "-----BEGIN USER NKEY SEED-----";
  const SEED_END: &str = "------END USER NKEY SEED------";

  fn extension_is(path: &str, ext: &str) -> bool {
    Path::new(path).extension().is_some_and(|found| found.eq_ignore_ascii_case(ext))
  }

  fn decorate_creds(jwt: &str, seed: &str) -> String {
    format!("{JWT_BEGIN}\n{jwt}\n{JWT_END}\n\n{SEED_BEGIN}\n{seed}\n{SEED_END}\n")
  }

  #[derive(Debug, Deserialize)]
  struct RulesDoc {
    rules: BTreeMap<String, RuleCfg>,
  }

  fn user_seed() -> String {
    nkeys::KeyPair::new_user().seed().expect("user seed")
  }

  fn user_jwt(public: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{public}"}}"#).as_bytes());
    format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode(b"sig"))
  }

  fn write_context(root: &Path, name: &str, body: &str) {
    fs::create_dir_all(root.join("context")).unwrap();
    fs::write(root.join("context.txt"), format!("{name}\n")).unwrap();
    fs::write(root.join("context").join(format!("{name}.json")), body).unwrap();
  }

  fn adapted(root: &Path, home: &Path) -> AdaptedNats {
    adapt(root, "/home/eng", home).expect("adapt").expect("selected context maps")
  }

  fn file<'a>(found: &'a AdaptedNats, rel: &str) -> &'a [u8] {
    found
      .files
      .iter()
      .find(|(path, _)| path == rel)
      .unwrap_or_else(|| panic!("{rel} missing"))
      .1
      .as_slice()
  }

  fn context_json(found: &AdaptedNats, name: &str) -> String {
    String::from_utf8(file(found, &format!("context/{name}.json")).to_vec()).unwrap()
  }

  fn decoy_bytes<'a>(found: &'a AdaptedNats, ext: &str) -> &'a [u8] {
    found
      .files
      .iter()
      .find(|(path, _)| path.starts_with("decoy/") && extension_is(path, ext))
      .unwrap_or_else(|| panic!("decoy {ext} missing"))
      .1
      .as_slice()
  }

  fn grant<'a>(found: &'a AdaptedNats, name: &str) -> &'a RewriteAdapted {
    let marker = format!("/context/{name}.json");
    found
      .grants
      .iter()
      .find(|grant| grant.fragment.contains(&marker))
      .unwrap_or_else(|| panic!("{name} missing"))
  }

  fn rule_named(found: &AdaptedNats, name: &str) -> RuleCfg {
    let doc: RulesDoc = toml::from_str(&grant(found, name).fragment).expect("fragment");
    doc.rules.into_values().next().expect("one rule")
  }

  fn rule_of(found: &AdaptedNats) -> RuleCfg {
    let name = String::from_utf8(file(found, "context.txt").to_vec()).expect("context.txt is utf-8");
    rule_named(found, name.trim())
  }

  #[test]
  fn integration_client_does_not_mount_the_secret_tree() {
    let yaml = include_str!("../../../../integration/compose.yaml");
    assert!(
      !yaml.lines().any(|line| line.trim() == "- ./out:/out"),
      "the client and smtp-direct mounts must not be the secret tree"
    );
    assert!(yaml.contains("- ./out/results:/out"));
    assert!(
      !yaml.contains("nats-discovered"),
      "the client must use the mount arkham init emits, not a copied tree"
    );
  }

  #[test]
  fn ipv6_auth_url_is_bracketed_once() {
    let server = ServerUrl::parse_list("tls://[::1]:4222")
      .expect("ipv6 url")
      .pop()
      .expect("one server");
    let auth = NatsPlain::UserPass {
      user: "agent".to_string(),
      pass: "p".to_string(),
    };
    assert_eq!(server.auth_string("tls", &auth, &[]).expect("auth url"), "tls://agent:p@[::1]:4222");
  }

  #[test]
  fn absent_context_dir_derives_nothing() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    assert!(adapt(&root, "/home/eng", home.path()).unwrap().is_none());
  }

  #[test]
  fn user_password_context_keeps_the_real_password_in_the_grant() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(
      &root,
      "demo",
      r#"{"url":"tls://nats.internal:4222","user":"agent","password":"real-nats-pass","tls_first":true,"jetstream_domain":"app"}"#, // betterleaks:allow
    );
    fs::write(root.join("context").join("other.json"), r#"{"password":"other-real-pass"}"#).unwrap(); // betterleaks:allow
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let fake = rule.value.as_ref().unwrap().expose_secret();
    let real = rule.real.as_ref().expect("stated real").expose_secret();
    let scope = NatsScope::from_strings(fake, real).expect("grant strings");
    assert!(scope.auth.signer().is_none());
    assert_eq!(scope.auth.fields().len(), 2);
    assert!(real.contains("real-nats-pass"), "{real}");
    assert!(!fake.contains("real-nats-pass"), "{fake}");
    assert!(real.contains("handshake_first=true"), "{real}");
    assert!(!fake.contains("handshake_first"), "{fake}");
    let text = context_json(&found, "demo");
    let decoy: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(decoy["user"], "agent");
    assert_eq!(decoy["tls_first"], true);
    assert_eq!(decoy["jetstream_domain"], "app");
    assert_ne!(decoy["password"], "real-nats-pass");
    assert!(!text.contains("real-nats-pass"));
    assert!(!text.contains("other-real-pass"));
    let other = context_json(&found, "other");
    assert!(!other.contains("other-real-pass"), "{other}");
    assert!(other.contains("localhost"), "{other}");
    assert!(found.skipped.is_empty(), "{:?}", found.skipped);
    assert!(found.grants.iter().all(|grant| !grant.fragment.contains("/context/other.json")));
    assert_eq!(found.container, "/home/eng/.config/nats");
    assert_eq!(file(&found, "context.txt"), b"demo\n");
    assert!(found.grants[0].fragment.contains("/context/demo.json"));
  }

  #[test]
  fn creds_file_is_read_for_the_grant_and_replaced_for_the_guest() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public.clone();
    let jwt = user_jwt(&public);
    let creds = home.path().join(".nkeys").join("user.creds");
    fs::create_dir_all(creds.parent().unwrap()).unwrap();
    fs::write(&creds, decorate_creds(&jwt, &seed)).unwrap();
    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"tls://nats.internal:4222","creds":"{}"}}"#, creds.display()),
    );
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let real = rule.real.as_ref().unwrap().expose_secret().to_string();
    let fake = rule.value.as_ref().unwrap().expose_secret().to_string();
    NatsScope::from_strings(&fake, &real).expect("creds grant");
    assert!(real.contains(&seed), "the grant holds the real seed");
    assert!(real.contains(&jwt), "the grant holds the real jwt");
    let guest_text = String::from_utf8(decoy_bytes(&found, "creds").to_vec()).unwrap();
    assert!(guest_text.contains(JWT_BEGIN));
    assert!(guest_text.contains(SEED_BEGIN));
    assert!(!guest_text.contains(&seed));
    assert!(!guest_text.contains(&jwt));
    let text = context_json(&found, "demo");
    assert!(!text.contains(&seed));
    assert!(!text.contains(&jwt));
    let decoy: Value = serde_json::from_str(&text).unwrap();
    assert!(decoy["creds"].as_str().unwrap().contains("/.config/nats/decoy/"));
  }

  #[test]
  fn nkey_file_and_token_and_unmapped_contexts() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let nkey = root.join("operator.nk");
    fs::create_dir_all(&root).unwrap();
    fs::write(&nkey, format!("{seed}\n")).unwrap();
    write_context(
      &root,
      "keyed",
      &format!(r#"{{"url":"tls://127.0.0.1:4222","nkey":"{}"}}"#, nkey.display()),
    );
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let real = rule.real.unwrap().expose_secret().to_string();
    assert!(real.contains(&seed));
    let guest = String::from_utf8(decoy_bytes(&found, "nk").to_vec()).unwrap();
    assert!(!guest.contains(&seed));
    NatsSeed::from_seed(SecretString::from(guest.trim().to_string())).expect("decoy seed");
    fs::write(&nkey, "# operator key\n").unwrap();
    let found = adapt(&root, "/home/eng", home.path()).expect("directory stays").expect("tree");
    assert!(found.grants.is_empty(), "{:?}", found.skipped);
    assert!(found.skipped.iter().any(|skip| matches!(
      skip,
      NatsSkip { name, cause: NatsSkipCause::Credential { .. } } if name == "keyed"
    )));

    write_context(&root, "tok", r#"{"url":"","token":"real-token","tls_first":true}"#);
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let real = rule.real.unwrap();
    assert!(real.expose_secret().contains("real-token"));
    assert!(real.expose_secret().contains("localhost"));
    assert!(!context_json(&found, "tok").contains("real-token"));
    assert!(found.skipped.iter().any(|skip| skip.name == "keyed"));

    write_context(&root, "bad", r#"{"url":"nats://a:4222,nats://b:4222","token":"real-token"}"#);
    let found = adapted(&root, home.path());
    assert_eq!(rules_of(&found).len(), 3, "tok plus both servers in bad");
    let bad = context_json(&found, "bad");
    assert!(bad.contains("nats://a:4222,nats://b:4222"), "{bad}");
    assert!(!bad.contains("real-token"), "{bad}");

    write_context(
      &root,
      "nsc",
      r#"{"url":"nats://nats.internal:4222","nsc":"nsc://operator/account/user"}"#,
    );
    let found = adapt(&root, "/home/eng", home.path()).expect("directory stays").expect("tree");
    assert!(found.skipped.iter().any(|skip| matches!(
      skip,
      NatsSkip { name, cause: NatsSkipCause::Credential { .. } } if name == "nsc"
    )));
    assert!(found.grants.iter().any(|grant| grant.fragment.contains("/context/tok.json")));
  }

  /// A creds path, wherever it points, mounts under `decoy/` and the real seed stays in the TLS grant.
  #[test]
  fn creds_file_mounts_under_the_decoy_dir() {
    for kind in ["relative", "traversal", "symlink", "outside"] {
      let home = tempdir().unwrap();
      let root = home.path().join(".config").join("nats");
      let seed = user_seed();
      let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public.clone();
      let jwt = user_jwt(&public);
      let creds_ref = match kind {
        "relative" => {
          let creds = root.join("creds");
          fs::create_dir_all(&creds).unwrap();
          fs::write(creds.join("user.creds"), decorate_creds(&jwt, &seed)).unwrap();
          "creds/user.creds".to_string()
        }
        "traversal" => {
          let ssh = home.path().join(".ssh");
          fs::create_dir_all(&ssh).unwrap();
          fs::write(ssh.join("config"), decorate_creds(&jwt, &seed)).unwrap();
          "../../.ssh/config".to_string()
        }
        "symlink" => {
          let outside = home.path().join("outside.creds");
          fs::write(&outside, decorate_creds(&jwt, &seed)).unwrap();
          let creds = root.join("creds");
          fs::create_dir_all(&creds).unwrap();
          std::os::unix::fs::symlink(&outside, creds.join("link.creds")).unwrap();
          "creds/link.creds".to_string()
        }
        "outside" => {
          let outside = tempdir().unwrap();
          let creds = outside.path().join("user.creds");
          fs::write(&creds, decorate_creds(&jwt, &seed)).unwrap();
          // Keep the temp dir alive until adapt returns.
          let found = creds_case(&root, home.path(), &creds.display().to_string(), &seed, &jwt);
          assert!(
            found.iter().all(|path| !path.contains(outside.path().to_string_lossy().as_ref())),
            "{kind} {found:?}"
          );
          continue;
        }
        _ => panic!("{kind}"),
      };
      let _containers = creds_case(&root, home.path(), &creds_ref, &seed, &jwt);
    }
  }

  fn creds_case(root: &Path, home: &Path, creds_ref: &str, seed: &str, jwt: &str) -> Vec<String> {
    write_context(
      root,
      "demo",
      &format!(r#"{{"url":"tls://nats.internal:4222","creds":"{creds_ref}"}}"#),
    );
    let found = adapted(root, home);
    let mut containers: Vec<String> = found
      .files
      .iter()
      .filter(|(path, _)| path.starts_with("decoy/"))
      .map(|(path, _)| path.clone())
      .collect();
    assert!(containers.iter().all(|path| !path.contains("..")), "{containers:?}");
    assert!(containers.iter().any(|path| path.starts_with("decoy/")), "{containers:?}");
    let creds = context_json(&found, "demo");
    let creds_path = serde_json::from_str::<Value>(&creds).unwrap()["creds"]
      .as_str()
      .unwrap()
      .to_string();
    assert!(creds_path.starts_with("~/.config/nats/decoy/"), "{creds_path}");
    assert!(!creds_path.contains(".."), "{creds_path}");
    containers.push(creds_path);
    let guest_text = String::from_utf8(decoy_bytes(&found, "creds").to_vec()).unwrap();
    assert!(!guest_text.contains(seed));
    assert!(!guest_text.contains(jwt));
    let real = rule_of(&found).real.unwrap().expose_secret().to_string();
    assert!(real.contains(seed), "{real}");
    assert!(real.contains(jwt), "{real}");
    containers
  }

  #[test]
  fn decoy_keeps_listed_fields_and_drops_the_rest() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(
      &root,
      "demo",
      r#"{"url":"nats://nats.internal:4222","user":"agent","password":"real-token","description":"kept","name":"demo","operator_note":"kept-too","windows_cert_match":"subject","user_jwt":"eyJhbGci.e30.sig"}"#, // betterleaks:allow
    );
    let found = adapted(&root, home.path());
    let text = String::from_utf8(file(&found, "context/demo.json").to_vec()).unwrap();
    let decoy: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(decoy["description"], "kept");
    assert!(decoy.get("name").is_none(), "{decoy}");
    assert!(decoy.get("operator_note").is_none(), "{decoy}");
    assert!(decoy.get("windows_cert_match").is_none());
    assert!(decoy.get("user_jwt").is_none());
    assert!(!text.contains("real-token"));
    assert_ne!(decoy["password"], "real-token");
    assert_eq!(found.grants.len(), 1, "{:?}", found.skipped);
    let real = rule_of(&found).real.expect("grant").expose_secret().to_string();
    assert!(real.starts_with("nats://"), "{real}");
    assert!(real.contains("real-token"), "{real}");
  }

  #[test]
  fn short_banner_creds_file_still_grants() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public.clone();
    let jwt = user_jwt(&public);
    let creds = root.join("user.creds");
    fs::create_dir_all(&root).unwrap();
    let body = format!(
      "---BEGIN NATS USER JWT---\n{jwt}\n---END NATS USER JWT---\n\n---BEGIN USER NKEY SEED---\n{seed}\n---END USER NKEY SEED---\n"
    );
    fs::write(&creds, body).unwrap();
    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"tls://nats.internal:4222","creds":"{}"}}"#, creds.display()),
    );
    let found = adapted(&root, home.path());
    let real = rule_of(&found).real.unwrap().expose_secret().to_string();
    assert!(real.contains(&seed));
    assert!(real.contains(&jwt));
  }

  #[test]
  fn user_with_empty_password_is_userinfo() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(&root, "demo", r#"{"url":"tls://nats.internal:4222","user":"agent","password":""}"#);
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let scope = NatsScope::from_strings(rule.value.unwrap().expose_secret(), rule.real.unwrap().expose_secret()).expect("userinfo");
    assert_eq!(
      scope
        .auth
        .fields()
        .iter()
        .map(|field| (<&str>::from(field.name), field.pair.fake.as_str(), field.pair.real.expose_secret()))
        .collect::<Vec<_>>(),
      vec![("user", "agent", "agent"), ("pass", "", "")]
    );
  }

  #[test]
  fn password_and_token_keep_surrounding_whitespace() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let password = "  spaced  "; // betterleaks:allow
    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"tls://nats.internal:4222","user":"agent","password":"{password}"}}"#),
    );
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let scope = NatsScope::from_strings(rule.value.unwrap().expose_secret(), rule.real.unwrap().expose_secret()).expect("spaced password");
    let pass = scope
      .auth
      .fields()
      .into_iter()
      .find(|field| <&str>::from(field.name) == "pass")
      .expect("pass");
    assert_eq!(pass.pair.real.expose_secret(), password);
    assert!(!context_json(&found, "demo").contains(password));

    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"tls://nats.internal:4222","token":"{password}"}}"#),
    );
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let scope = NatsScope::from_strings(rule.value.unwrap().expose_secret(), rule.real.unwrap().expose_secret()).expect("spaced token");
    let token = scope.auth.fields().into_iter().next().expect("token");
    assert_eq!(token.pair.real.expose_secret(), password);
  }

  #[test]
  fn user_named_nkey_or_creds_with_a_password_is_userinfo() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    for (user, password) in [("nkey", "ordinary-pass"), ("creds", "ordinary-pass")] {
      write_context(
        &root,
        "demo",
        &format!(r#"{{"url":"tls://nats.internal:4222","user":"{user}","password":"{password}"}}"#),
      );
      let found = adapted(&root, home.path());
      let rule = rule_of(&found);
      let scope = NatsScope::from_strings(rule.value.unwrap().expose_secret(), rule.real.unwrap().expose_secret())
        .unwrap_or_else(|err| panic!("{user}: {err}"));
      assert!(scope.auth.signer().is_none(), "{user}");
      let pairs: Vec<_> = scope
        .auth
        .fields()
        .iter()
        .map(|field| {
          (
            <&str>::from(field.name),
            field.pair.fake.clone(),
            field.pair.real.expose_secret().to_string(),
          )
        })
        .collect();
      assert_eq!(pairs[0].0, "user", "{user}");
      assert_eq!(pairs[0].1, user, "{user}");
      assert_eq!(pairs[0].2, user, "{user}");
      assert_eq!(pairs[1].0, "pass", "{user}");
      assert_eq!(pairs[1].2, password, "{user}");
      assert_ne!(pairs[1].1, password, "{user}");
    }
  }

  #[test]
  fn inline_user_jwt_and_user_seed_grant_and_the_guest_file_hides_them() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public.clone();
    let jwt = user_jwt(&public);
    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"tls://nats.internal:4222","user_jwt":"{jwt}","user_seed":"{seed}"}}"#),
    );
    let found = adapted(&root, home.path());
    let real = rule_of(&found).real.unwrap().expose_secret().to_string();
    assert!(real.contains(&seed));
    assert!(real.contains(&jwt));
    let guest_text = String::from_utf8(decoy_bytes(&found, "creds").to_vec()).unwrap();
    assert!(guest_text.contains(JWT_BEGIN));
    assert!(!guest_text.contains(&seed));
    assert!(!guest_text.contains(&jwt));
    let text = context_json(&found, "demo");
    assert!(!text.contains(&seed));
    assert!(!text.contains(&jwt));
    let scope = NatsScope::from_strings(rule_of(&found).value.unwrap().expose_secret(), &real).expect("inline user jwt");
    assert!(scope.auth.signer().is_some());
  }

  #[test]
  fn bare_jwt_or_seed_line_is_not_a_creds_file() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public;
    let jwt = user_jwt(&public);
    let creds = root.join("user.creds");
    fs::create_dir_all(&root).unwrap();
    fs::write(&creds, format!("{jwt}\n")).unwrap();
    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"tls://nats.internal:4222","creds":"{}"}}"#, creds.display()),
    );
    let found = adapt(&root, "/home/eng", home.path()).expect("directory stays").expect("tree");
    assert!(found.grants.is_empty());
    assert!(
      found
        .skipped
        .iter()
        .any(|skip| matches!(skip.cause, NatsSkipCause::Credential { .. }))
    );
    fs::write(&creds, format!("{jwt}\n{seed}\n")).unwrap();
    let found = adapt(&root, "/home/eng", home.path()).expect("directory stays").expect("tree");
    assert!(found.grants.is_empty());
    assert!(
      found
        .skipped
        .iter()
        .any(|skip| matches!(skip.cause, NatsSkipCause::Credential { .. }))
    );
  }

  /// A decorated nkey file is the seed on the host. The guest file stays a decoy.
  #[test]
  fn decorated_nkey_file_grants() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let nkey = root.join("user.nk");
    fs::create_dir_all(&root).unwrap();
    fs::write(&nkey, format!("{SEED_BEGIN}\n{seed}\n{SEED_END}\n")).unwrap();
    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"tls://nats.internal:4222","nkey":"{}"}}"#, nkey.display()),
    );
    let found = adapted(&root, home.path());
    let real = rule_of(&found).real.expect("decorated nkey").expose_secret().to_string();
    assert!(real.contains(&seed), "{real}");
    let guest = String::from_utf8(decoy_bytes(&found, "nk").to_vec()).unwrap();
    assert!(!guest.contains(&seed), "{guest}");
    assert!(found.skipped.is_empty(), "{:?}", found.skipped);
  }

  #[test]
  fn inline_nkey_text_is_not_a_path() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    write_context(&root, "demo", &format!(r#"{{"url":"nats://nats.internal:4222","nkey":"{seed}"}}"#));
    let found = adapt(&root, "/home/eng", home.path()).expect("directory stays").expect("tree");
    assert!(found.grants.is_empty());
    assert!(
      found
        .skipped
        .iter()
        .any(|skip| matches!(skip.cause, NatsSkipCause::Credential { .. }))
    );
    assert_eq!(file(&found, "context.txt"), b"demo\n");
  }

  /// Password, nkey, and creds contexts on one server each become a grant.
  /// The guest tree keeps the selected name and carries no real secret.
  #[test]
  fn every_context_file_gets_its_own_grant_and_decoy() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let nkey_seed = user_seed();
    let creds_seed = user_seed();
    let creds_public = NatsSeed::from_seed(SecretString::from(creds_seed.clone())).unwrap().public;
    let creds_jwt = user_jwt(&creds_public);
    let nkey_path = home.path().join("operator.nk");
    let creds_path = home.path().join("user.creds");
    fs::write(&nkey_path, format!("{nkey_seed}\n")).unwrap();
    fs::write(&creds_path, decorate_creds(&creds_jwt, &creds_seed)).unwrap();
    write_context(
      &root,
      "pass",
      r#"{"url":"tls://nats.internal:4222","user":"agent","password":"real-nats-pass","jetstream_domain":"app"}"#, // betterleaks:allow
    );
    let nkey_body = serde_json::json!({
      "url": "tls://nats.internal:4222",
      "nkey": nkey_path,
    });
    let creds_body = serde_json::json!({
      "url": "tls://nats.internal:4222",
      "creds": creds_path,
    });
    fs::write(root.join("context").join("nkey.json"), serde_json::to_string(&nkey_body).unwrap()).unwrap();
    fs::write(root.join("context").join("creds.json"), serde_json::to_string(&creds_body).unwrap()).unwrap();

    let found = adapt(&root, "/home/eng", home.path()).expect("adapt").expect("contexts map");
    let rules = rules_of(&found);
    assert_eq!(rules.len(), 3, "one grant per context file");
    let labels: Vec<&str> = rules.iter().map(|(label, _)| label.as_str()).collect();
    assert!(labels.iter().all(|label| context_identity_label(label)), "{labels:?}");
    assert_eq!(labels.iter().collect::<std::collections::BTreeSet<_>>().len(), 3, "{labels:?}");

    let fakes: Vec<String> = rules
      .iter()
      .map(|(_, rule)| rule.value.as_ref().unwrap().expose_secret().to_string())
      .collect();
    let reals: Vec<String> = rules
      .iter()
      .map(|(_, rule)| rule.real.as_ref().expect("stated real").expose_secret().to_string())
      .collect();
    assert_eq!(fakes.iter().collect::<std::collections::BTreeSet<_>>().len(), 3, "{fakes:?}");
    assert!(reals.iter().any(|real| real.contains("real-nats-pass")), "{reals:?}");
    assert!(reals.iter().any(|real| real.contains(&nkey_seed)), "{reals:?}");
    assert!(
      reals.iter().any(|real| real.contains(&creds_seed) && real.contains(&creds_jwt)),
      "{reals:?}"
    );
    for fake in &fakes {
      assert!(!fake.contains("real-nats-pass"), "{fake}");
      assert!(!fake.contains(&nkey_seed), "{fake}");
      assert!(!fake.contains(&creds_seed), "{fake}");
      assert!(!fake.contains(&creds_jwt), "{fake}");
    }

    let guest = guest_tree(&found);
    let paths: Vec<&str> = guest.iter().map(|(path, _)| path.as_str()).collect();
    for expected in [
      "/home/eng/.config/nats/context.txt",
      "/home/eng/.config/nats/context/pass.json",
      "/home/eng/.config/nats/context/nkey.json",
      "/home/eng/.config/nats/context/creds.json",
    ] {
      assert!(paths.contains(&expected), "{expected} missing from {paths:?}");
    }
    let selected = guest.iter().find(|(path, _)| path.ends_with("context.txt")).expect("context.txt");
    assert_eq!(selected.1, "pass\n");
    assert_eq!(file(&found, "context.txt"), b"pass\n");
    assert_eq!(found.grants.len(), 3);
    assert!(
      found
        .grants
        .iter()
        .all(|grant| grant.decoy.is_empty() && grant.decoy_files.is_empty())
    );
    for (_, text) in &guest {
      assert!(!text.contains("real-nats-pass"), "{text}");
      assert!(!text.contains(&nkey_seed), "{text}");
      assert!(!text.contains(&creds_seed), "{text}");
      assert!(!text.contains(&creds_jwt), "{text}");
    }
    assert!(
      guest
        .iter()
        .any(|(path, text)| path.contains("/.config/nats/decoy/") && extension_is(path, "nk") && !text.contains(&nkey_seed))
    );
    assert!(guest.iter().any(|(path, text)| path.contains("/.config/nats/decoy/")
      && extension_is(path, "creds")
      && text.contains(JWT_BEGIN)
      && !text.contains(&creds_jwt)));
  }

  /// A seed outside the nkey or creds field fails closed for every context.
  #[test]
  fn misplaced_seed_in_any_context_is_the_same_error() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let body = serde_json::json!({
      "url": "nats://nats.internal:4222",
      "user": "agent",
      "password": seed,
    });
    write_context(&root, "bad", &serde_json::to_string(&body).unwrap());
    match adapt(&root, "/home/eng", home.path()) {
      Err(err) => assert_misplaced_seed(err),
      Ok(_) => panic!("selected seed was accepted"),
    }

    write_context(
      &root,
      "demo",
      r#"{"url":"nats://nats.internal:4222","user":"agent","password":"real-nats-pass"}"#, // betterleaks:allow
    );
    fs::write(root.join("context").join("other.json"), serde_json::to_string(&body).unwrap()).unwrap();
    match adapt(&root, "/home/eng", home.path()) {
      Err(err) => assert_misplaced_seed(err),
      Ok(_) => panic!("non-selected seed was accepted"),
    }
  }

  fn context_identity_label(label: &str) -> bool {
    let Some(hex) = label.strip_prefix("nats-") else {
      return false;
    };
    hex.len() == 32 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
  }

  /// Two contexts can name one creds file, and two can name one client cert, on one server.
  /// The creds decoys stay on distinct guest paths. The loader accepts the shared dial.
  #[test]
  fn shared_creds_and_client_cert_load_on_one_server() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public;
    let jwt = user_jwt(&public);
    let creds = home.path().join("shared.creds");
    fs::write(&creds, decorate_creds(&jwt, &seed)).unwrap();
    let tls = root.join("tls");
    fs::create_dir_all(&tls).unwrap();
    fs::write(tls.join("client.crt"), b"cert-bytes").unwrap();
    fs::write(tls.join("client.key"), b"key-bytes").unwrap();
    fs::write(tls.join("ca.crt"), b"ca-bytes").unwrap();
    fs::create_dir_all(root.join("context")).unwrap();
    fs::write(root.join("context.txt"), "creds-a\n").unwrap();
    for name in ["creds-a", "creds-b"] {
      let body = serde_json::json!({
        "url": "tls://nats.internal:4222",
        "creds": creds,
        "cert": tls.join("client.crt"),
        "key": tls.join("client.key"),
        "ca": tls.join("ca.crt"),
      });
      fs::write(root.join("context").join(format!("{name}.json")), body.to_string()).unwrap();
    }
    for name in ["cert-a", "cert-b"] {
      let body = serde_json::json!({
        "url": "tls://nats.internal:4222",
        "user": name,
        "password": format!("pw-{name}"), // betterleaks:allow
        "cert": tls.join("client.crt"),
        "key": tls.join("client.key"),
        "ca": tls.join("ca.crt"),
      });
      fs::write(root.join("context").join(format!("{name}.json")), body.to_string()).unwrap();
    }
    let found = adapted(&root, home.path());
    assert_eq!(found.grants.len(), 4);
    let cred_paths: Vec<&str> = found
      .files
      .iter()
      .map(|(path, _)| path.as_str())
      .filter(|path| path.starts_with("decoy/") && extension_is(path, "creds"))
      .collect();
    assert_eq!(cred_paths.len(), 2, "{cred_paths:?}");
    assert_ne!(cred_paths[0], cred_paths[1]);
    let sslcerts: Vec<String> = rules_of(&found)
      .into_iter()
      .map(|(_, rule)| {
        let real = rule.real.expect("real").expose_secret().to_string();
        real
          .split("sslcert=")
          .nth(1)
          .unwrap_or("")
          .split('&')
          .next()
          .unwrap_or("")
          .to_string()
      })
      .collect();
    assert!(sslcerts.iter().all(|path| !path.is_empty() && path == &sslcerts[0]), "{sslcerts:?}");
    load_grants(&found).expect("one dial loads");
  }

  /// Different client certs on the selected server fail before grant load and name both contexts.
  #[test]
  fn selected_tls_clash_names_both_contexts() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let tls = root.join("tls");
    fs::create_dir_all(tls.join("a")).unwrap();
    fs::create_dir_all(tls.join("b")).unwrap();
    fs::write(tls.join("a").join("client.crt"), b"cert-a").unwrap();
    fs::write(tls.join("a").join("client.key"), b"key-a").unwrap();
    fs::write(tls.join("b").join("client.crt"), b"cert-b").unwrap();
    fs::write(tls.join("b").join("client.key"), b"key-b").unwrap();
    fs::create_dir_all(root.join("context")).unwrap();
    fs::write(root.join("context.txt"), "alpha\n").unwrap();
    for (name, side) in [("alpha", "a"), ("beta", "b")] {
      let body = serde_json::json!({
        "url": "tls://nats.internal:4222",
        "token": format!("tok-{name}"),
        "cert": tls.join(side).join("client.crt"),
        "key": tls.join(side).join("client.key"),
      });
      fs::write(root.join("context").join(format!("{name}.json")), body.to_string()).unwrap();
    }
    let err = adapt(&root, "/home/eng", home.path()).expect_err("selected clash");
    let Error::NatsSelected { skip, .. } = err else {
      panic!("expected NatsSelected, got {err}");
    };
    let NatsSkip {
      name,
      cause: NatsSkipCause::Dial { other, host, port },
    } = skip
    else {
      panic!("expected Dial, got {skip}");
    };
    assert!(name == "alpha" || other == "alpha", "{name} {other}");
    assert!(name == "beta" || other == "beta", "{name} {other}");
    assert_eq!(host, "nats.internal");
    assert_eq!(port, 4222);
  }

  /// Dropping server 0 of a multi-server context still writes that context's CA and client cert.
  #[test]
  fn dropped_first_server_still_materializes_the_tls_blobs() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let tls = root.join("tls");
    fs::create_dir_all(&tls).unwrap();
    fs::write(tls.join("ca.crt"), b"ca-bytes").unwrap();
    fs::write(tls.join("client.crt"), b"cert-bytes").unwrap();
    fs::write(tls.join("client.key"), b"key-bytes").unwrap();
    fs::create_dir_all(root.join("context")).unwrap();
    fs::write(
      root.join("context").join("aaa.json"),
      r#"{"url":"nats://a:4222","token":"aaa-token"}"#,
    )
    .unwrap();
    let body = serde_json::json!({
      "url": "tls://a:4222,tls://b:4222",
      "token": "multi-token",
      "ca": tls.join("ca.crt"),
      "cert": tls.join("client.crt"),
      "key": tls.join("client.key"),
    });
    fs::write(root.join("context").join("multi.json"), body.to_string()).unwrap();
    let found = adapt(&root, "/home/eng", home.path()).expect("adapt").expect("contexts");
    let survivors: Vec<_> = found
      .grants
      .iter()
      .filter(|grant| grant.fragment.contains("/context/multi.json"))
      .collect();
    assert_eq!(survivors.len(), 1, "{:?}", found.skipped);
    let survivor = survivors[0];
    assert!(survivor.fragment.contains("b:4222"), "{}", survivor.fragment);
    assert!(survivor.fragment.contains("sslrootcert="), "{}", survivor.fragment);
    assert!(survivor.fragment.contains("sslcert="), "{}", survivor.fragment);
    assert!(survivor.fragment.contains("sslkey="), "{}", survivor.fragment);
    let blobs: Vec<&[u8]> = survivor.materialized.iter().map(|(_, bytes)| bytes.as_slice()).collect();
    assert!(blobs.contains(&&b"ca-bytes"[..]), "{blobs:?}");
    assert!(blobs.contains(&&b"cert-bytes"[..]), "{blobs:?}");
    assert!(blobs.contains(&&b"key-bytes"[..]), "{blobs:?}");
    assert!(found.skipped.iter().any(|skip| matches!(
      skip,
      NatsSkip { name, cause: NatsSkipCause::Dial { host, port, .. } }
        if name == "multi" && host == "a" && *port == 4222
    )));
    let guest = context_json(&found, "multi");
    assert!(guest.contains("tls://a:4222,tls://b:4222"), "{guest}");
    assert!(!guest.contains("multi-token"), "{guest}");
  }

  /// A clash that does not include the selected context skips the other dial.
  #[test]
  fn unselected_tls_clash_skips_the_other_context() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let tls = root.join("tls");
    fs::create_dir_all(tls.join("a")).unwrap();
    fs::create_dir_all(tls.join("b")).unwrap();
    fs::write(tls.join("a").join("client.crt"), b"cert-a").unwrap();
    fs::write(tls.join("a").join("client.key"), b"key-a").unwrap();
    fs::write(tls.join("b").join("client.crt"), b"cert-b").unwrap();
    fs::write(tls.join("b").join("client.key"), b"key-b").unwrap();
    fs::create_dir_all(root.join("context")).unwrap();
    fs::write(root.join("context.txt"), "kept\n").unwrap();
    fs::write(
      root.join("context").join("kept.json"),
      r#"{"url":"tls://other.internal:4222","token":"kept-token"}"#,
    )
    .unwrap();
    for (name, side) in [("alpha", "a"), ("beta", "b")] {
      let body = serde_json::json!({
        "url": "tls://nats.internal:4222",
        "token": format!("tok-{name}"),
        "cert": tls.join(side).join("client.crt"),
        "key": tls.join(side).join("client.key"),
      });
      fs::write(root.join("context").join(format!("{name}.json")), body.to_string()).unwrap();
    }
    let found = adapted(&root, home.path());
    assert!(found.grants.iter().any(|grant| grant.fragment.contains("/context/kept.json")));
    assert_eq!(
      found
        .grants
        .iter()
        .filter(|grant| grant.fragment.contains("/context/alpha.json") || grant.fragment.contains("/context/beta.json"))
        .count(),
      1
    );
    assert!(found.skipped.iter().any(|skip| matches!(
      skip,
      NatsSkip { name, cause: NatsSkipCause::Dial { other, host, port } }
        if ((name == "alpha" && other == "beta") || (name == "beta" && other == "alpha"))
          && host == "nats.internal"
          && *port == 4222
    )));
  }

  /// The same context mints the same nkey decoy on the next adapt.
  #[test]
  fn nkey_decoy_is_stable_across_adapts() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let nkey = root.join("operator.nk");
    fs::create_dir_all(&root).unwrap();
    fs::write(&nkey, format!("{}\n", user_seed())).unwrap();
    write_context(
      &root,
      "keyed",
      &format!(r#"{{"url":"tls://127.0.0.1:4222","nkey":"{}"}}"#, nkey.display()),
    );
    let first = adapted(&root, home.path());
    let second = adapted(&root, home.path());
    assert_eq!(decoy_bytes(&first, "nk"), decoy_bytes(&second, "nk"));
  }

  fn load_grants(found: &AdaptedNats) -> Result<arkham_config::grants::ResolvedConfig, Box<arkham_config::Error>> {
    use arkham_config::config::{AppConfig, ProxyCfg, WorkspaceCfg};
    use arkham_config::grants::resolve;

    let cfg = AppConfig {
      proxy: ProxyCfg {
        listen: "127.0.0.1:8080".parse().expect("listen"),
        ca_file: None,
        root_certs: Vec::new(),
        handshake_timeout_secs: 10,
        ssh_host_key: None,
        ssh_known_hosts: None,
      },
      workspace: WorkspaceCfg::default(),
      rules: rules_of(found).into_iter().collect(),
      plugins: BTreeMap::new(),
      tools: BTreeMap::new(),
    };
    resolve(&cfg).map_err(Box::new)
  }

  fn rules_of(found: &AdaptedNats) -> Vec<(String, RuleCfg)> {
    let mut rules = Vec::new();
    for grant in &found.grants {
      let doc: RulesDoc = toml::from_str(&grant.fragment).expect("fragment");
      rules.extend(doc.rules);
    }
    rules
  }

  fn guest_tree(found: &AdaptedNats) -> Vec<(String, String)> {
    found
      .files
      .iter()
      .map(|(rel, bytes)| {
        (
          format!("{}/{rel}", found.container),
          String::from_utf8(bytes.clone()).expect("guest file is utf-8"),
        )
      })
      .collect()
  }

  /// `nats context select` renames inside the config directory. One writable
  /// directory mount is what that rename can replace.
  #[test]
  fn nats_tree_is_one_writable_directory() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(&root, "demo", r#"{"url":"tls://nats.internal:4222","token":"real-token"}"#);
    let found = adapted(&root, home.path());
    let files = tempdir().unwrap();
    let mut collector = RewriteCollector::new(files.path()).unwrap();
    found.install(&mut collector).unwrap();
    let outputs = collector.outputs();
    let nats: Vec<_> = outputs
      .mounts
      .iter()
      .filter(|mount| mount.container.starts_with("/home/eng/.config/nats"))
      .collect();
    assert_eq!(nats.len(), 1, "{:?}", nats.iter().map(|mount| &mount.container).collect::<Vec<_>>());
    assert!(!nats[0].ro);
    assert_eq!(nats[0].container, Path::new("/home/eng/.config/nats"));
    assert!(nats[0].host.is_dir());
    assert_eq!(fs::read_to_string(nats[0].host.join("context.txt")).unwrap(), "demo\n");
  }

  #[test]
  fn init_clears_stale_children_and_keeps_the_directory_inode() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(&root, "demo", r#"{"url":"tls://nats.internal:4222","token":"real-token"}"#);
    let files = tempdir().unwrap();
    let found = adapted(&root, home.path());
    let mut collector = RewriteCollector::new(files.path()).unwrap();
    found.install(&mut collector).unwrap();
    let host = collector.outputs().mounts.into_iter().next().expect("nats mount").host;
    let held = fs::File::open(&host).expect("open nats home");
    let inode = held.metadata().expect("nats home").ino();
    fs::write(host.join("previous-context.txt"), "gone\n").unwrap();
    fs::write(host.join("context").join("gone.json"), "{}\n").unwrap();
    fs::write(host.join("scratch.tmp"), "temp").unwrap();
    let found = adapted(&root, home.path());
    let mut collector = RewriteCollector::new(files.path()).unwrap();
    found.install(&mut collector).unwrap();
    let outputs = collector.outputs();
    let host = &outputs.mounts[0].host;
    assert_eq!(fs::metadata(host).expect("nats home").ino(), inode);
    assert!(!host.join("previous-context.txt").exists());
    assert!(!host.join("context").join("gone.json").exists());
    assert!(!host.join("scratch.tmp").exists());
    assert_eq!(fs::read_to_string(host.join("context.txt")).unwrap(), "demo\n");
    assert!(host.join("context").join("demo.json").is_file());
    assert!(outputs.grants.iter().any(|grant| grant.fragment.contains("/context/demo.json")));
    assert_eq!(held.metadata().expect("held nats home").ino(), inode);
  }

  #[test]
  fn old_nats_context_file_does_not_block_init() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(&root, "demo", r#"{"url":"tls://nats.internal:4222","token":"real-token"}"#);
    let files = tempdir().unwrap();
    let old = files.path().join("nats-context");
    fs::write(&old, "old-twin").unwrap();
    let found = adapted(&root, home.path());
    let mut collector = RewriteCollector::new(files.path()).unwrap();
    found.install(&mut collector).unwrap();
    let outputs = collector.outputs();
    let host = &outputs.mounts[0].host;
    assert!(host.is_dir());
    assert_eq!(host.file_name().and_then(|name| name.to_str()), Some(NATS_HOME_DIR));
    assert_eq!(fs::read_to_string(host.join("context.txt")).unwrap(), "demo\n");
    assert_eq!(fs::read_to_string(&old).unwrap(), "old-twin");
    assert!(outputs.grants.iter().any(|grant| grant.fragment.contains("/context/demo.json")));
  }

  /// A `nats://` URL with `tls_first` is an upstream TLS grant, and the rest of the directory still loads.
  #[test]
  fn cleartext_url_with_tls_first_still_grants() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(
      &root,
      "demo",
      r#"{"url":"nats://nats.internal:4222","user":"agent","password":"real-nats-pass","tls_first":true}"#, // betterleaks:allow
    );
    fs::write(
      root.join("context").join("other.json"),
      r#"{"url":"tls://other.internal:4222","token":"other-token"}"#,
    )
    .unwrap();
    let found = adapted(&root, home.path());
    assert_eq!(found.grants.len(), 2, "{:?}", found.skipped);
    let real = rule_of(&found).real.expect("stated real").expose_secret().to_string();
    assert!(real.starts_with("tls://"), "{real}");
    assert!(real.contains("handshake_first=true"), "{real}");
    assert!(real.contains("real-nats-pass"), "{real}");
  }

  #[test]
  fn two_cleartext_contexts_on_one_server_grant_and_hide_the_real_credential() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(
      &root,
      "demo",
      r#"{"url":"nats://nats.internal:4222","user":"agent","password":"real-nats-pass"}"#, // betterleaks:allow
    );
    fs::write(
      root.join("context").join("other.json"),
      r#"{"url":"nats://nats.internal:4222","token":"other-real-token"}"#,
    )
    .unwrap();
    let found = adapted(&root, home.path());
    assert_eq!(found.grants.len(), 2, "{:?}", found.skipped);
    let rendered = found.grants.iter().map(|grant| grant.fragment.clone()).collect::<String>();
    assert!(rendered.contains("real-nats-pass"), "{rendered}");
    assert!(rendered.contains("other-real-token"), "{rendered}");
    let guest = found
      .files
      .iter()
      .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
      .collect::<String>();
    assert!(!guest.contains("real-nats-pass"), "{guest}");
    assert!(!guest.contains("other-real-token"), "{guest}");
    let decoy = String::from_utf8(file(&found, "context/demo.json").to_vec()).unwrap();
    assert!(decoy.contains("password"), "{decoy}");
  }

  /// The same user and an empty password are the same credential. Both contexts load on one grant.
  #[test]
  fn two_cleartext_contexts_with_the_same_decoy_both_load() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(&root, "demo", r#"{"url":"nats://nats.internal:4222","user":"agent","password":""}"#);
    fs::write(
      root.join("context").join("other.json"),
      r#"{"url":"nats://nats.internal:4222","user":"agent","password":""}"#,
    )
    .unwrap();
    let found = adapted(&root, home.path());
    assert_eq!(found.grants.len(), 1, "{:?}", found.skipped);
    assert!(context_json(&found, "demo").contains("\"user\": \"agent\""));
    assert!(context_json(&found, "other").contains("\"user\": \"agent\""));
    let guest = found
      .files
      .iter()
      .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
      .collect::<String>();
    assert!(!guest.contains("real"), "{guest}");
  }

  /// A comma-separated list is one grant per server. An unselected context that
  /// does not map is a skip, and the selected grant still loads.
  #[test]
  fn unselected_reject_keeps_the_selected_grant() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(&root, "demo", r#"{"url":"tls://nats.internal:4222","token":"real-token"}"#);
    fs::write(
      root.join("context").join("bad.json"),
      r#"{"url":"nats://a:4222,nats://b:4222","token":"other-token"}"#,
    )
    .unwrap();
    let account = nkeys::KeyPair::new_account().seed().expect("account seed");
    fs::write(
      root.join("context").join("seeded.json"),
      serde_json::json!({
        "url": "tls://other.internal:4222",
        "user": "nkey",
        "password": account,
      })
      .to_string(),
    )
    .unwrap();
    let found = adapted(&root, home.path());
    assert_eq!(found.grants.len(), 3, "{:?}", found.skipped);
    assert!(found.grants.iter().any(|grant| grant.fragment.contains("/context/demo.json")));
    assert_eq!(
      found
        .grants
        .iter()
        .filter(|grant| grant.fragment.contains("/context/bad.json"))
        .count(),
      2
    );
    let bad = context_json(&found, "bad");
    assert!(bad.contains("nats://a:4222,nats://b:4222"), "{bad}");
    assert!(!bad.contains("other-token"), "{bad}");
    assert!(found.skipped.iter().any(|skip| matches!(
      skip,
      NatsSkip { name, cause: NatsSkipCause::Rejected } if name == "seeded"
    )));
  }

  /// The CLI accepts `prod.eu`. A name with `..` is a typed skip, not a silent drop.
  #[test]
  fn dotted_context_name_is_a_grant_and_traversal_is_a_skip() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(&root, "prod.eu", r#"{"url":"tls://nats.internal:4222","token":"real-token"}"#);
    fs::write(
      root.join("context").join("a..b.json"),
      r#"{"url":"tls://nats.internal:4222","token":"other-token"}"#,
    )
    .unwrap();
    let found = adapted(&root, home.path());
    assert!(
      found.grants.iter().any(|grant| grant.fragment.contains("/context/prod.eu.json")),
      "{:?}",
      found.grants.iter().map(|grant| grant.fragment.clone()).collect::<Vec<_>>()
    );
    assert!(
      found.skipped.iter().any(|skip| matches!(
        skip,
        NatsSkip { name, cause: NatsSkipCause::Name } if name == "a..b"
      )),
      "{:?}",
      found.skipped
    );
  }

  #[test]
  fn context_without_a_credential_is_copied_and_grants_nothing() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(&root, "local", r#"{"url":"nats://localhost:4222","description":"dev"}"#);
    fs::write(
      root.join("context").join("remote.json"),
      r#"{"url":"nats://nats.internal:4222","token":"real-token"}"#,
    )
    .unwrap();
    let found = adapted(&root, home.path());
    assert_eq!(found.grants.len(), 1, "{:?}", found.skipped);
    assert!(found.grants[0].fragment.contains("/context/remote.json"));
    let local = context_json(&found, "local");
    assert!(local.contains("nats://localhost:4222"), "{local}");
    assert!(local.contains("dev"), "{local}");
    assert!(!local.contains("password"), "{local}");
    assert!(!local.contains("token"), "{local}");
  }

  #[test]
  fn credential_in_the_server_url_is_the_grant() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(
      &root,
      "demo",
      r#"{"url":"nats://agent:real-nats-pass@nats.internal:4222"}"#, // betterleaks:allow
    );
    let found = adapted(&root, home.path());
    let real = rule_of(&found).real.expect("grant").expose_secret().to_string();
    assert!(real.contains("real-nats-pass"), "{real}");
    assert!(real.starts_with("nats://agent:"), "{real}");
    let decoy = context_json(&found, "demo");
    assert!(decoy.contains("\"user\": \"agent\""), "{decoy}");
    assert!(!decoy.contains("real-nats-pass"), "{decoy}");
    assert!(decoy.contains("nats://nats.internal:4222"), "{decoy}");
    assert!(!decoy.contains('@'), "{decoy}");
  }

  #[test]
  fn user_and_token_are_one_grant() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(
      &root,
      "demo",
      r#"{"url":"tls://nats.internal:4222","user":"agent","password":"real-nats-pass","token":"real-token"}"#, // betterleaks:allow
    );
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let scope = NatsScope::from_strings(rule.value.unwrap().expose_secret(), rule.real.unwrap().expose_secret()).expect("user token");
    let pairs: Vec<_> = scope
      .auth
      .fields()
      .iter()
      .map(|field| (<&str>::from(field.name), field.pair.real.expose_secret().to_string()))
      .collect();
    assert_eq!(pairs.len(), 3, "{pairs:?}");
    assert!(pairs.iter().any(|pair| pair.0 == "user" && pair.1 == "agent"));
    assert!(pairs.iter().any(|pair| pair.0 == "pass" && pair.1 == "real-nats-pass"));
    assert!(pairs.iter().any(|pair| pair.0 == "auth_token" && pair.1 == "real-token"));
    let decoy = context_json(&found, "demo");
    assert!(!decoy.contains("real-nats-pass"), "{decoy}");
    assert!(!decoy.contains("real-token"), "{decoy}");
    assert!(decoy.contains("\"token\""), "{decoy}");
  }

  #[test]
  fn jwt_without_a_seed_grants_and_does_not_sign() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed)).unwrap().public;
    let jwt = user_jwt(&public);
    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"nats://nats.internal:4222","user_jwt":"{jwt}"}}"#),
    );
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let real = rule.real.unwrap().expose_secret().to_string();
    let fake = rule.value.unwrap().expose_secret().to_string();
    let scope = NatsScope::from_strings(&fake, &real).expect("bearer jwt");
    assert!(scope.auth.signer().is_none());
    assert_eq!(scope.auth.fields().len(), 1);
    assert!(real.contains(&jwt), "{real}");
    let decoy = context_json(&found, "demo");
    assert!(!decoy.contains(&jwt), "{decoy}");
    assert!(decoy.contains("user_jwt"), "{decoy}");
    assert!(!decoy.contains("user_seed"), "{decoy}");
  }

  #[test]
  fn env_and_data_literals_resolve_on_the_host() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let saved = std::env::var_os("ARKHAM_NATS_TEST_PASS");
    crate::test_support::set_env("ARKHAM_NATS_TEST_PASS", "env-nats-pass"); // betterleaks:allow
    write_context(
      &root,
      "demo",
      r#"{"url":"nats://nats.internal:4222","user":"agent","password":"env://ARKHAM_NATS_TEST_PASS"}"#, // betterleaks:allow
    );
    let found = adapted(&root, home.path());
    let real = rule_of(&found).real.expect("env grant").expose_secret().to_string();
    assert!(real.contains("env-nats-pass"), "{real}");
    assert!(!real.contains("env://"), "{real}");
    assert!(!context_json(&found, "demo").contains("env-nats-pass"));
    assert!(!context_json(&found, "demo").contains("ARKHAM_NATS_TEST_PASS"));
    match saved {
      Some(value) => crate::test_support::set_env("ARKHAM_NATS_TEST_PASS", value),
      None => crate::test_support::unset_env("ARKHAM_NATS_TEST_PASS"),
    }

    let encoded = base64::engine::general_purpose::STANDARD.encode(b"data-nats-pass"); // betterleaks:allow
    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"nats://nats.internal:4222","user":"agent","password":"data:;base64,{encoded}"}}"#), // betterleaks:allow
    );
    let found = adapted(&root, home.path());
    let real = rule_of(&found).real.expect("data grant").expose_secret().to_string();
    assert!(real.contains("data-nats-pass"), "{real}");
    assert!(!context_json(&found, "demo").contains("data-nats-pass"));
    assert!(!context_json(&found, "demo").contains("data:"));
  }

  struct RestorePath(Option<std::ffi::OsString>);

  impl Drop for RestorePath {
    fn drop(&mut self) {
      match self.0.take() {
        Some(value) => crate::test_support::set_env("PATH", value),
        None => crate::test_support::unset_env("PATH"),
      }
    }
  }

  #[test]
  fn op_and_nsc_commands_resolve_on_the_host() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let bin = home.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public;
    let creds = home.path().join("user.creds");
    fs::write(&creds, decorate_creds(&user_jwt(&public), &seed)).unwrap();
    let op = bin.join("op");
    fs::write(
      &op,
      "#!/bin/sh\nif [ \"$1\" = read ] && [ \"$2\" = op://vault/item/password ]; then printf '%s\\n' 'op-nats-pass'; exit 0; fi\nexit 1\n", // betterleaks:allow
    )
    .unwrap();
    let nsc = bin.join("nsc");
    fs::write(
      &nsc,
      format!(
        "#!/bin/sh\nif [ \"$1\" = generate ] && [ \"$2\" = profile ] && [ \"$3\" = nsc://op/acct/user ]; then printf '%s' '{{\"user_creds\":\"{}\",\"operator\":{{\"service\":[\"nats://nsc.example:4222\"]}}}}'; exit 0; fi\nexit 1\n",
        creds.display()
      ),
    )
    .unwrap();
    for path in [&op, &nsc] {
      let mut mode = fs::metadata(path).unwrap().permissions();
      mode.set_mode(0o755);
      fs::set_permissions(path, mode).unwrap();
    }
    let saved = std::env::var_os("PATH");
    let mut path = bin.into_os_string();
    path.push(":");
    if let Some(rest) = &saved {
      path.push(rest);
    }
    crate::test_support::set_env("PATH", &path);
    let _path = RestorePath(saved);
    fs::create_dir_all(root.join("context")).unwrap();
    fs::write(root.join("context.txt"), "opened\n").unwrap();
    fs::write(
      root.join("context").join("opened.json"),
      r#"{"url":"nats://op.example:4222","user":"agent","password":"op://vault/item/password"}"#, // betterleaks:allow
    )
    .unwrap();
    fs::write(root.join("context").join("profile.json"), r#"{"nsc":"nsc://op/acct/user"}"#).unwrap();
    let found = adapt(&root, "/home/eng", home.path()).expect("adapt").expect("contexts");
    let rendered = found.grants.iter().map(|grant| grant.fragment.clone()).collect::<String>();
    assert!(rendered.contains("op-nats-pass"), "{rendered}"); // betterleaks:allow
    assert!(rendered.contains(&seed), "{rendered}");
    assert!(!rendered.contains("op://"), "{rendered}");
    for (_, bytes) in &found.files {
      let text = String::from_utf8_lossy(bytes);
      assert!(!text.contains("op-nats-pass"), "{text}"); // betterleaks:allow
      assert!(!text.contains(&seed), "{text}");
    }
  }

  /// `$BASE` expands once. A `$` in the expanded directory is part of the path.
  #[test]
  fn creds_path_with_a_dollar_in_the_directory_expands_once() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public;
    let dir = home.path().join("dir$name");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("user.creds"), decorate_creds(&user_jwt(&public), &seed)).unwrap();
    let saved_base = std::env::var_os("ARKHAM_NATS_CREDS_BASE");
    let saved_name = std::env::var_os("name");
    crate::test_support::set_env("ARKHAM_NATS_CREDS_BASE", &dir);
    crate::test_support::set_env("name", "EXPANDED");
    write_context(
      &root,
      "demo",
      r#"{"url":"tls://nats.internal:4222","creds":"$ARKHAM_NATS_CREDS_BASE/user.creds"}"#,
    );
    let found = adapted(&root, home.path());
    let real = rule_of(&found).real.expect("one expansion").expose_secret().to_string();
    assert!(real.contains(&seed), "{real}");
    assert!(!context_json(&found, "demo").contains(&seed));
    match saved_base {
      Some(value) => crate::test_support::set_env("ARKHAM_NATS_CREDS_BASE", value),
      None => crate::test_support::unset_env("ARKHAM_NATS_CREDS_BASE"),
    }
    match saved_name {
      Some(value) => crate::test_support::set_env("name", value),
      None => crate::test_support::unset_env("name"),
    }
  }

  /// `op` and `nsc` failures keep the tool's stderr on the skip.
  #[test]
  fn command_stderr_is_part_of_the_credential_skip() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let bin = home.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let op = bin.join("op");
    fs::write(&op, "#!/bin/sh\necho 'op: item missing' >&2\nexit 1\n").unwrap();
    let nsc = bin.join("nsc");
    fs::write(&nsc, "#!/bin/sh\necho 'nsc: profile missing' >&2\nexit 1\n").unwrap();
    for path in [&op, &nsc] {
      let mut mode = fs::metadata(path).unwrap().permissions();
      mode.set_mode(0o755);
      fs::set_permissions(path, mode).unwrap();
    }
    let saved = std::env::var_os("PATH");
    let mut path = bin.into_os_string();
    path.push(":");
    if let Some(rest) = &saved {
      path.push(rest);
    }
    crate::test_support::set_env("PATH", &path);
    let _path = RestorePath(saved);
    fs::create_dir_all(root.join("context")).unwrap();
    fs::write(
      root.join("context").join("opened.json"),
      r#"{"url":"nats://op.example:4222","user":"agent","password":"op://vault/item/password"}"#, // betterleaks:allow
    )
    .unwrap();
    fs::write(root.join("context").join("profile.json"), r#"{"nsc":"nsc://op/acct/user"}"#).unwrap();
    let found = adapt(&root, "/home/eng", home.path()).expect("adapt").expect("contexts");
    let text = found.skipped.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
    assert!(text.contains("op: item missing"), "{text}");
    assert!(text.contains("nsc: profile missing"), "{text}");
    assert!(found.grants.is_empty(), "{:?}", found.grants);
  }

  #[test]
  fn creds_path_expands_home_on_the_host() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public;
    let jwt = user_jwt(&public);
    let creds = home.path().join("user.creds");
    fs::write(&creds, decorate_creds(&jwt, &seed)).unwrap();
    let saved = std::env::var_os("HOME");
    crate::test_support::set_env("HOME", home.path());
    write_context(&root, "demo", r#"{"url":"tls://nats.internal:4222","creds":"$HOME/user.creds"}"#);
    let found = adapted(&root, home.path());
    let real = rule_of(&found).real.expect("expanded creds").expose_secret().to_string();
    assert!(real.contains(&seed), "{real}");
    assert!(!context_json(&found, "demo").contains(&seed));
    assert!(!context_json(&found, "demo").contains("$HOME"));
    match saved {
      Some(value) => crate::test_support::set_env("HOME", value),
      None => crate::test_support::unset_env("HOME"),
    }
  }

  #[test]
  fn cleartext_url_with_a_ca_grants_tls() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let ca = root.join("ca.pem");
    fs::create_dir_all(&root).unwrap();
    fs::write(&ca, b"ca-bytes").unwrap();
    write_context(
      &root,
      "demo",
      &format!(
        r#"{{"url":"nats://nats.internal:4222","user":"agent","password":"real-nats-pass","ca":"{}"}}"#, // betterleaks:allow
        ca.display()
      ),
    );
    let found = adapted(&root, home.path());
    let real = rule_of(&found).real.expect("tls grant").expose_secret().to_string();
    assert!(real.starts_with("tls://"), "{real}");
    assert!(real.contains("sslrootcert="), "{real}");
    assert!(real.contains("real-nats-pass"), "{real}");
    assert!(!context_json(&found, "demo").contains("real-nats-pass"));
    assert!(found.skipped.is_empty(), "{:?}", found.skipped);
  }

  /// `windows_cert_store` matches the host failure on Linux. `socks_proxy` stays
  /// a skip until the dial is decided. Neither drop takes the other contexts.
  #[test]
  fn windows_cert_store_and_socks_proxy_skip_that_context_only() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(&root, "demo", r#"{"url":"nats://nats.internal:4222","token":"real-token"}"#);
    fs::write(
      root.join("context").join("win.json"),
      r#"{"url":"tls://nats.internal:4222","token":"win-token","windows_cert_store":"windows"}"#,
    )
    .unwrap();
    fs::write(
      root.join("context").join("sock.json"),
      r#"{"url":"nats://other.internal:4222","token":"sock-token","socks_proxy":"socks5://127.0.0.1:1080"}"#,
    )
    .unwrap();
    let found = adapted(&root, home.path());
    assert_eq!(found.grants.len(), 1, "{:?}", found.skipped);
    assert!(found.grants[0].fragment.contains("/context/demo.json"));
    assert!(found.skipped.iter().any(|skip| matches!(
      skip,
      NatsSkip {
        name,
        cause: NatsSkipCause::Unsupported(NatsUnsupported::WindowsCertStore)
      } if name == "win"
    )));
    assert!(found.skipped.iter().any(|skip| matches!(
      skip,
      NatsSkip {
        name,
        cause: NatsSkipCause::Unsupported(NatsUnsupported::SocksProxy)
      } if name == "sock"
    )));
    let guest = found
      .files
      .iter()
      .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
      .collect::<String>();
    assert!(!guest.contains("win-token"), "{guest}");
    assert!(!guest.contains("sock-token"), "{guest}");
  }

  #[test]
  fn missing_selection_keeps_the_other_contexts() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    fs::create_dir_all(root.join("context")).unwrap();
    fs::write(
      root.join("context").join("demo.json"),
      r#"{"url":"nats://nats.internal:4222","token":"real-token"}"#,
    )
    .unwrap();
    fs::write(
      root.join("context").join("other.json"),
      r#"{"url":"nats://other.internal:4222","token":"other-token"}"#,
    )
    .unwrap();
    let found = adapt(&root, "/home/eng", home.path()).expect("adapt").expect("contexts");
    assert_eq!(found.grants.len(), 2, "{:?}", found.skipped);
    assert!(found.files.iter().all(|(path, _)| path != "context.txt"));
    assert!(
      !found
        .files
        .iter()
        .map(|(_, bytes)| String::from_utf8_lossy(bytes))
        .any(|text| text.contains("real-token") || text.contains("other-token"))
    );

    fs::write(root.join("context.txt"), "gone\n").unwrap();
    let found = adapt(&root, "/home/eng", home.path()).expect("adapt").expect("contexts");
    assert_eq!(found.grants.len(), 2, "{:?}", found.skipped);
    assert_eq!(file(&found, "context.txt"), b"gone\n");
    assert!(found.skipped.iter().any(|skip| matches!(
      skip,
      NatsSkip { name, cause: NatsSkipCause::Absent } if name == "gone"
    )));
  }

  fn assert_misplaced_seed(err: Error) {
    let Error::Config(source) = err else {
      panic!("expected the nats scope error, got {err}");
    };
    let arkham_config::Error::NatsScope { source, .. } = source.as_ref() else {
      panic!("expected NatsScope, got {source}");
    };
    assert!(matches!(source, arkham_config::grants::NatsUriError::MisplacedSeed), "{source}");
  }
}
