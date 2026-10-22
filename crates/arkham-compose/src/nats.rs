//! NATS context adapter: `~/.config/nats/context/<name>.json` is one
//! connection string plus the credential the CLI reads from disk. A TLS
//! context becomes one grant. A cleartext context mounts a decoy and writes
//! no real credential. `context.txt` is copied into the guest and is not how
//! a credential is chosen.
//!
//! The guest tree is one writable directory at `{home}/.config/nats`, so
//! `nats context select` can rename `context.txt`. A creds or nkey file is
//! `decoy/<label>.<suffix>` inside that directory. The decoy seed comes from
//! that context's `key_seed()`. Identical TLS bytes share one blob path. A
//! real dial clash is a typed error when `context.txt` names one of the
//! contexts, and a typed skip otherwise.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use arkham_config::config::IfMissing;
use arkham_config::context::{AmbientProtocol, ContextIdentity, ContextRef, Presented, identities, require_distinct};
use arkham_config::grants::{NATS_DEFAULT_PORT, NatsPlain, NatsScope, NatsSeed, NatsUriError, check_user_jwt};
use regex::Regex;
use secrecy::SecretString;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::adapt::{BLOB_PREFIX_NATS, GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, render_fragment};
use crate::error::Error;
use crate::rewrites::RewriteCollector;

/// JSON keys that name a credential. The decoy states the replacement.
const DROPPED_KEYS: &[&str] = &[
  "user",
  "password",
  "token",
  "creds",
  "nkey",
  "cert",
  "key",
  "ca",
  "nsc",
  "socks_proxy",
  "user_jwt",
  "user_seed",
];

/// One discovered context directory, ready for the ambient pass.
#[derive(Debug)]
pub(crate) struct AdaptedNats {
  /// TLS contexts that became grants, in file order.
  pub(crate) grants: Vec<RewriteAdapted>,
  /// Paths relative to [`Self::container`], including cleartext contexts.
  pub(crate) files: Vec<(String, Vec<u8>)>,
  /// `{home}/.config/nats`. The directory mounts here, writable.
  pub(crate) container: String,
  /// Contexts that did not map. The selected context is an error instead.
  pub(crate) skipped: Vec<NatsSkip>,
}

impl AdaptedNats {
  /// Mount the decoy tree as one writable directory and record the grants.
  ///
  /// # Errors
  ///
  /// Returns an error when the directory cannot be written.
  pub(crate) fn install(self, collector: &mut RewriteCollector) -> Result<(), Error> {
    collector.mount_directory(&format!("{BLOB_PREFIX_NATS}context"), &self.container, &self.files)?;
    collector.grants.extend(self.grants);
    Ok(())
  }
}

/// Map every context under `root`, or nothing when `context.txt` is absent.
///
/// # Errors
///
/// Returns an error when the selected context cannot be derived, a seed sits
/// outside the nkey or creds field, two contexts on one server cannot be told
/// apart, or a grant fragment cannot be serialized.
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
  /// `windows_cert_store`, `socks_proxy`, or `nsc`.
  #[error("uses {0}")]
  Unsupported(NatsUnsupported),
  /// The server URL is not one `nats` or `tls` URL.
  #[error("server url is not one nats or tls url")]
  ServerUrl,
  /// The credential does not map onto one auth method.
  #[error("credential does not map onto one auth method")]
  Credential,
  /// TLS material on a cleartext upstream.
  #[error("tls material on a cleartext upstream")]
  TlsOnCleartext,
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
  /// `nsc`.
  #[error("nsc")]
  Nsc,
}

struct GuestCred {
  tree_path: String,
  bytes: String,
}

impl GuestCred {
  fn written(&self) -> String {
    format!("~/.config/nats/{}", self.tree_path)
  }
}

/// Upstream dial compared within one host and port.
#[derive(Clone)]
struct Dial {
  host: String,
  port: u16,
  real_tls: bool,
  handshake_first: bool,
  cert: Option<Vec<u8>>,
  key: Option<Vec<u8>>,
  ca: Option<Vec<u8>>,
}

impl Dial {
  fn same_material(&self, other: &Self) -> bool {
    self.real_tls == other.real_tls
      && self.handshake_first == other.handshake_first
      && self.cert == other.cert
      && self.key == other.key
      && self.ca == other.ca
  }

  fn blob_name(bytes: &[u8], kind: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    format!("{BLOB_PREFIX_NATS}{}.{kind}", hex::encode(&digest[..16]))
  }
}

struct TlsQuery {
  pairs: Vec<(String, String)>,
  blobs: Vec<(String, Vec<u8>)>,
}

struct Ready {
  identity: ContextIdentity,
  dial: Dial,
  doc: Map<String, Value>,
  url: Url,
  fake: NatsPlain,
  guest: Option<GuestCred>,
  fake_url: String,
  /// Set for a TLS upstream. Cleartext validates this string and drops it.
  real_url: Option<String>,
  blobs: Vec<(String, Vec<u8>)>,
  decoy: String,
}

impl Ready {
  fn tls_query(&self) -> TlsQuery {
    let mut pairs = Vec::new();
    let mut blobs = Vec::new();
    if !self.dial.real_tls {
      return TlsQuery { pairs, blobs };
    }
    if self.dial.handshake_first {
      pairs.push(("handshake_first".to_string(), "true".to_string()));
    }
    for (kind, field, bytes) in [
      ("crt", "sslcert", self.dial.cert.as_deref()),
      ("key", "sslkey", self.dial.key.as_deref()),
      ("ca", "sslrootcert", self.dial.ca.as_deref()),
    ] {
      let Some(bytes) = bytes else {
        continue;
      };
      let name = Dial::blob_name(bytes, kind);
      pairs.push((field.to_string(), format!("{GRANTS_STATE_DIR}/rules.d/{name}")));
      blobs.push((name, bytes.to_vec()));
    }
    TlsQuery { pairs, blobs }
  }

  fn decoy_doc(&self) -> Map<String, Value> {
    let mut out = self.doc.clone();
    out.retain(|key, _| !DROPPED_KEYS.contains(&key.as_str()) && !key.starts_with("windows_"));
    out.insert("url".to_string(), Value::String(public_url(&self.url)));
    let written = self.guest.as_ref().map(GuestCred::written);
    let auth = self.fake.context_auth(written.as_deref());
    match &self.fake {
      NatsPlain::UserPass { .. } => {
        out.insert("user".to_string(), Value::String(auth.user));
        out.insert("password".to_string(), Value::String(auth.password));
      }
      NatsPlain::Token(_) => {
        out.insert("token".to_string(), Value::String(auth.token));
      }
      NatsPlain::Nkey(_) => {
        out.insert("nkey".to_string(), Value::String(auth.nkey));
      }
      NatsPlain::Creds { .. } => {
        out.insert("creds".to_string(), Value::String(auth.creds));
      }
    }
    out
  }
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

  /// Map every context under `root`, or nothing when `context.txt` is absent.
  ///
  /// # Errors
  ///
  /// Returns an error when the selected context cannot be derived, a seed
  /// sits outside the nkey or creds field, two contexts on one server cannot
  /// be told apart, or a grant fragment cannot be serialized.
  pub(crate) fn adapt(self) -> Result<Option<AdaptedNats>, Error> {
    let Some(selected) = self.selected_name()? else {
      return Ok(None);
    };
    let mut name_skips = Vec::new();
    let files = self.context_files(&mut name_skips)?;
    let mut skipped = Vec::new();
    for skip in name_skips {
      self.note(&selected, skip, &mut skipped)?;
    }
    if !files.iter().any(|(name, _)| name == &selected) {
      return Err(self.selected_error(skip(&selected, NatsSkipCause::Absent)));
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
    let mut ready = Vec::new();
    for ((name, path), id) in files.iter().zip(ids.iter()) {
      match self.one_context(path, name, id)? {
        Ok(item) => ready.push(item),
        Err(skip) => self.note(&selected, skip, &mut skipped)?,
      }
    }
    let (ready, dial_skips) = self.reconcile(&selected, ready)?;
    for skip in dial_skips {
      self.note(&selected, skip, &mut skipped)?;
    }
    let presented = ready
      .iter()
      .filter(|item| item.real_url.is_some())
      .map(|item| Presented {
        identity: &item.identity,
        host: item.dial.host.as_str(),
        port: item.dial.port,
        decoy: item.fake_url.as_bytes(),
      })
      .collect::<Vec<_>>();
    require_distinct(&presented)?;
    let mut tree = vec![("context.txt".to_string(), format!("{selected}\n").into_bytes())];
    let mut grants = Vec::new();
    for item in ready {
      Self::push_tree(&mut tree, &item);
      if let Some(grant) = Self::grant_of(item)? {
        grants.push(grant);
      }
    }
    Ok(Some(AdaptedNats {
      grants,
      files: tree,
      container: format!("{}/.config/nats", self.home),
      skipped,
    }))
  }

  fn note(&self, selected: &str, skip: NatsSkip, skipped: &mut Vec<NatsSkip>) -> Result<(), Error> {
    if skip.name == selected {
      return Err(self.selected_error(skip));
    }
    tracing::warn!(%skip, "nats context skipped");
    skipped.push(skip);
    Ok(())
  }

  fn selected_error(&self, skip: NatsSkip) -> Error {
    Error::NatsSelected {
      file: self.root.join("context").join(format!("{}.json", skip.name)),
      skip,
    }
  }

  fn selected_name(&self) -> Result<Option<String>, Error> {
    let path = self.root.join("context.txt");
    if !path.is_file() {
      return Ok(None);
    }
    let text = fs::read_to_string(&path).map_err(|source| Error::ReadFile {
      path: path.clone(),
      source,
    })?;
    let name = text.trim();
    if !context_name(name) {
      return Err(Error::NatsSelected {
        file: path,
        skip: skip(name, NatsSkipCause::Name),
      });
    }
    Ok(Some(name.to_string()))
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
        skipped.push(skip(&name, NatsSkipCause::Name));
        continue;
      }
      files.push((name, path));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
  }

  fn one_context(&self, path: &Path, name: &str, id: &ContextIdentity) -> Result<Result<Ready, NatsSkip>, Error> {
    let Ok(body) = fs::read_to_string(path) else {
      return Ok(Err(skip(name, NatsSkipCause::Document)));
    };
    let Ok(value) = serde_json::from_str::<Value>(&body) else {
      return Ok(Err(skip(name, NatsSkipCause::Document)));
    };
    let Some(doc) = value.as_object().cloned() else {
      return Ok(Err(skip(name, NatsSkipCause::Document)));
    };
    if let Some(feature) = unsupported(&doc) {
      return Ok(Err(skip(name, NatsSkipCause::Unsupported(feature))));
    }
    let Some(url) = dial_url(text(&doc, "url")) else {
      return Ok(Err(skip(name, NatsSkipCause::ServerUrl)));
    };
    let Some(real) = self.found_cred(&doc) else {
      return Ok(Err(skip(name, NatsSkipCause::Credential)));
    };
    let dial = match self.dial(&url, &doc) {
      Ok(dial) => dial,
      Err(cause) => return Ok(Err(skip(name, cause))),
    };
    let (fake, guest) = Self::wire_auth(&real, &id.env(), &id.label, id.key_seed())?;
    let Some(fake_url) = auth_url(&url, url.scheme(), &fake, &[]) else {
      return Ok(Err(skip(name, NatsSkipCause::Rejected)));
    };
    let mut item = Ready {
      identity: id.clone(),
      dial,
      doc,
      url,
      fake,
      guest,
      fake_url,
      real_url: None,
      blobs: Vec::new(),
      decoy: String::new(),
    };
    let query = item.tls_query();
    let pairs = query
      .pairs
      .iter()
      .map(|(key, value)| (key.as_str(), value.as_str()))
      .collect::<Vec<_>>();
    let scheme = if item.dial.real_tls { "tls" } else { "nats" };
    let Some(real_url) = auth_url(&item.url, scheme, &real, &pairs) else {
      return Ok(Err(skip(name, NatsSkipCause::Rejected)));
    };
    if let Err(err) = NatsScope::from_strings(&item.fake_url, &real_url) {
      return match scope_failure(name, err) {
        Ok(skip) => Ok(Err(skip)),
        Err(err) => Err(err),
      };
    }
    item.blobs = query.blobs;
    if item.dial.real_tls {
      item.real_url = Some(real_url);
    }
    item.decoy = match serde_json::to_string_pretty(&item.decoy_doc()) {
      Ok(text) => text,
      Err(_) => return Ok(Err(skip(name, NatsSkipCause::Rejected))),
    };
    Ok(Ok(item))
  }

  fn reconcile(&self, selected: &str, mut ready: Vec<Ready>) -> Result<(Vec<Ready>, Vec<NatsSkip>), Error> {
    let mut groups: BTreeMap<(String, u16), Vec<usize>> = BTreeMap::new();
    for (index, item) in ready.iter().enumerate() {
      if item.real_url.is_some() {
        groups.entry((item.dial.host.clone(), item.dial.port)).or_default().push(index);
      }
    }
    let mut skipped = Vec::new();
    let mut drop = Vec::new();
    for indexes in groups.into_values() {
      let at = indexes
        .iter()
        .position(|&index| ready[index].identity.name == selected)
        .unwrap_or(0);
      let canonical = indexes[at];
      let canonical_name = ready[canonical].identity.name.clone();
      let canonical_dial = ready[canonical].dial.clone();
      let selected_here = canonical_name == selected;
      for index in indexes {
        if ready[index].dial.same_material(&canonical_dial) {
          continue;
        }
        let other = ready[index].identity.name.clone();
        if selected_here {
          return Err(self.selected_error(NatsSkip {
            name: selected.to_string(),
            cause: NatsSkipCause::Dial {
              other,
              host: canonical_dial.host.clone(),
              port: canonical_dial.port,
            },
          }));
        }
        skipped.push(NatsSkip {
          name: other,
          cause: NatsSkipCause::Dial {
            other: canonical_name.clone(),
            host: canonical_dial.host.clone(),
            port: canonical_dial.port,
          },
        });
        drop.push(index);
      }
    }
    drop.sort_unstable();
    for index in drop.into_iter().rev() {
      ready.remove(index);
    }
    Ok((ready, skipped))
  }

  fn push_tree(tree: &mut Vec<(String, Vec<u8>)>, item: &Ready) {
    tree.push((format!("context/{}.json", item.identity.name), item.decoy.as_bytes().to_vec()));
    if let Some(guest) = &item.guest {
      tree.push((guest.tree_path.clone(), guest.bytes.as_bytes().to_vec()));
    }
  }

  fn grant_of(item: Ready) -> Result<Option<RewriteAdapted>, Error> {
    let Some(real_url) = item.real_url else {
      return Ok(None);
    };
    let fragment = GrantFragment {
      env: item.identity.env(),
      registry: false,
      allow: Vec::new(),
      value: Some(item.fake_url),
      real: Some(crate::adapt::Redacted(real_url)),
      generated: true,
      if_missing: Some(IfMissing::Ignore),
      tls: BTreeMap::new(),
      ssh: BTreeMap::new(),
    };
    Ok(Some(RewriteAdapted {
      fragment: render_fragment(&item.identity.source, &item.identity.label, &fragment)?,
      decoy: String::new(),
      materialized: item.blobs,
      decoy_files: Vec::new(),
    }))
  }

  fn dial(&self, url: &Url, doc: &Map<String, Value>) -> Result<Dial, NatsSkipCause> {
    let tls_first = doc.get("tls_first").and_then(Value::as_bool).unwrap_or(false);
    let real_tls = url.scheme() == "tls" || tls_first;
    let cert = text(doc, "cert");
    let key = text(doc, "key");
    let ca = text(doc, "ca");
    if !real_tls && (!cert.is_empty() || !key.is_empty() || !ca.is_empty()) {
      return Err(NatsSkipCause::TlsOnCleartext);
    }
    if cert.is_empty() != key.is_empty() {
      return Err(NatsSkipCause::TlsFile);
    }
    let read = |raw: &str| -> Option<Option<Vec<u8>>> {
      if raw.is_empty() {
        return Some(None);
      }
      let path = self.resolve_path(raw)?;
      fs::read(path).ok().map(Some)
    };
    let (Some(cert), Some(key), Some(ca)) = (read(cert), read(key), read(ca)) else {
      return Err(NatsSkipCause::TlsFile);
    };
    let Some(host) = url.host_str() else {
      return Err(NatsSkipCause::ServerUrl);
    };
    Ok(Dial {
      host: host.to_ascii_lowercase(),
      port: url.port().unwrap_or(NATS_DEFAULT_PORT),
      real_tls,
      handshake_first: tls_first,
      cert,
      key,
      ca,
    })
  }

  fn found_cred(&self, doc: &Map<String, Value>) -> Option<NatsPlain> {
    let user = text(doc, "user");
    let password = text(doc, "password");
    let token = text(doc, "token");
    let creds = text(doc, "creds");
    let nkey = text(doc, "nkey");
    let user_jwt = text(doc, "user_jwt");
    let user_seed = text(doc, "user_seed");
    let other_kind = !user.is_empty() || !password.is_empty() || !creds.is_empty() || !nkey.is_empty() || !user_jwt.is_empty();
    if !token.is_empty() && other_kind {
      return None;
    }
    if !user.is_empty() {
      return Some(NatsPlain::UserPass {
        user: user.to_string(),
        pass: password.to_string(),
      });
    }
    if !password.is_empty() {
      return None;
    }
    if !creds.is_empty() {
      let (seed, jwt) = self.load_creds(creds)?;
      return Some(NatsPlain::Creds { seed, jwt });
    }
    if !nkey.is_empty() {
      let path = self.resolve_path(nkey)?;
      return Some(NatsPlain::Nkey(nkey_file(&path)?));
    }
    if !user_jwt.is_empty() && !user_seed.is_empty() {
      let seed = self.load_user_seed(user_seed)?;
      let jwt = self.load_jwt(user_jwt)?;
      let parsed = NatsSeed::from_seed(SecretString::from(seed.clone())).ok()?;
      check_user_jwt(&jwt, &parsed.public).ok()?;
      return Some(NatsPlain::Creds { seed, jwt });
    }
    if !user_jwt.is_empty() {
      return None;
    }
    if !token.is_empty() {
      return Some(NatsPlain::Token(token.to_string()));
    }
    None
  }

  fn load_creds(&self, raw: &str) -> Option<(String, String)> {
    let path = self.resolve_path(raw)?;
    let text = fs::read_to_string(path).ok()?;
    let mut found = USER_CONFIG_RE.captures_iter(&text);
    let jwt = found.next()?.get(1)?.as_str().to_string();
    let seed = found.next()?.get(1)?.as_str().to_string();
    let parsed = NatsSeed::from_seed(SecretString::from(seed.clone())).ok()?;
    check_user_jwt(&jwt, &parsed.public).ok()?;
    Some((seed, jwt))
  }

  fn load_user_seed(&self, raw: &str) -> Option<String> {
    if NatsSeed::from_seed(SecretString::from(raw.to_string())).is_ok() {
      return Some(raw.to_string());
    }
    let path = self.resolve_path(raw)?;
    nkey_file(&path)
  }

  fn load_jwt(&self, raw: &str) -> Option<String> {
    let text = if let Some(path) = self.resolve_path(raw) {
      fs::read_to_string(path).ok()?
    } else {
      raw.to_string()
    };
    if let Some(jwt) = USER_CONFIG_RE.captures_iter(&text).next().and_then(|cap| cap.get(1)) {
      return Some(jwt.as_str().to_string());
    }
    let line = text.trim();
    if line.is_empty() || line.contains('\n') {
      None
    } else {
      Some(line.to_string())
    }
  }

  fn resolve_path(&self, raw: &str) -> Option<PathBuf> {
    if raw.is_empty() || (raw.contains("://") && !raw.starts_with("file://")) {
      return None;
    }
    let path = if let Some(rest) = raw.strip_prefix("file://") {
      let abs = rest.strip_prefix('/')?;
      PathBuf::from(format!("/{abs}"))
    } else if let Some(rest) = raw.strip_prefix("~/") {
      self.host_home.join(rest)
    } else if raw == "~" {
      self.host_home.to_path_buf()
    } else {
      let path = PathBuf::from(raw);
      if path.is_absolute() { path } else { self.root.join(path) }
    };
    path.is_file().then_some(path)
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

fn skip(name: &str, cause: NatsSkipCause) -> NatsSkip {
  NatsSkip {
    name: name.to_string(),
    cause,
  }
}

fn scope_failure(name: &str, err: NatsUriError) -> Result<NatsSkip, Error> {
  if matches!(err, NatsUriError::MisplacedSeed) {
    return Err(Error::Config(Box::new(arkham_config::Error::NatsScope {
      label: name.to_string(),
      source: err,
    })));
  }
  Ok(skip(name, NatsSkipCause::Rejected))
}

fn unsupported(doc: &Map<String, Value>) -> Option<NatsUnsupported> {
  if occupied(doc, "windows_cert_store") {
    return Some(NatsUnsupported::WindowsCertStore);
  }
  if occupied(doc, "socks_proxy") {
    return Some(NatsUnsupported::SocksProxy);
  }
  if occupied(doc, "nsc") {
    return Some(NatsUnsupported::Nsc);
  }
  None
}

fn nkey_file(path: &Path) -> Option<String> {
  let text = fs::read_to_string(path).ok()?;
  let seed = text.trim();
  NatsSeed::from_seed(SecretString::from(seed.to_string())).ok()?;
  Some(seed.to_string())
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

fn dial_url(raw: &str) -> Option<Url> {
  let raw = if raw.is_empty() { "nats://localhost:4222" } else { raw };
  if raw.split(',').filter(|part| !part.is_empty()).count() != 1 {
    return None;
  }
  let url = Url::parse(raw).ok()?;
  if url.scheme() != "nats" && url.scheme() != "tls" {
    return None;
  }
  url.host_str()?;
  Some(url)
}

fn auth_url(base: &Url, scheme: &str, auth: &NatsPlain, query: &[(&str, &str)]) -> Option<String> {
  let host = match base.host()? {
    url::Host::Domain(host) => host.to_string(),
    url::Host::Ipv4(addr) => addr.to_string(),
    url::Host::Ipv6(addr) => addr.to_string(),
  };
  Some(auth.connection_string(scheme, &host, base.port(), query))
}

fn public_url(url: &Url) -> String {
  let host = match url.host() {
    Some(url::Host::Ipv6(addr)) => format!("[{addr}]"),
    Some(host) => host.to_string(),
    None => "localhost".to_string(),
  };
  match url.port() {
    Some(port) => format!("{}://{host}:{port}", url.scheme()),
    None => format!("{}://{host}", url.scheme()),
  }
}

/// The credentials-file regex from async-nats `auth_utils`. The first capture
/// is the user JWT and the second is the nkey seed.
static USER_CONFIG_RE: LazyLock<Regex> = LazyLock::new(|| {
  Regex::new(r"\s*(?:(?:[-]{3,}.*[-]{3,}\r?\n)([\w\-.=]+)(?:\r?\n[-]{3,}.*[-]{3,}\r?\n))").expect("async-nats USER_CONFIG_RE is a constant")
});

#[cfg(test)]
mod tests {
  use arkham_config::config::RuleCfg;
  use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
  use pretty_assertions::assert_eq;
  use secrecy::ExposeSecret as _;
  use serde::Deserialize;
  use tempfile::tempdir;

  use super::*;

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
    let yaml = include_str!("../../../integration/compose.yaml");
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
    let base = url::Url::parse("tls://[::1]:4222").expect("ipv6 url");
    let auth = NatsPlain::UserPass {
      user: "agent".to_string(),
      pass: "p".to_string(),
    };
    assert_eq!(auth_url(&base, "tls", &auth, &[]).expect("auth url"), "tls://agent:p@[::1]:4222");
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
    assert!(
      found.skipped.iter().any(|skip| matches!(
        skip,
        NatsSkip { name, cause: NatsSkipCause::Credential } if name == "other"
      )),
      "{:?}",
      found.skipped
    );
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
    fs::write(&nkey, format!("# operator key\n{seed}\n")).unwrap();
    adapt(&root, "/home/eng", home.path()).expect_err("context does not map");

    write_context(&root, "tok", r#"{"url":"","token":"real-token","tls_first":true}"#);
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let real = rule.real.unwrap();
    assert!(real.expose_secret().contains("real-token"));
    assert!(real.expose_secret().contains("localhost"));
    assert!(!context_json(&found, "tok").contains("real-token"));

    write_context(&root, "bad", r#"{"url":"nats://a:4222,nats://b:4222","token":"real-token"}"#);
    adapt(&root, "/home/eng", home.path()).expect_err("context does not map");
    write_context(
      &root,
      "nsc",
      r#"{"url":"nats://nats.internal:4222","nsc":"nsc://operator/account/user"}"#,
    );
    adapt(&root, "/home/eng", home.path()).expect_err("context does not map");
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
  fn unknown_context_field_stays_on_the_decoy_and_secret_keys_do_not() {
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
    assert_eq!(decoy["name"], "demo");
    assert_eq!(decoy["operator_note"], "kept-too");
    assert!(decoy.get("windows_cert_match").is_none());
    assert!(decoy.get("user_jwt").is_none());
    assert!(!text.contains("real-token"));
    assert_ne!(decoy["password"], "real-token");
    assert!(found.grants.is_empty(), "a cleartext context writes no grant");
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
    adapt(&root, "/home/eng", home.path()).expect_err("context does not map");
    fs::write(&creds, format!("{jwt}\n{seed}\n")).unwrap();
    adapt(&root, "/home/eng", home.path()).expect_err("context does not map");
  }

  #[test]
  fn inline_nkey_text_is_not_a_path() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    write_context(&root, "demo", &format!(r#"{{"url":"nats://nats.internal:4222","nkey":"{seed}"}}"#));
    adapt(&root, "/home/eng", home.path()).expect_err("context does not map");
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

  #[test]
  fn selected_cleartext_does_not_clash_with_tls_on_the_same_server() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(
      &root,
      "demo",
      r#"{"url":"nats://nats.internal:4222","user":"agent","password":"real-nats-pass"}"#, // betterleaks:allow
    );
    fs::write(
      root.join("context").join("secure.json"),
      r#"{"url":"tls://nats.internal:4222","token":"secure-token"}"#,
    )
    .unwrap();
    let found = adapted(&root, home.path());
    assert!(
      found.grants.iter().any(|grant| grant.fragment.contains("/context/secure.json")),
      "{:?}",
      found.skipped
    );
    assert!(found.grants.iter().all(|grant| !grant.fragment.contains("/context/demo.json")));
    assert!(
      found.skipped.iter().all(|skip| !matches!(skip.cause, NatsSkipCause::Dial { .. })),
      "{:?}",
      found.skipped
    );
    let decoy = String::from_utf8(file(&found, "context/demo.json").to_vec()).unwrap();
    assert!(!decoy.contains("real-nats-pass"), "{decoy}");
    let real = rule_named(&found, "secure").real.expect("tls grant").expose_secret().to_string();
    assert!(real.contains("secure-token"), "{real}");
    assert!(!real.contains("real-nats-pass"), "{real}");
  }

  #[test]
  fn unselected_cleartext_that_sorts_first_does_not_skip_the_tls_grant() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(&root, "other", r#"{"url":"tls://other.internal:4222","token":"kept-token"}"#);
    fs::write(
      root.join("context").join("aplain.json"),
      r#"{"url":"nats://nats.internal:4222","user":"agent","password":"plain-pass"}"#, // betterleaks:allow
    )
    .unwrap();
    fs::write(
      root.join("context").join("bsecure.json"),
      r#"{"url":"tls://nats.internal:4222","token":"secure-token"}"#,
    )
    .unwrap();
    let found = adapted(&root, home.path());
    assert!(found.grants.iter().any(|grant| grant.fragment.contains("/context/other.json")));
    assert!(
      found.grants.iter().any(|grant| grant.fragment.contains("/context/bsecure.json")),
      "{:?}",
      found.skipped
    );
    assert!(found.grants.iter().all(|grant| !grant.fragment.contains("/context/aplain.json")));
    assert!(
      found.skipped.iter().all(|skip| !matches!(skip.cause, NatsSkipCause::Dial { .. })),
      "{:?}",
      found.skipped
    );
    let plain = String::from_utf8(file(&found, "context/aplain.json").to_vec()).unwrap();
    assert!(!plain.contains("plain-pass"), "{plain}");
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
  fn init_replaces_the_nats_directory() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(&root, "demo", r#"{"url":"tls://nats.internal:4222","token":"real-token"}"#);
    let files = tempdir().unwrap();
    let dir = files.path().join(format!("{BLOB_PREFIX_NATS}context"));
    fs::create_dir_all(dir.join("context")).unwrap();
    fs::write(dir.join("previous-context.txt"), "gone\n").unwrap();
    fs::write(dir.join("context").join("gone.json"), "{}\n").unwrap();
    fs::write(dir.join("scratch.tmp"), "temp").unwrap();
    let found = adapted(&root, home.path());
    let mut collector = RewriteCollector::new(files.path()).unwrap();
    found.install(&mut collector).unwrap();
    let outputs = collector.outputs();
    let host = &outputs.mounts[0].host;
    assert!(!host.join("previous-context.txt").exists());
    assert!(!host.join("context").join("gone.json").exists());
    assert!(!host.join("scratch.tmp").exists());
    assert_eq!(fs::read_to_string(host.join("context.txt")).unwrap(), "demo\n");
    assert!(host.join("context").join("demo.json").is_file());
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

  /// A cleartext upstream stores no real credential and still mounts the decoy.
  #[test]
  fn cleartext_context_omits_the_real_credential() {
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
    let rendered = found.grants.iter().map(|grant| grant.fragment.clone()).collect::<String>();
    assert!(!rendered.contains("real-nats-pass"), "{rendered}");
    assert!(!rendered.contains("other-real-token"), "{rendered}");
    let decoy = String::from_utf8(file(&found, "context/demo.json").to_vec()).unwrap();
    assert!(!decoy.contains("real-nats-pass"), "{decoy}");
    assert!(decoy.contains("password"), "{decoy}");
    assert!(found.grants.is_empty());
  }

  /// An unselected context that fails to map is a skip. The selected grant still loads.
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
    assert_eq!(found.grants.len(), 1, "{:?}", found.skipped);
    assert!(found.grants[0].fragment.contains("/context/demo.json"));
    assert!(found.skipped.iter().any(|skip| matches!(
      skip,
      NatsSkip { name, cause: NatsSkipCause::ServerUrl } if name == "bad"
    )));
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
