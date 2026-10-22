//! NATS context adapter: `~/.config/nats/context/<name>.json` is one
//! connection string plus the credential the CLI reads from disk. Each file
//! becomes one grant. `context.txt` is copied into the guest and is not how
//! a credential is chosen.
//!
//! A creds or nkey file mounts at `{home}/.config/nats/decoy/<label>.<suffix>`,
//! so two contexts can name one source file. The decoy seed comes from that
//! context's `key_seed()`. Identical TLS material on one server shares one
//! blob path. A real dial clash is a typed error when `context.txt` names
//! one of the contexts, and a typed skip otherwise.

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
use url::Url;

use crate::adapt::{GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, render_fragment};
use crate::error::Error;
use crate::rewrites::RewriteCollector;

const CONTEXT_NAME: &str = r"^[A-Za-z0-9_-]+$";

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
  /// One grant per context that mapped, in file order.
  pub(crate) grants: Vec<NatsGrant>,
  /// `context.txt`, written once for the directory.
  pub(crate) context_txt: DecoyFile,
  /// Contexts that did not map. The selected context is an error instead.
  pub(crate) skipped: Vec<NatsSkip>,
}

/// One context's grant and the decoy JSON mounted at [`Self::dest`].
#[derive(Debug)]
pub(crate) struct NatsGrant {
  /// Grant fragment and decoy JSON.
  pub(crate) adapted: RewriteAdapted,
  /// Container path of the decoy context JSON.
  pub(crate) dest: String,
  /// Grant label. Also the host file name, so it does not move when a context is added.
  label: String,
}

impl AdaptedNats {
  /// Write `context.txt` once, then each context's decoy and grant.
  ///
  /// `context.txt` is writable. Context JSON and credential files stay read-only.
  ///
  /// # Errors
  ///
  /// Returns an error when a decoy file or grant fragment cannot be written.
  pub(crate) fn install(self, collector: &mut RewriteCollector) -> Result<(), Error> {
    collector.mount_decoy_file(
      &crate::adapt::DecoyFile {
        name: self.context_txt.name,
        bytes: self.context_txt.bytes,
        container: self.context_txt.container,
      },
      false,
    )?;
    for grant in self.grants {
      collector.twin(vec![grant.adapted], &grant.label, &grant.dest)?;
    }
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
pub enum NatsSkip {
  /// `windows_cert_store`, `socks_proxy`, or `nsc`.
  #[error("context `{name}` uses {feature}")]
  Unsupported {
    /// Context name.
    name: String,
    /// The field that kept it out.
    feature: NatsUnsupported,
  },
  /// The server URL is not one `nats` or `tls` URL.
  #[error("context `{name}` server url is not one nats or tls url")]
  ServerUrl {
    /// Context name.
    name: String,
  },
  /// The credential does not map onto one auth method.
  #[error("context `{name}` credential does not map onto one auth method")]
  Credential {
    /// Context name.
    name: String,
  },
  /// TLS material on a cleartext upstream.
  #[error("context `{name}` tls material on a cleartext upstream")]
  TlsOnCleartext {
    /// Context name.
    name: String,
  },
  /// `cert` without `key`, or a TLS file that cannot be read.
  #[error("context `{name}` tls file cannot be read")]
  TlsFile {
    /// Context name.
    name: String,
  },
  /// The context file cannot be read.
  #[error("context `{name}` cannot be read")]
  Unreadable {
    /// Context name.
    name: String,
  },
  /// The context file is not JSON.
  #[error("context `{name}` is not json")]
  NotJson {
    /// Context name.
    name: String,
  },
  /// The JSON value is not an object.
  #[error("context `{name}` is not an object")]
  NotObject {
    /// Context name.
    name: String,
  },
  /// The connection strings were rejected, other than a misplaced seed.
  #[error("context `{name}` connection was rejected")]
  Rejected {
    /// Context name.
    name: String,
  },
  /// This context and `other` share a server but not the upstream TLS dial.
  #[error("context `{name}` shares {host}:{port} with `{other}` but not the upstream tls")]
  Dial {
    /// Context being left out, or the selected context when this is an error.
    name: String,
    /// The other context in the clash.
    other: String,
    /// Shared host.
    host: String,
    /// Shared port.
    port: u16,
  },
  /// `context.txt` names a file that is not in the directory.
  #[error("context `{name}` is not in the context directory")]
  Absent {
    /// Context name.
    name: String,
  },
  /// `identities` did not return one record per context file.
  #[error("context `{name}` has no identity")]
  Identity {
    /// Context name.
    name: String,
  },
}

/// A field that has no substitute in the connection-string model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatsUnsupported {
  /// `windows_cert_store`.
  WindowsCertStore,
  /// `socks_proxy`.
  SocksProxy,
  /// `nsc`.
  Nsc,
}

impl std::fmt::Display for NatsUnsupported {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(match self {
      Self::WindowsCertStore => "windows_cert_store",
      Self::SocksProxy => "socks_proxy",
      Self::Nsc => "nsc",
    })
  }
}

/// One agent-side file the adapter writes and mounts.
#[derive(Debug)]
pub(crate) struct DecoyFile {
  /// File name under the rewrite files dir.
  name: String,
  /// File contents as written.
  bytes: Vec<u8>,
  /// Absolute container path.
  container: String,
}

struct GuestCred {
  written: String,
  container: String,
  bytes: String,
}

struct FoundCred {
  real: NatsPlain,
}

/// Upstream dial compared within one host and port. Paths are assigned later.
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
}

struct Ready {
  name: String,
  path: PathBuf,
  label: String,
  env: String,
  identity: ContextIdentity,
  dial: Dial,
  doc: Map<String, Value>,
  url: Url,
  real: NatsPlain,
  fake: NatsPlain,
  guest: Option<GuestCred>,
  fake_url: String,
  /// Label whose TLS blobs this context shares. Equal material uses one path.
  blob: String,
}

enum Outcome {
  Skip(NatsSkip),
  Ready(Box<Ready>),
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
    let files = self.context_files()?;
    if !files.iter().any(|(name, _)| name == &selected) {
      return Err(self.selected_error(&selected, NatsSkip::Absent { name: selected.clone() }));
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
    if ids.len() != files.len() {
      return Err(self.selected_error(&selected, NatsSkip::Identity { name: selected.clone() }));
    }
    let mut ready = Vec::new();
    let mut skipped = Vec::new();
    for ((name, path), id) in files.iter().zip(ids.iter()) {
      match self.one_context(path, name, id)? {
        Outcome::Skip(skip) if name == &selected => return Err(self.selected_error(name, skip)),
        Outcome::Skip(skip) => {
          tracing::warn!(%skip, "nats context skipped");
          skipped.push(skip);
        }
        Outcome::Ready(item) => ready.push(*item),
      }
    }
    let (ready, dial_skips) = self.reconcile(&selected, ready)?;
    for skip in dial_skips {
      tracing::warn!(%skip, "nats context skipped");
      skipped.push(skip);
    }
    if !ready.iter().any(|item| item.name == selected) {
      return Err(self.selected_error(&selected, NatsSkip::Absent { name: selected.clone() }));
    }
    let presented = ready
      .iter()
      .map(|item| Presented {
        identity: &item.identity,
        host: item.dial.host.as_str(),
        port: item.dial.port,
        decoy: item.fake_url.as_bytes(),
      })
      .collect::<Vec<_>>();
    require_distinct(&presented)?;
    let mut grants = Vec::with_capacity(ready.len());
    for item in ready {
      grants.push(self.render(item)?);
    }
    if !skipped.is_empty() {
      tracing::debug!(skipped = skipped.len(), "nats contexts left out of the grant set");
    }
    Ok(Some(AdaptedNats {
      grants,
      context_txt: self.context_txt(&selected),
      skipped,
    }))
  }

  fn selected_error(&self, name: &str, skip: NatsSkip) -> Error {
    Error::NatsSelected {
      file: self.root.join("context").join(format!("{name}.json")),
      skip,
    }
  }

  fn context_txt(&self, selected: &str) -> DecoyFile {
    DecoyFile {
      name: "context-txt".to_string(),
      bytes: format!("{selected}\n").into_bytes(),
      container: format!("{}/.config/nats/context.txt", self.home),
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
    if context_name(name).is_none() {
      return Err(Error::SourceInvalid {
        file: path,
        detail: "context.txt does not name a context".to_string(),
      });
    }
    Ok(Some(name.to_string()))
  }

  fn context_files(&self) -> Result<Vec<(String, PathBuf)>, Error> {
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
      let Some(name) = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|name| context_name(name).is_some())
      else {
        continue;
      };
      files.push((name.to_string(), path));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
  }

  fn one_context(&self, path: &Path, name: &str, id: &ContextIdentity) -> Result<Outcome, Error> {
    let Ok(body) = fs::read_to_string(path) else {
      return Ok(Outcome::Skip(NatsSkip::Unreadable { name: name.to_string() }));
    };
    let Ok(value) = serde_json::from_str::<Value>(&body) else {
      return Ok(Outcome::Skip(NatsSkip::NotJson { name: name.to_string() }));
    };
    let Some(doc) = value.as_object() else {
      return Ok(Outcome::Skip(NatsSkip::NotObject { name: name.to_string() }));
    };
    self.map_context(path, name, doc, id)
  }

  fn map_context(&self, path: &Path, name: &str, doc: &Map<String, Value>, id: &ContextIdentity) -> Result<Outcome, Error> {
    let name_owned = name.to_string();
    if let Some(feature) = unsupported(doc) {
      return Ok(Outcome::Skip(NatsSkip::Unsupported { name: name_owned, feature }));
    }
    let Some(url) = dial_url(text(doc, "url")) else {
      return Ok(Outcome::Skip(NatsSkip::ServerUrl { name: name_owned }));
    };
    let Some(found) = self.found_cred(doc) else {
      return Ok(Outcome::Skip(NatsSkip::Credential { name: name_owned }));
    };
    let real_tls = url.scheme() == "tls";
    let dial = match self.dial(&url, doc, real_tls) {
      DialRead::Skip(skip) => {
        return Ok(Outcome::Skip(match skip {
          DialSkip::TlsOnCleartext => NatsSkip::TlsOnCleartext { name: name_owned },
          DialSkip::TlsFile => NatsSkip::TlsFile { name: name_owned },
        }));
      }
      DialRead::Ready(dial) => dial,
    };
    let (fake, guest) = self.wire_auth(&found, &id.env(), &id.label, id.key_seed())?;
    let Some(fake_url) = auth_url(&url, url.scheme(), &fake, &[]) else {
      return Ok(Outcome::Skip(NatsSkip::Rejected { name: name_owned }));
    };
    let Some(real_url) = auth_url(&url, if real_tls { "tls" } else { "nats" }, &found.real, &[]) else {
      return Ok(Outcome::Skip(NatsSkip::Rejected { name: name_owned }));
    };
    if let Err(err) = NatsScope::from_strings(&fake_url, &real_url) {
      return Ok(Outcome::Skip(scope_failure(name, err)?));
    }
    Ok(Outcome::Ready(Box::new(Ready {
      name: name_owned,
      path: path.to_path_buf(),
      label: id.label.clone(),
      env: id.env(),
      identity: id.clone(),
      dial,
      doc: doc.clone(),
      url,
      real: found.real,
      fake,
      guest,
      fake_url,
      blob: id.label.clone(),
    })))
  }

  /// Keep one dial per host and port. The selected context's dial wins when
  /// it is in the group; a difference is then an error. Otherwise the first
  /// context's dial wins and the others are skipped.
  fn reconcile(&self, selected: &str, mut ready: Vec<Ready>) -> Result<(Vec<Ready>, Vec<NatsSkip>), Error> {
    let mut groups: BTreeMap<(String, u16), Vec<usize>> = BTreeMap::new();
    for (index, item) in ready.iter().enumerate() {
      groups.entry((item.dial.host.clone(), item.dial.port)).or_default().push(index);
    }
    let mut skipped = Vec::new();
    let mut drop = Vec::new();
    for indexes in groups.values() {
      let Some(&first) = indexes.first() else {
        continue;
      };
      let canonical = indexes
        .iter()
        .copied()
        .find(|&index| ready[index].name == selected)
        .unwrap_or(first);
      let selected_here = ready[canonical].name == selected;
      let canonical_label = ready[canonical].label.clone();
      let canonical_dial = ready[canonical].dial.clone();
      for &index in indexes {
        if ready[index].dial.same_material(&canonical_dial) {
          ready[index].blob.clone_from(&canonical_label);
          continue;
        }
        if selected_here {
          return Err(self.selected_error(
            selected,
            NatsSkip::Dial {
              name: selected.to_string(),
              other: ready[index].name.clone(),
              host: canonical_dial.host.clone(),
              port: canonical_dial.port,
            },
          ));
        }
        skipped.push(NatsSkip::Dial {
          name: ready[index].name.clone(),
          other: ready[canonical].name.clone(),
          host: canonical_dial.host.clone(),
          port: canonical_dial.port,
        });
        drop.push(index);
      }
    }
    drop.sort_unstable();
    drop.dedup();
    for index in drop.into_iter().rev() {
      ready.remove(index);
    }
    Ok((ready, skipped))
  }

  fn render(&self, item: Ready) -> Result<NatsGrant, Error> {
    let TlsQuery {
      pairs: query,
      blobs: materialized,
    } = tls_query(&item);
    let query_ref = query.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect::<Vec<_>>();
    let real_scheme = if item.dial.real_tls { "tls" } else { "nats" };
    let Some(real_url) = auth_url(&item.url, real_scheme, &item.real, &query_ref) else {
      return Err(self.selected_error(&item.name, NatsSkip::Rejected { name: item.name.clone() }));
    };
    if let Err(err) = NatsScope::from_strings(&item.fake_url, &real_url) {
      let skip = scope_failure(&item.name, err)?;
      return Err(self.selected_error(&item.name, skip));
    }
    let decoy_doc = decoy_context(&item.doc, &item.url, item.guest.as_ref(), &item.fake);
    let decoy = serde_json::to_string_pretty(&decoy_doc).map_err(|err| Error::SourceInvalid {
      file: item.path.clone(),
      detail: err.to_string(),
    })?;
    let mut decoy_files = Vec::new();
    if let Some(guest) = item.guest {
      decoy_files.push(crate::adapt::DecoyFile {
        name: format!("{}.credential", item.label),
        bytes: guest.bytes.into_bytes(),
        container: guest.container,
      });
    }
    let fragment = GrantFragment {
      env: item.env,
      registry: false,
      allow: Vec::new(),
      value: Some(item.fake_url),
      real: Some(crate::adapt::Redacted(real_url)),
      generated: true,
      if_missing: Some(IfMissing::Ignore),
      tls: BTreeMap::new(),
      ssh: BTreeMap::new(),
    };
    let adapted = RewriteAdapted {
      fragment: render_fragment(&item.path, &item.label, &fragment)?,
      decoy,
      materialized,
      decoy_files,
    };
    Ok(NatsGrant {
      dest: format!("{}/.config/nats/context/{}.json", self.home, item.name),
      label: item.label,
      adapted,
    })
  }

  fn dial(&self, url: &Url, doc: &Map<String, Value>, real_tls: bool) -> DialRead {
    let cert = text(doc, "cert");
    let key = text(doc, "key");
    let ca = text(doc, "ca");
    if !real_tls && (!cert.is_empty() || !key.is_empty() || !ca.is_empty()) {
      return DialRead::Skip(DialSkip::TlsOnCleartext);
    }
    if cert.is_empty() != key.is_empty() {
      return DialRead::Skip(DialSkip::TlsFile);
    }
    let read = |raw: &str| -> Option<Option<Vec<u8>>> {
      if raw.is_empty() {
        return Some(None);
      }
      let path = self.resolve_path(raw)?;
      fs::read(path).ok().map(Some)
    };
    let (Some(cert), Some(key), Some(ca)) = (read(cert), read(key), read(ca)) else {
      return DialRead::Skip(DialSkip::TlsFile);
    };
    let Some(host) = url.host_str() else {
      return DialRead::Skip(DialSkip::TlsFile);
    };
    DialRead::Ready(Dial {
      host: host.to_ascii_lowercase(),
      port: url.port().unwrap_or(NATS_DEFAULT_PORT),
      real_tls,
      handshake_first: doc.get("tls_first").and_then(Value::as_bool).unwrap_or(false),
      cert,
      key,
      ca,
    })
  }

  fn found_cred(&self, doc: &Map<String, Value>) -> Option<FoundCred> {
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
      return Some(FoundCred {
        real: NatsPlain::UserPass {
          user: user.to_string(),
          pass: password.to_string(),
        },
      });
    }
    if !password.is_empty() {
      return None;
    }
    if !creds.is_empty() {
      let (seed, jwt) = self.load_creds(creds)?;
      return Some(FoundCred {
        real: NatsPlain::Creds { seed, jwt },
      });
    }
    if !nkey.is_empty() {
      let path = self.resolve_path(nkey)?;
      return Some(FoundCred {
        real: NatsPlain::Nkey(nkey_file(&path)?),
      });
    }
    if !user_jwt.is_empty() && !user_seed.is_empty() {
      let seed = self.load_user_seed(user_seed)?;
      let jwt = self.load_jwt(user_jwt)?;
      let parsed = NatsSeed::from_seed(SecretString::from(seed.clone())).ok()?;
      check_user_jwt(&jwt, &parsed.public).ok()?;
      return Some(FoundCred {
        real: NatsPlain::Creds { seed, jwt },
      });
    }
    if !user_jwt.is_empty() {
      return None;
    }
    if !token.is_empty() {
      return Some(FoundCred {
        real: NatsPlain::Token(token.to_string()),
      });
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

  fn wire_auth(&self, found: &FoundCred, env: &str, label: &str, key_seed: &[u8; 32]) -> Result<(NatsPlain, Option<GuestCred>), Error> {
    let prepared = found.real.prepare(env, key_seed).map_err(|_source| Error::NatsDecoy)?;
    let guest = prepared.file.map(|file| GuestCred {
      written: format!("~/.config/nats/decoy/{label}.{}", file.suffix),
      container: format!("{}/.config/nats/decoy/{label}.{}", self.home, file.suffix),
      bytes: file.body,
    });
    Ok((prepared.decoy, guest))
  }
}

enum DialRead {
  Skip(DialSkip),
  Ready(Dial),
}

enum DialSkip {
  TlsOnCleartext,
  TlsFile,
}

struct TlsQuery {
  pairs: Vec<(String, String)>,
  blobs: Vec<(String, Vec<u8>)>,
}

fn tls_query(item: &Ready) -> TlsQuery {
  let mut pairs = Vec::new();
  let mut blobs = Vec::new();
  if item.dial.handshake_first {
    pairs.push(("handshake_first".to_string(), "true".to_string()));
  }
  let label = &item.blob;
  for (kind, field, bytes) in [
    ("crt", "sslcert", item.dial.cert.as_deref()),
    ("key", "sslkey", item.dial.key.as_deref()),
    ("ca", "sslrootcert", item.dial.ca.as_deref()),
  ] {
    let Some(bytes) = bytes else {
      continue;
    };
    let name = format!("{label}.{kind}");
    pairs.push((field.to_string(), format!("{GRANTS_STATE_DIR}/rules.d/{name}")));
    blobs.push((name, bytes.to_vec()));
  }
  TlsQuery { pairs, blobs }
}

fn scope_failure(name: &str, err: NatsUriError) -> Result<NatsSkip, Error> {
  if matches!(err, NatsUriError::MisplacedSeed) {
    return Err(Error::Config(Box::new(arkham_config::Error::NatsScope {
      label: name.to_string(),
      source: err,
    })));
  }
  Ok(NatsSkip::Rejected { name: name.to_string() })
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

fn context_name(name: &str) -> Option<&str> {
  Regex::new(CONTEXT_NAME).ok()?.is_match(name).then_some(name)
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
    Some(_) => url.host_str().unwrap_or("localhost").to_string(),
    None => "localhost".to_string(),
  };
  match url.port() {
    Some(port) => format!("{}://{host}:{port}", url.scheme()),
    None => format!("{}://{host}", url.scheme()),
  }
}

fn decoy_context(doc: &Map<String, Value>, dial: &Url, guest: Option<&GuestCred>, fake: &NatsPlain) -> Map<String, Value> {
  let mut out = doc.clone();
  out.retain(|key, _| !DROPPED_KEYS.contains(&key.as_str()) && !key.starts_with("windows_"));
  out.insert("url".to_string(), Value::String(public_url(dial)));
  let auth = fake.context_auth(guest.map(|guest| guest.written.as_str()));
  match fake {
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

  fn primary(found: &AdaptedNats) -> &RewriteAdapted {
    let name = String::from_utf8(found.context_txt.bytes.clone()).expect("context.txt is utf-8");
    let name = name.trim();
    let grant = found
      .grants
      .iter()
      .find(|grant| grant.dest.ends_with(&format!("/{name}.json")))
      .expect("selected grant");
    &grant.adapted
  }

  fn rule_of(found: &AdaptedNats) -> RuleCfg {
    let doc: RulesDoc = toml::from_str(&primary(found).fragment).expect("fragment");
    doc.rules.into_values().next().expect("one rule")
  }

  #[test]
  fn integration_client_does_not_mount_the_secret_tree() {
    let yaml = include_str!("../../../integration/compose.yaml");
    assert!(
      !yaml.lines().any(|line| line.trim() == "- ./out:/out"),
      "the client and smtp-direct mounts must not be the secret tree"
    );
    assert!(yaml.contains("- ./out/results:/out"));
    assert!(yaml.contains("./out/nats-discovery/guest:/opt/nats-discovered:ro"));
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
    let decoy: Value = serde_json::from_str(&primary(&found).decoy).unwrap();
    assert_eq!(decoy["user"], "agent");
    assert_eq!(decoy["tls_first"], true);
    assert_eq!(decoy["jetstream_domain"], "app");
    assert_ne!(decoy["password"], "real-nats-pass");
    assert!(!primary(&found).decoy.contains("real-nats-pass"));
    assert!(!primary(&found).decoy.contains("other-real-pass"));
    assert!(
      found.skipped.iter().any(|skip| matches!(
        skip,
        NatsSkip::Credential { name } if name == "other"
      )),
      "{:?}",
      found.skipped
    );
    assert!(found.grants.iter().all(|grant| !grant.dest.ends_with("other.json")));
    assert_eq!(found.context_txt.container, "/home/eng/.config/nats/context.txt");
    assert_eq!(found.context_txt.bytes, b"demo\n");
    assert_eq!(found.grants[0].dest, "/home/eng/.config/nats/context/demo.json");
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
      &format!(r#"{{"url":"nats://nats.internal:4222","creds":"{}"}}"#, creds.display()),
    );
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let real = rule.real.as_ref().unwrap().expose_secret().to_string();
    let fake = rule.value.as_ref().unwrap().expose_secret().to_string();
    NatsScope::from_strings(&fake, &real).expect("creds grant");
    assert!(real.contains(&seed), "the grant holds the real seed");
    assert!(real.contains(&jwt), "the grant holds the real jwt");
    let guest = primary(&found)
      .decoy_files
      .iter()
      .find(|file| file.container.contains("/.config/nats/decoy/") && extension_is(&file.container, "creds"))
      .expect("per-context creds");
    let guest_text = String::from_utf8(guest.bytes.clone()).unwrap();
    assert!(guest_text.contains(JWT_BEGIN));
    assert!(guest_text.contains(SEED_BEGIN));
    assert!(!guest_text.contains(&seed));
    assert!(!guest_text.contains(&jwt));
    assert!(!primary(&found).decoy.contains(&seed));
    assert!(!primary(&found).decoy.contains(&jwt));
    let decoy: Value = serde_json::from_str(&primary(&found).decoy).unwrap();
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
      &format!(r#"{{"url":"nats://127.0.0.1:4222","nkey":"{}"}}"#, nkey.display()),
    );
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let real = rule.real.unwrap().expose_secret().to_string();
    assert!(real.contains(&seed));
    let guest = &primary(&found)
      .decoy_files
      .iter()
      .find(|file| file.container.contains("/.config/nats/decoy/") && extension_is(&file.container, "nk"))
      .unwrap()
      .bytes;
    let guest = String::from_utf8(guest.clone()).unwrap();
    assert!(!guest.contains(&seed));
    NatsSeed::from_seed(SecretString::from(guest.trim().to_string())).expect("decoy seed");
    fs::write(&nkey, format!("# operator key\n{seed}\n")).unwrap();
    adapt(&root, "/home/eng", home.path()).expect_err("context does not map");

    write_context(&root, "tok", r#"{"url":"","token":"real-token"}"#);
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let real = rule.real.unwrap();
    assert!(real.expose_secret().contains("real-token"));
    assert!(real.expose_secret().contains("localhost"));
    assert!(!primary(&found).decoy.contains("real-token"));

    write_context(&root, "bad", r#"{"url":"nats://a:4222,nats://b:4222","token":"real-token"}"#);
    adapt(&root, "/home/eng", home.path()).expect_err("context does not map");
    write_context(
      &root,
      "nsc",
      r#"{"url":"nats://nats.internal:4222","nsc":"nsc://operator/account/user"}"#,
    );
    adapt(&root, "/home/eng", home.path()).expect_err("context does not map");
  }

  #[test]
  fn traversal_creds_path_stays_inside_the_decoy_dir() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public.clone();
    let jwt = user_jwt(&public);
    let ssh = home.path().join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    fs::write(ssh.join("config"), decorate_creds(&jwt, &seed)).unwrap();
    write_context(&root, "demo", r#"{"url":"nats://nats.internal:4222","creds":"../../.ssh/config"}"#);
    let found = adapted(&root, home.path());
    let containers: Vec<&str> = primary(&found).decoy_files.iter().map(|file| file.container.as_str()).collect();
    assert!(containers.iter().all(|path| !path.contains("..")), "{containers:?}");
    assert!(
      containers.iter().any(|path| path.starts_with("/home/eng/.config/nats/decoy/")),
      "{containers:?}"
    );
    let guest = primary(&found)
      .decoy_files
      .iter()
      .find(|file| file.container.contains("decoy"))
      .expect("decoy creds");
    let guest_text = String::from_utf8(guest.bytes.clone()).unwrap();
    assert!(!guest_text.contains(&seed));
    assert!(rule_of(&found).real.unwrap().expose_secret().contains(&seed));
  }

  #[test]
  fn relative_creds_path_mirrors_under_the_nats_dir() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public.clone();
    let jwt = user_jwt(&public);
    let creds = root.join("creds");
    fs::create_dir_all(&creds).unwrap();
    fs::write(creds.join("user.creds"), decorate_creds(&jwt, &seed)).unwrap();
    write_context(&root, "demo", r#"{"url":"nats://nats.internal:4222","creds":"creds/user.creds"}"#);
    let found = adapted(&root, home.path());
    let guest = primary(&found)
      .decoy_files
      .iter()
      .find(|file| file.container.contains("/.config/nats/decoy/") && extension_is(&file.container, "creds"))
      .expect("per-context relative creds");
    let guest_text = String::from_utf8(guest.bytes.clone()).unwrap();
    assert!(!guest_text.contains(&seed));
  }

  #[test]
  fn symlink_creds_mounts_at_the_lexical_path() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public.clone();
    let jwt = user_jwt(&public);
    let outside = home.path().join("outside.creds");
    fs::write(&outside, decorate_creds(&jwt, &seed)).unwrap();
    let creds = root.join("creds");
    fs::create_dir_all(&creds).unwrap();
    std::os::unix::fs::symlink(&outside, creds.join("link.creds")).unwrap();
    write_context(&root, "demo", r#"{"url":"nats://nats.internal:4222","creds":"creds/link.creds"}"#);
    let found = adapted(&root, home.path());
    let guest = primary(&found)
      .decoy_files
      .iter()
      .find(|file| file.container.contains("/.config/nats/decoy/") && extension_is(&file.container, "creds"))
      .expect("lexical symlink path");
    let guest_text = String::from_utf8(guest.bytes.clone()).unwrap();
    assert!(!guest_text.contains(&seed));
    assert!(rule_of(&found).real.unwrap().expose_secret().contains(&seed));
    assert!(
      !primary(&found)
        .decoy_files
        .iter()
        .any(|file| file.container.contains("outside.creds"))
    );
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
    let decoy: Value = serde_json::from_str(&primary(&found).decoy).unwrap();
    assert_eq!(decoy["description"], "kept");
    assert_eq!(decoy["name"], "demo");
    assert_eq!(decoy["operator_note"], "kept-too");
    assert!(decoy.get("windows_cert_match").is_none());
    assert!(decoy.get("user_jwt").is_none());
    assert!(!primary(&found).decoy.contains("real-token"));
    assert_ne!(decoy["password"], "real-token");
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
      &format!(r#"{{"url":"nats://nats.internal:4222","creds":"{}"}}"#, creds.display()),
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
    write_context(&root, "demo", r#"{"url":"nats://nats.internal:4222","user":"agent","password":""}"#);
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
      &format!(r#"{{"url":"nats://nats.internal:4222","user":"agent","password":"{password}"}}"#),
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
    assert!(!primary(&found).decoy.contains(password));

    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"nats://nats.internal:4222","token":"{password}"}}"#),
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
        &format!(r#"{{"url":"nats://nats.internal:4222","user":"{user}","password":"{password}"}}"#),
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
  fn absolute_creds_path_outside_home_falls_back_to_the_decoy_dir() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let outside = tempdir().unwrap();
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public.clone();
    let jwt = user_jwt(&public);
    let creds = outside.path().join("user.creds");
    fs::write(&creds, decorate_creds(&jwt, &seed)).unwrap();
    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"nats://nats.internal:4222","creds":"{}"}}"#, creds.display()),
    );
    let found = adapted(&root, home.path());
    let containers: Vec<&str> = primary(&found).decoy_files.iter().map(|file| file.container.as_str()).collect();
    assert!(
      containers.iter().any(|path| path.starts_with("/home/eng/.config/nats/decoy/")),
      "{containers:?}"
    );
    assert!(
      containers
        .iter()
        .all(|path| !path.contains(outside.path().to_string_lossy().as_ref())),
      "{containers:?}"
    );
    let guest = primary(&found)
      .decoy_files
      .iter()
      .find(|file| file.container.contains("decoy"))
      .expect("decoy creds");
    let guest_text = String::from_utf8(guest.bytes.clone()).unwrap();
    assert!(!guest_text.contains(&seed));
    assert!(!guest_text.contains(&jwt));
    let real = rule_of(&found).real.unwrap().expose_secret().to_string();
    assert!(real.contains(&seed));
    assert!(real.contains(&jwt));
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
      &format!(r#"{{"url":"nats://nats.internal:4222","user_jwt":"{jwt}","user_seed":"{seed}"}}"#),
    );
    let found = adapted(&root, home.path());
    let real = rule_of(&found).real.unwrap().expose_secret().to_string();
    assert!(real.contains(&seed));
    assert!(real.contains(&jwt));
    let guest = primary(&found)
      .decoy_files
      .iter()
      .find(|file| {
        file.container.contains("decoy")
          || Path::new(&file.container)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("creds"))
      })
      .expect("guest creds");
    let guest_text = String::from_utf8(guest.bytes.clone()).unwrap();
    assert!(guest_text.contains(JWT_BEGIN));
    assert!(!guest_text.contains(&seed));
    assert!(!guest_text.contains(&jwt));
    assert!(!primary(&found).decoy.contains(&seed));
    assert!(!primary(&found).decoy.contains(&jwt));
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
      &format!(r#"{{"url":"nats://nats.internal:4222","creds":"{}"}}"#, creds.display()),
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
    assert_eq!(found.context_txt.bytes, b"pass\n");
    assert_eq!(found.grants.len(), 3);
    assert!(found.grants.iter().all(|grant| !grant.adapted.decoy.is_empty()));
    assert!(found.grants.iter().all(|grant| {
      grant
        .adapted
        .decoy_files
        .iter()
        .all(|file| !file.container.ends_with("context.txt") && !file.container.contains("/context/"))
    }));
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
      .grants
      .iter()
      .flat_map(|grant| grant.adapted.decoy_files.iter().map(|file| file.container.as_str()))
      .filter(|path| extension_is(path, "creds"))
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
    let NatsSkip::Dial { name, other, host, port } = skip else {
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
      r#"{"url":"nats://other.internal:4222","token":"kept-token"}"#,
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
    assert!(found.grants.iter().any(|grant| grant.dest.ends_with("/kept.json")));
    assert_eq!(
      found
        .grants
        .iter()
        .filter(|grant| grant.dest.contains("alpha") || grant.dest.contains("beta"))
        .count(),
      1
    );
    assert!(found.skipped.iter().any(|skip| matches!(
      skip,
      NatsSkip::Dial { name, other, host, port }
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
      &format!(r#"{{"url":"nats://127.0.0.1:4222","nkey":"{}"}}"#, nkey.display()),
    );
    let first = adapted(&root, home.path());
    let second = adapted(&root, home.path());
    assert_eq!(primary(&first).decoy_files[0].bytes, primary(&second).decoy_files[0].bytes);
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
      let doc: RulesDoc = toml::from_str(&grant.adapted.fragment).expect("fragment");
      rules.extend(doc.rules);
    }
    rules
  }

  fn guest_tree(found: &AdaptedNats) -> Vec<(String, String)> {
    let mut guest = vec![(
      found.context_txt.container.clone(),
      String::from_utf8(found.context_txt.bytes.clone()).expect("context.txt is utf-8"),
    )];
    for grant in &found.grants {
      guest.push((grant.dest.clone(), grant.adapted.decoy.clone()));
      for file in &grant.adapted.decoy_files {
        guest.push((
          file.container.clone(),
          String::from_utf8(file.bytes.clone()).expect("guest file is utf-8"),
        ));
      }
    }
    guest
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
