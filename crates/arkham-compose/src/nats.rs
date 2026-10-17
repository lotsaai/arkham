//! NATS CLI context adapter. The discovery root is `~/.config/nats`:
//! `context.txt` names the selected context, and
//! `context/<name>.json` holds it. Credential files that context
//! references are read here and never mounted for the guest.
//!
//! The selected context becomes one connection-string grant. The decoy
//! context and decoy credential files are what the guest mounts. Real
//! seeds and JWTs stay in the grant fragment.
//!
//! A creds or nkey path is mounted only when it is lexically under the
//! host home and contains no `..` segment. A symlink is not canonicalized:
//! the read follows it, and the decoy mounts at the path the context named.
//! A path that escapes falls back to `~/.config/nats/decoy/`. The `nkey`
//! field is a file path. `user_seed` may be inline text. `guest_tls_mode`
//! is not derived. The context describes the upstream dial, and the guest
//! leg's mode stays on the rule `tls` table.
//!
//! Checked against the NATS CLI context document and the nsc credentials
//! file: `context.txt`, `context/<name>.json`, the JSON fields below, and
//! the decorated banners. `$XDG_CONFIG_HOME`, `NATS_*` overrides, `nsc://`,
//! and a comma-separated server list are not read. No maintained crate
//! exposes `ParseDecoratedJWT` or `ParseDecoratedNKey`. `nkeys` 0.4 parses
//! a seed, and the banner scan below follows the Go regex `[-]{3,}`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use arkham_config::config::{IfMissing, fake_for};
use arkham_config::grants::{NatsPlain, NatsScope, NatsSeed};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::adapt::{DecoyFile, GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, render_fragment, rewrite_label};
use crate::error::Error;
use crate::paths::normalize;

/// Official decorated-credential banners. The NATS libraries write these
/// spellings, including the extra dash on `END`. A read accepts any banner
/// of three or more dashes.
const JWT_BEGIN: &str = "-----BEGIN NATS USER JWT-----";
const JWT_END: &str = "------END NATS USER JWT------";
const SEED_BEGIN: &str = "-----BEGIN USER NKEY SEED-----";
const SEED_END: &str = "------END USER NKEY SEED------";

/// One context file. Unknown JSON keys are dropped. Secret fields stay on
/// this struct for the grant and are copied onto the decoy only when they
/// are the rewritten auth field.
#[derive(Debug, Deserialize)]
struct NatsContext {
  #[serde(default)]
  description: String,
  #[serde(default)]
  url: String,
  #[serde(default)]
  user: String,
  #[serde(default)]
  password: String,
  #[serde(default)]
  token: String,
  #[serde(default)]
  creds: String,
  #[serde(default)]
  nkey: String,
  #[serde(default)]
  cert: String,
  #[serde(default)]
  key: String,
  #[serde(default)]
  ca: String,
  #[serde(default)]
  nsc: String,
  #[serde(default)]
  inbox_prefix: String,
  #[serde(default)]
  jetstream_domain: String,
  #[serde(default)]
  jetstream_api_prefix: String,
  #[serde(default)]
  jetstream_event_prefix: String,
  #[serde(default)]
  user_jwt: String,
  #[serde(default)]
  user_seed: String,
  #[serde(default)]
  color_scheme: String,
  #[serde(default)]
  tls_first: bool,
  #[serde(default)]
  socks_proxy: String,
  #[serde(default)]
  windows_cert_store: String,
}

impl NatsContext {
  fn trim(&mut self) {
    let fields = [
      &mut self.description,
      &mut self.url,
      &mut self.user,
      &mut self.password,
      &mut self.token,
      &mut self.creds,
      &mut self.nkey,
      &mut self.cert,
      &mut self.key,
      &mut self.ca,
      &mut self.nsc,
      &mut self.inbox_prefix,
      &mut self.jetstream_domain,
      &mut self.jetstream_api_prefix,
      &mut self.jetstream_event_prefix,
      &mut self.user_jwt,
      &mut self.user_seed,
      &mut self.color_scheme,
      &mut self.socks_proxy,
      &mut self.windows_cert_store,
    ];
    for field in fields {
      *field = field.trim().to_string();
    }
  }
}

/// One discovered context, ready for the ambient pass.
pub(crate) struct AdaptedNats {
  /// The grant and the decoy files.
  pub(crate) adapted: Vec<RewriteAdapted>,
  /// Container path of the decoy context JSON.
  pub(crate) context_dest: String,
}

/// Decoy credential file mounted for the guest.
struct GuestCred {
  /// Path written into the decoy context. `~` is the guest home.
  written: String,
  /// Absolute container path.
  container: String,
  /// Decoy file bytes.
  bytes: String,
}

/// Credential the context states, after its files have been read.
enum AuthKind {
  /// CONNECT `user` and `pass`.
  UserPass { user: String, pass: String },
  /// CONNECT `auth_token`.
  Token(String),
  /// User seed. `source` is the file the context named, when it named one.
  Nkey { seed: String, source: Option<PathBuf> },
  /// User seed and user JWT.
  Creds {
    seed: String,
    jwt: String,
    source: Option<PathBuf>,
  },
}

/// TLS files copied into the grant layer for the real connection string.
enum TlsMaterial {
  /// The context names no TLS file.
  None,
  /// The context names TLS material this adapter will not guess.
  Skip(&'static str),
  /// Query paths and the bytes written beside the fragment.
  Files {
    /// `sslcert`.
    cert: Option<(String, (String, Vec<u8>))>,
    /// `sslkey`.
    key: Option<(String, (String, Vec<u8>))>,
    /// `sslrootcert`.
    ca: Option<(String, (String, Vec<u8>))>,
  },
}

/// Map the selected context under `root`, or nothing when there is no
/// selection or the context cannot be derived.
///
/// # Errors
///
/// Returns an error when the decoy seed cannot be minted or the grant
/// fragment cannot be serialized.
pub(crate) fn adapt(root: &Path, home: &str, host_home: &Path) -> Result<Option<AdaptedNats>, Error> {
  let selected = root.join("context.txt");
  if !selected.is_file() {
    return Ok(None);
  }
  let text = match fs::read_to_string(&selected) {
    Ok(text) => text,
    Err(err) => {
      tracing::warn!(source = %selected.display(), %err, "nats source skipped: context.txt cannot be read");
      return Ok(None);
    }
  };
  let Some(name) = context_name(&text) else {
    tracing::warn!(source = %selected.display(), "nats source skipped: context.txt does not name one context");
    return Ok(None);
  };
  let path = root.join("context").join(format!("{name}.json"));
  if !path.is_file() {
    tracing::warn!(source = %path.display(), "nats source skipped: the selected context file is absent");
    return Ok(None);
  }
  let body = match fs::read_to_string(&path) {
    Ok(body) => body,
    Err(err) => {
      tracing::warn!(source = %path.display(), %err, "nats source skipped: the context cannot be read");
      return Ok(None);
    }
  };
  let Ok(mut doc) = serde_json::from_str::<NatsContext>(&body) else {
    tracing::warn!(source = %path.display(), "nats source skipped: the context is not a context object");
    return Ok(None);
  };
  doc.trim();
  map_context(&path, name, &doc, home, host_home, root)
}

fn context_name(text: &str) -> Option<&str> {
  let name = text.trim();
  if name.is_empty() || name.contains(['/', '\\']) || name.contains("..") {
    None
  } else {
    Some(name)
  }
}

fn map_context(
  path: &Path,
  name: &str,
  doc: &NatsContext,
  home: &str,
  host_home: &Path,
  root: &Path,
) -> Result<Option<AdaptedNats>, Error> {
  if !doc.windows_cert_store.is_empty() || !doc.socks_proxy.is_empty() || !doc.nsc.is_empty() {
    return Ok(skip(path, "windows cert store, socks proxy, and nsc are not derived"));
  }
  let Some(dial) = dial_url(&doc.url) else {
    return Ok(skip(path, "the server url is not one nats:// or tls:// address"));
  };
  let Some(kind) = auth_kind(doc, host_home, root) else {
    return Ok(skip(path, "the credential does not map onto one auth method"));
  };
  let label = rewrite_label(path, name)?;
  let env = label.to_uppercase().replace('-', "_");
  let real_tls = dial.scheme() == "tls" || doc.tls_first;
  if !real_tls && (!doc.cert.is_empty() || !doc.key.is_empty() || !doc.ca.is_empty()) {
    return Ok(skip(path, "tls material on a cleartext server url is not derived"));
  }
  let mut query: Vec<(String, String)> = Vec::new();
  let mut materialized = Vec::new();
  if real_tls && doc.tls_first {
    query.push(("handshake_first".to_string(), "true".to_string()));
  }
  if real_tls {
    match tls_material(doc, &label, host_home, root) {
      TlsMaterial::None => {}
      TlsMaterial::Skip(reason) => return Ok(skip(path, reason)),
      TlsMaterial::Files { cert, key, ca } => {
        for (name, pair) in [("sslcert", cert), ("sslkey", key), ("sslrootcert", ca)] {
          if let Some((container, blob)) = pair {
            query.push((name.to_string(), container));
            materialized.push(blob);
          }
        }
      }
    }
  }
  let (fake_auth, real_auth, guest) = wire_auth(&kind, &env, host_home, home, &label)?;
  let query_ref: Vec<(&str, &str)> = query.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
  let Some(fake) = auth_url(&dial, dial.scheme(), &fake_auth, &[]) else {
    return Ok(skip(path, "the decoy connection string could not be built"));
  };
  let real_scheme = if real_tls { "tls" } else { "nats" };
  let Some(real) = auth_url(&dial, real_scheme, &real_auth, &query_ref) else {
    return Ok(skip(path, "the real connection string could not be built"));
  };
  if let Err(err) = NatsScope::from_strings(&fake, &real) {
    tracing::warn!(source = %path.display(), %err, "nats context skipped: the connection strings were rejected");
    return Ok(None);
  }
  let fragment = render_fragment(
    path,
    &label,
    &GrantFragment {
      env,
      registry: false,
      allow: Vec::new(),
      value: Some(fake),
      real: Some(crate::adapt::Redacted(real)),
      generated: true,
      if_missing: Some(IfMissing::Ignore),
      tls: BTreeMap::new(),
      ssh: BTreeMap::new(),
    },
  )?;
  let decoy_doc = decoy_context(doc, &dial, guest.as_ref(), &fake_auth);
  let decoy = serde_json::to_string_pretty(&decoy_doc).map_err(|err| Error::SourceInvalid {
    file: path.to_path_buf(),
    detail: format!("context json: {err}"),
  })?;
  let mut decoy_files = vec![DecoyFile {
    name: "nats-context-txt".to_string(),
    bytes: format!("{name}\n").into_bytes(),
    container: format!("{home}/.config/nats/context.txt"),
  }];
  if let Some(guest) = guest {
    decoy_files.push(DecoyFile {
      name: format!("nats-{label}.credential"),
      bytes: guest.bytes.into_bytes(),
      container: guest.container,
    });
  }
  Ok(Some(AdaptedNats {
    context_dest: format!("{home}/.config/nats/context/{name}.json"),
    adapted: vec![RewriteAdapted {
      fragment,
      decoy,
      materialized,
      decoy_files,
    }],
  }))
}

fn skip(path: &Path, reason: &str) -> Option<AdaptedNats> {
  tracing::warn!(source = %path.display(), reason, "nats context skipped");
  None
}

fn wire_auth(
  kind: &AuthKind,
  env: &str,
  host_home: &Path,
  home: &str,
  label: &str,
) -> Result<(NatsPlain, NatsPlain, Option<GuestCred>), Error> {
  match kind {
    AuthKind::UserPass { user, pass } => {
      let decoy = if pass.is_empty() { String::new() } else { fake_for(env, None) };
      Ok((
        NatsPlain::UserPass {
          user: user.clone(),
          pass: decoy,
        },
        NatsPlain::UserPass {
          user: user.clone(),
          pass: pass.clone(),
        },
        None,
      ))
    }
    AuthKind::Token(token) => Ok((NatsPlain::Token(fake_for(env, None)), NatsPlain::Token(token.clone()), None)),
    AuthKind::Nkey { seed, source } => {
      let (decoy, _) = mint_seed()?;
      let (written, container) = guest_file(source.as_deref(), host_home, home, &format!("{label}.nk"));
      let bytes = format!("{decoy}\n");
      Ok((
        NatsPlain::Nkey(decoy),
        NatsPlain::Nkey(seed.clone()),
        Some(GuestCred { written, container, bytes }),
      ))
    }
    AuthKind::Creds { seed, jwt, source } => {
      let (decoy_seed, public) = mint_seed()?;
      let decoy_token = decoy_jwt(&public);
      let (written, container) = guest_file(source.as_deref(), host_home, home, &format!("{label}.creds"));
      let bytes = decorate_creds(&decoy_token, &decoy_seed);
      Ok((
        NatsPlain::Creds {
          seed: decoy_seed,
          jwt: decoy_token,
        },
        NatsPlain::Creds {
          seed: seed.clone(),
          jwt: jwt.clone(),
        },
        Some(GuestCred { written, container, bytes }),
      ))
    }
  }
}

fn auth_kind(doc: &NatsContext, host_home: &Path, root: &Path) -> Option<AuthKind> {
  let kind = if !doc.user.is_empty() {
    AuthKind::UserPass {
      user: doc.user.clone(),
      pass: doc.password.clone(),
    }
  } else if !doc.password.is_empty() {
    return None;
  } else if !doc.creds.is_empty() {
    let parsed = load_creds(&doc.creds, host_home, root)?;
    AuthKind::Creds {
      seed: parsed.0,
      jwt: parsed.1,
      source: resolve_path(&doc.creds, host_home, root),
    }
  } else if !doc.nkey.is_empty() {
    AuthKind::Nkey {
      seed: load_nkey_file(&doc.nkey, host_home, root)?,
      source: resolve_path(&doc.nkey, host_home, root),
    }
  } else if !doc.user_jwt.is_empty() && !doc.user_seed.is_empty() {
    let seed = load_user_seed(&doc.user_seed, host_home, root)?;
    let jwt = load_jwt(&doc.user_jwt, host_home, root)?;
    let parsed = NatsSeed::from_seed(SecretString::from(seed.clone())).ok()?;
    if !parsed.matches_user_jwt(&jwt) {
      return None;
    }
    AuthKind::Creds { jwt, seed, source: None }
  } else if !doc.user_jwt.is_empty() {
    return None;
  } else if !doc.token.is_empty() {
    AuthKind::Token(doc.token.clone())
  } else {
    return None;
  };
  if !doc.token.is_empty() && !matches!(kind, AuthKind::Token(_)) {
    None
  } else {
    Some(kind)
  }
}

fn load_creds(raw: &str, host_home: &Path, root: &Path) -> Option<(String, String)> {
  let path = resolve_path(raw, host_home, root)?;
  let text = fs::read_to_string(path).ok()?;
  let jwt = decorated_jwt(&text)?;
  let seed = decorated_seed(&text)?;
  let parsed = NatsSeed::from_seed(SecretString::from(seed.clone())).ok()?;
  parsed.matches_user_jwt(&jwt).then_some((seed, jwt))
}

fn load_nkey_file(raw: &str, host_home: &Path, root: &Path) -> Option<String> {
  let path = resolve_path(raw, host_home, root)?;
  accepted_seed(&fs::read_to_string(path).ok()?)
}

fn load_user_seed(raw: &str, host_home: &Path, root: &Path) -> Option<String> {
  if let Some(seed) = accepted_seed(raw) {
    return Some(seed);
  }
  load_nkey_file(raw, host_home, root)
}

fn load_jwt(raw: &str, host_home: &Path, root: &Path) -> Option<String> {
  let text = if let Some(path) = resolve_path(raw, host_home, root) {
    fs::read_to_string(path).ok()?
  } else {
    raw.to_string()
  };
  decorated_jwt(&text)
}

fn accepted_seed(text: &str) -> Option<String> {
  let seed = decorated_seed(text)?;
  NatsSeed::from_seed(SecretString::from(seed.clone())).ok()?;
  Some(seed)
}

/// Banner-wrapped values. The Go regex is `[-]{3,}.*[-]{3,}` around one
/// `[\w\-.=]+` line. The first value is the JWT and the second is the seed.
fn decorated_payloads(text: &str) -> Vec<String> {
  let lines: Vec<&str> = text.lines().collect();
  let mut out = Vec::new();
  let mut index = 0;
  while index + 2 < lines.len() {
    if is_banner(lines[index]) && is_payload(lines[index + 1]) && is_banner(lines[index + 2]) {
      out.push(lines[index + 1].trim().to_string());
      index += 3;
    } else {
      index += 1;
    }
  }
  out
}

fn is_banner(line: &str) -> bool {
  let line = line.trim();
  let bytes = line.as_bytes();
  if bytes.len() < 6 || !line.starts_with('-') || !line.ends_with('-') {
    return false;
  }
  let start = bytes.iter().take_while(|byte| **byte == b'-').count();
  let end = bytes.iter().rev().take_while(|byte| **byte == b'-').count();
  start >= 3 && end >= 3 && (start + end <= bytes.len() || start == bytes.len())
}

fn is_payload(line: &str) -> bool {
  let line = line.trim();
  !line.is_empty()
    && line
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'='))
}

fn decorated_jwt(text: &str) -> Option<String> {
  let payloads = decorated_payloads(text);
  if let Some(jwt) = payloads.first() {
    return Some(jwt.clone());
  }
  let trimmed = text.trim();
  (trimmed.lines().count() == 1 && is_payload(trimmed)).then(|| trimmed.to_string())
}

fn decorated_seed(text: &str) -> Option<String> {
  let payloads = decorated_payloads(text);
  if payloads.len() > 1 {
    return payloads.get(1).cloned();
  }
  text
    .lines()
    .map(str::trim)
    .find(|line| {
      let bytes = line.as_bytes();
      bytes.len() >= 2 && bytes[0] == b'S' && matches!(bytes[1], b'O' | b'A' | b'U')
    })
    .map(str::to_string)
}

fn resolve_path(raw: &str, host_home: &Path, root: &Path) -> Option<PathBuf> {
  let raw = raw.trim();
  if raw.is_empty() || (raw.contains("://") && !raw.starts_with("file://")) {
    return None;
  }
  let path = if let Some(rest) = raw.strip_prefix("file://") {
    let abs = rest.strip_prefix('/')?;
    PathBuf::from(format!("/{abs}"))
  } else if let Some(rest) = raw.strip_prefix("~/") {
    host_home.join(rest)
  } else if raw == "~" {
    host_home.to_path_buf()
  } else {
    let path = PathBuf::from(raw);
    if path.is_absolute() { path } else { root.join(path) }
  };
  path.is_file().then_some(path)
}

fn dial_url(raw: &str) -> Option<Url> {
  let raw = raw.trim();
  let raw = if raw.is_empty() { "nats://localhost:4222" } else { raw };
  if raw.split(',').filter(|part| !part.trim().is_empty()).count() != 1 {
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
  let (username, password) = auth.userinfo();
  let mut url = base.clone();
  url.set_scheme(scheme).ok()?;
  url.set_username(&username).ok()?;
  let empty = password.as_deref() == Some("");
  match password.as_deref() {
    Some(pass) if !pass.is_empty() => {
      url.set_password(Some(pass)).ok()?;
    }
    Some(_) | None => {
      url.set_password(None).ok()?;
    }
  }
  url.set_query(None);
  if !query.is_empty() {
    let mut pairs = url.query_pairs_mut();
    for (key, value) in query {
      pairs.append_pair(key, value);
    }
  }
  let rendered = url.to_string();
  if empty { insert_empty_password(&rendered) } else { Some(rendered) }
}

/// `url` will not keep an empty password, so put the colon back.
fn insert_empty_password(rendered: &str) -> Option<String> {
  let (scheme, rest) = rendered.split_once("://")?;
  let (info, tail) = rest.split_once('@')?;
  if info.contains(':') {
    return Some(rendered.to_string());
  }
  Some(format!("{scheme}://{info}:@{tail}"))
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

fn tls_material(doc: &NatsContext, label: &str, host_home: &Path, root: &Path) -> TlsMaterial {
  if doc.cert.is_empty() && doc.key.is_empty() && doc.ca.is_empty() {
    return TlsMaterial::None;
  }
  if doc.cert.is_empty() != doc.key.is_empty() {
    return TlsMaterial::Skip("cert and key come together");
  }
  let copied = |raw: &str, kind: &str| {
    if raw.is_empty() {
      return Some(None);
    }
    copy_tls(label, kind, raw, host_home, root).map(Some)
  };
  let (Some(cert), Some(key), Some(ca)) = (copied(&doc.cert, "crt"), copied(&doc.key, "key"), copied(&doc.ca, "ca")) else {
    return TlsMaterial::Skip("a tls file named by the context cannot be read");
  };
  TlsMaterial::Files { cert, key, ca }
}

fn copy_tls(label: &str, kind: &str, raw: &str, host_home: &Path, root: &Path) -> Option<(String, (String, Vec<u8>))> {
  let path = resolve_path(raw, host_home, root)?;
  let bytes = fs::read(&path).ok()?;
  let name = format!("nats-{label}.{kind}");
  let container = format!("{GRANTS_STATE_DIR}/rules.d/{name}");
  Some((container, (name, bytes)))
}

fn guest_file(source: Option<&Path>, host_home: &Path, home: &str, fallback: &str) -> (String, String) {
  let fallback_pair = (
    format!("~/.config/nats/decoy/{fallback}"),
    format!("{home}/.config/nats/decoy/{fallback}"),
  );
  let Some(path) = source else {
    return fallback_pair;
  };
  if path.components().any(|component| matches!(component, Component::ParentDir)) {
    return fallback_pair;
  }
  let path = normalize(path);
  let Ok(rest) = path.strip_prefix(host_home) else {
    return fallback_pair;
  };
  if rest.as_os_str().is_empty() {
    return fallback_pair;
  }
  let rel = rest.to_string_lossy().replace('\\', "/");
  if rel.split('/').any(|part| part.is_empty() || part == "..") {
    return fallback_pair;
  }
  (format!("~/{rel}"), format!("{home}/{rel}"))
}

/// Fields the guest may see. Everything else on [`NatsContext`] stays off this struct.
#[derive(Serialize)]
struct DecoyContext {
  #[serde(skip_serializing_if = "String::is_empty")]
  description: String,
  url: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  user: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  password: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  token: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  creds: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  nkey: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  inbox_prefix: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  jetstream_domain: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  jetstream_api_prefix: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  jetstream_event_prefix: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  color_scheme: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  tls_first: Option<bool>,
}

fn decoy_context(doc: &NatsContext, dial: &Url, guest: Option<&GuestCred>, fake: &NatsPlain) -> DecoyContext {
  let mut out = DecoyContext {
    description: doc.description.clone(),
    url: public_url(dial),
    user: String::new(),
    password: String::new(),
    token: String::new(),
    creds: String::new(),
    nkey: String::new(),
    inbox_prefix: doc.inbox_prefix.clone(),
    jetstream_domain: doc.jetstream_domain.clone(),
    jetstream_api_prefix: doc.jetstream_api_prefix.clone(),
    jetstream_event_prefix: doc.jetstream_event_prefix.clone(),
    color_scheme: doc.color_scheme.clone(),
    tls_first: doc.tls_first.then_some(true),
  };
  match fake {
    NatsPlain::UserPass { user, pass } => {
      out.user.clone_from(user);
      out.password.clone_from(pass);
    }
    NatsPlain::Token(token) => out.token.clone_from(token),
    NatsPlain::Nkey(_) => {
      if let Some(guest) = guest {
        out.nkey.clone_from(&guest.written);
      }
    }
    NatsPlain::Creds { .. } => {
      if let Some(guest) = guest {
        out.creds.clone_from(&guest.written);
      }
    }
  }
  out
}

fn mint_seed() -> Result<(String, String), Error> {
  let pair = nkeys::KeyPair::new_user();
  let seed = pair.seed().map_err(|_source| Error::NatsDecoy)?;
  Ok((seed, pair.public_key()))
}

fn decoy_jwt(public: &str) -> String {
  let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
  let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{public}"}}"#).as_bytes());
  let sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
  format!("{header}.{payload}.{sig}")
}

fn decorate_creds(jwt: &str, seed: &str) -> String {
  format!("{JWT_BEGIN}\n{jwt}\n{JWT_END}\n\n{SEED_BEGIN}\n{seed}\n{SEED_END}\n")
}

#[cfg(test)]
mod tests {
  use arkham_config::config::RuleCfg;
  use pretty_assertions::assert_eq;
  use secrecy::ExposeSecret as _;
  use serde::Deserialize;
  use serde_json::Value;
  use tempfile::tempdir;

  use super::*;

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

  fn creds_file(seed: &str, jwt: &str) -> String {
    decorate_creds(jwt, seed)
  }

  fn write_context(root: &Path, name: &str, body: &str) {
    fs::create_dir_all(root.join("context")).unwrap();
    fs::write(root.join("context.txt"), format!("{name}\n")).unwrap();
    fs::write(root.join("context").join(format!("{name}.json")), body).unwrap();
  }

  fn adapted(root: &Path, home: &Path) -> AdaptedNats {
    adapt(root, "/home/eng", home).expect("adapt").expect("selected context maps")
  }

  fn rule_of(found: &AdaptedNats) -> RuleCfg {
    let doc: RulesDoc = toml::from_str(&found.adapted[0].fragment).expect("fragment");
    doc.rules.into_values().next().expect("one rule")
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
    let decoy: Value = serde_json::from_str(&found.adapted[0].decoy).unwrap();
    assert_eq!(decoy["user"], "agent");
    assert_eq!(decoy["tls_first"], true);
    assert_eq!(decoy["jetstream_domain"], "app");
    assert_ne!(decoy["password"], "real-nats-pass");
    assert!(!found.adapted[0].decoy.contains("real-nats-pass"));
    assert!(!found.adapted[0].decoy.contains("other-real-pass"));
    let mounted = found.adapted[0]
      .decoy_files
      .iter()
      .any(|file| file.container == "/home/eng/.config/nats/context.txt");
    assert!(mounted);
    assert_eq!(found.context_dest, "/home/eng/.config/nats/context/demo.json");
  }

  #[test]
  fn creds_file_is_read_for_the_grant_and_replaced_for_the_guest() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone()))
      .unwrap()
      .public_key()
      .to_string();
    let jwt = user_jwt(&public);
    let creds = home.path().join(".nkeys").join("user.creds");
    fs::create_dir_all(creds.parent().unwrap()).unwrap();
    fs::write(&creds, creds_file(&seed, &jwt)).unwrap();
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
    let guest = found.adapted[0]
      .decoy_files
      .iter()
      .find(|file| file.container.contains("user.creds"))
      .expect("mirrored creds");
    let guest_text = String::from_utf8(guest.bytes.clone()).unwrap();
    assert!(guest_text.contains(JWT_BEGIN));
    assert!(guest_text.contains(SEED_BEGIN));
    assert!(!guest_text.contains(&seed));
    assert!(!guest_text.contains(&jwt));
    assert!(!found.adapted[0].decoy.contains(&seed));
    assert!(!found.adapted[0].decoy.contains(&jwt));
    let decoy: Value = serde_json::from_str(&found.adapted[0].decoy).unwrap();
    assert!(decoy["creds"].as_str().unwrap().contains(".nkeys/user.creds"));
  }

  #[test]
  fn nkey_file_and_token_and_unmapped_contexts() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let nkey = root.join("operator.nk");
    fs::create_dir_all(&root).unwrap();
    fs::write(&nkey, format!("# operator key\n{seed}\n")).unwrap();
    write_context(
      &root,
      "keyed",
      &format!(r#"{{"url":"nats://127.0.0.1:4222","nkey":"{}"}}"#, nkey.display()),
    );
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let real = rule.real.unwrap().expose_secret().to_string();
    assert!(real.contains(&seed));
    let guest = &found.adapted[0]
      .decoy_files
      .iter()
      .find(|file| file.container.ends_with("operator.nk"))
      .unwrap()
      .bytes;
    let guest = String::from_utf8(guest.clone()).unwrap();
    assert!(!guest.contains(&seed));
    NatsSeed::from_seed(SecretString::from(guest.trim().to_string())).expect("decoy seed");

    write_context(&root, "tok", r#"{"url":"","token":"real-token"}"#);
    let found = adapted(&root, home.path());
    let rule = rule_of(&found);
    let real = rule.real.unwrap();
    assert!(real.expose_secret().contains("real-token"));
    assert!(real.expose_secret().contains("localhost"));
    assert!(!found.adapted[0].decoy.contains("real-token"));

    write_context(&root, "bad", r#"{"url":"nats://a:4222,nats://b:4222","token":"real-token"}"#);
    assert!(adapt(&root, "/home/eng", home.path()).unwrap().is_none());
    write_context(
      &root,
      "nsc",
      r#"{"url":"nats://nats.internal:4222","nsc":"nsc://operator/account/user"}"#,
    );
    assert!(adapt(&root, "/home/eng", home.path()).unwrap().is_none());
  }

  #[test]
  fn traversal_creds_path_stays_inside_the_decoy_dir() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone()))
      .unwrap()
      .public_key()
      .to_string();
    let jwt = user_jwt(&public);
    let ssh = home.path().join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    fs::write(ssh.join("config"), creds_file(&seed, &jwt)).unwrap();
    write_context(&root, "demo", r#"{"url":"nats://nats.internal:4222","creds":"../../.ssh/config"}"#);
    let found = adapted(&root, home.path());
    let containers: Vec<&str> = found.adapted[0].decoy_files.iter().map(|file| file.container.as_str()).collect();
    assert!(containers.iter().all(|path| !path.contains("..")), "{containers:?}");
    assert!(
      containers.iter().any(|path| path.starts_with("/home/eng/.config/nats/decoy/")),
      "{containers:?}"
    );
    let guest = found.adapted[0]
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
    let public = NatsSeed::from_seed(SecretString::from(seed.clone()))
      .unwrap()
      .public_key()
      .to_string();
    let jwt = user_jwt(&public);
    let creds = root.join("creds");
    fs::create_dir_all(&creds).unwrap();
    fs::write(creds.join("user.creds"), creds_file(&seed, &jwt)).unwrap();
    write_context(&root, "demo", r#"{"url":"nats://nats.internal:4222","creds":"creds/user.creds"}"#);
    let found = adapted(&root, home.path());
    let guest = found.adapted[0]
      .decoy_files
      .iter()
      .find(|file| file.container.ends_with("/.config/nats/creds/user.creds"))
      .expect("mirrored relative creds");
    let guest_text = String::from_utf8(guest.bytes.clone()).unwrap();
    assert!(!guest_text.contains(&seed));
  }

  #[test]
  fn symlink_creds_mounts_at_the_lexical_path() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone()))
      .unwrap()
      .public_key()
      .to_string();
    let jwt = user_jwt(&public);
    let outside = home.path().join("outside.creds");
    fs::write(&outside, creds_file(&seed, &jwt)).unwrap();
    let creds = root.join("creds");
    fs::create_dir_all(&creds).unwrap();
    std::os::unix::fs::symlink(&outside, creds.join("link.creds")).unwrap();
    write_context(&root, "demo", r#"{"url":"nats://nats.internal:4222","creds":"creds/link.creds"}"#);
    let found = adapted(&root, home.path());
    let guest = found.adapted[0]
      .decoy_files
      .iter()
      .find(|file| file.container == "/home/eng/.config/nats/creds/link.creds")
      .expect("lexical symlink path");
    let guest_text = String::from_utf8(guest.bytes.clone()).unwrap();
    assert!(!guest_text.contains(&seed));
    assert!(rule_of(&found).real.unwrap().expose_secret().contains(&seed));
    assert!(
      !found.adapted[0]
        .decoy_files
        .iter()
        .any(|file| file.container.contains("outside.creds"))
    );
  }

  #[test]
  fn unknown_context_field_is_absent_from_the_decoy() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(
      &root,
      "demo",
      r#"{"url":"nats://nats.internal:4222","token":"real-token","description":"kept","operator_note":"not-for-the-guest"}"#,
    );
    let found = adapted(&root, home.path());
    assert!(!found.adapted[0].decoy.contains("not-for-the-guest"));
    assert!(!found.adapted[0].decoy.contains("operator_note"));
    assert!(found.adapted[0].decoy.contains("kept"));
  }

  #[test]
  fn short_banner_creds_file_still_grants() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone()))
      .unwrap()
      .public_key()
      .to_string();
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
        .map(|field| (field.name.as_str(), field.pair.fake.as_str(), field.pair.real.expose_secret()))
        .collect::<Vec<_>>(),
      vec![("user", "agent", "agent"), ("pass", "", "")]
    );
  }

  #[test]
  fn inline_nkey_text_is_not_a_path() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    let seed = user_seed();
    write_context(&root, "demo", &format!(r#"{{"url":"nats://nats.internal:4222","nkey":"{seed}"}}"#));
    assert!(adapt(&root, "/home/eng", home.path()).unwrap().is_none());
  }
}
