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
//! and a comma-separated server list are not read. async-nats 0.50 keeps
//! `parse_jwt_and_key_from_creds` private; the banner regex below is that
//! crate's `USER_CONFIG_RE`. `nkeys` 0.4 parses a seed.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use arkham_config::config::IfMissing;
use arkham_config::grants::{NatsPlain, NatsScope, NatsSeed};
use regex::Regex;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::Url;

/// The credentials-file regex from async-nats 0.50 `auth_utils`. The first
/// capture is the user JWT and the second is the nkey seed. A pattern that
/// does not compile yields no credential.
static USER_CONFIG_RE: LazyLock<Option<Regex>> =
  LazyLock::new(|| Regex::new(r"\s*(?:(?:[-]{3,}.*[-]{3,}\r?\n)([\w\-.=]+)(?:\r?\n[-]{3,}.*[-]{3,}\r?\n))").ok());

use crate::adapt::{BLOB_PREFIX_NATS, DecoyFile, GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, render_fragment, rewrite_label};
use crate::error::Error;
use crate::paths::normalize;

fn trimmed<'de, D>(deserializer: D) -> Result<String, D::Error>
where
  D: serde::Deserializer<'de>,
{
  let value = String::deserialize(deserializer)?;
  Ok(value.trim().to_string())
}

/// One context file. Unknown JSON keys are dropped. Secret fields stay on
/// this struct for the grant and are copied onto the decoy only when they
/// are the rewritten auth field. `Debug` redacts the secret fields.
#[derive(Deserialize)]
struct NatsContext {
  #[serde(default, deserialize_with = "trimmed")]
  description: String,
  #[serde(default, deserialize_with = "trimmed")]
  url: String,
  #[serde(default, deserialize_with = "trimmed")]
  user: String,
  #[serde(default, deserialize_with = "trimmed")]
  password: String,
  #[serde(default, deserialize_with = "trimmed")]
  token: String,
  #[serde(default, deserialize_with = "trimmed")]
  creds: String,
  #[serde(default, deserialize_with = "trimmed")]
  nkey: String,
  #[serde(default, deserialize_with = "trimmed")]
  cert: String,
  #[serde(default, deserialize_with = "trimmed")]
  key: String,
  #[serde(default, deserialize_with = "trimmed")]
  ca: String,
  #[serde(default, deserialize_with = "trimmed")]
  nsc: String,
  #[serde(default, deserialize_with = "trimmed")]
  inbox_prefix: String,
  #[serde(default, deserialize_with = "trimmed")]
  jetstream_domain: String,
  #[serde(default, deserialize_with = "trimmed")]
  jetstream_api_prefix: String,
  #[serde(default, deserialize_with = "trimmed")]
  jetstream_event_prefix: String,
  #[serde(default, deserialize_with = "trimmed")]
  user_jwt: String,
  #[serde(default, deserialize_with = "trimmed")]
  user_seed: String,
  #[serde(default, deserialize_with = "trimmed")]
  color_scheme: String,
  #[serde(default)]
  tls_first: bool,
  #[serde(default, deserialize_with = "trimmed")]
  socks_proxy: String,
  #[serde(default, deserialize_with = "trimmed")]
  windows_cert_store: String,
}

impl std::fmt::Debug for NatsContext {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("NatsContext")
      .field("url", &self.url)
      .field("user", &self.user)
      .field("password", &"redacted")
      .field("token", &"redacted")
      .field("user_seed", &"redacted")
      .field("user_jwt", &"redacted")
      .finish_non_exhaustive()
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
  let Ok(doc) = serde_json::from_str::<NatsContext>(&body) else {
    tracing::warn!(source = %path.display(), "nats source skipped: the context is not a context object");
    return Ok(None);
  };
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
  let Some(found) = found_cred(doc, host_home, root) else {
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
  let (fake_auth, guest) = wire_auth(&found, &env, host_home, home, &label)?;
  let query_ref: Vec<(&str, &str)> = query.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
  let Some(fake) = auth_url(&dial, dial.scheme(), &fake_auth, &[]) else {
    return Ok(skip(path, "the decoy connection string could not be built"));
  };
  let real_scheme = if real_tls { "tls" } else { "nats" };
  let Some(real) = auth_url(&dial, real_scheme, &found.real, &query_ref) else {
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
    name: format!("{BLOB_PREFIX_NATS}context-txt"),
    bytes: format!("{name}\n").into_bytes(),
    container: format!("{home}/.config/nats/context.txt"),
  }];
  if let Some(guest) = guest {
    decoy_files.push(DecoyFile {
      name: format!("{BLOB_PREFIX_NATS}{label}.credential"),
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

/// Real credential plus the file the context named, when it named one.
struct FoundCred {
  real: NatsPlain,
  source: Option<PathBuf>,
}

fn wire_auth(found: &FoundCred, env: &str, host_home: &Path, home: &str, label: &str) -> Result<(NatsPlain, Option<GuestCred>), Error> {
  let prepared = found.real.prepare(env).map_err(|_source| Error::NatsDecoy)?;
  let guest = prepared.file.map(|file| {
    let (written, container) = guest_file(found.source.as_deref(), host_home, home, &format!("{label}.{}", file.suffix));
    GuestCred {
      written,
      container,
      bytes: file.body,
    }
  });
  Ok((prepared.decoy, guest))
}

fn found_cred(doc: &NatsContext, host_home: &Path, root: &Path) -> Option<FoundCred> {
  let other_kind =
    !doc.user.is_empty() || !doc.password.is_empty() || !doc.creds.is_empty() || !doc.nkey.is_empty() || !doc.user_jwt.is_empty();
  if !doc.token.is_empty() && other_kind {
    return None;
  }
  if !doc.user.is_empty() {
    return Some(FoundCred {
      real: NatsPlain::UserPass {
        user: doc.user.clone(),
        pass: doc.password.clone(),
      },
      source: None,
    });
  }
  if !doc.password.is_empty() {
    return None;
  }
  if !doc.creds.is_empty() {
    let (seed, jwt) = load_creds(&doc.creds, host_home, root)?;
    return Some(FoundCred {
      real: NatsPlain::Creds { seed, jwt },
      source: resolve_path(&doc.creds, host_home, root),
    });
  }
  if !doc.nkey.is_empty() {
    let path = resolve_path(&doc.nkey, host_home, root)?;
    let seed = accepted_seed(&fs::read_to_string(&path).ok()?)?;
    return Some(FoundCred {
      real: NatsPlain::Nkey(seed),
      source: Some(path),
    });
  }
  if !doc.user_jwt.is_empty() && !doc.user_seed.is_empty() {
    let seed = load_user_seed(&doc.user_seed, host_home, root)?;
    let jwt = load_jwt(&doc.user_jwt, host_home, root)?;
    let parsed = NatsSeed::from_seed(SecretString::from(seed.clone())).ok()?;
    if !parsed.matches_user_jwt(&jwt) {
      return None;
    }
    return Some(FoundCred {
      real: NatsPlain::Creds { seed, jwt },
      source: None,
    });
  }
  if !doc.user_jwt.is_empty() {
    return None;
  }
  if !doc.token.is_empty() {
    return Some(FoundCred {
      real: NatsPlain::Token(doc.token.clone()),
      source: None,
    });
  }
  None
}

fn load_creds(raw: &str, host_home: &Path, root: &Path) -> Option<(String, String)> {
  let path = resolve_path(raw, host_home, root)?;
  let text = fs::read_to_string(path).ok()?;
  let jwt = decorated_jwt(&text)?;
  let seed = decorated_seed(&text)?;
  let parsed = NatsSeed::from_seed(SecretString::from(seed.clone())).ok()?;
  parsed.matches_user_jwt(&jwt).then_some((seed, jwt))
}

fn load_user_seed(raw: &str, host_home: &Path, root: &Path) -> Option<String> {
  if let Some(seed) = accepted_seed(raw) {
    return Some(seed);
  }
  let path = resolve_path(raw, host_home, root)?;
  accepted_seed(&fs::read_to_string(path).ok()?)
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

fn decorated_jwt(text: &str) -> Option<String> {
  if let Some(re) = USER_CONFIG_RE.as_ref()
    && let Some(matched) = re.captures_iter(text).next()
    && let Some(group) = matched.get(1)
  {
    return Some(group.as_str().to_string());
  }
  let trimmed = text.trim();
  let bare = trimmed.lines().count() == 1
    && !trimmed.is_empty()
    && trimmed
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'='));
  bare.then(|| trimmed.to_string())
}

fn decorated_seed(text: &str) -> Option<String> {
  if let Some(re) = USER_CONFIG_RE.as_ref()
    && let Some(matched) = re.captures_iter(text).nth(1)
    && let Some(group) = matched.get(1)
  {
    return Some(group.as_str().to_string());
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
  let name = format!("{BLOB_PREFIX_NATS}{label}.{kind}");
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
  let auth = fake.context_auth(guest.map(|guest| guest.written.as_str()));
  DecoyContext {
    description: doc.description.clone(),
    url: public_url(dial),
    user: auth.user,
    password: auth.password,
    token: auth.token,
    creds: auth.creds,
    nkey: auth.nkey,
    inbox_prefix: doc.inbox_prefix.clone(),
    jetstream_domain: doc.jetstream_domain.clone(),
    jetstream_api_prefix: doc.jetstream_api_prefix.clone(),
    jetstream_event_prefix: doc.jetstream_event_prefix.clone(),
    color_scheme: doc.color_scheme.clone(),
    tls_first: doc.tls_first.then_some(true),
  }
}

#[cfg(test)]
mod tests {
  use arkham_config::config::RuleCfg;
  use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
  use pretty_assertions::assert_eq;
  use secrecy::ExposeSecret as _;
  use serde::Deserialize;
  use serde_json::Value;
  use tempfile::tempdir;

  use super::*;

  const JWT_BEGIN: &str = "-----BEGIN NATS USER JWT-----";
  const JWT_END: &str = "------END NATS USER JWT------";
  const SEED_BEGIN: &str = "-----BEGIN USER NKEY SEED-----";
  const SEED_END: &str = "------END USER NKEY SEED------";

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

  fn rule_of(found: &AdaptedNats) -> RuleCfg {
    let doc: RulesDoc = toml::from_str(&found.adapted[0].fragment).expect("fragment");
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
    fs::write(ssh.join("config"), decorate_creds(&jwt, &seed)).unwrap();
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
    fs::write(creds.join("user.creds"), decorate_creds(&jwt, &seed)).unwrap();
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
    fs::write(&outside, decorate_creds(&jwt, &seed)).unwrap();
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
  fn context_debug_redacts_secrets_and_deserialize_trims() {
    let doc: NatsContext = serde_json::from_str(
      r#"{"user":"  agent  ","password":" ZZZ-PASS ","token":"ZZZ-TOKEN","user_seed":"ZZZ-SEED","user_jwt":"ZZZ-JWT"}"#, // betterleaks:allow
    )
    .unwrap();
    assert_eq!(doc.user, "agent");
    assert_eq!(doc.password, "ZZZ-PASS");
    let shown = format!("{doc:?}");
    assert!(shown.contains("redacted"), "{shown}");
    for secret in ["ZZZ-PASS", "ZZZ-TOKEN", "ZZZ-SEED", "ZZZ-JWT"] {
      assert!(!shown.contains(secret), "{shown}");
    }
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
            field.name.as_str(),
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
    let public = NatsSeed::from_seed(SecretString::from(seed.clone()))
      .unwrap()
      .public_key()
      .to_string();
    let jwt = user_jwt(&public);
    let creds = outside.path().join("user.creds");
    fs::write(&creds, decorate_creds(&jwt, &seed)).unwrap();
    write_context(
      &root,
      "demo",
      &format!(r#"{{"url":"nats://nats.internal:4222","creds":"{}"}}"#, creds.display()),
    );
    let found = adapted(&root, home.path());
    let containers: Vec<&str> = found.adapted[0].decoy_files.iter().map(|file| file.container.as_str()).collect();
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
    let guest = found.adapted[0]
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
    let public = NatsSeed::from_seed(SecretString::from(seed.clone()))
      .unwrap()
      .public_key()
      .to_string();
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
    let guest = found.adapted[0]
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
    assert!(!found.adapted[0].decoy.contains(&seed));
    assert!(!found.adapted[0].decoy.contains(&jwt));
    let scope = NatsScope::from_strings(rule_of(&found).value.unwrap().expose_secret(), &real).expect("inline user jwt");
    assert!(scope.auth.signer().is_some());
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
