//! NATS CLI context adapter. The discovery root is `~/.config/nats`:
//! `context.txt` names the selected context, and
//! `context/<name>.json` holds it. Credential files that context
//! references are read here and never mounted for the guest.
//!
//! The selected context becomes one connection-string grant. The decoy
//! context and decoy credential files are what the guest mounts. Real
//! seeds and JWTs stay in the grant fragment.
//!
//! Checked against the NATS CLI context document and the nsc credentials
//! file: `context.txt`, `context/<name>.json`, the JSON fields below, and
//! the decorated banners. `$XDG_CONFIG_HOME`, `NATS_*` overrides, `nsc://`,
//! and a comma-separated server list are not read.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::config::{IfMissing, fake_for};
use arkham_config::grants::{NatsScope, NatsSeed};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::SecretString;
use serde_json::{Map, Value};
use url::Url;

use crate::adapt::{DecoyFile, GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, render_fragment, rewrite_label};
use crate::error::Error;

/// Official decorated-credential banners. The NATS libraries use these
/// spellings, including the extra dash on `END`.
const JWT_BEGIN: &str = "-----BEGIN NATS USER JWT-----";
const JWT_END: &str = "------END NATS USER JWT------";
const SEED_BEGIN: &str = "-----BEGIN USER NKEY SEED-----";
const SEED_END: &str = "------END USER NKEY SEED------";

/// Secret JSON fields cleared on the decoy context.
const SECRET_FIELDS: [&str; 10] = [
  "password",
  "token",
  "creds",
  "nkey",
  "user_jwt",
  "user_seed",
  "cert",
  "key",
  "ca",
  "nsc",
];

/// One discovered context, ready for the ambient pass.
pub(crate) struct AdaptedNats {
  /// The grant and the decoy files.
  pub(crate) adapted: Vec<RewriteAdapted>,
  /// Container path of the decoy context JSON.
  pub(crate) context_dest: String,
}

/// Username and password of one connection string.
struct WireAuth {
  /// URL username. A token uses this and leaves the password empty.
  username: String,
  /// URL password. Empty for a token.
  password: String,
}

/// Decoy credential file mounted for the guest.
struct GuestCred {
  /// Context field that names the file (`nkey` or `creds`).
  field: &'static str,
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
  let Ok(Value::Object(doc)) = serde_json::from_str::<Value>(&body) else {
    tracing::warn!(source = %path.display(), "nats source skipped: the context is not a JSON object");
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
  doc: &Map<String, Value>,
  home: &str,
  host_home: &Path,
  root: &Path,
) -> Result<Option<AdaptedNats>, Error> {
  if non_empty(doc, "windows_cert_store") || non_empty(doc, "socks_proxy") || non_empty(doc, "nsc") {
    return Ok(skip(path, "windows cert store, socks proxy, and nsc are not derived"));
  }
  let Some(dial) = dial_url(&str_field(doc, "url")) else {
    return Ok(skip(path, "the server url is not one nats:// or tls:// address"));
  };
  let Some(kind) = auth_kind(doc, host_home, root) else {
    return Ok(skip(path, "the credential does not map onto one auth method"));
  };
  let label = rewrite_label(path, name)?;
  let env = label.to_uppercase().replace('-', "_");
  let tls_first = bool_field(doc, "tls_first");
  let real_tls = dial.scheme() == "tls" || tls_first;
  if !real_tls && (non_empty(doc, "cert") || non_empty(doc, "key") || non_empty(doc, "ca")) {
    return Ok(skip(path, "tls material on a cleartext server url is not derived"));
  }
  let mut query: Vec<(String, String)> = Vec::new();
  let mut materialized = Vec::new();
  if real_tls && tls_first {
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
      real: Some(real),
      if_missing: Some(IfMissing::Ignore),
      tls: BTreeMap::new(),
      ssh: BTreeMap::new(),
    },
  )?;
  let decoy_doc = decoy_context(doc, &dial, &kind, guest.as_ref(), &fake_auth);
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
) -> Result<(WireAuth, WireAuth, Option<GuestCred>), Error> {
  match kind {
    AuthKind::UserPass { user, pass } => Ok((
      WireAuth {
        username: user.clone(),
        password: fake_for(env, None),
      },
      WireAuth {
        username: user.clone(),
        password: pass.clone(),
      },
      None,
    )),
    AuthKind::Token(token) => Ok((
      WireAuth {
        username: fake_for(env, None),
        password: String::new(),
      },
      WireAuth {
        username: token.clone(),
        password: String::new(),
      },
      None,
    )),
    AuthKind::Nkey { seed, source } => {
      let (decoy, _) = mint_seed()?;
      let (written, container) = guest_file(source.as_deref(), host_home, home, &format!("{label}.nk"));
      let bytes = format!("{decoy}\n");
      Ok((
        WireAuth {
          username: "nkey".to_string(),
          password: decoy,
        },
        WireAuth {
          username: "nkey".to_string(),
          password: seed.clone(),
        },
        Some(GuestCred {
          field: "nkey",
          written,
          container,
          bytes,
        }),
      ))
    }
    AuthKind::Creds { seed, jwt, source } => {
      let (decoy_seed, public) = mint_seed()?;
      let decoy_token = decoy_jwt(&public);
      let (written, container) = guest_file(source.as_deref(), host_home, home, &format!("{label}.creds"));
      let bytes = decorate_creds(&decoy_token, &decoy_seed);
      Ok((
        WireAuth {
          username: "creds".to_string(),
          password: format!("{decoy_seed}:{decoy_token}"),
        },
        WireAuth {
          username: "creds".to_string(),
          password: format!("{seed}:{jwt}"),
        },
        Some(GuestCred {
          field: "creds",
          written,
          container,
          bytes,
        }),
      ))
    }
  }
}

fn auth_kind(doc: &Map<String, Value>, host_home: &Path, root: &Path) -> Option<AuthKind> {
  let user = str_field(doc, "user");
  let password = str_field(doc, "password");
  let token = str_field(doc, "token");
  let creds = str_field(doc, "creds");
  let nkey = str_field(doc, "nkey");
  let user_jwt = str_field(doc, "user_jwt");
  let user_seed = str_field(doc, "user_seed");
  let kind = if !user.is_empty() {
    if password.is_empty() {
      return None;
    }
    AuthKind::UserPass { user, pass: password }
  } else if !password.is_empty() {
    return None;
  } else if !creds.is_empty() {
    let parsed = load_creds(&creds, host_home, root)?;
    AuthKind::Creds {
      seed: parsed.0,
      jwt: parsed.1,
      source: resolve_path(&creds, host_home, root),
    }
  } else if !nkey.is_empty() {
    AuthKind::Nkey {
      seed: load_seed(&nkey, host_home, root)?,
      source: resolve_path(&nkey, host_home, root),
    }
  } else if !user_jwt.is_empty() && !user_seed.is_empty() {
    AuthKind::Creds {
      jwt: load_jwt(&user_jwt, host_home, root)?,
      seed: load_seed(&user_seed, host_home, root)?,
      source: None,
    }
  } else if !user_jwt.is_empty() {
    return None;
  } else if !token.is_empty() {
    AuthKind::Token(token.clone())
  } else {
    return None;
  };
  if !token.is_empty() && !matches!(kind, AuthKind::Token(_)) {
    None
  } else {
    Some(kind)
  }
}

fn load_creds(raw: &str, host_home: &Path, root: &Path) -> Option<(String, String)> {
  let path = resolve_path(raw, host_home, root)?;
  let text = fs::read_to_string(path).ok()?;
  let jwt = jwt_text(&text)?;
  let seed = accepted_seed(&text)?;
  Some((seed, jwt))
}

fn load_seed(raw: &str, host_home: &Path, root: &Path) -> Option<String> {
  if let Some(seed) = accepted_seed(raw) {
    return Some(seed);
  }
  let path = resolve_path(raw, host_home, root)?;
  accepted_seed(&fs::read_to_string(path).ok()?)
}

fn load_jwt(raw: &str, host_home: &Path, root: &Path) -> Option<String> {
  if let Some(jwt) = jwt_text(raw) {
    return Some(jwt);
  }
  let path = resolve_path(raw, host_home, root)?;
  jwt_text(&fs::read_to_string(path).ok()?)
}

fn accepted_seed(text: &str) -> Option<String> {
  let seed = seed_text(text)?;
  NatsSeed::from_seed(SecretString::from(seed.clone())).ok()?;
  Some(seed)
}

fn seed_text(text: &str) -> Option<String> {
  if text.contains(SEED_BEGIN) {
    return between(text, SEED_BEGIN, SEED_END);
  }
  text
    .lines()
    .map(str::trim)
    .find(|line| !line.is_empty() && !line.starts_with('#'))
    .map(str::to_string)
}

fn jwt_text(text: &str) -> Option<String> {
  if text.contains(JWT_BEGIN) {
    return between(text, JWT_BEGIN, JWT_END);
  }
  let trimmed = text.trim();
  (trimmed.split('.').count() == 3 && !trimmed.chars().any(char::is_whitespace)).then(|| trimmed.to_string())
}

fn between(text: &str, begin: &str, end: &str) -> Option<String> {
  let start = text.find(begin)? + begin.len();
  let rest = text.get(start..)?;
  let stop = rest.find(end)?;
  let body: String = rest.get(..stop)?.split_whitespace().collect();
  if body.is_empty() { None } else { Some(body) }
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

fn auth_url(base: &Url, scheme: &str, auth: &WireAuth, query: &[(&str, &str)]) -> Option<String> {
  let mut url = base.clone();
  url.set_scheme(scheme).ok()?;
  url.set_username(&auth.username).ok()?;
  if auth.password.is_empty() {
    url.set_password(None).ok()?;
  } else {
    url.set_password(Some(&auth.password)).ok()?;
  }
  url.set_query(None);
  if !query.is_empty() {
    let mut pairs = url.query_pairs_mut();
    for (key, value) in query {
      pairs.append_pair(key, value);
    }
  }
  Some(url.to_string())
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

fn tls_material(doc: &Map<String, Value>, label: &str, host_home: &Path, root: &Path) -> TlsMaterial {
  let cert = str_field(doc, "cert");
  let key = str_field(doc, "key");
  let ca = str_field(doc, "ca");
  if cert.is_empty() && key.is_empty() && ca.is_empty() {
    return TlsMaterial::None;
  }
  if cert.is_empty() != key.is_empty() {
    return TlsMaterial::Skip("cert and key come together");
  }
  let copied = |raw: &str, kind: &str| {
    if raw.is_empty() {
      return Some(None);
    }
    copy_tls(label, kind, raw, host_home, root).map(Some)
  };
  let (Some(cert), Some(key), Some(ca)) = (copied(&cert, "crt"), copied(&key, "key"), copied(&ca, "ca")) else {
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
  if let Some(path) = source
    && let Ok(rest) = path.strip_prefix(host_home)
  {
    let rel = rest.to_string_lossy().replace('\\', "/");
    return (format!("~/{rel}"), format!("{home}/{rel}"));
  }
  (
    format!("~/.config/nats/decoy/{fallback}"),
    format!("{home}/.config/nats/decoy/{fallback}"),
  )
}

fn decoy_context(doc: &Map<String, Value>, dial: &Url, kind: &AuthKind, guest: Option<&GuestCred>, fake: &WireAuth) -> Value {
  let mut out = doc.clone();
  for key in SECRET_FIELDS {
    out.insert(key.to_string(), Value::String(String::new()));
  }
  out.insert("user".to_string(), Value::String(String::new()));
  out.insert("url".to_string(), Value::String(public_url(dial)));
  match kind {
    AuthKind::UserPass { user, .. } => {
      out.insert("user".to_string(), Value::String(user.clone()));
      out.insert("password".to_string(), Value::String(fake.password.clone()));
    }
    AuthKind::Token(_) => {
      out.insert("token".to_string(), Value::String(fake.username.clone()));
    }
    AuthKind::Nkey { .. } | AuthKind::Creds { .. } => {
      if let Some(guest) = guest {
        out.insert(guest.field.to_string(), Value::String(guest.written.clone()));
      }
    }
  }
  Value::Object(out)
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

fn str_field(doc: &Map<String, Value>, key: &str) -> String {
  doc.get(key).and_then(Value::as_str).unwrap_or("").trim().to_string()
}

fn bool_field(doc: &Map<String, Value>, key: &str) -> bool {
  doc.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn non_empty(doc: &Map<String, Value>, key: &str) -> bool {
  !str_field(doc, key).is_empty()
}

#[cfg(test)]
mod tests {
  use arkham_config::config::RuleCfg;
  use pretty_assertions::assert_eq;
  use secrecy::ExposeSecret as _;
  use serde::Deserialize;
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
}
