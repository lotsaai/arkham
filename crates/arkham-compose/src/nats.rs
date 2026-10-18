//! NATS CLI context adapter.
//!
//! A symlink is not canonicalized: the read follows it, and the decoy
//! mounts at the path the context named. `guest_tls_mode` is not derived.
//! The context describes the upstream dial, and the guest leg's mode stays
//! on the rule `tls` table.
//!
//! async-nats 0.50 keeps `parse_jwt_and_key_from_creds` private; the banner
//! regex below is that crate's `USER_CONFIG_RE`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use arkham_config::config::IfMissing;
use arkham_config::grants::{NatsPlain, NatsScope, NatsSeed, check_user_jwt};
use regex::Regex;
use secrecy::SecretString;
use serde_json::{Map, Value};
use url::Url;

/// The credentials-file regex from async-nats 0.50 `auth_utils`. The first
/// capture is the user JWT and the second is the nkey seed.
static USER_CONFIG_RE: LazyLock<Regex> = LazyLock::new(|| {
  Regex::new(r"\s*(?:(?:[-]{3,}.*[-]{3,}\r?\n)([\w\-.=]+)(?:\r?\n[-]{3,}.*[-]{3,}\r?\n))").expect("async-nats USER_CONFIG_RE is a constant")
});

use crate::adapt::{BLOB_PREFIX_NATS, DecoyFile, GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, render_fragment, rewrite_label};
use crate::error::Error;
use crate::paths::{normalize, path_under_home};

const DROPPED_KEYS: &[&str] = &[
  "cert",
  "key",
  "ca",
  "user_seed",
  "user_jwt",
  "socks_proxy",
  "nsc",
  "user",
  "password",
  "token",
  "creds",
  "nkey",
];

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
  let Ok(value) = serde_json::from_str::<Value>(&body) else {
    tracing::warn!(source = %path.display(), "nats source skipped: the context is not json");
    return Ok(None);
  };
  let Some(doc) = value.as_object() else {
    tracing::warn!(source = %path.display(), "nats source skipped: the context is not a context object");
    return Ok(None);
  };
  map_context(&path, name, doc, home, host_home, root)
}

fn context_name(text: &str) -> Option<&str> {
  let name = text.trim();
  if name.is_empty() || name.contains(['/', '\\']) || name.contains("..") {
    None
  } else {
    Some(name)
  }
}

fn text<'a>(doc: &'a Map<String, Value>, key: &str) -> &'a str {
  doc.get(key).and_then(Value::as_str).unwrap_or("")
}

fn occupied(doc: &Map<String, Value>, key: &str) -> bool {
  match doc.get(key) {
    Some(Value::String(value)) => !value.is_empty(),
    Some(Value::Array(values)) => !values.is_empty(),
    Some(Value::Null) | None => false,
    Some(_) => true,
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
  if occupied(doc, "windows_cert_store") || occupied(doc, "socks_proxy") || occupied(doc, "nsc") {
    tracing::warn!(source = %path.display(), reason = "windows cert store, socks proxy, and nsc are not derived", "nats context skipped");
    return Ok(None);
  }
  let Some(dial) = dial_url(text(doc, "url")) else {
    tracing::warn!(source = %path.display(), reason = "the server url is not one nats:// or tls:// address", "nats context skipped");
    return Ok(None);
  };
  let Some(found) = found_cred(doc, host_home, root) else {
    tracing::warn!(source = %path.display(), reason = "the credential does not map onto one auth method", "nats context skipped");
    return Ok(None);
  };
  let label = rewrite_label(path, name)?;
  let env = label.to_uppercase().replace('-', "_");
  let real_tls = dial.scheme() == "tls" || matches!(doc.get("tls_first"), Some(Value::Bool(true)));
  if !real_tls && (!text(doc, "cert").is_empty() || !text(doc, "key").is_empty() || !text(doc, "ca").is_empty()) {
    tracing::warn!(source = %path.display(), reason = "tls material on a cleartext server url is not derived", "nats context skipped");
    return Ok(None);
  }
  let mut query: Vec<(String, String)> = Vec::new();
  let mut materialized = Vec::new();
  if real_tls && matches!(doc.get("tls_first"), Some(Value::Bool(true))) {
    query.push(("handshake_first".to_string(), "true".to_string()));
  }
  if real_tls {
    match tls_material(doc, &label, host_home, root) {
      TlsMaterial::None => {}
      TlsMaterial::Skip(reason) => {
        tracing::warn!(source = %path.display(), reason, "nats context skipped");
        return Ok(None);
      }
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
    tracing::warn!(source = %path.display(), reason = "the decoy connection string could not be built", "nats context skipped");
    return Ok(None);
  };
  let real_scheme = if real_tls { "tls" } else { "nats" };
  let Some(real) = auth_url(&dial, real_scheme, &found.real, &query_ref) else {
    tracing::warn!(source = %path.display(), reason = "the real connection string could not be built", "nats context skipped");
    return Ok(None);
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

fn found_cred(doc: &Map<String, Value>, host_home: &Path, root: &Path) -> Option<FoundCred> {
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
      source: None,
    });
  }
  if !password.is_empty() {
    return None;
  }
  if !creds.is_empty() {
    let (seed, jwt) = load_creds(creds, host_home, root)?;
    return Some(FoundCred {
      real: NatsPlain::Creds { seed, jwt },
      source: resolve_path(creds, host_home, root),
    });
  }
  if !nkey.is_empty() {
    let path = resolve_path(nkey, host_home, root)?;
    let seed = nkey_file(&path)?;
    return Some(FoundCred {
      real: NatsPlain::Nkey(seed),
      source: Some(path),
    });
  }
  if !user_jwt.is_empty() && !user_seed.is_empty() {
    let seed = load_user_seed(user_seed, host_home, root)?;
    let jwt = load_jwt(user_jwt, host_home, root)?;
    let parsed = NatsSeed::from_seed(SecretString::from(seed.clone())).ok()?;
    check_user_jwt(&jwt, &parsed.public).ok()?;
    return Some(FoundCred {
      real: NatsPlain::Creds { seed, jwt },
      source: None,
    });
  }
  if !user_jwt.is_empty() {
    return None;
  }
  if !token.is_empty() {
    return Some(FoundCred {
      real: NatsPlain::Token(token.to_string()),
      source: None,
    });
  }
  None
}

fn load_creds(raw: &str, host_home: &Path, root: &Path) -> Option<(String, String)> {
  let path = resolve_path(raw, host_home, root)?;
  let text = fs::read_to_string(path).ok()?;
  let mut found = USER_CONFIG_RE.captures_iter(&text);
  let jwt = found.next()?.get(1)?.as_str().to_string();
  let seed = found.next()?.get(1)?.as_str().to_string();
  let parsed = NatsSeed::from_seed(SecretString::from(seed.clone())).ok()?;
  check_user_jwt(&jwt, &parsed.public).ok()?;
  Some((seed, jwt))
}

fn nkey_file(path: &Path) -> Option<String> {
  let text = fs::read_to_string(path).ok()?;
  let seed = text.trim();
  NatsSeed::from_seed(SecretString::from(seed.to_string())).ok()?;
  Some(seed.to_string())
}

fn load_user_seed(raw: &str, host_home: &Path, root: &Path) -> Option<String> {
  if NatsSeed::from_seed(SecretString::from(raw.to_string())).is_ok() {
    return Some(raw.to_string());
  }
  let path = resolve_path(raw, host_home, root)?;
  nkey_file(&path)
}

/// Go `natscontext` passes this literal to `nats.UserJWTAndSeed`.
fn load_jwt(raw: &str, host_home: &Path, root: &Path) -> Option<String> {
  let text = if let Some(path) = resolve_path(raw, host_home, root) {
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

fn resolve_path(raw: &str, host_home: &Path, root: &Path) -> Option<PathBuf> {
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

fn tls_material(doc: &Map<String, Value>, label: &str, host_home: &Path, root: &Path) -> TlsMaterial {
  let cert = text(doc, "cert");
  let key = text(doc, "key");
  let ca = text(doc, "ca");
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
  let (Some(cert), Some(key), Some(ca)) = (copied(cert, "crt"), copied(key, "key"), copied(ca, "ca")) else {
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
  let Some(rel) = path_under_home(&normalize(path), host_home) else {
    return fallback_pair;
  };
  (format!("~/{rel}"), format!("{home}/{rel}"))
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
    let guest = &found.adapted[0]
      .decoy_files
      .iter()
      .find(|file| file.container.ends_with("operator.nk"))
      .unwrap()
      .bytes;
    let guest = String::from_utf8(guest.clone()).unwrap();
    assert!(!guest.contains(&seed));
    NatsSeed::from_seed(SecretString::from(guest.trim().to_string())).expect("decoy seed");
    fs::write(&nkey, format!("# operator key\n{seed}\n")).unwrap();
    assert!(adapt(&root, "/home/eng", home.path()).unwrap().is_none());

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
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public.clone();
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
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public.clone();
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
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public.clone();
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
  fn unknown_context_field_stays_on_the_decoy_and_secret_keys_do_not() {
    let home = tempdir().unwrap();
    let root = home.path().join(".config").join("nats");
    write_context(
      &root,
      "demo",
      r#"{"url":"nats://nats.internal:4222","user":"agent","password":"real-token","description":"kept","name":"demo","operator_note":"kept-too","windows_cert_match":"subject","user_jwt":"eyJhbGci.e30.sig"}"#, // betterleaks:allow
    );
    let found = adapted(&root, home.path());
    let decoy: Value = serde_json::from_str(&found.adapted[0].decoy).unwrap();
    assert_eq!(decoy["description"], "kept");
    assert_eq!(decoy["name"], "demo");
    assert_eq!(decoy["operator_note"], "kept-too");
    assert!(decoy.get("windows_cert_match").is_none());
    assert!(decoy.get("user_jwt").is_none());
    assert!(!found.adapted[0].decoy.contains("real-token"));
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
    assert!(!found.adapted[0].decoy.contains(password));

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
    assert!(adapt(&root, "/home/eng", home.path()).unwrap().is_none());
    fs::write(&creds, format!("{jwt}\n{seed}\n")).unwrap();
    assert!(adapt(&root, "/home/eng", home.path()).unwrap().is_none());
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
