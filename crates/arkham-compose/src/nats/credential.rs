//! One credential reference from a NATS context field.
//!
//! `env://`, `file://`, `op://`, `nsc://`, and `data:` resolve on the host.
//! Anything else is the text. A path expands once.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use arkham_config::grants::{NatsPlain, NatsSeed, check_user_jwt};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use regex::Regex;
use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

use super::NatsSkipCause;

/// Where a context field's credential lives.
#[derive(Debug)]
pub(super) enum CredentialRef {
  /// Text already in the context.
  Literal(String),
  /// A path, expanded once.
  File(PathBuf),
  /// `env://NAME`. The name keeps the reference's case.
  Env(String),
  /// `op://...`, passed to `op read`.
  Op(String),
  /// `nsc://...`, passed to `nsc generate profile`.
  Nsc(String),
  /// Decoded `data:;base64` bytes.
  Data(Vec<u8>),
}

impl CredentialRef {
  /// Classify `raw`. A `file` reference expands once.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when a `data` reference is not base64.
  pub(super) fn parse(raw: &str, host_home: &Path, root: &Path) -> Result<Self, NatsSkipCause> {
    Ok(match scheme_of(raw).as_deref() {
      Some("file") => Self::File(resolve_path(raw, host_home, root)),
      Some("env") => Self::Env(env_name(raw)?),
      Some("op") => Self::Op(format!("op://{}", remainder(raw, "op"))),
      Some("nsc") => Self::Nsc(format!("nsc://{}", remainder(raw, "nsc"))),
      Some("data") => Self::Data(decode_data(raw)?),
      Some(_) | None => Self::Literal(raw.to_string()),
    })
  }

  /// Bytes this reference names. A failed `op` or `nsc` keeps that command's stderr.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when the file, variable, or command is missing.
  pub(super) fn read(&self) -> Result<Vec<u8>, NatsSkipCause> {
    match self {
      Self::Literal(text) => Ok(text.as_bytes().to_vec()),
      Self::File(path) => read_file(path),
      Self::Env(name) => env_bytes(name),
      Self::Op(refer) => command_stdout("op", &["read", refer]),
      Self::Nsc(refer) => read_file(Path::new(&load_profile(refer)?.0)),
      Self::Data(bytes) => Ok(bytes.clone()),
    }
  }

  /// Inline text, or the trimmed text a resolver returns.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when a resolver reference cannot be read.
  pub(super) fn literal_text(raw: &str, host_home: &Path, root: &Path) -> Result<String, NatsSkipCause> {
    if raw.is_empty() {
      return Ok(String::new());
    }
    match Self::parse(raw, host_home, root)? {
      Self::Literal(text) => Ok(text),
      other => utf8(&other.read()?).map(trim_end),
    }
  }

  /// A creds file: a user JWT and a user seed.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when the file is not that pair.
  pub(super) fn creds(raw: &str, host_home: &Path, root: &Path) -> Result<NatsPlain, NatsSkipCause> {
    let (jwt, seed) = creds_parts(&utf8(&read_material(raw, host_home, root)?)?)?;
    plain_creds(seed, jwt)
  }

  /// `user_jwt` with `user_seed`. The JWT `sub` must be that seed's public key.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when either reference fails or the pair does not match.
  pub(super) fn paired(seed_raw: &str, jwt_raw: &str, host_home: &Path, root: &Path) -> Result<NatsPlain, NatsSkipCause> {
    plain_creds(
      Self::user_seed(seed_raw, host_home, root)?,
      Self::user_jwt(jwt_raw, host_home, root)?,
    )
  }

  /// An nkey file. Inline seed text is not a path.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when the file is not a user nkey seed.
  pub(super) fn nkey(raw: &str, host_home: &Path, root: &Path) -> Result<String, NatsSkipCause> {
    seed_in(&utf8(&read_material(raw, host_home, root)?)?).ok_or_else(NatsSkipCause::credential)
  }

  /// A user seed, a resolver, or a file of one seed.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when none of those is a user nkey seed.
  pub(super) fn user_seed(raw: &str, host_home: &Path, root: &Path) -> Result<String, NatsSkipCause> {
    text_or_file(raw, host_home, root, seed_in)
  }

  /// A user JWT, a resolver, or a file whose text is one.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when none of those yields a JWT line.
  pub(super) fn user_jwt(raw: &str, host_home: &Path, root: &Path) -> Result<String, NatsSkipCause> {
    text_or_file(raw, host_home, root, jwt_text)
  }

  /// A TLS file. Empty is absent. Only `file` and a bare path are files.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::TlsFile`] when the reference is another scheme or cannot be read.
  pub(super) fn tls_file(raw: &str, host_home: &Path, root: &Path) -> Result<Option<Vec<u8>>, NatsSkipCause> {
    if raw.is_empty() {
      return Ok(None);
    }
    if scheme_of(raw).is_some_and(|scheme| scheme != "file") {
      return Err(NatsSkipCause::TlsFile);
    }
    std::fs::read(resolve_path(raw, host_home, root))
      .map(Some)
      .map_err(|_source| NatsSkipCause::TlsFile)
  }

  /// Creds path and operator service list from `nsc generate profile`.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when `nsc` fails or the profile has no creds file.
  pub(super) fn nsc_profile(raw: &str) -> Result<(String, String), NatsSkipCause> {
    let refer = match scheme_of(raw).as_deref() {
      Some("nsc") => format!("nsc://{}", remainder(raw, "nsc")),
      _ => format!("nsc://{raw}"),
    };
    load_profile(&refer)
  }
}

fn read_material(raw: &str, host_home: &Path, root: &Path) -> Result<Vec<u8>, NatsSkipCause> {
  match CredentialRef::parse(raw, host_home, root)? {
    CredentialRef::Literal(text) => read_file(&resolve_path(&text, host_home, root)),
    other => other.read(),
  }
}

fn text_or_file(raw: &str, host_home: &Path, root: &Path, pick: fn(&str) -> Option<String>) -> Result<String, NatsSkipCause> {
  let resolved = CredentialRef::literal_text(raw, host_home, root)?;
  if let Some(found) = pick(&resolved) {
    return Ok(found);
  }
  pick(&read_file_string(&resolve_path(&resolved, host_home, root))?).ok_or_else(NatsSkipCause::credential)
}

fn plain_creds(seed: String, jwt: String) -> Result<NatsPlain, NatsSkipCause> {
  let parsed = NatsSeed::from_seed(SecretString::from(seed.clone())).map_err(|_source| NatsSkipCause::credential())?;
  check_user_jwt(&jwt, &parsed.public).map_err(|_source| NatsSkipCause::credential())?;
  Ok(NatsPlain::Creds { seed, jwt })
}

fn read_file(path: &Path) -> Result<Vec<u8>, NatsSkipCause> {
  std::fs::read(path).map_err(|_source| NatsSkipCause::credential())
}

fn read_file_string(path: &Path) -> Result<String, NatsSkipCause> {
  utf8(&read_file(path)?)
}

fn utf8(bytes: &[u8]) -> Result<String, NatsSkipCause> {
  String::from_utf8(bytes.to_vec()).map_err(|_source| NatsSkipCause::credential())
}

fn trim_end(mut text: String) -> String {
  while text.ends_with(['\r', '\n']) {
    text.pop();
  }
  text
}

fn env_name(raw: &str) -> Result<String, NatsSkipCause> {
  let name = remainder(raw, "env");
  if name.is_empty() {
    Err(NatsSkipCause::credential())
  } else {
    Ok(name.to_string())
  }
}

fn env_bytes(name: &str) -> Result<Vec<u8>, NatsSkipCause> {
  match std::env::var(name) {
    Ok(value) if !value.is_empty() => Ok(value.into_bytes()),
    _ => Err(NatsSkipCause::credential()),
  }
}

fn scheme_of(raw: &str) -> Option<String> {
  Url::parse(raw).ok().map(|url| url.scheme().to_owned())
}

fn remainder<'a>(raw: &'a str, scheme: &str) -> &'a str {
  match raw.split_once("://") {
    Some((head, rest)) if head.eq_ignore_ascii_case(scheme) => rest,
    _ => raw,
  }
}

fn resolve_path(raw: &str, host_home: &Path, root: &Path) -> PathBuf {
  let home = host_home.to_string_lossy().into_owned();
  let expanded =
    shellexpand::full_with_context_no_errors(strip_file(raw), || Some(home), |key| Some(std::env::var(key).unwrap_or_default()));
  let path = PathBuf::from(expanded.as_ref());
  if path.is_absolute() { path } else { root.join(path) }
}

fn strip_file(raw: &str) -> &str {
  if scheme_of(raw).as_deref() == Some("file") {
    return remainder(raw, "file");
  }
  let Some(head) = raw.get(.."file://".len()) else {
    return raw;
  };
  if head.eq_ignore_ascii_case("file://") {
    &raw["file://".len()..]
  } else {
    raw
  }
}

fn decode_data(raw: &str) -> Result<Vec<u8>, NatsSkipCause> {
  let rest = raw.split_once(':').map_or(raw, |(_, rest)| rest);
  let (header, payload) = rest.split_once(',').ok_or_else(NatsSkipCause::credential)?;
  if !header.split(';').any(|part| part.trim() == "base64") {
    return Err(NatsSkipCause::credential());
  }
  STANDARD.decode(payload).map_err(|_source| NatsSkipCause::credential())
}

fn command_stdout(program: &str, args: &[&str]) -> Result<Vec<u8>, NatsSkipCause> {
  let output = Command::new(program)
    .args(args)
    .output()
    .map_err(|_source| NatsSkipCause::credential())?;
  if output.status.success() {
    Ok(output.stdout)
  } else {
    Err(NatsSkipCause::credential_output(&output.stderr))
  }
}

fn load_profile(refer: &str) -> Result<(String, String), NatsSkipCause> {
  let stdout = command_stdout("nsc", &["generate", "profile", refer])?;
  let profile = serde_json::from_slice::<NscProfile>(&stdout).map_err(|_source| NatsSkipCause::credential())?;
  if profile.user_creds.is_empty() {
    return Err(NatsSkipCause::credential());
  }
  Ok((profile.user_creds, profile.operator.service.join(",")))
}

#[derive(Deserialize)]
struct NscProfile {
  user_creds: String,
  #[serde(default)]
  operator: NscOperator,
}

#[derive(Deserialize, Default)]
struct NscOperator {
  #[serde(default)]
  service: Vec<String>,
}

fn seed_in(text: &str) -> Option<String> {
  let trimmed = text.trim();
  NatsSeed::from_seed(SecretString::from(trimmed.to_string())).ok()?;
  Some(trimmed.to_string())
}

fn jwt_text(text: &str) -> Option<String> {
  if let Some(jwt) = user_config_re()?.captures_iter(text).next().and_then(|cap| cap.get(1)) {
    return Some(jwt.as_str().to_string());
  }
  let line = text.trim();
  (!line.is_empty() && !line.contains('\n')).then(|| line.to_string())
}

fn creds_parts(text: &str) -> Result<(String, String), NatsSkipCause> {
  let mut found = user_config_re().ok_or_else(NatsSkipCause::credential)?.captures_iter(text);
  let jwt = capture(&mut found)?;
  let seed = capture(&mut found)?;
  Ok((jwt, seed))
}

fn capture(found: &mut regex::CaptureMatches<'_, '_>) -> Result<String, NatsSkipCause> {
  found
    .next()
    .and_then(|cap| cap.get(1))
    .map(|item| item.as_str().to_string())
    .ok_or_else(NatsSkipCause::credential)
}

fn user_config_re() -> Option<&'static Regex> {
  static RE: OnceLock<Option<Regex>> = OnceLock::new();
  RE.get_or_init(|| Regex::new(r"\s*(?:(?:[-]{3,}.*[-]{3,}\r?\n)([\w\-.=]+)(?:\r?\n[-]{3,}.*[-]{3,}\r?\n))").ok())
    .as_ref()
}
