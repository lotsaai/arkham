//! One credential reference from a NATS context field.
//!
//! `env://`, `file://`, `op://`, `nsc://`, and `data:` resolve on the host.
//! Anything else is the text. A path expands once.

use std::path::PathBuf;
use std::process::Command;
use std::sync::LazyLock;

use arkham_config::grants::{NatsPlain, NatsSeed, check_user_jwt};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use regex::Regex;
use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

use super::{NatsContextTree, NatsSkipCause};

/// Creds-file pattern from async-nats. The pattern is a fixed constant.
static CREDS_RE: LazyLock<Regex> = LazyLock::new(|| {
  Regex::new(r"\s*(?:(?:[-]{3,}.*[-]{3,}\r?\n)([\w\-.=]+)(?:\r?\n[-]{3,}.*[-]{3,}\r?\n))").expect("async-nats creds pattern")
});

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
  /// Bytes this reference names. A failed `op` or `nsc` keeps that command's stderr.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when the file, variable, or command is missing.
  pub(super) fn read(&self) -> Result<Vec<u8>, NatsSkipCause> {
    match self {
      Self::Literal(text) => Ok(text.as_bytes().to_vec()),
      Self::File(path) => std::fs::read(path).map_err(|_source| NatsSkipCause::credential()),
      Self::Env(name) => match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value.into_bytes()),
        _ => Err(NatsSkipCause::credential()),
      },
      Self::Op(refer) => command_stdout("op", &["read", refer]),
      Self::Nsc(refer) => {
        let (path, _) = load_profile(refer)?;
        std::fs::read(path).map_err(|_source| NatsSkipCause::credential())
      }
      Self::Data(bytes) => Ok(bytes.clone()),
    }
  }
}

impl NatsContextTree<'_> {
  fn parse(&self, raw: &str) -> Result<CredentialRef, NatsSkipCause> {
    Ok(match scheme_of(raw).as_deref() {
      Some("file") => CredentialRef::File(self.resolve_path(raw)),
      Some("env") => {
        let name = remainder(raw, "env");
        if name.is_empty() {
          return Err(NatsSkipCause::credential());
        }
        CredentialRef::Env(name.to_string())
      }
      Some("op") => CredentialRef::Op(format!("op://{}", remainder(raw, "op"))),
      Some("nsc") => CredentialRef::Nsc(format!("nsc://{}", remainder(raw, "nsc"))),
      Some("data") => CredentialRef::Data(decode_data(raw)?),
      Some(_) | None => CredentialRef::Literal(raw.to_string()),
    })
  }

  fn resolve_path(&self, raw: &str) -> PathBuf {
    let home = self.host_home.to_string_lossy().into_owned();
    let expanded = shellexpand::full_with_context_no_errors(
      remainder(raw, "file"),
      || Some(home),
      |key| Some(std::env::var(key).unwrap_or_default()),
    );
    let path = PathBuf::from(expanded.as_ref());
    if path.is_absolute() { path } else { self.root.join(path) }
  }

  /// Inline text, or the trimmed text a resolver returns.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when a resolver reference cannot be read.
  pub(super) fn literal_text(&self, raw: &str) -> Result<String, NatsSkipCause> {
    if raw.is_empty() {
      return Ok(String::new());
    }
    match self.parse(raw)? {
      CredentialRef::Literal(text) => Ok(text),
      other => Ok(utf8(other.read()?)?.trim_end_matches(['\r', '\n']).to_string()),
    }
  }

  /// A creds file: a user JWT and a user seed.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when the file is not that pair.
  pub(super) fn creds(&self, raw: &str) -> Result<NatsPlain, NatsSkipCause> {
    let text = utf8(self.material(raw)?)?;
    let mut caps = CREDS_RE
      .captures_iter(&text)
      .filter_map(|cap| cap.get(1).map(|item| item.as_str().to_owned()));
    let jwt = caps.next().ok_or_else(NatsSkipCause::credential)?;
    let seed = caps.next().ok_or_else(NatsSkipCause::credential)?;
    plain_creds(seed, jwt)
  }

  /// `user_jwt` with `user_seed`. The JWT `sub` must be that seed's public key.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when either reference fails or the pair does not match.
  pub(super) fn paired(&self, seed_raw: &str, jwt_raw: &str) -> Result<NatsPlain, NatsSkipCause> {
    plain_creds(self.literal_text(seed_raw)?, self.literal_text(jwt_raw)?)
  }

  /// An nkey file. A plain seed, a decorated seed, or a creds file.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when no line is a user nkey seed.
  pub(super) fn nkey(&self, raw: &str) -> Result<String, NatsSkipCause> {
    seed_line(&utf8(self.material(raw)?)?).ok_or_else(NatsSkipCause::credential)
  }

  /// A TLS file. Empty is absent. Only `file` and a bare path are files.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::TlsFile`] when the reference is another scheme or cannot be read.
  pub(super) fn tls_file(&self, raw: &str) -> Result<Option<Vec<u8>>, NatsSkipCause> {
    if raw.is_empty() {
      return Ok(None);
    }
    if scheme_of(raw).is_some_and(|scheme| scheme != "file") {
      return Err(NatsSkipCause::TlsFile);
    }
    std::fs::read(self.resolve_path(raw))
      .map(Some)
      .map_err(|_source| NatsSkipCause::TlsFile)
  }

  /// Creds path and operator service list from `nsc generate profile`.
  ///
  /// # Errors
  ///
  /// [`NatsSkipCause::Credential`] when `nsc` fails or the profile has no creds file.
  pub(super) fn nsc_profile(&self, raw: &str) -> Result<(String, String), NatsSkipCause> {
    let refer = match self.parse(raw) {
      Ok(CredentialRef::Nsc(refer)) => refer,
      _ => format!("nsc://{raw}"),
    };
    load_profile(&refer)
  }

  fn material(&self, raw: &str) -> Result<Vec<u8>, NatsSkipCause> {
    match self.parse(raw)? {
      CredentialRef::Literal(text) => std::fs::read(self.resolve_path(&text)).map_err(|_source| NatsSkipCause::credential()),
      other => other.read(),
    }
  }
}

fn plain_creds(seed: String, jwt: String) -> Result<NatsPlain, NatsSkipCause> {
  let parsed = NatsSeed::from_seed(SecretString::from(seed.clone())).map_err(|_source| NatsSkipCause::credential())?;
  check_user_jwt(&jwt, &parsed.public).map_err(|_source| NatsSkipCause::credential())?;
  Ok(NatsPlain::Creds { seed, jwt })
}

fn utf8(bytes: Vec<u8>) -> Result<String, NatsSkipCause> {
  String::from_utf8(bytes).map_err(|_source| NatsSkipCause::credential())
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

fn seed_line(text: &str) -> Option<String> {
  text
    .lines()
    .map(str::trim)
    .find(|line| NatsSeed::from_seed(SecretString::from(line.to_string())).is_ok())
    .map(str::to_string)
}
