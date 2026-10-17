//! NATS vertical: the protocol's scope types, its connection-string law,
//! and the rule-to-scope assembly.
//!
//! `nats://` and `tls://` are the two spellings official NATS clients
//! accept, and both are [`Scheme::Nats`]. A `nats://` real string is a
//! cleartext upstream, so CONNECT forwards the decoy. A `tls://` real
//! string is a TLS upstream: the server sends one cleartext INFO line and
//! the client upgrades before CONNECT, or with `handshake_first=true` both
//! legs do TLS before any protocol byte.

use std::path::PathBuf;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use strum::{EnumIter, IntoEnumIterator as _, IntoStaticStr};
use url::Url;

use super::{Credential, Grant, GuestTlsMode, RootCert, Scheme};
use crate::config::RuleCfg;
use crate::error::Error;

/// Port a NATS string means when it names none.
pub const NATS_DEFAULT_PORT: u16 = 4222;

/// The URL spellings official NATS clients accept. Both are
/// [`Scheme::Nats`]; `tls` never becomes a scheme of its own, because
/// `Expect::Tls` already means HTTPS inside the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
pub(crate) enum NatsUriScheme {
  Nats,
  Tls,
}

impl NatsUriScheme {
  fn prefix(self) -> &'static str {
    match self {
      Self::Nats => "nats://",
      Self::Tls => "tls://",
    }
  }

  /// The spelling `entry` starts with. `RuleCfg::value_scheme` and
  /// `NatsUri::from_str` both read it, so the prefix list has one home.
  pub(crate) fn of(entry: &str) -> Option<Self> {
    Self::iter().find(|scheme| entry.starts_with(scheme.prefix()))
  }
}

/// One dial address of a NATS rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsEndpoint {
  /// Dial host, lowercased once at parse.
  pub host: String,
  /// Dial port, [`NATS_DEFAULT_PORT`] when the string names none.
  pub port: u16,
}

/// One CONNECT field's decoy and the real value it stands in for.
#[derive(Debug, Clone)]
pub struct NatsPair {
  /// The value the agent's string states.
  pub fake: String,
  /// The value the real string states.
  pub real: SecretString,
}

/// Username that selects a signature kind. The tag spellings are this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
enum AuthTag {
  /// `nats://nkey:<user-seed>@host`.
  Nkey,
  /// `nats://creds:<user-seed>:<user-jwt>@host`.
  Creds,
}

impl AuthTag {
  fn as_str(self) -> &'static str {
    <&str>::from(self)
  }

  fn parse(user: &str) -> Option<Self> {
    Self::iter().find(|tag| tag.as_str() == user)
  }
}

/// User nkey seed. The raw seed is not a CONNECT field.
///
/// `Debug` shows [`Self::public_key`] only. [`secrecy::SecretString`] redacts the seed.
#[derive(Debug, Clone)]
pub struct NatsSeed {
  raw: SecretString,
  public: String,
}

impl NatsSeed {
  /// Parse a user seed and keep its public key.
  ///
  /// # Errors
  ///
  /// [`NatsUriError::Seed`] when the text is not an nkey seed.
  /// [`NatsUriError::UserSeed`] when the seed is not a user nkey.
  pub fn from_seed(raw: SecretString) -> Result<Self, NatsUriError> {
    // `nkeys` errors can echo the seed, so the failure stays a static variant.
    let pair = nkeys::KeyPair::from_seed(raw.expose_secret()).map_err(|_source| NatsUriError::Seed)?;
    if pair.key_pair_type() != nkeys::KeyPairType::User {
      return Err(NatsUriError::UserSeed);
    }
    Ok(Self {
      public: pair.public_key(),
      raw,
    })
  }

  /// Public key derived from the seed.
  #[must_use]
  pub fn public_key(&self) -> &str {
    &self.public
  }

  /// Raw ed25519 signature of `message` under this seed.
  ///
  /// `None` when the stored seed does not rebuild. The seed is not copied into that `None`.
  #[must_use]
  pub fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
    let pair = nkeys::KeyPair::from_seed(self.raw.expose_secret()).ok()?;
    pair.sign(message).ok()
  }

  /// `true` when `sig` is an ed25519 signature of `message` under `public`.
  #[must_use]
  pub fn verify(public: &str, message: &[u8], sig: &[u8]) -> bool {
    let Ok(pair) = nkeys::KeyPair::from_public_key(public) else {
      return false;
    };
    pair.verify(message, sig).is_ok()
  }
}

/// Nkey rule. CONNECT `nkey` is the public key. There is no JWT slot.
#[derive(Debug, Clone)]
pub struct Nkey {
  fake_public: String,
  real: NatsSeed,
}

impl Nkey {
  /// Decoy public key the guest CONNECT `nkey` must equal.
  #[must_use]
  pub fn fake_public(&self) -> &str {
    &self.fake_public
  }

  /// Real public key written into the upstream CONNECT `nkey`.
  #[must_use]
  pub fn real_public(&self) -> &str {
    self.real.public_key()
  }

  /// Sign with the real seed.
  #[must_use]
  pub fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
    self.real.sign(message)
  }
}

/// User-JWT rule. CONNECT `jwt` is the pair.
///
/// A present CONNECT `nkey` must be [`Self::fake_public`]. The upstream line
/// then carries [`Self::real_public`]. nats.js `credsAuthenticator` sends
/// `jwt`, `nkey`, and `sig` together. A missing `nkey` is still accepted.
/// [`Self::fake_public`] is the guest key a decoy signature must verify under.
/// The signer is the real seed that signs the upstream nonce.
#[derive(Debug, Clone)]
pub struct UserJwt {
  jwt: NatsPair,
  fake_public: String,
  signer: NatsSeed,
}

impl UserJwt {
  /// Decoy user JWT the guest CONNECT `jwt` must equal.
  #[must_use]
  pub fn fake_jwt(&self) -> &str {
    &self.jwt.fake
  }

  /// Real user JWT written into the upstream CONNECT `jwt`.
  #[must_use]
  pub fn real_jwt(&self) -> &SecretString {
    &self.jwt.real
  }

  /// Public key of the decoy seed. The decoy seed itself is not kept.
  #[must_use]
  pub fn fake_public(&self) -> &str {
    &self.fake_public
  }

  /// Public key of the real seed.
  #[must_use]
  pub fn real_public(&self) -> &str {
    self.signer.public_key()
  }

  /// Sign with the real seed.
  #[must_use]
  pub fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
    self.signer.sign(message)
  }
}

/// The credential a NATS rule maps. One variant covers both strings, so a
/// user/password fake with a token real cannot be built.
#[derive(Debug, Clone)]
pub enum NatsAuth {
  /// `user:pass` userinfo. CONNECT `user` and `pass` swap together.
  UserPass {
    /// CONNECT `user`.
    user: NatsPair,
    /// CONNECT `pass`.
    pass: NatsPair,
  },
  /// Lone userinfo, which every official client sends as CONNECT
  /// `auth_token`.
  Token(NatsPair),
  /// Username `nkey` and a user seed. CONNECT `nkey` swaps the public key.
  Nkey(Nkey),
  /// Username `creds` and `seed:jwt`. CONNECT `jwt` swaps the user JWT.
  UserJwt(UserJwt),
}

/// How the proxy reaches the real server. Only the real string states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatsUpstream {
  /// `nats://`. The leg never upgrades and CONNECT carries the decoy.
  Cleartext,
  /// `tls://`. The leg is TLS before CONNECT, verified against `trust`.
  Tls {
    /// Where TLS sits relative to the first protocol byte.
    order: NatsTlsOrder,
    /// Upstream verification material.
    trust: NatsTrust,
  },
}

/// Where TLS sits relative to the first protocol byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatsTlsOrder {
  /// Cleartext INFO, then the client's TLS handshake, then CONNECT.
  AfterInfo,
  /// `handshake_first=true`. TLS before any protocol byte, on both legs.
  HandshakeFirst,
}

/// Upstream verification material. It lives only inside
/// [`NatsUpstream::Tls`], so trust on a cleartext leg cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsTrust {
  /// `sslrootcert`, or [`RootCert::System`] when absent.
  pub root_cert: RootCert,
  /// `sslcert` with `sslkey`.
  pub identity: Option<NatsClientIdentity>,
}

/// A PEM client certificate and its key, named by the real string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsClientIdentity {
  /// `sslcert`.
  pub cert: PathBuf,
  /// `sslkey`.
  pub key: PathBuf,
}

/// Both legs of one NATS rule.
#[derive(Debug, Clone)]
pub struct NatsScope {
  /// Where the agent dials, from the fake string. The fake's spelling is
  /// not kept: the guest picks its own TLS after INFO.
  pub downstream: NatsEndpoint,
  /// Where the proxy dials, from the real string.
  pub upstream: NatsEndpoint,
  /// The upstream TLS law, from the real string alone.
  pub upstream_tls: NatsUpstream,
  /// Both legs' credential values, one kind.
  pub auth: NatsAuth,
  /// How the guest leg treats client certificates (rule table, not the URL).
  pub guest_tls: GuestTlsMode,
}

/// Why one `nats://` or `tls://` string, or a pair of them, was rejected.
///
/// The text names the field or the problem. It never includes the string,
/// because the string carries the credential.
#[derive(Debug, thiserror::Error)]
pub enum NatsUriError {
  /// The string is not `nats://` or `tls://`.
  #[error("bad connection string: expected nats:// or tls://")]
  Scheme,
  /// `url` could not parse the string.
  #[error("bad connection string: {source}")]
  Url {
    /// Parser failure.
    #[source]
    source: url::ParseError,
  },
  /// The string has no host.
  #[error("bad connection string: empty host")]
  EmptyHost,
  /// The userinfo component is not UTF-8 after percent-decoding.
  #[error("bad connection string: the {label} is not valid UTF-8")]
  UserinfoUtf8 {
    /// `user`, `password`, or `token`.
    label: &'static str,
    /// Decoder failure.
    #[source]
    source: std::str::Utf8Error,
  },
  /// The string has no userinfo.
  #[error("bad connection string: a string with no userinfo maps nothing")]
  CredentialRequired,
  /// The userinfo has a password and no user.
  #[error("bad connection string: a password needs a user; a lone value is a token")]
  UserRequired,
  /// A NATS string carries a path.
  #[error("bad connection string: a NATS string has no path")]
  Path,
  /// `handshake_first` on a cleartext `nats://` string.
  #[error("bad connection string: handshake_first belongs on tls://")]
  HandshakeFirstOnCleartext,
  /// `handshake_first` was not `true`.
  #[error("bad connection string: handshake_first is `true` or absent, not `{value}`")]
  HandshakeFirstValue {
    /// The rejected value.
    value: String,
  },
  /// A path query was empty.
  #[error("bad connection string: {key} needs a path")]
  EmptyMaterial {
    /// `sslrootcert`, `sslcert`, or `sslkey`.
    key: &'static str,
  },
  /// The query key is not one a NATS string accepts.
  #[error("bad connection string: unknown query `{key}`")]
  UnknownQuery {
    /// The rejected key.
    key: String,
  },
  /// Trust material on a cleartext `nats://` string.
  #[error("bad connection string: cleartext `nats://` carries no TLS state; trust belongs on `tls://`")]
  TrustOnCleartext,
  /// Client identity on a cleartext `nats://` string.
  #[error("bad connection string: cleartext `nats://` carries no TLS state; identity belongs on `tls://`")]
  IdentityOnCleartext,
  /// `sslcert` and `sslkey` were not paired.
  #[error("bad connection string: sslcert and sslkey come together")]
  CertKeyPair,
  /// The fake string carried an option only the real string may set.
  #[error("bad connection string: `{key}` belongs on the real connection string")]
  FakeRealOnly {
    /// The rejected key.
    key: String,
  },
  /// The fake string carried a query key it does not accept.
  #[error("bad connection string: the fake connection string does not accept `{key}`")]
  FakeUnknown {
    /// The rejected key.
    key: String,
  },
  /// The two strings use different auth kinds.
  #[error("bad connection strings: fake and real use different auth kinds")]
  AuthKindMismatch,
  /// The `nkey` or `creds` password is not a parseable nkey seed.
  #[error("bad connection string: nkey seed does not parse")]
  Seed,
  /// The seed parses and its public key is not a user key.
  #[error("bad connection string: nkey seed is not a user nkey")]
  UserSeed,
  /// The `creds` password is not `seed:jwt` with a three-segment user JWT.
  #[error("bad connection string: user jwt must be three segments with a string sub")]
  UserJwt,
  /// The JWT `sub` and the seed's public key differ.
  #[error("bad connection string: user jwt sub does not match the nkey seed")]
  JwtSeedMismatch,
}

/// Userinfo as one string states it, before pairing with the other string.
#[derive(Debug)]
enum UriAuth {
  UserPass { user: String, pass: SecretString },
  Token(SecretString),
  Nkey(NatsSeed),
  UserJwt { jwt: SecretString, signer: NatsSeed },
}

/// One parsed NATS string. Callers only ever see [`NatsScope`].
#[derive(Debug)]
struct NatsUri {
  scheme: NatsUriScheme,
  endpoint: NatsEndpoint,
  auth: UriAuth,
  query: Vec<(String, String)>,
}

impl FromStr for NatsUri {
  type Err = NatsUriError;

  /// Parse one NATS string. A username of `nkey` or `creds` selects that
  /// kind. Any other `user:pass` is a user and password. A lone value is a
  /// token, and no userinfo maps nothing.
  fn from_str(entry: &str) -> Result<Self, Self::Err> {
    let scheme = NatsUriScheme::of(entry).ok_or(NatsUriError::Scheme)?;
    let url = Url::parse(entry).map_err(|source| NatsUriError::Url { source })?;
    let host = match url.host() {
      Some(url::Host::Domain(domain)) => domain.to_ascii_lowercase(),
      Some(url::Host::Ipv4(addr)) => addr.to_string(),
      Some(url::Host::Ipv6(addr)) => addr.to_string(),
      None => return Err(NatsUriError::EmptyHost),
    };
    // `url` drops an empty password, so `user:@host` reads as a token.
    let auth = match (url.username(), url.password()) {
      ("", None) => return Err(NatsUriError::CredentialRequired),
      ("", Some(_)) => return Err(NatsUriError::UserRequired),
      (token, None) => UriAuth::Token(SecretString::from(decode(token, "token")?)),
      (user, Some(pass)) => {
        let user = decode(user, "user")?;
        let pass = SecretString::from(decode(pass, "password")?);
        match AuthTag::parse(&user) {
          Some(tag) => parse_tagged(tag, pass)?,
          None => UriAuth::UserPass { user, pass },
        }
      }
    };
    if url.path() != "" && url.path() != "/" {
      return Err(NatsUriError::Path);
    }
    let query = url
      .query_pairs()
      .map(|(key, value)| (key.into_owned(), value.into_owned()))
      .collect();
    Ok(Self {
      scheme,
      endpoint: NatsEndpoint {
        host,
        port: url.port().unwrap_or(NATS_DEFAULT_PORT),
      },
      auth,
      query,
    })
  }
}

/// `Url` leaves userinfo percent-encoded. A `%` that is not two hex digits
/// stays literal; only invalid UTF-8 fails.
fn decode(raw: &str, label: &'static str) -> Result<String, NatsUriError> {
  percent_encoding::percent_decode_str(raw)
    .decode_utf8()
    .map(std::borrow::Cow::into_owned)
    .map_err(|source| NatsUriError::UserinfoUtf8 { label, source })
}

fn parse_tagged(tag: AuthTag, password: SecretString) -> Result<UriAuth, NatsUriError> {
  match tag {
    AuthTag::Nkey => Ok(UriAuth::Nkey(NatsSeed::from_seed(password)?)),
    AuthTag::Creds => {
      let (seed, jwt) = split_creds(password.expose_secret())?;
      let signer = NatsSeed::from_seed(SecretString::from(seed))?;
      check_user_jwt(&jwt, signer.public_key())?;
      Ok(UriAuth::UserJwt {
        jwt: SecretString::from(jwt),
        signer,
      })
    }
  }
}

/// `seed:jwt`. The seed has no colon, so the first colon is the split.
fn split_creds(password: &str) -> Result<(String, String), NatsUriError> {
  let Some((seed, jwt)) = password.split_once(':') else {
    return Err(NatsUriError::UserJwt);
  };
  if seed.is_empty() || jwt.is_empty() {
    return Err(NatsUriError::UserJwt);
  }
  Ok((seed.to_string(), jwt.to_string()))
}

/// Three non-empty base64url segments. The payload `sub` must be the seed's public key.
///
/// `nkeys` does not read JWT claims. A decoder that verifies the account
/// signature needs the account key, and this string only carries the user
/// seed. The segments are decoded with `base64` and `serde_json`.
fn check_user_jwt(jwt: &str, public: &str) -> Result<(), NatsUriError> {
  let mut parts = jwt.split('.');
  let Some(header) = parts.next().filter(|part| !part.is_empty()) else {
    return Err(NatsUriError::UserJwt);
  };
  let Some(payload) = parts.next().filter(|part| !part.is_empty()) else {
    return Err(NatsUriError::UserJwt);
  };
  let Some(signature) = parts.next().filter(|part| !part.is_empty()) else {
    return Err(NatsUriError::UserJwt);
  };
  if parts.next().is_some() {
    return Err(NatsUriError::UserJwt);
  }
  // A decode or JSON error can echo the segment, so it stays a static variant.
  let header_bytes = decode_b64url(header).ok_or(NatsUriError::UserJwt)?;
  let payload_bytes = decode_b64url(payload).ok_or(NatsUriError::UserJwt)?;
  if decode_b64url(signature).is_none() {
    return Err(NatsUriError::UserJwt);
  }
  let header_value = serde_json::from_slice::<Value>(&header_bytes).map_err(|_source| NatsUriError::UserJwt)?;
  if !header_value.is_object() {
    return Err(NatsUriError::UserJwt);
  }
  let payload_value = serde_json::from_slice::<Value>(&payload_bytes).map_err(|_source| NatsUriError::UserJwt)?;
  let Some(sub) = payload_value.get("sub").and_then(Value::as_str) else {
    return Err(NatsUriError::UserJwt);
  };
  if sub != public {
    return Err(NatsUriError::JwtSeedMismatch);
  }
  Ok(())
}

fn decode_b64url(raw: &str) -> Option<Vec<u8>> {
  URL_SAFE_NO_PAD.decode(raw).or_else(|_| URL_SAFE.decode(raw)).ok()
}

/// A query key the real string may carry. The fake-string check and
/// [`upstream_law`] both match this enum, so a new key has one place to land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
enum NatsQuery {
  HandshakeFirst,
  SslRootCert,
  SslCert,
  SslKey,
}

impl NatsQuery {
  fn as_str(self) -> &'static str {
    match self {
      Self::HandshakeFirst => "handshake_first",
      Self::SslRootCert => "sslrootcert",
      Self::SslCert => "sslcert",
      Self::SslKey => "sslkey",
    }
  }

  fn parse(key: &str) -> Option<Self> {
    Self::iter().find(|query| query.as_str() == key)
  }
}

/// The fake string takes no query. Its guest TLS mode is the rule `tls` table.
fn reject_fake_query(uri: &NatsUri) -> Result<(), NatsUriError> {
  let Some((key, _)) = uri.query.first() else {
    return Ok(());
  };
  if NatsQuery::parse(key).is_some() {
    return Err(NatsUriError::FakeRealOnly { key: key.clone() });
  }
  Err(NatsUriError::FakeUnknown { key: key.clone() })
}

/// The real string's TLS law. `nats://` takes no query. `tls://` is
/// [`NatsTlsOrder::AfterInfo`] unless `handshake_first=true`.
fn upstream_law(uri: &NatsUri) -> Result<NatsUpstream, NatsUriError> {
  match uri.scheme {
    NatsUriScheme::Nats => match uri.query.first() {
      None => Ok(NatsUpstream::Cleartext),
      Some((key, _)) => Err(match NatsQuery::parse(key) {
        None => NatsUriError::UnknownQuery { key: key.clone() },
        Some(NatsQuery::HandshakeFirst) => NatsUriError::HandshakeFirstOnCleartext,
        Some(NatsQuery::SslRootCert) => NatsUriError::TrustOnCleartext,
        Some(NatsQuery::SslCert | NatsQuery::SslKey) => NatsUriError::IdentityOnCleartext,
      }),
    },
    NatsUriScheme::Tls => tls_upstream(&uri.query),
  }
}

fn tls_upstream(query: &[(String, String)]) -> Result<NatsUpstream, NatsUriError> {
  let mut order = NatsTlsOrder::AfterInfo;
  let mut root_cert = RootCert::System;
  let mut cert = None;
  let mut key = None;
  for (name, value) in query {
    let parsed = NatsQuery::parse(name).ok_or_else(|| NatsUriError::UnknownQuery { key: name.clone() })?;
    match parsed {
      NatsQuery::HandshakeFirst => {
        if value != "true" {
          return Err(NatsUriError::HandshakeFirstValue { value: value.clone() });
        }
        order = NatsTlsOrder::HandshakeFirst;
      }
      NatsQuery::SslRootCert if value == "system" => root_cert = RootCert::System,
      NatsQuery::SslRootCert => root_cert = RootCert::Path(material(parsed, value)?),
      NatsQuery::SslCert => cert = Some(material(parsed, value)?),
      NatsQuery::SslKey => key = Some(material(parsed, value)?),
    }
  }
  let identity = match (cert, key) {
    (None, None) => None,
    (Some(cert), Some(key)) => Some(NatsClientIdentity { cert, key }),
    (Some(_), None) | (None, Some(_)) => return Err(NatsUriError::CertKeyPair),
  };
  Ok(NatsUpstream::Tls {
    order,
    trust: NatsTrust { root_cert, identity },
  })
}

fn material(query: NatsQuery, value: &str) -> Result<PathBuf, NatsUriError> {
  if value.is_empty() {
    return Err(NatsUriError::EmptyMaterial { key: query.as_str() });
  }
  Ok(PathBuf::from(value))
}

impl NatsScope {
  /// Both legs of a NATS rule from its two connection strings: the fake
  /// the rule states, the real the secret source resolved.
  ///
  /// # Errors
  ///
  /// Either string is not a NATS string, the fake carries a query, the real
  /// query breaks [`upstream_law`], or the two userinfo kinds differ.
  pub fn from_strings(fake: &str, real: &str) -> Result<Self, NatsUriError> {
    let downstream = fake.parse::<NatsUri>()?;
    let upstream = real.parse::<NatsUri>()?;
    reject_fake_query(&downstream)?;
    let upstream_tls = upstream_law(&upstream)?;
    let auth = match (downstream.auth, upstream.auth) {
      (
        UriAuth::UserPass {
          user: fake_user,
          pass: fake_pass,
        },
        UriAuth::UserPass {
          user: real_user,
          pass: real_pass,
        },
      ) => NatsAuth::UserPass {
        user: NatsPair {
          fake: fake_user,
          real: SecretString::from(real_user),
        },
        pass: NatsPair {
          fake: fake_pass.expose_secret().to_string(),
          real: real_pass,
        },
      },
      (UriAuth::Token(fake), UriAuth::Token(real)) => NatsAuth::Token(NatsPair {
        fake: fake.expose_secret().to_string(),
        real,
      }),
      (UriAuth::Nkey(fake), UriAuth::Nkey(real)) => NatsAuth::Nkey(Nkey {
        fake_public: fake.public_key().to_string(),
        real,
      }),
      (
        UriAuth::UserJwt {
          jwt: fake_jwt,
          signer: fake,
        },
        UriAuth::UserJwt {
          jwt: real_jwt,
          signer: real,
        },
      ) => NatsAuth::UserJwt(UserJwt {
        jwt: NatsPair {
          fake: fake_jwt.expose_secret().to_string(),
          real: real_jwt,
        },
        fake_public: fake.public_key().to_string(),
        signer: real,
      }),
      (
        UriAuth::UserPass { .. } | UriAuth::Token(_) | UriAuth::Nkey(_) | UriAuth::UserJwt { .. },
        UriAuth::UserPass { .. } | UriAuth::Token(_) | UriAuth::Nkey(_) | UriAuth::UserJwt { .. },
      ) => return Err(NatsUriError::AuthKindMismatch),
    };
    Ok(Self {
      downstream: downstream.endpoint,
      upstream: upstream.endpoint,
      upstream_tls,
      auth,
      guest_tls: GuestTlsMode::default(),
    })
  }

  /// Grant-level match for a concrete request: scheme + port + host.
  pub(super) fn matches(scope: &Self, scheme: Scheme, host: &str, port: u16) -> bool {
    scheme == Scheme::Nats && port == scope.downstream.port && scope.downstream.host.eq_ignore_ascii_case(host)
  }
}

/// Assemble one NATS grant from its rule.
///
/// # Errors
///
/// Returns an error when either string fails the law above, or when a
/// `tls` row tries to state what only the real string may state.
pub(super) fn grant(label: &str, rule: &RuleCfg, real: &str) -> Result<Grant, Error> {
  let fake = rule
    .value
    .as_ref()
    .map(|value| value.expose_secret().to_string())
    .unwrap_or_default();
  let mut scope = NatsScope::from_strings(&fake, real).map_err(|source| Error::NatsScope {
    label: label.to_string(),
    source,
  })?;
  for (key, tls) in &rule.tls {
    if key != &rule.env {
      return Err(Error::TlsEnvMismatch {
        label: label.to_string(),
        key: key.clone(),
        env: rule.env.clone(),
      });
    }
    if tls.client_cert.is_some() || tls.client_key.is_some() {
      return Err(Error::NatsIdentity { label: label.to_string() });
    }
    if tls.root_cert.is_some() {
      return Err(Error::NatsTrust { label: label.to_string() });
    }
    scope.guest_tls = tls.guest_tls_mode;
  }
  if scope.upstream_tls == NatsUpstream::Cleartext {
    tracing::warn!(
      label,
      host = %scope.upstream.host,
      port = scope.upstream.port,
      "nats:// upstream is cleartext; CONNECT forwards the decoy"
    );
  }
  let (fake, value) = match &scope.auth {
    NatsAuth::UserPass { pass, .. } => (pass.fake.clone(), pass.real.clone()),
    NatsAuth::Token(token) => (token.fake.clone(), token.real.clone()),
    NatsAuth::Nkey(nkey) => (nkey.fake_public().to_string(), SecretString::from(nkey.real_public().to_string())),
    NatsAuth::UserJwt(jwt) => (jwt.fake_jwt().to_string(), jwt.real_jwt().clone()),
  };
  let credential = Credential {
    label: label.to_string(),
    fake,
    value,
  };
  Ok(Grant::Nats {
    credential,
    scope: Box::new(scope),
  })
}

#[cfg(test)]
mod tests {
  use std::path::PathBuf;

  use pretty_assertions::assert_eq;
  use secrecy::ExposeSecret as _;

  use super::{
    NATS_DEFAULT_PORT, NatsAuth, NatsClientIdentity, NatsEndpoint, NatsScope, NatsTlsOrder, NatsTrust, NatsUpstream, NatsUri, NatsUriError,
  };
  use crate::grants::RootCert;

  const FAKE_PASS: &str = "arkham_fake_nats_pass"; // betterleaks:allow
  const REAL_PASS: &str = "real-nats-pass"; // betterleaks:allow
  const FAKE_TOKEN: &str = "arkham_fake_nats_token"; // betterleaks:allow
  const REAL_TOKEN: &str = "real-nats-token"; // betterleaks:allow

  /// Every CONNECT field a scope swaps, as `(field, fake, real)`.
  fn fields(auth: &NatsAuth) -> Vec<(&'static str, String, String)> {
    match auth {
      NatsAuth::UserPass { user, pass } => vec![
        ("user", user.fake.clone(), user.real.expose_secret().to_string()),
        ("pass", pass.fake.clone(), pass.real.expose_secret().to_string()),
      ],
      NatsAuth::Token(token) => vec![("auth_token", token.fake.clone(), token.real.expose_secret().to_string())],
      NatsAuth::Nkey(nkey) => vec![("nkey", nkey.fake_public().to_string(), nkey.real_public().to_string())],
      NatsAuth::UserJwt(jwt) => vec![("jwt", jwt.fake_jwt().to_string(), jwt.real_jwt().expose_secret().to_string())],
    }
  }

  fn endpoint(host: &str, port: u16) -> NatsEndpoint {
    NatsEndpoint {
      host: host.to_string(),
      port,
    }
  }

  fn system_trust() -> NatsTrust {
    NatsTrust {
      root_cert: RootCert::System,
      identity: None,
    }
  }

  #[test]
  fn nats_strings_accept_each_auth_kind_and_tls_order() {
    let user_fake = format!("nats://agent:{FAKE_PASS}@NATS.internal:4222");
    let user_pass = vec![
      ("user", "agent".to_string(), "agent".to_string()),
      ("pass", FAKE_PASS.to_string(), REAL_PASS.to_string()),
    ];
    let accepted = [
      (
        user_fake.clone(),
        format!("nats://agent:{REAL_PASS}@nats.upstream"),
        endpoint("nats.upstream", NATS_DEFAULT_PORT),
        NatsUpstream::Cleartext,
        user_pass.clone(),
      ),
      (
        format!("nats://{FAKE_TOKEN}@nats.internal:4222"),
        format!("nats://{REAL_TOKEN}@nats.upstream:4333"),
        endpoint("nats.upstream", 4333),
        NatsUpstream::Cleartext,
        vec![("auth_token", FAKE_TOKEN.to_string(), REAL_TOKEN.to_string())],
      ),
      (
        user_fake.clone(),
        format!("tls://agent:{REAL_PASS}@nats.upstream:4222"),
        endpoint("nats.upstream", 4222),
        NatsUpstream::Tls {
          order: NatsTlsOrder::AfterInfo,
          trust: system_trust(),
        },
        user_pass.clone(),
      ),
      (
        user_fake.clone(),
        format!("tls://agent:{REAL_PASS}@nats.upstream?handshake_first=true"),
        endpoint("nats.upstream", NATS_DEFAULT_PORT),
        NatsUpstream::Tls {
          order: NatsTlsOrder::HandshakeFirst,
          trust: system_trust(),
        },
        user_pass.clone(),
      ),
      (
        user_fake.clone(),
        format!("tls://agent:{REAL_PASS}@nats.upstream:4222?sslrootcert=/certs/ca.crt"),
        endpoint("nats.upstream", 4222),
        NatsUpstream::Tls {
          order: NatsTlsOrder::AfterInfo,
          trust: NatsTrust {
            root_cert: RootCert::Path(PathBuf::from("/certs/ca.crt")),
            identity: None,
          },
        },
        user_pass.clone(),
      ),
      (
        user_fake.clone(),
        format!("tls://agent:{REAL_PASS}@nats.upstream:4222?sslcert=/certs/c.pem&sslkey=/certs/c.key"),
        endpoint("nats.upstream", 4222),
        NatsUpstream::Tls {
          order: NatsTlsOrder::AfterInfo,
          trust: NatsTrust {
            root_cert: RootCert::System,
            identity: Some(NatsClientIdentity {
              cert: PathBuf::from("/certs/c.pem"),
              key: PathBuf::from("/certs/c.key"),
            }),
          },
        },
        user_pass,
      ),
    ];
    for (fake, real, upstream, upstream_tls, swapped) in accepted {
      let scope = NatsScope::from_strings(&fake, &real).unwrap_or_else(|err| panic!("{real}: {err}"));
      assert_eq!(scope.downstream, endpoint("nats.internal", 4222), "{real}");
      assert_eq!(scope.upstream, upstream, "{real}");
      assert_eq!(scope.upstream_tls, upstream_tls, "{real}");
      assert_eq!(fields(&scope.auth), swapped, "{real}");
    }
  }

  #[test]
  fn tls_ipv6_host_drops_the_brackets() {
    let scope = NatsScope::from_strings("nats://u:p@[::1]:4222", "tls://u:p@[::1]:4222").expect("ipv6");
    assert_eq!(scope.downstream.host, "::1");
    assert_eq!(scope.upstream.host, "::1");
    assert_eq!(scope.upstream.port, 4222);
  }

  #[test]
  fn nats_uri_reads_both_spellings_with_the_default_port() {
    let plain: NatsUri = format!("nats://{FAKE_TOKEN}@nats.internal").parse().expect("nats://");
    assert_eq!(plain.endpoint, endpoint("nats.internal", 4222));
    let tls: NatsUri = format!("tls://agent:{FAKE_PASS}@nats.internal:4443").parse().expect("tls://");
    assert_eq!(tls.endpoint, endpoint("nats.internal", 4443));
    let err = format!("http://agent:{FAKE_PASS}@nats.internal")
      .parse::<NatsUri>()
      .expect_err("http://");
    assert!(matches!(err, NatsUriError::Scheme), "{err}");
    let err = "nats://nats.internal:4222".parse::<NatsUri>().expect_err("no userinfo");
    assert!(matches!(err, NatsUriError::CredentialRequired), "{err}");
  }

  #[test]
  fn nats_strings_reject_misplaced_tls_paths_and_mixed_auth() {
    let fake = format!("nats://agent:{FAKE_PASS}@nats.internal:4222");
    let rejected = [
      (
        fake.clone(),
        format!("nats://agent:{REAL_PASS}@nats.upstream:4222?sslrootcert=/certs/ca.crt"),
        "trust belongs on `tls://`",
      ),
      (
        fake.clone(),
        format!("nats://agent:{REAL_PASS}@nats.upstream:4222?handshake_first=true"),
        "handshake_first belongs on tls://",
      ),
      (
        fake.clone(),
        format!("tls://agent:{REAL_PASS}@nats.upstream:4222?sslcert=/certs/c.pem"),
        "sslcert and sslkey come together",
      ),
      (
        fake.clone(),
        format!("tls://agent:{REAL_PASS}@nats.upstream:4222/subject"),
        "a NATS string has no path",
      ),
      (
        fake.clone(),
        format!("tls://agent:{REAL_PASS}@nats.upstream:4222?sslmode=require"),
        "unknown query `sslmode`",
      ),
      (
        fake.clone(),
        format!("tls://{REAL_TOKEN}@nats.upstream:4222"),
        "different auth kinds",
      ),
      (
        format!("nats://agent:{FAKE_PASS}@nats.internal:4222?sslrootcert=/certs/ca.crt"),
        format!("tls://agent:{REAL_PASS}@nats.upstream:4222"),
        "`sslrootcert` belongs on the real connection string",
      ),
    ];
    for (fake, real, problem) in rejected {
      let err = NatsScope::from_strings(&fake, &real).expect_err(problem);
      let text = err.to_string();
      assert!(text.contains(problem), "{text}");
      for secret in [FAKE_PASS, REAL_PASS, REAL_TOKEN, fake.as_str(), real.as_str()] {
        assert!(!text.contains(secret), "{text} contains {secret}");
      }
      let wrapped = crate::Error::NatsScope {
        label: "NATS_URL".into(),
        source: err,
      };
      assert!(!wrapped.to_string().contains(REAL_PASS), "{wrapped}");
    }
  }

  fn user_material() -> (String, String) {
    let pair = nkeys::KeyPair::new_user();
    let seed = pair.seed().expect("user seed");
    let public = pair.public_key();
    (seed, public)
  }

  fn b64_nopad(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
  }

  /// Three base64url segments. Header key order is the caller's.
  fn user_jwt(public: &str, header_json: &[u8]) -> String {
    let header = b64_nopad(header_json);
    let payload = b64_nopad(format!(r#"{{"name":"agent","sub":"{public}"}}"#).as_bytes());
    let sig = b64_nopad(b"sig");
    format!("{header}.{payload}.{sig}")
  }

  fn hides(err: &NatsUriError, secrets: &[&str]) {
    let text = err.to_string();
    for secret in secrets {
      assert!(!secret.is_empty(), "the check needs the material");
      assert!(!text.contains(secret), "{text} contains a secret");
    }
  }

  struct SignedStrings {
    fake_seed: String,
    real_seed: String,
    fake_public: String,
    real_public: String,
    fake_jwt: String,
    real_jwt: String,
    fake_nkey: String,
    real_nkey: String,
    fake_creds: String,
    real_creds: String,
  }

  fn signed_strings() -> SignedStrings {
    let (fake_seed, fake_public) = user_material();
    let (real_seed, real_public) = user_material();
    let fake_jwt = user_jwt(&fake_public, br#"{"alg":"ed25519-nkey","typ":"JWT"}"#);
    let real_jwt = user_jwt(&real_public, br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let fake_nkey = format!("nats://nkey:{fake_seed}@NATS.internal:4222");
    let real_nkey = format!("tls://nkey:{real_seed}@nats.upstream:4222?sslrootcert=/certs/ca.pem");
    let fake_creds = format!("nats://creds:{fake_seed}:{fake_jwt}@nats.internal:4222");
    let real_creds = format!("tls://creds:{real_seed}:{real_jwt}@nats.upstream:4222?handshake_first=true");
    SignedStrings {
      fake_seed,
      real_seed,
      fake_public,
      real_public,
      fake_jwt,
      real_jwt,
      fake_nkey,
      real_nkey,
      fake_creds,
      real_creds,
    }
  }

  #[test]
  fn nkey_and_user_jwt_round_trip_public_material_and_reject_the_rest() {
    let case = signed_strings();
    assert_nkey_round_trip(&case);
    assert_user_jwt_round_trip(&case);
    assert_lone_seed_stays_a_token(&case);
    assert_grant_stores_public_material(&case);
    assert_signed_kinds_reject(&case);
  }

  fn assert_nkey_round_trip(case: &SignedStrings) {
    let scope = NatsScope::from_strings(&case.fake_nkey, &case.real_nkey).expect("nkey");
    let NatsAuth::Nkey(nkey) = &scope.auth else {
      panic!("nkey username is the nkey kind");
    };
    assert_eq!(nkey.fake_public(), case.fake_public);
    assert_eq!(nkey.real_public(), case.real_public);
    assert!(nkey.fake_public().starts_with('U'));
    let nonce = b"N0NCE";
    let signed = nkey.sign(nonce).expect("real seed signs");
    assert!(super::NatsSeed::verify(nkey.real_public(), nonce, &signed));
    assert!(!super::NatsSeed::verify(nkey.fake_public(), nonce, &signed));
    let shown = format!("{nkey:?}");
    assert!(!shown.contains(&case.fake_seed));
    assert!(!shown.contains(&case.real_seed));
  }

  fn assert_user_jwt_round_trip(case: &SignedStrings) {
    let header_typ_first = br#"{"typ":"JWT","alg":"ed25519-nkey"}"#;
    let padded_payload = base64::Engine::encode(
      &base64::engine::general_purpose::URL_SAFE,
      format!(r#"{{"sub":"{}","pad":"x"}}"#, case.fake_public).as_bytes(),
    );
    assert!(padded_payload.contains('='), "the padded fixture needs padding");
    let padded_jwt = format!("{}.{padded_payload}.{}", b64_nopad(header_typ_first), b64_nopad(b"sig"));
    let padded = NatsScope::from_strings(
      &format!("nats://creds:{}:{padded_jwt}@nats.internal:4222", case.fake_seed),
      &format!("tls://creds:{}:{}@nats.upstream:4222", case.real_seed, case.real_jwt),
    )
    .expect("padded jwt payload");
    let NatsAuth::UserJwt(padded_kind) = &padded.auth else {
      panic!("creds username is the user jwt kind");
    };
    assert_eq!(padded_kind.fake_public(), case.fake_public);

    let scope = NatsScope::from_strings(&case.fake_creds, &case.real_creds).expect("creds");
    assert!(matches!(
      scope.upstream_tls,
      NatsUpstream::Tls {
        order: NatsTlsOrder::HandshakeFirst,
        ..
      }
    ));
    let NatsAuth::UserJwt(creds) = &scope.auth else {
      panic!("creds username is the user jwt kind");
    };
    assert_eq!(creds.fake_jwt(), case.fake_jwt);
    assert_eq!(creds.real_jwt().expose_secret(), case.real_jwt);
    assert_eq!(creds.fake_public(), case.fake_public);
    assert_eq!(creds.real_public(), case.real_public);
    let signed = creds.sign(b"N0NCE").expect("real seed signs");
    assert!(super::NatsSeed::verify(creds.real_public(), b"N0NCE", &signed));
    let shown = format!("{creds:?}");
    assert!(!shown.contains(&case.fake_seed));
    assert!(!shown.contains(&case.real_seed));
    assert!(!shown.contains(&case.real_jwt));
  }

  fn assert_lone_seed_stays_a_token(case: &SignedStrings) {
    let lone = NatsScope::from_strings(
      &format!("nats://{}@nats.internal:4222", case.fake_seed),
      &format!("nats://{}@nats.upstream:4222", case.real_seed),
    )
    .expect("lone userinfo");
    let NatsAuth::Token(token) = &lone.auth else {
      panic!("a lone seed is a token");
    };
    assert_eq!(token.fake, case.fake_seed);
    assert_eq!(token.real.expose_secret(), case.real_seed);
    for name in ["nkey", "creds"] {
      let token = NatsScope::from_strings(
        &format!("nats://{name}@nats.internal:4222"),
        &format!("tls://{name}@nats.upstream:4222"),
      )
      .expect(name);
      let NatsAuth::Token(token) = &token.auth else {
        panic!("{name} without a password is a token");
      };
      assert_eq!(token.fake, name);
    }
    let user = NatsScope::from_strings(
      &format!("nats://agent:{FAKE_PASS}@nats.internal:4222"),
      &format!("tls://agent:{REAL_PASS}@nats.upstream:4222"),
    )
    .expect("user pass");
    assert!(matches!(user.auth, NatsAuth::UserPass { .. }));
  }

  fn assert_grant_stores_public_material(case: &SignedStrings) {
    let rule: crate::config::RuleCfg = toml::from_str(&format!("env = \"NATS_NKEY_URL\"\nvalue = {:?}\n", case.fake_nkey)).expect("rule");
    let grant = super::grant("nats-nkey", &rule, &case.real_nkey).expect("grant");
    let credential = grant.credential().expect("credential");
    assert_eq!(credential.fake, case.fake_public);
    assert_eq!(credential.value.expose_secret(), case.real_public);
    assert!(!credential.value.expose_secret().contains(&case.real_seed));
    let rule: crate::config::RuleCfg = toml::from_str(&format!("env = \"NATS_CREDS_URL\"\nvalue = {:?}\n", case.fake_creds)).expect("rule");
    let grant = super::grant("nats-creds", &rule, &case.real_creds).expect("grant");
    let credential = grant.credential().expect("credential");
    assert_eq!(credential.fake, case.fake_jwt);
    assert_eq!(credential.value.expose_secret(), case.real_jwt);
    assert!(!credential.value.expose_secret().contains(&case.real_seed));
  }

  fn assert_signed_kinds_reject(case: &SignedStrings) {
    let account_seed = nkeys::KeyPair::new_account().seed().expect("account seed");
    let other_public = user_material().1;
    let bad_sub = user_jwt(&other_public, br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let rejected = [
      (case.fake_nkey.clone(), case.real_creds.clone(), NatsUriError::AuthKindMismatch),
      (
        case.fake_nkey.clone(),
        format!("tls://agent:{REAL_PASS}@nats.upstream:4222"),
        NatsUriError::AuthKindMismatch,
      ),
      (
        format!("nats://agent:{FAKE_PASS}@nats.internal:4222"),
        case.real_nkey.clone(),
        NatsUriError::AuthKindMismatch,
      ),
      (
        format!("nats://nkey:{account_seed}@nats.internal:4222"),
        case.real_nkey.clone(),
        NatsUriError::UserSeed,
      ),
      (
        "nats://nkey:not-a-seed@nats.internal:4222".to_string(),
        case.real_nkey.clone(),
        NatsUriError::Seed,
      ),
      (
        format!("nats://creds:{}@nats.internal:4222", case.fake_seed),
        case.real_creds.clone(),
        NatsUriError::UserJwt,
      ),
      (
        format!("nats://creds:{account_seed}:{}@nats.internal:4222", case.fake_jwt),
        case.real_creds.clone(),
        NatsUriError::UserSeed,
      ),
      (
        format!("nats://creds:{}:{bad_sub}@nats.internal:4222", case.fake_seed),
        case.real_creds.clone(),
        NatsUriError::JwtSeedMismatch,
      ),
      (
        format!("nats://creds:{}:aaaa.bbbb@nats.internal:4222", case.fake_seed),
        case.real_creds.clone(),
        NatsUriError::UserJwt,
      ),
    ];
    for (fake, real, kind) in rejected {
      let err = NatsScope::from_strings(&fake, &real).expect_err("rejected");
      assert!(std::mem::discriminant(&err) == std::mem::discriminant(&kind), "{err} != {kind}");
      hides(
        &err,
        &[
          case.fake_seed.as_str(),
          case.real_seed.as_str(),
          account_seed.as_str(),
          case.fake_jwt.as_str(),
          case.real_jwt.as_str(),
          bad_sub.as_str(),
          "not-a-seed",
        ],
      );
    }
  }
}
