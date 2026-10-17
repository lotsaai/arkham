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

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use strum::{EnumIter, IntoEnumIterator as _, IntoStaticStr};
use url::Url;

use super::{Credential, Grant, GuestTlsMode, RootCert, Scheme};
use crate::config::{RuleCfg, fake_for};
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

/// Username and password of one NATS string.
///
/// `password: None` is a token, so the string has no colon. `Some("")` is a
/// user whose password is empty, so the string keeps `user:@host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsUserinfo {
  /// Username, or the token when [`Self::password`] is `None`.
  pub user: String,
  /// Password. `None` is a token. `Some("")` keeps the colon.
  pub password: Option<String>,
}

impl NatsUserinfo {
  /// `user`, `user:pass`, or `user:` when the password is empty.
  #[must_use]
  pub fn encode(&self) -> String {
    let user = encode_userinfo_component(&self.user);
    match &self.password {
      None => user,
      Some(pass) => format!("{user}:{}", encode_userinfo_component(pass)),
    }
  }
}

/// One credential before it is paired with the other string.
///
/// [`Self::NKEY_USER`] and [`Self::CREDS_USER`] are the username spellings.
/// A username with one of those spellings is that kind only when the
/// password parses as that kind. Any other password is [`Self::UserPass`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatsPlain {
  /// CONNECT `user` and `pass`. `pass` may be empty.
  UserPass {
    /// CONNECT `user`.
    user: String,
    /// CONNECT `pass`.
    pass: String,
  },
  /// CONNECT `auth_token`.
  Token(String),
  /// Username [`Self::NKEY_USER`] and a user seed.
  Nkey(String),
  /// Username [`Self::CREDS_USER`] and `seed:jwt`.
  Creds {
    /// User seed.
    seed: String,
    /// User JWT.
    jwt: String,
  },
}

/// Guest credential file a discovered context mounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsGuestFile {
  /// File body. The real seed and JWT are not in it.
  pub body: String,
  /// Suffix used when the context named no in-home path.
  pub suffix: &'static str,
}

/// Decoy credential and the guest file it needs.
///
/// `signs` is true when CONNECT must sign the server nonce. The proxy reads
/// that from [`NatsAuth::signer`] after the two strings are paired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsPrepared {
  /// Decoy of the same kind as the real credential.
  pub decoy: NatsPlain,
  /// Guest file, when this kind is read from a file.
  pub file: Option<NatsGuestFile>,
  /// CONNECT signs the nonce.
  pub signs: bool,
}

/// Auth fields of a decoy context file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NatsContextAuth {
  /// Context `user`.
  pub user: String,
  /// Context `password`.
  pub password: String,
  /// Context `token`.
  pub token: String,
  /// Context `nkey`. A path, not a seed.
  pub nkey: String,
  /// Context `creds`. A path, not the file body.
  pub creds: String,
}

impl NatsPlain {
  /// Username spelling of [`Self::Nkey`].
  pub const NKEY_USER: &'static str = "nkey";
  /// Username spelling of [`Self::Creds`].
  pub const CREDS_USER: &'static str = "creds";

  /// Username and password for a connection string.
  #[must_use]
  pub fn userinfo(&self) -> NatsUserinfo {
    match self {
      Self::UserPass { user, pass } => NatsUserinfo {
        user: user.clone(),
        password: Some(pass.clone()),
      },
      Self::Token(token) => NatsUserinfo {
        user: token.clone(),
        password: None,
      },
      Self::Nkey(seed) => NatsUserinfo {
        user: Self::NKEY_USER.to_string(),
        password: Some(seed.clone()),
      },
      Self::Creds { seed, jwt } => NatsUserinfo {
        user: Self::CREDS_USER.to_string(),
        password: Some(format!("{seed}:{jwt}")),
      },
    }
  }

  /// Connection string. An empty password stays `user:@host`.
  #[must_use]
  pub fn connection_string(&self, scheme: &str, host: &str, port: Option<u16>, query: &[(&str, &str)]) -> String {
    let host_part = if host.contains(':') {
      format!("[{host}]")
    } else {
      host.to_string()
    };
    let authority = match port {
      Some(port) => format!("{host_part}:{port}"),
      None => host_part,
    };
    let mut rendered = format!("{scheme}://{}@{authority}", self.userinfo().encode());
    if query.is_empty() {
      return rendered;
    }
    let Ok(mut url) = Url::parse("nats://placeholder.invalid/") else {
      return rendered;
    };
    {
      let mut pairs = url.query_pairs_mut();
      for (key, value) in query {
        pairs.append_pair(key, value);
      }
    }
    if let Some(query) = url.query() {
      rendered.push('?');
      rendered.push_str(query);
    }
    rendered
  }

  /// Mint the decoy and the guest file for this credential.
  ///
  /// # Errors
  ///
  /// [`NatsUriError::Decoy`] when the decoy user seed cannot be minted.
  pub fn prepare(&self, env: &str) -> Result<NatsPrepared, NatsUriError> {
    match self {
      Self::UserPass { user, pass } => {
        let decoy_pass = if pass.is_empty() { String::new() } else { fake_for(env, None) };
        Ok(NatsPrepared {
          decoy: Self::UserPass {
            user: user.clone(),
            pass: decoy_pass,
          },
          file: None,
          signs: false,
        })
      }
      Self::Token(_) => Ok(NatsPrepared {
        decoy: Self::Token(fake_for(env, None)),
        file: None,
        signs: false,
      }),
      Self::Nkey(_) => {
        let seed = mint_user_seed()?;
        Ok(NatsPrepared {
          decoy: Self::Nkey(seed.clone()),
          file: Some(NatsGuestFile {
            body: format!("{seed}\n"),
            suffix: "nk",
          }),
          signs: true,
        })
      }
      Self::Creds { .. } => {
        let seed = mint_user_seed()?;
        let public = NatsSeed::from_seed(SecretString::from(seed.clone()))?.public_key().to_string();
        let jwt = decoy_user_jwt(&public);
        Ok(NatsPrepared {
          decoy: Self::Creds {
            seed: seed.clone(),
            jwt: jwt.clone(),
          },
          file: Some(NatsGuestFile {
            body: decorate_creds(&jwt, &seed),
            suffix: "creds",
          }),
          signs: true,
        })
      }
    }
  }

  /// Context auth fields for this decoy. `guest_path` is the mounted file.
  #[must_use]
  pub fn context_auth(&self, guest_path: Option<&str>) -> NatsContextAuth {
    let path = guest_path.unwrap_or("").to_string();
    match self {
      Self::UserPass { user, pass } => NatsContextAuth {
        user: user.clone(),
        password: pass.clone(),
        ..NatsContextAuth::default()
      },
      Self::Token(token) => NatsContextAuth {
        token: token.clone(),
        ..NatsContextAuth::default()
      },
      Self::Nkey(_) => NatsContextAuth {
        nkey: path,
        ..NatsContextAuth::default()
      },
      Self::Creds { .. } => NatsContextAuth {
        creds: path,
        ..NatsContextAuth::default()
      },
    }
  }

  fn pair(self, real: Self) -> Result<NatsAuth, NatsUriError> {
    if std::mem::discriminant(&self) != std::mem::discriminant(&real) {
      return Err(NatsUriError::AuthKindMismatch);
    }
    match (self, real) {
      (
        Self::UserPass {
          user: fake_user,
          pass: fake_pass,
        },
        Self::UserPass {
          user: real_user,
          pass: real_pass,
        },
      ) => Ok(NatsAuth::UserPass {
        user: NatsPair {
          fake: fake_user,
          real: SecretString::from(real_user),
        },
        pass: NatsPair {
          fake: fake_pass,
          real: SecretString::from(real_pass),
        },
      }),
      (Self::Token(fake), Self::Token(real)) => Ok(NatsAuth::Token(NatsPair {
        fake,
        real: SecretString::from(real),
      })),
      (Self::Nkey(fake), Self::Nkey(real)) => {
        let fake = NatsSeed::from_seed(SecretString::from(fake))?;
        let real = NatsSeed::from_seed(SecretString::from(real))?;
        Ok(NatsAuth::Nkey {
          public_key: NatsPair {
            fake: fake.public_key().to_string(),
            real: SecretString::from(real.public_key().to_string()),
          },
          seed: real,
        })
      }
      (
        Self::Creds {
          seed: fake_seed,
          jwt: fake_jwt,
        },
        Self::Creds {
          seed: real_seed,
          jwt: real_jwt,
        },
      ) => {
        let fake = NatsSeed::from_seed(SecretString::from(fake_seed))?;
        check_user_jwt(&fake_jwt, fake.public_key())?;
        let real = NatsSeed::from_seed(SecretString::from(real_seed))?;
        check_user_jwt(&real_jwt, real.public_key())?;
        Ok(NatsAuth::UserJwt {
          jwt: NatsPair {
            fake: fake_jwt,
            real: SecretString::from(real_jwt),
          },
          public_key: NatsPair {
            fake: fake.public_key().to_string(),
            real: SecretString::from(real.public_key().to_string()),
          },
          seed: real,
        })
      }
      _ => Err(NatsUriError::AuthKindMismatch),
    }
  }
}

fn mint_user_seed() -> Result<String, NatsUriError> {
  nkeys::KeyPair::new_user().seed().map_err(|_source| NatsUriError::Decoy)
}

fn decoy_user_jwt(public: &str) -> String {
  let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
  let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{public}"}}"#).as_bytes());
  let sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
  format!("{header}.{payload}.{sig}")
}

fn decorate_creds(jwt: &str, seed: &str) -> String {
  format!(
    "-----BEGIN NATS USER JWT-----\n{jwt}\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n{seed}\n------END USER NKEY SEED------\n"
  )
}

/// Percent-encode one userinfo component the way `url` does, so a later
/// parse decodes the same text.
fn encode_userinfo_component(value: &str) -> String {
  let Ok(mut url) = Url::parse("nats://placeholder.invalid/") else {
    return String::new();
  };
  if url.set_username(value).is_err() {
    return String::new();
  }
  let rendered = url.as_str();
  let Some(rest) = rendered.strip_prefix("nats://") else {
    return String::new();
  };
  rest.split_once('@').map(|(encoded, _)| encoded.to_string()).unwrap_or_default()
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

  /// `true` when `jwt` is a NATS user JWT whose `sub` is this seed's public key.
  ///
  /// The check is [`jwt::Token::parse_unverified`]. It reads the header and
  /// claims and does not check the account signature.
  #[must_use]
  pub fn matches_user_jwt(&self, jwt: &str) -> bool {
    check_user_jwt(jwt, &self.public).is_ok()
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

/// JSON key of a CONNECT field. The spellings are this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum NatsField {
  /// CONNECT `user`.
  User,
  /// CONNECT `pass`.
  Pass,
  /// CONNECT `auth_token`.
  AuthToken,
  /// CONNECT `nkey`.
  Nkey,
  /// CONNECT `jwt`.
  Jwt,
  /// CONNECT `sig`.
  Sig,
}

impl NatsField {
  /// The JSON key.
  #[must_use]
  pub fn as_str(self) -> &'static str {
    <&str>::from(self)
  }
}

/// Whether a CONNECT field has to be present for the method to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldPresence {
  /// The field must equal the decoy.
  Required,
  /// Absent is allowed. A present value must equal the decoy.
  Optional,
}

/// One CONNECT field this method rewrites and redacts.
#[derive(Debug, Clone, Copy)]
pub struct AuthField<'a> {
  /// JSON key.
  pub name: NatsField,
  /// Decoy and real value.
  pub pair: &'a NatsPair,
  /// Whether the field may be absent.
  pub presence: FieldPresence,
}

/// Nonce signature step. User/password and token have none.
#[derive(Debug, Clone, Copy)]
pub struct AuthSign<'a> {
  /// Public key the guest `sig` must verify under.
  pub verify: &'a str,
  /// Real seed that signs the upstream nonce.
  pub seed: &'a NatsSeed,
}

/// The credential a NATS rule maps. One variant covers both strings, so a
/// user/password fake with a token real cannot be built. Every variant
/// answers [`Self::fields`], [`Self::forbidden`], and [`Self::signer`].
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
  Nkey {
    /// CONNECT `nkey`. The real value is the public key, not the seed.
    public_key: NatsPair,
    /// Real seed. It signs the upstream nonce and is not a CONNECT field.
    seed: NatsSeed,
  },
  /// Username `creds` and `seed:jwt`. CONNECT `jwt` swaps the user JWT.
  /// A present CONNECT `nkey` swaps the public key. nats.js
  /// `credsAuthenticator` sends `jwt`, `nkey`, and `sig` together. A missing
  /// `nkey` still matches.
  UserJwt {
    /// CONNECT `jwt`.
    jwt: NatsPair,
    /// CONNECT `nkey`, when the client sends one.
    public_key: NatsPair,
    /// Real seed. It signs the upstream nonce and is not a CONNECT field.
    seed: NatsSeed,
  },
}

impl NatsAuth {
  /// CONNECT fields this method rewrites. The user JWT comes before its
  /// public key, because the public key is a substring of the JWT.
  #[must_use]
  pub fn fields(&self) -> Vec<AuthField<'_>> {
    match self {
      Self::UserPass { user, pass } => vec![
        AuthField {
          name: NatsField::User,
          pair: user,
          presence: FieldPresence::Required,
        },
        AuthField {
          name: NatsField::Pass,
          pair: pass,
          presence: FieldPresence::Required,
        },
      ],
      Self::Token(token) => vec![AuthField {
        name: NatsField::AuthToken,
        pair: token,
        presence: FieldPresence::Required,
      }],
      Self::Nkey { public_key, .. } => vec![AuthField {
        name: NatsField::Nkey,
        pair: public_key,
        presence: FieldPresence::Required,
      }],
      Self::UserJwt { jwt, public_key, .. } => vec![
        AuthField {
          name: NatsField::Jwt,
          pair: jwt,
          presence: FieldPresence::Required,
        },
        AuthField {
          name: NatsField::Nkey,
          pair: public_key,
          presence: FieldPresence::Optional,
        },
      ],
    }
  }

  /// CONNECT fields that reject the line when present.
  #[must_use]
  pub fn forbidden(&self) -> &'static [NatsField] {
    match self {
      Self::Nkey { .. } => &[NatsField::Jwt],
      Self::UserPass { .. } | Self::Token(_) | Self::UserJwt { .. } => &[],
    }
  }

  /// Nonce signature, when this method signs.
  #[must_use]
  pub fn signer(&self) -> Option<AuthSign<'_>> {
    match self {
      Self::Nkey { public_key, seed } | Self::UserJwt { public_key, seed, .. } => Some(AuthSign {
        verify: &public_key.fake,
        seed,
      }),
      Self::UserPass { .. } | Self::Token(_) => None,
    }
  }

  /// The value the grant records. A signature seed is not it.
  #[must_use]
  pub fn credential(&self) -> (&str, &SecretString) {
    match self {
      Self::UserPass { pass, .. } => (&pass.fake, &pass.real),
      Self::Token(token) => (&token.fake, &token.real),
      Self::Nkey { public_key, .. } => (&public_key.fake, &public_key.real),
      Self::UserJwt { jwt, .. } => (&jwt.fake, &jwt.real),
    }
  }
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
  /// A decoy user seed could not be minted.
  #[error("decoy nkey seed could not be minted")]
  Decoy,
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

/// One parsed NATS string. Callers only ever see [`NatsScope`].
#[derive(Debug)]
struct NatsUri {
  scheme: NatsUriScheme,
  endpoint: NatsEndpoint,
  auth: NatsPlain,
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
    let (user, password) = userinfo_parts(entry)?;
    let auth = match password {
      None => NatsPlain::Token(user),
      Some(pass) => classify_userinfo(user, pass)?,
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

/// Userinfo from the raw string. `url` drops the colon of an empty password,
/// so this split is the only read of that form. `None` is a token.
fn userinfo_parts(entry: &str) -> Result<(String, Option<String>), NatsUriError> {
  let rest = entry.split_once("://").ok_or(NatsUriError::Scheme)?.1;
  let info = rest.split_once('@').ok_or(NatsUriError::CredentialRequired)?.0;
  if info.is_empty() {
    return Err(NatsUriError::CredentialRequired);
  }
  match info.split_once(':') {
    None => Ok((decode(info, "token")?, None)),
    Some((user, pass)) => {
      if user.is_empty() {
        return Err(NatsUriError::UserRequired);
      }
      Ok((decode(user, "user")?, Some(decode(pass, "password")?)))
    }
  }
}

/// `nkey` and `creds` select that kind only when the password parses as it.
/// An ordinary password stays user and password, including a user whose
/// name is one of those spellings.
fn classify_userinfo(user: String, pass: String) -> Result<NatsPlain, NatsUriError> {
  if user == NatsPlain::NKEY_USER {
    return match NatsSeed::from_seed(SecretString::from(pass.clone())) {
      Ok(_) => Ok(NatsPlain::Nkey(pass)),
      Err(NatsUriError::Seed) => Ok(NatsPlain::UserPass { user, pass }),
      Err(err) => Err(err),
    };
  }
  if user == NatsPlain::CREDS_USER {
    return match plain_creds(&pass) {
      Ok(plain) => Ok(plain),
      Err(NatsUriError::UserJwt) => Ok(NatsPlain::UserPass { user, pass }),
      Err(err) => Err(err),
    };
  }
  Ok(NatsPlain::UserPass { user, pass })
}

fn plain_creds(password: &str) -> Result<NatsPlain, NatsUriError> {
  let (seed, jwt) = split_creds(password)?;
  let signer = NatsSeed::from_seed(SecretString::from(seed.clone()))?;
  check_user_jwt(&jwt, signer.public_key())?;
  Ok(NatsPlain::Creds { seed, jwt })
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

#[derive(Deserialize)]
struct UserJwtHeader {
  alg: String,
  typ: String,
}

#[derive(Deserialize)]
struct UserJwtClaims {
  sub: String,
}

/// A NATS user JWT. The header is `alg` `ed25519-nkey` and `typ` `JWT`.
/// The payload `sub` must be the seed's public key.
///
/// `jwt` 0.16 `Token::parse_unverified` reads the header and claims and does
/// not check the account signature. This string carries the user seed, not
/// the account key. `jwt::Error::Json` can echo a segment, so a parse failure
/// stays a static variant.
fn check_user_jwt(jwt: &str, public: &str) -> Result<(), NatsUriError> {
  let token = jwt::Token::<UserJwtHeader, UserJwtClaims, _>::parse_unverified(jwt).map_err(|_source| NatsUriError::UserJwt)?;
  let header = token.header();
  if header.alg != "ed25519-nkey" || header.typ != "JWT" {
    return Err(NatsUriError::UserJwt);
  }
  if token.claims().sub != public {
    return Err(NatsUriError::JwtSeedMismatch);
  }
  Ok(())
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
    let auth = downstream.auth.pair(upstream.auth)?;
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
  let (fake, value) = scope.auth.credential();
  let (fake, value) = (fake.to_string(), value.clone());
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

  #[test]
  fn username_nkey_or_creds_with_an_ordinary_password_is_userinfo() {
    for user in ["nkey", "creds"] {
      let scope = NatsScope::from_strings(
        &format!("nats://{user}:ordinary-pass@nats.internal:4222"),
        &format!("nats://{user}:ordinary-pass@nats.upstream:4222"),
      )
      .unwrap_or_else(|err| panic!("{user}: {err}"));
      assert_eq!(
        fields(&scope.auth),
        vec![
          ("user", user.to_string(), user.to_string()),
          ("pass", "ordinary-pass".to_string(), "ordinary-pass".to_string()),
        ],
        "{user}"
      );
    }
  }

  #[test]
  fn empty_password_userinfo_is_user_and_password() {
    let scope = NatsScope::from_strings("nats://agent:@nats.internal:4222", "nats://agent:@nats.internal:4222").expect("empty password");
    assert_eq!(
      fields(&scope.auth),
      vec![
        ("user", "agent".to_string(), "agent".to_string()),
        ("pass", String::new(), String::new()),
      ]
    );
  }

  const FAKE_PASS: &str = "arkham_fake_nats_pass"; // betterleaks:allow
  const REAL_PASS: &str = "real-nats-pass"; // betterleaks:allow
  const FAKE_TOKEN: &str = "arkham_fake_nats_token"; // betterleaks:allow
  const REAL_TOKEN: &str = "real-nats-token"; // betterleaks:allow

  /// Every CONNECT field a scope swaps, as `(field, fake, real)`.
  fn fields(auth: &NatsAuth) -> Vec<(&'static str, String, String)> {
    auth
      .fields()
      .into_iter()
      .map(|field| {
        (
          field.name.as_str(),
          field.pair.fake.clone(),
          field.pair.real.expose_secret().to_string(),
        )
      })
      .collect()
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

  /// Account-signed user JWT, the shape `gen-nats-demo` writes and nats-server checks.
  fn account_signed_user_jwt(user_public: &str) -> String {
    let account = nkeys::KeyPair::new_account();
    let header = serde_json::json!({ "typ": "JWT", "alg": "ed25519-nkey" });
    let payload = serde_json::json!({
      "jti": format!("user-{user_public}"),
      "iat": 1_700_000_000_i64,
      "iss": account.public_key(),
      "name": "agent",
      "sub": user_public,
      "nats": {
        "pub": { "allow": [">"] },
        "sub": { "allow": [">"] },
        "subs": -1,
        "data": -1,
        "payload": -1,
        "type": "user",
        "version": 2
      }
    });
    let head = b64_nopad(&serde_json::to_vec(&header).expect("header"));
    let body = b64_nopad(&serde_json::to_vec(&payload).expect("payload"));
    let input = format!("{head}.{body}");
    let sig = account.sign(input.as_bytes()).expect("account signs");
    format!("{input}.{}", b64_nopad(&sig))
  }

  #[test]
  fn jwt_crate_parses_an_account_signed_nats_user_jwt() {
    let (seed, public) = user_material();
    let jwt = account_signed_user_jwt(&public);
    let token = jwt::Token::<super::UserJwtHeader, super::UserJwtClaims, _>::parse_unverified(&jwt).expect("account-signed user jwt");
    assert_eq!(token.header().alg, "ed25519-nkey");
    assert_eq!(token.header().typ, "JWT");
    assert_eq!(token.claims().sub, public);
    let real_jwt = account_signed_user_jwt(&public);
    let scope = NatsScope::from_strings(
      &format!("nats://creds:{seed}:{jwt}@nats.internal:4222"),
      &format!("tls://creds:{seed}:{real_jwt}@nats.upstream:4222"),
    );
    assert!(scope.is_ok(), "the grant rejected an account-signed user jwt");

    let header = b64_nopad(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let padded_payload = base64::Engine::encode(
      &base64::engine::general_purpose::URL_SAFE,
      format!(r#"{{"sub":"{public}","pad":"x"}}"#).as_bytes(),
    );
    assert!(padded_payload.contains('='), "the padded fixture needs padding");
    let padded = format!("{header}.{padded_payload}.{}", b64_nopad(b"sig"));
    let padded_token = jwt::Token::<super::UserJwtHeader, super::UserJwtClaims, _>::parse_unverified(&padded).expect("padded segment");
    assert_eq!(padded_token.claims().sub, public);
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
    let NatsAuth::Nkey { public_key, seed } = &scope.auth else {
      panic!("nkey username is the nkey kind");
    };
    assert_eq!(public_key.fake, case.fake_public);
    assert_eq!(public_key.real.expose_secret(), case.real_public);
    assert!(public_key.fake.starts_with('U'));
    assert_eq!(scope.auth.forbidden(), &[super::NatsField::Jwt]);
    assert!(scope.auth.signer().is_some());
    let nonce = b"N0NCE";
    let signed = seed.sign(nonce).expect("real seed signs");
    assert!(super::NatsSeed::verify(&case.real_public, nonce, &signed));
    assert!(!super::NatsSeed::verify(&case.fake_public, nonce, &signed));
    let shown = format!("{scope:?}");
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
    let NatsAuth::UserJwt { public_key, .. } = &padded.auth else {
      panic!("creds username is the user jwt kind");
    };
    assert_eq!(public_key.fake, case.fake_public);

    let scope = NatsScope::from_strings(&case.fake_creds, &case.real_creds).expect("creds");
    assert!(matches!(
      scope.upstream_tls,
      NatsUpstream::Tls {
        order: NatsTlsOrder::HandshakeFirst,
        ..
      }
    ));
    let NatsAuth::UserJwt { jwt, public_key, seed } = &scope.auth else {
      panic!("creds username is the user jwt kind");
    };
    assert_eq!(jwt.fake, case.fake_jwt);
    assert_eq!(jwt.real.expose_secret(), case.real_jwt);
    assert_eq!(public_key.fake, case.fake_public);
    assert_eq!(public_key.real.expose_secret(), case.real_public);
    assert_eq!(scope.auth.forbidden(), &[]);
    let names: Vec<&str> = scope.auth.fields().iter().map(|field| field.name.as_str()).collect();
    assert_eq!(names, ["jwt", "nkey"]);
    let signed = seed.sign(b"N0NCE").expect("real seed signs");
    assert!(super::NatsSeed::verify(public_key.real.expose_secret(), b"N0NCE", &signed));
    let shown = format!("{scope:?}");
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
        NatsUriError::AuthKindMismatch,
      ),
      (
        format!("nats://creds:{}@nats.internal:4222", case.fake_seed),
        case.real_creds.clone(),
        NatsUriError::AuthKindMismatch,
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
        NatsUriError::AuthKindMismatch,
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
