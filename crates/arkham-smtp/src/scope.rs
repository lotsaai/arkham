//! SMTP connection-string law and the scope it produces.
//!
//! `smtp://` is a cleartext session that may upgrade with STARTTLS.
//! `smtps://` is implicit TLS from the first byte. AUTH swaps on either
//! leg. `starttls=required` on an `smtp://` string records that the server
//! demands the upgrade. Trust and identity ride the real string on either scheme.

use std::path::PathBuf;
use std::str::FromStr;

use secrecy::SecretString;
use strum::EnumIter;
use url::Url;

use arkham_wire::{GuestTlsMode, RootCert};

/// `smtp://` or `smtps://` as the connection string states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MailScheme {
  /// Cleartext until STARTTLS.
  Clear,
  /// TLS from the first byte.
  Tls,
}

/// One leg of an SMTP rule: the connection facts of one connection string.
#[derive(Debug, Clone)]
pub struct SmtpLeg {
  /// Dial host.
  pub host: String,
  /// Dial port.
  pub port: u16,
  /// AUTH identity this leg presents.
  pub user: String,
  /// AUTH secret this leg presents.
  pub password: SecretString,
}

/// An SMTP rule's scope: both legs of its one connection-string mapping.
///
/// Each string states its own transport in its scheme. `smtp://` is
/// cleartext. `smtps://` is TLS from the first byte. Trust and identity
/// ride the real string's query (`sslrootcert`, `sslcert`/`sslkey`) on
/// either scheme. The rule's `tls` table states the guest leg's mode,
/// keyed by the rule's env name.
#[derive(Debug, Clone)]
pub struct SmtpScope {
  /// The guest's leg, from the rule's stated fake connection string.
  pub downstream: SmtpLeg,
  /// Whether the guest leg is implicit TLS (an `smtps://` fake string).
  pub is_downstream_tls: bool,
  /// The server's leg, from the resolved real connection string.
  pub upstream: SmtpLeg,
  /// Whether the upstream leg is implicit TLS (an `smtps://` real string).
  pub is_upstream_tls: bool,
  /// The real string says the server requires STARTTLS before AUTH.
  pub starttls_required: bool,
  /// Trust anchor for upstream verification, when the real string names one.
  pub root_cert: Option<RootCert>,
  /// PEM client certificate for upstream authentication, when named.
  pub client_cert: Option<PathBuf>,
  /// PEM client key, paired with [`Self::client_cert`].
  pub client_key: Option<PathBuf>,
  /// How the guest leg treats client certificates (rule table, not the URL).
  pub guest_tls: GuestTlsMode,
}

/// Why one `smtp://` or `smtps://` string was rejected.
///
/// The text names the field or the problem. It never includes the connection
/// string: that string carries the user and the password.
#[derive(Debug, thiserror::Error)]
pub enum SmtpUriError {
  /// The string is not `smtp://` or `smtps://`.
  #[error("bad connection string: expected smtp:// or smtps://")]
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
    /// `user` or `password`.
    label: &'static str,
    /// Decoder failure.
    #[source]
    source: std::str::Utf8Error,
  },
  /// AUTH has no identity.
  #[error("bad connection string: the user is required — a string with no AUTH identity maps nothing")]
  UserRequired,
  /// AUTH has no secret.
  #[error("bad connection string: the password is required — a string with no credential maps nothing")]
  PasswordRequired,
  /// An SMTP string carries a path.
  #[error("bad connection string: an SMTP string has no path")]
  Path,
  /// `starttls` was set on `smtps://`.
  #[error("bad connection string: smtps:// is already TLS; `starttls` belongs on smtp://")]
  StarttlsOnTls,
  /// `starttls` was not `required`.
  #[error("bad connection string: starttls is `required` or absent, not `{value}`")]
  StarttlsValue {
    /// The rejected value.
    value: String,
  },
  /// A query tried to restate the transport the scheme already states.
  #[error("bad connection string: smtp strings state their transport in the scheme, never in `{key}`")]
  TransportQuery {
    /// `sslmode`, `ssl`, or `sslnegotiation`.
    key: String,
  },
  /// A path query was empty.
  #[error("bad connection string: {key} needs a path")]
  EmptyMaterial {
    /// `sslrootcert`, `sslcert`, or `sslkey`.
    key: &'static str,
  },
  /// The query key is not one this scheme accepts.
  #[error("bad connection string: unknown query `{key}`")]
  UnknownQuery {
    /// The rejected key.
    key: String,
  },
  /// `sslcert` and `sslkey` were not paired.
  #[error("bad connection string: sslcert and sslkey come together")]
  CertKeyPair,
  /// The fake string carried an option that only the real string may set.
  #[error("bad connection string: `{key}` belongs on the real connection string")]
  FakeRealOnly {
    /// `starttls`, or a trust or identity key.
    key: String,
  },
  /// The fake string carried a query key it does not accept.
  #[error("bad connection string: the fake connection string does not accept `{key}`")]
  FakeUnknown {
    /// The rejected key.
    key: String,
  },
}

/// One parsed `smtp://` or `smtps://` string.
#[derive(Debug)]
struct SmtpUri {
  scheme: MailScheme,
  host: String,
  port: u16,
  user: String,
  password: SecretString,
  starttls_required: bool,
  query: Vec<(String, String)>,
}

impl FromStr for SmtpUri {
  type Err = SmtpUriError;

  /// Parse one SMTP connection string. The user and the password are both
  /// required: a string with no AUTH identity maps nothing. An omitted port
  /// is 587 for `smtp://` and 465 for `smtps://`.
  fn from_str(entry: &str) -> Result<Self, Self::Err> {
    let scheme = if entry.starts_with("smtps://") {
      MailScheme::Tls
    } else if entry.starts_with("smtp://") {
      MailScheme::Clear
    } else {
      return Err(SmtpUriError::Scheme);
    };
    let url = Url::parse(entry).map_err(|source| SmtpUriError::Url { source })?;
    let host = url.host().map(|host| host.to_string()).ok_or(SmtpUriError::EmptyHost)?;
    // `Url` leaves userinfo percent-encoded. An SMTP user is an address,
    // so `@` is written `%40` and has to be decoded before AUTH. A `%`
    // that is not two hex digits stays literal; only invalid UTF-8 fails.
    let user = percent_encoding::percent_decode_str(url.username())
      .decode_utf8()
      .map_err(|source| SmtpUriError::UserinfoUtf8 { label: "user", source })?
      .into_owned();
    if user.is_empty() {
      return Err(SmtpUriError::UserRequired);
    }
    let password = match url.password().filter(|password| !password.is_empty()) {
      Some(password) => {
        let decoded = percent_encoding::percent_decode_str(password)
          .decode_utf8()
          .map_err(|source| SmtpUriError::UserinfoUtf8 { label: "password", source })?
          .into_owned();
        SecretString::new(decoded.into())
      }
      None => return Err(SmtpUriError::PasswordRequired),
    };
    if url.path() != "" && url.path() != "/" {
      return Err(SmtpUriError::Path);
    }
    let mut starttls_required = false;
    let mut query = Vec::new();
    for (key, value) in url.query_pairs() {
      if key == "starttls" {
        if scheme == MailScheme::Tls {
          return Err(SmtpUriError::StarttlsOnTls);
        }
        if value != "required" {
          return Err(SmtpUriError::StarttlsValue { value: value.into_owned() });
        }
        starttls_required = true;
        continue;
      }
      query.push((key.into_owned(), value.into_owned()));
    }
    let default_port = if scheme == MailScheme::Tls { 465 } else { 587 };
    Ok(Self {
      scheme,
      host,
      port: url.port().unwrap_or(default_port),
      user,
      password,
      starttls_required,
      query,
    })
  }
}

impl SmtpUri {
  /// The leg a rule builds from this string.
  fn leg(self) -> SmtpLeg {
    SmtpLeg {
      host: self.host,
      port: self.port,
      user: self.user,
      password: self.password,
    }
  }
}

/// Trust and identity from the real string's query. Legal on cleartext and TLS.
struct SmtpTls {
  root_cert: Option<RootCert>,
  client_cert: Option<PathBuf>,
  client_key: Option<PathBuf>,
}

/// A query key the real string may carry. `starttls` is consumed before
/// the query list, so it is not a variant. Both the fake-string check and
/// `smtp_tls` match this enum, so a new key has one place to land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
enum SmtpQuery {
  SslMode,
  Ssl,
  SslNegotiation,
  SslRootCert,
  SslCert,
  SslKey,
}

impl SmtpQuery {
  fn parse(key: &str) -> Option<Self> {
    Some(match key {
      "sslmode" => Self::SslMode,
      "ssl" => Self::Ssl,
      "sslnegotiation" => Self::SslNegotiation,
      "sslrootcert" => Self::SslRootCert,
      "sslcert" => Self::SslCert,
      "sslkey" => Self::SslKey,
      _ => return None,
    })
  }

  fn as_str(self) -> &'static str {
    match self {
      Self::SslMode => "sslmode",
      Self::Ssl => "ssl",
      Self::SslNegotiation => "sslnegotiation",
      Self::SslRootCert => "sslrootcert",
      Self::SslCert => "sslcert",
      Self::SslKey => "sslkey",
    }
  }
}

fn reject_fake_query(uri: &SmtpUri) -> Result<(), SmtpUriError> {
  if uri.starttls_required {
    return Err(SmtpUriError::FakeRealOnly { key: "starttls".into() });
  }
  let Some((key, _)) = uri.query.first() else {
    return Ok(());
  };
  if SmtpQuery::parse(key).is_some() {
    return Err(SmtpUriError::FakeRealOnly { key: key.clone() });
  }
  Err(SmtpUriError::FakeUnknown { key: key.clone() })
}

fn smtp_tls(uri: &SmtpUri) -> Result<SmtpTls, SmtpUriError> {
  let mut root_cert = None;
  let mut client_cert = None;
  let mut client_key = None;
  for (key, value) in &uri.query {
    let tls_material = match SmtpQuery::parse(key) {
      None => return Err(SmtpUriError::UnknownQuery { key: key.clone() }),
      Some(SmtpQuery::SslMode | SmtpQuery::Ssl | SmtpQuery::SslNegotiation) => {
        return Err(SmtpUriError::TransportQuery { key: key.clone() });
      }
      Some(query @ SmtpQuery::SslRootCert) => {
        if value.is_empty() {
          return Err(SmtpUriError::EmptyMaterial { key: query.as_str() });
        }
        Some(if value == "system" {
          RootCert::System
        } else {
          RootCert::Path(PathBuf::from(value))
        })
      }
      Some(query @ SmtpQuery::SslCert) => {
        if value.is_empty() {
          return Err(SmtpUriError::EmptyMaterial { key: query.as_str() });
        }
        client_cert = Some(PathBuf::from(value));
        None
      }
      Some(query @ SmtpQuery::SslKey) => {
        if value.is_empty() {
          return Err(SmtpUriError::EmptyMaterial { key: query.as_str() });
        }
        client_key = Some(PathBuf::from(value));
        None
      }
    };
    if let Some(root) = tls_material {
      root_cert = Some(root);
    }
  }
  if client_cert.is_some() != client_key.is_some() {
    return Err(SmtpUriError::CertKeyPair);
  }
  Ok(SmtpTls {
    root_cert,
    client_cert,
    client_key,
  })
}

impl SmtpScope {
  /// Both legs of an SMTP rule from its two connection strings: the fake
  /// the rule states, the real the secret source resolved.
  ///
  /// # Errors
  ///
  /// Either string is not an `smtp://` or `smtps://` connection string, the
  /// fake string has a query, or the real string's query breaks the law above.
  /// The guest's TLS mode comes from the rule `tls` table, so the fake
  /// string takes no query options.
  pub fn from_strings(fake: &str, real: &str) -> Result<Self, SmtpUriError> {
    let downstream = fake.parse::<SmtpUri>()?;
    let upstream = real.parse::<SmtpUri>()?;
    reject_fake_query(&downstream)?;
    let SmtpTls {
      root_cert,
      client_cert,
      client_key,
    } = smtp_tls(&upstream)?;
    Ok(Self {
      is_downstream_tls: downstream.scheme == MailScheme::Tls,
      downstream: downstream.leg(),
      is_upstream_tls: upstream.scheme == MailScheme::Tls,
      starttls_required: upstream.starttls_required,
      upstream: upstream.leg(),
      root_cert,
      client_cert,
      client_key,
      guest_tls: GuestTlsMode::default(),
    })
  }
}

#[cfg(test)]
mod tests {
  use std::path::PathBuf;

  use super::{RootCert, SmtpScope, SmtpUri};

  const USER: &str = "agent%40box.test";
  const USER_TEXT: &str = "agent@box.test";
  const PASS: &str = "real-smtp-pass"; // betterleaks:allow

  #[test]
  fn smtp_uri_error_names_the_problem_and_hides_userinfo() {
    let parsed = [
      (format!("smtp://{USER}:{PASS}@mail.internal:587/inbox"), "no path"),
      (format!("smtp://{USER}:{PASS}@mail.internal:587?starttls=maybe"), "starttls"),
      (format!("smtps://{USER}:{PASS}@mail.internal:465?starttls=required"), "already TLS"),
      (format!("http://{USER}:{PASS}@mail.internal"), "expected smtp://"),
      (format!("smtp://{USER}@mail.internal:587"), "the password is required"),
      (format!("smtp://:{PASS}@mail.internal:587"), "the user is required"),
      (format!("smtp://{USER}:%FF@mail.internal:587"), "the password is not valid UTF-8"), // betterleaks:allow
    ];
    for (entry, problem) in parsed {
      let err = entry.parse::<SmtpUri>().expect_err("rejected string");
      assert_hides(&entry, &err.to_string(), problem);
    }
    let fake = format!("smtp://{USER}:{PASS}@mail.internal:587");
    let queried = [
      (format!("smtp://{USER}:{PASS}@mail.internal:587?sslmode=require"), "sslmode"),
      (format!("smtps://{USER}:{PASS}@mail.internal:465?sslcert="), "sslcert needs a path"),
    ];
    for (real, problem) in queried {
      let err = SmtpScope::from_strings(&fake, &real).expect_err("rejected string");
      assert_hides(&real, &err.to_string(), problem);
      assert_hides(&fake, &err.to_string(), problem);
      let wrapped = crate::Error::Scope {
        label: "SMTP_URL".into(),
        source: SmtpScope::from_strings(&fake, &real).expect_err("rejected string"),
      };
      assert_hides(&real, &wrapped.to_string(), problem);
    }
  }

  #[test]
  fn every_real_query_key_is_rejected_on_the_fake_string() {
    let real = format!("smtp://{USER}:{PASS}@mail.internal:587");
    for query in <super::SmtpQuery as strum::IntoEnumIterator>::iter() {
      assert_eq!(super::SmtpQuery::parse(query.as_str()), Some(query));
      let key = query.as_str();
      let fake = format!("smtp://{USER}:{PASS}@mail.internal:587?{key}=1");
      let err = SmtpScope::from_strings(&fake, &real).expect_err(key);
      assert!(
        matches!(err, super::SmtpUriError::FakeRealOnly { key: ref got } if got == key),
        "{key}: {err}"
      );
      let text = err.to_string();
      assert_hides(&fake, &text, key);
      assert!(!text.contains("smtp://"), "{text}");
    }
  }

  #[test]
  fn fake_query_rejects_real_only_and_unknown_options() {
    let real = format!("smtp://{USER}:{PASS}@mail.internal:587");
    let cases = [
      (format!("smtp://{USER}:{PASS}@mail.internal:587?starttls=required"), "starttls"),
      (format!("smtp://{USER}:{PASS}@mail.internal:587?sslmode=require"), "sslmode"),
      (format!("smtp://{USER}:{PASS}@mail.internal:587?sslrootcert=/ca.pem"), "sslrootcert"),
      (format!("smtps://{USER}:{PASS}@mail.internal:465?sslcert=/c.pem"), "sslcert"),
      (format!("smtp://{USER}:{PASS}@mail.internal:587?foo=1"), "foo"),
    ];
    for (fake, key) in cases {
      let err = SmtpScope::from_strings(&fake, &real).expect_err("fake query");
      let text = err.to_string();
      assert_hides(&fake, &text, key);
      assert_hides(&real, &text, key);
      assert!(!text.contains("smtp://"), "{text}");
    }
  }

  #[test]
  fn cleartext_real_string_keeps_trust_and_identity() {
    let fake = format!("smtp://{USER}:{PASS}@mail.internal:587");
    let trust = format!("smtp://{USER}:{PASS}@mail.internal:25?sslrootcert=/ca.pem");
    let scope = SmtpScope::from_strings(&fake, &trust).expect("trust on cleartext");
    assert!(matches!(scope.root_cert, Some(RootCert::Path(ref path)) if path == &PathBuf::from("/ca.pem")));
    assert!(!scope.is_upstream_tls);
    let identity = format!("smtp://{USER}:{PASS}@mail.internal:25?sslcert=/c.pem&sslkey=/c.key");
    let scope = SmtpScope::from_strings(&fake, &identity).expect("identity on cleartext");
    assert_eq!(scope.client_cert, Some(PathBuf::from("/c.pem")));
    assert_eq!(scope.client_key, Some(PathBuf::from("/c.key")));
  }

  fn assert_hides(entry: &str, text: &str, problem: &str) {
    assert!(text.contains(problem), "{text}");
    for secret in [USER, USER_TEXT, PASS, entry] {
      assert!(!text.contains(secret), "{text} contains {secret}");
    }
  }
}
