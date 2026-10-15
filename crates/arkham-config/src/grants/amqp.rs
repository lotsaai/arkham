//! AMQP vertical. The connection string is the grant: the scheme states
//! each leg's transport (`amqp://` cleartext, `amqps://` TLS from the first
//! byte), and the rule-to-scope assembly lives here.

use std::path::PathBuf;
use std::str::FromStr;

use secrecy::{ExposeSecret as _, SecretString};
use url::Url;

use super::{Credential, Grant, GuestTlsMode, RootCert, Scheme};
use crate::config::RuleCfg;
use crate::error::Error;

/// One leg of an AMQP rule: the connection facts of one connection string.
#[derive(Debug, Clone)]
pub struct AmqpLeg {
  /// Dial host.
  pub host: String,
  /// Dial port.
  pub port: u16,
  /// SASL user this leg presents.
  pub user: String,
  /// SASL password this leg presents.
  pub password: SecretString,
  /// Virtual host the string names. The relay never rewrites it.
  pub vhost: String,
}

/// An AMQP rule's scope: both legs of its one connection-string mapping.
/// Each string's scheme states its leg's transport: `amqp://` is cleartext,
/// `amqps://` is TLS from the first byte, and there is no in-band upgrade.
/// Trust and identity ride the real string's query (`sslrootcert`,
/// `sslcert`/`sslkey`); the rule's `tls` table states the guest leg's
/// mode, keyed by the rule's env name.
#[derive(Debug, Clone)]
pub struct AmqpScope {
  /// The guest's leg, from the rule's stated fake connection string.
  pub downstream: AmqpLeg,
  /// Whether the guest leg is TLS from the first byte (an `amqps://` fake string).
  pub is_downstream_tls: bool,
  /// The server's leg, from the resolved real connection string.
  pub upstream: AmqpLeg,
  /// Whether the upstream leg is TLS from the first byte (an `amqps://` real string).
  pub is_upstream_tls: bool,
  /// Trust anchor for upstream verification, when the real string names one.
  pub root_cert: Option<RootCert>,
  /// PEM client certificate for upstream mTLS, when the real string names one.
  pub client_cert: Option<PathBuf>,
  /// PEM client key for upstream mTLS, when the real string names one.
  pub client_key: Option<PathBuf>,
  /// How the guest leg treats client certificates (rule table, not the URL).
  pub guest_tls: GuestTlsMode,
}

/// Why one `amqp://` or `amqps://` string was rejected.
///
/// The text names the field or the problem. It never includes the connection
/// string: that string carries the user and the password.
#[derive(Debug, thiserror::Error)]
pub enum AmqpUriError {
  /// The string is not `amqp://` or `amqps://`.
  #[error("bad connection string: expected amqp:// or amqps://")]
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
  /// A component is not UTF-8 after percent-decoding.
  #[error("bad connection string: the {label} is not valid UTF-8")]
  NotUtf8 {
    /// `user`, `password`, or `vhost`.
    label: &'static str,
    /// Decoder failure.
    #[source]
    source: std::str::Utf8Error,
  },
  /// The string has no user.
  #[error("bad connection string: the user is required — a string with no credential maps nothing")]
  UserRequired,
  /// The string has no password.
  #[error("bad connection string: the password is required — a string with no credential maps nothing")]
  PasswordRequired,
  /// A query tried to restate the transport the scheme already states.
  #[error("bad connection string: amqp strings state their transport in the scheme, never in `{key}`")]
  TransportQuery {
    /// `sslmode`, `ssl`, or `sslnegotiation`.
    key: String,
  },
  /// TLS material on a cleartext string, which never opens TLS.
  #[error("bad connection string: {key} is legal only on amqps://")]
  CleartextMaterial {
    /// `sslrootcert`, `sslcert`, or `sslkey`.
    key: &'static str,
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
}

/// One parsed `amqp://` or `amqps://` string.
#[derive(Debug)]
struct AmqpUri {
  scheme: Scheme,
  host: String,
  port: u16,
  user: String,
  password: SecretString,
  vhost: String,
  query: Vec<(String, String)>,
}

/// Percent-decode one URL component; only invalid UTF-8 fails.
fn decode(raw: &str, label: &'static str) -> Result<String, AmqpUriError> {
  percent_encoding::percent_decode_str(raw)
    .decode_utf8()
    .map(std::borrow::Cow::into_owned)
    .map_err(|source| AmqpUriError::NotUtf8 { label, source })
}

impl FromStr for AmqpUri {
  type Err = AmqpUriError;

  /// Parse one AMQP connection string. The user and the password are both
  /// required: a string with no credential maps nothing. An omitted port is
  /// 5672 for `amqp://` and 5671 for `amqps://`. The vhost is the path with
  /// one leading slash removed, percent-decoded; no path is `/`.
  ///
  /// # Errors
  ///
  /// Returns [`AmqpUriError`] when the scheme, host, or userinfo breaks the
  /// amqp law. The error text names the problem and never the connection
  /// string.
  fn from_str(entry: &str) -> Result<Self, Self::Err> {
    let scheme = if entry.starts_with("amqps://") {
      Scheme::Amqps
    } else if entry.starts_with("amqp://") {
      Scheme::Amqp
    } else {
      return Err(AmqpUriError::Scheme);
    };
    let url = Url::parse(entry).map_err(|source| AmqpUriError::Url { source })?;
    let host = url.host().map(|host| host.to_string()).ok_or(AmqpUriError::EmptyHost)?;
    let user = decode(url.username(), "user")?;
    if user.is_empty() {
      return Err(AmqpUriError::UserRequired);
    }
    let password = match url.password().filter(|password| !password.is_empty()) {
      Some(password) => SecretString::new(decode(password, "password")?.into()),
      None => return Err(AmqpUriError::PasswordRequired),
    };
    let vhost = match url.path().strip_prefix('/') {
      Some(path) => decode(path, "vhost")?,
      None => "/".to_string(),
    };
    let port = url.port().unwrap_or(if scheme == Scheme::Amqps { 5671 } else { 5672 });
    Ok(Self {
      scheme,
      host,
      port,
      user,
      password,
      vhost,
      query: url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect(),
    })
  }
}

impl AmqpUri {
  /// The leg a rule builds from this string.
  fn leg(self) -> AmqpLeg {
    AmqpLeg {
      host: self.host,
      port: self.port,
      user: self.user,
      password: self.password,
      vhost: self.vhost,
    }
  }
}

/// Trust and identity from one `amqps://` string's query.
struct AmqpTls {
  root_cert: Option<RootCert>,
  client_cert: Option<PathBuf>,
  client_key: Option<PathBuf>,
}

fn amqp_tls(uri: &AmqpUri) -> Result<AmqpTls, AmqpUriError> {
  let mut root_cert = None;
  let mut client_cert = None;
  let mut client_key = None;
  for (key, value) in &uri.query {
    let material = |key: &'static str| {
      if uri.scheme != Scheme::Amqps {
        Err(AmqpUriError::CleartextMaterial { key })
      } else if value.is_empty() {
        Err(AmqpUriError::EmptyMaterial { key })
      } else {
        Ok(PathBuf::from(value))
      }
    };
    match key.as_str() {
      "sslmode" | "ssl" | "sslnegotiation" => {
        return Err(AmqpUriError::TransportQuery { key: key.clone() });
      }
      "sslrootcert" => {
        let path = material("sslrootcert")?;
        root_cert = Some(if value == "system" {
          RootCert::System
        } else {
          RootCert::Path(path)
        });
      }
      "sslcert" => client_cert = Some(material("sslcert")?),
      "sslkey" => client_key = Some(material("sslkey")?),
      _ => return Err(AmqpUriError::UnknownQuery { key: key.clone() }),
    }
  }
  if client_cert.is_some() != client_key.is_some() {
    return Err(AmqpUriError::CertKeyPair);
  }
  Ok(AmqpTls {
    root_cert,
    client_cert,
    client_key,
  })
}

impl AmqpScope {
  /// Both legs of an AMQP rule from its two connection strings.
  ///
  /// # Errors
  /// Either string is not an `amqp://` or `amqps://` connection string,
  /// or its query breaks the amqp law above.
  pub fn from_strings(fake: &str, real: &str) -> Result<Self, AmqpUriError> {
    let downstream = fake.parse::<AmqpUri>()?;
    let upstream = real.parse::<AmqpUri>()?;
    amqp_tls(&downstream)?;
    let AmqpTls {
      root_cert,
      client_cert,
      client_key,
    } = amqp_tls(&upstream)?;
    Ok(Self {
      is_downstream_tls: downstream.scheme == Scheme::Amqps,
      downstream: downstream.leg(),
      is_upstream_tls: upstream.scheme == Scheme::Amqps,
      upstream: upstream.leg(),
      root_cert,
      client_cert,
      client_key,
      guest_tls: GuestTlsMode::default(),
    })
  }

  /// Grant-level match for a concrete request: scheme + port + host.
  pub(super) fn matches(scope: &Self, scheme: Scheme, host: &str, port: u16) -> bool {
    matches!(scheme, Scheme::Amqp | Scheme::Amqps) && port == scope.downstream.port && scope.downstream.host.eq_ignore_ascii_case(host)
  }
}

/// Assemble one AMQP grant from its rule.
///
/// # Errors
///
/// Returns an error when either string fails the amqp law above, or when
/// a `tls` row tries to state what only the real string may state.
pub(super) fn grant(label: &str, rule: &RuleCfg, real: &str) -> Result<Grant, Error> {
  let fake = rule
    .value
    .as_ref()
    .map(|value| value.expose_secret().to_string())
    .unwrap_or_default();
  let mut scope = AmqpScope::from_strings(&fake, real).map_err(|source| Error::AmqpScope {
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
      return Err(Error::AmqpIdentity { label: label.to_string() });
    }
    if tls.root_cert.is_some() {
      return Err(Error::AmqpTrust { label: label.to_string() });
    }
    scope.guest_tls = tls.guest_tls_mode;
  }
  let credential = Credential {
    label: label.to_string(),
    fake: scope.downstream.password.expose_secret().to_string(),
    value: scope.upstream.password.clone(),
  };
  Ok(Grant::Amqp {
    credential,
    scope: Box::new(scope),
  })
}

#[cfg(test)]
mod tests {
  use super::AmqpScope;

  const USER: &str = "arkham-amqp";
  const PASS: &str = "arkham_real_amqp_pass_01"; // betterleaks:allow

  #[test]
  fn amqp_uri_error_names_the_problem_and_hides_userinfo() {
    let parsed = [
      (format!("http://{USER}:{PASS}@mq.internal"), "expected amqp:// or amqps://"),
      (format!("amqp://{USER}@mq.internal"), "the password is required"),
      (format!("amqp://:{PASS}@mq.internal"), "the user is required"),
      (format!("amqp://{USER}:%FF@mq.internal"), "the password is not valid UTF-8"), // betterleaks:allow
    ];
    for (entry, problem) in parsed {
      let err = entry.parse::<super::AmqpUri>().expect_err("rejected string");
      assert_hides(&entry, &err.to_string(), problem);
    }
    let fake = format!("amqp://{USER}:{PASS}@mq.internal");
    let queried = [
      (format!("amqp://{USER}:{PASS}@mq.internal?sslmode=require"), "sslmode"),
      (format!("amqps://{USER}:{PASS}@mq.internal?sslcert="), "sslcert needs a path"),
      (format!("amqps://{USER}:{PASS}@mq.internal?unknown=1"), "unknown query"),
      (format!("amqps://{USER}:{PASS}@mq.internal?sslcert=/c.pem"), "come together"),
      (format!("amqp://{USER}:{PASS}@mq.internal?sslrootcert=system"), "amqps"),
    ];
    for (real, problem) in queried {
      let err = AmqpScope::from_strings(&fake, &real).expect_err("rejected string");
      assert_hides(&real, &err.to_string(), problem);
      assert_hides(&fake, &err.to_string(), problem);
    }
  }

  #[test]
  fn amqp_scope_ports_and_tls_follow_each_string() {
    let fake = format!("amqp://{USER}:arkham_fake_amqp_pass@mq.internal/demo"); // betterleaks:allow
    let real = format!("amqps://{USER}:{PASS}@mq.internal:5671/%2F?sslrootcert=system");
    let scope = AmqpScope::from_strings(&fake, &real).expect("pair of strings");
    assert_eq!(scope.downstream.port, 5672);
    assert_eq!(scope.upstream.port, 5671);
    assert!(!scope.is_downstream_tls);
    assert!(scope.is_upstream_tls);
    assert_eq!(scope.downstream.vhost, "demo");
    assert_eq!(scope.upstream.vhost, "/");
    assert_eq!(scope.downstream.user, USER);
    let bare = format!("amqp://{USER}:arkham_fake_amqp_pass@mq.internal"); // betterleaks:allow
    let bare_scope = AmqpScope::from_strings(&bare, &real).expect("default vhost");
    assert_eq!(bare_scope.downstream.vhost, "/");
  }

  fn assert_hides(entry: &str, text: &str, problem: &str) {
    assert!(text.contains(problem), "{text}");
    for secret in [USER, PASS, "arkham_fake_amqp_pass", entry] {
      assert!(!text.contains(secret), "{text} contains {secret}");
    }
  }
}
