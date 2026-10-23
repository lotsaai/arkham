//! LDAP vertical: the protocol's scope types, its own connection-string
//! law (each string's scheme states how that leg opens), and the
//! rule-to-scope assembly.

use std::path::PathBuf;
use std::str::FromStr;

use secrecy::{ExposeSecret as _, SecretString};
use url::Url;

use super::{Credential, Grant, GuestTlsMode, RootCert, Scheme};
use crate::config::RuleCfg;
use crate::error::Error;

/// One leg of an LDAP rule: the connection facts of one connection string.
#[derive(Debug, Clone)]
pub struct LdapLeg {
  /// Dial host.
  pub host: String,
  /// Dial port.
  pub port: u16,
  /// Bind DN this leg presents.
  pub dn: String,
  /// Simple-bind password this leg presents.
  pub password: SecretString,
}

/// An LDAP rule's scope: both legs of its one connection-string mapping.
/// Each string states how its leg opens: `ldap://` is cleartext (and may
/// upgrade with `StartTLS`), `ldaps://` is TLS from the first byte. Trust
/// and identity ride the real string's query (`sslrootcert`,
/// `sslcert`/`sslkey`); the rule's `tls` table states the guest leg's
/// mode, keyed by the rule's env name.
#[derive(Debug, Clone)]
pub struct LdapScope {
  /// The guest's leg, from the rule's stated fake connection string.
  pub downstream: LdapLeg,
  /// Whether the guest leg is TLS from the first byte (an `ldaps://` fake string).
  pub is_downstream_tls: bool,
  /// The server's leg, from the resolved real connection string.
  pub upstream: LdapLeg,
  /// Whether the upstream leg is TLS from the first byte (an `ldaps://` real string).
  pub is_upstream_tls: bool,
  /// Trust anchor for upstream verification, when the real string names one.
  /// `StartTLS` uses it after the upgrade; LDAPS uses it on connect.
  pub root_cert: Option<RootCert>,
  /// PEM client certificate for upstream mTLS, when the real string names one.
  pub client_cert: Option<PathBuf>,
  /// PEM client key for upstream mTLS, when the real string names one.
  pub client_key: Option<PathBuf>,
  /// How the guest leg treats client certificates (rule table, not the URL).
  pub guest_tls: GuestTlsMode,
}

/// Why one `ldap://` or `ldaps://` string was rejected.
///
/// The text names the field or the problem. It never includes the connection
/// string: that string carries the bind DN and the password.
#[derive(Debug, thiserror::Error)]
pub enum LdapUriError {
  /// The string is not `ldap://` or `ldaps://`.
  #[error("bad connection string: expected ldap:// or ldaps://")]
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
    /// `bind dn` or `password`.
    label: &'static str,
    /// Decoder failure.
    #[source]
    source: std::str::Utf8Error,
  },
  /// The bind has no DN.
  #[error("bad connection string: the bind dn is required — a string with no credential maps nothing")]
  DnRequired,
  /// The bind has no password.
  #[error("bad connection string: the password is required — a string with no credential maps nothing")]
  PasswordRequired,
  /// An LDAP string carries a path.
  #[error("bad connection string: an ldap string has no path")]
  Path,
  /// A query tried to restate the transport the scheme already states.
  #[error("bad connection string: ldap strings state their transport in the scheme, never in `{key}`")]
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
}

/// One parsed `ldap://` or `ldaps://` string.
#[derive(Debug)]
struct LdapUri {
  scheme: Scheme,
  host: String,
  port: u16,
  dn: String,
  password: SecretString,
  query: Vec<(String, String)>,
}

impl FromStr for LdapUri {
  type Err = LdapUriError;

  /// Parse one LDAP connection string. The bind DN and the password are both
  /// required: a string with no credential maps nothing. An omitted port is
  /// 389 for `ldap://` and 636 for `ldaps://`.
  ///
  /// # Errors
  ///
  /// Returns [`LdapUriError`] when the scheme, userinfo, path, or query
  /// breaks the ldap law. The error text names the problem and never the
  /// connection string.
  fn from_str(entry: &str) -> Result<Self, Self::Err> {
    let scheme = if entry.starts_with("ldaps://") {
      Scheme::Ldaps
    } else if entry.starts_with("ldap://") {
      Scheme::Ldap
    } else {
      return Err(LdapUriError::Scheme);
    };
    let url = Url::parse(entry).map_err(|source| LdapUriError::Url { source })?;
    let host = url.host().map(|host| host.to_string()).ok_or(LdapUriError::EmptyHost)?;
    // `Url` leaves userinfo percent-encoded. A bind DN carries `=` and
    // spaces, written `%3D` and `%20`, and has to be decoded before the
    // directory sees it. A `%` that is not two hex digits stays literal;
    // only invalid UTF-8 fails.
    let dn = percent_encoding::percent_decode_str(url.username())
      .decode_utf8()
      .map_err(|source| LdapUriError::UserinfoUtf8 { label: "bind dn", source })?
      .into_owned();
    if dn.is_empty() {
      return Err(LdapUriError::DnRequired);
    }
    let password = match url.password().filter(|password| !password.is_empty()) {
      Some(password) => {
        let decoded = percent_encoding::percent_decode_str(password)
          .decode_utf8()
          .map_err(|source| LdapUriError::UserinfoUtf8 { label: "password", source })?
          .into_owned();
        SecretString::new(decoded.into())
      }
      None => return Err(LdapUriError::PasswordRequired),
    };
    if !matches!(url.path(), "" | "/") {
      return Err(LdapUriError::Path);
    }
    let port = url.port().unwrap_or(if scheme == Scheme::Ldaps { 636 } else { 389 });
    Ok(Self {
      scheme,
      host,
      port,
      dn,
      password,
      query: url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect(),
    })
  }
}

impl LdapUri {
  /// The leg a rule builds from this string.
  fn leg(self) -> LdapLeg {
    LdapLeg {
      host: self.host,
      port: self.port,
      dn: self.dn,
      password: self.password,
    }
  }
}

/// Trust and identity from one string's query. Both schemes may carry it:
/// `ldaps://` verifies on connect, and `ldap://` verifies after `StartTLS`.
struct LdapTls {
  root_cert: Option<RootCert>,
  client_cert: Option<PathBuf>,
  client_key: Option<PathBuf>,
}

fn ldap_tls(uri: &LdapUri) -> Result<LdapTls, LdapUriError> {
  let mut root_cert = None;
  let mut client_cert = None;
  let mut client_key = None;
  for (key, value) in &uri.query {
    match key.as_str() {
      "sslmode" | "ssl" | "sslnegotiation" => {
        return Err(LdapUriError::TransportQuery { key: key.clone() });
      }
      "sslrootcert" => {
        if value.is_empty() {
          return Err(LdapUriError::EmptyMaterial { key: "sslrootcert" });
        }
        root_cert = Some(if value == "system" {
          RootCert::System
        } else {
          RootCert::Path(PathBuf::from(value))
        });
      }
      "sslcert" => {
        if value.is_empty() {
          return Err(LdapUriError::EmptyMaterial { key: "sslcert" });
        }
        client_cert = Some(PathBuf::from(value));
      }
      "sslkey" => {
        if value.is_empty() {
          return Err(LdapUriError::EmptyMaterial { key: "sslkey" });
        }
        client_key = Some(PathBuf::from(value));
      }
      _ => return Err(LdapUriError::UnknownQuery { key: key.clone() }),
    }
  }
  if client_cert.is_some() != client_key.is_some() {
    return Err(LdapUriError::CertKeyPair);
  }
  Ok(LdapTls {
    root_cert,
    client_cert,
    client_key,
  })
}

impl LdapScope {
  /// Both legs of an LDAP rule from its two connection strings.
  ///
  /// # Errors
  /// Either string is not an `ldap://` or `ldaps://` connection string,
  /// or its query breaks the ldap law above.
  pub fn from_strings(fake: &str, real: &str) -> Result<Self, LdapUriError> {
    let downstream = fake.parse::<LdapUri>()?;
    let upstream = real.parse::<LdapUri>()?;
    ldap_tls(&downstream)?;
    let LdapTls {
      root_cert,
      client_cert,
      client_key,
    } = ldap_tls(&upstream)?;
    Ok(Self {
      is_downstream_tls: downstream.scheme == Scheme::Ldaps,
      downstream: downstream.leg(),
      is_upstream_tls: upstream.scheme == Scheme::Ldaps,
      upstream: upstream.leg(),
      root_cert,
      client_cert,
      client_key,
      guest_tls: GuestTlsMode::default(),
    })
  }

  /// Grant-level match for a concrete request: scheme + port + host.
  pub(super) fn matches(scope: &Self, scheme: Scheme, host: &str, port: u16) -> bool {
    matches!(scheme, Scheme::Ldap | Scheme::Ldaps) && port == scope.downstream.port && scope.downstream.host.eq_ignore_ascii_case(host)
  }
}

/// Assemble one LDAP grant from its rule.
///
/// # Errors
///
/// Returns an error when either string fails the ldap law above, or when a
/// `tls` row tries to state what only the real string may state.
pub(super) fn grant(label: &str, rule: &RuleCfg, real: &str) -> Result<Grant, Error> {
  let fake = rule
    .value
    .as_ref()
    .map(|value| value.expose_secret().to_string())
    .unwrap_or_default();
  let mut scope = LdapScope::from_strings(&fake, real).map_err(|source| Error::LdapScope {
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
      return Err(Error::LdapIdentity { label: label.to_string() });
    }
    if tls.root_cert.is_some() {
      return Err(Error::LdapTrust { label: label.to_string() });
    }
    scope.guest_tls = tls.guest_tls_mode;
  }
  let credential = Credential {
    label: label.to_string(),
    fake: scope.downstream.password.expose_secret().to_string(),
    value: scope.upstream.password.clone(),
  };
  Ok(Grant::Ldap {
    credential,
    scope: Box::new(scope),
  })
}

#[cfg(test)]
mod tests {
  use super::{LdapScope, LdapUri};

  const DN: &str = "cn%3DDirectory%20Manager";
  const DN_TEXT: &str = "cn=Directory Manager";
  const PASS: &str = "arkham_real_ldap_pass_01"; // betterleaks:allow

  #[test]
  fn ldap_uri_error_names_the_problem_and_hides_userinfo() {
    let parsed = [
      (format!("ldap://{DN}:{PASS}@ldap.internal:389/dc=example"), "no path"),
      (format!("http://{DN}:{PASS}@ldap.internal"), "expected ldap://"),
      (format!("ldap://{DN}@ldap.internal:389"), "the password is required"),
      (format!("ldap://:{PASS}@ldap.internal:389"), "the bind dn is required"),
      (format!("ldap://{DN}:%FF@ldap.internal:389"), "the password is not valid UTF-8"), // betterleaks:allow
    ];
    for (entry, problem) in parsed {
      let err = entry.parse::<LdapUri>().expect_err("rejected string");
      assert_hides(&entry, &err.to_string(), problem);
    }
    let fake = format!("ldap://{DN}:{PASS}@ldap.internal:389");
    let queried = [
      (format!("ldap://{DN}:{PASS}@ldap.internal:389?sslmode=require"), "sslmode"),
      (format!("ldap://{DN}:{PASS}@ldap.internal:389?sslcert="), "sslcert needs a path"),
      (format!("ldap://{DN}:{PASS}@ldap.internal:389?unknown=1"), "unknown query"),
      (format!("ldap://{DN}:{PASS}@ldap.internal:389?sslcert=/c.pem"), "come together"),
    ];
    for (real, problem) in queried {
      let err = LdapScope::from_strings(&fake, &real).expect_err("rejected string");
      assert_hides(&real, &err.to_string(), problem);
      assert_hides(&fake, &err.to_string(), problem);
      let wrapped = crate::Error::LdapScope {
        label: "LDAP_URL".into(),
        source: LdapScope::from_strings(&fake, &real).expect_err("rejected string"),
      };
      assert_hides(&real, &wrapped.to_string(), problem);
    }
  }

  fn assert_hides(entry: &str, text: &str, problem: &str) {
    assert!(text.contains(problem), "{text}");
    for secret in [DN, DN_TEXT, PASS, entry] {
      assert!(!text.contains(secret), "{text} contains {secret}");
    }
  }
}
