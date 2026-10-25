//! Postgres vertical: the protocol's scope types, its own connection-string
//! law (libpq's `sslmode` query grammar), and the rule-to-scope assembly.

use std::path::PathBuf;

use secrecy::SecretString;
use url::Url;

use super::{Grant, GuestTlsMode, RootCert, Scheme, apply_guest_tls, downstream_covers, map_tls_row, password_credential, stated_fake};
use crate::config::RuleCfg;
use crate::error::Error;

/// Postgres TLS negotiation, read from the entry's `sslmode` query.
///
/// The values are libpq's, because the entry URL is the user's statement about
/// how this endpoint is reached, not a place for the proxy's own policy. The
/// mode governs the leg to the real server; the guest leg answers what the
/// guest asks for, the way a real server does.
///
/// A `require` verifies the chain only when the entry also names a
/// `sslrootcert`, which is what libpq does. `verify-ca` and `verify-full` need
/// one, because there is no other source of trust this proxy could use without
/// inventing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
  /// Never TLS.
  Disable,
  /// Cleartext first; TLS when the server refuses cleartext.
  Allow,
  /// TLS when the server accepts it, cleartext when it refuses.
  Prefer,
  /// TLS only; a server that refuses it fails the connection.
  Require,
  /// TLS only, verifying the server certificate chain.
  VerifyCa,
  /// TLS only, verifying the chain and the host name.
  VerifyFull,
}

/// How the entry asks a server for TLS, from its `sslnegotiation` query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslNegotiation {
  /// The 8-byte `SSLRequest`, then its one-byte answer. Every server since
  /// forever.
  Postgres,
  /// TLS straight away, with the `postgresql` ALPN identifier. PostgreSQL 17
  /// and later only.
  Direct,
}

/// One leg of a postgres rule: the connection facts of one connection
/// string. The downstream leg comes from the rule's stated fake string; the
/// upstream leg comes from the resolved real connection string.
#[derive(Debug, Clone)]
pub struct PostgresLeg {
  /// Dial host.
  pub host: String,
  /// Dial port.
  pub port: u16,
  /// User this leg presents.
  pub user: Option<String>,
  /// Password this leg presents.
  pub password: SecretString,
  /// Database name, when the string names one.
  pub database: Option<String>,
}

/// A postgres rule's scope: both legs of its one connection-string mapping.
/// The real string states the upstream TLS policy; the rule's `tls` table
/// states the guest leg's mode, keyed by the rule's env name.
#[derive(Debug, Clone)]
pub struct PostgresScope {
  /// The guest's leg, from the rule's stated fake connection string: the
  /// guest dials this host and port — the port is the rule's match key —
  /// and presents this user and password.
  pub downstream: PostgresLeg,
  /// The server's leg, from the resolved real connection string: arkham
  /// dials this host and port and presents this user and password.
  pub upstream: PostgresLeg,
  /// TLS mode for the leg to the real server.
  pub ssl: SslMode,
  /// How TLS is asked for, when the entry states it.
  pub negotiation: SslNegotiation,
  /// Trust anchor for server verification, when the entry names one: a PEM
  /// path, or the platform store via `sslrootcert=system`.
  pub root_cert: Option<RootCert>,
  /// PEM client certificate for upstream mTLS, when the entry names one.
  pub client_cert: Option<PathBuf>,
  /// PEM client key for upstream mTLS, when the entry names one.
  pub client_key: Option<PathBuf>,
  /// How the guest leg treats client certificates (rule table, not the URL).
  pub guest_tls: GuestTlsMode,
}

/// One parsed `postgres://` string: connection facts plus raw query pairs.
#[derive(Debug)]
struct PgUri {
  host: String,
  port: u16,
  user: Option<String>,
  password: SecretString,
  database: Option<String>,
  query: Vec<(String, String)>,
}

fn decode_userinfo(raw: &str) -> Result<String, std::str::Utf8Error> {
  percent_encoding::percent_decode_str(raw)
    .decode_utf8()
    .map(std::borrow::Cow::into_owned)
}

impl PgUri {
  /// Parse one postgres connection string. The password is required — a
  /// string with no credential maps nothing.
  fn parse(entry: &str) -> Result<Self, String> {
    if !entry.starts_with("postgres://") {
      return Err(format!("bad connection string `{entry}`: expected postgres://"));
    }
    let url = Url::parse(entry).map_err(|err| format!("bad connection string `{entry}`: {err}"))?;
    let host = url
      .host()
      .map(|host| host.to_string())
      .ok_or_else(|| format!("bad connection string `{entry}`: empty host"))?;
    // `Url` leaves userinfo percent-encoded. A `:` in the password is stored
    // as `%3A`, and the client sends the decoded bytes.
    let user = if url.username().is_empty() {
      None
    } else {
      Some(decode_userinfo(url.username()).map_err(|source| format!("bad connection string `{entry}`: user is not utf-8: {source}"))?)
    };
    let password = match url.password().filter(|password| !password.is_empty()) {
      Some(password) => {
        let decoded =
          decode_userinfo(password).map_err(|source| format!("bad connection string `{entry}`: password is not utf-8: {source}"))?;
        if decoded.is_empty() {
          return Err(format!(
            "bad connection string `{entry}`: the password is required — a string with no credential maps nothing"
          ));
        }
        SecretString::new(decoded.into())
      }
      None => {
        return Err(format!(
          "bad connection string `{entry}`: the password is required — a string with no credential maps nothing"
        ));
      }
    };
    let database = match url.path() {
      "" | "/" => None,
      path => match path.strip_prefix('/').filter(|rest| !rest.contains('/')) {
        Some(name) if !name.is_empty() => Some(name.to_string()),
        _ => return Err(format!("bad connection string `{entry}`: database is one path segment")),
      },
    };
    Ok(Self {
      host,
      port: url.port().unwrap_or(5432),
      user,
      password,
      database,
      query: url.query_pairs().map(|(key, value)| (key.to_string(), value.to_string())).collect(),
    })
  }

  /// The leg a rule builds from this string.
  fn leg(self) -> PostgresLeg {
    PostgresLeg {
      host: self.host,
      port: self.port,
      user: self.user,
      password: self.password,
      database: self.database,
    }
  }
}

/// libpq's TLS parameters from one string's query.
struct PgTls {
  ssl: SslMode,
  negotiation: SslNegotiation,
  root_cert: Option<RootCert>,
  client_cert: Option<PathBuf>,
  client_key: Option<PathBuf>,
}

fn postgres_tls(entry: &str, uri: &PgUri) -> Result<PgTls, String> {
  let mut ssl = SslMode::Prefer;
  let mut negotiation = SslNegotiation::Postgres;
  let mut root_cert = None;
  let mut client_cert = None;
  let mut client_key = None;
  for (key, value) in &uri.query {
    match key.as_str() {
      "sslmode" | "ssl" => {
        ssl = match value.as_str() {
          "disable" => SslMode::Disable,
          "allow" => SslMode::Allow,
          "prefer" => SslMode::Prefer,
          "require" => SslMode::Require,
          "verify-ca" => SslMode::VerifyCa,
          "verify-full" => SslMode::VerifyFull,
          _ => {
            return Err(format!(
              "bad connection string `{entry}`: sslmode is disable, allow, prefer, require, verify-ca or verify-full"
            ));
          }
        };
      }
      "sslnegotiation" => {
        negotiation = match value.as_str() {
          "postgres" => SslNegotiation::Postgres,
          "direct" => SslNegotiation::Direct,
          _ => return Err(format!("bad connection string `{entry}`: sslnegotiation is postgres or direct")),
        };
      }
      "sslrootcert" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslrootcert needs a path"));
        }
        root_cert = Some(if value == "system" {
          RootCert::System
        } else {
          RootCert::Path(PathBuf::from(value))
        });
      }
      "sslcert" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslcert needs a path"));
        }
        client_cert = Some(PathBuf::from(value));
      }
      "sslkey" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslkey needs a path"));
        }
        client_key = Some(PathBuf::from(value));
      }
      _ => return Err(format!("bad connection string `{entry}`: unknown query `{key}`")),
    }
  }
  if client_cert.is_some() != client_key.is_some() {
    return Err(format!("bad connection string `{entry}`: sslcert and sslkey come together"));
  }
  Ok(PgTls {
    ssl,
    negotiation,
    root_cert,
    client_cert,
    client_key,
  })
}

impl PostgresScope {
  /// Both legs of a postgres rule from its two connection strings: the fake
  /// the rule states, the real the secret source resolved. The real
  /// string's TLS parameters state the upstream policy.
  ///
  /// # Errors
  /// Either string is not a `postgres://` connection string, or the real
  /// one names a verifying sslmode with no `sslrootcert` to verify against.
  pub fn from_strings(fake: &str, real: &str) -> Result<Self, String> {
    let downstream = PgUri::parse(fake)?;
    let upstream = PgUri::parse(real)?;
    let PgTls {
      ssl,
      negotiation,
      root_cert,
      client_cert,
      client_key,
    } = postgres_tls(real, &upstream)?;
    if matches!(ssl, SslMode::VerifyCa | SslMode::VerifyFull) && root_cert.is_none() {
      return Err("sslmode needs `sslrootcert=<path>` to verify against".to_string());
    }
    Ok(Self {
      downstream: downstream.leg(),
      upstream: upstream.leg(),
      ssl,
      negotiation,
      root_cert,
      client_cert,
      client_key,
      guest_tls: GuestTlsMode::default(),
    })
  }

  /// Grant-level match for a concrete request: scheme + port + host.
  pub(super) fn matches(scope: &Self, scheme: Scheme, host: &str, port: u16) -> bool {
    scheme == Scheme::Postgres && downstream_covers(&scope.downstream.host, scope.downstream.port, Some(host), port)
  }
}

/// Assemble one postgres grant from its rule: the scope from the two
/// strings, the guest-leg mode from the `tls` table keyed by the env name.
///
/// # Errors
///
/// Returns an error when either string fails the postgres law above, or
/// when a `tls` row tries to state what only the real string may state.
pub(super) fn grant(label: &str, rule: &RuleCfg, real: &str) -> Result<Grant, Error> {
  let mut scope = PostgresScope::from_strings(&stated_fake(rule), real).map_err(|err| Error::PostgresScope {
    label: label.to_string(),
    detail: err,
  })?;
  scope.guest_tls = apply_guest_tls(rule).map_err(|row| {
    map_tls_row(
      label,
      row,
      Error::PostgresIdentity { label: label.to_string() },
      Error::PostgresTrust { label: label.to_string() },
    )
  })?;
  let credential = password_credential(label, &scope.downstream.password, scope.upstream.password.clone());
  Ok(Grant::Postgres {
    credential,
    scope: Box::new(scope),
  })
}
