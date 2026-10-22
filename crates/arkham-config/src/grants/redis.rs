//! Redis vertical: the protocol's scope types, its own connection-string
//! law (each string's scheme states its leg's transport), and the
//! rule-to-scope assembly.

use std::path::PathBuf;

use secrecy::{ExposeSecret as _, SecretString};
use url::Url;

use super::{Credential, Grant, GuestTlsMode, RootCert, Scheme};
use crate::config::RuleCfg;
use crate::error::Error;

/// One leg of a redis rule: the connection facts of one connection string.
#[derive(Debug, Clone)]
pub struct RedisLeg {
  /// Dial host.
  pub host: String,
  /// Dial port.
  pub port: u16,
  /// User this leg presents (Redis 6 ACL).
  pub user: Option<String>,
  /// Password this leg presents.
  pub password: SecretString,
  /// Database index, when the string names one.
  pub database: Option<String>,
}

/// A redis rule's scope: both legs of its one connection-string mapping.
/// Each string states its own leg's transport in its scheme: `redis://` is
/// cleartext, `rediss://` is TLS. Trust and identity ride the real string's
/// query (`sslrootcert`, `sslcert`/`sslkey`); the rule's `tls` table states
/// the guest leg's mode, keyed by the rule's env name.
#[derive(Debug, Clone)]
pub struct RedisScope {
  /// The guest's leg, from the rule's stated fake connection string: the
  /// guest dials this host and port — the port is the rule's match key —
  /// and presents this user and password.
  pub downstream: RedisLeg,
  /// Whether the guest leg is TLS (a `rediss://` fake string).
  pub is_downstream_tls: bool,
  /// The server's leg, from the resolved real connection string: arkham
  /// dials this host and port and presents this user and password.
  pub upstream: RedisLeg,
  /// Whether the upstream leg is TLS (a `rediss://` real string).
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

/// One parsed `redis://` or `rediss://` string: connection facts plus raw
/// query pairs.
#[derive(Debug)]
struct RedisUri {
  scheme: Scheme,
  host: String,
  port: u16,
  user: Option<String>,
  password: SecretString,
  database: Option<String>,
  query: Vec<(String, String)>,
}

impl RedisUri {
  /// Parse one redis connection string. The password is required — a
  /// string with no credential maps nothing.
  fn parse(entry: &str) -> Result<Self, String> {
    let scheme = if entry.starts_with("redis://") {
      Scheme::Redis
    } else if entry.starts_with("rediss://") {
      Scheme::Rediss
    } else {
      return Err(format!("bad connection string `{entry}`: expected redis:// or rediss://"));
    };
    let url = Url::parse(entry).map_err(|err| format!("bad connection string `{entry}`: {err}"))?;
    let host = url
      .host()
      .map(|host| host.to_string())
      .ok_or_else(|| format!("bad connection string `{entry}`: empty host"))?;
    let user = (!url.username().is_empty()).then(|| url.username().to_string());
    let password = url
      .password()
      .filter(|password| !password.is_empty())
      .map(|password| SecretString::new(password.to_string().into()))
      .ok_or_else(|| format!("bad connection string `{entry}`: the password is required — a string with no credential maps nothing"))?;
    let database = match url.path() {
      "" | "/" => None,
      path => match path.strip_prefix('/').filter(|rest| !rest.contains('/')) {
        Some(name) if !name.is_empty() => Some(name.to_string()),
        _ => return Err(format!("bad connection string `{entry}`: database is one path segment")),
      },
    };
    Ok(Self {
      scheme,
      host,
      port: url.port().unwrap_or(6379),
      user,
      password,
      database,
      query: url.query_pairs().map(|(key, value)| (key.to_string(), value.to_string())).collect(),
    })
  }

  /// The leg a rule builds from this string.
  fn leg(self) -> RedisLeg {
    RedisLeg {
      host: self.host,
      port: self.port,
      user: self.user,
      password: self.password,
      database: self.database,
    }
  }
}

/// Trust and identity from one string's query. The scheme says whether the
/// leg speaks TLS. A cleartext string may still name a certificate.
struct RedisTls {
  root_cert: Option<RootCert>,
  client_cert: Option<PathBuf>,
  client_key: Option<PathBuf>,
}

fn redis_tls(entry: &str, uri: &RedisUri) -> Result<RedisTls, String> {
  let mut root_cert = None;
  let mut client_cert = None;
  let mut client_key = None;
  for (key, value) in &uri.query {
    let tls_material = match key.as_str() {
      "sslmode" | "ssl" => {
        return Err(format!(
          "bad connection string `{entry}`: redis strings state their transport in the scheme, never in `sslmode`"
        ));
      }
      "sslnegotiation" => {
        return Err(format!(
          "bad connection string `{entry}`: redis strings state their transport in the scheme, never in `sslnegotiation`"
        ));
      }
      "sslrootcert" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslrootcert needs a path"));
        }
        Some(if value == "system" {
          RootCert::System
        } else {
          RootCert::Path(PathBuf::from(value))
        })
      }
      "sslcert" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslcert needs a path"));
        }
        client_cert = Some(PathBuf::from(value));
        None
      }
      "sslkey" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslkey needs a path"));
        }
        client_key = Some(PathBuf::from(value));
        None
      }
      _ => return Err(format!("bad connection string `{entry}`: unknown query `{key}`")),
    };
    if let Some(root) = tls_material {
      root_cert = Some(root);
    }
  }
  if client_cert.is_some() != client_key.is_some() {
    return Err(format!("bad connection string `{entry}`: sslcert and sslkey come together"));
  }
  Ok(RedisTls {
    root_cert,
    client_cert,
    client_key,
  })
}

impl RedisScope {
  /// Both legs of a redis rule from its two connection strings: the fake
  /// the rule states, the real the secret source resolved.
  ///
  /// # Errors
  /// Either string is not a `redis://` or `rediss://` connection string,
  /// or its query breaks the redis law above.
  pub fn from_strings(fake: &str, real: &str) -> Result<Self, String> {
    let downstream = RedisUri::parse(fake)?;
    let upstream = RedisUri::parse(real)?;
    let RedisTls {
      root_cert,
      client_cert,
      client_key,
    } = redis_tls(real, &upstream)?;
    Ok(Self {
      is_downstream_tls: downstream.scheme == Scheme::Rediss,
      downstream: downstream.leg(),
      is_upstream_tls: upstream.scheme == Scheme::Rediss,
      upstream: upstream.leg(),
      root_cert,
      client_cert,
      client_key,
      guest_tls: GuestTlsMode::default(),
    })
  }

  /// Grant-level match for a concrete request: scheme + port + host.
  pub(super) fn matches(scope: &Self, scheme: Scheme, host: &str, port: u16) -> bool {
    matches!(scheme, Scheme::Redis | Scheme::Rediss) && port == scope.downstream.port && scope.downstream.host.eq_ignore_ascii_case(host)
  }
}

/// Assemble one redis grant from its rule. The guest-leg mode comes from
/// the `tls` table keyed by the env name. Cleartext and TLS both swap.
///
/// # Errors
///
/// Returns an error when either string fails the redis law above, or when a
/// `tls` row tries to state what only the real string may state.
pub(super) fn grant(label: &str, rule: &RuleCfg, real: &str) -> Result<Grant, Error> {
  let fake = rule
    .value
    .as_ref()
    .map(|value| value.expose_secret().to_string())
    .unwrap_or_default();
  let mut scope = RedisScope::from_strings(&fake, real).map_err(|err| Error::RedisScope {
    label: label.to_string(),
    detail: err,
  })?;
  // The rule table states the guest leg only; the upstream identity and
  // trust live in the real string's query.
  for (key, tls) in &rule.tls {
    if key != &rule.env {
      return Err(Error::TlsEnvMismatch {
        label: label.to_string(),
        key: key.clone(),
        env: rule.env.clone(),
      });
    }
    if tls.client_cert.is_some() || tls.client_key.is_some() {
      return Err(Error::RedisIdentity { label: label.to_string() });
    }
    if tls.root_cert.is_some() {
      return Err(Error::RedisTrust { label: label.to_string() });
    }
    scope.guest_tls = tls.guest_tls_mode;
  }
  // The wire needles are the credentials: fake password in, real
  // password out; the legs' users swap when they differ.
  let credential = Credential {
    label: label.to_string(),
    fake: scope.downstream.password.expose_secret().to_string(),
    value: scope.upstream.password.clone(),
  };
  Ok(Grant::Redis {
    credential,
    scope: Box::new(scope),
  })
}
