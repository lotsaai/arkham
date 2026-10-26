use std::path::PathBuf;
use std::str::FromStr;

use secrecy::SecretString;
use strum::EnumIter;
use url::{Host, Url};

use super::nats::NATS_DEFAULT_PORT;
use super::postgres::SslNegotiation;

/// Host pattern: exact, `*.`-wildcard (subdomains only), or any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPat {
  /// Exact hostname, ASCII case-insensitive.
  Exact(String),
  /// `*.`-prefixed suffix; matches subdomains only, never the apex.
  Wildcard(String),
  /// Any host (`*`).
  Any,
}

impl HostPat {
  /// Check if a hostname matches this pattern.
  ///
  /// Uses ASCII case-insensitive comparison to avoid `to_lowercase()`
  /// allocations (DNS hostnames are ASCII per RFC 4343). Wildcards match
  /// subdomains only: `*.example.com` matches `a.example.com` but never
  /// the apex `example.com`.
  #[must_use]
  pub fn matches(&self, hostname: &str) -> bool {
    match self {
      HostPat::Exact(h) => hostname.eq_ignore_ascii_case(h),
      HostPat::Wildcard(pattern) => {
        if let Some(suffix) = pattern.strip_prefix("*.") {
          hostname.len() > suffix.len() + 1
            && hostname.as_bytes()[hostname.len() - suffix.len() - 1] == b'.'
            && hostname[hostname.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        } else {
          hostname.eq_ignore_ascii_case(pattern)
        }
      }
      HostPat::Any => true,
    }
  }
}

/// Parse a user-facing host string: `*` is any host, `*.`-prefixed
/// strings are wildcards, everything else matches exactly. Infallible.
impl FromStr for HostPat {
  type Err = std::convert::Infallible;

  fn from_str(host: &str) -> Result<Self, Self::Err> {
    Ok(if host == "*" {
      HostPat::Any
    } else if host.starts_with("*.") {
      HostPat::Wildcard(host.to_string())
    } else {
      HostPat::Exact(host.to_string())
    })
  }
}

/// Grant scheme: the URL scheme names the protocol. No inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
pub enum Scheme {
  /// Plain HTTP.
  Http,
  /// TLS HTTP.
  Https,
  /// Raw TCP.
  Tcp,
  /// Postgres wire protocol. TLS comes from the `sslmode` query.
  Postgres,
  /// Cleartext Redis. Each connection string states its own leg's transport.
  Redis,
  /// TLS Redis. Each connection string states its own leg's transport.
  Rediss,
  /// Cleartext LDAP. Each connection string states how its leg opens.
  /// A cleartext leg may upgrade with `StartTLS`.
  Ldap,
  /// TLS LDAP (LDAPS). Each connection string states how its leg opens.
  Ldaps,
  /// SSH. The proxy terminates the protocol on both legs; port defaults
  /// to 22 the way ssh itself defaults it.
  Ssh,
  /// Cleartext SMTP. `STARTTLS` upgrades the session when the peer asks,
  /// or when the real string says `starttls=required`. Port defaults to 587,
  /// the submission port.
  Smtp,
  /// Implicit TLS SMTP from the first byte. Port defaults to 465.
  Smtps,
  /// NATS, spelled `nats://` or `tls://` in a connection string. The real
  /// string's spelling states the upstream TLS. Port defaults to 4222.
  Nats,
  /// Cleartext AMQP (0-9-1 or 1.0). Each connection string states its own
  /// leg's transport. Port defaults to 5672.
  Amqp,
  /// TLS AMQP from the first byte. Port defaults to 5671.
  Amqps,
}

impl Scheme {
  /// Lowercase URL scheme for this variant.
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Http => "http",
      Self::Https => "https",
      Self::Tcp => "tcp",
      Self::Postgres => "postgres",
      Self::Redis => "redis",
      Self::Rediss => "rediss",
      Self::Ldap => "ldap",
      Self::Ldaps => "ldaps",
      Self::Ssh => "ssh",
      Self::Smtp => "smtp",
      Self::Smtps => "smtps",
      Self::Nats => "nats",
      Self::Amqp => "amqp",
      Self::Amqps => "amqps",
    }
  }

  /// Every scheme the proxy serves, in enum order.
  pub fn all() -> impl Iterator<Item = Self> {
    <Self as strum::IntoEnumIterator>::iter()
  }
}

/// One real secret and the decoy that stands in for it. Shared by every
/// grant kind, because substitution only ever needs these three.
#[derive(Debug, Clone)]
pub struct Credential {
  /// Secret label (log identifier, never the value).
  pub label: String,
  /// Deterministic format-valid decoy presented to clients.
  pub fake: String,
  /// Real secret value swapped upstream.
  pub value: SecretString,
}

/// How the guest leg treats client certificates. The mode is arkham's own
/// configuration, carried by the rule's `tls` table, never by an entry URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestTlsMode {
  /// Terminate TLS and never ask the guest for a client certificate.
  #[default]
  Tls,
  /// Request a client certificate and admit only ones arkham's own CA signs.
  Mtls,
}

/// Allow entry for a bearer-style credential: an endpoint, plus the upstream
/// client identity an https entry names for mTLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointScope {
  /// Entry scheme.
  pub scheme: Scheme,
  /// Entry host pattern.
  pub host: HostPat,
  /// Entry port.
  pub port: u16,
  /// PEM client certificate for upstream mTLS, when the entry names one.
  pub client_cert: Option<PathBuf>,
  /// PEM client key for upstream mTLS, when the entry names one.
  pub client_key: Option<PathBuf>,
  /// Upstream CA bundle trusting this entry's host, additive to the global
  /// egress trust (rule table, not the URL).
  pub root_cert: Option<PathBuf>,
  /// How the guest leg treats client certificates (rule table, not the URL).
  pub guest_tls: GuestTlsMode,
}

/// Allow entry for an SSH identity mapping: the guest leg admits only the
/// decoy public key, the upstream leg presents the real private key, and
/// upstream host keys follow OpenSSH `accept-new` into arkham's own
/// `known_hosts` — never a per-host pin here. The rule's `ssh` table names
/// the two key blobs; both are required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshScope {
  /// Entry host pattern.
  pub host: HostPat,
  /// Entry port.
  pub port: u16,
  /// Real private key (openssh format) the upstream leg presents.
  pub identity: PathBuf,
  /// Decoy public key (`authorized_keys` format) the guest leg admits.
  pub guest_key: PathBuf,
}

/// Upstream trust anchor an entry names with `sslrootcert`: a PEM path, or
/// libpq's `system` spelling for the platform trust store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RootCert {
  /// PEM trust anchors read from this path.
  Path(PathBuf),
  /// The platform trust store.
  System,
}

/// Parse one `allow` entry into typed parts. The `url` crate does the
/// work: every field is read off the parsed [`url::Url`]. The only special
/// case is the `*` host marker, which cannot survive URL parsing, so a
/// `w` placeholder stands in for one parse and the marker is restored from
/// the parsed host.
///
/// http/https/tcp stay authority-only (default ports 80/443; tcp needs an
/// explicit port). postgres is not an entry scheme: a database rule states
/// no allow entries — its connection string is the grant. Entries match,
/// secrets live in values.
impl FromStr for EndpointScope {
  type Err = String;

  fn from_str(entry: &str) -> Result<Self, Self::Err> {
    let Some((scheme_raw, rest)) = entry.split_once("://") else {
      return Err("missing `://`".to_string());
    };
    let wildcard = rest.starts_with('*');
    let probe = if wildcard {
      format!("{scheme_raw}://w{}", &rest[1..])
    } else {
      entry.to_string()
    };
    let url = Url::parse(&probe).map_err(|err| format!("bad allow entry `{entry}`: {err}"))?;
    let scheme = match url.scheme() {
      "http" => Scheme::Http,
      "https" => Scheme::Https,
      "tcp" => Scheme::Tcp,
      "ssh" => Scheme::Ssh,
      "postgres" | "redis" | "rediss" | "smtp" | "smtps" | "ldap" | "ldaps" | "nats" | "tls" | "amqp" | "amqps" => {
        return Err(format!(
          "bad allow entry `{entry}`: database rules state no allow entries — the connection string is the grant"
        ));
      }
      other => return Err(format!("unknown scheme `{other}`")),
    };
    if url.password().is_some() {
      return Err(format!(
        "bad allow entry `{entry}`: passwords live in values, never in match entries"
      ));
    }
    let parsed_host = match url.host() {
      Some(Host::Domain(domain)) => domain.to_string(),
      Some(Host::Ipv4(addr)) => addr.to_string(),
      Some(Host::Ipv6(addr)) => addr.to_string(),
      None => return Err(format!("bad allow entry `{entry}`: empty host")),
    };
    let host = if wildcard {
      let tail = parsed_host.strip_prefix('w').unwrap_or(&parsed_host);
      if tail.is_empty() {
        HostPat::Any
      } else if tail.starts_with('.') && tail.len() > 1 {
        HostPat::Wildcard(format!("*{tail}"))
      } else {
        return Err(format!("bad allow entry `{entry}`: `*` only leads `*` or `*.suffix`"));
      }
    } else {
      HostPat::Exact(parsed_host)
    };
    let port = match (url.port(), scheme) {
      (Some(port), _) => port,
      (None, Scheme::Http) => 80,
      (None, Scheme::Https) => 443,
      (None, Scheme::Tcp) => return Err("tcp grant requires an explicit port".to_string()),
      (None, Scheme::Postgres) => 5432,
      (None, Scheme::Redis | Scheme::Rediss) => 6379,
      (None, Scheme::Ldap) => 389,
      (None, Scheme::Ldaps) => 636,
      (None, Scheme::Ssh) => 22,
      (None, Scheme::Smtp) => 587,
      (None, Scheme::Smtps) => 465,
      (None, Scheme::Nats) => NATS_DEFAULT_PORT,
      (None, Scheme::Amqp) => 5672,
      (None, Scheme::Amqps) => 5671,
    };
    reject_endpoint_query(entry, &url)?;
    Ok(EndpointScope {
      scheme,
      host,
      port,
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls: GuestTlsMode::default(),
    })
  }
}

/// Endpoint entries are identity only. Every libpq query parameter is
/// rejected, and the rejection names the parameter exactly.
fn reject_endpoint_query(entry: &str, url: &url::Url) -> Result<(), String> {
  let mut negotiation = SslNegotiation::Postgres;
  let mut root_cert = None;
  let mut client_cert = None;
  let mut client_key = None;
  let mut ssl_seen = false;
  for (key, value) in url.query_pairs() {
    match key.as_ref() {
      "sslmode" | "ssl" => {
        match value.as_ref() {
          "disable" | "allow" | "prefer" | "require" | "verify-ca" | "verify-full" => {}
          _ => {
            return Err(format!(
              "bad allow entry `{entry}`: sslmode is disable, allow, prefer, require, verify-ca or verify-full"
            ));
          }
        }
        ssl_seen = true;
      }
      "sslnegotiation" => {
        negotiation = match value.as_ref() {
          "postgres" => SslNegotiation::Postgres,
          "direct" => SslNegotiation::Direct,
          _ => return Err(format!("bad allow entry `{entry}`: sslnegotiation is postgres or direct")),
        };
      }
      "sslrootcert" => {
        if value.is_empty() {
          return Err(format!("bad allow entry `{entry}`: sslrootcert needs a path"));
        }
        root_cert = Some(if value == "system" {
          RootCert::System
        } else {
          RootCert::Path(PathBuf::from(value.as_ref()))
        });
      }
      "sslcert" => {
        if value.is_empty() {
          return Err(format!("bad allow entry `{entry}`: sslcert needs a path"));
        }
        client_cert = Some(PathBuf::from(value.as_ref()));
      }
      "sslkey" => {
        if value.is_empty() {
          return Err(format!("bad allow entry `{entry}`: sslkey needs a path"));
        }
        client_key = Some(PathBuf::from(value.as_ref()));
      }
      _ => return Err(format!("bad allow entry `{entry}`: unknown query `{key}`")),
    }
  }
  if client_cert.is_some() != client_key.is_some() {
    return Err(format!("bad allow entry `{entry}`: sslcert and sslkey come together"));
  }
  if !url.username().is_empty() {
    return Err(format!("bad allow entry `{entry}`: userinfo is postgres-only"));
  }
  if let Some(path) = url.path().strip_prefix('/').filter(|path| !path.is_empty()) {
    return Err(format!("bad allow entry `{entry}`: paths are postgres-only, found `/{path}`"));
  }
  if ssl_seen {
    return Err(format!("bad allow entry `{entry}`: sslmode is postgres-only"));
  }
  if negotiation != SslNegotiation::Postgres {
    return Err(format!("bad allow entry `{entry}`: sslnegotiation is postgres-only"));
  }
  if root_cert.is_some() {
    return Err(format!("bad allow entry `{entry}`: sslrootcert is postgres-only"));
  }
  if client_cert.is_some() || client_key.is_some() {
    return Err(format!("bad allow entry `{entry}`: sslcert and sslkey are postgres-only"));
  }
  Ok(())
}
