//! Grant model: a credential is one real secret, and a grant says what kind
//! of endpoints that secret may be presented at. A rule is one kind, inferred
//! from the URL schemes of its `allow` entries. The protocol verticals
//! (`postgres`, `redis`, `smtp`, `ldap`, `nats`) own their scope types and their connection-string
//! laws; this module owns the enum, the matching dispatch, and the
//! collection of rules into grants.

mod ldap;
mod nats;
mod postgres;
mod redis;
mod smtp;

pub use ldap::{LdapLeg, LdapScope, LdapUriError};
pub(crate) use nats::NatsUriScheme;
pub use nats::{
  AuthField, AuthSign, FieldPresence, NATS_DEFAULT_PORT, NatsAuth, NatsClientIdentity, NatsEndpoint, NatsField, NatsPair, NatsScope,
  NatsSeed, NatsTlsOrder, NatsTrust, NatsUpstream, NatsUriError,
};
pub use postgres::{PostgresLeg, PostgresScope, SslMode, SslNegotiation};
pub use redis::{RedisLeg, RedisScope};
pub use smtp::{SmtpLeg, SmtpScope, SmtpUriError};

use std::path::PathBuf;
use std::str::FromStr;

use secrecy::{ExposeSecret as _, SecretString};
use strum::EnumIter;
use url::{Host, Url};

use crate::config::{AppConfig, RuleCfg, fake_for};
use crate::error::Error;
use crate::plugins::resolve_plugins;

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
      "postgres" | "redis" | "rediss" | "smtp" | "smtps" | "ldap" | "ldaps" | "nats" | "tls" => {
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

/// One secret and the endpoints it may be presented at. A rule is one kind,
/// so the variants carry only the fields their kind can use.
#[derive(Debug, Clone)]
pub enum Grant {
  /// Bearer-style secret for HTTP or raw TCP endpoints.
  Token {
    /// The real secret and its decoy.
    credential: Credential,
    /// Parsed endpoint entries.
    allow: Vec<EndpointScope>,
    /// Decoy template this grant's decoys render from.
    pattern: Option<String>,
    /// `OAuth2` token-issuer flow, when this grant's rule declares one.
    oauth2: Option<crate::registry::OAuthFlow>,
  },
  /// One postgres connection-string mapping: fake connection string to
  /// real, 1:1. The real string's query states the upstream TLS policy.
  Postgres {
    /// The wire needles: the fake password and the real password.
    credential: Credential,
    /// The one scope this rule maps, carrying both legs' facts.
    scope: Box<PostgresScope>,
  },
  /// One redis connection-string mapping: fake string to real, 1:1. Each
  /// string states its own leg's transport in its scheme.
  Redis {
    /// The wire needles: the fake password and the real password.
    credential: Credential,
    /// The one scope this rule maps, carrying both legs' facts.
    scope: Box<RedisScope>,
  },
  /// One SMTP connection-string mapping: fake string to real, 1:1. Each
  /// string states its own leg's transport in its scheme. `starttls=required`
  /// on the real `smtp://` string withholds the password until the upgrade.
  Smtp {
    /// The wire needles: the fake password and the real password.
    credential: Credential,
    /// The one scope this rule maps, carrying both legs' facts.
    scope: Box<SmtpScope>,
  },
  /// One LDAP connection-string mapping: fake string to real, 1:1. Each
  /// string states how its leg opens. A cleartext leg may `StartTLS`.
  Ldap {
    /// The wire needles: the fake password and the real password.
    credential: Credential,
    /// The one scope this rule maps, carrying both legs' facts.
    scope: Box<LdapScope>,
  },
  /// One NATS connection-string mapping: fake string to real, 1:1. The real
  /// string's spelling states whether the upstream leg is TLS.
  Nats {
    /// The wire value this grant swaps: password, token, public key, or user JWT.
    credential: Credential,
    /// The one scope this rule maps, carrying both legs' facts.
    scope: Box<NatsScope>,
  },
  /// One SSH identity mapping: the guest presents the decoy key, arkham
  /// presents the real key upstream. No wire substitution, so no credential.
  Ssh {
    /// Parsed ssh entries, each carrying its key material paths.
    allow: Vec<SshScope>,
  },
}

impl Grant {
  /// The secret this grant swaps, when the kind swaps one on the wire. SSH
  /// grants swap keys at the protocol layer instead, so they carry none.
  #[must_use]
  pub fn credential(&self) -> Option<&Credential> {
    match self {
      Grant::Token { credential, .. }
      | Grant::Postgres { credential, .. }
      | Grant::Redis { credential, .. }
      | Grant::Smtp { credential, .. }
      | Grant::Ldap { credential, .. }
      | Grant::Nats { credential, .. } => Some(credential),
      Grant::Ssh { .. } => None,
    }
  }

  /// Grant-level match for a concrete request: scheme + port + host.
  #[must_use]
  pub fn matches(&self, scheme: Scheme, host: &str, port: u16) -> bool {
    match self {
      Grant::Token { allow, .. } => allow.iter().any(|entry| endpoint_match(entry, scheme, host, port)),
      Grant::Postgres { scope, .. } => PostgresScope::matches(scope, scheme, host, port),
      Grant::Redis { scope, .. } => RedisScope::matches(scope, scheme, host, port),
      Grant::Smtp { scope, .. } => SmtpScope::matches(scope, scheme, host, port),
      Grant::Ldap { scope, .. } => LdapScope::matches(scope, scheme, host, port),
      Grant::Nats { scope, .. } => NatsScope::matches(scope, scheme, host, port),
      Grant::Ssh { allow } => allow.iter().any(|entry| ssh_match(entry, scheme, host, port)),
    }
  }

  /// Endpoint entry of `scheme` covering a destination. `host` None matches
  /// any host on the port, which is all a transparent capture knows before
  /// the identity is read.
  #[must_use]
  pub fn endpoint(&self, scheme: Scheme, host: Option<&str>, port: u16) -> Option<&EndpointScope> {
    let Grant::Token { allow, .. } = self else {
      return None;
    };
    allow
      .iter()
      .find(|entry| entry.scheme == scheme && entry.port == port && host.is_none_or(|host| entry.host.matches(host)))
  }

  /// The postgres scope whose downstream (guest-side) port and host cover
  /// a destination, `host` optional as above: transparent capture knows the
  /// port before it knows the host.
  #[must_use]
  pub fn postgres(&self, host: Option<&str>, port: u16) -> Option<&PostgresScope> {
    let Grant::Postgres { scope, .. } = self else {
      return None;
    };
    (scope.downstream.port == port && host.is_none_or(|host| scope.downstream.host.eq_ignore_ascii_case(host))).then(|| scope.as_ref())
  }

  /// The redis scope whose downstream (guest-side) port and host cover a
  /// destination, `host` optional as above: transparent capture knows the
  /// port before it knows the host.
  #[must_use]
  pub fn redis(&self, host: Option<&str>, port: u16) -> Option<&RedisScope> {
    let Grant::Redis { scope, .. } = self else {
      return None;
    };
    (scope.downstream.port == port && host.is_none_or(|host| scope.downstream.host.eq_ignore_ascii_case(host))).then(|| scope.as_ref())
  }

  /// The SMTP scope whose downstream (guest-side) port and host cover a
  /// destination, `host` optional as above: transparent capture knows the
  /// port before it knows the host.
  #[must_use]
  pub fn smtp(&self, host: Option<&str>, port: u16) -> Option<&SmtpScope> {
    let Grant::Smtp { scope, .. } = self else {
      return None;
    };
    (scope.downstream.port == port && host.is_none_or(|host| scope.downstream.host.eq_ignore_ascii_case(host))).then(|| scope.as_ref())
  }

  /// The LDAP scope whose downstream (guest-side) port and host cover a
  /// destination, `host` optional as above: transparent capture knows the
  /// port before it knows the host.
  #[must_use]
  pub fn ldap(&self, host: Option<&str>, port: u16) -> Option<&LdapScope> {
    let Grant::Ldap { scope, .. } = self else {
      return None;
    };
    (scope.downstream.port == port && host.is_none_or(|host| scope.downstream.host.eq_ignore_ascii_case(host))).then(|| scope.as_ref())
  }

  /// The NATS scope whose downstream (guest-side) port and host cover a
  /// destination, `host` optional as above: transparent capture knows the
  /// port before it knows the host.
  #[must_use]
  pub fn nats(&self, host: Option<&str>, port: u16) -> Option<&NatsScope> {
    let Grant::Nats { scope, .. } = self else {
      return None;
    };
    (scope.downstream.port == port && host.is_none_or(|host| scope.downstream.host.eq_ignore_ascii_case(host))).then(|| scope.as_ref())
  }

  /// The ssh scope whose port and host cover a destination, `host` optional
  /// as above: transparent capture knows the port before it knows the host.
  #[must_use]
  pub fn ssh(&self, host: Option<&str>, port: u16) -> Option<&SshScope> {
    let Grant::Ssh { allow } = self else {
      return None;
    };
    allow
      .iter()
      .find(|entry| entry.port == port && host.is_none_or(|host| entry.host.matches(host)))
  }
}

fn endpoint_match(entry: &EndpointScope, scheme: Scheme, host: &str, port: u16) -> bool {
  entry.scheme == scheme && host_port_match(&entry.host, entry.port, host, port)
}

fn ssh_match(entry: &SshScope, scheme: Scheme, host: &str, port: u16) -> bool {
  scheme == Scheme::Ssh && entry.port == port && entry.host.matches(host)
}

fn host_port_match(pat: &HostPat, entry_port: u16, host: &str, port: u16) -> bool {
  entry_port == port && pat.matches(host)
}

/// Resolved proxy config: listener settings plus parsed grants.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
  /// Proxy listener settings.
  pub proxy: crate::config::ProxyCfg,
  /// Parsed per-secret grants.
  pub grants: Vec<Grant>,
  /// Parsed plugin grants.
  pub plugins: Vec<crate::plugins::ResolvedPlugin>,
}

/// Parse every rule's `allow` entries into grants. A rule's entries must all
/// be one kind; the kind comes from their schemes, and the grant carries only
/// that kind's fields.
///
/// # Errors
///
/// Returns an error when an `allow` entry is not a valid URI grant, or when
/// one rule mixes endpoint and database entries.
pub fn resolve(cfg: &AppConfig) -> Result<ResolvedConfig, Error> {
  let mut collector = GrantCollector::default();
  for (label, rule) in &cfg.rules {
    collector.collect(label, rule)?;
  }
  Ok(ResolvedConfig {
    proxy: cfg.proxy.clone(),
    grants: collector.grants,
    plugins: resolve_plugins(cfg)?,
  })
}

/// One rule table's grants, collected kind by kind. Each method owns one
/// rule kind's validation and grant shape; a warn-and-skip outcome stays a
/// plain `Ok(())` so the entrypoint remains a fold over the rule table.
#[derive(Debug, Default)]
struct GrantCollector {
  grants: Vec<Grant>,
}

impl GrantCollector {
  /// Fold one rule into the set, dispatching on the rule's kind.
  fn collect(&mut self, label: &str, rule: &RuleCfg) -> Result<(), Error> {
    // A rule whose stated value is a connection string names its protocol;
    // the vertical owns the rest of that rule's law.
    if let Some(scheme) = rule.value_scheme() {
      return self.connection_string(label, rule, scheme);
    }
    let parsed = Self::parse_entries(label, rule)?;
    if parsed.is_empty() {
      tracing::warn!(label, env = %rule.env, "rule has no allow entries; no grant");
      return Ok(());
    }
    // An ssh table that cannot apply — the rule's entries are not ssh —
    // would vanish silently; that is a misspecified rule, fail closed.
    if !rule.ssh.is_empty() && parsed.first().is_none_or(|(_, scope)| scope.scheme != Scheme::Ssh) {
      return Err(Error::SshMisplaced { label: label.to_string() });
    }
    if parsed.first().is_some_and(|(_, scope)| scope.scheme == Scheme::Ssh) {
      return self.ssh(label, rule, parsed);
    }
    self.token(label, rule, parsed);
    Ok(())
  }

  /// Connection-string rule: the rule states the fake string in `value`;
  /// the real one resolved from the secret source into `real`. No allow
  /// entries — the connection string is the grant. The protocol vertical
  /// assembles the grant.
  fn connection_string(&mut self, label: &str, rule: &RuleCfg, scheme: Scheme) -> Result<(), Error> {
    if !rule.allow.is_empty() {
      return Err(Error::ConnectionStringAllow { label: label.to_string() });
    }
    let Some(real) = rule.real.clone() else {
      // The secret source did not resolve this name; no grant rather than
      // a rule that swaps in nothing.
      tracing::warn!(label, env = %rule.env, "rule has no resolved real connection string; no grant");
      return Ok(());
    };
    if rule.value.is_none() {
      return Err(Error::ConnectionStringValueMissing { label: label.to_string() });
    }
    let grant = match scheme {
      Scheme::Postgres => postgres::grant(label, rule, real.expose_secret()),
      Scheme::Redis | Scheme::Rediss => redis::grant(label, rule, real.expose_secret()),
      Scheme::Smtp | Scheme::Smtps => smtp::grant(label, rule, real.expose_secret()),
      Scheme::Ldap | Scheme::Ldaps => ldap::grant(label, rule, real.expose_secret()),
      Scheme::Nats => nats::grant(label, rule, real.expose_secret()),
      _ => {
        return Err(Error::ConnectionStringScheme {
          label: label.to_string(),
          scheme,
        });
      }
    }?;
    self.grants.push(grant);
    Ok(())
  }

  /// Parse a rule's `allow` entries with their `tls` overlay applied, and
  /// reject `tls` rows no entry claims.
  fn parse_entries(label: &str, rule: &RuleCfg) -> Result<Vec<(String, EndpointScope)>, Error> {
    let mut parsed = Vec::with_capacity(rule.allow.len());
    for entry in &rule.allow {
      let mut scope: EndpointScope = entry.parse().map_err(|err| Error::BadAllow {
        label: label.to_string(),
        entry: entry.clone(),
        detail: err,
      })?;
      // Identity comes from the entry; arkham's own TLS configuration comes
      // from the rule's `tls` table, keyed by the entry itself. SSH entries
      // pin their trust instead, so a `tls` row on one is a config error.
      if let Some(tls) = rule.tls.get(entry) {
        if scope.scheme == Scheme::Ssh {
          return Err(Error::SshTls {
            label: label.to_string(),
            entry: entry.clone(),
          });
        }
        if tls.client_cert.is_some() != tls.client_key.is_some() {
          return Err(Error::CertKeyPair {
            label: label.to_string(),
            entry: entry.clone(),
          });
        }
        scope.client_cert.clone_from(&tls.client_cert);
        scope.client_key.clone_from(&tls.client_key);
        scope.root_cert.clone_from(&tls.root_cert);
        scope.guest_tls = tls.guest_tls_mode;
      }
      parsed.push((entry.clone(), scope));
    }
    for key in rule.tls.keys() {
      if !rule.allow.iter().any(|entry| entry == key) {
        return Err(Error::TlsUnknownEntry {
          label: label.to_string(),
          key: key.clone(),
        });
      }
    }
    Ok(parsed)
  }

  /// SSH rule: every entry ssh, key material from the `ssh` table, and no
  /// credential to resolve — the swap happens at the protocol layer.
  fn ssh(&mut self, label: &str, rule: &RuleCfg, parsed: Vec<(String, EndpointScope)>) -> Result<(), Error> {
    if parsed.iter().any(|(_, scope)| scope.scheme != Scheme::Ssh) {
      return Err(Error::SshMixedSchemes { label: label.to_string() });
    }
    if rule.value.is_some() {
      return Err(Error::SshValue { label: label.to_string() });
    }
    for key in rule.ssh.keys() {
      if !rule.allow.iter().any(|entry| entry == key) {
        return Err(Error::SshUnknownEntry {
          label: label.to_string(),
          key: key.clone(),
        });
      }
    }
    let mut allow = Vec::with_capacity(parsed.len());
    for (entry, scope) in parsed {
      let Some(ssh) = rule.ssh.get(&entry) else {
        return Err(Error::SshIdentity {
          label: label.to_string(),
          entry,
          detail: "no ssh config for this entry".to_string(),
        });
      };
      let identity = ssh.identity.clone().ok_or_else(|| Error::SshIdentity {
        label: label.to_string(),
        entry: entry.clone(),
        detail: "identity is required".to_string(),
      })?;
      let guest_key = ssh.guest_key.clone().ok_or_else(|| Error::SshIdentity {
        label: label.to_string(),
        entry: entry.clone(),
        detail: "guest_key is required".to_string(),
      })?;
      allow.push(SshScope {
        host: scope.host,
        port: scope.port,
        identity,
        guest_key,
      });
    }
    self.grants.push(Grant::Ssh { allow });
    Ok(())
  }

  /// Token rule: `allow` names the hosts and `value` is the real secret.
  fn token(&mut self, label: &str, rule: &RuleCfg, parsed: Vec<(String, EndpointScope)>) {
    let Some(value) = rule.value.clone() else {
      // `secrets::resolve` fills this before `serve`; a caller that skips
      // resolution gets no grant rather than a rule that swaps in nothing.
      tracing::warn!(label, env = %rule.env, "rule has no resolved value; no grant");
      return;
    };
    let allow: Vec<EndpointScope> = parsed.into_iter().map(|(_, scope)| scope).collect();
    // A decoy is a key the proxy maps back to the real value; its shape is
    // a prop for the observer. Raw TCP grants need the decoy at the real
    // value's length (the raw swap is equal-length only), so the decoy
    // falls back to a length-matched render there.
    let (fake, _) = decoy_for_rule(&rule.env, rule.pattern.as_deref(), &allow, value.expose_secret().len());
    self.grants.push(Grant::Token {
      credential: Credential {
        label: label.to_string(),
        fake,
        value,
      },
      allow,
      pattern: rule.pattern.clone(),
      oauth2: rule.oauth2.clone(),
    });
  }
}

/// The decoy a rule's grant will use: the shaped decoy, falling back to a
/// length-matched render when the rule has a `tcp://` allow entry and the
/// shape renders another length than the real value. Returns the decoy and
/// whether the length-matched fallback fired.
#[must_use]
pub fn decoy_for_rule(env: &str, pattern: Option<&str>, allow: &[EndpointScope], value_len: usize) -> (String, bool) {
  let shaped = fake_for(env, pattern);
  if allow.iter().any(|scope| scope.scheme == Scheme::Tcp) && shaped.len() != value_len {
    let length_pattern = format!("{{hex:{value_len}}}");
    (crate::config::fake_for(env, Some(&length_pattern)), true)
  } else {
    (shaped, false)
  }
}

/// Scheme + port + host all match, over raw parsed endpoint entries.
/// Plugins match this way.
#[must_use]
pub fn uri_match(allow: &[EndpointScope], scheme: Scheme, host: &str, port: u16) -> bool {
  allow.iter().any(|entry| endpoint_match(entry, scheme, host, port))
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeMap;

  use super::*;
  use crate::config::{HostSshCfg, HostTlsCfg, IfMissing, ProxyCfg, WorkspaceCfg};

  fn endpoint_grant(entries: &[&str]) -> Grant {
    Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: "fake".into(),
        value: SecretString::from("value"),
      },
      allow: entries.iter().map(|entry| endpoint_scope(entry)).collect(),
      pattern: None,
      oauth2: None,
    }
  }

  fn endpoint_scope(entry: &str) -> EndpointScope {
    entry.parse().unwrap()
  }

  /// One database rule: the stated fake string plus the secret-source real
  /// string, exactly as serve loads it.
  fn cfg_with_db(fake: &str, real: &str) -> AppConfig {
    let mut rules = BTreeMap::new();
    rules.insert(
      "t".to_string(),
      RuleCfg {
        env: "DATABASE_URL".into(),
        value: Some(SecretString::from(fake)),
        real: Some(SecretString::from(real)),
        fnox_key: None,
        allow: vec![],
        pattern: None,
        registry: None,
        oauth2: None,
        tls: BTreeMap::new(),
        ssh: BTreeMap::new(),
        if_missing: crate::config::IfMissing::default(),
      },
    );
    AppConfig {
      proxy: ProxyCfg {
        listen: "127.0.0.1:8080".parse().unwrap(),
        ca_file: None,
        root_certs: Vec::new(),
        handshake_timeout_secs: 10,
        ssh_host_key: None,
        ssh_known_hosts: None,
      },
      workspace: WorkspaceCfg::default(),
      rules,
      plugins: BTreeMap::new(),
      tools: BTreeMap::new(),
    }
  }

  fn mtls_on(cfg: &mut AppConfig) {
    let mut tls = BTreeMap::new();
    tls.insert(
      "DATABASE_URL".to_string(),
      HostTlsCfg {
        client_cert: None,
        client_key: None,
        root_cert: None,
        guest_tls_mode: GuestTlsMode::Mtls,
        guest_cert: None,
        guest_key: None,
      },
    );
    cfg.rules.get_mut("t").unwrap().tls = tls;
  }

  fn assert_mtls_rejected(fake: &str, real: &str, secrets: &[&str], pred: impl Fn(&crate::Error) -> bool) {
    let mut cfg = cfg_with_db(fake, real);
    mtls_on(&mut cfg);
    let Err(err) = resolve(&cfg) else {
      panic!("mtls on a cleartext fake must be rejected");
    };
    assert!(pred(&err), "{err}");
    let text = err.to_string();
    for secret in secrets {
      assert!(!text.contains(secret), "mtls rejection included a credential");
    }
  }

  /// A resolved postgres scope, through [`resolve`] exactly as serve does.
  fn postgres_scope(fake: &str, real: &str) -> PostgresScope {
    let resolved = resolve(&cfg_with_db(fake, real)).unwrap();
    let Some(Grant::Postgres { scope, .. }) = resolved.grants.first() else {
      panic!("a postgres rule resolves to a postgres grant");
    };
    (**scope).clone()
  }

  /// A resolved postgres grant.
  fn postgres_grant(fake: &str, real: &str) -> Grant {
    let resolved = resolve(&cfg_with_db(fake, real)).unwrap();
    resolved.grants.into_iter().next().unwrap()
  }

  /// A resolved redis scope, through [`resolve`] exactly as serve does.
  fn redis_scope(fake: &str, real: &str) -> RedisScope {
    let resolved = resolve(&cfg_with_db(fake, real)).unwrap();
    let Some(Grant::Redis { scope, .. }) = resolved.grants.first() else {
      panic!("a redis rule resolves to a redis grant");
    };
    (**scope).clone()
  }

  /// A resolved redis grant.
  fn redis_grant(fake: &str, real: &str) -> Grant {
    let resolved = resolve(&cfg_with_db(fake, real)).unwrap();
    resolved.grants.into_iter().next().unwrap()
  }

  #[test]
  fn redis_grant_answers_for_redis_schemes() {
    let grant = redis_grant(
      "redis://app:fake@db.internal:6379/0", // betterleaks:allow
      "redis://app:real@db.internal:6379/0", // betterleaks:allow
    );
    assert!(grant.matches(Scheme::Redis, "db.internal", 6379));
    assert!(grant.matches(Scheme::Rediss, "db.internal", 6379));
    assert!(!grant.matches(Scheme::Tcp, "db.internal", 6379));
    assert!(!grant.matches(Scheme::Redis, "db.internal", 6380));
    assert!(!grant.matches(Scheme::Redis, "other.internal", 6379));
    assert!(grant.endpoint(Scheme::Redis, Some("db.internal"), 6379).is_none());
    assert!(grant.postgres(Some("db.internal"), 6379).is_none());
    let credential = grant.credential().expect("a redis grant swaps a credential");
    assert_eq!(credential.label, "t");
    assert_eq!(credential.fake, "fake");
  }

  #[test]
  fn redis_legs_come_from_their_own_strings() {
    let scope = redis_scope(
      "redis://guest:fake@fake.internal:6380/0", // betterleaks:allow
      "rediss://svc:real@db.internal:6381/1",    // betterleaks:allow
    );
    assert_eq!(scope.downstream.host, "fake.internal");
    assert_eq!(scope.downstream.port, 6380);
    assert_eq!(scope.downstream.user.as_deref(), Some("guest"));
    assert_eq!(scope.upstream.host, "db.internal");
    assert_eq!(scope.upstream.port, 6381);
    assert_eq!(scope.upstream.user.as_deref(), Some("svc"));
    assert_eq!(scope.upstream.database.as_deref(), Some("1"));
  }

  #[test]
  fn redis_default_port_is_6379() {
    let scope = redis_scope(
      "redis://app:fake@db.internal/0",  // betterleaks:allow
      "rediss://app:real@db.internal/0", // betterleaks:allow
    );
    assert_eq!(scope.downstream.port, 6379);
    assert_eq!(scope.upstream.port, 6379);
  }

  #[test]
  fn redis_strings_need_their_credentials() {
    let cfg = cfg_with_db("redis://app@db.internal:6379/0", "redis://app:real@db.internal:6379/0"); // betterleaks:allow
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("the password is required"), "{err}");
    let cfg = cfg_with_db("redis://app:fake@db.internal:6379/0", "redis://app@db.internal:6379/0"); // betterleaks:allow
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("the password is required"), "{err}");
  }

  #[test]
  fn redis_strings_reject_libpq_transport_queries() {
    let cfg = cfg_with_db(
      "redis://app:fake@db.internal:6379/0",                 // betterleaks:allow
      "redis://app:real@db.internal:6379/0?sslmode=require", // betterleaks:allow
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("sslmode"), "{err}");
  }

  #[test]
  fn redis_trust_and_identity_ride_the_real_string() {
    let scope = redis_scope(
      "redis://app:fake@db.internal:6379/0",                                        // betterleaks:allow
      "rediss://app:real@h:6380/0?sslrootcert=system&sslcert=/c.pem&sslkey=/c.key", // betterleaks:allow
    );
    assert_eq!(scope.root_cert, Some(RootCert::System));
    assert_eq!(scope.client_cert, Some(PathBuf::from("/c.pem")));
    assert_eq!(scope.client_key, Some(PathBuf::from("/c.key")));
    let cfg = cfg_with_db(
      "redis://app:fake@db.internal:6379/0",       // betterleaks:allow
      "rediss://app:real@h:6380/0?sslcert=/c.pem", // betterleaks:allow
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("come together"), "{err}");
  }

  #[test]
  fn redis_rules_state_no_allow_entries() {
    let mut cfg = cfg_with_db(
      "redis://app:fake@db.internal:6379/0", // betterleaks:allow
      "redis://app:real@db.internal:6379/0", // betterleaks:allow
    );
    cfg.rules.get_mut("t").unwrap().allow = vec!["https://api.github.com".to_string()];
    resolve(&cfg).unwrap_err();
  }

  #[test]
  fn redis_schemes_are_not_endpoint_grants() {
    "redis://db.internal:6379".parse::<EndpointScope>().unwrap_err();
    "rediss://db.internal:6380".parse::<EndpointScope>().unwrap_err();
  }

  #[test]
  fn redis_mtls_on_a_cleartext_fake_is_rejected() {
    assert_mtls_rejected(
      "redis://app:arkham_fake_redis_pass@db.internal:6379/0",         // betterleaks:allow
      "rediss://app:arkham_real_redis_pass_01@db.internal:6379/0",     // betterleaks:allow
      &["arkham_fake_redis_pass", "arkham_real_redis_pass_01", "app"], // betterleaks:allow
      |err| matches!(err, crate::Error::RedisCleartextMtls { .. }),
    );
  }

  #[test]
  fn redis_mtls_on_a_cleartext_upstream_is_rejected() {
    assert_mtls_rejected(
      "redis://app:arkham_fake_redis_pass@db.internal:6379/0",         // betterleaks:allow
      "redis://app:arkham_real_redis_pass_01@db.internal:6379/0",      // betterleaks:allow
      &["arkham_fake_redis_pass", "arkham_real_redis_pass_01", "app"], // betterleaks:allow
      |err| matches!(err, crate::Error::RedisCleartextMtls { .. }),
    );
  }

  #[test]
  fn redis_mtls_on_rediss_lands_on_the_scope() {
    let mut cfg = cfg_with_db(
      "rediss://app:arkham_fake_redis_pass@db.internal:6379/0",    // betterleaks:allow
      "rediss://app:arkham_real_redis_pass_01@db.internal:6379/0", // betterleaks:allow
    );
    mtls_on(&mut cfg);
    let resolved = resolve(&cfg).expect("rediss fake can demand a client certificate");
    let Some(Grant::Redis { scope, .. }) = resolved.grants.first() else {
      panic!("a redis rule");
    };
    assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
    assert!(scope.is_downstream_tls);
  }

  #[test]
  fn ldap_grant_answers_for_ldap_schemes() {
    let grant = redis_grant_like(
      "ldap://cn%3DDirectory%20Manager:fake@ldap.internal:389", // betterleaks:allow
      "ldap://cn%3DDirectory%20Manager:real@ldap.internal:389", // betterleaks:allow
    );
    assert!(grant.matches(Scheme::Ldap, "ldap.internal", 389));
    assert!(grant.matches(Scheme::Ldaps, "ldap.internal", 389));
    assert!(!grant.matches(Scheme::Ldap, "ldap.internal", 636));
    assert!(grant.ldap(None, 389).is_some());
    assert!(grant.ldap(Some("other.internal"), 389).is_none());
    assert!(grant.redis(Some("ldap.internal"), 389).is_none());
    let credential = grant.credential().expect("an ldap grant swaps a credential");
    assert_eq!(credential.fake, "fake");
    let scope = grant.ldap(Some("ldap.internal"), 389).expect("scope");
    assert_eq!(scope.downstream.dn, "cn=Directory Manager");
    assert!(!scope.is_downstream_tls);
  }

  /// Resolve through the same collector path as redis, for an ldap value.
  fn redis_grant_like(fake: &str, real: &str) -> Grant {
    let resolved = resolve(&cfg_with_db(fake, real)).unwrap();
    resolved.grants.into_iter().next().unwrap()
  }

  #[test]
  fn ldap_default_ports_follow_the_scheme() {
    let grant = redis_grant_like(
      "ldap://cn%3Ddir:fake@ldap.internal",  // betterleaks:allow
      "ldaps://cn%3Ddir:real@ldap.internal", // betterleaks:allow
    );
    let scope = grant.ldap(None, 389).expect("downstream port 389");
    assert_eq!(scope.downstream.port, 389);
    assert_eq!(scope.upstream.port, 636);
    assert!(scope.is_upstream_tls);
    assert!(!scope.is_downstream_tls);
  }

  #[test]
  fn ldap_strings_need_a_bind_dn_and_password() {
    let cfg = cfg_with_db("ldap://ldap.internal:389", "ldap://cn%3Ddir:real@ldap.internal:389"); // betterleaks:allow
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("bind dn"), "{err}");
    let cfg = cfg_with_db("ldap://cn%3Ddir@ldap.internal:389", "ldap://cn%3Ddir:real@ldap.internal:389"); // betterleaks:allow
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("password is required"), "{err}");
  }

  #[test]
  fn ldap_strings_reject_sslmode_and_keep_trust_on_the_real_string() {
    let cfg = cfg_with_db(
      "ldap://cn%3Ddir:fake@ldap.internal:389",                 // betterleaks:allow
      "ldap://cn%3Ddir:real@ldap.internal:389?sslmode=require", // betterleaks:allow
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("sslmode"), "{err}");
    let grant = redis_grant_like(
      "ldap://cn%3Ddir:fake@ldap.internal:389", // betterleaks:allow
      "ldap://cn%3Ddir:real@ldap.internal:389?sslrootcert=system&sslcert=/c.pem&sslkey=/c.key", // betterleaks:allow
    );
    let scope = grant.ldap(None, 389).expect("scope");
    assert_eq!(scope.root_cert, Some(RootCert::System));
    assert_eq!(scope.client_cert, Some(PathBuf::from("/c.pem")));
    assert_eq!(scope.client_key, Some(PathBuf::from("/c.key")));
  }

  #[test]
  fn ldap_schemes_are_not_endpoint_grants() {
    "ldap://ldap.internal:389".parse::<EndpointScope>().unwrap_err();
    "ldaps://ldap.internal:636".parse::<EndpointScope>().unwrap_err();
  }

  #[test]
  fn ldap_mtls_on_a_cleartext_fake_is_rejected() {
    assert_mtls_rejected(
      "ldap://cn%3Ddir:arkham_fake_ldap_pass@ldap.internal:389",     // betterleaks:allow
      "ldaps://cn%3Ddir:arkham_real_ldap_pass_01@ldap.internal:636", // betterleaks:allow
      &["arkham_fake_ldap_pass", "arkham_real_ldap_pass_01", "cn=dir"], // betterleaks:allow
      |err| matches!(err, crate::Error::LdapCleartextMtls { .. }),
    );
  }

  #[test]
  fn ldap_mtls_on_a_cleartext_upstream_still_loads() {
    let mut cfg = cfg_with_db(
      "ldap://cn%3Ddir:arkham_fake_ldap_pass@ldap.internal:389",    // betterleaks:allow
      "ldap://cn%3Ddir:arkham_real_ldap_pass_01@ldap.internal:389", // betterleaks:allow
    );
    mtls_on(&mut cfg);
    let resolved = resolve(&cfg).expect("ldap starttls with mtls still loads");
    let Some(Grant::Ldap { scope, .. }) = resolved.grants.first() else {
      panic!("an ldap rule");
    };
    assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
    assert!(!scope.is_downstream_tls);
    assert!(!scope.is_upstream_tls);
  }

  #[test]
  fn ldap_mtls_on_ldaps_lands_on_the_scope() {
    let mut cfg = cfg_with_db(
      "ldaps://cn%3Ddir:arkham_fake_ldap_pass@ldap.internal:636",    // betterleaks:allow
      "ldaps://cn%3Ddir:arkham_real_ldap_pass_01@ldap.internal:636", // betterleaks:allow
    );
    mtls_on(&mut cfg);
    let resolved = resolve(&cfg).expect("ldaps fake can demand a client certificate");
    let Some(Grant::Ldap { scope, .. }) = resolved.grants.first() else {
      panic!("an ldap rule");
    };
    assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
    assert!(scope.is_downstream_tls);
  }

  #[test]
  fn nats_grant_answers_for_the_nats_scheme_on_its_downstream_port() {
    let grant = redis_grant_like(
      "nats://agent:fake@nats.internal",                               // betterleaks:allow
      "tls://agent:real@nats.upstream:4443?sslrootcert=/certs/ca.crt", // betterleaks:allow
    );
    assert!(grant.matches(Scheme::Nats, "NATS.internal", 4222));
    assert!(!grant.matches(Scheme::Nats, "nats.internal", 4443));
    assert!(!grant.matches(Scheme::Tcp, "nats.internal", 4222));
    assert!(grant.nats(None, 4222).is_some());
    assert!(grant.nats(Some("other.internal"), 4222).is_none());
    assert!(grant.smtp(Some("nats.internal"), 4222).is_none());
    let credential = grant.credential().expect("a nats grant swaps a credential");
    assert_eq!((credential.fake.as_str(), credential.value.expose_secret()), ("fake", "real"));
    let scope = grant.nats(Some("nats.internal"), 4222).expect("scope");
    assert_eq!(scope.upstream.port, 4443);
  }

  #[test]
  fn nats_tls_spelling_reaches_the_nats_vertical() {
    let grant = redis_grant_like("tls://fake-token@nats.internal", "tls://real-token@nats.upstream");
    let credential = grant.credential().expect("a nats grant swaps a credential");
    assert_eq!(
      (credential.fake.as_str(), credential.value.expose_secret()),
      ("fake-token", "real-token")
    );
    assert!(grant.nats(Some("nats.internal"), NATS_DEFAULT_PORT).is_some());
  }

  #[test]
  fn nats_spellings_are_not_endpoint_grants() {
    for entry in ["nats://nats.internal:4222", "tls://nats.internal:4222"] {
      let err = entry.parse::<EndpointScope>().unwrap_err();
      assert!(err.contains("the connection string is the grant"), "{err}");
    }
  }

  #[test]
  fn nats_rule_table_states_only_the_guest_leg() {
    let mut cfg = cfg_with_db(
      "nats://agent:fake@nats.internal", // betterleaks:allow
      "tls://agent:real@nats.upstream",  // betterleaks:allow
    );
    let entry = || HostTlsCfg {
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls_mode: GuestTlsMode::Mtls,
      guest_cert: None,
      guest_key: None,
    };
    let mut trust = entry();
    trust.root_cert = Some(PathBuf::from("/certs/ca.crt"));
    cfg.rules.get_mut("t").unwrap().tls = BTreeMap::from([("DATABASE_URL".to_string(), trust)]);
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("nats states upstream trust"), "{err}");
    let mut identity = entry();
    identity.client_cert = Some(PathBuf::from("/c.pem"));
    identity.client_key = Some(PathBuf::from("/c.key"));
    cfg.rules.get_mut("t").unwrap().tls = BTreeMap::from([("DATABASE_URL".to_string(), identity)]);
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("nats states the upstream identity"), "{err}");
    cfg.rules.get_mut("t").unwrap().tls = BTreeMap::from([("DATABASE_URL".to_string(), entry())]);
    let grant = resolve(&cfg).unwrap().grants.into_iter().next().unwrap();
    assert_eq!(grant.nats(None, 4222).expect("scope").guest_tls, GuestTlsMode::Mtls);
  }

  #[test]
  fn rule_table_for_a_redis_rule_keys_by_its_env() {
    let mut cfg = cfg_with_db(
      "rediss://app:fake@db.internal:6379/0", // betterleaks:allow
      "rediss://app:real@db.internal:6379/0", // betterleaks:allow
    );
    let entry = || HostTlsCfg {
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls_mode: GuestTlsMode::Mtls,
      guest_cert: Some(PathBuf::from("/in/cert.pem")),
      guest_key: Some(PathBuf::from("/in/key.pem")),
    };
    // A wrong key names nothing; the rule's env is the key.
    let mut tls = BTreeMap::new();
    tls.insert("REDIS_PASSWORD".to_string(), entry());
    cfg.rules.get_mut("t").unwrap().tls = tls;
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("the rule's env is `DATABASE_URL`"), "{err}");
    // The table states the guest leg, never the upstream identity or trust —
    // the connection string already owns those.
    let mut tls = BTreeMap::new();
    let mut e = entry();
    e.client_cert = Some(PathBuf::from("/c.pem"));
    e.client_key = Some(PathBuf::from("/c.key"));
    tls.insert("DATABASE_URL".to_string(), e);
    cfg.rules.get_mut("t").unwrap().tls = tls;
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("never in the rule table"), "{err}");
    // Keyed correctly, the guest-leg mode lands on the scope.
    let mut tls = BTreeMap::new();
    tls.insert("DATABASE_URL".to_string(), entry());
    cfg.rules.get_mut("t").unwrap().tls = tls;
    let resolved = resolve(&cfg).unwrap();
    let Some(Grant::Redis { scope, .. }) = resolved.grants.first() else {
      panic!("a redis rule");
    };
    assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
  }

  /// A resolved SMTP scope, through [`resolve`] exactly as serve does.
  fn smtp_scope(fake: &str, real: &str) -> SmtpScope {
    let resolved = resolve(&cfg_with_db(fake, real)).unwrap();
    let Some(Grant::Smtp { scope, .. }) = resolved.grants.first() else {
      panic!("an smtp rule resolves to an smtp grant");
    };
    (**scope).clone()
  }

  /// A resolved SMTP grant.
  fn smtp_grant(fake: &str, real: &str) -> Grant {
    let resolved = resolve(&cfg_with_db(fake, real)).unwrap();
    resolved.grants.into_iter().next().unwrap()
  }

  #[test]
  fn smtp_grant_answers_for_smtp_schemes() {
    let grant = smtp_grant(
      "smtp://agent%40demo.test:fake@mail.internal:587",                   // betterleaks:allow
      "smtp://agent%40demo.test:real@mail.internal:587?starttls=required", // betterleaks:allow
    );
    assert!(grant.matches(Scheme::Smtp, "mail.internal", 587));
    assert!(grant.matches(Scheme::Smtps, "mail.internal", 587));
    assert!(!grant.matches(Scheme::Tcp, "mail.internal", 587));
    assert!(!grant.matches(Scheme::Smtp, "mail.internal", 25));
    assert!(!grant.matches(Scheme::Smtp, "other.internal", 587));
    assert!(grant.endpoint(Scheme::Smtp, Some("mail.internal"), 587).is_none());
    assert!(grant.redis(Some("mail.internal"), 587).is_none());
    let credential = grant.credential().expect("an smtp grant swaps a credential");
    assert_eq!(credential.label, "t");
    assert_eq!(credential.fake, "fake");
    let scope = grant.smtp(Some("mail.internal"), 587).expect("port and host cover the scope");
    assert!(scope.starttls_required);
    assert_eq!(scope.downstream.user, "agent@demo.test");
    assert!(!scope.is_downstream_tls);
    assert!(!scope.is_upstream_tls);
    let encoded = smtp_scope(
      "smtp://agent%40demo.test:p%40ss@mail.internal:587", // betterleaks:allow
      "smtp://agent%40demo.test:re%61l@mail.internal:587", // betterleaks:allow
    );
    assert_eq!(encoded.downstream.user, "agent@demo.test");
    assert_eq!(encoded.downstream.password.expose_secret(), "p@ss");
    assert_eq!(encoded.upstream.password.expose_secret(), "real");
    // A `%` that is not two hex digits stays literal. Invalid UTF-8 fails.
    let literal = smtp_scope(
      "smtp://agent%zz:fake@mail.internal:587", // betterleaks:allow
      "smtp://agent:real@mail.internal:587",    // betterleaks:allow
    );
    assert_eq!(literal.downstream.user, "agent%zz");
    let cfg = cfg_with_db(
      "smtp://agent%FF:fake@mail.internal:587", // betterleaks:allow
      "smtp://agent:real@mail.internal:587",    // betterleaks:allow
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("UTF-8"), "{err}");
  }

  #[test]
  fn smtp_default_ports_follow_the_scheme() {
    let scope = smtp_scope(
      "smtp://agent:fake@mail.internal",                     // betterleaks:allow
      "smtps://agent:real@mail.internal?sslrootcert=system", // betterleaks:allow
    );
    assert_eq!(scope.downstream.port, 587);
    assert_eq!(scope.upstream.port, 465);
    assert!(!scope.is_downstream_tls);
    assert!(scope.is_upstream_tls);
    assert!(!scope.starttls_required);
    assert_eq!(scope.root_cert, Some(RootCert::System));
  }

  #[test]
  fn smtp_resend_ports_keep_the_scheme_transport() {
    // 25, 465, 587, 2465, and 2587 are the ports Resend publishes. 2465 is
    // implicit TLS and 2587 is STARTTLS only because the string says so:
    // an explicit port is never rewritten, and it does not pick the scheme.
    let relay = smtp_scope(
      "smtp://agent:fake@mail.internal:25", // betterleaks:allow
      "smtp://agent:real@mail.internal:25", // betterleaks:allow
    );
    assert_eq!(relay.downstream.port, 25);
    assert_eq!(relay.upstream.port, 25);
    assert!(!relay.is_downstream_tls);
    assert!(!relay.is_upstream_tls);
    assert!(!relay.starttls_required);
    let submission = smtp_scope(
      "smtp://agent:fake@mail.internal:587",                   // betterleaks:allow
      "smtp://agent:real@mail.internal:587?starttls=required", // betterleaks:allow
    );
    assert_eq!(submission.upstream.port, 587);
    assert!(submission.starttls_required);
    assert!(!submission.is_upstream_tls);
    let implicit = smtp_scope(
      "smtps://agent:fake@mail.internal:465", // betterleaks:allow
      "smtps://agent:real@mail.internal:465", // betterleaks:allow
    );
    assert_eq!(implicit.downstream.port, 465);
    assert!(implicit.is_downstream_tls);
    assert!(implicit.is_upstream_tls);
    assert!(!implicit.starttls_required);
    let alt_implicit = smtp_scope(
      "smtps://agent:fake@mail.internal:2465", // betterleaks:allow
      "smtps://agent:real@mail.internal:2465", // betterleaks:allow
    );
    assert_eq!(alt_implicit.downstream.port, 2465);
    assert_eq!(alt_implicit.upstream.port, 2465);
    assert!(alt_implicit.is_downstream_tls);
    assert!(alt_implicit.is_upstream_tls);
    assert!(!alt_implicit.starttls_required);
    let alt_starttls = smtp_scope(
      "smtp://agent:fake@mail.internal:2587",                   // betterleaks:allow
      "smtp://agent:real@mail.internal:2587?starttls=required", // betterleaks:allow
    );
    assert_eq!(alt_starttls.downstream.port, 2587);
    assert_eq!(alt_starttls.upstream.port, 2587);
    assert!(alt_starttls.starttls_required);
    assert!(!alt_starttls.is_downstream_tls);
    assert!(!alt_starttls.is_upstream_tls);
  }

  #[test]
  fn smtp_strings_need_user_and_password() {
    let cfg = cfg_with_db("smtp://mail.internal:587", "smtp://agent:real@mail.internal:587"); // betterleaks:allow
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("the user is required"), "{err}");
    let cfg = cfg_with_db(
      "smtp://agent:fake@mail.internal:587", // betterleaks:allow
      "smtp://agent@mail.internal:587",
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("the password is required"), "{err}");
  }

  #[test]
  fn smtp_strings_reject_transport_queries_and_a_path() {
    let cfg = cfg_with_db(
      "smtp://agent:fake@mail.internal:587",                 // betterleaks:allow
      "smtp://agent:real@mail.internal:587?sslmode=require", // betterleaks:allow
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("sslmode"), "{err}");
    let cfg = cfg_with_db(
      "smtp://agent:fake@mail.internal:587/inbox", // betterleaks:allow
      "smtp://agent:real@mail.internal:587",       // betterleaks:allow
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("no path"), "{err}");
  }

  #[test]
  fn smtp_starttls_is_required_or_absent_and_only_on_cleartext() {
    let cfg = cfg_with_db(
      "smtp://agent:fake@mail.internal:587",                        // betterleaks:allow
      "smtp://agent:real@mail.internal:587?starttls=opportunistic", // betterleaks:allow
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("required"), "{err}");
    let cfg = cfg_with_db(
      "smtp://agent:fake@mail.internal:587",                    // betterleaks:allow
      "smtps://agent:real@mail.internal:465?starttls=required", // betterleaks:allow
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("already TLS"), "{err}");
  }

  #[test]
  fn smtp_trust_belongs_on_a_tls_leg() {
    let scope = smtp_scope(
      "smtp://agent:fake@mail.internal:587", // betterleaks:allow
      "smtp://agent:real@mail.internal:587?starttls=required&sslrootcert=/ca.pem&sslcert=/c.pem&sslkey=/c.key", // betterleaks:allow
    );
    assert_eq!(scope.root_cert, Some(RootCert::Path(PathBuf::from("/ca.pem"))));
    assert_eq!(scope.client_cert, Some(PathBuf::from("/c.pem")));
    assert_eq!(scope.client_key, Some(PathBuf::from("/c.key")));
    let cfg = cfg_with_db(
      "smtp://agent:fake@mail.internal:25",                     // betterleaks:allow
      "smtp://agent:real@mail.internal:25?sslrootcert=/ca.pem", // betterleaks:allow
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("no TLS state"), "{err}");
  }

  #[test]
  fn smtp_rules_state_no_allow_entries() {
    let mut cfg = cfg_with_db(
      "smtp://agent:fake@mail.internal:587", // betterleaks:allow
      "smtp://agent:real@mail.internal:587", // betterleaks:allow
    );
    cfg.rules.get_mut("t").unwrap().allow = vec!["https://api.github.com".to_string()];
    resolve(&cfg).unwrap_err();
  }

  #[test]
  fn smtp_schemes_are_not_endpoint_grants() {
    "smtp://mail.internal:587".parse::<EndpointScope>().unwrap_err();
    "smtps://mail.internal:465".parse::<EndpointScope>().unwrap_err();
  }

  #[test]
  fn smtp_mtls_on_a_cleartext_fake_is_rejected() {
    assert_mtls_rejected(
      "smtp://agent:arkham_fake_smtp_pass@mail.internal:587",          // betterleaks:allow
      "smtps://agent:arkham_real_smtp_pass_01@mail.internal:465",      // betterleaks:allow
      &["arkham_fake_smtp_pass", "arkham_real_smtp_pass_01", "agent"], // betterleaks:allow
      |err| matches!(err, crate::Error::SmtpCleartextMtls { .. }),
    );
  }

  #[test]
  fn smtp_mtls_on_starttls_still_loads() {
    let mut cfg = cfg_with_db(
      "smtp://agent:arkham_fake_smtp_pass@mail.internal:587", // betterleaks:allow
      "smtp://agent:arkham_real_smtp_pass_01@mail.internal:587?starttls=required", // betterleaks:allow
    );
    mtls_on(&mut cfg);
    let resolved = resolve(&cfg).expect("smtp starttls with mtls still loads");
    let Some(Grant::Smtp { scope, .. }) = resolved.grants.first() else {
      panic!("an smtp rule");
    };
    assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
    assert!(!scope.is_downstream_tls);
    assert!(!scope.is_upstream_tls);
    assert!(scope.starttls_required);
  }

  #[test]
  fn smtp_mtls_on_smtps_lands_on_the_scope() {
    let mut cfg = cfg_with_db(
      "smtps://agent:arkham_fake_smtp_pass@mail.internal:465",    // betterleaks:allow
      "smtps://agent:arkham_real_smtp_pass_01@mail.internal:465", // betterleaks:allow
    );
    mtls_on(&mut cfg);
    let resolved = resolve(&cfg).expect("smtps fake can demand a client certificate");
    let Some(Grant::Smtp { scope, .. }) = resolved.grants.first() else {
      panic!("an smtp rule");
    };
    assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
    assert!(scope.is_downstream_tls);
  }

  #[test]
  fn rule_table_for_an_smtp_rule_keys_by_its_env() {
    let mut cfg = cfg_with_db(
      "smtps://agent:fake@mail.internal:465", // betterleaks:allow
      "smtps://agent:real@mail.internal:465", // betterleaks:allow
    );
    let entry = || HostTlsCfg {
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls_mode: GuestTlsMode::Mtls,
      guest_cert: Some(PathBuf::from("/in/cert.pem")),
      guest_key: Some(PathBuf::from("/in/key.pem")),
    };
    let mut tls = BTreeMap::new();
    let mut e = entry();
    e.root_cert = Some(PathBuf::from("/ca.pem"));
    tls.insert("DATABASE_URL".to_string(), e);
    cfg.rules.get_mut("t").unwrap().tls = tls;
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("never in the rule table"), "{err}");
    let mut tls = BTreeMap::new();
    tls.insert("DATABASE_URL".to_string(), entry());
    cfg.rules.get_mut("t").unwrap().tls = tls;
    let resolved = resolve(&cfg).unwrap();
    let Some(Grant::Smtp { scope, .. }) = resolved.grants.first() else {
      panic!("an smtp rule");
    };
    assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
  }

  fn cfg_with_rule(entries: &[&str]) -> AppConfig {
    cfg_with_tls(entries, BTreeMap::new())
  }

  /// [`cfg_with_rule`] plus per-entry TLS configuration.
  fn cfg_with_tls(entries: &[&str], tls: BTreeMap<String, HostTlsCfg>) -> AppConfig {
    let mut rules = BTreeMap::new();
    rules.insert(
      "t".to_string(),
      RuleCfg {
        env: "T".into(),
        value: Some(SecretString::from("value")),
        real: None,
        fnox_key: None,
        allow: entries.iter().map(|entry| (*entry).to_string()).collect(),
        pattern: None,
        registry: None,
        oauth2: None,
        ssh: BTreeMap::new(),
        tls,
        if_missing: crate::config::IfMissing::default(),
      },
    );
    AppConfig {
      proxy: ProxyCfg {
        listen: "127.0.0.1:8080".parse().unwrap(),
        ca_file: None,
        ssh_host_key: None,
        ssh_known_hosts: None,
        root_certs: Vec::new(),
        handshake_timeout_secs: 10,
      },
      workspace: WorkspaceCfg::default(),
      rules,
      plugins: BTreeMap::new(),
      tools: BTreeMap::new(),
    }
  }

  fn config_with_rule(label: &str, env: &str, value: &str, allow: Vec<&str>) -> AppConfig {
    let mut rules = BTreeMap::new();
    rules.insert(
      label.to_string(),
      RuleCfg {
        env: env.to_string(),
        value: Some(SecretString::from(value)),
        real: None,
        fnox_key: None,
        allow: allow.into_iter().map(str::to_string).collect(),
        pattern: None,
        oauth2: None,
        registry: Some(false),
        ssh: BTreeMap::new(),
        tls: BTreeMap::new(),
        if_missing: IfMissing::Error,
      },
    );
    AppConfig {
      proxy: ProxyCfg {
        listen: "127.0.0.1:8080".parse().unwrap(),
        ca_file: None,
        ssh_host_key: None,
        ssh_known_hosts: None,
        root_certs: Vec::new(),
        handshake_timeout_secs: 10,
      },
      workspace: WorkspaceCfg::default(),
      rules,
      plugins: BTreeMap::new(),
      tools: BTreeMap::new(),
    }
  }

  #[test]
  fn tcp_grant_decoy_matches_the_real_value_length() {
    let config = config_with_rule("db", "PGPASSWORD", "twenty-char-password", vec!["tcp://10.0.0.8:5432"]);
    let resolved = resolve(&config).unwrap();
    let grant = &resolved.grants[0];
    let credential = grant.credential().expect("an endpoint rule carries a credential");
    assert_eq!(credential.fake.len(), 20, "decoy length equals the real value length");
  }

  #[test]
  fn https_only_grant_keeps_the_shaped_decoy() {
    let config = config_with_rule("gh", "GITHUB_TOKEN", "ghp_real", vec!["https://api.github.com"]);
    let resolved = resolve(&config).unwrap();
    let grant = &resolved.grants[0];
    let credential = grant.credential().expect("an endpoint rule carries a credential");
    assert_eq!(credential.fake, crate::config::fake_for("GITHUB_TOKEN", None));
    assert_eq!(credential.fake.len(), 32, "default pattern renders 32 hex characters");
  }

  #[test]
  fn uri_matching_covers_scheme_port_host() {
    let grant = endpoint_grant(&[
      "https://api.github.com",
      "https://*.githubusercontent.com",
      "tcp://10.0.0.8:5432",
      "https://*",
    ]);
    assert!(grant.matches(Scheme::Https, "api.github.com", 443));
    assert!(grant.matches(Scheme::Https, "API.GITHUB.COM", 443));
    assert!(!grant.matches(Scheme::Https, "api.github.com", 8443));
    assert!(!grant.matches(Scheme::Http, "api.github.com", 80));
    assert!(grant.matches(Scheme::Https, "x.githubusercontent.com", 443));
    // Apex matches here via the `https://*` entry; wildcard-apex exclusion
    // is covered by `wildcard_excludes_apex_but_matches_subdomains`.
    assert!(grant.matches(Scheme::Https, "githubusercontent.com", 443));
    assert!(grant.matches(Scheme::Tcp, "10.0.0.8", 5432));
    assert!(!grant.matches(Scheme::Tcp, "10.0.0.8", 5433));
    assert!(grant.matches(Scheme::Https, "anything.example", 443));
    assert!(!grant.matches(Scheme::Http, "anything.example", 80));
  }

  #[test]
  fn wildcard_excludes_apex_but_matches_subdomains() {
    let grant = endpoint_grant(&["https://*.example.com"]);
    assert!(!grant.matches(Scheme::Https, "example.com", 443));
    assert!(grant.matches(Scheme::Https, "a.example.com", 443));
    assert!(grant.matches(Scheme::Https, "A.EXAMPLE.COM", 443));
    assert!(
      grant.matches(Scheme::Https, "a.b.example.com", 443),
      "matches at any depth, e.g. api.v3.aave.com"
    );
    assert!(!grant.matches(Scheme::Https, "notexample.com", 443));
    assert!(!grant.matches(Scheme::Https, "example.com.evil.com", 443));
  }

  #[test]
  fn a_tcp_scope_is_not_an_https_scope() {
    // A tcp:// scope on a TLS port is not a TLS scope: the arm comes from the
    // scheme the config names.
    let grant = endpoint_grant(&["tcp://api.github.com:443"]);
    assert!(grant.endpoint(Scheme::Tcp, Some("api.github.com"), 443).is_some());
    assert!(grant.endpoint(Scheme::Https, Some("api.github.com"), 443).is_none());
    let grant = endpoint_grant(&["https://api.github.com"]);
    assert!(grant.endpoint(Scheme::Https, Some("api.github.com"), 443).is_some());
  }

  #[test]
  fn bad_entries_error() {
    "gopher://h".parse::<EndpointScope>().unwrap_err();
    "tcp://h".parse::<EndpointScope>().unwrap_err();
    "postgres://*:5432".parse::<EndpointScope>().unwrap_err();
    "https://".parse::<EndpointScope>().unwrap_err();
    "https://:443".parse::<EndpointScope>().unwrap_err();
    "https://h:abc".parse::<EndpointScope>().unwrap_err();
    "no-scheme".parse::<EndpointScope>().unwrap_err();
    "https://::1".parse::<EndpointScope>().unwrap_err();
    "https://::1:443".parse::<EndpointScope>().unwrap_err();
    "https://user@h".parse::<EndpointScope>().unwrap_err();
    "https://h/path".parse::<EndpointScope>().unwrap_err();
    "https://h?q=1".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432?sslmode=maybe".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432?sslnegotiation=maybe".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432?sslmode=verify-ca".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432?sslmode=verify-full".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432?sslmode=require&sslrootcert="
      .parse::<EndpointScope>()
      .unwrap_err();
    "https://h?sslnegotiation=direct".parse::<EndpointScope>().unwrap_err();
    "https://h?sslrootcert=/ca.pem".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432/a/b?sslmode=disable".parse::<EndpointScope>().unwrap_err();
    "https://h:443?sslcert=/c.pem&sslkey=/c.key".parse::<EndpointScope>().unwrap_err();
    "https://h?sslcert=/c.pem".parse::<EndpointScope>().unwrap_err();
    "https://h?sslkey=/c.key".parse::<EndpointScope>().unwrap_err();
    "https://h?sslcert=&sslkey=/c.key".parse::<EndpointScope>().unwrap_err();
    "tcp://h:443?sslcert=/c.pem&sslkey=/c.key".parse::<EndpointScope>().unwrap_err();
    "http://h?sslcert=/c.pem&sslkey=/c.key".parse::<EndpointScope>().unwrap_err();
  }

  #[test]
  fn client_identity_is_stated_by_the_real_string() {
    // libpq's own grammar carries the client identity on the real string —
    // the upstream leg's policy; endpoint URLs carry nothing of the kind.
    let pg = postgres_scope(
      "postgres://app:fake@db.internal:5432/main", // betterleaks:allow
      "postgres://app:real@db.internal:5432/main?sslmode=require&sslcert=/c.pem&sslkey=/c.key", // betterleaks:allow
    );
    assert_eq!(pg.client_cert, Some(PathBuf::from("/c.pem")));
    assert_eq!(pg.client_key, Some(PathBuf::from("/c.key")));
    let bare = endpoint_scope("https://api.internal");
    assert_eq!(bare.client_cert, None);
    assert_eq!(bare.client_key, None);
    assert_eq!(bare.guest_tls, GuestTlsMode::default());
  }

  #[test]
  fn rule_table_states_arkham_own_tls_configuration() {
    let mut tls = BTreeMap::new();
    tls.insert(
      "https://api.internal:443".to_string(),
      HostTlsCfg {
        client_cert: Some(PathBuf::from("/c.pem")),
        client_key: Some(PathBuf::from("/c.key")),
        root_cert: None,
        guest_tls_mode: GuestTlsMode::Mtls,
        guest_cert: Some(PathBuf::from("/in/cert.pem")),
        guest_key: Some(PathBuf::from("/in/key.pem")),
      },
    );
    let cfg = cfg_with_tls(&["https://api.internal:443"], tls);
    let resolved = resolve(&cfg).unwrap();
    let Grant::Token { allow, .. } = &resolved.grants[0] else {
      panic!("an endpoint rule");
    };
    assert_eq!(allow[0].client_cert, Some(PathBuf::from("/c.pem")));
    assert_eq!(allow[0].client_key, Some(PathBuf::from("/c.key")));
    assert_eq!(allow[0].guest_tls, GuestTlsMode::Mtls);
  }

  #[test]
  fn rule_table_for_a_database_rule_keys_by_its_env() {
    let mut cfg = cfg_with_db(
      "postgres://app:fake@db.internal:5432/main",                 // betterleaks:allow
      "postgres://app:real@db.internal:5432/main?sslmode=require", // betterleaks:allow
    );
    let entry = || HostTlsCfg {
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls_mode: GuestTlsMode::Mtls,
      guest_cert: Some(PathBuf::from("/in/cert.pem")),
      guest_key: Some(PathBuf::from("/in/key.pem")),
    };
    // A wrong key names nothing; the rule's env is the key.
    let mut tls = BTreeMap::new();
    tls.insert("PGPASSWORD".to_string(), entry());
    cfg.rules.get_mut("t").unwrap().tls = tls;
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("the rule's env is `DATABASE_URL`"), "{err}");
    // The table states the guest leg, never the upstream identity — libpq's
    // URL already owns that (`sslcert`/`sslkey`).
    let mut tls = BTreeMap::new();
    let mut e = entry();
    e.client_cert = Some(PathBuf::from("/c.pem"));
    e.client_key = Some(PathBuf::from("/c.key"));
    tls.insert("DATABASE_URL".to_string(), e);
    cfg.rules.get_mut("t").unwrap().tls = tls;
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("never in the rule table"), "{err}");
    // Keyed correctly, the guest-leg mode lands on the scope.
    let mut tls = BTreeMap::new();
    tls.insert("DATABASE_URL".to_string(), entry());
    cfg.rules.get_mut("t").unwrap().tls = tls;
    let resolved = resolve(&cfg).unwrap();
    let Some(Grant::Postgres { scope, .. }) = resolved.grants.first() else {
      panic!("a database rule");
    };
    assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
  }

  #[test]
  fn postgres_mtls_stays_when_the_guest_picks_tls() {
    let mut cfg = cfg_with_db(
      "postgres://app:arkham_fake_pg_pass@db.internal:5432/main", // betterleaks:allow
      "postgres://app:arkham_real_pg_pass_01@db.internal:5432/main?sslmode=require", // betterleaks:allow
    );
    mtls_on(&mut cfg);
    let resolved = resolve(&cfg).expect("postgres mtls stays, the guest picks the transport");
    let Some(Grant::Postgres { scope, .. }) = resolved.grants.first() else {
      panic!("a database rule");
    };
    assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
  }

  #[test]
  fn rule_table_keys_must_name_allowed_entries() {
    let mut tls = BTreeMap::new();
    tls.insert(
      "https://other.internal:443".to_string(),
      HostTlsCfg {
        client_cert: None,
        client_key: None,
        root_cert: None,
        guest_tls_mode: GuestTlsMode::default(),
        guest_cert: None,
        guest_key: None,
      },
    );
    let cfg = cfg_with_tls(&["https://api.internal:443"], tls);
    assert!(resolve(&cfg).unwrap_err().to_string().contains("the rule does not allow"));
  }

  #[test]
  fn system_names_the_platform_trust_store() {
    let pg = postgres_scope(
      "postgres://app:fake@db.internal:5432/main",                         // betterleaks:allow
      "postgres://app:real@h:5432?sslmode=verify-full&sslrootcert=system", // betterleaks:allow
    );
    assert_eq!(pg.root_cert, Some(RootCert::System));
    let path = postgres_scope(
      "postgres://app:fake@db.internal:5432/main",                          // betterleaks:allow
      "postgres://app:real@h:5432?sslmode=verify-full&sslrootcert=/ca.pem", // betterleaks:allow
    );
    assert_eq!(path.root_cert, Some(RootCert::Path(PathBuf::from("/ca.pem"))));
  }

  #[test]
  fn bracketed_ipv6_matches_bare_ip() {
    let grant = endpoint_grant(&["tcp://[::1]:5432", "https://[2001:db8::1]"]);
    assert!(grant.matches(Scheme::Tcp, "::1", 5432));
    assert!(grant.matches(Scheme::Https, "2001:db8::1", 443));
  }

  #[test]
  fn scope_lookup_answers_by_scheme_and_by_port() {
    // A port-only lookup answers while the identity is still unknown, which is
    // all a transparent capture has to work with.
    let grant = endpoint_grant(&["https://api.github.com"]);
    assert!(grant.endpoint(Scheme::Https, Some("api.github.com"), 443).is_some());
    assert!(grant.endpoint(Scheme::Https, Some("api.github.com"), 80).is_none());
    assert!(grant.endpoint(Scheme::Https, Some("evil.example"), 443).is_none());
    assert!(grant.endpoint(Scheme::Https, None, 443).is_some());
  }

  #[test]
  fn a_database_rule_maps_two_connection_strings() {
    let scope = postgres_scope(
      "postgres://app:fake@fake.internal:5433/main", // betterleaks:allow
      "postgres://app:real@db.internal:5432/main?sslmode=verify-full&sslrootcert=/ca.pem", // betterleaks:allow
    );
    // The fake string states the guest's leg; its port is the match key.
    assert_eq!(scope.downstream.host, "fake.internal");
    assert_eq!(scope.downstream.port, 5433);
    assert_eq!(scope.downstream.user.as_deref(), Some("app"));
    assert_eq!(scope.downstream.password.expose_secret(), "fake");
    assert_eq!(scope.downstream.database.as_deref(), Some("main"));
    // The real string states the server's leg and the upstream policy.
    assert_eq!(scope.upstream.host, "db.internal");
    assert_eq!(scope.upstream.port, 5432);
    assert_eq!(scope.upstream.user.as_deref(), Some("app"));
    assert_eq!(scope.upstream.password.expose_secret(), "real");
    assert_eq!(scope.upstream.database.as_deref(), Some("main"));
    assert_eq!(scope.ssl, SslMode::VerifyFull);
    assert_eq!(scope.root_cert, Some(RootCert::Path(PathBuf::from("/ca.pem"))));
  }

  #[test]
  fn postgres_grant_answers_only_for_postgres() {
    let grant = postgres_grant(
      "postgres://app:fake@db.internal:5432/main",                 // betterleaks:allow
      "postgres://app:real@db.internal:5432/main?sslmode=require", // betterleaks:allow
    );
    assert!(grant.matches(Scheme::Postgres, "db.internal", 5432));
    assert!(!grant.matches(Scheme::Https, "db.internal", 5432));
    assert!(grant.postgres(Some("db.internal"), 5432).is_some());
    assert!(grant.postgres(None, 5432).is_some());
    assert!(grant.postgres(Some("db.internal"), 5433).is_none());
    // The wire needles are the two passwords: fake in, real out.
    let Grant::Postgres { credential, .. } = &grant else {
      panic!("a postgres grant");
    };
    assert_eq!(credential.fake, "fake");
    assert_eq!(credential.value.expose_secret(), "real");
  }

  #[test]
  fn the_kind_comes_from_the_stated_value() {
    let cfg = cfg_with_rule(&["https://api.github.com"]);
    let resolved = resolve(&cfg).unwrap();
    assert!(matches!(resolved.grants[0], Grant::Token { .. }));
    let credential = resolved.grants[0].credential().expect("an endpoint rule carries a credential");
    assert_eq!(credential.label, "t");

    let cfg = cfg_with_db(
      "postgres://app:fake@db.internal:5432/main",                 // betterleaks:allow
      "postgres://app:real@db.internal:5432/main?sslmode=disable", // betterleaks:allow
    );
    let resolved = resolve(&cfg).unwrap();
    let Grant::Postgres { scope, .. } = &resolved.grants[0] else {
      panic!("database rule must resolve to a database grant");
    };
    // The real string states the upstream policy.
    assert_eq!(scope.ssl, SslMode::Disable);
    assert_eq!(scope.upstream.database.as_deref(), Some("main"));
  }

  #[test]
  fn a_database_rule_states_no_allow_entries() {
    let mut cfg = cfg_with_db(
      "postgres://app:fake@db.internal:5432/main",                 // betterleaks:allow
      "postgres://app:real@db.internal:5432/main?sslmode=require", // betterleaks:allow
    );
    cfg.rules.get_mut("t").unwrap().allow = vec!["https://api.github.com".to_string()];
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("no allow entries"), "{err}");
    assert!(err.contains("the connection string is the grant"), "{err}");
  }

  #[test]
  fn database_strings_need_their_credentials() {
    // Both strings carry a password: a string with no credential maps
    // nothing.
    let cfg = cfg_with_db("postgres://app@db.internal:5432/main", "postgres://app:real@db.internal:5432/main"); // betterleaks:allow
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("the password is required"), "{err}");
    let cfg = cfg_with_db("postgres://app:fake@db.internal:5432/main", "postgres://app@db.internal:5432/main"); // betterleaks:allow
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("the password is required"), "{err}");
    // A schemed value that is not a connection string fails: the URL
    // mandate is enforced at parse. A bare token is a different kind of
    // rule, not a database rule at all.
    let cfg = cfg_with_db("postgres://app:fake@/main", "postgres://app:real@db.internal:5432/main"); // betterleaks:allow
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("empty host"), "{err}");
    // Without the secret-source real string there is no grant at all.
    let mut cfg = cfg_with_db(
      "postgres://app:fake@db.internal:5432/main", // betterleaks:allow
      "postgres://app:real@db.internal:5432/main", // betterleaks:allow
    );
    cfg.rules.get_mut("t").unwrap().real = None;
    let resolved = resolve(&cfg).unwrap();
    assert!(resolved.grants.is_empty());
  }

  /// One ssh rule: entries plus per-entry key material, no value.
  fn cfg_with_ssh(entries: &[&str], ssh: BTreeMap<String, HostSshCfg>) -> AppConfig {
    let mut rules = BTreeMap::new();
    rules.insert(
      "t".to_string(),
      RuleCfg {
        env: "T".into(),
        value: None,
        real: None,
        fnox_key: None,
        allow: entries.iter().map(|entry| (*entry).to_string()).collect(),
        pattern: None,
        oauth2: None,
        registry: None,
        if_missing: IfMissing::Error,
        tls: BTreeMap::new(),
        ssh,
      },
    );
    AppConfig {
      proxy: ProxyCfg {
        listen: "127.0.0.1:8080".parse().unwrap(),
        ca_file: None,
        ssh_host_key: None,
        ssh_known_hosts: None,
        root_certs: Vec::new(),
        handshake_timeout_secs: 10,
      },
      workspace: WorkspaceCfg::default(),
      rules,
      plugins: BTreeMap::new(),
      tools: BTreeMap::new(),
    }
  }

  /// Complete per-entry ssh config pointing at state-side blobs.
  fn ssh_material(entry: &str) -> BTreeMap<String, HostSshCfg> {
    BTreeMap::from([(
      entry.to_string(),
      HostSshCfg {
        identity: Some(PathBuf::from("/arkham/grants/rules.d/t.identity")),
        guest_key: Some(PathBuf::from("/arkham/grants/rules.d/t.guest_key")),
      },
    )])
  }

  #[test]
  fn ssh_entry_defaults_to_port_22() {
    let scope: EndpointScope = "ssh://git.example".parse().unwrap();
    assert_eq!(scope.scheme, Scheme::Ssh);
    assert_eq!(scope.port, 22);
    assert!(matches!(&scope.host, HostPat::Exact(host) if host == "git.example"));

    let scope: EndpointScope = "ssh://git.example:2222".parse().unwrap();
    assert_eq!(scope.port, 2222);

    let err = "ssh://user@git.example".parse::<EndpointScope>().unwrap_err();
    assert!(err.contains("userinfo is postgres-only"), "{err}");
    let err = "ssh://git.example?sslmode=require".parse::<EndpointScope>().unwrap_err();
    assert!(err.contains("postgres-only"), "{err}");
  }

  #[test]
  fn ssh_rule_resolves_with_its_key_material() {
    let cfg = cfg_with_ssh(&["ssh://git.example"], ssh_material("ssh://git.example"));
    let resolved = resolve(&cfg).unwrap();
    let Some(Grant::Ssh { allow }) = resolved.grants.first() else {
      panic!("an ssh rule resolves to an ssh grant");
    };
    let scope = &allow[0];
    assert_eq!(scope.port, 22);
    assert_eq!(scope.identity, PathBuf::from("/arkham/grants/rules.d/t.identity"));
    assert_eq!(scope.guest_key, PathBuf::from("/arkham/grants/rules.d/t.guest_key"));
    assert!(resolved.grants[0].matches(Scheme::Ssh, "git.example", 22));
    assert!(!resolved.grants[0].matches(Scheme::Tcp, "git.example", 22));
    assert!(!resolved.grants[0].matches(Scheme::Ssh, "git.example", 2222));
    assert!(resolved.grants[0].credential().is_none());
  }

  #[test]
  fn transparent_capture_finds_the_ssh_scope_before_the_host_is_known() {
    let cfg = cfg_with_ssh(&["ssh://git.example:2222"], ssh_material("ssh://git.example:2222"));
    let resolved = resolve(&cfg).unwrap();
    let grant = &resolved.grants[0];
    let scope = grant.ssh(None, 2222).expect("the port alone narrows the scope");
    assert!(matches!(&scope.host, HostPat::Exact(host) if host == "git.example"));
    assert!(grant.ssh(Some("elsewhere.example"), 2222).is_none());
    assert!(grant.ssh(None, 22).is_none());
  }

  #[test]
  fn ssh_entry_without_key_material_fails_closed() {
    let cfg = cfg_with_ssh(&["ssh://git.example"], BTreeMap::new());
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("no ssh config for this entry"), "{err}");
  }

  #[test]
  fn ssh_config_missing_a_field_fails_closed() {
    let mut ssh = ssh_material("ssh://git.example");
    ssh.get_mut("ssh://git.example").unwrap().identity = None;
    let cfg = cfg_with_ssh(&["ssh://git.example"], ssh);
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("identity is required"), "{err}");
  }

  #[test]
  fn ssh_config_naming_an_ungranted_entry_fails_closed() {
    let mut ssh = ssh_material("ssh://git.example");
    ssh.insert(
      "ssh://other.example".to_string(),
      HostSshCfg {
        identity: None,
        guest_key: None,
      },
    );
    let cfg = cfg_with_ssh(&["ssh://git.example"], ssh);
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("ssh config names entry `ssh://other.example`"), "{err}");
  }

  #[test]
  fn ssh_rule_cannot_mix_schemes() {
    let cfg = cfg_with_ssh(&["ssh://git.example", "https://git.example"], BTreeMap::new());
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("ssh entries cannot mix"), "{err}");
  }

  #[test]
  fn ssh_rule_states_no_value() {
    let mut cfg = cfg_with_ssh(&["ssh://git.example"], ssh_material("ssh://git.example"));
    cfg.rules.get_mut("t").unwrap().value = Some(SecretString::from("nothing would swap it"));
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("an ssh rule states no `value`"), "{err}");
  }

  #[test]
  fn ssh_entry_takes_no_tls_config() {
    let mut cfg = cfg_with_ssh(&["ssh://git.example"], ssh_material("ssh://git.example"));
    cfg.rules.get_mut("t").unwrap().tls.insert(
      "ssh://git.example".to_string(),
      HostTlsCfg {
        client_cert: None,
        client_key: None,
        root_cert: None,
        guest_tls_mode: GuestTlsMode::default(),
        guest_cert: None,
        guest_key: None,
      },
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("states no `tls` config"), "{err}");
  }

  #[test]
  fn ssh_material_on_a_non_ssh_rule_fails_closed() {
    let mut cfg = cfg_with_ssh(&["https://api.example"], BTreeMap::new());
    cfg.rules.get_mut("t").unwrap().ssh.insert(
      "ssh://git.example".to_string(),
      HostSshCfg {
        identity: Some(PathBuf::from("/arkham/grants/rules.d/t.identity")),
        guest_key: Some(PathBuf::from("/arkham/grants/rules.d/t.guest_key")),
      },
    );
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("ssh config on a rule with no ssh entry"), "{err}");
  }
}
