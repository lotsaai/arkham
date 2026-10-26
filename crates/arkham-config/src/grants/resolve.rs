use secrecy::{ExposeSecret as _, SecretString};

use crate::config::{AppConfig, RuleCfg, fake_for};
use crate::error::Error;
use crate::plugins::resolve_plugins;

use super::amqp::AmqpScope;
use super::ldap::LdapScope;
use super::nats::NatsScope;
use super::postgres::PostgresScope;
use super::redis::RedisScope;
use super::scope::{Credential, EndpointScope, GuestTlsMode, HostPat, Scheme, SshScope};
use super::smtp::SmtpScope;

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
  /// on the real `smtp://` string upgrades that leg; AUTH swaps either way.
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
  /// One AMQP connection-string mapping: fake string to real, 1:1. Each
  /// string states its own leg's transport in its scheme.
  Amqp {
    /// The wire needles: the fake password and the real password.
    credential: Credential,
    /// The one scope this rule maps, carrying both legs' facts.
    scope: Box<AmqpScope>,
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
      | Grant::Nats { credential, .. }
      | Grant::Amqp { credential, .. } => Some(credential),
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
      Grant::Amqp { scope, .. } => AmqpScope::matches(scope, scheme, host, port),
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

  /// Postgres scope covering this downstream destination.
  #[must_use]
  pub fn postgres(&self, host: Option<&str>, port: u16) -> Option<&PostgresScope> {
    let Grant::Postgres { scope, .. } = self else { return None };
    downstream_covers(&scope.downstream.host, scope.downstream.port, host, port).then(|| scope.as_ref())
  }

  /// Redis scope covering this downstream destination.
  #[must_use]
  pub fn redis(&self, host: Option<&str>, port: u16) -> Option<&RedisScope> {
    let Grant::Redis { scope, .. } = self else { return None };
    downstream_covers(&scope.downstream.host, scope.downstream.port, host, port).then(|| scope.as_ref())
  }

  /// SMTP scope covering this downstream destination.
  #[must_use]
  pub fn smtp(&self, host: Option<&str>, port: u16) -> Option<&SmtpScope> {
    let Grant::Smtp { scope, .. } = self else { return None };
    downstream_covers(&scope.downstream.host, scope.downstream.port, host, port).then(|| scope.as_ref())
  }

  /// LDAP scope covering this downstream destination.
  #[must_use]
  pub fn ldap(&self, host: Option<&str>, port: u16) -> Option<&LdapScope> {
    let Grant::Ldap { scope, .. } = self else { return None };
    downstream_covers(&scope.downstream.host, scope.downstream.port, host, port).then(|| scope.as_ref())
  }

  /// NATS scope covering this downstream destination.
  #[must_use]
  pub fn nats(&self, host: Option<&str>, port: u16) -> Option<&NatsScope> {
    let Grant::Nats { scope, .. } = self else { return None };
    downstream_covers(&scope.downstream.host, scope.downstream.port, host, port).then(|| scope.as_ref())
  }

  /// AMQP scope covering this downstream destination.
  #[must_use]
  pub fn amqp(&self, host: Option<&str>, port: u16) -> Option<&AmqpScope> {
    let Grant::Amqp { scope, .. } = self else { return None };
    downstream_covers(&scope.downstream.host, scope.downstream.port, host, port).then(|| scope.as_ref())
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

/// Downstream `(host, port)` cover. `host` none matches any host on the port.
#[must_use]
pub(crate) fn downstream_covers(downstream_host: &str, downstream_port: u16, host: Option<&str>, port: u16) -> bool {
  downstream_port == port && host.is_none_or(|host| downstream_host.eq_ignore_ascii_case(host))
}

/// Why a rule `tls` row cannot state the guest leg.
pub(crate) enum TlsRow {
  /// The row key is not the rule's env name.
  Mismatch { key: String, env: String },
  /// The row names a client certificate or key.
  Identity,
  /// The row names a root certificate.
  Trust,
}

/// Guest TLS mode from the rule table. The last matching row wins.
///
/// # Errors
///
/// Returns a row that names the wrong env, a client identity, or a root.
pub(crate) fn apply_guest_tls(rule: &RuleCfg) -> Result<GuestTlsMode, TlsRow> {
  let mut mode = GuestTlsMode::default();
  for (key, tls) in &rule.tls {
    if key != &rule.env {
      return Err(TlsRow::Mismatch {
        key: key.clone(),
        env: rule.env.clone(),
      });
    }
    if tls.client_cert.is_some() || tls.client_key.is_some() {
      return Err(TlsRow::Identity);
    }
    if tls.root_cert.is_some() {
      return Err(TlsRow::Trust);
    }
    mode = tls.guest_tls_mode;
  }
  Ok(mode)
}

/// Map a [`TlsRow`] onto the protocol's identity and trust errors.
pub(crate) fn map_tls_row(label: &str, row: TlsRow, identity: Error, trust: Error) -> Error {
  match row {
    TlsRow::Mismatch { key, env } => Error::TlsEnvMismatch {
      label: label.to_string(),
      key,
      env,
    },
    TlsRow::Identity => identity,
    TlsRow::Trust => trust,
  }
}

/// Password credential. The downstream password is the decoy and the upstream password is the real value.
pub(crate) fn password_credential(label: &str, fake: &SecretString, value: SecretString) -> Credential {
  Credential {
    label: label.to_string(),
    fake: fake.expose_secret().to_string(),
    value,
  }
}

/// The fake connection string a rule states, or empty when it states none.
pub(crate) fn stated_fake(rule: &RuleCfg) -> String {
  rule
    .value
    .as_ref()
    .map(|value| value.expose_secret().to_string())
    .unwrap_or_default()
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
      Scheme::Postgres => super::postgres::grant(label, rule, real.expose_secret()),
      Scheme::Redis | Scheme::Rediss => super::redis::grant(label, rule, real.expose_secret()),
      Scheme::Smtp | Scheme::Smtps => super::smtp::grant(label, rule, real.expose_secret()),
      Scheme::Ldap | Scheme::Ldaps => super::ldap::grant(label, rule, real.expose_secret()),
      Scheme::Nats => super::nats::grant(label, rule, real.expose_secret()),
      Scheme::Amqp | Scheme::Amqps => super::amqp::grant(label, rule, real.expose_secret()),
      _ => {
        return Err(Error::ConnectionStringScheme {
          label: label.to_string(),
          scheme,
        });
      }
    }?;
    if let Grant::Nats { scope, .. } = &grant {
      for existing in &self.grants {
        let Grant::Nats {
          credential,
          scope: previous,
        } = existing
        else {
          continue;
        };
        if previous.downstream != scope.downstream {
          continue;
        }
        if previous.upstream != scope.upstream
          || !previous.upstream_tls.same_dial(&scope.upstream_tls)
          || previous.guest_tls != scope.guest_tls
        {
          return Err(Error::NatsSharedEndpoint {
            previous: credential.label.clone(),
            label: label.to_string(),
            host: scope.downstream.host.clone(),
            port: scope.downstream.port,
          });
        }
      }
    }
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
