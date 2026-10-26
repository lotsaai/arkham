use std::collections::BTreeMap;
use std::path::PathBuf;

use secrecy::{ExposeSecret as _, SecretString};

use crate::config::{AppConfig, RuleCfg};

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
      generated: false,
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

fn assert_mtls_loads(fake: &str, real: &str) {
  let mut cfg = cfg_with_db(fake, real);
  mtls_on(&mut cfg);
  let resolved = resolve(&cfg).expect("mtls on a cleartext fake loads");
  let mode = match resolved.grants.first() {
    Some(Grant::Redis { scope, .. }) => scope.guest_tls,
    Some(Grant::Smtp { scope, .. }) => scope.guest_tls,
    Some(Grant::Ldap { scope, .. }) => scope.guest_tls,
    Some(Grant::Amqp { scope, .. }) => scope.guest_tls,
    other => panic!("mtls grant: {other:?}"),
  };
  assert_eq!(mode, GuestTlsMode::Mtls);
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
fn redis_mtls_on_a_cleartext_fake_loads() {
  assert_mtls_loads(
    "redis://app:arkham_fake_redis_pass@db.internal:6379/0",     // betterleaks:allow
    "rediss://app:arkham_real_redis_pass_01@db.internal:6379/0", // betterleaks:allow
  );
}

#[test]
fn redis_mtls_on_a_cleartext_upstream_loads() {
  assert_mtls_loads(
    "redis://app:arkham_fake_redis_pass@db.internal:6379/0",    // betterleaks:allow
    "redis://app:arkham_real_redis_pass_01@db.internal:6379/0", // betterleaks:allow
  );
}

#[test]
fn redis_cleartext_grant_loads_client_cert_and_trust() {
  let scope = redis_scope(
    "redis://app:fake@db.internal:6379/0", // betterleaks:allow
    "redis://app:real@db.internal:6379/0?sslrootcert=/ca.pem&sslcert=/c.pem&sslkey=/c.key", // betterleaks:allow
  );
  assert!(!scope.is_upstream_tls);
  assert_eq!(scope.root_cert, Some(RootCert::Path(PathBuf::from("/ca.pem"))));
  assert_eq!(scope.client_cert, Some(PathBuf::from("/c.pem")));
  assert_eq!(scope.client_key, Some(PathBuf::from("/c.key")));
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
fn ldap_mtls_on_a_cleartext_fake_loads() {
  assert_mtls_loads(
    "ldap://cn%3Ddir:arkham_fake_ldap_pass@ldap.internal:389",     // betterleaks:allow
    "ldaps://cn%3Ddir:arkham_real_ldap_pass_01@ldap.internal:636", // betterleaks:allow
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

fn nats_rule(env: &str, fake: &str, real: &str) -> RuleCfg {
  RuleCfg {
    env: env.to_string(),
    value: Some(SecretString::from(fake)),
    real: Some(SecretString::from(real)),
    generated: false,
    fnox_key: None,
    allow: vec![],
    pattern: None,
    registry: None,
    oauth2: None,
    tls: BTreeMap::new(),
    ssh: BTreeMap::new(),
    if_missing: IfMissing::default(),
  }
}

fn two_nats(first: (&str, &str, &str), second: (&str, &str, &str)) -> AppConfig {
  let mut cfg = cfg_with_db(
    "nats://unused:unused@unused.invalid:4222",
    "nats://unused:unused@unused.invalid:4222",
  );
  cfg.rules.clear();
  cfg.rules.insert(first.0.to_string(), nats_rule(first.0, first.1, first.2));
  cfg.rules.insert(second.0.to_string(), nats_rule(second.0, second.1, second.2));
  cfg
}

#[test]
fn nats_grants_sharing_a_fake_endpoint_reject_a_different_upstream() {
  let cfg = two_nats(
    ("nats_a", "nats://agent:one@nats.internal:4222", "tls://agent:one@nats.one:4222"),
    ("nats_b", "nats://other:two@nats.internal:4222", "tls://other:two@nats.two:4222"),
  );
  let err = resolve(&cfg).expect_err("different upstreams on one fake endpoint");
  let text = err.to_string();
  assert!(text.contains("nats.internal") && text.contains("4222"), "{err}");
}

#[test]
fn nats_grants_sharing_a_fake_endpoint_reject_a_different_guest_tls() {
  let mut cfg = two_nats(
    (
      "nats_a",
      "nats://agent:one@nats.internal:4222",
      "tls://agent:one@nats.upstream:4222",
    ),
    ("nats_b", "nats://tok@nats.internal:4222", "tls://tok@nats.upstream:4222"),
  );
  cfg.rules.get_mut("nats_b").expect("rule").tls.insert(
    "nats_b".to_string(),
    HostTlsCfg {
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls_mode: GuestTlsMode::Mtls,
      guest_cert: None,
      guest_key: None,
    },
  );
  let err = resolve(&cfg).expect_err("different guest tls on one fake endpoint");
  assert!(err.to_string().contains("nats.internal"), "{err}");
}

#[test]
fn nats_grants_sharing_a_fake_endpoint_keep_distinct_auth() {
  let cfg = two_nats(
    (
      "nats_a",
      "nats://agent:one@nats.internal:4222",
      "tls://agent:one@nats.upstream:4222",
    ),
    ("nats_b", "nats://tok@nats.internal:4222", "tls://tok@nats.upstream:4222"),
  );
  let resolved = resolve(&cfg).expect("same upstream and guest tls");
  assert_eq!(resolved.grants.len(), 2);
}

#[test]
fn nats_shared_endpoint_compares_ca_file_bytes() {
  let dir = tempfile::tempdir().unwrap();
  let left = dir.path().join("copied.ca");
  let right = dir.path().join("demo.ca");
  let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
  std::fs::write(&left, pem).unwrap();
  std::fs::write(&right, pem).unwrap();
  let real_a = format!("tls://agent:one@nats.upstream:4222?sslrootcert={}", left.display());
  let real_b = format!("tls://tok@nats.upstream:4222?sslrootcert={}", right.display());
  let cfg = two_nats(
    ("nats_a", "nats://agent:one@nats.internal:4222", &real_a),
    ("nats_b", "nats://tok@nats.internal:4222", &real_b),
  );
  let resolved = resolve(&cfg).expect("the same CA bytes are one trust anchor");
  assert_eq!(resolved.grants.len(), 2);

  std::fs::write(&right, b"-----BEGIN CERTIFICATE-----\nOTHER\n-----END CERTIFICATE-----\n").unwrap();
  let cfg = two_nats(
    ("nats_a", "nats://agent:one@nats.internal:4222", &real_a),
    ("nats_b", "nats://tok@nats.internal:4222", &real_b),
  );
  let err = resolve(&cfg).expect_err("different CA bytes");
  assert!(err.to_string().contains("nats.internal"), "{err}");

  let missing = dir.path().join("missing.ca");
  let real_missing = format!("tls://tok@nats.upstream:4222?sslrootcert={}", missing.display());
  let cfg = two_nats(
    ("nats_a", "nats://agent:one@nats.internal:4222", &real_a),
    ("nats_b", "nats://tok@nats.internal:4222", &real_missing),
  );
  let err = resolve(&cfg).expect_err("an unreadable CA is not the other file");
  assert!(err.to_string().contains("nats.internal"), "{err}");
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
fn amqp_grant_answers_for_amqp_schemes() {
  let grant = redis_grant_like(
    "amqp://agent:fake@mq.internal",                          // betterleaks:allow
    "amqps://agent:real@mq.internal:5671?sslrootcert=system", // betterleaks:allow
  );
  assert!(grant.matches(Scheme::Amqp, "mq.internal", 5672));
  assert!(grant.matches(Scheme::Amqps, "MQ.INTERNAL", 5672));
  assert!(!grant.matches(Scheme::Tcp, "mq.internal", 5672));
  assert!(!grant.matches(Scheme::Amqp, "mq.internal", 5671));
  assert!(grant.amqp(None, 5672).is_some());
  assert!(grant.amqp(Some("other.internal"), 5672).is_none());
  assert!(grant.ldap(Some("mq.internal"), 5672).is_none());
  let credential = grant.credential().expect("an amqp grant swaps a credential");
  assert_eq!(credential.fake, "fake");
  assert_eq!(credential.value.expose_secret(), "real");
  let scope = grant.amqp(Some("mq.internal"), 5672).expect("scope");
  assert_eq!(scope.root_cert, Some(RootCert::System));
  assert!(scope.is_upstream_tls);
  assert!(!scope.is_downstream_tls);
}

#[test]
fn amqp_schemes_are_not_endpoint_grants() {
  let err = "amqp://mq.internal:5672".parse::<EndpointScope>().unwrap_err();
  assert!(err.contains("the connection string is the grant"), "{err}");
  "amqps://mq.internal:5671".parse::<EndpointScope>().unwrap_err();
}

#[test]
fn amqp_rule_table_states_only_the_guest_leg() {
  let mut cfg = cfg_with_db(
    "amqps://agent:fake@mq.internal",                     // betterleaks:allow
    "amqps://agent:real@mq.internal?sslrootcert=/ca.pem", // betterleaks:allow
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
  e.client_cert = Some(PathBuf::from("/c.pem"));
  e.client_key = Some(PathBuf::from("/c.key"));
  tls.insert("DATABASE_URL".to_string(), e);
  cfg.rules.get_mut("t").unwrap().tls = tls;
  let err = resolve(&cfg).unwrap_err().to_string();
  assert!(err.contains("amqp states the upstream identity"), "{err}");
  let mut tls = BTreeMap::new();
  let mut e = entry();
  e.root_cert = Some(PathBuf::from("/ca.pem"));
  tls.insert("DATABASE_URL".to_string(), e);
  cfg.rules.get_mut("t").unwrap().tls = tls;
  let err = resolve(&cfg).unwrap_err().to_string();
  assert!(err.contains("amqp states upstream trust"), "{err}");
  let mut tls = BTreeMap::new();
  tls.insert("DATABASE_URL".to_string(), entry());
  cfg.rules.get_mut("t").unwrap().tls = tls;
  let resolved = resolve(&cfg).unwrap();
  let Some(Grant::Amqp { scope, .. }) = resolved.grants.first() else {
    panic!("an amqp rule");
  };
  assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
  assert!(scope.is_downstream_tls);
  assert_eq!(scope.root_cert, Some(RootCert::Path(PathBuf::from("/ca.pem"))));
}

#[test]
fn amqp_mtls_on_a_cleartext_fake_loads() {
  let mut cfg = cfg_with_db(
    "amqp://agent:arkham_fake_amqp_pass@mq.internal",        // betterleaks:allow
    "amqps://svc:arkham_real_amqp_pass_01@mq.internal:5671", // betterleaks:allow
  );
  let mut tls = BTreeMap::new();
  tls.insert(
    "DATABASE_URL".to_string(),
    crate::config::HostTlsCfg {
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls_mode: GuestTlsMode::Mtls,
      guest_cert: None,
      guest_key: None,
    },
  );
  cfg.rules.get_mut("t").unwrap().tls = tls;
  let resolved = resolve(&cfg).expect("mtls on a cleartext amqp fake loads");
  let Some(Grant::Amqp { scope, .. }) = resolved.grants.first() else {
    panic!("an amqp rule");
  };
  assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
  assert!(!scope.is_downstream_tls);
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
fn smtp_mtls_on_a_cleartext_fake_loads() {
  assert_mtls_loads(
    "smtp://agent:arkham_fake_smtp_pass@mail.internal:587",     // betterleaks:allow
    "smtps://agent:arkham_real_smtp_pass_01@mail.internal:465", // betterleaks:allow
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
      generated: false,
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
      generated: false,
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
  let encoded = postgres_scope(
    "postgres://app:fake%3Apass@db.internal:5432/main", // betterleaks:allow
    "postgres://app:real%3Apass@db.internal:5432/main", // betterleaks:allow
  );
  assert_eq!(encoded.downstream.password.expose_secret(), "fake:pass");
  assert_eq!(encoded.upstream.password.expose_secret(), "real:pass");
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
      generated: false,
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
