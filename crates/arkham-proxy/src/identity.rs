//! What the config says a destination is, and the one place a strategy is
//! picked.
//!
//! The grant scopes covering a destination name the protocol, so the arm that
//! serves a connection comes from the config and never from the shape of its
//! bytes. Identity, the hostname those scopes are matched against, is read
//! from the opening bytes of the protocol the config named, because a
//! transparent capture destination is an IP. `Expect::serve` is the only
//! `match` on the picked protocol in the crate; every arm lives in its
//! vertical under `transports/`.

use arkham_config::grants::{
  AmqpScope, Grant, LdapScope, NatsScope, PostgresScope, RedisScope, ResolvedConfig, Scheme, SmtpScope, SshScope,
};
use rama::tls::client::{ClientHello, ClientHelloHandshakePrefix, parse_client_hello_handshake_prefix};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

use std::time::Duration;

use crate::Error;
use crate::ProxyState;
use crate::transports::ServeStream;
use crate::transports::Transport;
use crate::transports::http::MAX_HEAD;
use crate::transports::tcp::splice;

/// Hard cap for a single `ClientHello` (RFC 8446 §5.1: a record payload is at
/// most 2^14 bytes, plus the 5-byte record header).
const MAX_HELLO: usize = 16 * 1024 + 5;

/// Connection-gating context for one candidate stream: targets, identity
/// material, and the replay buffer. A struct, not eight params.
#[derive(Clone, Copy)]
pub(crate) struct CandidateParams<'a> {
  /// Shared proxy state (mint guard, plugins, dial mark).
  pub(crate) state: &'a ProxyState,
  /// Live config snapshot.
  pub(crate) snapshot: &'a ResolvedConfig,
  /// Upstream TCP target.
  pub(crate) dial_host: &'a str,
  /// Upstream port.
  pub(crate) port: u16,
  /// Identity the ingress already knows, or None when only the capture
  /// destination is known and the identity has to be read from the protocol.
  pub(crate) host: Option<&'a str>,
  /// Hostname for raw `tcp://` scope matching.
  pub(crate) raw_host: &'a str,
  /// Pipelined bytes read past the ingress head.
  pub(crate) initial: &'a [u8],
}

/// How a destination is served, from the grant scopes that cover it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Expect<'a> {
  /// An `https://` scope: terminate TLS, then read the h1/h2 framing.
  Tls,
  /// An `http://` scope: a plaintext request head.
  Plain,
  /// A `tcp://` scope: opaque bytes, equal-length substitution, nothing read.
  Raw,
  /// A `postgres://` scope: pgwire framing, over whatever transport the entry
  /// states for the far side and the guest asks for on this side.
  Postgres(&'a PostgresScope),
  /// A `redis://` or `rediss://` scope: RESP framing, each string stating
  /// its own leg's transport.
  Redis(&'a RedisScope),
  /// An `smtp://` or `smtps://` scope: SMTP framing. Implicit TLS settles
  /// before the dialogue; `STARTTLS` upgrades the same sockets mid-session.
  Smtp(&'a SmtpScope),
  /// An `ldap://` or `ldaps://` scope: BER LDAP, each string stating how
  /// its leg opens. A cleartext leg may upgrade with `StartTLS`.
  Ldap(&'a LdapScope),
  /// A `nats://` or `tls://` scope: NATS framing after a cleartext INFO, or
  /// TLS first when the real string asks for `handshake_first`.
  Nats(&'a NatsScope),
  Amqp(&'a AmqpScope),
  /// An `ssh://` scope: the guest leg terminates here against a decoy key.
  Ssh(&'a SshScope),
  Splice,
}

/// Resolve the arm for a destination. `host` is the identity when the ingress
/// already knows it (a CONNECT authority), and None when only the captured
/// port is known (transparent capture), where identity is read afterwards and
/// the port alone shortlists the scopes.
///
/// One port carrying several protocol families is ambiguous without reading
/// bytes. The order below is the tie-break, and an arm whose framing does not
/// arrive closes rather than guessing a different one.
/// Unit arms compare by kind; a Postgres arm equals only itself — its scope
/// carries secrets, so there is no value comparison to build on.
impl PartialEq for Expect<'_> {
  fn eq(&self, other: &Self) -> bool {
    match (self, other) {
      (Expect::Postgres(a), Expect::Postgres(b)) => std::ptr::eq(*a, *b),
      (Expect::Redis(a), Expect::Redis(b)) => std::ptr::eq(*a, *b),
      (Expect::Smtp(a), Expect::Smtp(b)) => std::ptr::eq(*a, *b),
      (Expect::Ldap(a), Expect::Ldap(b)) => std::ptr::eq(*a, *b),
      (Expect::Nats(a), Expect::Nats(b)) => std::ptr::eq(*a, *b),
      (Expect::Amqp(a), Expect::Amqp(b)) => std::ptr::eq(*a, *b),
      (Expect::Ssh(a), Expect::Ssh(b)) => std::ptr::eq(*a, *b),
      (Expect::Tls, Expect::Tls) | (Expect::Plain, Expect::Plain) | (Expect::Raw, Expect::Raw) | (Expect::Splice, Expect::Splice) => true,
      _ => false,
    }
  }
}

impl Eq for Expect<'_> {}

#[must_use]
pub(crate) fn expect<'a>(grants: &'a [Grant], host: Option<&str>, port: u16) -> Expect<'a> {
  if let Some(scope) = grants.iter().find_map(|grant| grant.postgres(host, port)) {
    return Expect::Postgres(scope);
  }
  if let Some(scope) = grants.iter().find_map(|grant| grant.redis(host, port)) {
    return Expect::Redis(scope);
  }
  if let Some(scope) = grants.iter().find_map(|grant| grant.smtp(host, port)) {
    return Expect::Smtp(scope);
  }
  if let Some(scope) = grants.iter().find_map(|grant| grant.ldap(host, port)) {
    return Expect::Ldap(scope);
  }
  if let Some(scope) = grants.iter().find_map(|grant| grant.nats(host, port)) {
    return Expect::Nats(scope);
  }
  if let Some(scope) = grants.iter().find_map(|grant| grant.amqp(host, port)) {
    return Expect::Amqp(scope);
  }
  if let Some(scope) = grants.iter().find_map(|grant| grant.ssh(host, port)) {
    return Expect::Ssh(scope);
  }
  for (scheme, arm) in [
    (Scheme::Https, Expect::Tls),
    (Scheme::Http, Expect::Plain),
    (Scheme::Tcp, Expect::Raw),
  ] {
    if grants.iter().any(|grant| grant.endpoint(scheme, host, port).is_some()) {
      return arm;
    }
  }
  Expect::Splice
}

impl<'a> Expect<'a> {
  /// The one pick: route one candidate stream to the transport retained
  /// for the protocol the grants stated. The only `match` on `Expect` in
  /// the crate.
  ///
  /// # Errors
  ///
  /// Returns an error when a leg cannot be settled; malformed guest
  /// traffic closes quietly instead.
  pub(crate) async fn serve<G>(self, guest: G, params: CandidateParams<'a>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let state = params.state;
    let CandidateParams {
      dial_host, port, initial, ..
    } = params;
    match self {
      // No scope covers this destination: copy the bytes unchanged.
      Expect::Splice => splice(guest, dial_host, port, state.fwmark, initial).await,
      // Opaque bytes: nothing is read, the machines scan as the stream arrives.
      Expect::Raw => state.tcp.serve(ServeStream { guest, params, scope: &() }).await,
      // Declared HTTP: the `Host` head names the peer.
      Expect::Plain => state.http.serve(ServeStream { guest, params, scope: &() }).await,
      // Declared TLS: the ClientHello names the peer.
      Expect::Tls => state.https.serve(ServeStream { guest, params, scope: &() }).await,
      // Declared Postgres: each leg's transport settles in the vertical.
      Expect::Postgres(scope) => state.postgres.serve(ServeStream { guest, params, scope }).await,
      // Declared Redis: each connection string states its own leg's transport.
      Expect::Redis(scope) => state.redis.serve(ServeStream { guest, params, scope }).await,
      // Declared SMTP: implicit TLS settles first; STARTTLS upgrades later.
      Expect::Smtp(scope) => state.smtp.serve(ServeStream { guest, params, scope }).await,
      // Declared LDAP: cleartext may StartTLS; LDAPS settles both legs first.
      Expect::Ldap(scope) => state.ldap.serve(ServeStream { guest, params, scope }).await,
      // Declared NATS: INFO stays cleartext unless the real string asks for TLS first.
      Expect::Nats(scope) => state.nats.serve(ServeStream { guest, params, scope }).await,
      Expect::Amqp(scope) => state.amqp.serve(ServeStream { guest, params, scope }).await,
      // Declared ssh: the guest leg terminates here against a decoy key.
      Expect::Ssh(scope) => state.ssh.serve(ServeStream { guest, params, scope }).await,
    }
  }
}

/// A complete TLS `ClientHello`, with the SNI when it carries one.
pub(crate) enum Hello {
  /// Complete hello naming its host.
  Named {
    /// Every byte read so far, replayed into the relay.
    buf: Vec<u8>,
    /// The server name the hello names.
    sni: String,
    /// The parsed hello, handed to the TLS terminator.
    hello: ClientHello,
  },
  /// A hello that yields no SNI. The ingress authority, when there is one, is
  /// the only identity available.
  Unnamed {
    /// Every byte read so far, replayed into the relay.
    buf: Vec<u8>,
    /// The parsed hello, when the bytes completed one. Callers mirror it
    /// instead of re-parsing the buffer they were just handed.
    hello: Option<ClientHello>,
  },
}

/// An SNI-less TLS opening: the buffer plus its parsed hello when the bytes
/// completed one. `None` when the bytes never opened as a TLS record.
fn unnamed(buf: Vec<u8>) -> Option<Hello> {
  let hello = hello_complete(&buf);
  buf
    .first()
    .is_some_and(|byte| *byte == 0x16)
    .then_some(Hello::Unnamed { buf, hello })
}

/// Read until a `ClientHello` completes. None when the bytes are not TLS, or
/// the hello never completes inside the pre-auth budget and the size cap.
///
/// # Errors
///
/// Returns an error when the guest stream fails to read.
pub(crate) async fn read_client_hello<G: AsyncRead + Unpin>(
  guest: &mut G,
  initial: &[u8],
  budget: Option<Duration>,
) -> Result<Option<Hello>, Error> {
  let mut buf = initial.to_vec();
  let mut chunk = [0u8; 4096];
  // Total pre-auth budget: per-read timeouts re-arm, so a dripping client
  // could otherwise hold this task indefinitely one byte at a time.
  // `None` is the relay's own read: no added deadline.
  let deadline = budget.map(|budget| tokio::time::Instant::now() + budget);
  loop {
    // SNI first: a hello completing exactly at the size cutoff still counts.
    if let Some((sni, hello)) = hello_sni(&buf) {
      return Ok(Some(Hello::Named { buf, sni, hello }));
    }
    // A complete hello without SNI is final: IP-literal clients never send
    // one, so waiting out the budget would stall every such handshake.
    if hello_complete(&buf).is_some() {
      return Ok(unnamed(buf));
    }
    let over_cap = buf.len() > MAX_HELLO;
    let remaining = deadline.map(|deadline| deadline.saturating_duration_since(tokio::time::Instant::now()));
    if over_cap || remaining.is_some_and(|left| left.is_zero()) {
      // Bytes that opened as a TLS record but never completed: no SNI to
      // name the peer with, so the caller falls back to its authority.
      return Ok(unnamed(buf));
    }
    let read = match remaining {
      Some(left) => match tokio::time::timeout(left, guest.read(&mut chunk)).await {
        Ok(read) => read,
        Err(_elapsed) => return Ok(unnamed(buf)),
      },
      None => guest.read(&mut chunk).await,
    };
    let n = read?;
    if n == 0 {
      return Ok(unnamed(buf));
    }
    buf.extend_from_slice(&chunk[..n]);
    if buf.first() != Some(&0x16) {
      // Not a TLS record, so no ClientHello is coming.
      return Ok(None);
    }
  }
}

/// Read until the HTTP request head completes, and take the identity from its
/// `Host` field. None when no complete head arrives inside the pre-auth budget
/// and the head cap.
///
/// # Errors
///
/// Returns an error when the guest stream fails to read.
pub(crate) async fn read_http_head<G: AsyncRead + Unpin>(
  guest: &mut G,
  initial: &[u8],
  budget: Duration,
  default_port: u16,
) -> Result<Option<(Vec<u8>, String, u16)>, Error> {
  let mut buf = initial.to_vec();
  let mut chunk = [0u8; 4096];
  let deadline = tokio::time::Instant::now() + budget;
  loop {
    if let Some((host, port)) = http_head_host(&buf, default_port) {
      return Ok(Some((buf, host, port)));
    }
    let over_cap = buf.len() > MAX_HEAD;
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if over_cap || remaining.is_zero() {
      return Ok(None);
    }
    let read = tokio::time::timeout(remaining, guest.read(&mut chunk)).await;
    let Ok(n) = read else { return Ok(None) };
    let n = n?;
    if n == 0 {
      return Ok(None);
    }
    buf.extend_from_slice(&chunk[..n]);
  }
}

/// A complete `ClientHello` in `buf`, via rama's parser. None while the
/// hello is still incomplete or invalid. Carries no SNI verdict: an
/// IP-literal client sends a complete hello with none, and its ALPN and
/// fingerprint are still worth mirroring upstream.
pub(crate) fn hello_complete(buf: &[u8]) -> Option<ClientHello> {
  match parse_client_hello_handshake_prefix(buf) {
    ClientHelloHandshakePrefix::Complete(hello) => Some(hello),
    _ => None,
  }
}

/// SNI plus hello of a complete `ClientHello` in `buf`, via rama's parser.
/// None while the hello is still incomplete, invalid, or carries no SNI, so
/// the caller keeps accumulating.
pub(crate) fn hello_sni(buf: &[u8]) -> Option<(String, ClientHello)> {
  let hello = hello_complete(buf)?;
  let sni = hello.ext_server_name().map(ToString::to_string)?;
  Some((sni, hello))
}

/// Host header of a complete HTTP request head, port-defaulted to the dialed
/// port. None when the buffer is not a complete request head or the header is
/// missing or unparseable.
pub(crate) fn http_head_host(buf: &[u8], default_port: u16) -> Option<(String, u16)> {
  let mut headers = [httparse::EMPTY_HEADER; 32];
  let mut req = httparse::Request::new(&mut headers);
  if req.parse(buf).ok()? != httparse::Status::Complete(head_len(buf)?) {
    return None;
  }
  let host = req.headers.iter().find(|header| header.name.eq_ignore_ascii_case("host"))?;
  let value = std::str::from_utf8(host.value).ok()?;
  super::parse_authority(value, Some(default_port))
}

/// Offset just past the head boundary, when the buffer holds one.
fn head_len(head: &[u8]) -> Option<usize> {
  head.windows(4).position(|w| w == b"\r\n\r\n").map(|pos| pos + 4)
}

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::grants::{Credential, GuestTlsMode, HostPat, PostgresLeg, SslMode, SslNegotiation};
  use secrecy::SecretString;
  use std::time::Instant;

  fn token_grant(entries: &[&str]) -> Vec<Grant> {
    vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: "fake".into(),
        value: SecretString::from("value"),
      },
      allow: entries.iter().map(|entry| entry.parse().unwrap()).collect(),
      pattern: None,
      oauth2: None,
    }]
  }

  fn postgres_grant(port: u16, ssl: SslMode) -> Vec<Grant> {
    vec![Grant::Postgres {
      credential: Credential {
        label: "pg".into(),
        fake: "fake".into(),
        value: SecretString::from("value"),
      },
      scope: Box::new(PostgresScope {
        downstream: PostgresLeg {
          host: "db.internal".to_string(),
          port,
          user: None,
          password: SecretString::from("fake"),
          database: None,
        },
        upstream: PostgresLeg {
          host: "db.internal".to_string(),
          port,
          user: None,
          password: SecretString::from("value"),
          database: None,
        },
        ssl,
        negotiation: SslNegotiation::Postgres,
        root_cert: None,
        client_cert: None,
        client_key: None,
        guest_tls: GuestTlsMode::default(),
      }),
    }]
  }

  #[test]
  fn the_scope_scheme_names_the_arm() {
    // A tcp:// scope on a TLS port is not a TLS scope, and no byte decides
    // this: the config does.
    let grants = token_grant(&["tcp://api.github.com:443"]);
    assert_eq!(expect(&grants, Some("api.github.com"), 443), Expect::Raw);
    let grants = token_grant(&["https://api.github.com"]);
    assert_eq!(expect(&grants, Some("api.github.com"), 443), Expect::Tls);
    let grants = token_grant(&["http://api.github.com"]);
    assert_eq!(expect(&grants, Some("api.github.com"), 80), Expect::Plain);
  }

  #[test]
  fn an_uncovered_destination_splices_and_a_bare_port_shortlists() {
    let grants = token_grant(&["https://api.github.com"]);
    assert_eq!(expect(&grants, Some("elsewhere.example"), 443), Expect::Splice);
    // Transparent capture knows the port before it knows the host, so the arm
    // resolves with None and the identity is read afterwards.
    assert_eq!(expect(&grants, None, 443), Expect::Tls);
    assert_eq!(expect(&grants, None, 8443), Expect::Splice);
  }

  #[test]
  fn a_database_scope_carries_its_sslmode() {
    let grants = postgres_grant(5432, SslMode::Require);
    let Expect::Postgres(scope) = expect(&grants, Some("db.internal"), 5432) else {
      panic!("a database scope resolves to the postgres arm")
    };
    assert_eq!(scope.ssl, SslMode::Require);
    // Port alone is enough on the transparent path: no startup bytes are
    // inspected to reach this answer, and the entry that comes back is the
    // same one, so its sslmode and trust anchor travel with it.
    assert!(matches!(expect(&grants, None, 5432), Expect::Postgres(other) if std::ptr::eq(other, scope)));
  }

  #[test]
  fn an_ssh_grant_routes_to_the_ssh_arm_and_only_its_port() {
    // An ssh grant must reach the ssh arm by host and port alone
    // (transparent capture); nothing else may reach it.
    let grants = vec![Grant::Ssh {
      allow: vec![SshScope {
        host: HostPat::Exact("git.example".to_string()),
        port: 22,
        identity: std::path::PathBuf::from("/arkham/grants/rules.d/t.identity"),
        guest_key: std::path::PathBuf::from("/arkham/grants/rules.d/t.guest_key"),
      }],
    }];
    let Expect::Ssh(scope) = expect(&grants, Some("git.example"), 22) else {
      panic!("an ssh grant resolves to the ssh arm")
    };
    assert_eq!(scope.port, 22);
    assert!(
      matches!(expect(&grants, None, 22), Expect::Ssh(other) if std::ptr::eq(other, scope)),
      "port alone routes"
    );
    assert_eq!(expect(&grants, Some("git.example"), 2222), Expect::Splice, "another port does not");
    assert_eq!(
      expect(&grants, Some("elsewhere.example"), 22),
      Expect::Splice,
      "another host does not"
    );
  }
  #[test]
  fn an_smtp_grant_routes_to_the_smtp_arm_and_only_its_port() {
    let scope = SmtpScope::from_strings(
      "smtp://agent:fake@mail.internal:587",                   // betterleaks:allow
      "smtp://agent:real@mail.internal:587?starttls=required", // betterleaks:allow
    )
    .unwrap();
    let grants = vec![Grant::Smtp {
      credential: Credential {
        label: "smtp".into(),
        fake: "fake".into(),
        value: SecretString::from("real"),
      },
      scope: Box::new(scope),
    }];
    let Expect::Smtp(found) = expect(&grants, Some("mail.internal"), 587) else {
      panic!("an smtp grant resolves to the smtp arm")
    };
    assert!(found.starttls_required);
    assert!(
      matches!(expect(&grants, None, 587), Expect::Smtp(other) if std::ptr::eq(other, found)),
      "port alone routes"
    );
    assert_eq!(expect(&grants, Some("mail.internal"), 25), Expect::Splice, "another port does not");
  }

  #[test]
  fn a_nats_grant_routes_to_the_nats_arm_and_only_its_port() {
    let grants = crate::transports::nats::fixtures::nats_grants(
      "nats://agent:fake@nats.internal:4222", // betterleaks:allow
      "tls://agent:real@nats.upstream:4222",  // betterleaks:allow
    );
    let Expect::Nats(found) = expect(&grants, Some("nats.internal"), 4222) else {
      panic!("a nats grant resolves to the nats arm")
    };
    assert_eq!(found.upstream.host, "nats.upstream");
    assert!(
      matches!(expect(&grants, None, 4222), Expect::Nats(other) if std::ptr::eq(other, found)),
      "port alone routes"
    );
    assert_eq!(
      expect(&grants, Some("nats.internal"), 4223),
      Expect::Splice,
      "another port does not"
    );
    assert_eq!(
      expect(&grants, Some("nats.upstream"), 4222),
      Expect::Splice,
      "the real host is not a guest destination"
    );
  }

  #[tokio::test]
  async fn a_complete_hello_without_sni_returns_unnamed_at_once() {
    // Minimal TLS 1.3 ClientHello with no SNI extension, as an IP-literal
    // client (kubectl against 127.0.0.1) sends: holding out for an SNI
    // that never comes burns the whole pre-auth budget and stalls the
    // handshake past the client's own timeout.
    let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x36, 0x01, 0x00, 0x00, 0x32, 0x03, 0x03];
    hello.extend_from_slice(&[0xAA; 32]);
    hello.extend_from_slice(&[
      0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x07, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
    ]);
    let start = Instant::now();
    let read = read_client_hello(&mut &*hello, &[], Some(Duration::from_secs(30))).await.unwrap();
    assert!(matches!(read, Some(Hello::Unnamed { .. })), "an SNI-less hello resolves unnamed");
    assert!(start.elapsed() < Duration::from_secs(5), "no budget burn: {:?}", start.elapsed());
  }
}
