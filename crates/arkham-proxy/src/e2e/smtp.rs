//! SMTP AUTH through the MITM. The peer is scripted so the test can read
//! the AUTH line the proxy forwarded.

use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use super::fixture::*;
use base64::Engine as _;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{AsyncSmtpConnection, Certificate, CertificateStore, Identity, TlsParameters};
use lettre::transport::smtp::commands::{Expn, Help, Starttls, Vrfy};
use lettre::transport::smtp::extension::ClientId;
use rama::crypto::pem::PemEncode as _;
use secrecy::ExposeSecret as _;
use tokio::io::ReadBuf;

const FAKE: &str = "fake-smtp-pass"; // betterleaks:allow
const VALUE: &str = "real-smtp-pass"; // betterleaks:allow
const USER: &str = "agent@demo.test";

fn smtp_grant(fake: &str, real: &str) -> Grant {
  let scope = arkham_config::grants::SmtpScope::from_strings(fake, real).unwrap();
  Grant::Smtp {
    credential: Credential {
      label: "smtp".into(),
      fake: scope.downstream.password.expose_secret().to_string(),
      value: scope.upstream.password.clone(),
    },
    scope: Box::new(scope),
  }
}

fn plain_initial(user: &str, pass: &str) -> String {
  base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"))
}

fn hello() -> ClientId {
  ClientId::Domain("client".to_owned())
}

fn decoy_credentials() -> Credentials {
  Credentials::new(USER.to_owned(), FAKE.to_owned())
}

fn tls_parameters(domain: &str, ca_pem: &[u8], identity: Option<Identity>, skip_server_name: bool) -> TlsParameters {
  let mut builder = TlsParameters::builder(domain.to_owned())
    .certificate_store(CertificateStore::None)
    .add_root_certificate(Certificate::from_pem(ca_pem).unwrap());
  if skip_server_name {
    builder = builder.dangerous_accept_invalid_hostnames(true);
  }
  if let Some(identity) = identity {
    builder = builder.identify_with(identity);
  }
  builder.build().unwrap()
}

fn tls_trusting(ca_pem: &[u8], identity: Option<Identity>) -> TlsParameters {
  tls_parameters("localhost", ca_pem, identity, false)
}

/// An IP literal becomes `ServerName::IpAddress`. rustls sends the SNI
/// extension only for a DNS name, so the `ClientHello` has none.
fn tls_without_sni(ca_pem: &[u8], identity: Option<Identity>) -> TlsParameters {
  tls_parameters("127.0.0.1", ca_pem, identity, true)
}

fn assert_leaf_names_localhost(der: &[u8]) {
  let cert = rustls::pki_types::CertificateDer::from(der.to_vec());
  let parsed = rustls::server::ParsedCertificate::try_from(&cert).unwrap();
  let name = ServerName::try_from("localhost".to_owned()).unwrap();
  rustls::client::verify_server_name(&parsed, &name).unwrap();
}

/// `Identity::from_pem` on the rustls backend keeps the certificate argument
/// as raw bytes and parses only the key as PEM. Callers pass the leaf DER.
fn client_identity(ca: &CertAuthority) -> Identity {
  let (chain, key) = arkham_pki::ca::generate_client_pair(ca, "guest").unwrap();
  let leaf = chain.first().unwrap();
  Identity::from_pem(leaf.as_ref(), key.to_pem().as_bytes()).unwrap()
}

async fn lettre_session(stream: TcpStream) -> AsyncSmtpConnection {
  AsyncSmtpConnection::connect_with_transport(Box::new(stream), &hello())
    .await
    .unwrap()
}

async fn read_reply<S>(stream: &mut S) -> String
where
  S: AsyncRead + Unpin,
{
  let mut all = Vec::new();
  let mut buf = [0u8; 1];
  let mut line = Vec::new();
  loop {
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 1, "smtp reply ended early");
    line.push(buf[0]);
    if buf[0] != b'\n' {
      continue;
    }
    let finished = line.get(3) != Some(&b'-');
    all.extend_from_slice(&line);
    line.clear();
    if finished {
      break;
    }
  }
  String::from_utf8(all).unwrap()
}

async fn write_cmd<S>(stream: &mut S, line: &str)
where
  S: AsyncWrite + Unpin,
{
  stream.write_all(line.as_bytes()).await.unwrap();
  stream.flush().await.unwrap();
}

/// One scripted submission server. `starttls` upgrades after the
/// command and records every AUTH line, cleartext then TLS.
async fn serve_submission<S>(mut conn: S, acceptor: Option<TlsAcceptor>, seen: Arc<Mutex<Vec<String>>>)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  write_cmd(&mut conn, "220 mail.demo.test ESMTP\r\n").await;
  loop {
    let line = read_reply(&mut conn).await;
    if line.to_ascii_uppercase().starts_with("EHLO") || line.to_ascii_uppercase().starts_with("HELO") {
      write_cmd(&mut conn, "250-mail.demo.test\r\n250 AUTH PLAIN LOGIN\r\n").await;
      continue;
    }
    if line.to_ascii_uppercase().starts_with("STARTTLS") {
      write_cmd(&mut conn, "220 2.0.0 Ready to start TLS\r\n").await;
      let Some(acceptor) = acceptor else {
        return;
      };
      let tls = acceptor.accept(conn).await.unwrap();
      serve_authed(tls, seen).await;
      return;
    }
    if line.to_ascii_uppercase().starts_with("AUTH ") {
      seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(line);
      write_cmd(&mut conn, "235 2.7.0 Authentication successful\r\n").await;
      return;
    }
    write_cmd(&mut conn, "502 5.5.2 unimplemented\r\n").await;
  }
}

async fn serve_authed<S>(mut conn: S, seen: Arc<Mutex<Vec<String>>>)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  loop {
    let line = read_reply(&mut conn).await;
    if line.to_ascii_uppercase().starts_with("EHLO") || line.to_ascii_uppercase().starts_with("HELO") {
      write_cmd(&mut conn, "250-mail.demo.test\r\n250 AUTH PLAIN LOGIN\r\n").await;
      continue;
    }
    if line.to_ascii_uppercase().starts_with("AUTH ") {
      seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(line);
      // Before STARTTLS the proxy must have forwarded the decoy, and the
      // server refuses it. After the upgrade the real password is the
      // only one that authenticates. The caller decides which reply by
      // how many AUTH lines it has already seen: the first is the
      // pre-upgrade refusal when this function is the post-upgrade half.
      write_cmd(&mut conn, "235 2.7.0 Authentication successful\r\n").await;
      return;
    }
    write_cmd(&mut conn, "502 5.5.2 unimplemented\r\n").await;
  }
}

/// Submission dialogue that refuses AUTH until STARTTLS, recording both
/// AUTH lines so the test can see the decoy and then the real password.
/// `refuse_once` answers the first STARTTLS with `454` and the next with
/// `220`. `HELP`, `VRFY`, and `EXPN` stay in the cleartext loop.
async fn serve_starttls<S>(mut conn: S, acceptor: TlsAcceptor, seen: Arc<Mutex<Vec<String>>>, mut refuse_once: bool)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  write_cmd(&mut conn, "220 mail.demo.test ESMTP\r\n").await;
  loop {
    let line = read_reply(&mut conn).await;
    let upper = line.to_ascii_uppercase();
    if upper.starts_with("EHLO") || upper.starts_with("HELO") {
      write_cmd(&mut conn, "250-mail.demo.test\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n").await;
      continue;
    }
    if upper.starts_with("HELP") || upper.starts_with("VRFY") || upper.starts_with("EXPN") {
      write_cmd(&mut conn, "250 2.0.0 ok\r\n").await;
      continue;
    }
    if upper.starts_with("AUTH ") {
      seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(line);
      write_cmd(&mut conn, "530 5.7.0 Must issue a STARTTLS command first\r\n").await;
      continue;
    }
    if upper.starts_with("STARTTLS") {
      if refuse_once {
        refuse_once = false;
        write_cmd(&mut conn, "454 4.7.0 TLS temporarily unavailable\r\n").await;
        continue;
      }
      write_cmd(&mut conn, "220 2.0.0 Ready to start TLS\r\n").await;
      let tls = acceptor.accept(conn).await.unwrap();
      serve_authed(tls, seen).await;
      return;
    }
    write_cmd(&mut conn, "502 5.5.2 unimplemented\r\n").await;
  }
}

#[tokio::test]
async fn smtp_auth_swaps_before_and_after_starttls() {
  let fx = starttls_fixture().await;
  let stub_seen = Arc::clone(&fx.seen);
  let acceptor = fx.acceptor.clone();
  let stub_task = tokio::spawn(async move {
    let (conn, _) = fx.stub.accept().await.unwrap();
    serve_starttls(conn, acceptor, stub_seen, false).await;
  });

  let stream = tunnel(fx.proxy_addr, fx.stub_port).await;
  let mut conn = lettre_session(stream).await;
  let refused = conn.auth(&[Mechanism::Plain], &decoy_credentials()).await.unwrap_err();
  assert_eq!(refused.status().map(u16::from), Some(530), "{refused}");
  assert!(!refused.to_string().contains(VALUE), "{refused}");
  conn.starttls(tls_trusting(&fx.proxy_ca_pem, None), &hello()).await.unwrap();
  let ok = conn.auth(&[Mechanism::Plain], &decoy_credentials()).await.unwrap();
  assert!(ok.has_code(235), "{ok:?}");
  assert!(!format!("{ok:?}").contains(VALUE), "{ok:?}");
  drop(conn);
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  let recorded = fx.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_eq!(recorded.len(), 2, "{recorded:?}");
  assert!(
    recorded[0].contains(&plain_initial(USER, VALUE)),
    "pre-upgrade AUTH must carry the real password: {}",
    recorded[0]
  );
  assert!(
    !recorded[0].contains(&plain_initial(USER, FAKE)),
    "pre-upgrade AUTH must not carry the decoy"
  );
  assert!(
    recorded[1].contains(&plain_initial(USER, VALUE)),
    "post-upgrade AUTH must carry the real password: {}",
    recorded[1]
  );
  assert!(!recorded[1].contains(&plain_initial(USER, FAKE)));
  fx.proxy.abort();
}

/// `HELP` is an opening command. `STARTTLS` after it still upgrades, and
/// the AUTH that follows carries the real password.
#[tokio::test]
async fn help_then_starttls_still_swaps_auth() {
  let fx = starttls_fixture().await;
  let stub_seen = Arc::clone(&fx.seen);
  let acceptor = fx.acceptor.clone();
  let stub_task = tokio::spawn(async move {
    let (conn, _) = fx.stub.accept().await.unwrap();
    serve_starttls(conn, acceptor, stub_seen, false).await;
  });
  let mut conn = lettre_session(tunnel(fx.proxy_addr, fx.stub_port).await).await;
  let help = conn.command(Help::new(None)).await.unwrap();
  assert!(help.has_code(250), "{help:?}");
  let vrfy = conn.command(Vrfy::new(USER.to_owned())).await.unwrap();
  assert!(vrfy.has_code(250), "{vrfy:?}");
  let expn = conn.command(Expn::new("list".to_owned())).await.unwrap();
  assert!(expn.has_code(250), "{expn:?}");
  conn.starttls(tls_trusting(&fx.proxy_ca_pem, None), &hello()).await.unwrap();
  let ok = conn.auth(&[Mechanism::Plain], &decoy_credentials()).await.unwrap();
  assert!(ok.has_code(235), "{ok:?}");
  assert!(!format!("{ok:?}").contains(VALUE), "{ok:?}");
  drop(conn);
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  let recorded = fx.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_eq!(recorded.len(), 1, "{recorded:?}");
  assert!(
    recorded[0].contains(&plain_initial(USER, VALUE)),
    "post-upgrade AUTH must carry the real password: {}",
    recorded[0]
  );
  fx.proxy.abort();
}

/// A `454` leaves the session in the opening. The next `STARTTLS` upgrades.
#[tokio::test]
async fn refused_starttls_then_retry_still_swaps_auth() {
  let fx = starttls_fixture().await;
  let stub_seen = Arc::clone(&fx.seen);
  let acceptor = fx.acceptor.clone();
  let stub_task = tokio::spawn(async move {
    let (conn, _) = fx.stub.accept().await.unwrap();
    serve_starttls(conn, acceptor, stub_seen, true).await;
  });
  let mut conn = lettre_session(tunnel(fx.proxy_addr, fx.stub_port).await).await;
  let refused = conn.command(Starttls).await.unwrap_err();
  assert_eq!(refused.status().map(u16::from), Some(454), "{refused}");
  conn.starttls(tls_trusting(&fx.proxy_ca_pem, None), &hello()).await.unwrap();
  let ok = conn.auth(&[Mechanism::Plain], &decoy_credentials()).await.unwrap();
  assert!(ok.has_code(235), "{ok:?}");
  assert!(!format!("{ok:?}").contains(VALUE), "{ok:?}");
  drop(conn);
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  let recorded = fx.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_eq!(recorded.len(), 1, "{recorded:?}");
  assert!(
    recorded[0].contains(&plain_initial(USER, VALUE)),
    "post-upgrade AUTH must carry the real password: {}",
    recorded[0]
  );
  fx.proxy.abort();
}

struct StarttlsFixture {
  proxy_addr: SocketAddr,
  proxy: tokio::task::JoinHandle<()>,
  stub: TcpListener,
  stub_port: u16,
  proxy_ca_pem: Vec<u8>,
  acceptor: TlsAcceptor,
  seen: Arc<Mutex<Vec<String>>>,
  _stub_ca_dir: tempfile::TempDir,
}

async fn starttls_fixture() -> StarttlsFixture {
  install_crypto_provider();
  let proxy_ca = CertAuthority::generate().unwrap();
  let stub_ca = CertAuthority::generate().unwrap();
  let stub_cert = stub_ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let bundle = tempfile::tempdir().unwrap();
  let bundle_path = bundle.path().join("ca.pem");
  std::fs::write(&bundle_path, stub_ca.cert_pem()).unwrap();
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let grants = vec![smtp_grant(
    &format!("smtp://agent%40demo.test:{FAKE}@localhost:{stub_port}"),
    &format!(
      "smtp://agent%40demo.test:{VALUE}@localhost:{stub_port}?starttls=required&sslrootcert={}",
      bundle_path.display()
    ),
  )];
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, &proxy_ca)).await;
  StarttlsFixture {
    proxy_addr,
    proxy,
    stub,
    stub_port,
    proxy_ca_pem: proxy_ca.cert_pem(),
    acceptor,
    seen: Arc::new(Mutex::new(Vec::new())),
    _stub_ca_dir: bundle,
  }
}

async fn tunnel(proxy_addr: SocketAddr, stub_port: u16) -> TcpStream {
  let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
  stream
    .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut head = [0u8; 19];
  stream.read_exact(&mut head).await.unwrap();
  assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
  stream
}

/// Server that advertises CHUNKING and accepts `BDAT` chunks. Records
/// each payload so the test can see the octets pass without a deadlock.
async fn serve_bdat<S>(mut conn: S, seen: Arc<Mutex<Vec<Vec<u8>>>>)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  write_cmd(&mut conn, "220 mail.demo.test ESMTP\r\n").await;
  loop {
    let line = read_reply(&mut conn).await;
    let upper = line.to_ascii_uppercase();
    if upper.starts_with("EHLO") || upper.starts_with("HELO") {
      write_cmd(&mut conn, "250-mail.demo.test\r\n250-PIPELINING\r\n250 CHUNKING\r\n").await;
      continue;
    }
    if upper.starts_with("BDAT") {
      let Some(n) = bdat_size(line.as_bytes()) else {
        write_cmd(&mut conn, "501 5.5.4 missing chunk size\r\n").await;
        continue;
      };
      let mut payload = vec![0u8; n];
      if n > 0 {
        conn.read_exact(&mut payload).await.unwrap();
      }
      seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(payload);
      write_cmd(&mut conn, "250 2.0.0 chunk accepted\r\n").await;
      continue;
    }
    if upper.starts_with("QUIT") {
      write_cmd(&mut conn, "221 bye\r\n").await;
      return;
    }
    write_cmd(&mut conn, "502 5.5.2 unimplemented\r\n").await;
  }
}

fn bdat_size(line: &[u8]) -> Option<usize> {
  let body = line.strip_suffix(b"\r\n").unwrap_or(line);
  let mut parts = body.split(|byte| *byte == b' ' || *byte == b'\t').filter(|part| !part.is_empty());
  let verb = parts.next()?;
  if !verb.eq_ignore_ascii_case(b"BDAT") {
    return None;
  }
  let size = std::str::from_utf8(parts.next()?).ok()?;
  size.parse().ok()
}

/// `BDAT` stays a byte-level guest. lettre submits with `DATA` and never
/// emits a chunked payload, so it cannot show those octets passing unchanged.
#[tokio::test]
async fn bdat_payload_is_passed_exactly() {
  let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
  let fx = mitm_fixture(|port| {
    vec![smtp_grant(
      &format!("smtp://agent%40demo.test:{FAKE}@localhost:{port}"),
      &format!("smtp://agent%40demo.test:{VALUE}@localhost:{port}"),
    )]
  })
  .await;
  let stub_seen = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (conn, _) = fx.stub.accept().await.unwrap();
    serve_bdat(conn, stub_seen).await;
  });

  let result = tokio::time::timeout(Duration::from_secs(5), async {
    let mut stream = TcpStream::connect(fx.proxy_addr).await.unwrap();
    stream
      .write_all(format!("CONNECT localhost:{} HTTP/1.1\r\nHost: localhost\r\n\r\n", fx.stub_port).as_bytes())
      .await
      .unwrap();
    let mut head = [0u8; 19];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    let greeting = read_reply(&mut stream).await;
    assert!(greeting.starts_with("220"), "{greeting}");
    write_cmd(&mut stream, "EHLO client\r\n").await;
    let ehlo = read_reply(&mut stream).await;
    assert_eq!(ehlo, "250-mail.demo.test\r\n250-PIPELINING\r\n250 CHUNKING\r\n");
    write_cmd(&mut stream, "BDAT 5\r\n").await;
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    let accepted = read_reply(&mut stream).await;
    assert!(accepted.starts_with("250"), "{accepted}");
    write_cmd(&mut stream, "BDAT 0 LAST\r\n").await;
    let last = read_reply(&mut stream).await;
    assert!(last.starts_with("250"), "{last}");
    write_cmd(&mut stream, "BDAT\r\n").await;
    let missing = read_reply(&mut stream).await;
    assert!(missing.starts_with("501"), "{missing}");
    write_cmd(&mut stream, "QUIT\r\n").await;
  })
  .await;
  fx.proxy.abort();
  result.expect("BDAT splice timed out");
  let _ = tokio::time::timeout(Duration::from_secs(2), stub_task).await;
  let recorded = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_eq!(recorded, vec![b"hello".to_vec(), Vec::new()]);
}

/// A session that never upgrades stays cleartext upstream and still swaps.
#[tokio::test]
async fn smtp_cleartext_session_swaps_the_password() {
  let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
  let fx = mitm_fixture(|port| {
    vec![smtp_grant(
      &format!("smtp://agent%40demo.test:{FAKE}@localhost:{port}"),
      &format!("smtp://agent%40demo.test:{VALUE}@localhost:{port}"),
    )]
  })
  .await;
  let stub_seen = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (conn, _) = fx.stub.accept().await.unwrap();
    serve_submission(conn, None, stub_seen).await;
  });

  let mut conn = lettre_session(tunnel(fx.proxy_addr, fx.stub_port).await).await;
  let ok = conn.auth(&[Mechanism::Plain], &decoy_credentials()).await.unwrap();
  assert!(ok.has_code(235), "{ok:?}");
  assert!(!format!("{ok:?}").contains(VALUE), "{ok:?}");
  drop(conn);
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  let recorded = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_eq!(recorded.len(), 1, "{recorded:?}");
  assert!(
    recorded[0].contains(&plain_initial(USER, VALUE)),
    "cleartext AUTH must carry the real password: {}",
    recorded[0]
  );
  assert!(
    !recorded[0].contains(&plain_initial(USER, FAKE)),
    "cleartext AUTH must not carry the decoy"
  );
  fx.proxy.abort();
}

struct ImplicitTls {
  ca_pem: Vec<u8>,
  guest_port: u16,
  seen: Arc<Mutex<Vec<String>>>,
  stub: tokio::task::JoinHandle<()>,
  serve: tokio::task::JoinHandle<Result<(), crate::Error>>,
  _bundle: tempfile::TempDir,
}

async fn implicit_tls() -> ImplicitTls {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let bundle = tempfile::tempdir().unwrap();
  let bundle_path = bundle.path().join("ca.pem");
  std::fs::write(&bundle_path, ca.cert_pem()).unwrap();
  let grants = vec![smtp_grant(
    &format!("smtps://agent%40demo.test:{FAKE}@localhost:{stub_port}"),
    &format!(
      "smtps://agent%40demo.test:{VALUE}@localhost:{stub_port}?sslrootcert={}",
      bundle_path.display()
    ),
  )];
  let state = test_state_with(grants, &ca);
  let snapshot = state.snapshot();
  let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
  let stub_seen = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let tls = acceptor.accept(conn).await.unwrap();
    serve_submission(tls, None, stub_seen).await;
  });
  let guest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let guest_port = local_addr(&guest_listener).port();
  let serve = tokio::spawn({
    let state = Arc::clone(&state);
    let snapshot = Arc::clone(&snapshot);
    async move {
      let (guest, _) = guest_listener.accept().await.unwrap();
      serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await
    }
  });
  ImplicitTls {
    ca_pem: ca.cert_pem(),
    guest_port,
    seen,
    stub: stub_task,
    serve,
    _bundle: bundle,
  }
}

async fn implicit_session(fx: &ImplicitTls, tls: TlsParameters) -> AsyncSmtpConnection {
  AsyncSmtpConnection::connect_tokio1(
    ("127.0.0.1", fx.guest_port),
    Some(Duration::from_secs(10)),
    &hello(),
    Some(tls),
    None,
  )
  .await
  .unwrap()
}

fn assert_implicit_swapped(recorded: &[String]) {
  assert_eq!(recorded.len(), 1, "{recorded:?}");
  assert!(
    recorded[0].contains(&plain_initial(USER, VALUE)),
    "implicit TLS AUTH must carry the real password: {recorded:?}"
  );
  assert!(
    !recorded[0].contains(&plain_initial(USER, FAKE)),
    "implicit TLS AUTH must not carry the decoy"
  );
}

#[tokio::test]
async fn smtps_implicit_tls_swaps_the_password() {
  let fx = implicit_tls().await;
  let mut conn = implicit_session(&fx, tls_trusting(&fx.ca_pem, None)).await;
  let ok = conn.auth(&[Mechanism::Plain], &decoy_credentials()).await.unwrap();
  assert!(ok.has_code(235), "{ok:?}");
  assert!(!format!("{ok:?}").contains(VALUE), "{ok:?}");
  drop(conn);
  let _ = tokio::time::timeout(Duration::from_secs(10), fx.stub).await;
  let recorded = fx.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_implicit_swapped(&recorded);
  fx.serve.await.unwrap().unwrap();
}

#[tokio::test]
async fn smtps_without_sni_mints_for_the_grant_host() {
  let fx = implicit_tls().await;
  let mut conn = implicit_session(&fx, tls_without_sni(&fx.ca_pem, None)).await;
  assert_leaf_names_localhost(&conn.peer_certificate().unwrap());
  let ok = conn.auth(&[Mechanism::Plain], &decoy_credentials()).await.unwrap();
  assert!(ok.has_code(235), "{ok:?}");
  assert!(!format!("{ok:?}").contains(VALUE), "{ok:?}");
  drop(conn);
  let _ = tokio::time::timeout(Duration::from_secs(10), fx.stub).await;
  let recorded = fx.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
  assert_implicit_swapped(&recorded);
  fx.serve.await.unwrap().unwrap();
}

#[test]
fn smtp_mtls_on_a_cleartext_fake_loads() {
  let fake = format!("smtp://agent%40demo.test:{FAKE}@localhost:587");
  let real = format!("smtps://agent%40demo.test:{VALUE}@localhost:465");
  let grants = resolve_mtls_grants("SMTP_URL", &fake, &real).expect("mtls on an smtp fake loads");
  let scope = grants.first().and_then(|grant| grant.smtp(None, 587)).expect("scope");
  assert_eq!(scope.guest_tls, arkham_config::grants::GuestTlsMode::Mtls);
  assert!(!scope.is_downstream_tls);
}

/// Read one SMTP line, or `None` when the peer closes or the budget ends.
async fn read_line_or_end<S>(stream: &mut S) -> Option<String>
where
  S: AsyncRead + Unpin,
{
  let mut line = Vec::new();
  let mut buf = [0u8; 1];
  loop {
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
      Ok(Ok(1)) => {
        line.push(buf[0]);
        if buf[0] == b'\n' {
          return String::from_utf8(line).ok();
        }
      }
      _ => return None,
    }
  }
}

/// Bytes read from the upstream socket after its `220` Ready. A `ClientHello`
/// is the first thing a TLS client writes, so zero means the proxy never
/// started the upstream handshake.
struct Counted<S> {
  inner: S,
  read: Arc<AtomicUsize>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
  fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    let before = buf.filled().len();
    let this = self.get_mut();
    let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
    if matches!(poll, Poll::Ready(Ok(()))) {
      let n = buf.filled().len().saturating_sub(before);
      let _ = this.read.fetch_add(n, Ordering::Relaxed);
    }
    poll
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().inner).poll_flush(cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
  }
}

struct StarttlsUpstream {
  tls: bool,
  bytes: usize,
  auth: Vec<String>,
}

/// Cleartext SMTP through `STARTTLS`, then a real TLS accept. `bytes` counts
/// only what arrives after the `220`.
async fn accept_starttls_upstream(mut conn: TcpStream, acceptor: TlsAcceptor) -> StarttlsUpstream {
  write_cmd(&mut conn, "220 mail.demo.test ESMTP\r\n").await;
  loop {
    let Some(line) = read_line_or_end(&mut conn).await else {
      return StarttlsUpstream {
        tls: false,
        bytes: 0,
        auth: Vec::new(),
      };
    };
    let upper = line.to_ascii_uppercase();
    if upper.starts_with("EHLO") || upper.starts_with("HELO") {
      write_cmd(&mut conn, "250-mail.demo.test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n").await;
      continue;
    }
    if upper.starts_with("STARTTLS") {
      write_cmd(&mut conn, "220 2.0.0 Ready to start TLS\r\n").await;
      let read = Arc::new(AtomicUsize::new(0));
      let counted = Counted {
        inner: conn,
        read: Arc::clone(&read),
      };
      let accepted = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(counted)).await;
      let Ok(Ok(tls)) = accepted else {
        return StarttlsUpstream {
          tls: false,
          bytes: read.load(Ordering::Relaxed),
          auth: Vec::new(),
        };
      };
      let auth = Arc::new(Mutex::new(Vec::new()));
      serve_authed(tls, Arc::clone(&auth)).await;
      return StarttlsUpstream {
        tls: true,
        bytes: read.load(Ordering::Relaxed),
        auth: auth.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),
      };
    }
    write_cmd(&mut conn, "502 5.5.2 unimplemented\r\n").await;
  }
}

async fn guest_starttls_auth(proxy_addr: SocketAddr, stub_port: u16, tls: TlsParameters) -> Option<Vec<u8>> {
  let stream = tunnel(proxy_addr, stub_port).await;
  let Ok(mut conn) = AsyncSmtpConnection::connect_with_transport(Box::new(stream), &hello()).await else {
    return None;
  };
  if conn.starttls(tls, &hello()).await.is_err() {
    return None;
  }
  if conn.auth(&[Mechanism::Plain], &decoy_credentials()).await.is_err() {
    return None;
  }
  Some(conn.peer_certificate().unwrap())
}

/// STARTTLS under mtls, against an upstream that actually speaks TLS.
/// A CA-signed client certificate completes AUTH and the upstream records
/// the real credential. No certificate fails on the guest handshake, so
/// that upstream accept reads nothing and records no AUTH.
#[tokio::test]
async fn smtp_mtls_starttls_without_a_client_certificate_sends_no_auth_upstream() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let fake = format!("smtp://agent%40demo.test:{FAKE}@localhost:{stub_port}");
  let real = format!(
    "smtp://agent%40demo.test:{VALUE}@localhost:{stub_port}?starttls=required&sslrootcert={}",
    bundle.display()
  );
  let grants = resolve_mtls_grants("SMTP_URL", &fake, &real).expect("smtp starttls with mtls still loads");
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, &ca)).await;
  let (tx, mut rx) = tokio::sync::mpsc::channel(2);
  let stub_task = tokio::spawn(async move {
    for _ in 0..2 {
      let Ok(Ok((conn, _))) = tokio::time::timeout(Duration::from_secs(10), stub.accept()).await else {
        return;
      };
      let report = accept_starttls_upstream(conn, acceptor.clone()).await;
      if tx.send(report).await.is_err() {
        return;
      }
    }
  });

  let ca_pem = ca.cert_pem();
  let der = guest_starttls_auth(proxy_addr, stub_port, tls_without_sni(&ca_pem, Some(client_identity(&ca)))).await;
  let der = der.expect("client certificate did not complete AUTH");
  assert_leaf_names_localhost(&der);
  let control = rx.recv().await.unwrap();
  assert!(control.tls, "client certificate did not open upstream TLS");
  assert!(control.bytes > 0, "client certificate did not reach the upstream TLS handshake");
  assert!(
    control.auth.iter().any(|line| line.contains(&plain_initial(USER, VALUE))),
    "client certificate did not deliver the real credential upstream"
  );
  assert!(
    control.auth.iter().all(|line| !line.contains(&plain_initial(USER, FAKE))),
    "client certificate delivered the decoy upstream"
  );

  let authed = guest_starttls_auth(proxy_addr, stub_port, tls_without_sni(&ca_pem, None)).await;
  assert!(authed.is_none(), "certless guest completed STARTTLS");
  let refused = rx.recv().await.unwrap();
  assert_eq!(refused.bytes, 0, "certless guest sent a ClientHello upstream");
  assert!(refused.auth.is_empty(), "certless guest sent AUTH upstream");
  assert!(!refused.tls, "certless guest opened upstream TLS");

  stub_task.abort();
  proxy.abort();
}
