//! NATS through the MITM: a `nats://` server leg keeps the decoy, a `tls://`
//! server leg carries the real password, nkey, or user JWT only after its
//! upgrade, and a guest hello without SNI mints for the grant host.

use std::path::PathBuf;

use arkham_config::grants::NatsSeed;
use base64::Engine as _;

use super::*;
use crate::transports::nats::fixtures::{mint_user, nats_grants};

const FAKE: &str = "arkham_fake_nats_pass"; // betterleaks:allow
const VALUE: &str = "arkham_real_nats_pass_01"; // betterleaks:allow
const INFO: &[u8] = b"INFO {\"server_id\":\"NSTUB\",\"auth_required\":true,\"tls_required\":true}\r\n";
/// A cleartext upstream whose INFO does not demand TLS.
const CLEAR_INFO: &[u8] = b"INFO {\"server_id\":\"NSTUB\",\"auth_required\":true,\"tls_required\":false}\r\n";

/// How the real string opens the server leg.
#[derive(Clone, Copy)]
enum ServerLeg {
  /// `nats://`: never upgrades.
  Cleartext,
  /// `tls://`: upgrades right after INFO.
  AfterInfo,
  /// `tls://...?handshake_first=true`: TLS before any NATS byte.
  HandshakeFirst,
}

/// A NATS server stand-in: a TCP listener plus a TLS acceptor for
/// `localhost` signed by the proxy's CA, which the bundle file also holds.
struct NatsStub {
  ca: CertAuthority,
  acceptor: TlsAcceptor,
  listener: TcpListener,
  port: u16,
  bundle: PathBuf,
  _bundle_dir: tempfile::TempDir,
}

async fn nats_stub() -> NatsStub {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = local_addr(&listener).port();
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  NatsStub {
    ca,
    acceptor,
    listener,
    port,
    bundle,
    _bundle_dir: bundle_dir,
  }
}

impl NatsStub {
  /// The decoy string names the stub; the real string opens `leg` to it.
  fn grants(&self, leg: ServerLeg) -> Vec<Grant> {
    let port = self.port;
    let root = self.bundle.display();
    let real = match leg {
      ServerLeg::Cleartext => format!("nats://agent:{VALUE}@localhost:{port}"),
      ServerLeg::AfterInfo => format!("tls://agent:{VALUE}@localhost:{port}?sslrootcert={root}"),
      ServerLeg::HandshakeFirst => format!("tls://agent:{VALUE}@localhost:{port}?handshake_first=true&sslrootcert={root}"),
    };
    nats_grants(&format!("nats://agent:{FAKE}@localhost:{port}"), &real)
  }

  /// A guest TLS client that trusts the proxy's CA.
  fn guest_connector(&self, sni: bool) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(self.ca.cert_der().clone()).unwrap();
    let mut config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.enable_sni = sni;
    TlsConnector::from(Arc::new(config))
  }
}

fn connect_line(pass: &str) -> String {
  format!("CONNECT {{\"verbose\":false,\"user\":\"agent\",\"pass\":\"{pass}\",\"name\":\"e2e\"}}\r\n")
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
  hay.windows(needle.len()).any(|window| window == needle)
}

/// One line through LF, read a byte at a time so nothing past it is taken
/// from a stream that may switch to TLS next.
async fn read_line<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
  let mut line = Vec::new();
  let mut byte = [0u8; 1];
  while line.last() != Some(&b'\n') {
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut byte))
      .await
      .expect("a line within five seconds")
      .expect("peer closed mid-line");
    line.push(byte[0]);
  }
  line
}

/// The stub reads CONNECT over `conn` and checks which password crossed.
async fn expect_connect<S: AsyncRead + Unpin>(conn: &mut S, pass: &str, absent: &str) {
  let connect = read_line(conn).await;
  assert!(connect.starts_with(b"CONNECT "), "first guest line is CONNECT");
  assert!(
    contains(&connect, format!("\"pass\":\"{pass}\"").as_bytes()),
    "CONNECT carries {pass}"
  );
  assert!(!contains(&connect, absent.as_bytes()), "CONNECT still carries {absent}");
}

async fn connect_through_proxy(proxy_addr: SocketAddr, port: u16) -> TcpStream {
  let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
  stream
    .write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut head = [0u8; 19];
  stream.read_exact(&mut head).await.unwrap();
  assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
  stream
}

#[tokio::test]
async fn nats_cleartext_server_leg_receives_the_decoy() {
  let stub = nats_stub().await;
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(stub.grants(ServerLeg::Cleartext), &stub.ca)).await;
  let port = stub.port;
  let listener = stub.listener;
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = listener.accept().await.unwrap();
    let mut opening = CLEAR_INFO.to_vec();
    opening.extend_from_slice(b"PING\r\n");
    conn.write_all(&opening).await.unwrap();
    expect_connect(&mut conn, FAKE, VALUE).await;
    assert_eq!(read_line(&mut conn).await, b"PING\r\n");
    conn.write_all(b"PONG\r\n").await.unwrap();
    assert_eq!(read_line(&mut conn).await, b"PONG\r\n");
  });
  let mut guest = connect_through_proxy(proxy_addr, port).await;
  assert_eq!(read_line(&mut guest).await, CLEAR_INFO);
  guest.write_all(format!("{}PING\r\n", connect_line(FAKE)).as_bytes()).await.unwrap();
  assert_eq!(read_line(&mut guest).await, b"PING\r\n", "the bytes after INFO reach the guest");
  assert_eq!(read_line(&mut guest).await, b"PONG\r\n");
  guest.write_all(b"PONG\r\n").await.unwrap();
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  proxy.abort();
}

/// INFO arrives in two writes and the stub's TLS starts right after it. The
/// guest stays cleartext; CONNECT reaches the stub only inside TLS, with the
/// real password, and a server line naming it comes back as the decoy.
#[tokio::test]
async fn nats_tls_server_leg_swaps_connect_after_the_upgrade() {
  let stub = nats_stub().await;
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(stub.grants(ServerLeg::AfterInfo), &stub.ca)).await;
  let port = stub.port;
  let NatsStub { listener, acceptor, .. } = stub;
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = listener.accept().await.unwrap();
    let (head, tail) = INFO.split_at(12);
    conn.write_all(head).await.unwrap();
    conn.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    conn.write_all(tail).await.unwrap();
    let mut tls = acceptor.accept(conn).await.unwrap();
    expect_connect(&mut tls, VALUE, FAKE).await;
    assert_eq!(read_line(&mut tls).await, b"PUB orders 5\r\n");
    assert_eq!(read_line(&mut tls).await, b"hello\r\n");
    tls.write_all(b"MSG orders 1 5\r\nhello\r\n").await.unwrap();
    tls
      .write_all(format!("-ERR 'Authorization Violation for {VALUE}'\r\n").as_bytes())
      .await
      .unwrap();
    tls.flush().await.unwrap();
  });
  let mut guest = connect_through_proxy(proxy_addr, port).await;
  assert_eq!(read_line(&mut guest).await, INFO);
  guest
    .write_all(format!("{}PUB orders 5\r\nhello\r\n", connect_line(FAKE)).as_bytes())
    .await
    .unwrap();
  assert_eq!(read_line(&mut guest).await, b"MSG orders 1 5\r\n");
  assert_eq!(read_line(&mut guest).await, b"hello\r\n");
  assert_eq!(
    read_line(&mut guest).await,
    format!("-ERR 'Authorization Violation for {FAKE}'\r\n").as_bytes()
  );
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  proxy.abort();
}

/// Transparent capture has no CONNECT authority. A guest that starts TLS
/// after INFO without SNI is served a leaf for the grant host.
#[tokio::test]
async fn nats_tls_guest_without_sni_mints_for_the_grant_host() {
  let stub = nats_stub().await;
  let state = test_state_with(stub.grants(ServerLeg::AfterInfo), &stub.ca);
  let snapshot = state.snapshot();
  let port = stub.port;
  let connector = stub.guest_connector(false);
  let NatsStub { listener, acceptor, .. } = stub;
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = listener.accept().await.unwrap();
    conn.write_all(INFO).await.unwrap();
    let mut tls = acceptor.accept(conn).await.unwrap();
    expect_connect(&mut tls, VALUE, FAKE).await;
    tls.write_all(b"+OK\r\n").await.unwrap();
    tls.flush().await.unwrap();
  });
  let (guest, mut client_end) = tokio::io::duplex(64 * 1024);
  let serve = tokio::spawn({
    let state = Arc::clone(&state);
    let snapshot = Arc::clone(&snapshot);
    async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", port, "127.0.0.1").await }
  });
  assert_eq!(read_line(&mut client_end).await, INFO);
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(name, client_end))
    .await
    .unwrap()
    .unwrap();
  tls.write_all(connect_line(FAKE).as_bytes()).await.unwrap();
  assert_eq!(read_line(&mut tls).await, b"+OK\r\n");
  drop(tls);
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  serve.await.unwrap().unwrap();
}

/// `handshake_first`: both legs settle TLS before INFO, and CONNECT swaps.
#[tokio::test]
async fn nats_handshake_first_settles_both_legs_before_info() {
  let stub = nats_stub().await;
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(stub.grants(ServerLeg::HandshakeFirst), &stub.ca)).await;
  let port = stub.port;
  let connector = stub.guest_connector(true);
  let NatsStub { listener, acceptor, .. } = stub;
  let stub_task = tokio::spawn(async move {
    let (conn, _) = listener.accept().await.unwrap();
    let mut tls = acceptor.accept(conn).await.unwrap();
    tls.write_all(INFO).await.unwrap();
    tls.flush().await.unwrap();
    expect_connect(&mut tls, VALUE, FAKE).await;
    tls.write_all(b"+OK\r\n").await.unwrap();
    tls.flush().await.unwrap();
  });
  let stream = connect_through_proxy(proxy_addr, port).await;
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(name, stream))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(read_line(&mut tls).await, INFO);
  tls.write_all(connect_line(FAKE).as_bytes()).await.unwrap();
  assert_eq!(read_line(&mut tls).await, b"+OK\r\n");
  drop(tls);
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  proxy.abort();
}

const E2E_NONCE: &[u8] = b"e2e-nonce";
const NONCE_INFO: &[u8] = b"INFO {\"server_id\":\"NSTUB\",\"auth_required\":true,\"tls_required\":true,\"nonce\":\"e2e-nonce\"}\r\n";

fn e2e_b64(bytes: &[u8]) -> String {
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn e2e_user_jwt(public: &str) -> String {
  let header = e2e_b64(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
  let payload = e2e_b64(format!(r#"{{"sub":"{public}"}}"#).as_bytes());
  format!("{header}.{payload}.{}", e2e_b64(b"sig"))
}

fn signed_connect(field: &str, value: &str, sig: &str) -> String {
  format!("CONNECT {{\"{field}\":\"{value}\",\"sig\":\"{sig}\",\"verbose\":false}}\r\n")
}

struct SignedMaterial {
  fake_url: String,
  real_userinfo: String,
  line: String,
  field: &'static str,
  expect: String,
  absent: Vec<String>,
  public: String,
}

fn signed_material(user_jwt: bool, port: u16) -> SignedMaterial {
  let (fake_raw, fake_seed) = mint_user();
  let (real_raw, real_seed) = mint_user();
  let sig = e2e_b64(&fake_seed.sign(E2E_NONCE).expect("fake seed signs"));
  if user_jwt {
    let fake_jwt = e2e_user_jwt(fake_seed.public_key());
    let real_jwt = e2e_user_jwt(real_seed.public_key());
    SignedMaterial {
      fake_url: format!("nats://creds:{fake_raw}:{fake_jwt}@localhost:{port}"),
      real_userinfo: format!("creds:{real_raw}:{real_jwt}"),
      line: format!(
        "CONNECT {{\"jwt\":\"{fake_jwt}\",\"nkey\":\"{}\",\"sig\":\"{sig}\",\"verbose\":false}}\r\n",
        fake_seed.public_key()
      ),
      field: "jwt",
      expect: real_jwt,
      absent: vec![fake_jwt, fake_raw, real_raw, fake_seed.public_key().to_string()],
      public: real_seed.public_key().to_string(),
    }
  } else {
    let fake_public = fake_seed.public_key().to_string();
    SignedMaterial {
      fake_url: format!("nats://nkey:{fake_raw}@localhost:{port}"),
      real_userinfo: format!("nkey:{real_raw}"),
      line: signed_connect("nkey", &fake_public, &sig),
      field: "nkey",
      expect: real_seed.public_key().to_string(),
      absent: vec![fake_public, fake_raw, real_raw],
      public: real_seed.public_key().to_string(),
    }
  }
}

/// The stub reads one CONNECT and checks the swapped field plus the nonce signature.
async fn expect_signed<S: AsyncRead + Unpin>(conn: &mut S, field: &str, expect: &str, public: &str, absent: &[String]) {
  let connect = read_line(conn).await;
  let text = String::from_utf8(connect).expect("CONNECT is utf-8");
  assert!(text.starts_with("CONNECT "), "{text}");
  let json = text.trim().strip_prefix("CONNECT").expect("verb").trim();
  let parsed: serde_json::Value = serde_json::from_str(json).expect("CONNECT json");
  assert_eq!(parsed.get(field).and_then(serde_json::Value::as_str), Some(expect));
  if parsed.get("nkey").is_some() {
    assert_eq!(parsed.get("nkey").and_then(serde_json::Value::as_str), Some(public));
  }
  let sig = parsed.get("sig").and_then(serde_json::Value::as_str).expect("sig");
  let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig).expect("sig bytes");
  assert!(
    NatsSeed::verify(public, E2E_NONCE, &raw),
    "upstream sig verifies under the real public key"
  );
  for needle in absent {
    assert!(!text.contains(needle), "{text} still carries a decoy or a seed");
  }
}

async fn signed_round_trip(handshake_first: bool, user_jwt: bool) {
  let stub = nats_stub().await;
  let material = signed_material(user_jwt, stub.port);
  let root = stub.bundle.display().to_string();
  let query = if handshake_first {
    format!("handshake_first=true&sslrootcert={root}")
  } else {
    format!("sslrootcert={root}")
  };
  let real = format!("tls://{}@localhost:{}?{query}", material.real_userinfo, stub.port);
  let grants = nats_grants(&material.fake_url, &real);
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, &stub.ca)).await;
  let port = stub.port;
  let connector = stub.guest_connector(true);
  let line = material.line.clone();
  let field = material.field;
  let expect = material.expect.clone();
  let public = material.public.clone();
  let absent = material.absent.clone();
  let NatsStub { listener, acceptor, .. } = stub;
  let stub_task = tokio::spawn(async move {
    let (conn, _) = listener.accept().await.unwrap();
    if handshake_first {
      let mut tls = acceptor.accept(conn).await.unwrap();
      tls.write_all(NONCE_INFO).await.unwrap();
      tls.flush().await.unwrap();
      expect_signed(&mut tls, field, &expect, &public, &absent).await;
      tls.write_all(b"+OK\r\n").await.unwrap();
      tls.flush().await.unwrap();
    } else {
      let mut plain = conn;
      plain.write_all(NONCE_INFO).await.unwrap();
      plain.flush().await.unwrap();
      let mut tls = acceptor.accept(plain).await.unwrap();
      expect_signed(&mut tls, field, &expect, &public, &absent).await;
      tls.write_all(b"+OK\r\n").await.unwrap();
      tls.flush().await.unwrap();
    }
  });
  if handshake_first {
    let stream = connect_through_proxy(proxy_addr, port).await;
    let name = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(name, stream))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(read_line(&mut tls).await, NONCE_INFO);
    tls.write_all(line.as_bytes()).await.unwrap();
    assert_eq!(read_line(&mut tls).await, b"+OK\r\n");
    drop(tls);
  } else {
    let mut guest = connect_through_proxy(proxy_addr, port).await;
    assert_eq!(read_line(&mut guest).await, NONCE_INFO);
    guest.write_all(line.as_bytes()).await.unwrap();
    assert_eq!(read_line(&mut guest).await, b"+OK\r\n");
  }
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  proxy.abort();
}

#[tokio::test]
async fn nats_after_info_swaps_a_verifying_nkey() {
  signed_round_trip(false, false).await;
}

#[tokio::test]
async fn nats_handshake_first_swaps_a_verifying_nkey() {
  signed_round_trip(true, false).await;
}

#[tokio::test]
async fn nats_after_info_swaps_a_verifying_user_jwt() {
  signed_round_trip(false, true).await;
}

#[tokio::test]
async fn nats_handshake_first_swaps_a_verifying_user_jwt() {
  signed_round_trip(true, true).await;
}

/// `guest_tls_mode = mtls` and a cleartext guest after INFO: the proxy
/// returns [`crate::Error::NatsGuestPlaintext`] and the stub sees no CONNECT.
#[tokio::test]
async fn nats_mtls_plaintext_guest_writes_nothing_upstream() {
  let stub = nats_stub().await;
  let port = stub.port;
  let root = stub.bundle.display().to_string();
  let fake = format!("nats://agent:{FAKE}@localhost:{port}");
  let real = format!("tls://agent:{VALUE}@localhost:{port}?sslrootcert={root}");
  let grants = super::resolve_mtls_grants("NATS_URL", &fake, &real).expect("nats mtls on a cleartext fake still loads");
  let state = test_state_with(grants, &stub.ca);
  let snapshot = state.snapshot();
  let NatsStub { listener, acceptor, .. } = stub;
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = listener.accept().await.unwrap();
    conn.write_all(INFO).await.unwrap();
    conn.flush().await.unwrap();
    let mut tls = acceptor.accept(conn).await.unwrap();
    let mut buf = [0u8; 64];
    let upstream = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
      .await
      .expect("upstream closes");
    match upstream {
      Ok(0) | Err(_) => {}
      Ok(n) => panic!("plaintext mtls guest wrote {n} bytes upstream"),
    }
  });
  let (guest, mut client) = tokio::io::duplex(64 * 1024);
  let serve = tokio::spawn(async move { serve_connect_stream(guest, &state, snapshot.as_ref(), "localhost", port, &[]).await });
  assert_eq!(read_line(&mut client).await, INFO);
  client.write_all(connect_line(FAKE).as_bytes()).await.unwrap();
  let err = tokio::time::timeout(Duration::from_secs(10), serve)
    .await
    .expect("serve finishes")
    .expect("serve task");
  let err = err.expect_err("plaintext mtls guest");
  assert!(matches!(err, crate::Error::NatsGuestPlaintext), "{err}");
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
}
