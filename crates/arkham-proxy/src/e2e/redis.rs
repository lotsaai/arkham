//! Guest AUTH and PING go through the `redis` crate on cleartext, TLS, and a
//! no-SNI `ClientHello`. The guest holds the decoy. The in-process stub records
//! the upstream AUTH.

use std::sync::Mutex;

use super::fixture::*;
use ::redis::AsyncCommands as _;
use secrecy::ExposeSecret as _;

const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn redis_grant(fake: &str, real: &str) -> Grant {
  let scope = RedisScope::from_strings(fake, real).unwrap();
  Grant::Redis {
    credential: Credential {
      label: "r".into(),
      fake: scope.downstream.password.expose_secret().to_string(),
      value: scope.upstream.password.clone(),
    },
    scope: Box::new(scope),
  }
}

/// Serve one redis connection: AUTH then PING, recording every byte.
async fn serve_redis<S>(mut conn: S, seen: Arc<Mutex<Vec<u8>>>)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let expected = ::redis::cmd("AUTH").arg(VALUE).get_packed_command();
  let mut buf = vec![0u8; expected.len()];
  conn.read_exact(&mut buf).await.unwrap();
  *seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = buf.clone();
  assert_eq!(buf, expected, "upstream must see the real, reframed AUTH");
  conn.write_all(b"+OK\r\n").await.unwrap();
  let ping = ::redis::cmd("PING").get_packed_command();
  let mut got = vec![0u8; ping.len()];
  conn.read_exact(&mut got).await.unwrap();
  assert_eq!(got, ping);
  conn.write_all(b"+PONG\r\n").await.unwrap();
}

async fn connect_through_proxy(proxy_addr: SocketAddr, stub_port: u16) -> TcpStream {
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

/// AUTH with the decoy, then PING, on a stream the test already connected.
async fn authed_ping<S>(stream: S) -> String
where
  S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let info = ::redis::RedisConnectionInfo::default().set_password(FAKE).set_skip_set_lib_name();
  let (mut conn, driver) = ::redis::aio::MultiplexedConnection::new_with_config(&info, stream, ::redis::AsyncConnectionConfig::new())
    .await
    .unwrap();
  let driver = tokio::spawn(driver);
  let pong: String = conn.ping().await.unwrap();
  driver.abort();
  pong
}

fn recorded(seen: &Mutex<Vec<u8>>) -> Vec<u8> {
  seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
}

#[tokio::test]
async fn redis_auth_swaps_over_cleartext() {
  let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
  let fx = mitm_fixture(|port| {
    vec![redis_grant(
      &format!("redis://app:{FAKE}@localhost:{port}/0"),
      &format!("redis://app:{VALUE}@localhost:{port}/0"),
    )]
  })
  .await;
  let stub_seen = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (conn, _) = fx.stub.accept().await.unwrap();
    serve_redis(conn, stub_seen).await;
  });

  let stream = connect_through_proxy(fx.proxy_addr, fx.stub_port).await;
  assert_eq!(authed_ping(stream).await, "PONG");
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  assert_eq!(
    recorded(&seen),
    ::redis::cmd("AUTH").arg(VALUE).get_packed_command(),
    "the stub recorded the reframed real AUTH"
  );
  fx.proxy.abort();
}

#[tokio::test]
async fn redis_auth_swaps_over_tls_both_legs() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  // A rediss string verifies against its own anchor, never the platform
  // store: the bundle is the arkham CA, exactly what the stub presents.
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let grants = vec![redis_grant(
    &format!("rediss://app:{FAKE}@localhost:{stub_port}/0"),
    &format!("rediss://app:{VALUE}@localhost:{stub_port}/0?sslrootcert={}", bundle.display()),
  )];
  let state = test_state_with(grants, &ca);
  let (proxy_addr, proxy) = run_proxy_with(state).await;

  let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
  let stub_seen = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let tls = acceptor.accept(conn).await.unwrap();
    serve_redis(tls, stub_seen).await;
  });

  let stream = connect_through_proxy(proxy_addr, stub_port).await;
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let tls = TlsConnector::from(Arc::new(config)).connect(name, stream).await.unwrap();
  assert_eq!(authed_ping(tls).await, "PONG");
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  assert_eq!(recorded(&seen), ::redis::cmd("AUTH").arg(VALUE).get_packed_command());
  proxy.abort();
}

#[tokio::test]
async fn redis_tls_without_sni_mints_for_the_grant_host() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let grants = vec![redis_grant(
    &format!("rediss://app:{FAKE}@localhost:{stub_port}/0"),
    &format!("rediss://app:{VALUE}@localhost:{stub_port}/0?sslrootcert={}", bundle.display()),
  )];
  let state = test_state_with(grants, &ca);
  let snapshot = state.snapshot();

  let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
  let stub_seen = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let tls = acceptor.accept(conn).await.unwrap();
    serve_redis(tls, stub_seen).await;
  });

  let (guest, client_end) = tokio::io::duplex(64 * 1024);
  let serve = tokio::spawn({
    let state = Arc::clone(&state);
    let snapshot = Arc::clone(&snapshot);
    async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
  });

  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let mut config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
  // The redis crate builds its own rustls ClientConfig (no enable_sni knob)
  // and verifies the dialed host, so it cannot send a no-SNI ClientHello that
  // still checks the grant host.
  config.enable_sni = false;
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let tls = tokio::time::timeout(
    Duration::from_secs(10),
    TlsConnector::from(Arc::new(config)).connect(name, client_end),
  )
  .await
  .unwrap()
  .unwrap();
  assert_eq!(authed_ping(tls).await, "PONG");
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  assert_eq!(recorded(&seen), ::redis::cmd("AUTH").arg(VALUE).get_packed_command());
  serve.await.unwrap().unwrap();
}

#[test]
fn redis_mtls_on_a_cleartext_fake_loads() {
  let fake = format!("redis://app:{FAKE}@localhost:6379/0");
  let real = format!("rediss://app:{VALUE}@localhost:6379/0");
  let grants = resolve_mtls_grants("REDIS_URL", &fake, &real).expect("mtls on a cleartext redis fake loads");
  let scope = grants.first().and_then(|grant| grant.redis(None, 6379)).expect("scope");
  assert_eq!(scope.guest_tls, arkham_config::grants::GuestTlsMode::Mtls);
  assert!(!scope.is_downstream_tls);
}
