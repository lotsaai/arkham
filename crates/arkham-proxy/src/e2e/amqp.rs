use std::sync::Mutex;

use super::*;
use amq_protocol::frame::{AMQPFrame, WriteContext, gen_frame, parse_frame};
use amq_protocol::protocol::{AMQPClass, connection};
use amq_protocol::types::FieldTable;
use arkham_config::grants::AmqpScope;
use fe2o3_amqp::acceptor::sasl_acceptor::SaslServerFrame;
use fe2o3_amqp::acceptor::{ConnectionAcceptor, SaslAcceptor};
use fe2o3_amqp::connection::{ConnectionHandle, OpenError};
use fe2o3_amqp::sasl_profile::SaslProfile;
use fe2o3_amqp_types::primitives::{Array, Binary, Symbol};
use fe2o3_amqp_types::sasl::{SaslCode, SaslInit, SaslOutcome, SaslResponse};
use secrecy::ExposeSecret as _;

const FAKE: &str = "arkham_fake_amqp_pass"; // betterleaks:allow
const VALUE: &str = "arkham_real_amqp_pass_longer_01"; // betterleaks:allow
const HEADER_091: &[u8] = b"AMQP\x00\x00\x09\x01";

fn amqp_grant(fake: &str, real: &str) -> Grant {
  let scope = AmqpScope::from_strings(fake, real).unwrap();
  Grant::Amqp {
    credential: Credential {
      label: "amqp".into(),
      fake: scope.downstream.password.expose_secret().to_string(),
      value: scope.upstream.password.clone(),
    },
    scope: Box::new(scope),
  }
}

fn plain(user: &str, password: &str) -> Vec<u8> {
  format!("\0{user}\0{password}").into_bytes()
}

fn encode(frame: &AMQPFrame) -> Vec<u8> {
  gen_frame(frame)(WriteContext::from(Vec::new())).unwrap().into_inner().0
}

fn start() -> Vec<u8> {
  encode(&AMQPFrame::Method(
    0,
    AMQPClass::Connection(connection::AMQPMethod::Start(connection::Start {
      version_major: 0,
      version_minor: 9,
      server_properties: FieldTable::default(),
      mechanisms: "PLAIN AMQPLAIN".into(),
      locales: "en_US".into(),
    })),
  ))
}

fn start_ok(response: Vec<u8>) -> Vec<u8> {
  encode(&AMQPFrame::Method(
    0,
    AMQPClass::Connection(connection::AMQPMethod::StartOk(connection::StartOk {
      client_properties: FieldTable::default(),
      mechanism: "PLAIN".into(),
      response: response.into(),
      locale: "en_US".into(),
    })),
  ))
}

fn close(reply_text: &str) -> Vec<u8> {
  encode(&AMQPFrame::Method(
    0,
    AMQPClass::Connection(connection::AMQPMethod::Close(connection::Close {
      reply_code: 403,
      reply_text: reply_text.into(),
      class_id: 10,
      method_id: 11,
    })),
  ))
}

async fn read_header<S: AsyncRead + Unpin>(conn: &mut S) -> Vec<u8> {
  let mut header = vec![0u8; 8];
  conn.read_exact(&mut header).await.unwrap();
  header
}

async fn read_frame<S: AsyncRead + Unpin>(conn: &mut S) -> AMQPFrame {
  let mut head = [0u8; 7];
  conn.read_exact(&mut head).await.unwrap();
  let size = u32::from_be_bytes(head[3..7].try_into().unwrap());
  let mut rest = vec![0u8; usize::try_from(size).unwrap() + 1];
  conn.read_exact(&mut rest).await.unwrap();
  let bytes = [head.as_slice(), rest.as_slice()].concat();
  let (left, frame) = parse_frame(bytes.as_slice()).unwrap();
  assert!(left.is_empty(), "one frame");
  frame
}

fn start_ok_response(frame: AMQPFrame) -> Vec<u8> {
  let AMQPFrame::Method(0, AMQPClass::Connection(connection::AMQPMethod::StartOk(ok))) = frame else {
    panic!("start-ok");
  };
  ok.response.as_bytes().to_vec()
}

#[derive(Clone)]
struct RecordPlain {
  seen: Arc<Mutex<Option<Vec<u8>>>>,
}

impl SaslAcceptor for RecordPlain {
  fn mechanisms(&self) -> Array<Symbol> {
    Array::from(vec![Symbol::from("PLAIN")])
  }

  fn on_init(&mut self, init: SaslInit) -> SaslServerFrame {
    assert_eq!(init.mechanism.as_str(), "PLAIN");
    *self.seen.lock().unwrap() = init.initial_response.map(Binary::into_vec);
    SaslServerFrame::Outcome(SaslOutcome {
      code: SaslCode::Ok,
      additional_data: None,
    })
  }

  fn on_response(&mut self, _response: SaslResponse) -> SaslServerFrame {
    SaslServerFrame::Outcome(SaslOutcome {
      code: SaslCode::Sys,
      additional_data: None,
    })
  }
}

async fn guest_sasl<S>(stream: S) -> Result<ConnectionHandle<()>, OpenError>
where
  S: AsyncRead + AsyncWrite + std::fmt::Debug + Unpin + Send + 'static,
{
  fe2o3_amqp::Connection::builder()
    .container_id("arkham-guest")
    .scheme("amqp")
    .sasl_profile(SaslProfile::Plain {
      username: "agent".into(),
      password: FAKE.into(),
    })
    .open_with_stream(stream)
    .await
}

async fn guest_lapin(stream: TcpStream) -> lapin::Result<lapin::Connection> {
  let uri = format!("amqp://agent:{FAKE}@127.0.0.1/%2f").parse::<lapin::uri::AMQPUri>().unwrap();
  let held = Arc::new(Mutex::new(Some(async_compat::Compat::new(stream))));
  lapin::Connection::connector(
    uri,
    lapin::runtime::default_runtime()?,
    async move |_uri, _runtime| {
      let Some(sock) = held.lock().unwrap().take() else {
        return Err(lapin::ErrorKind::InvalidConnectionState(lapin::ConnectionState::Error).into());
      };
      Ok(lapin::AsyncTcpStream::Plain(sock))
    },
    lapin::ConnectionProperties::default(),
  )
  .await
}

// Lapin's connector stream is Compat<tokio::net::TcpStream>. A rustls
// TlsStream is not that type. Enabling lapin's rustls feature would also
// enable TLS on the shared amq-protocol crate. The URI password is the decoy.
async fn guest_lapin_tls<S>(guest: S) -> lapin::Result<lapin::Connection>
where
  S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = local_addr(&listener).port();
  let accept = listener.accept();
  let dial = TcpStream::connect(("127.0.0.1", port));
  let (accepted, dialed) = tokio::join!(accept, dial);
  let (accepted, _) = accepted.unwrap();
  let dialed = dialed.unwrap();
  tokio::spawn(async move {
    let (mut reader, mut writer) = tokio::io::split(accepted);
    let (mut guest_reader, mut guest_writer) = tokio::io::split(guest);
    let outbound = tokio::io::copy(&mut reader, &mut guest_writer);
    let inbound = tokio::io::copy(&mut guest_reader, &mut writer);
    let (copied_out, copied_in) = tokio::join!(outbound, inbound);
    let _ = copied_out.ok();
    let _ = copied_in.ok();
  });
  guest_lapin(dialed).await
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

fn ca_bundle(ca: &CertAuthority) -> (tempfile::TempDir, std::path::PathBuf) {
  let dir = tempfile::tempdir().unwrap();
  let bundle = dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  (dir, bundle)
}

fn guest_tls(ca: &CertAuthority, sni: bool) -> TlsConnector {
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let mut config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
  config.enable_sni = sni;
  TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn plaintext_guest_with_mtls_swaps_the_password() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let (_bundle_dir, bundle) = ca_bundle(&ca);
  let fake = format!("amqp://agent:{FAKE}@localhost:{stub_port}");
  let real = format!("amqps://svc:{VALUE}@localhost:{stub_port}?sslrootcert={}", bundle.display());
  let grants = mtls_grants(&fake, &real).expect("mtls on a cleartext fake still loads");
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, &ca)).await;
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = acceptor.accept(conn).await.unwrap();
    assert_eq!(read_header(&mut tls).await, HEADER_091);
    tls.write_all(&start()).await.unwrap();
    let response = start_ok_response(read_frame(&mut tls).await);
    assert_eq!(response, plain("svc", VALUE));
    tls.write_all(&close(&format!("ACCESS_REFUSED - password {VALUE}"))).await.unwrap();
  });
  let stream = connect_through_proxy(proxy_addr, stub_port).await;
  let guest = tokio::spawn(guest_lapin(stream));
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  let err = tokio::time::timeout(Duration::from_secs(10), guest)
    .await
    .unwrap()
    .unwrap()
    .unwrap_err();
  let text = err.to_string();
  assert!(text.contains(&format!("ACCESS_REFUSED - password {FAKE}")), "{text}");
  assert!(!text.contains(VALUE), "{text}");
  proxy.abort();
}

fn mtls_grants(fake: &str, real: &str) -> Result<Vec<Grant>, Box<arkham_config::Error>> {
  use std::collections::BTreeMap;

  use arkham_config::config::{AppConfig, HostTlsCfg, IfMissing, ProxyCfg, WorkspaceCfg};
  use arkham_config::grants::resolve;
  use secrecy::SecretString;

  let mut tls = BTreeMap::new();
  tls.insert(
    "AMQP_URL".to_string(),
    HostTlsCfg {
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls_mode: GuestTlsMode::Mtls,
      guest_cert: None,
      guest_key: None,
    },
  );
  let mut rules = BTreeMap::new();
  rules.insert(
    "broker".to_string(),
    arkham_config::RuleCfg {
      env: "AMQP_URL".into(),
      value: Some(SecretString::from(fake)),
      real: Some(SecretString::from(real)),
      generated: false,
      fnox_key: None,
      allow: Vec::new(),
      pattern: None,
      oauth2: None,
      registry: None,
      if_missing: IfMissing::default(),
      tls,
      ssh: BTreeMap::new(),
    },
  );
  let cfg = AppConfig {
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
  };
  resolve(&cfg).map(|resolved| resolved.grants).map_err(Box::new)
}

#[tokio::test]
async fn amqp_cleartext_start_ok_swaps_the_password() {
  let fx = mitm_fixture(|port| {
    vec![amqp_grant(
      &format!("amqp://agent:{FAKE}@localhost:{port}"),
      &format!("amqp://svc:{VALUE}@localhost:{port}"),
    )]
  })
  .await;
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = fx.stub.accept().await.unwrap();
    assert_eq!(read_header(&mut conn).await, HEADER_091);
    conn.write_all(&start()).await.unwrap();
    assert_eq!(start_ok_response(read_frame(&mut conn).await), plain("svc", VALUE));
    conn.write_all(&close(&format!("ACCESS_REFUSED - password {VALUE}"))).await.unwrap();
  });
  let stream = connect_through_proxy(fx.proxy_addr, fx.stub_port).await;
  let guest = tokio::spawn(guest_lapin(stream));
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  let err = tokio::time::timeout(Duration::from_secs(10), guest)
    .await
    .unwrap()
    .unwrap()
    .unwrap_err();
  let text = err.to_string();
  assert!(text.contains(&format!("ACCESS_REFUSED - password {FAKE}")), "{text}");
  assert!(!text.contains(VALUE), "{text}");
  fx.proxy.abort();
}

#[tokio::test]
async fn amqps_start_ok_swaps_to_the_real_password_after_tls() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let (_bundle_dir, bundle) = ca_bundle(&ca);
  let grants = vec![amqp_grant(
    &format!("amqps://agent:{FAKE}@localhost:{stub_port}"),
    &format!("amqps://svc:{VALUE}@localhost:{stub_port}?sslrootcert={}", bundle.display()),
  )];
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, &ca)).await;
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = acceptor.accept(conn).await.unwrap();
    assert_eq!(read_header(&mut tls).await, HEADER_091);
    tls.write_all(&start()).await.unwrap();
    assert_eq!(start_ok_response(read_frame(&mut tls).await), plain("svc", VALUE));
    tls.write_all(&close(&format!("ACCESS_REFUSED - password {VALUE}"))).await.unwrap();
  });
  let stream = connect_through_proxy(proxy_addr, stub_port).await;
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let tls = guest_tls(&ca, true).connect(name, stream).await.unwrap();
  let guest = tokio::spawn(guest_lapin_tls(tls));
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  let err = tokio::time::timeout(Duration::from_secs(10), guest)
    .await
    .unwrap()
    .unwrap()
    .unwrap_err();
  let text = err.to_string();
  assert!(text.contains(&format!("ACCESS_REFUSED - password {FAKE}")), "{text}");
  assert!(!text.contains(VALUE), "{text}");
  proxy.abort();
}

#[tokio::test]
async fn amqps_without_sni_mints_and_swaps_for_the_grant_host() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let (_bundle_dir, bundle) = ca_bundle(&ca);
  let grants = vec![amqp_grant(
    &format!("amqps://agent:{FAKE}@localhost:{stub_port}"),
    &format!("amqps://svc:{VALUE}@localhost:{stub_port}?sslrootcert={}", bundle.display()),
  )];
  let state = test_state_with(grants, &ca);
  let snapshot = state.snapshot();
  let seen = Arc::new(Mutex::new(None));
  let stub_seen = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let tls = acceptor.accept(conn).await.unwrap();
    let broker = ConnectionAcceptor::builder()
      .container_id("amqp-stub")
      .sasl_acceptor(RecordPlain { seen: stub_seen })
      .build();
    let mut connection = broker.accept(tls).await.unwrap();
    connection.close().await.unwrap();
  });
  let (guest, client_end) = tokio::io::duplex(64 * 1024);
  let serve = tokio::spawn({
    let state = Arc::clone(&state);
    let snapshot = Arc::clone(&snapshot);
    async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
  });
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let tls = tokio::time::timeout(Duration::from_secs(10), guest_tls(&ca, false).connect(name, client_end))
    .await
    .unwrap()
    .unwrap();
  let mut connection = tokio::time::timeout(Duration::from_secs(10), guest_sasl(tls))
    .await
    .unwrap()
    .unwrap();
  connection.close().await.unwrap();
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  assert_eq!(seen.lock().unwrap().as_deref(), Some(plain("svc", VALUE).as_slice()));
  serve.await.unwrap().unwrap();
}

#[tokio::test]
async fn amqps_broker_stalls_tls_and_the_leg_closes_within_budget() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let (_bundle_dir, bundle) = ca_bundle(&ca);
  let grants = vec![amqp_grant(
    &format!("amqp://agent:{FAKE}@localhost:{stub_port}"),
    &format!("amqps://svc:{VALUE}@localhost:{stub_port}?sslrootcert={}", bundle.display()),
  )];
  let state = test_state_with_budget(grants, Vec::new(), &ca, 1);
  let snapshot = state.snapshot();
  let stall = tokio::spawn(async move {
    let (_conn, _) = stub.accept().await.unwrap();
    std::future::pending::<()>().await;
  });
  // A client writes a protocol header while it waits. This guest stays silent
  // so only the handshake budget can close the leg.
  let (guest, client_end) = tokio::io::duplex(8 * 1024);
  let serve =
    tokio::spawn(async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await });
  let joined = tokio::time::timeout(Duration::from_secs(4), serve)
    .await
    .expect("broker TLS stall closed the leg within the handshake budget");
  let err = joined.expect("serve task").expect_err("handshake budget");
  assert!(matches!(err, crate::Error::AmqpHandshakeTimeout), "{err}");
  drop(client_end);
  stall.abort();
}

#[tokio::test]
async fn amqp_without_a_grant_splices_byte_identical() {
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let (proxy_addr, proxy) = run_proxy().await;
  // lapin cannot produce these bytes. It waits for Connection.Start before
  // Start-Ok, and that Start-Ok carries client properties.
  let mut opening = HEADER_091.to_vec();
  opening.extend(start_ok(plain("agent", FAKE)));
  let reply = close(&format!("ACCESS_REFUSED - password {VALUE}"));
  let stub_task = tokio::spawn({
    let opening = opening.clone();
    let reply = reply.clone();
    async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let mut got = vec![0u8; opening.len()];
      conn.read_exact(&mut got).await.unwrap();
      assert_eq!(got, opening);
      conn.write_all(&reply).await.unwrap();
    }
  });
  let mut stream = connect_through_proxy(proxy_addr, stub_port).await;
  stream.write_all(&opening).await.unwrap();
  let mut got = vec![0u8; reply.len()];
  stream.read_exact(&mut got).await.unwrap();
  assert_eq!(got, reply);
  drop(stream);
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  proxy.abort();
}
