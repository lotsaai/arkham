use super::*;
use amq_protocol::frame::{AMQPFrame, WriteContext, gen_frame, parse_frame};
use amq_protocol::protocol::{AMQPClass, connection};
use amq_protocol::types::FieldTable;
use arkham_config::grants::AmqpScope;
use fe2o3_amqp_types::primitives::Binary;
use fe2o3_amqp_types::sasl::{SaslCode, SaslInit, SaslOutcome};
use secrecy::ExposeSecret as _;

const FAKE: &str = "arkham_fake_amqp_pass"; // betterleaks:allow
const VALUE: &str = "arkham_real_amqp_pass_longer_01"; // betterleaks:allow
const HEADER_091: &[u8] = b"AMQP\x00\x00\x09\x01";
const HEADER_SASL: &[u8] = b"AMQP\x03\x01\x00\x00";

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

fn close_text(frame: AMQPFrame) -> String {
  let AMQPFrame::Method(0, AMQPClass::Connection(connection::AMQPMethod::Close(close))) = frame else {
    panic!("connection.close");
  };
  close.reply_text.as_str().to_string()
}

fn sasl_frame(body: &[u8]) -> Vec<u8> {
  let mut out = u32::try_from(body.len() + 8).unwrap().to_be_bytes().to_vec();
  out.extend([2, 1, 0, 0]);
  out.extend_from_slice(body);
  out
}

async fn read_frame_10<S: AsyncRead + Unpin>(conn: &mut S) -> Vec<u8> {
  let mut head = [0u8; 8];
  conn.read_exact(&mut head).await.unwrap();
  let size = usize::try_from(u32::from_be_bytes(head[..4].try_into().unwrap())).unwrap();
  let mut body = vec![0u8; size - 8];
  conn.read_exact(&mut body).await.unwrap();
  body
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
async fn amqp_cleartext_start_ok_forwards_the_decoy() {
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
    assert_eq!(start_ok_response(read_frame(&mut conn).await), plain("agent", FAKE));
    conn.write_all(&close("ACCESS_REFUSED")).await.unwrap();
  });
  let mut stream = connect_through_proxy(fx.proxy_addr, fx.stub_port).await;
  stream.write_all(HEADER_091).await.unwrap();
  assert!(matches!(
    read_frame(&mut stream).await,
    AMQPFrame::Method(0, AMQPClass::Connection(connection::AMQPMethod::Start(_)))
  ));
  stream.write_all(&start_ok(plain("agent", FAKE))).await.unwrap();
  assert_eq!(close_text(read_frame(&mut stream).await), "ACCESS_REFUSED");
  drop(stream);
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
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
  let mut tls = guest_tls(&ca, true).connect(name, stream).await.unwrap();
  tls.write_all(HEADER_091).await.unwrap();
  assert!(matches!(
    read_frame(&mut tls).await,
    AMQPFrame::Method(0, AMQPClass::Connection(connection::AMQPMethod::Start(_)))
  ));
  tls.write_all(&start_ok(plain("agent", FAKE))).await.unwrap();
  assert_eq!(close_text(read_frame(&mut tls).await), format!("ACCESS_REFUSED - password {FAKE}"));
  drop(tls);
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
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
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = acceptor.accept(conn).await.unwrap();
    assert_eq!(read_header(&mut tls).await, HEADER_SASL);
    let init: SaslInit = serde_amqp::from_slice(&read_frame_10(&mut tls).await).unwrap();
    assert_eq!(init.mechanism.as_str(), "PLAIN");
    assert_eq!(init.initial_response.unwrap().into_vec(), plain("svc", VALUE));
    let outcome = SaslOutcome {
      code: SaslCode::Ok,
      additional_data: None,
    };
    let mut reply = HEADER_SASL.to_vec();
    reply.extend(sasl_frame(&serde_amqp::to_vec(&outcome).unwrap()));
    tls.write_all(&reply).await.unwrap();
  });
  let (guest, client_end) = tokio::io::duplex(64 * 1024);
  let serve = tokio::spawn({
    let state = Arc::clone(&state);
    let snapshot = Arc::clone(&snapshot);
    async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
  });
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let mut tls = tokio::time::timeout(Duration::from_secs(10), guest_tls(&ca, false).connect(name, client_end))
    .await
    .unwrap()
    .unwrap();
  let init = SaslInit {
    mechanism: "PLAIN".into(),
    initial_response: Some(Binary::from(plain("agent", FAKE))),
    hostname: Some("localhost".into()),
  };
  let mut opening = HEADER_SASL.to_vec();
  opening.extend(sasl_frame(&serde_amqp::to_vec(&init).unwrap()));
  tls.write_all(&opening).await.unwrap();
  assert_eq!(read_header(&mut tls).await, HEADER_SASL);
  let outcome: SaslOutcome = serde_amqp::from_slice(&read_frame_10(&mut tls).await).unwrap();
  assert_eq!(outcome.code, SaslCode::Ok);
  drop(tls);
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
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
