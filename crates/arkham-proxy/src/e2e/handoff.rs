use std::net::{Ipv4Addr, Ipv6Addr};

use rama::proxy::haproxy::protocol::v1::Addresses;
use rama::proxy::haproxy::protocol::v2::PROTOCOL_PREFIX;

use super::fixture::*;
use crate::{bind_handoff, serve_handoff};

async fn listen(addr: &str, state: Arc<ProxyState>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
  let listener = bind_handoff(addr.parse().unwrap()).await.unwrap();
  let bound = listener.local_addr().unwrap();
  let task = tokio::spawn(async move {
    serve_handoff(listener, state).await;
  });
  (bound, task)
}

/// One write of a v1 header plus `payload`. The stub must see `payload`
/// only, and the client must see `reply` unchanged.
async fn relay_payload(proxy_addr: SocketAddr, stub: TcpListener, header: String, payload: &[u8], reply: &[u8]) {
  let expect = payload.to_vec();
  let reply_bytes = reply.to_vec();
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = tokio::time::timeout(Duration::from_secs(5), stub.accept()).await.unwrap().unwrap();
    let mut got = vec![0u8; expect.len()];
    conn.read_exact(&mut got).await.unwrap();
    assert_eq!(got, expect);
    assert!(got.windows(b"PROXY".len()).all(|window| window != b"PROXY"));
    let mut extra = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut extra))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(n, 0);
    conn.write_all(&reply_bytes).await.unwrap();
  });
  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  let mut bytes = header.into_bytes();
  bytes.extend_from_slice(payload);
  client.write_all(&bytes).await.unwrap();
  client.shutdown().await.unwrap();
  let mut got_reply = vec![0u8; reply.len()];
  tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut got_reply))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(got_reply, reply);
  stub_task.await.unwrap();
}

async fn expect_eof(client: &mut TcpStream) {
  let mut buf = [0u8; 8];
  let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(n, 0);
}

#[tokio::test]
async fn v1_tcp4_then_tls_substitutes_by_sni() {
  const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
  const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";
  const SNI: &str = "testtun.invalid";
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let bundle = dir.path().join("arkham-ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let ca_der = ca.cert_der().clone();
  let stub_cert = ca.generate_domain_cert(SNI).unwrap();
  let stub_acceptor = TlsAcceptor::from(Arc::new(stub_server_config(&stub_cert.server_config, Alpn::Http1)));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let grants = vec![Grant::Token {
    credential: Credential {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE),
    },
    allow: vec![EndpointScope {
      scheme: Scheme::Https,
      host: SNI.parse().unwrap(),
      port: stub_port,
      client_cert: None,
      client_key: None,
      root_cert: Some(bundle),
      guest_tls: GuestTlsMode::Tls,
    }],
    pattern: None,
    oauth2: None,
  }];
  let state = test_state_with(grants, &ca);
  let (proxy_addr, proxy) = listen("127.0.0.1:0", state).await;
  let stub_task = tokio::spawn(async move {
    let (conn, peer) = stub.accept().await.unwrap();
    assert_ne!(peer.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    let mut tls = stub_acceptor.accept(conn).await.unwrap();
    let head = read_head_from(&mut tls).await;
    let head_str = String::from_utf8(head).unwrap();
    assert!(head_str.contains(&format!("Bearer {VALUE}")), "{head_str}");
    assert!(!head_str.contains(FAKE), "{head_str}");
    let body = format!("echo:{VALUE}");
    tls
      .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
      .await
      .unwrap();
  });
  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  let header = Addresses::new_tcp4(Ipv4Addr::new(203, 0, 113, 9), Ipv4Addr::LOCALHOST, 9, stub_port).to_string();
  client.write_all(header.as_bytes()).await.unwrap();
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca_der).unwrap();
  let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
  let server_name = ServerName::try_from(SNI.to_string()).unwrap();
  let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client))
    .await
    .unwrap()
    .unwrap();
  tls
    .write_all(format!("GET /x HTTP/1.1\r\nHost: {SNI}\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  stub_task.await.unwrap();
  let response = read_head_from(&mut tls).await;
  let resp = String::from_utf8_lossy(&response);
  assert!(!resp.contains(VALUE), "{resp}");
  let expect = format!("echo:{FAKE}");
  assert_eq!(read_body(&mut tls, &response, expect.len()).await, expect.as_bytes());
  proxy.abort();
}

#[tokio::test]
async fn v1_tcp4_splice_relays_blob_verbatim() {
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let (proxy_addr, proxy) = listen("127.0.0.1:0", test_state()).await;
  let blob: Vec<u8> = (0..256u32).map(|i| u8::try_from(i % 251).expect("fits u8")).collect();
  let header = Addresses::new_tcp4(Ipv4Addr::new(203, 0, 113, 9), Ipv4Addr::LOCALHOST, 9, stub_port).to_string();
  relay_payload(proxy_addr, stub, header, &blob, b"splice-reply").await;
  proxy.abort();
}

#[tokio::test]
async fn rejected_preambles_close_without_dial() {
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let (proxy_addr, proxy) = listen("127.0.0.1:0", test_state()).await;
  let mut silent = TcpStream::connect(proxy_addr).await.unwrap();
  silent.shutdown().await.unwrap();
  expect_eof(&mut silent).await;
  let mut http = TcpStream::connect(proxy_addr).await.unwrap();
  http.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
  expect_eof(&mut http).await;
  let mut v2 = TcpStream::connect(proxy_addr).await.unwrap();
  v2.write_all(PROTOCOL_PREFIX).await.unwrap();
  expect_eof(&mut v2).await;
  tokio::time::timeout(Duration::from_secs(2), stub.accept()).await.unwrap_err();
  proxy.abort();
}

#[tokio::test]
async fn silent_peer_stays_open_until_handshake_budget() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let state = test_state_with_budget(Vec::new(), Vec::new(), &ca, 1);
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let (proxy_addr, proxy) = listen("127.0.0.1:0", state).await;
  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  let mut buf = [0u8; 1];
  let early = tokio::time::timeout(Duration::from_millis(400), client.read(&mut buf)).await;
  assert!(early.is_err(), "read still pending at 400ms");
  let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(n, 0);
  tokio::time::timeout(Duration::from_secs(2), stub.accept()).await.unwrap_err();
  proxy.abort();
}

#[tokio::test]
async fn v1_tcp6_splice_relays_short_payload() {
  let stub = TcpListener::bind("[::1]:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let (proxy_addr, proxy) = listen("[::1]:0", test_state()).await;
  let payload: Vec<u8> = (0..32u32).map(|i| u8::try_from(i).expect("fits u8")).collect();
  let header = Addresses::new_tcp6("2001:db8::1".parse::<Ipv6Addr>().unwrap(), Ipv6Addr::LOCALHOST, 9, stub_port).to_string();
  relay_payload(proxy_addr, stub, header, &payload, b"tcp6-reply").await;
  proxy.abort();
}
