//! Talos selection: the guest certificate picks the context, and that
//! context's client certificate is what the upstream handshake sees.

use super::*;

use std::path::Path;

use arkham_pki::ca::{generate_client_pair, generate_domain_pair};
use rama::crypto::pem::PemEncode as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

const LABEL_A: &str = "talos-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LABEL_B: &str = "talos-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[tokio::test]
async fn guest_certificate_selects_the_matching_upstream_identity() {
  install_crypto_provider();
  let arkham = CertAuthority::generate().unwrap();
  let cluster_a = CertAuthority::generate().unwrap();
  let cluster_b = CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();

  let (client_a, key_a) = generate_client_pair(&cluster_a, "prod").unwrap();
  let (client_b, key_b) = generate_client_pair(&cluster_b, "staging").unwrap();
  let (guest_a, guest_key_a) = generate_client_pair(&arkham, "guest-prod").unwrap();
  let (guest_b, guest_key_b) = generate_client_pair(&arkham, "guest-staging").unwrap();
  write_chain(&dir.path().join(format!("{LABEL_A}.client.crt")), &client_a);
  write_key(&dir.path().join(format!("{LABEL_A}.client.key")), &key_a);
  std::fs::write(dir.path().join(format!("{LABEL_A}.ca.crt")), cluster_a.cert_pem()).unwrap();
  write_chain(&dir.path().join(format!("{LABEL_A}.guest.crt")), &guest_a);
  write_chain(&dir.path().join(format!("{LABEL_B}.client.crt")), &client_b);
  write_key(&dir.path().join(format!("{LABEL_B}.client.key")), &key_b);
  std::fs::write(dir.path().join(format!("{LABEL_B}.ca.crt")), cluster_b.cert_pem()).unwrap();
  write_chain(&dir.path().join(format!("{LABEL_B}.guest.crt")), &guest_b);

  let (server_a, server_key_a) = generate_domain_pair(&cluster_a, "localhost").unwrap();
  let (server_b, server_key_b) = generate_domain_pair(&cluster_b, "localhost").unwrap();
  let mut client_trust = rustls::RootCertStore::empty();
  client_trust.add(cluster_a.cert_der().clone()).unwrap();
  client_trust.add(cluster_b.cert_der().clone()).unwrap();
  let config_a = server_config(&client_trust, server_a, server_key_a);
  let config_b = server_config(&client_trust, server_b, server_key_b);

  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let grants = vec![
    talos_grant(LABEL_A, stub_port, dir.path()),
    talos_grant(LABEL_B, stub_port, dir.path()),
  ];
  let state = test_state_with(grants, &arkham);
  let (proxy_addr, proxy) = run_proxy_with(state).await;

  let stub_task = tokio::spawn(async move {
    let first = accept_ping(&stub, config_a).await;
    let second = accept_ping(&stub, config_b).await;
    (first, second)
  });

  ping(proxy_addr, stub_port, &arkham, &guest_a, &guest_key_a).await;
  ping(proxy_addr, stub_port, &arkham, &guest_b, &guest_key_b).await;
  let (first, second) = stub_task.await.unwrap();
  assert_eq!(first.as_ref(), client_a.first().unwrap().as_ref());
  assert_eq!(second.as_ref(), client_b.first().unwrap().as_ref());
  proxy.abort();
}

#[tokio::test]
async fn unknown_guest_certificate_does_not_dial() {
  install_crypto_provider();
  let arkham = CertAuthority::generate().unwrap();
  let cluster = CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let (client, key) = generate_client_pair(&cluster, "prod").unwrap();
  let (guest, _) = generate_client_pair(&arkham, "guest-prod").unwrap();
  let (unknown, unknown_key) = generate_client_pair(&arkham, "guest-other").unwrap();
  write_chain(&dir.path().join(format!("{LABEL_A}.client.crt")), &client);
  write_key(&dir.path().join(format!("{LABEL_A}.client.key")), &key);
  std::fs::write(dir.path().join(format!("{LABEL_A}.ca.crt")), cluster.cert_pem()).unwrap();
  write_chain(&dir.path().join(format!("{LABEL_A}.guest.crt")), &guest);

  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let state = test_state_with(vec![talos_grant(LABEL_A, stub_port, dir.path())], &arkham);
  let (proxy_addr, proxy) = run_proxy_with(state).await;

  let guest_tcp = connect_proxy(proxy_addr, stub_port).await;
  let connector = guest_connector(&arkham, &unknown, &unknown_key);
  let tls = connector
    .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest_tcp)
    .await
    .unwrap();
  let dialed = tokio::time::timeout(Duration::from_secs(2), stub.accept()).await;
  assert!(dialed.is_err(), "unknown certificate dialed upstream");
  drop(tls);
  proxy.abort();
}

#[tokio::test]
async fn missing_guest_certificate_does_not_dial() {
  install_crypto_provider();
  let arkham = CertAuthority::generate().unwrap();
  let cluster = CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let (client, key) = generate_client_pair(&cluster, "prod").unwrap();
  let (guest, _) = generate_client_pair(&arkham, "guest-prod").unwrap();
  write_chain(&dir.path().join(format!("{LABEL_A}.client.crt")), &client);
  write_key(&dir.path().join(format!("{LABEL_A}.client.key")), &key);
  std::fs::write(dir.path().join(format!("{LABEL_A}.ca.crt")), cluster.cert_pem()).unwrap();
  write_chain(&dir.path().join(format!("{LABEL_A}.guest.crt")), &guest);

  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let state = test_state_with(vec![talos_grant(LABEL_A, stub_port, dir.path())], &arkham);
  let (proxy_addr, proxy) = run_proxy_with(state).await;

  let guest_tcp = connect_proxy(proxy_addr, stub_port).await;
  let mut roots = rustls::RootCertStore::empty();
  roots.add(arkham.cert_der().clone()).unwrap();
  let mut config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
  config.alpn_protocols = vec![b"h2".to_vec()];
  let connector = TlsConnector::from(Arc::new(config));
  let _connected = connector
    .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest_tcp)
    .await;
  let dialed = tokio::time::timeout(Duration::from_secs(1), stub.accept()).await;
  assert!(dialed.is_err(), "missing certificate dialed upstream");
  proxy.abort();
}

fn talos_grant(label: &str, port: u16, dir: &Path) -> Grant {
  Grant::Token {
    credential: Credential {
      label: label.to_string(),
      fake: "fake".into(),
      value: secrecy::SecretString::from("value"),
    },
    allow: vec![EndpointScope {
      scheme: Scheme::Https,
      host: "localhost".parse().unwrap(),
      port,
      client_cert: Some(dir.join(format!("{label}.client.crt"))),
      client_key: Some(dir.join(format!("{label}.client.key"))),
      root_cert: Some(dir.join(format!("{label}.ca.crt"))),
      guest_tls: GuestTlsMode::Mtls,
    }],
    pattern: None,
    oauth2: None,
  }
}

fn server_config(trust: &rustls::RootCertStore, chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> rustls::ServerConfig {
  let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(trust.clone()))
    .build()
    .unwrap();
  let mut config = rustls::ServerConfig::builder()
    .with_client_cert_verifier(verifier)
    .with_single_cert(chain, key)
    .unwrap();
  config.alpn_protocols = vec![b"h2".to_vec()];
  config
}

fn write_chain(path: &Path, chain: &[CertificateDer<'static>]) {
  let mut pem = Vec::new();
  for cert in chain {
    pem.extend_from_slice(cert.to_pem().as_bytes());
  }
  std::fs::write(path, pem).unwrap();
}

fn write_key(path: &Path, key: &PrivateKeyDer<'static>) {
  std::fs::write(path, key.to_pem()).unwrap();
}

fn guest_connector(arkham: &CertAuthority, chain: &[CertificateDer<'static>], key: &PrivateKeyDer<'static>) -> TlsConnector {
  let mut roots = rustls::RootCertStore::empty();
  roots.add(arkham.cert_der().clone()).unwrap();
  let mut config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_client_auth_cert(chain.to_vec(), key.clone_key())
    .unwrap();
  config.alpn_protocols = vec![b"h2".to_vec()];
  TlsConnector::from(Arc::new(config))
}

async fn connect_proxy(proxy_addr: SocketAddr, stub_port: u16) -> TcpStream {
  let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
  guest
    .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut ok = [0u8; 19];
  guest.read_exact(&mut ok).await.unwrap();
  assert_eq!(&ok, b"HTTP/1.1 200 OK\r\n\r\n");
  guest
}

async fn ping(
  proxy_addr: SocketAddr,
  stub_port: u16,
  arkham: &CertAuthority,
  chain: &[CertificateDer<'static>],
  key: &PrivateKeyDer<'static>,
) {
  let guest = connect_proxy(proxy_addr, stub_port).await;
  let connector = guest_connector(arkham, chain, key);
  let mut tls = connector
    .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest)
    .await
    .unwrap();
  tls.write_all(b"talos-ping").await.unwrap();
  let mut pong = [0u8; 10];
  tls.read_exact(&mut pong).await.unwrap();
  assert_eq!(&pong, b"talos-pong");
}

async fn accept_ping(stub: &TcpListener, config: rustls::ServerConfig) -> CertificateDer<'static> {
  let (stream, _) = stub.accept().await.unwrap();
  let mut tls = TlsAcceptor::from(Arc::new(config)).accept(stream).await.unwrap();
  let peer = tls
    .get_ref()
    .1
    .peer_certificates()
    .and_then(|certs| certs.first().cloned())
    .unwrap();
  let mut ping = [0u8; 10];
  tls.read_exact(&mut ping).await.unwrap();
  assert_eq!(&ping, b"talos-ping");
  tls.write_all(b"talos-pong").await.unwrap();
  peer
}
