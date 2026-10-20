use super::*;

use bytes::Bytes;

#[tokio::test]
async fn mitm_terminates_both_ends_verbatim() {
  let fx = mitm_fixture(|port| localhost_grant(port, "fake", "value")).await;
  let MitmFixture {
    proxy_addr,
    proxy,
    stub,
    stub_port,
    stub_acceptor,
    connector,
  } = fx;
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = stub_acceptor.accept(conn).await.unwrap();
    let head = read_head_from(&mut tls).await;
    let head_str = String::from_utf8(head).unwrap();
    assert!(head_str.contains("Authorization: Bearer hello\r\n"), "{head_str}");
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
    tls.shutdown().await.unwrap();
  });
  let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  tls
    .write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer hello\r\n\r\n")
    .await
    .unwrap();
  let response = read_head_from(&mut tls).await;
  assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", response.escape_ascii());
  assert_eq!(read_body(&mut tls, &response, 2).await, b"hi");
  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn mitm_substitutes_request_and_redacts_response() {
  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  let fx = mitm_fixture(|port| localhost_grant(port, FAKE, VALUE)).await;
  let MitmFixture {
    proxy_addr,
    proxy,
    stub,
    stub_port,
    stub_acceptor,
    connector,
  } = fx;
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = stub_acceptor.accept(conn).await.unwrap();
    let head = read_head_from(&mut tls).await;
    let head_str = String::from_utf8(head).unwrap();
    assert!(head_str.contains(&format!("Authorization: Bearer {VALUE}\r\n")), "{head_str}");
    assert!(!head_str.contains(FAKE), "{head_str}");
    let body = format!("echo:{VALUE}");
    tls
      .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
      .await
      .unwrap();
    tls.shutdown().await.unwrap();
  });
  let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  tls
    .write_all(format!("GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let response = read_head_from(&mut tls).await;
  let resp_str = String::from_utf8_lossy(&response);
  assert!(!resp_str.contains(VALUE), "{resp_str}");
  let expect_body = format!("echo:{FAKE}");
  assert_eq!(read_body(&mut tls, &response, expect_body.len()).await, expect_body.as_bytes());
  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn connect_authority_sni_mismatch_closes_without_dial() {
  let fx = mitm_fixture(|port| localhost_grant(port, "fake", "value")).await;
  let MitmFixture {
    proxy_addr,
    proxy,
    stub,
    stub_port,
    connector,
    ..
  } = fx;
  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  client
    .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut head = vec![0u8; 19];
  tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
  // Authority says localhost, SNI says otherwise: the relay must close
  // quietly instead of minting, so the handshake fails on EOF.
  let server_name = ServerName::try_from("other.test".to_string()).unwrap();
  let handshake = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client)).await;
  let failed = match handshake {
    Err(_) | Ok(Err(_)) => true,
    Ok(Ok(_)) => false,
  };
  assert!(failed, "mismatched SNI must not complete a handshake");
  // No upstream dial happened: the stub accept still hangs.
  tokio::time::timeout(Duration::from_secs(2), stub.accept()).await.unwrap_err();
  proxy.abort();
}
#[tokio::test]
async fn non_candidate_splices_bytes_verbatim() {
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_addr = local_addr(&stub);
  let (proxy_addr, proxy) = run_proxy().await; // no grants: splice path
  let blob: Vec<u8> = (0..256u32).map(|i| u8::try_from(i % 251).expect("fits u8")).collect();
  let expect = blob.clone();
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let mut got = vec![0u8; expect.len()];
    conn.read_exact(&mut got).await.unwrap();
    assert_eq!(got, expect);
  });
  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  client
    .write_all(format!("CONNECT {stub_addr} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut head = vec![0u8; 19];
  tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
    .await
    .unwrap()
    .unwrap();
  client.write_all(&blob).await.unwrap();
  tokio::time::timeout(Duration::from_secs(5), stub_task).await.unwrap().unwrap();
  proxy.abort();
}

#[tokio::test]
async fn tls_through_splice_leaves_fake_untouched() {
  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  let fx = mitm_fixture(|_| Vec::new()).await; // no grants: splice, full TLS through
  let MitmFixture {
    proxy_addr,
    proxy,
    stub,
    stub_port,
    stub_acceptor,
    connector,
  } = fx;
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = stub_acceptor.accept(conn).await.unwrap();
    let head = read_head_from(&mut tls).await;
    let head_str = String::from_utf8(head).unwrap();
    assert!(head_str.contains(&format!("Bearer {FAKE}\r\n")), "{head_str}");
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
    tls.shutdown().await.unwrap();
  });
  let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  tls
    .write_all(format!("GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let response = read_head_from(&mut tls).await;
  assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", response.escape_ascii());
  assert_eq!(read_body(&mut tls, &response, 2).await, b"hi");
  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn https_scope_without_alpn_relays_raw() {
  // No ALPN agreed, so nothing proves the plaintext is HTTP and the pump
  // frames it raw: bytes swap in place, with no head parsed and none waited
  // for. That last part is what lets a non-HTTP protocol on an https scope
  // flow immediately instead of stalling on a head that never comes.
  const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
  const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";
  let fx = mitm_fixture_no_alpn(|port| localhost_grant(port, FAKE, VALUE)).await;
  let MitmFixture {
    proxy_addr,
    proxy,
    stub,
    stub_port,
    stub_acceptor,
    connector,
  } = fx;
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = stub_acceptor.accept(conn).await.unwrap();
    let mut auth = vec![0u8; 5 + VALUE.len() + 1];
    tls.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, format!("AUTH {VALUE}\n").into_bytes(), "upstream sees the real value");
    tls.write_all(format!("TOKEN {VALUE}\n").as_bytes()).await.unwrap();
  });
  let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  tls.write_all(format!("AUTH {FAKE}\n").as_bytes()).await.unwrap();
  let mut token = vec![0u8; 6 + VALUE.len() + 1];
  tls.read_exact(&mut token).await.unwrap();
  assert_eq!(token, format!("TOKEN {FAKE}\n").into_bytes(), "guest sees the fake back");
  stub_task.await.unwrap();
  proxy.abort();
}

/// The entry's `sslcert`/`sslkey` pair is the proxy's upstream client
/// identity: the stub demands a client certificate the arkham CA signed, and
/// the substitution round trip only completes when the egress leg presents
/// exactly the entry's.
#[tokio::test]
async fn https_entry_presents_its_client_identity_upstream() {
  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  use rama::crypto::pem::PemEncode as _;
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let (client_chain, client_key) = arkham_pki::ca::generate_client_pair(&ca, "arkham-client").unwrap();
  let mut cert_pem = Vec::new();
  for cert in &client_chain {
    cert_pem.extend_from_slice(cert.to_pem().as_bytes());
  }
  let cert_path = dir.path().join("client.pem");
  let key_path = dir.path().join("client.key");
  let bundle = dir.path().join("arkham-ca.pem");
  std::fs::write(&cert_path, &cert_pem).unwrap();
  std::fs::write(&key_path, client_key.to_pem()).unwrap();
  std::fs::write(&bundle, ca.cert_pem()).unwrap();

  let (server_chain, server_key) = arkham_pki::ca::generate_domain_pair(&ca, "localhost").unwrap();
  let mut client_roots = rustls::RootCertStore::empty();
  client_roots.add(ca.cert_der().clone()).unwrap();
  let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
    .build()
    .unwrap();
  let server_config = rustls::ServerConfig::builder()
    .with_client_cert_verifier(verifier)
    .with_single_cert(server_chain, server_key)
    .unwrap();
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let stub_task = tokio::spawn(async move {
    let (stream, _) = stub.accept().await.unwrap();
    let mut tls = TlsAcceptor::from(Arc::new(server_config)).accept(stream).await.unwrap();
    let peer = tls.get_ref().1.peer_certificates().and_then(|certs| certs.first().cloned());
    let head = read_head_from(&mut tls).await;
    assert!(head.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
    tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
    peer
  });

  let grants = vec![Grant::Token {
    credential: Credential {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE.to_string()),
    },
    allow: vec![EndpointScope {
      scheme: Scheme::Https,
      host: "localhost".parse().unwrap(),
      port: stub_port,
      client_cert: Some(cert_path.clone()),
      client_key: Some(key_path.clone()),
      root_cert: Some(bundle),
      guest_tls: arkham_config::grants::GuestTlsMode::Tls,
    }],
    pattern: None,
    oauth2: None,
  }];
  let state = test_state_with_plugins(grants, Vec::new(), &ca);
  let (proxy_addr, _proxy) = run_proxy_with(state).await;

  let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
  guest
    .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut ok = [0u8; 19];
  guest.read_exact(&mut ok).await.unwrap();
  assert_eq!(&ok, b"HTTP/1.1 200 OK\r\n\r\n");
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
  let mut tls = connector
    .connect(rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap(), guest)
    .await
    .unwrap();
  tls
    .write_all(format!("GET / HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let head = read_head_from(&mut tls).await;
  assert!(head.starts_with(b"HTTP/1.1 200 OK"));

  let peer = stub_task.await.unwrap();
  assert_eq!(peer.as_ref(), client_chain.first());
}

/// `root_cert` on an https entry: egress trusts the entry's private CA
/// bundle on top of the globals, so substitution works against hosts no
/// public CA signs. The stub's CA is standalone, never the arkham CA.
#[tokio::test]
async fn https_entry_root_cert_trusts_private_upstream_ca() {
  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let upstream_ca = CertAuthority::generate().unwrap();

  let (server_chain, server_key) = arkham_pki::ca::generate_domain_pair(&upstream_ca, "localhost").unwrap();
  let server_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(server_chain, server_key)
    .unwrap();
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
  let seen_later = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (stream, _) = stub.accept().await.unwrap();
    let mut tls = TlsAcceptor::from(Arc::new(server_config)).accept(stream).await.unwrap();
    let head = read_head_from(&mut tls).await;
    seen_later.lock().await.extend_from_slice(&head);
    tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
  });

  let dir = tempfile::tempdir().unwrap();
  let bundle = dir.path().join("upstream-ca.pem");
  std::fs::write(&bundle, upstream_ca.cert_pem()).unwrap();

  let grants = vec![Grant::Token {
    credential: Credential {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE.to_string()),
    },
    allow: vec![EndpointScope {
      scheme: Scheme::Https,
      host: "localhost".parse().unwrap(),
      port: stub_port,
      client_cert: None,
      client_key: None,
      root_cert: Some(bundle),
      guest_tls: arkham_config::grants::GuestTlsMode::Tls,
    }],
    pattern: None,
    oauth2: None,
  }];
  let state = test_state_with_plugins(grants, Vec::new(), &ca);
  let (proxy_addr, _proxy) = run_proxy_with(state).await;

  let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
  guest
    .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut ok = [0u8; 19];
  guest.read_exact(&mut ok).await.unwrap();
  assert_eq!(&ok, b"HTTP/1.1 200 OK\r\n\r\n");
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
  let mut tls = connector
    .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest)
    .await
    .unwrap();
  tls
    .write_all(format!("GET / HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let head = read_head_from(&mut tls).await;
  assert!(head.starts_with(b"HTTP/1.1 200 OK"));

  stub_task.await.unwrap();
  let seen = seen.lock().await;
  assert!(seen.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
}

/// Global `root_certs`: the bundle in `[proxy]` trusts the private-CA stub
/// for entries naming no `root_cert` of their own.
#[tokio::test]
async fn https_global_root_certs_trust_private_upstream_ca() {
  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let upstream_ca = CertAuthority::generate().unwrap();

  let (server_chain, server_key) = arkham_pki::ca::generate_domain_pair(&upstream_ca, "localhost").unwrap();
  let server_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(server_chain, server_key)
    .unwrap();
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
  let seen_later = Arc::clone(&seen);
  let stub_task = tokio::spawn(async move {
    let (stream, _) = stub.accept().await.unwrap();
    let mut tls = TlsAcceptor::from(Arc::new(server_config)).accept(stream).await.unwrap();
    let head = read_head_from(&mut tls).await;
    seen_later.lock().await.extend_from_slice(&head);
    tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
  });

  let dir = tempfile::tempdir().unwrap();
  let bundle = dir.path().join("upstream-ca.pem");
  std::fs::write(&bundle, upstream_ca.cert_pem()).unwrap();

  let grants = vec![Grant::Token {
    credential: Credential {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE.to_string()),
    },
    allow: vec![EndpointScope {
      scheme: Scheme::Https,
      host: "localhost".parse().unwrap(),
      port: stub_port,
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls: arkham_config::grants::GuestTlsMode::Tls,
    }],
    pattern: None,
    oauth2: None,
  }];
  let state = Arc::new(
    ProxyState::new(
      ResolvedConfig {
        proxy: arkham_config::config::ProxyCfg {
          listen: "127.0.0.1:0".parse().unwrap(),
          ca_file: None,
          root_certs: vec![bundle],
          ssh_host_key: None,
          ssh_known_hosts: None,
          handshake_timeout_secs: 10,
        },
        grants,
        plugins: Vec::new(),
      },
      &ca,
    )
    .unwrap(),
  );
  let (proxy_addr, _proxy) = run_proxy_with(state).await;

  let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
  guest
    .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut ok = [0u8; 19];
  guest.read_exact(&mut ok).await.unwrap();
  assert_eq!(&ok, b"HTTP/1.1 200 OK\r\n\r\n");
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
  let mut tls = connector
    .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest)
    .await
    .unwrap();
  tls
    .write_all(format!("GET / HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let head = read_head_from(&mut tls).await;
  assert!(head.starts_with(b"HTTP/1.1 200 OK"));

  stub_task.await.unwrap();
  let seen = seen.lock().await;
  assert!(seen.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
}

/// Same private-CA stub without `root_cert`: egress fails closed at the
/// upstream handshake, so the guest never gets a response head.
#[tokio::test]
async fn https_without_root_cert_fails_closed_on_private_upstream_ca() {
  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let upstream_ca = CertAuthority::generate().unwrap();

  let (server_chain, server_key) = arkham_pki::ca::generate_domain_pair(&upstream_ca, "localhost").unwrap();
  let server_config = Arc::new(
    rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(server_chain, server_key)
      .unwrap(),
  );
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  tokio::spawn(async move {
    loop {
      let Ok((stream, _)) = stub.accept().await else { return };
      let acceptor = TlsAcceptor::from(Arc::clone(&server_config));
      tokio::spawn(async move {
        let Ok(mut tls) = acceptor.accept(stream).await else { return };
        let _ = read_head_from(&mut tls).await;
      });
    }
  });

  let grants = vec![Grant::Token {
    credential: Credential {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from("real".to_string()),
    },
    allow: vec![EndpointScope {
      scheme: Scheme::Https,
      host: "localhost".parse().unwrap(),
      port: stub_port,
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls: arkham_config::grants::GuestTlsMode::Tls,
    }],
    pattern: None,
    oauth2: None,
  }];
  let state = test_state_with_plugins(grants, Vec::new(), &ca);
  let (proxy_addr, _proxy) = run_proxy_with(state).await;

  let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
  guest
    .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut ok = [0u8; 19];
  guest.read_exact(&mut ok).await.unwrap();
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
  let Ok(mut tls) = connector
    .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest)
    .await
  else {
    return;
  };
  tls
    .write_all(format!("GET / HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut chunk = [0u8; 4096];
  let closed = match tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk)).await {
    Err(_) | Ok(Err(_) | Ok(0)) => true,
    Ok(Ok(_)) => false,
  };
  assert!(closed, "egress to an untrusted upstream must fail closed");
}

/// `guest_tls_mode = "mtls"` on an https entry: arkham demands a client
/// certificate from the guest and admits only ones its own CA signs.
///
/// TLS 1.3 hands the guest the server Finished before the server
/// validates the guest certificate, so a refused guest's `connect` can
/// still return `Ok` — the refusal surfaces on the read after, never in
/// the connect result. The assertion point is therefore the request
/// round trip, not the handshake.
#[tokio::test]
#[expect(clippy::too_many_lines, reason = "linear test script, split would obscure the flow")]
async fn https_guest_mtls_admits_only_ca_signed_guests() {
  // CONNECT, guest TLS, one GET, then read until the response head is
  // whole; a refused guest never gets that far.
  async fn guest_round_trip(
    proxy_addr: SocketAddr,
    stub_port: u16,
    config: Arc<rustls::ClientConfig>,
    token: &'static str,
  ) -> std::io::Result<Vec<u8>> {
    let mut guest = TcpStream::connect(proxy_addr).await?;
    guest
      .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
      .await?;
    let mut ok = [0u8; 19];
    guest.read_exact(&mut ok).await?;
    let mut tls = TlsConnector::from(config)
      .connect(rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap(), guest)
      .await?;
    tls
      .write_all(format!("GET / HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\r\n").as_bytes())
      .await?;
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
      let n = match tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk)).await {
        Ok(read) => read?,
        Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no answer")),
      };
      if n == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "refused"));
      }
      head.extend_from_slice(&chunk[..n]);
      if head.windows(4).any(|w| w == b"\r\n\r\n") {
        return Ok(head);
      }
    }
  }
  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let bundle = dir.path().join("arkham-ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();

  let (server_chain, server_key) = arkham_pki::ca::generate_domain_pair(&ca, "localhost").unwrap();
  let server_config = Arc::new(
    rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(server_chain, server_key)
      .unwrap(),
  );
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
  let seen_later = Arc::clone(&seen);
  // One upstream connection per guest attempt (the relay dials upstream
  // before answering the guest); refused guests leave the handler on
  // EOF or timeout instead of an HTTP exchange.
  let stub_task = tokio::spawn(async move {
    loop {
      let Ok((conn, _)) = stub.accept().await else { return };
      let seen = Arc::clone(&seen);
      let acceptor = TlsAcceptor::from(Arc::clone(&server_config));
      tokio::spawn(async move {
        let Ok(mut tls) = acceptor.accept(conn).await else { return };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
          let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk)).await else {
            return;
          };
          if n == 0 {
            return;
          }
          buf.extend_from_slice(&chunk[..n]);
          if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
          }
        }
        seen.lock().await.extend(buf);
        tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
      });
    }
  });

  let grants = vec![Grant::Token {
    credential: Credential {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE.to_string()),
    },
    allow: vec![EndpointScope {
      scheme: Scheme::Https,
      host: "localhost".parse().unwrap(),
      port: stub_port,
      client_cert: None,
      client_key: None,
      root_cert: Some(bundle),
      guest_tls: arkham_config::grants::GuestTlsMode::Mtls,
    }],
    pattern: None,
    oauth2: None,
  }];
  let state = test_state_with_plugins(grants, Vec::new(), &ca);
  let (proxy_addr, _proxy) = run_proxy_with(state).await;

  // CA-signed guest: full round trip with fake-to-real substitution.
  let (chain, key) = arkham_pki::ca::generate_client_pair(&ca, "guest").unwrap();
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let mut config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_client_auth_cert(chain, key)
    .unwrap();
  config.alpn_protocols = vec![b"http/1.1".to_vec()];
  let head = guest_round_trip(proxy_addr, stub_port, Arc::new(config), FAKE).await.unwrap();
  assert!(head.starts_with(b"HTTP/1.1 200 OK"));
  assert!(seen_later.lock().await.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));

  // Certless guest: refused — the read after connect dies.
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  guest_round_trip(proxy_addr, stub_port, guest_client_config(roots, Alpn::Http1), FAKE)
    .await
    .expect_err("the certless guest must not round-trip");

  // Guest with a certificate arkham's CA did not sign: refused too.
  let stranger = CertAuthority::generate().unwrap();
  let (chain, key) = arkham_pki::ca::generate_client_pair(&stranger, "guest").unwrap();
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let mut config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_client_auth_cert(chain, key)
    .unwrap();
  config.alpn_protocols = vec![b"http/1.1".to_vec()];
  guest_round_trip(proxy_addr, stub_port, Arc::new(config), FAKE)
    .await
    .expect_err("an untrusted guest must not round-trip");

  stub_task.abort();
}

#[tokio::test]
async fn mitm_h2_substitutes_headers() {
  use httlib_hpack::{Decoder, Encoder};

  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  let fx = mitm_fixture_h2(|port| localhost_grant(port, FAKE, VALUE)).await;
  let MitmFixture {
    proxy_addr,
    proxy,
    stub,
    stub_port,
    stub_acceptor,
    connector,
  } = fx;

  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = stub_acceptor.accept(conn).await.unwrap();
    // Raw preface + HEADERS arrive; upstream HPACK-decodes the value.
    let mut preface = [0u8; 24];
    tls.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let mut hdr = [0u8; 9];
    tls.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[3], 0x1, "expected HEADERS");
    assert_eq!(u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff, 1);
    let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
    let mut block = vec![0u8; len];
    tls.read_exact(&mut block).await.unwrap();
    let mut decoder = Decoder::default();
    let mut headers = Vec::new();
    decoder.decode(&mut block, &mut headers).unwrap();
    let auth = headers.iter().find(|(name, _, _)| name == b"authorization").unwrap();
    assert_eq!(auth.1, format!("Bearer {VALUE}").as_bytes());
    tls.shutdown().await.unwrap();
  });

  let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  let mut encoder = Encoder::default();
  let mut block = Vec::new();
  for (name, value) in [
    (":method", "GET"),
    (":scheme", "https"),
    (":path", "/"),
    (":authority", "localhost"),
    ("authorization", &format!("Bearer {FAKE}")),
  ] {
    encoder
      .encode(
        (name.as_bytes().to_vec(), value.as_bytes().to_vec(), Encoder::NEVER_INDEXED),
        &mut block,
      )
      .unwrap();
  }
  let mut frame = Vec::from(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
  let len = u32::try_from(block.len()).unwrap();
  frame.extend_from_slice(&len.to_be_bytes()[1..]);
  frame.extend_from_slice(&[0x1, 0x4 | 0x1, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS|END_STREAM
  frame.extend_from_slice(&block);
  tls.write_all(&frame).await.unwrap();
  tls.flush().await.unwrap();
  // Stub shuts down after asserting; EOF ends the test race-free.
  let mut one = [0u8; 1];
  assert_eq!(tls.read(&mut one).await.unwrap(), 0);
  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn transparent_tls_mitm_substitutes_by_sni_identity() {
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
      guest_tls: arkham_config::grants::GuestTlsMode::Tls,
    }],
    pattern: None,
    oauth2: None,
  }];
  let state = test_state_with(grants, &ca);
  let snapshot = state.snapshot();
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = stub_acceptor.accept(conn).await.unwrap();
    let head = read_head_from(&mut tls).await;
    let head_str = String::from_utf8(head).unwrap();
    assert!(head_str.contains(&format!("Bearer {VALUE}")), "{head_str}");
    let body = format!("echo:{VALUE}");
    tls
      .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
      .await
      .unwrap();
  });
  let (guest, client_end) = tokio::io::duplex(64 * 1024);
  let serve = tokio::spawn({
    let state = Arc::clone(&state);
    let snapshot = Arc::clone(&snapshot);
    // TUN shape: dial target is an address, the SNI alone is the identity.
    async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
  });
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca_der).unwrap();
  let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
  let server_name = ServerName::try_from(SNI.to_string()).unwrap();
  let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client_end))
    .await
    .unwrap()
    .unwrap();
  tls
    .write_all(format!("GET /x HTTP/1.1\r\nHost: {SNI}\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  stub_task.await.unwrap();
  let mut response = Vec::new();
  let mut chunk = [0u8; 4096];
  loop {
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
      .await
      .unwrap()
      .unwrap();
    response.extend_from_slice(&chunk[..n]);
    if response.windows(4).any(|w| w == b"\r\n\r\n") {
      break;
    }
  }
  let head_end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
  let expect = format!("echo:{FAKE}");
  let mut body = Vec::from(&response[head_end..]);
  while body.len() < expect.len() {
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
      .await
      .unwrap()
      .unwrap();
    body.extend_from_slice(&chunk[..n]);
  }
  assert_eq!(body, expect.as_bytes());
  serve.await.unwrap().unwrap();
}

#[tokio::test]
async fn transparent_tls_mitm_uses_captured_ip_when_hello_has_no_sni() {
  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let upstream_ca = CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let bundle = dir.path().join("upstream-ca.pem");
  std::fs::write(&bundle, upstream_ca.cert_pem()).unwrap();
  let ca_der = ca.cert_der().clone();
  let stub_cert = upstream_ca.generate_domain_cert("127.0.0.1").unwrap();
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
      host: "127.0.0.1".parse().unwrap(),
      port: stub_port,
      client_cert: None,
      client_key: None,
      root_cert: Some(bundle),
      guest_tls: arkham_config::grants::GuestTlsMode::Tls,
    }],
    pattern: None,
    oauth2: None,
  }];
  let state = test_state_with(grants, &ca);
  let snapshot = state.snapshot();
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = stub_acceptor.accept(conn).await.unwrap();
    let head = read_head_from(&mut tls).await;
    let head_str = String::from_utf8(head).unwrap();
    assert!(head_str.contains(&format!("Bearer {VALUE}")), "{head_str}");
    let body = format!("echo:{VALUE}");
    tls
      .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
      .await
      .unwrap();
  });
  let (guest, client_end) = tokio::io::duplex(64 * 1024);
  let serve = tokio::spawn({
    let state = Arc::clone(&state);
    let snapshot = Arc::clone(&snapshot);
    // IP-literal client: the captured destination is the identity.
    async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
  });
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca_der).unwrap();
  let connector = TlsConnector::from(guest_client_config(roots, Alpn::Http1));
  // IpAddress sends no SNI extension, like kubectl against an address.
  let server_name = ServerName::IpAddress("127.0.0.1".parse::<IpAddr>().unwrap().into());
  let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client_end))
    .await
    .unwrap()
    .unwrap();
  tls
    .write_all(format!("GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  stub_task.await.unwrap();
  let head = read_head_from(&mut tls).await;
  let expect = format!("echo:{FAKE}");
  assert_eq!(read_body(&mut tls, &head, expect.len()).await, expect.as_bytes());
  serve.await.unwrap().unwrap();
}
/// Real h2 client and real h2 server through the MITM, needle split across
/// DATA frames in both directions. h2 is a full HTTP/2 implementation: it
/// judges the HPACK blocks arkham re-encodes and the frame framing it emits.
#[tokio::test]
async fn http2_real_client_and_server_round_trip_split_data() {
  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  let fx = mitm_fixture_h2(|port| localhost_grant(port, FAKE, VALUE)).await;
  let MitmFixture {
    proxy_addr,
    proxy,
    stub,
    stub_port,
    stub_acceptor,
    connector,
  } = fx;

  let stub_task: tokio::task::JoinHandle<Result<(), String>> = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.map_err(|err| format!("accept: {err}"))?;
    let tls = stub_acceptor.accept(conn).await.map_err(|err| format!("tls: {err}"))?;
    let mut server = h2::server::handshake(tls).await.map_err(|err| format!("h2 handshake: {err}"))?;
    let Some(result) = server.accept().await else {
      return Err(String::from("no request"));
    };
    let (request, mut respond) = result.map_err(|err| format!("accept request: {err}"))?;
    let (parts, mut body) = request.into_parts();
    let mut received = Vec::new();
    while let Some(chunk) = body.data().await {
      match chunk {
        Ok(chunk) => received.extend_from_slice(&chunk),
        Err(err) => return Err(format!("body: {err}")),
      }
    }
    let auth = parts
      .headers
      .get("authorization")
      .map(|value| value.to_str().unwrap_or("?").to_string());
    let response = hyper::Response::builder().status(200).body(()).unwrap();
    let mut stream = respond.send_response(response, false).map_err(|err| format!("respond: {err}"))?;
    let reply = format!("download:{VALUE}");
    let (first, second) = reply.as_bytes().split_at(12);
    stream
      .send_data(Bytes::copy_from_slice(first), false)
      .map_err(|err| format!("send reply 1: {err}"))?;
    stream
      .send_data(Bytes::copy_from_slice(second), true)
      .map_err(|err| format!("send reply 2: {err}"))?;
    // h2 flushes writes by driving the connection, so give it a bounded turn
    // rather than relying on what a drop happens to do with the buffer.
    let _ = tokio::time::timeout(Duration::from_millis(300), server.accept()).await;
    if auth.as_deref() != Some(format!("Bearer {VALUE}").as_str()) {
      return Err(format!("authorization header is {auth:?}"));
    }
    if received != format!("upload:{VALUE}").as_bytes() {
      return Err(format!("request body is {:?}", String::from_utf8_lossy(&received)));
    }
    Ok(())
  });

  let tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  let (mut sender, conn) = h2::client::handshake(tls).await.unwrap();
  let client_task = tokio::spawn(async move {
    let _ = conn.await;
  });
  let request = hyper::Request::builder()
    .method("POST")
    .uri("https://localhost/x")
    .header("authorization", format!("Bearer {FAKE}"))
    .body(())
    .unwrap();
  let (response, mut stream) = sender.send_request(request, false).unwrap();
  let upload = format!("upload:{FAKE}");
  let (first, second) = upload.as_bytes().split_at(12);
  stream.send_data(Bytes::copy_from_slice(first), false).unwrap();
  stream.send_data(Bytes::copy_from_slice(second), true).unwrap();
  let response = tokio::time::timeout(Duration::from_secs(10), response).await.unwrap().unwrap();
  assert_eq!(response.status(), 200);
  let mut body = response.into_body();
  let mut received = Vec::new();
  while let Some(chunk) = body.data().await {
    received.extend_from_slice(&chunk.unwrap());
  }
  assert_eq!(String::from_utf8(received).unwrap(), format!("download:{FAKE}"));
  // The stub's report is the assertion that substitution reached the
  // upstream, so await it rather than ending the test on the client alone.
  let stub_result = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  client_task.abort();
  stub_result.unwrap().unwrap().unwrap();
  proxy.abort();
}

struct SharedPairs {
  client_cert: std::path::PathBuf,
  client_key: std::path::PathBuf,
  bundle: std::path::PathBuf,
  bearer_bundle: std::path::PathBuf,
  expected_leaf: rustls::pki_types::CertificateDer<'static>,
  guest_pem: std::path::PathBuf,
  guest_key: std::path::PathBuf,
}

/// Certificate grant files plus a second copy of the same CA. The two bundle
/// paths are how a declared kubeconfig and an ambient one name one cluster.
fn shared_pairs(ca: &CertAuthority, dir: &std::path::Path) -> SharedPairs {
  use arkham_pki::ca::{generate_client_pair, load_or_generate_client_pair};
  use rama::crypto::pem::PemEncode as _;

  let (upstream_chain, upstream_key) = generate_client_pair(ca, "upstream-user").unwrap();
  let mut upstream_pem = Vec::new();
  for cert in &upstream_chain {
    upstream_pem.extend_from_slice(cert.to_pem().as_bytes());
  }
  let client_cert = dir.join("kube-user-shared.client.crt");
  let client_key = dir.join("kube-user-shared.client.key");
  std::fs::write(&client_cert, &upstream_pem).unwrap();
  std::fs::write(&client_key, upstream_key.to_pem()).unwrap();
  let (guest_pem, guest_key) = load_or_generate_client_pair(ca, dir, "kube-user-shared").unwrap();
  std::fs::copy(&guest_pem, dir.join("kube-user-shared.guest.crt")).unwrap();
  let bundle = dir.join("ca.pem");
  let bearer_bundle = dir.join("ca-bearer.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  std::fs::write(&bearer_bundle, ca.cert_pem()).unwrap();
  SharedPairs {
    client_cert,
    client_key,
    bundle,
    bearer_bundle,
    expected_leaf: upstream_chain.into_iter().next().unwrap(),
    guest_pem,
    guest_key,
  }
}

fn https_scope(
  port: u16,
  guest_tls: GuestTlsMode,
  cert: Option<std::path::PathBuf>,
  key: Option<std::path::PathBuf>,
  root: std::path::PathBuf,
) -> EndpointScope {
  EndpointScope {
    scheme: Scheme::Https,
    host: "localhost".parse().unwrap(),
    port,
    client_cert: cert,
    client_key: key,
    root_cert: Some(root),
    guest_tls,
  }
}

fn https_grant(label: &str, fake: &str, value: &str, scope: EndpointScope) -> Grant {
  Grant::Token {
    credential: Credential {
      label: label.into(),
      fake: fake.into(),
      value: secrecy::SecretString::from(value.to_string()),
    },
    allow: vec![scope],
    pattern: None,
    oauth2: None,
  }
}

fn guest_connector(ca: &CertAuthority, guest_pem: &std::path::Path, guest_key: &std::path::Path) -> TlsConnector {
  use rustls::pki_types::pem::PemObject as _;
  use rustls::pki_types::{CertificateDer, PrivateKeyDer};

  let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(guest_pem)
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let key = PrivateKeyDer::from_pem_file(guest_key).unwrap();
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let mut config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_client_auth_cert(chain, key)
    .unwrap();
  config.alpn_protocols = vec![b"http/1.1".to_vec()];
  TlsConnector::from(Arc::new(config))
}

/// Two https grants share a destination and name the same CA from different
/// files. The presented guest certificate selects the certificate grant, and
/// upstream sees that grant's client pair.
#[tokio::test]
async fn https_shared_destination_selects_the_presented_guest_cert() {
  use arkham_pki::ca::generate_domain_pair;

  const CERT_FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const CERT_VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const BEARER_FAKE: &str = "ghp_cccccccccccccccccccccccccccccccccccccccc";
  const BEARER_VALUE: &str = "ghp_dddddddddddddddddddddddddddddddddddddddd";

  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let pairs = shared_pairs(&ca, dir.path());

  let (server_chain, server_key) = generate_domain_pair(&ca, "localhost").unwrap();
  let mut trust = rustls::RootCertStore::empty();
  trust.add(ca.cert_der().clone()).unwrap();
  let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(trust))
    .allow_unauthenticated()
    .build()
    .unwrap();
  let server_config = Arc::new(
    rustls::ServerConfig::builder()
      .with_client_cert_verifier(verifier)
      .with_single_cert(server_chain, server_key)
      .unwrap(),
  );
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let expected_leaf = pairs.expected_leaf.clone();
  let stub_task = tokio::spawn(async move {
    let (stream, _) = stub.accept().await.unwrap();
    let mut tls = TlsAcceptor::from(server_config).accept(stream).await.unwrap();
    let peer = tls.get_ref().1.peer_certificates().and_then(|certs| certs.first().cloned());
    let head = read_head_from(&mut tls).await;
    tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
    (peer, head)
  });

  let grants = vec![
    https_grant(
      "cert-user",
      CERT_FAKE,
      CERT_VALUE,
      https_scope(
        stub_port,
        GuestTlsMode::Mtls,
        Some(pairs.client_cert),
        Some(pairs.client_key),
        pairs.bundle,
      ),
    ),
    https_grant(
      "bearer-user",
      BEARER_FAKE,
      BEARER_VALUE,
      https_scope(stub_port, GuestTlsMode::Tls, None, None, pairs.bearer_bundle),
    ),
  ];
  let state = test_state_with_plugins(grants, Vec::new(), &ca);
  let (proxy_addr, proxy) = run_proxy_with(state).await;
  let connector = guest_connector(&ca, &pairs.guest_pem, &pairs.guest_key);

  let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
  guest
    .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut ok = [0u8; 19];
  guest.read_exact(&mut ok).await.unwrap();
  assert_eq!(&ok, b"HTTP/1.1 200 OK\r\n\r\n");
  let mut tls = connector
    .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest)
    .await
    .unwrap();
  tls.write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n").await.unwrap();
  let head = read_head_from(&mut tls).await;
  assert!(head.starts_with(b"HTTP/1.1 200 OK"), "{}", head.escape_ascii());
  let (peer, upstream_head) = stub_task.await.unwrap();
  assert_eq!(
    peer.as_ref(),
    Some(&expected_leaf),
    "upstream sees the certificate grant's client pair"
  );
  assert!(
    !upstream_head
      .windows(BEARER_VALUE.len())
      .any(|window| window == BEARER_VALUE.as_bytes()),
    "the bearer grant's secret must not ride a certificate-selected connection"
  );
  proxy.abort();
}

const CERT_FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CERT_VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const BEARER_FAKE: &str = "ghp_cccccccccccccccccccccccccccccccccccccccc";
const BEARER_VALUE: &str = "ghp_dddddddddddddddddddddddddddddddddddddddd";

fn anonymous_connector(ca: &CertAuthority) -> TlsConnector {
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let mut config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
  config.alpn_protocols = vec![b"http/1.1".to_vec()];
  TlsConnector::from(Arc::new(config))
}

fn shared_server(ca: &CertAuthority) -> Arc<rustls::ServerConfig> {
  use arkham_pki::ca::generate_domain_pair;

  let (server_chain, server_key) = generate_domain_pair(ca, "localhost").unwrap();
  let mut trust = rustls::RootCertStore::empty();
  trust.add(ca.cert_der().clone()).unwrap();
  let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(trust))
    .allow_unauthenticated()
    .build()
    .unwrap();
  Arc::new(
    rustls::ServerConfig::builder()
      .with_client_cert_verifier(verifier)
      .with_single_cert(server_chain, server_key)
      .unwrap(),
  )
}

fn shared_grants(port: u16, pairs: &SharedPairs) -> Vec<Grant> {
  vec![
    https_grant(
      "cert-user",
      CERT_FAKE,
      CERT_VALUE,
      https_scope(
        port,
        GuestTlsMode::Mtls,
        Some(pairs.client_cert.clone()),
        Some(pairs.client_key.clone()),
        pairs.bundle.clone(),
      ),
    ),
    https_grant(
      "bearer-user",
      BEARER_FAKE,
      BEARER_VALUE,
      https_scope(port, GuestTlsMode::Tls, None, None, pairs.bearer_bundle.clone()),
    ),
  ]
}

async fn exchange(
  state: Arc<ProxyState>,
  stub: TcpListener,
  server: Arc<rustls::ServerConfig>,
  connector: TlsConnector,
  port: u16,
  request: &[u8],
) -> (Vec<u8>, Option<rustls::pki_types::CertificateDer<'static>>) {
  let stub_task = tokio::spawn(async move {
    let (stream, _) = stub.accept().await.unwrap();
    let mut tls = TlsAcceptor::from(server).accept(stream).await.unwrap();
    let peer = tls.get_ref().1.peer_certificates().and_then(|certs| certs.first().cloned());
    let head = read_head_from(&mut tls).await;
    tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
    (peer, head)
  });
  let (proxy_addr, proxy) = run_proxy_with(state).await;
  let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
  guest
    .write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut ok = [0u8; 19];
  guest.read_exact(&mut ok).await.unwrap();
  assert_eq!(&ok, b"HTTP/1.1 200 OK\r\n\r\n");
  let mut tls = connector
    .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest)
    .await
    .unwrap();
  tls.write_all(request).await.unwrap();
  let head = read_head_from(&mut tls).await;
  assert!(head.starts_with(b"HTTP/1.1 200 OK"), "{}", head.escape_ascii());
  let (peer, upstream) = stub_task.await.unwrap();
  proxy.abort();
  (upstream, peer)
}

/// No client certificate selects the bearer grant. The files are removed
/// after the proxy state is built, so a later connection cannot be reading
/// them again.
#[tokio::test]
async fn https_without_a_certificate_sends_the_bearer_secret() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let pairs = shared_pairs(&ca, dir.path());
  let server = shared_server(&ca);
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = stub.local_addr().unwrap().port();
  let grants = shared_grants(port, &pairs);
  let connector = anonymous_connector(&ca);
  let state = test_state_with_plugins(grants, Vec::new(), &ca);
  for path in [
    &pairs.client_cert,
    &pairs.client_key,
    &pairs.bundle,
    &pairs.bearer_bundle,
    &dir.path().join("kube-user-shared.guest.crt"),
  ] {
    std::fs::remove_file(path).unwrap();
  }
  let request = format!("GET / HTTP/1.1\r\nhost: localhost\r\nAuthorization: Bearer {BEARER_FAKE}\r\n\r\n");
  let (upstream, peer) = exchange(state, stub, server, connector, port, request.as_bytes()).await;
  assert!(peer.is_none(), "a bearer grant presents no client certificate");
  assert!(
    upstream.windows(BEARER_VALUE.len()).any(|window| window == BEARER_VALUE.as_bytes()),
    "upstream must see the bearer secret: {}",
    upstream.escape_ascii()
  );
  assert!(
    !upstream.windows(CERT_VALUE.len()).any(|window| window == CERT_VALUE.as_bytes()),
    "the certificate grant's secret must stay off this connection"
  );
}

/// Sending the certificate grant's decoy as a bearer, with no client
/// certificate, must not substitute that grant's real secret.
#[tokio::test]
async fn https_without_a_certificate_keeps_the_mtls_secret() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let pairs = shared_pairs(&ca, dir.path());
  let server = shared_server(&ca);
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = stub.local_addr().unwrap().port();
  let state = test_state_with_plugins(shared_grants(port, &pairs), Vec::new(), &ca);
  let request = format!("GET / HTTP/1.1\r\nhost: localhost\r\nAuthorization: Bearer {CERT_FAKE}\r\n\r\n");
  let (upstream, _) = exchange(state, stub, server, anonymous_connector(&ca), port, request.as_bytes()).await;
  assert!(
    !upstream.windows(CERT_VALUE.len()).any(|window| window == CERT_VALUE.as_bytes()),
    "mtls secret leaked without a client certificate: {}",
    upstream.escape_ascii()
  );
  assert!(
    upstream.windows(CERT_FAKE.len()).any(|window| window == CERT_FAKE.as_bytes()),
    "the unmatched decoy stays literal: {}",
    upstream.escape_ascii()
  );
}

/// A certificate this CA signed, which no grant's guest leaf is, is closed
/// before a request completes. The upstream request must not carry the
/// certificate grant's secret.
#[tokio::test]
async fn https_unknown_client_certificate_fails_the_handshake() {
  use arkham_pki::ca::load_or_generate_client_pair;

  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let pairs = shared_pairs(&ca, dir.path());
  let (other_pem, other_key) = load_or_generate_client_pair(&ca, dir.path(), "kube-user-other").unwrap();
  let connector = guest_connector(&ca, &other_pem, &other_key);
  let server = shared_server(&ca);
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = stub.local_addr().unwrap().port();
  let state = test_state_with_plugins(shared_grants(port, &pairs), Vec::new(), &ca);
  let stub_task = tokio::spawn(async move {
    let accepted = tokio::time::timeout(Duration::from_secs(3), stub.accept()).await;
    let Ok(Ok((stream, _))) = accepted else {
      return None;
    };
    let upstream = tokio::time::timeout(Duration::from_secs(2), async move {
      let mut tls = TlsAcceptor::from(server).accept(stream).await.ok()?;
      Some(read_head_from(&mut tls).await)
    })
    .await;
    upstream.ok().flatten()
  });
  let (proxy_addr, proxy) = run_proxy_with(state).await;
  let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
  guest
    .write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut ok = [0u8; 19];
  guest.read_exact(&mut ok).await.unwrap();
  assert_eq!(&ok, b"HTTP/1.1 200 OK\r\n\r\n");
  let connected = connector
    .connect(ServerName::try_from("localhost".to_string()).unwrap(), guest)
    .await;
  let exchanged = match connected {
    Err(_) => false,
    Ok(mut tls) => {
      use tokio::io::AsyncReadExt as _;
      if tls.write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n").await.is_err() {
        false
      } else {
        let mut buf = [0u8; 8];
        let got = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
        matches!(got, Ok(Ok(n)) if n > 0 && buf[..n].starts_with(b"HTTP/"))
      }
    }
  };
  assert!(!exchanged, "an unknown client certificate must not complete a request");
  if let Some(head) = stub_task.await.unwrap() {
    assert!(
      !head.windows(CERT_VALUE.len()).any(|window| window == CERT_VALUE.as_bytes()),
      "unknown certificate must not swap in the mtls secret"
    );
  }
  proxy.abort();
}
