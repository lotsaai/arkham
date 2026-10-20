use super::*;

fn localhost_tcp_grant(port: u16, fake: &str, value: &str) -> Vec<Grant> {
  vec![Grant::Token {
    credential: Credential {
      label: "t".into(),
      fake: fake.into(),
      value: secrecy::SecretString::from(value.to_string()),
    },
    allow: vec![EndpointScope {
      scheme: Scheme::Tcp,
      host: "localhost".parse().unwrap(),
      port,
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls: arkham_config::grants::GuestTlsMode::Tls,

      upstream_port: None,
    }],
    pattern: None,
    oauth2: None,
  }]
}

#[tokio::test]
async fn tcp_only_grant_splices_tls_verbatim() {
  // A tcp:// grant on the TLS port must not trigger MITM: the handshake
  // passes through to the stub, fakes stay fakes, values stay values.
  const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
  const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";
  let fx = mitm_fixture(|port| localhost_tcp_grant(port, FAKE, VALUE)).await;
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
    assert!(head_str.contains(&format!("Authorization: Bearer {FAKE}\r\n")), "{head_str}");
    assert!(!head_str.contains(VALUE), "{head_str}");
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
  assert!(resp_str.contains(VALUE), "{resp_str}");
  let expect_body = format!("echo:{VALUE}");
  assert_eq!(read_body(&mut tls, &response, expect_body.len()).await, expect_body.as_bytes());
  stub_task.await.unwrap();
  proxy.abort();
}
