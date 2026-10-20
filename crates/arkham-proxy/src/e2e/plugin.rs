use super::*;

/// Hook that votes `Close` on every call.
struct CloseHook;

impl arkham_plugin::RewriteHook for CloseHook {
  fn rewrite_head<'a>(&'a mut self, _head: &'a mut arkham_plugin::Head) -> arkham_plugin::BoxFuture<'a, arkham_plugin::Verdict> {
    Box::pin(async move { arkham_plugin::Verdict::Close })
  }

  fn rewrite_trailers<'a>(
    &'a mut self,
    _headers: &'a mut Vec<arkham_plugin::Header>,
  ) -> arkham_plugin::BoxFuture<'a, arkham_plugin::Verdict> {
    Box::pin(async move { arkham_plugin::Verdict::Close })
  }

  fn rewrite_chunk<'a>(&'a mut self, _data: &'a mut Vec<u8>, _eof: bool) -> arkham_plugin::BoxFuture<'a, arkham_plugin::Verdict> {
    Box::pin(async move { arkham_plugin::Verdict::Close })
  }
}

#[tokio::test]
async fn plugin_e2e_close_verdict_drops_connection() {
  let (guest_end, mut client_end) = tokio::io::duplex(64 * 1024);
  let (server_end, mut stub_end) = tokio::io::duplex(64 * 1024);
  let (mut request, mut response) = (
    Http::new(&[], Scheme::Http, "x", 80, Direction::Downstream, Some(Box::new(CloseHook)), None),
    Http::new(&[], Scheme::Http, "x", 80, Direction::Upstream, None, None),
  );
  let (relay_out, ()) = tokio::join!(relay_guarded(guest_end, server_end, &mut request, &mut response, b"", b""), async {
    client_end.write_all(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
  });
  relay_out.unwrap();
  assert!(matches!(request.feed(&[]).await, (Rewritten::Close, _)));
  // The latched head never reached the wire: upstream sees nothing.
  // The relay already returned, dropping its server half, so the read
  // resolves as EOF — zero bytes means `Ok(0)`, a leak would be `Ok(n)`.
  let mut buf = [0u8; 64];
  let n = stub_end.read(&mut buf).await.unwrap();
  assert_eq!(n, 0, "upstream must receive zero bytes");
}

/// Fixture component path, or `None` when `ARKHAM_PLUGIN_FIXTURES` is unset
/// or the fixture was not built (`mise run build:plugins` first).
fn plugin_fixture(name: &str) -> Option<std::path::PathBuf> {
  let path = std::path::PathBuf::from(std::env::var_os("ARKHAM_PLUGIN_FIXTURES")?).join(format!("{name}.wasm"));
  path.is_file().then_some(path)
}

/// Plugin allow list mirroring [`localhost_grant`]: the MITM leg selects
/// hooks with the same identity the machine receives.
fn plugin_allow(port: u16) -> Vec<EndpointScope> {
  vec![EndpointScope {
    scheme: Scheme::Https,
    host: "localhost".parse().unwrap(),
    port,
    client_cert: None,
    client_key: None,
    root_cert: None,
    guest_tls: arkham_config::grants::GuestTlsMode::Tls,

    upstream_port: None,
  }]
}

fn plugin_entry(name: &str, port: u16, fixture: std::path::PathBuf) -> ResolvedPlugin {
  ResolvedPlugin {
    name: name.to_string(),
    path: fixture,
    allow: plugin_allow(port),
    direction: PluginDirection::Both,
  }
}

#[tokio::test]
async fn plugin_e2e_request_head_chunk_and_trailers() {
  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  let Some(fixture) = plugin_fixture("marker-request") else {
    println!("skip: ARKHAM_PLUGIN_FIXTURES missing marker-request.wasm");
    return;
  };
  let fx = mitm_fixture_with_plugins(
    |port| localhost_grant(port, FAKE, VALUE),
    |port| vec![plugin_entry("marker-request", port, fixture.clone())],
  )
  .await;
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
    // Stage 1 plugin head effect.
    assert!(head_str.contains("x-arkham-plugin: marker\r\n"), "{head_str}");
    // Chunked rest: the head read may have swallowed the whole message
    // (client sent it in one block); only read more when the chunked
    // terminator is not in hand yet.
    let mut message = head_str;
    while !message.contains("x-trailer-plugin: marker\r\n\r\n") {
      let mut chunk = [0u8; 4096];
      let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      assert!(n > 0, "unexpected EOF waiting for chunked body");
      message.push_str(&String::from_utf8_lossy(&chunk[..n]));
    }
    assert!(message.contains("C\r\nhello-marked\r\n0\r\n"), "{message}");
    assert!(message.contains("x-client-trailer: yes\r\n"), "{message}");
    assert!(message.contains("x-trailer-plugin: marker\r\n"), "{message}");
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
    tls.shutdown().await.unwrap();
  });
  let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  tls
    .write_all(
      format!(
        "POST /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {FAKE}\r\nTransfer-Encoding: chunked\r\nTrailer: x-client-trailer\r\n\r\n5\r\nhello\r\n0\r\nx-client-trailer: yes\r\n\r\n"
      )
      .as_bytes(),
    )
    .await
    .unwrap();
  let response = read_head_from(&mut tls).await;
  assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", response.escape_ascii());
  assert_eq!(read_body(&mut tls, &response, 2).await, b"hi");
  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn plugin_e2e_response_head_and_chunk() {
  let Some(fixture) = plugin_fixture("marker-response") else {
    println!("skip: ARKHAM_PLUGIN_FIXTURES missing marker-response.wasm");
    return;
  };
  let fx = mitm_fixture_with_plugins(
    |port| localhost_grant(port, "fake", "value"),
    |port| vec![plugin_entry("marker-response", port, fixture.clone())],
  )
  .await;
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
    assert!(
      !String::from_utf8(head).unwrap().contains("x-arkham-response-plugin"),
      "response-only world leaves the request leg alone"
    );
    tls
      .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
      .await
      .unwrap();
    tls.shutdown().await.unwrap();
  });
  let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  tls.write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
  let response = read_head_from(&mut tls).await;
  let resp_str = String::from_utf8_lossy(&response);
  assert!(resp_str.contains("x-arkham-response-plugin: marker\r\n"), "{resp_str}");
  // The chunk hook grew the body; chunked framing carries the new size.
  let mut message = response;
  while !message.ends_with(b"0\r\n\r\n") {
    let mut chunk = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk))
      .await
      .unwrap()
      .unwrap();
    assert!(n > 0, "unexpected EOF waiting for chunked body");
    message.extend_from_slice(&chunk[..n]);
  }
  let message = String::from_utf8_lossy(&message);
  assert!(message.contains("C\r\nhello-marked\r\n0\r\n\r\n"), "{message}");
  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn plugin_e2e_h2_chunk_hook_per_frame() {
  use httlib_hpack::{Decoder, Encoder};

  fn data_frame(flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&h2_len(payload.len()));
    frame.extend_from_slice(&[0x0, flags, 0, 0, 0, 1]);
    frame.extend_from_slice(payload);
    frame
  }

  let Some(fixture) = plugin_fixture("marker-request") else {
    println!("skip: ARKHAM_PLUGIN_FIXTURES missing marker-request.wasm");
    return;
  };
  let fx = mitm_fixture_with_plugins_h2(
    |port| localhost_grant(port, "fake", "value"),
    |port| vec![plugin_entry("marker-request", port, fixture.clone())],
  )
  .await;
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
    let mut preface = [0u8; 24];
    tls.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let mut hdr = [0u8; 9];
    tls.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[3], 0x1, "expected HEADERS");
    let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
    let mut block = vec![0u8; len];
    tls.read_exact(&mut block).await.unwrap();
    let mut decoder = Decoder::default();
    let mut headers = Vec::new();
    decoder.decode(&mut block, &mut headers).unwrap();
    assert!(
      headers
        .iter()
        .any(|(name, value, _)| name == b"x-arkham-plugin" && value == b"marker"),
      "head hook marker upstream"
    );
    // Three DATA frames, END_STREAM only on the last.
    let mut bodies = Vec::new();
    for (i, end_stream) in [false, false, true].iter().enumerate() {
      let mut hdr = [0u8; 9];
      tls.read_exact(&mut hdr).await.unwrap();
      assert_eq!(hdr[3], 0x0, "expected DATA frame {i}");
      assert_eq!(hdr[4] & 0x1, u8::from(*end_stream), "END_STREAM on frame {i}");
      let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
      let mut payload = vec![0u8; len];
      tls.read_exact(&mut payload).await.unwrap();
      bodies.push(payload);
    }
    // One marker per DATA frame: the hook ran per frame (streaming),
    // not once over a buffered body (which would mark at most once).
    let joined = String::from_utf8(bodies.concat()).unwrap();
    assert_eq!(joined.matches("-marked").count(), 3, "{joined}");
    assert_eq!(joined.replace("-marked", ""), "AAAAAAAABBBBBBBBC");
    tls.shutdown().await.unwrap();
  });
  let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  let mut encoder = Encoder::default();
  let mut block = Vec::new();
  for (name, value) in [
    (":method", "POST"),
    (":scheme", "https"),
    (":path", "/x"),
    (":authority", "localhost"),
  ] {
    encoder
      .encode(
        (name.as_bytes().to_vec(), value.as_bytes().to_vec(), Encoder::NEVER_INDEXED),
        &mut block,
      )
      .unwrap();
  }
  let mut request = Vec::from(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
  request.extend_from_slice(&h2_len(block.len()));
  request.extend_from_slice(&[0x1, 0x4, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS
  request.extend_from_slice(&block);
  request.extend_from_slice(&data_frame(0x0, b"AAAAAAAA"));
  request.extend_from_slice(&data_frame(0x0, b"BBBBBBBB"));
  request.extend_from_slice(&data_frame(0x1, b"C"));
  tls.write_all(&request).await.unwrap();
  tls.flush().await.unwrap();
  let mut one = [0u8; 1];
  assert_eq!(tls.read(&mut one).await.unwrap(), 0);
  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn plugin_e2e_h2_trailers_hook() {
  use httlib_hpack::{Decoder, Encoder};

  let Some(fixture) = plugin_fixture("marker-request") else {
    println!("skip: ARKHAM_PLUGIN_FIXTURES missing marker-request.wasm");
    return;
  };
  let fx = mitm_fixture_with_plugins_h2(
    |port| localhost_grant(port, "fake", "value"),
    |port| vec![plugin_entry("marker-request", port, fixture.clone())],
  )
  .await;
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
    let mut preface = [0u8; 24];
    tls.read_exact(&mut preface).await.unwrap();
    // Skip the request HEADERS; the second HEADERS block is trailers.
    for _ in 0..2 {
      let mut hdr = [0u8; 9];
      tls.read_exact(&mut hdr).await.unwrap();
      assert_eq!(hdr[3], 0x1, "expected HEADERS");
      let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
      let mut block = vec![0u8; len];
      tls.read_exact(&mut block).await.unwrap();
      if hdr[4] & 0x1 == 0x1 {
        let mut decoder = Decoder::default();
        let mut headers = Vec::new();
        decoder.decode(&mut block, &mut headers).unwrap();
        assert!(headers.iter().any(|(name, value, _)| name == b"x-t" && value == b"abc"));
        assert!(
          headers
            .iter()
            .any(|(name, value, _)| name == b"x-trailer-plugin" && value == b"marker"),
          "trailer hook marker upstream"
        );
      }
    }
    tls.shutdown().await.unwrap();
  });
  let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  let mut encoder = Encoder::default();
  let mut head_block = Vec::new();
  for (name, value) in [
    (":method", "POST"),
    (":scheme", "https"),
    (":path", "/x"),
    (":authority", "localhost"),
  ] {
    encoder
      .encode(
        (name.as_bytes().to_vec(), value.as_bytes().to_vec(), Encoder::NEVER_INDEXED),
        &mut head_block,
      )
      .unwrap();
  }
  let mut trailer_block = Vec::new();
  encoder
    .encode(
      ("x-t".as_bytes().to_vec(), "abc".as_bytes().to_vec(), Encoder::NEVER_INDEXED),
      &mut trailer_block,
    )
    .unwrap();
  let mut request = Vec::from(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
  request.extend_from_slice(&h2_len(head_block.len()));
  request.extend_from_slice(&[0x1, 0x4, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS
  request.extend_from_slice(&head_block);
  request.extend_from_slice(&h2_len(trailer_block.len()));
  request.extend_from_slice(&[0x1, 0x4 | 0x1, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS|END_STREAM
  request.extend_from_slice(&trailer_block);
  tls.write_all(&request).await.unwrap();
  tls.flush().await.unwrap();
  let mut one = [0u8; 1];
  assert_eq!(tls.read(&mut one).await.unwrap(), 0);
  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn plugin_e2e_grant_mismatch_not_invoked() {
  let Some(fixture) = plugin_fixture("marker-request") else {
    println!("skip: ARKHAM_PLUGIN_FIXTURES missing marker-request.wasm");
    return;
  };
  let fx = mitm_fixture_with_plugins(
    |port| localhost_grant(port, "fake", "value"),
    |port| {
      vec![ResolvedPlugin {
        name: "marker-request".to_string(),
        path: fixture.clone(),
        allow: vec![EndpointScope {
          scheme: Scheme::Https,
          host: "other.invalid".parse().unwrap(),
          port,
          client_cert: None,
          client_key: None,
          root_cert: None,
          guest_tls: arkham_config::grants::GuestTlsMode::Tls,

          upstream_port: None,
        }],
        direction: PluginDirection::Both,
      }]
    },
  )
  .await;
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
    assert!(
      !String::from_utf8(head).unwrap().contains("x-arkham-plugin"),
      "ungranted plugin stays out of the head"
    );
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
    tls.shutdown().await.unwrap();
  });
  let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  tls.write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
  let response = read_head_from(&mut tls).await;
  assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", response.escape_ascii());
  assert_eq!(read_body(&mut tls, &response, 2).await, b"hi");
  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn plugin_e2e_trap_fails_closed() {
  let Some(fixture) = plugin_fixture("trap-request") else {
    println!("skip: ARKHAM_PLUGIN_FIXTURES missing trap-request.wasm");
    return;
  };
  let fx = mitm_fixture_with_plugins(
    |port| localhost_grant(port, "fake", "value"),
    |port| vec![plugin_entry("trap-request", port, fixture.clone())],
  )
  .await;
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
    // The proxy already completed the upstream TLS handshake before the
    // guest trapped on the request head: application bytes must be zero.
    let mut buf = [0u8; 64];
    let res = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await.unwrap();
    assert!(
      matches!(res, Ok(0)) || res.is_err(),
      "upstream must receive zero bytes, got {res:?}"
    );
  });
  let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  tls.write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
  let mut one = [0u8; 1];
  let res = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut one)).await.unwrap();
  assert!(matches!(res, Ok(0)) || res.is_err(), "guest connection must drop, got {res:?}");
  stub_task.await.unwrap();
  proxy.abort();
}
