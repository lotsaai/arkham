use super::*;

#[test]
fn parse_authority_bracketed_v6_default_port() {
  assert_eq!(parse_authority("[::1]:8080", None), Some(("::1".to_string(), 8080)));
  assert_eq!(parse_authority("[::1]", Some(80)), Some(("::1".to_string(), 80)));
  assert_eq!(parse_authority("[::1]", None), None);
  assert_eq!(parse_authority("[::1]extra", Some(80)), None);
  assert_eq!(parse_authority("example.com", Some(80)), Some(("example.com".to_string(), 80)));
  // Unbracketed IPv6 is never split: mirrors the grant parser rejection.
  assert_eq!(parse_authority("::1", Some(80)), None);
  assert_eq!(parse_authority("::1", None), None);
  assert_eq!(parse_authority("2001:db8::1:443", None), None);
  // Userinfo never authenticates upstream: reject, don't dial it.
  assert_eq!(parse_authority("user@example.com:80", None), None);
}

#[tokio::test]
async fn connect_splices_bytes_verbatim() {
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_addr = local_addr(&stub);
  let (proxy_addr, proxy) = run_proxy().await;

  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let mut buf = [0u8; 5];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
    conn.write_all(b"world").await.unwrap();
  });

  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  client
    .write_all(format!("CONNECT {stub_addr} HTTP/1.1\r\nHost: {stub_addr}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut head = vec![0u8; 19];
  tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
  client.write_all(b"hello").await.unwrap();
  let mut echo = [0u8; 5];
  tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echo))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(&echo, b"world");

  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn absolute_form_forwards_head_verbatim() {
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_addr = local_addr(&stub);
  let (proxy_addr, proxy) = run_proxy().await;

  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let head = read_head_from(&mut conn).await;
    let head_str = String::from_utf8(head).unwrap();
    assert!(
      head_str.starts_with(&format!("GET http://{stub_addr}/x HTTP/1.1\r\n")),
      "{head_str}"
    );
    conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
  });

  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  client
    .write_all(format!("GET http://{stub_addr}/x HTTP/1.1\r\nHost: {stub_addr}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut response = Vec::new();
  tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
    .await
    .unwrap()
    .unwrap();
  assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{}", response.escape_ascii());

  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn malformed_request_closes_without_response() {
  let (proxy_addr, proxy) = run_proxy().await;
  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  client.write_all(b"GARBAGE\r\n\r\n").await.unwrap();
  let mut response = Vec::new();
  tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(response, [] as [u8; 0]);
  proxy.abort();
}

#[tokio::test]
async fn absolute_form_ungranted_chunked_splices_byte_identical() {
  // No grants: chunked bodies must pass through byte-identical, never
  // re-encoded into a single chunk.
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_addr = local_addr(&stub);
  let (proxy_addr, proxy) = run_proxy().await;
  let body = "3\r\naaa\r\n3\r\nbbb\r\n0\r\n\r\n";
  let request = format!("POST http://{stub_addr}/x HTTP/1.1\r\nHost: {stub_addr}\r\nTransfer-Encoding: chunked\r\n\r\n{body}");
  let expected = request.clone().into_bytes();
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
      let n = conn.read(&mut chunk).await.unwrap();
      if n == 0 {
        break;
      }
      buf.extend_from_slice(&chunk[..n]);
      if buf.ends_with(b"0\r\n\r\n") {
        break;
      }
    }
    assert_eq!(buf, expected, "ungranted chunked request must be byte-identical");
    conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
  });
  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  client.write_all(request.as_bytes()).await.unwrap();
  let mut response = Vec::new();
  tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
    .await
    .unwrap()
    .unwrap();
  assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{}", response.escape_ascii());
  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn connect_pipelined_bytes_reach_upstream_verbatim() {
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_addr = local_addr(&stub);
  let (proxy_addr, proxy) = run_proxy().await; // no grants: splice path
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let mut buf = [0u8; 5];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"early", "pipelined post-head bytes must survive");
    conn.write_all(b"ok").await.unwrap();
  });
  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  // CONNECT head + payload in ONE write: the tail must be replayed.
  client
    .write_all(format!("CONNECT {stub_addr} HTTP/1.1\r\nHost: x\r\n\r\nearly").as_bytes())
    .await
    .unwrap();
  let mut head = vec![0u8; 19];
  tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
  let mut reply = [0u8; 2];
  tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(&reply, b"ok");
  stub_task.await.unwrap();
  proxy.abort();
}

#[tokio::test]
async fn transparent_plain_http_honors_http_grant() {
  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let grants = vec![Grant::Token {
    credential: Credential {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE),
    },
    allow: vec![EndpointScope {
      scheme: Scheme::Http,
      host: "127.0.0.1".parse().unwrap(),
      port: stub_port,
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls: arkham_config::grants::GuestTlsMode::Tls,

      upstream_port: None,
    }],
    pattern: None,
    oauth2: None,
  }];
  let state = test_state_with(grants, &ca);
  let snapshot = state.snapshot();
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let head = read_head_from(&mut conn).await;
    let head_str = String::from_utf8(head).unwrap();
    assert!(head_str.contains(&format!("Authorization: Bearer {VALUE}")), "{head_str}");
    let body = format!("echo:{VALUE}");
    conn
      .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
      .await
      .unwrap();
  });
  let (guest, mut client_end) = tokio::io::duplex(64 * 1024);
  let serve = tokio::spawn({
    let state = Arc::clone(&state);
    let snapshot = Arc::clone(&snapshot);
    async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
  });
  client_end
    .write_all(
      format!("GET /x HTTP/1.1\r\nHost: 127.0.0.1:{stub_port}\r\nAuthorization: Bearer {FAKE}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
  let response = read_head_from(&mut client_end).await;
  let resp_str = String::from_utf8_lossy(&response);
  assert!(!resp_str.contains(VALUE), "{resp_str}");
  let expect = format!("echo:{FAKE}");
  assert_eq!(read_body(&mut client_end, &response, expect.len()).await, expect.as_bytes());
  stub_task.await.unwrap();
  serve.await.unwrap().unwrap();
}

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;

/// Request or response body with no declared length, so hyper frames it
/// chunked and the de-chunking on the far side is a real implementation's.
struct Chunks(Vec<Bytes>);

impl hyper::body::Body for Chunks {
  type Data = Bytes;
  type Error = std::io::Error;

  fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
    let this = self.get_mut();
    Poll::Ready(if this.0.is_empty() {
      None
    } else {
      Some(Ok(hyper::body::Frame::data(this.0.remove(0))))
    })
  }
}

/// Real hyper client and real hyper server through the MITM, chunked in both
/// directions, with the needle split across chunk boundaries. The proxy
/// re-chunks around its hold-back window, so the framing on the wire is
/// arkham's own output and has to be accepted by an independent HTTP/1
/// implementation on either side.
#[tokio::test]
async fn http1_real_client_and_server_round_trip_chunked() {
  use http_body_util::BodyExt as _;
  use hyper::body::Incoming;
  use hyper::service::service_fn;
  use hyper::{Request, Response};
  use hyper_util::rt::TokioIo;

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
    let tls = stub_acceptor.accept(conn).await.unwrap();
    let service = service_fn(|req: Request<Incoming>| async move {
      assert_eq!(
        req.headers().get("authorization").unwrap().to_str().unwrap(),
        format!("Bearer {VALUE}")
      );
      // The proxy re-emitted this request's chunked framing itself.
      assert_eq!(req.headers().get("transfer-encoding").unwrap().to_str().unwrap(), "chunked");
      let body = req.into_body().collect().await.unwrap().to_bytes();
      assert_eq!(String::from_utf8(body.to_vec()).unwrap(), format!("upload:{VALUE}"));
      let parts = format!("download:{VALUE}")
        .as_bytes()
        .chunks(8)
        .map(Bytes::copy_from_slice)
        .collect();
      Ok::<_, std::io::Error>(Response::new(Chunks(parts)))
    });
    hyper::server::conn::http1::Builder::new()
      .serve_connection(TokioIo::new(tls), service)
      .await
      .unwrap();
  });

  let tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
  let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
  let client_task = tokio::spawn(conn);
  let parts: Vec<Bytes> = format!("upload:{FAKE}").as_bytes().chunks(7).map(Bytes::copy_from_slice).collect();
  let request = Request::builder()
    .method("POST")
    .uri("/x")
    .header("host", "localhost")
    .header("authorization", format!("Bearer {FAKE}"))
    .body(Chunks(parts))
    .unwrap();
  let response = sender.send_request(request).await.unwrap();
  assert_eq!(response.status(), 200);
  // The chunked path, not a fixed-length fallback: the response body below
  // is framed by arkham, not passed through.
  assert_eq!(response.headers().get("transfer-encoding").unwrap().to_str().unwrap(), "chunked");
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(String::from_utf8(body.to_vec()).unwrap(), format!("download:{FAKE}"));
  drop(sender);
  let _ = client_task.await;
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  proxy.abort();
}
