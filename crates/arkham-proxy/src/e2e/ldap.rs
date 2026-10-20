//! LDAP simple bind through the MITM: a cleartext upstream keeps the decoy,
//! `StartTLS` swaps only after the upgrade, and LDAPS swaps from the first byte.

use super::*;
use arkham_config::grants::LdapScope;
use rasn::prelude::OctetString;
use rasn_ldap::{
  AuthenticationChoice, BindRequest, BindResponse, ExtendedRequest, ExtendedResponse, Filter, LdapMessage, LdapResult, LdapString,
  ProtocolOp, ResultCode, SearchRequest, SearchRequestDerefAliases, SearchRequestScope, SearchResultDone,
};
use secrecy::ExposeSecret as _;

const FAKE: &str = "arkham_fake_ldap_pass"; // betterleaks:allow
const VALUE: &str = "arkham_real_ldap_pass_01"; // betterleaks:allow
const DN: &str = "cn=Directory Manager";
const STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

fn ldap_grant(fake: &str, real: &str) -> Grant {
  let scope = LdapScope::from_strings(fake, real).unwrap();
  Grant::Ldap {
    credential: Credential {
      label: "ldap".into(),
      fake: scope.downstream.password.expose_secret().to_string(),
      value: scope.upstream.password.clone(),
    },
    scope: Box::new(scope),
  }
}

fn user(dn: &str) -> String {
  dn.replace('=', "%3D").replace(' ', "%20")
}

fn bind_message(id: u32, password: &str) -> LdapMessage {
  LdapMessage::new(
    id,
    ProtocolOp::BindRequest(BindRequest::new(
      3,
      LdapString::from(DN),
      AuthenticationChoice::Simple(OctetString::from(password.as_bytes())),
    )),
  )
}

fn encode(message: &LdapMessage) -> Vec<u8> {
  rasn::ber::encode(message).unwrap()
}

async fn read_message<S: AsyncRead + Unpin>(conn: &mut S) -> LdapMessage {
  read_message_result(conn).await.unwrap()
}

async fn read_message_result<S: AsyncRead + Unpin>(conn: &mut S) -> Result<LdapMessage, std::io::Error> {
  let mut buf = Vec::new();
  let mut tmp = [0u8; 1024];
  loop {
    let n = conn.read(&mut tmp).await?;
    if n == 0 {
      return Err(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "peer closed before an ldap message",
      ));
    }
    buf.extend_from_slice(&tmp[..n]);
    if let Ok((message, _)) = rasn::ber::decode_with_remainder::<LdapMessage>(&buf) {
      return Ok(message);
    }
  }
}

fn simple_password(message: &LdapMessage) -> &[u8] {
  let ProtocolOp::BindRequest(request) = &message.protocol_op else {
    panic!("expected a bind request");
  };
  let AuthenticationChoice::Simple(password) = &request.authentication else {
    panic!("expected simple authentication");
  };
  password.as_ref()
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

#[tokio::test]
async fn ldap_cleartext_bind_forwards_the_decoy() {
  let fx = mitm_fixture(|port| {
    vec![ldap_grant(
      &format!("ldap://{}:{FAKE}@localhost:{port}", user(DN)),
      &format!("ldap://{}:{VALUE}@localhost:{port}", user(DN)),
    )]
  })
  .await;
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = fx.stub.accept().await.unwrap();
    let request = read_message(&mut conn).await;
    assert_eq!(simple_password(&request), FAKE.as_bytes());
    let response = LdapMessage::new(
      request.message_id,
      ProtocolOp::BindResponse(BindResponse::new(
        ResultCode::InvalidCredentials,
        LdapString::from(""),
        LdapString::from(""),
        None,
        None,
      )),
    );
    conn.write_all(&encode(&response)).await.unwrap();
  });
  let mut stream = connect_through_proxy(fx.proxy_addr, fx.stub_port).await;
  stream.write_all(&encode(&bind_message(1, FAKE))).await.unwrap();
  let response = read_message(&mut stream).await;
  let ProtocolOp::BindResponse(body) = response.protocol_op else {
    panic!("bind response");
  };
  assert_eq!(body.result_code, ResultCode::InvalidCredentials);
  drop(stream);
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  fx.proxy.abort();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
  StartTlsFirst,
  BindThenStartTls,
  SearchThenStartTls,
  AlreadyTls,
  Pipelined,
  SecondStartTls,
}

fn upstream_tls(flow: Flow) -> bool {
  matches!(flow, Flow::AlreadyTls | Flow::Pipelined | Flow::SecondStartTls)
}

async fn ldap_flow(flow: Flow) {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let scheme = if upstream_tls(flow) { "ldaps" } else { "ldap" };
  let grants = vec![ldap_grant(
    &format!("ldap://{}:{FAKE}@localhost:{stub_port}", user(DN)),
    &format!(
      "{scheme}://{}:{VALUE}@localhost:{stub_port}?sslrootcert={}",
      user(DN),
      bundle.display()
    ),
  )];
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, &ca)).await;
  let stub_task = tokio::spawn(async move { serve_flow(stub, acceptor, flow).await });
  drive_guest(connect_through_proxy(proxy_addr, stub_port).await, flow, &ca).await;
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  proxy.abort();
}

async fn serve_flow(stub: TcpListener, acceptor: TlsAcceptor, flow: Flow) {
  let (conn, _) = stub.accept().await.unwrap();
  if upstream_tls(flow) {
    serve_tls(acceptor, conn, flow).await;
  } else {
    serve_clear(acceptor, conn, flow).await;
  }
}

async fn serve_tls<S>(acceptor: TlsAcceptor, conn: S, flow: Flow)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let mut tls = acceptor.accept(conn).await.unwrap();
  let opening = read_message(&mut tls).await;
  assert_eq!(simple_password(&opening), VALUE.as_bytes());
  write_bind_result(&mut tls, opening.message_id, ResultCode::Success).await;
  if matches!(flow, Flow::Pipelined) {
    assert!(read_message_result(&mut tls).await.is_err(), "starttls was forwarded");
    return;
  }
  let next = read_message(&mut tls).await;
  assert_eq!(simple_password(&next), VALUE.as_bytes(), "starttls must not be forwarded");
  write_bind_result(&mut tls, next.message_id, ResultCode::Success).await;
  if matches!(flow, Flow::SecondStartTls) {
    let third = read_message(&mut tls).await;
    assert_eq!(simple_password(&third), VALUE.as_bytes());
    write_bind_result(&mut tls, third.message_id, ResultCode::Success).await;
  }
}

async fn serve_clear<S>(acceptor: TlsAcceptor, mut conn: S, flow: Flow)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  if flow != Flow::StartTlsFirst {
    let opening = read_message(&mut conn).await;
    if matches!(flow, Flow::SearchThenStartTls) {
      let ProtocolOp::SearchRequest(_) = &opening.protocol_op else {
        panic!("search request");
      };
      write_search_done(&mut conn, opening.message_id).await;
    } else {
      assert_eq!(simple_password(&opening), FAKE.as_bytes(), "cleartext bind must keep the decoy");
      write_bind_result(&mut conn, opening.message_id, ResultCode::InvalidCredentials).await;
    }
  }
  let request = read_message(&mut conn).await;
  let ProtocolOp::ExtendedReq(extended) = &request.protocol_op else {
    panic!("starttls after the first operation");
  };
  assert_eq!(extended.request_name.as_ref(), STARTTLS_OID);
  write_starttls_success(&mut conn, request.message_id).await;
  let mut tls = acceptor.accept(conn).await.unwrap();
  let bind = read_message(&mut tls).await;
  assert_eq!(
    simple_password(&bind),
    VALUE.as_bytes(),
    "protected bind must carry the real password"
  );
  write_bind_result(&mut tls, bind.message_id, ResultCode::Success).await;
}

async fn drive_guest<S>(stream: S, flow: Flow, ca: &CertAuthority)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let mut io = Inbox {
    stream,
    pending: Vec::new(),
  };
  if matches!(flow, Flow::Pipelined) {
    drive_pipelined(&mut io).await;
    return;
  }
  let start_id = if matches!(flow, Flow::StartTlsFirst) { 1 } else { 2 };
  match flow {
    Flow::SearchThenStartTls => {
      io.write(&encode(&search_message(1))).await;
      let opened = io.message().await;
      let ProtocolOp::SearchResDone(SearchResultDone(body)) = opened.protocol_op else {
        panic!("search done");
      };
      assert_eq!(body.result_code, ResultCode::Success);
    }
    Flow::BindThenStartTls => expect_bind(&mut io, 1, ResultCode::InvalidCredentials).await,
    Flow::AlreadyTls | Flow::SecondStartTls => expect_bind(&mut io, 1, ResultCode::Success).await,
    Flow::StartTlsFirst | Flow::Pipelined => {}
  }
  io.write(&encode(&starttls_message(start_id))).await;
  let started = tokio::time::timeout(Duration::from_secs(5), io.message())
    .await
    .expect("starttls result");
  let ProtocolOp::ExtendedResp(body) = &started.protocol_op else {
    panic!("starttls response");
  };
  assert_eq!(body.result_code, ResultCode::Success);
  let mut tls = handshake(io, ca).await;
  expect_bind(&mut tls, start_id + 1, ResultCode::Success).await;
  if matches!(flow, Flow::SecondStartTls) {
    tls.write(&encode(&starttls_message(start_id + 2))).await;
    let again = tokio::time::timeout(Duration::from_secs(5), tls.message())
      .await
      .expect("second starttls result");
    let ProtocolOp::ExtendedResp(body) = again.protocol_op else {
      panic!("starttls response");
    };
    assert_eq!(again.message_id, start_id + 2);
    assert_eq!(body.result_code, ResultCode::OperationsError);
    expect_bind(&mut tls, start_id + 3, ResultCode::Success).await;
  }
}

async fn drive_pipelined<S>(io: &mut Inbox<S>)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let mut bytes = encode(&bind_message(1, FAKE));
  bytes.extend(encode(&starttls_message(2)));
  io.write(&bytes).await;
  let mut saw_bind = false;
  let mut saw_starttls = false;
  for _ in 0..2 {
    let message = tokio::time::timeout(Duration::from_secs(5), io.message())
      .await
      .expect("pipelined result");
    match message.protocol_op {
      ProtocolOp::BindResponse(body) => {
        assert_eq!(message.message_id, 1);
        assert_eq!(body.result_code, ResultCode::Success);
        saw_bind = true;
      }
      ProtocolOp::ExtendedResp(body) => {
        assert_eq!(message.message_id, 2);
        assert_eq!(body.result_code, ResultCode::OperationsError);
        saw_starttls = true;
      }
      _ => panic!("pipelined response"),
    }
  }
  assert!(saw_bind && saw_starttls, "bind result and starttls operationsError");
}

async fn expect_bind<S>(io: &mut Inbox<S>, id: u32, code: ResultCode)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  io.write(&encode(&bind_message(id, FAKE))).await;
  let response = io.message().await;
  let ProtocolOp::BindResponse(body) = response.protocol_op else {
    panic!("bind response");
  };
  assert_eq!(response.message_id, id);
  assert_eq!(body.result_code, code);
}

async fn handshake<S>(io: Inbox<S>, ca: &CertAuthority) -> Inbox<tokio_rustls::client::TlsStream<crate::connection::Prefixed<S>>>
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let Inbox { stream, pending } = io;
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let tls = tokio::time::timeout(
    Duration::from_secs(5),
    guest_connector(ca, false).connect(name, crate::connection::Prefixed::new(pending, stream)),
  )
  .await
  .expect("starttls upgrades")
  .expect("guest handshake");
  Inbox {
    stream: tls,
    pending: Vec::new(),
  }
}

struct Inbox<S> {
  stream: S,
  pending: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Inbox<S> {
  async fn write(&mut self, bytes: &[u8]) {
    self.stream.write_all(bytes).await.unwrap();
  }

  async fn message(&mut self) -> LdapMessage {
    loop {
      if let Ok((message, rest)) = rasn::ber::decode_with_remainder::<LdapMessage>(&self.pending) {
        self.pending = rest.to_vec();
        return message;
      }
      let mut tmp = [0u8; 1024];
      let n = self.stream.read(&mut tmp).await.unwrap();
      assert_ne!(n, 0, "peer closed before an ldap message");
      let Some(chunk) = tmp.get(..n) else {
        panic!("short read");
      };
      self.pending.extend_from_slice(chunk);
    }
  }
}

fn starttls_message(id: u32) -> LdapMessage {
  LdapMessage::new(
    id,
    ProtocolOp::ExtendedReq(ExtendedRequest {
      request_name: OctetString::from_static(STARTTLS_OID),
      request_value: None,
    }),
  )
}

fn search_message(id: u32) -> LdapMessage {
  LdapMessage::new(
    id,
    ProtocolOp::SearchRequest(SearchRequest::new(
      LdapString::from(""),
      SearchRequestScope::BaseObject,
      SearchRequestDerefAliases::NeverDerefAliases,
      0,
      0,
      false,
      Filter::Present(LdapString::from("objectClass")),
      Vec::new(),
    )),
  )
}

async fn write_bind_result<S>(stream: &mut S, id: u32, code: ResultCode)
where
  S: AsyncWrite + Unpin,
{
  let response = LdapMessage::new(
    id,
    ProtocolOp::BindResponse(BindResponse::new(code, LdapString::from(""), LdapString::from(""), None, None)),
  );
  stream.write_all(&encode(&response)).await.unwrap();
}

async fn write_starttls_success<S>(stream: &mut S, id: u32)
where
  S: AsyncWrite + Unpin,
{
  let response = LdapMessage::new(
    id,
    ProtocolOp::ExtendedResp(ExtendedResponse {
      result_code: ResultCode::Success,
      matched_dn: LdapString::from(""),
      diagnostic_message: LdapString::from(""),
      referral: None,
      response_name: Some(OctetString::from_static(STARTTLS_OID)),
      response_value: None,
    }),
  );
  stream.write_all(&encode(&response)).await.unwrap();
}

async fn write_search_done<S>(stream: &mut S, id: u32)
where
  S: AsyncWrite + Unpin,
{
  let response = LdapMessage::new(
    id,
    ProtocolOp::SearchResDone(SearchResultDone(LdapResult::new(
      ResultCode::Success,
      LdapString::from(""),
      LdapString::from(""),
    ))),
  );
  stream.write_all(&encode(&response)).await.unwrap();
}

#[tokio::test]
async fn ldap_starttls_then_bind_swaps_the_password() {
  ldap_flow(Flow::StartTlsFirst).await;
}

#[tokio::test]
async fn ldap_bind_then_starttls_then_protected_bind_swaps_the_password() {
  ldap_flow(Flow::BindThenStartTls).await;
}

#[tokio::test]
async fn ldap_search_then_starttls_then_protected_bind_swaps_the_password() {
  ldap_flow(Flow::SearchThenStartTls).await;
}

#[tokio::test]
async fn ldap_bind_then_starttls_is_answered_when_upstream_is_already_tls() {
  ldap_flow(Flow::AlreadyTls).await;
}

#[tokio::test]
async fn ldap_pipelined_bind_then_starttls_is_operations_error() {
  ldap_flow(Flow::Pipelined).await;
}

#[tokio::test]
async fn ldap_second_starttls_on_a_tls_session_is_operations_error() {
  ldap_flow(Flow::SecondStartTls).await;
}

fn guest_connector(ca: &CertAuthority, present: bool) -> TlsConnector {
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
  let config = if present {
    let (chain, key) = arkham_pki::ca::generate_client_pair(ca, "guest").unwrap();
    builder.with_client_auth_cert(chain, key).unwrap()
  } else {
    builder.with_no_client_auth()
  };
  TlsConnector::from(Arc::new(config))
}

/// Cleartext bind, then `StartTLS`, then a protected bind. `Ok` is the
/// protected result code. `Err` is the guest handshake after a successful
/// `StartTLS` result.
async fn bind_then_starttls_bind(proxy_addr: SocketAddr, stub_port: u16, connector: TlsConnector) -> Result<ResultCode, String> {
  let mut stream = connect_through_proxy(proxy_addr, stub_port).await;
  stream.write_all(&encode(&bind_message(1, FAKE))).await.unwrap();
  let opened = read_message(&mut stream).await;
  let ProtocolOp::BindResponse(body) = opened.protocol_op else {
    panic!("bind response");
  };
  assert_eq!(body.result_code, ResultCode::InvalidCredentials);
  let start = LdapMessage::new(
    2,
    ProtocolOp::ExtendedReq(ExtendedRequest {
      request_name: OctetString::from_static(STARTTLS_OID),
      request_value: None,
    }),
  );
  stream.write_all(&encode(&start)).await.unwrap();
  let started = read_message(&mut stream).await;
  let ProtocolOp::ExtendedResp(body) = &started.protocol_op else {
    panic!("starttls response");
  };
  assert_eq!(body.result_code, ResultCode::Success);
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let connect = tokio::time::timeout(Duration::from_secs(5), connector.connect(name, stream)).await;
  let Ok(connect) = connect else {
    return Err("handshake timed out".to_string());
  };
  let mut tls = connect.map_err(|err| err.to_string())?;
  tls
    .write_all(&encode(&bind_message(3, FAKE)))
    .await
    .map_err(|err| err.to_string())?;
  let response = read_message_result(&mut tls).await.map_err(|err| err.to_string())?;
  let ProtocolOp::BindResponse(body) = response.protocol_op else {
    panic!("bind response");
  };
  Ok(body.result_code)
}

/// `guest_tls_mode = mtls` on a cleartext `ldap://` fake. A CA-signed guest
/// completes the protected bind and the upstream sees the real password.
/// A guest with no certificate is refused at the handshake, after it has
/// already seen the `StartTLS` success, and the upstream never starts TLS.
#[tokio::test]
async fn ldap_bind_then_starttls_enforces_guest_mtls() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let fake = format!("ldap://{}:{FAKE}@localhost:{stub_port}", user(DN));
  let real = format!("ldap://{}:{VALUE}@localhost:{stub_port}?sslrootcert={}", user(DN), bundle.display());
  let grants = super::resolve_mtls_grants("LDAP_URL", &fake, &real).expect("ldap starttls with mtls still loads");
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, &ca)).await;
  let (tx, mut rx) = tokio::sync::mpsc::channel(2);
  let stub_task = tokio::spawn(async move {
    for _ in 0..2 {
      let Ok(Ok((mut conn, _))) = tokio::time::timeout(Duration::from_secs(10), stub.accept()).await else {
        return;
      };
      let opening = read_message(&mut conn).await;
      assert_eq!(simple_password(&opening), FAKE.as_bytes(), "cleartext bind must keep the decoy");
      let response = LdapMessage::new(
        opening.message_id,
        ProtocolOp::BindResponse(BindResponse::new(
          ResultCode::InvalidCredentials,
          LdapString::from(""),
          LdapString::from(""),
          None,
          None,
        )),
      );
      conn.write_all(&encode(&response)).await.unwrap();
      let request = read_message(&mut conn).await;
      let ProtocolOp::ExtendedReq(extended) = &request.protocol_op else {
        panic!("starttls after the bind");
      };
      assert_eq!(extended.request_name.as_ref(), STARTTLS_OID);
      let response = LdapMessage::new(
        request.message_id,
        ProtocolOp::ExtendedResp(ExtendedResponse {
          result_code: ResultCode::Success,
          matched_dn: LdapString::from(""),
          diagnostic_message: LdapString::from(""),
          referral: None,
          response_name: Some(OctetString::from_static(STARTTLS_OID)),
          response_value: None,
        }),
      );
      conn.write_all(&encode(&response)).await.unwrap();
      let accepted = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(conn))
        .await
        .expect("upstream accept timed out");
      let Ok(mut tls) = accepted else {
        let _ = tx.send(false).await;
        continue;
      };
      let bind = read_message(&mut tls).await;
      assert_eq!(
        simple_password(&bind),
        VALUE.as_bytes(),
        "protected bind must carry the real password"
      );
      let ok = LdapMessage::new(
        bind.message_id,
        ProtocolOp::BindResponse(BindResponse::new(
          ResultCode::Success,
          LdapString::from(""),
          LdapString::from(""),
          None,
          None,
        )),
      );
      tls.write_all(&encode(&ok)).await.unwrap();
      let _ = tx.send(true).await;
    }
  });

  let protected = bind_then_starttls_bind(proxy_addr, stub_port, guest_connector(&ca, true))
    .await
    .expect("ca-signed guest handshake");
  assert_eq!(protected, ResultCode::Success);
  assert!(rx.recv().await.unwrap(), "ca-signed guest did not open upstream tls");

  let refused = bind_then_starttls_bind(proxy_addr, stub_port, guest_connector(&ca, false)).await;
  let Err(reason) = refused else {
    panic!("certless guest completed the handshake");
  };
  assert_ne!(reason, "handshake timed out", "certless guest hung instead of being refused");
  assert!(!rx.recv().await.unwrap(), "certless guest opened upstream tls");
  stub_task.abort();
  proxy.abort();
}

#[tokio::test]
async fn ldap_tls_without_sni_mints_for_the_grant_host() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let acceptor = TlsAcceptor::from(Arc::new((*stub_cert.server_config).clone()));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let grants = vec![ldap_grant(
    &format!("ldaps://{}:{FAKE}@localhost:{stub_port}", user(DN)),
    &format!(
      "ldaps://{}:{VALUE}@localhost:{stub_port}?sslrootcert={}",
      user(DN),
      bundle.display()
    ),
  )];
  let state = test_state_with(grants, &ca);
  let snapshot = state.snapshot();
  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = acceptor.accept(conn).await.unwrap();
    let bind = read_message(&mut tls).await;
    assert_eq!(simple_password(&bind), VALUE.as_bytes());
    let ok = LdapMessage::new(
      bind.message_id,
      ProtocolOp::BindResponse(BindResponse::new(
        ResultCode::Success,
        LdapString::from(""),
        LdapString::from(""),
        None,
        None,
      )),
    );
    tls.write_all(&encode(&ok)).await.unwrap();
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
  config.enable_sni = false;
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let mut tls = tokio::time::timeout(
    Duration::from_secs(10),
    TlsConnector::from(Arc::new(config)).connect(name, client_end),
  )
  .await
  .unwrap()
  .unwrap();
  tls.write_all(&encode(&bind_message(1, FAKE))).await.unwrap();
  let response = read_message(&mut tls).await;
  let ProtocolOp::BindResponse(body) = response.protocol_op else {
    panic!("bind response");
  };
  assert_eq!(body.result_code, ResultCode::Success);
  drop(tls);
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  serve.await.unwrap().unwrap();
}

#[test]
fn ldap_mtls_plaintext_guest_is_rejected_at_load() {
  let fake = format!("ldap://{}:{FAKE}@localhost:389", user(DN));
  let real = format!("ldaps://{}:{VALUE}@localhost:636", user(DN));
  let Err(err) = super::resolve_mtls_grants("LDAP_URL", &fake, &real) else {
    panic!("mtls on an ldap fake with an ldaps real must be rejected");
  };
  assert!(matches!(err.as_ref(), arkham_config::Error::LdapCleartextMtls { .. }), "{err}");
  let text = err.to_string();
  assert!(!text.contains(FAKE), "mtls rejection included a credential");
  assert!(!text.contains(VALUE), "mtls rejection included a credential");
}
