//! LDAP simple bind through the MITM: a cleartext upstream swaps the real
//! password the same way TLS does, and LDAPS swaps from the first byte.

use super::fixture::*;
use arkham_config::grants::LdapScope;
use rasn::prelude::OctetString;
use rasn_ldap::{
  AuthenticationChoice, BindRequest, BindResponse, ExtendedRequest, ExtendedResponse, LdapMessage, LdapString, ProtocolOp, ResultCode,
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
async fn ldap_cleartext_bind_swaps_the_password() {
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
    assert_eq!(simple_password(&request), VALUE.as_bytes());
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
  let stream = connect_through_proxy(fx.proxy_addr, fx.stub_port).await;
  let result = ldap3_bind(stream, Ldap3Open::Clear, FAKE).await.expect("ldap3 bind");
  assert_eq!(result.rc, ResultCode::InvalidCredentials as u32, "{result}");
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  fx.proxy.abort();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
  StartTlsFirst,
  Pipelined,
}

fn upstream_tls(flow: Flow) -> bool {
  matches!(flow, Flow::Pipelined)
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
  let stream = connect_through_proxy(proxy_addr, stub_port).await;
  if matches!(flow, Flow::StartTlsFirst) {
    let result = ldap3_bind(
      stream,
      Ldap3Open::StartTls {
        ca: &ca,
        client_cert: false,
      },
      FAKE,
    )
    .await
    .expect("ldap3 bind");
    result.success().expect("protected bind");
  } else {
    let mut io = Inbox {
      stream,
      pending: Vec::new(),
    };
    drive_pipelined(&mut io).await;
  }
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  proxy.abort();
}

async fn serve_flow(stub: TcpListener, acceptor: TlsAcceptor, flow: Flow) {
  let (conn, _) = stub.accept().await.unwrap();
  if upstream_tls(flow) {
    serve_tls(acceptor, conn, flow).await;
  } else {
    serve_clear(acceptor, conn).await;
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
  assert!(matches!(flow, Flow::Pipelined));
  assert!(read_message_result(&mut tls).await.is_err(), "starttls was forwarded");
}

async fn serve_clear<S>(acceptor: TlsAcceptor, mut conn: S)
where
  S: AsyncRead + AsyncWrite + Unpin,
{
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

#[tokio::test]
async fn ldap_starttls_then_bind_swaps_the_password() {
  ldap_flow(Flow::StartTlsFirst).await;
}

// Bind then StartTLS, and search then StartTLS, are compose scenario 14.
// ldapts drives both against 389ds. The scenario names are
// `ldap bind then starttls then bind swaps the decoy password` and
// `ldap search then starttls then bind swaps the decoy password`.
//
// A second StartTLS on an already protected session is
// `ldap second starttls on a tls session is operations error`.
// Bind then StartTLS when the upstream is already TLS is
// `ldap bind then starttls against an already tls upstream swaps the decoy`.
// Bind then StartTLS with guest mTLS is
// `ldap bind then starttls with a client certificate swaps the decoy`.

/// ldap3 can send a bind and `StartTLS` before either result, using two
/// cloned handles and `extended`. It flushes each message on its own, so
/// only this byte guest puts both in one read.
#[tokio::test]
async fn ldap_pipelined_bind_then_starttls_is_operations_error() {
  ldap_flow(Flow::Pipelined).await;
}

enum Ldap3Open<'a> {
  Clear,
  StartTls { ca: &'a CertAuthority, client_cert: bool },
  Ldaps { ca: &'a CertAuthority, sni: bool },
}

fn guest_config(ca: &CertAuthority, present: bool) -> rustls::ClientConfig {
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
  if present {
    let (chain, key) = arkham_pki::ca::generate_client_pair(ca, "guest").unwrap();
    builder.with_client_auth_cert(chain, key).unwrap()
  } else {
    builder.with_no_client_auth()
  }
}

async fn ldap3_bind(stream: TcpStream, open: Ldap3Open<'_>, password: &str) -> Result<ldap3::LdapResult, ldap3::LdapError> {
  let bind = async {
    let std_stream = stream.into_std().expect("ldap3 takes a std stream");
    let mut settings = ldap3::LdapConnSettings::new().set_std_stream(ldap3::StdStream::Tcp(std_stream));
    let url = match open {
      Ldap3Open::Clear => "ldap://localhost",
      Ldap3Open::StartTls { ca, client_cert } => {
        settings = settings.set_starttls(true).set_config(Arc::new(guest_config(ca, client_cert)));
        "ldap://localhost"
      }
      Ldap3Open::Ldaps { ca, sni } => {
        let mut config = guest_config(ca, false);
        config.enable_sni = sni;
        settings = settings.set_config(Arc::new(config));
        "ldaps://localhost"
      }
    };
    let (conn, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, url).await?;
    tokio::spawn(async move {
      let _ = conn.drive().await;
    });
    ldap.simple_bind(DN, password).await
  };
  tokio::time::timeout(Duration::from_secs(10), bind)
    .await
    .expect("ldap3 bind timed out")
}

async fn answer_ldaps_bind(stub: TcpListener, acceptor: TlsAcceptor) {
  let (conn, _) = stub.accept().await.unwrap();
  let mut tls = acceptor.accept(conn).await.unwrap();
  let bind = read_message(&mut tls).await;
  assert_eq!(simple_password(&bind), VALUE.as_bytes());
  write_bind_result(&mut tls, bind.message_id, ResultCode::Success).await;
}

#[tokio::test]
async fn ldap_starttls_with_a_client_cert_swaps_the_password() {
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
  let grants = resolve_mtls_grants("LDAP_URL", &fake, &real).expect("ldap starttls with mtls still loads");
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, &ca)).await;
  let stub_task = tokio::spawn(async move { serve_flow(stub, acceptor, Flow::StartTlsFirst).await });
  let stream = connect_through_proxy(proxy_addr, stub_port).await;
  let result = ldap3_bind(
    stream,
    Ldap3Open::StartTls {
      ca: &ca,
      client_cert: true,
    },
    FAKE,
  )
  .await
  .expect("ldap3 bind");
  result.success().expect("mtls protected bind");
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  proxy.abort();
}

#[tokio::test]
async fn ldap_starttls_without_a_client_cert_never_reaches_upstream() {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let fake = format!("ldap://{}:{FAKE}@localhost:{stub_port}", user(DN));
  let real = format!("ldap://{}:{VALUE}@localhost:{stub_port}?sslrootcert={}", user(DN), bundle.display());
  let grants = resolve_mtls_grants("LDAP_URL", &fake, &real).expect("ldap starttls with mtls still loads");
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, &ca)).await;
  let stub_task = tokio::spawn(async move { bytes_after_starttls(stub).await });
  let stream = connect_through_proxy(proxy_addr, stub_port).await;
  let opened = ldap3_bind(
    stream,
    Ldap3Open::StartTls {
      ca: &ca,
      client_cert: false,
    },
    FAKE,
  )
  .await;
  assert!(opened.is_err(), "certless guest completed starttls");
  let tail = tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  assert!(
    !tail.windows(VALUE.len()).any(|window| window == VALUE.as_bytes()),
    "real password reached the upstream"
  );
  assert!(tail.is_empty(), "upstream saw bytes after starttls");
  proxy.abort();
}

async fn bytes_after_starttls(stub: TcpListener) -> Vec<u8> {
  let (mut conn, _) = tokio::time::timeout(Duration::from_secs(10), stub.accept()).await.unwrap().unwrap();
  let (request, mut tail) = read_message_and_rest(&mut conn).await;
  match &request.protocol_op {
    ProtocolOp::BindRequest(_) => {
      assert_ne!(simple_password(&request), VALUE.as_bytes(), "real password on the opening bind");
      panic!("upstream saw a bind");
    }
    ProtocolOp::ExtendedReq(extended) => {
      assert_eq!(extended.request_name.as_ref(), STARTTLS_OID);
    }
    _ => panic!("opening message"),
  }
  write_starttls_success(&mut conn, request.message_id).await;
  let mut tmp = [0u8; 2048];
  if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut tmp)).await
    && let Some(chunk) = tmp.get(..n)
  {
    tail.extend_from_slice(chunk);
  }
  tail
}

async fn read_message_and_rest<S: AsyncRead + Unpin>(conn: &mut S) -> (LdapMessage, Vec<u8>) {
  let mut buf = Vec::new();
  let mut tmp = [0u8; 1024];
  loop {
    let n = conn.read(&mut tmp).await.unwrap();
    assert_ne!(n, 0, "peer closed before an ldap message");
    let Some(chunk) = tmp.get(..n) else {
      panic!("short read");
    };
    buf.extend_from_slice(chunk);
    if let Ok((message, rest)) = rasn::ber::decode_with_remainder::<LdapMessage>(&buf) {
      return (message, rest.to_vec());
    }
  }
}

#[tokio::test]
async fn ldap_ldaps_bind_swaps_the_password() {
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
  let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, &ca)).await;
  let stub_task = tokio::spawn(async move { answer_ldaps_bind(stub, acceptor).await });
  let stream = connect_through_proxy(proxy_addr, stub_port).await;
  let result = ldap3_bind(stream, Ldap3Open::Ldaps { ca: &ca, sni: true }, FAKE)
    .await
    .expect("ldap3 bind");
  result.success().expect("ldaps bind");
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
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
  let stub_task = tokio::spawn(async move { answer_ldaps_bind(stub, acceptor).await });
  let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let ingress_addr = local_addr(&ingress);
  let serve = tokio::spawn({
    let state = Arc::clone(&state);
    let snapshot = Arc::clone(&snapshot);
    async move {
      let (guest, _) = ingress.accept().await.unwrap();
      serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await
    }
  });
  let stream = TcpStream::connect(ingress_addr).await.unwrap();
  let result = ldap3_bind(stream, Ldap3Open::Ldaps { ca: &ca, sni: false }, FAKE)
    .await
    .expect("ldap3 bind");
  result.success().expect("ldaps bind without sni");
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  serve.await.unwrap().unwrap();
}

#[test]
fn ldap_mtls_on_a_cleartext_fake_loads() {
  let fake = format!("ldap://{}:{FAKE}@localhost:389", user(DN));
  let real = format!("ldaps://{}:{VALUE}@localhost:636", user(DN));
  let grants = resolve_mtls_grants("LDAP_URL", &fake, &real).expect("mtls on an ldap fake loads");
  let scope = grants.first().and_then(|grant| grant.ldap(None, 389)).expect("scope");
  assert_eq!(scope.guest_tls, arkham_config::grants::GuestTlsMode::Mtls);
  assert!(!scope.is_downstream_tls);
}
