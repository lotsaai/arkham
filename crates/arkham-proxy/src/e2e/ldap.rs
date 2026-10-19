//! LDAP simple bind through the MITM: a cleartext upstream keeps the decoy,
//! `StartTLS` swaps only after the upgrade, and LDAPS swaps from the first byte.

use super::*;
use arkham_config::grants::LdapScope;
use rasn::prelude::OctetString;
use rasn_ldap::{
  AuthenticationChoice, BindRequest, BindResponse, ExtendedRequest, ExtendedResponse, Filter, LdapMessage, LdapResult, LdapString, ProtocolOp,
  ResultCode, SearchRequest, SearchRequestDerefAliases, SearchRequestScope, SearchResultDone,
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
  let mut buf = Vec::new();
  let mut tmp = [0u8; 1024];
  loop {
    let n = conn.read(&mut tmp).await.unwrap();
    assert!(n > 0, "peer closed before an ldap message");
    buf.extend_from_slice(&tmp[..n]);
    if let Ok((message, _)) = rasn::ber::decode_with_remainder::<LdapMessage>(&buf) {
      return message;
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

#[tokio::test]
async fn ldap_starttls_then_bind_swaps_the_password() {
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
    &format!("ldap://{}:{FAKE}@localhost:{stub_port}", user(DN)),
    &format!("ldap://{}:{VALUE}@localhost:{stub_port}?sslrootcert={}", user(DN), bundle.display()),
  )];
  let state = test_state_with(grants, &ca);
  let (proxy_addr, proxy) = run_proxy_with(state).await;
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let request = read_message(&mut conn).await;
    let ProtocolOp::ExtendedReq(extended) = &request.protocol_op else {
      panic!("starttls request");
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
  let mut stream = connect_through_proxy(proxy_addr, stub_port).await;
  let start = LdapMessage::new(
    1,
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
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let mut tls = TlsConnector::from(Arc::new(config)).connect(name, stream).await.unwrap();
  tls.write_all(&encode(&bind_message(2, FAKE))).await.unwrap();
  let response = read_message(&mut tls).await;
  let ProtocolOp::BindResponse(body) = response.protocol_op else {
    panic!("bind response");
  };
  assert_eq!(body.result_code, ResultCode::Success);
  drop(tls);
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  proxy.abort();
}

/// What the guest sends before `StartTLS` on the same connection.
#[derive(Clone, Copy)]
enum BeforeStartTls {
  /// A simple bind. The cleartext upstream must see the decoy.
  Bind,
  /// A base-object search. The directory answers, then the guest upgrades.
  Search,
}

async fn late_starttls_then_protected_bind(before: BeforeStartTls) {
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
    &format!("ldap://{}:{FAKE}@localhost:{stub_port}", user(DN)),
    &format!("ldap://{}:{VALUE}@localhost:{stub_port}?sslrootcert={}", user(DN), bundle.display()),
  )];
  let state = test_state_with(grants, &ca);
  let (proxy_addr, proxy) = run_proxy_with(state).await;
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let opening = read_message(&mut conn).await;
    match before {
      BeforeStartTls::Bind => {
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
      }
      BeforeStartTls::Search => {
        let ProtocolOp::SearchRequest(_) = &opening.protocol_op else {
          panic!("search request");
        };
        let response = LdapMessage::new(
          opening.message_id,
          ProtocolOp::SearchResDone(SearchResultDone(LdapResult::new(
            ResultCode::Success,
            LdapString::from(""),
            LdapString::from(""),
          ))),
        );
        conn.write_all(&encode(&response)).await.unwrap();
      }
    }
    let request = read_message(&mut conn).await;
    let ProtocolOp::ExtendedReq(extended) = &request.protocol_op else {
      panic!("starttls after the first operation");
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
    let mut tls = acceptor.accept(conn).await.unwrap();
    let bind = read_message(&mut tls).await;
    assert_eq!(simple_password(&bind), VALUE.as_bytes(), "protected bind must carry the real password");
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
  let mut stream = connect_through_proxy(proxy_addr, stub_port).await;
  match before {
    BeforeStartTls::Bind => stream.write_all(&encode(&bind_message(1, FAKE))).await.unwrap(),
    BeforeStartTls::Search => {
      let search = LdapMessage::new(
        1,
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
      );
      stream.write_all(&encode(&search)).await.unwrap();
    }
  }
  let opened = read_message(&mut stream).await;
  match before {
    BeforeStartTls::Bind => {
      let ProtocolOp::BindResponse(body) = opened.protocol_op else {
        panic!("bind response");
      };
      assert_eq!(body.result_code, ResultCode::InvalidCredentials);
    }
    BeforeStartTls::Search => {
      let ProtocolOp::SearchResDone(SearchResultDone(body)) = opened.protocol_op else {
        panic!("search done");
      };
      assert_eq!(body.result_code, ResultCode::Success);
    }
  }
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
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca.cert_der().clone()).unwrap();
  let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
  let name = ServerName::try_from("localhost".to_string()).unwrap();
  let mut tls = tokio::time::timeout(
    Duration::from_secs(5),
    TlsConnector::from(Arc::new(config)).connect(name, stream),
  )
  .await
  .expect("starttls after the first operation upgrades")
  .expect("guest handshake");
  tls.write_all(&encode(&bind_message(3, FAKE))).await.unwrap();
  let response = read_message(&mut tls).await;
  let ProtocolOp::BindResponse(body) = response.protocol_op else {
    panic!("bind response");
  };
  assert_eq!(body.result_code, ResultCode::Success);
  drop(tls);
  tokio::time::timeout(Duration::from_secs(10), stub_task).await.unwrap().unwrap();
  proxy.abort();
}

#[tokio::test]
async fn ldap_bind_then_starttls_then_protected_bind_swaps_the_password() {
  late_starttls_then_protected_bind(BeforeStartTls::Bind).await;
}

#[tokio::test]
async fn ldap_search_then_starttls_then_protected_bind_swaps_the_password() {
  late_starttls_then_protected_bind(BeforeStartTls::Search).await;
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
