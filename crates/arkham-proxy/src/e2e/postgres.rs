use super::*;

use std::pin::Pin;
use std::task::{Context, Poll};

/// Real Postgres client and real Postgres server through the MITM on the
/// cleartext path. tokio-postgres judges the startup handshake arkham parses
/// and the relay; pgwire serves it. The fake travels out in the statement
/// and the real value travels back in the row, so both substitution
/// directions are exercised end to end.
#[tokio::test]
#[expect(clippy::too_many_lines, reason = "linear test script, split would obscure the flow")]
async fn postgres_real_client_and_server_round_trip() {
  use std::sync::Mutex;

  use futures::Sink;
  use futures::stream;
  use pgwire::api::query::SimpleQueryHandler;
  use pgwire::api::results::{DataRowEncoder, FieldFormat, FieldInfo, QueryResponse, Response};
  use pgwire::api::{ClientInfo, PgWireServerHandlers, Type};
  use pgwire::error::{PgWireError, PgWireResult};
  use pgwire::messages::PgWireBackendMessage;

  const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
  const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";

  /// Answers every statement with one row carrying the real value, and
  /// records the statement it was handed.
  struct StubQueryHandler {
    seen: Arc<Mutex<Option<String>>>,
  }

  #[async_trait::async_trait]
  impl SimpleQueryHandler for StubQueryHandler {
    async fn do_query<C>(&self, _client: &mut C, query: &str) -> PgWireResult<Vec<Response>>
    where
      C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
      C::Error: std::fmt::Debug,
      PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
      *self.seen.lock().unwrap() = Some(query.to_string());
      let field = FieldInfo::new("token".into(), None, None, Type::VARCHAR, FieldFormat::Text);
      let schema = Arc::new(vec![field]);
      let mut encoder = DataRowEncoder::new(Arc::clone(&schema));
      encoder.encode_field(&VALUE.to_string())?;
      let row = encoder.take_row();
      Ok(vec![Response::Query(QueryResponse::new(schema, stream::iter(vec![Ok(row)])))])
    }
  }

  struct StubHandlers {
    query: Arc<StubQueryHandler>,
  }

  impl PgWireServerHandlers for StubHandlers {
    fn simple_query_handler(&self) -> Arc<impl SimpleQueryHandler> {
      Arc::clone(&self.query)
    }
  }

  let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
  let handler = Arc::new(StubQueryHandler { seen: Arc::clone(&seen) });
  let fx = mitm_fixture(|port| {
    vec![Grant::Postgres {
      credential: Credential {
        label: "pg".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      scope: Box::new(
        PostgresScope::from_strings(
          &format!("postgres://app:{FAKE}@localhost:{port}/main"),
          &format!("postgres://app:{VALUE}@localhost:{port}/main?sslmode=disable"),
        )
        .unwrap(),
      ),
    }]
  })
  .await;
  let MitmFixture {
    proxy_addr,
    proxy,
    stub,
    stub_port,
    ..
  } = fx;

  // Cleartext `sslmode=disable`: the stub speaks Postgres on the raw socket.
  let stub_task: tokio::task::JoinHandle<Result<(), String>> = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.map_err(|err| format!("accept: {err}"))?;
    pgwire::tokio::process_socket(conn, None, StubHandlers { query: handler })
      .await
      .map_err(|err| format!("pgwire server: {err}"))
  });

  let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
  stream
    .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut head = [0u8; 19];
  stream.read_exact(&mut head).await.unwrap();
  assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
  let config: tokio_postgres::Config = format!("host=localhost port={stub_port} user=stubuser dbname=stubdb sslmode=disable")
    .parse()
    .unwrap();
  let (client, connection) = config.connect_raw(stream, tokio_postgres::NoTls).await.unwrap();
  let conn_task = tokio::spawn(async move {
    let _ = connection.await;
  });
  let rows = client.simple_query(&format!("SELECT '{FAKE}'")).await.unwrap();
  let mut token = None;
  for message in rows {
    if let tokio_postgres::SimpleQueryMessage::Row(row) = message {
      token = row.get("token").map(str::to_string);
    }
  }
  assert_eq!(token.as_deref(), Some(FAKE), "response row must carry the fake");
  assert_eq!(
    seen.lock().unwrap().as_deref(),
    Some(format!("SELECT '{VALUE}'").as_str()),
    "upstream must receive the real value"
  );
  drop(client);
  conn_task.abort();
  let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
  proxy.abort();
}

/// Real TLS Postgres on both ends: a TLS-capable client against a TLS-capable
/// server, for each handshake shape the entry URL and the guest can ask for.
///
/// The entry's `sslmode` is the statement about the far side and the guest
/// states its own transport, so the same proxy is exercised in all four
/// combinations.
mod pg_tls {
  use std::sync::atomic::{AtomicBool, Ordering};

  use futures::Sink;
  use futures::stream;
  use pgwire::api::query::SimpleQueryHandler;
  use pgwire::api::results::{DataRowEncoder, FieldFormat, FieldInfo, QueryResponse, Response};
  use pgwire::api::{ClientInfo, PgWireServerHandlers, Type};
  use pgwire::error::{PgWireError, PgWireResult};
  use pgwire::messages::PgWireBackendMessage;
  use tokio::io::ReadBuf;
  use tokio_postgres::tls::MakeTlsConnect as _;

  use super::*;

  const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
  const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";

  /// Answers every statement with one row carrying the real value, and
  /// records the statement it was handed.
  struct StubQueryHandler {
    seen: Arc<std::sync::Mutex<Option<String>>>,
  }

  #[async_trait::async_trait]
  impl SimpleQueryHandler for StubQueryHandler {
    async fn do_query<C>(&self, _client: &mut C, query: &str) -> PgWireResult<Vec<Response>>
    where
      C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
      C::Error: std::fmt::Debug,
      PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
      *self.seen.lock().unwrap() = Some(query.to_string());
      let field = FieldInfo::new("token".into(), None, None, Type::VARCHAR, FieldFormat::Text);
      let schema = Arc::new(vec![field]);
      let mut encoder = DataRowEncoder::new(Arc::clone(&schema));
      encoder.encode_field(&VALUE.to_string())?;
      let row = encoder.take_row();
      Ok(vec![Response::Query(QueryResponse::new(schema, stream::iter(vec![Ok(row)])))])
    }
  }

  struct StubHandlers {
    query: Arc<StubQueryHandler>,
  }

  impl PgWireServerHandlers for StubHandlers {
    fn simple_query_handler(&self) -> Arc<impl SimpleQueryHandler> {
      Arc::clone(&self.query)
    }
  }

  /// Client-side TLS for a real Postgres client: rustls trusting the CA the
  /// proxy mints from, which is what a `sslmode=require` client needs once
  /// the server's certificate is ours.
  #[derive(Clone)]
  struct PgTls {
    connector: TlsConnector,
  }

  struct PgTlsStream(tokio_rustls::client::TlsStream<TcpStream>);

  impl tokio_postgres::tls::TlsStream for PgTlsStream {
    fn channel_binding(&self) -> tokio_postgres::tls::ChannelBinding {
      tokio_postgres::tls::ChannelBinding::none()
    }
  }

  impl AsyncRead for PgTlsStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
      Pin::new(&mut self.0).poll_read(cx, buf)
    }
  }

  impl AsyncWrite for PgTlsStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
      Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
      Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
      Pin::new(&mut self.0).poll_shutdown(cx)
    }
  }

  struct PgConnect {
    connector: TlsConnector,
    server_name: rustls::pki_types::ServerName<'static>,
    /// Set when this connector's `connect` runs. tokio-postgres calls that
    /// only after the server answers `S`.
    saw_s: Option<Arc<AtomicBool>>,
  }

  impl tokio_postgres::tls::MakeTlsConnect<TcpStream> for PgTls {
    type Stream = PgTlsStream;
    type TlsConnect = PgConnect;
    type Error = std::io::Error;

    fn make_tls_connect(&mut self, domain: &str) -> Result<PgConnect, std::io::Error> {
      let server_name = rustls::pki_types::ServerName::try_from(domain.to_string())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
      Ok(PgConnect {
        connector: self.connector.clone(),
        server_name,
        saw_s: None,
      })
    }
  }

  impl tokio_postgres::tls::TlsConnect<TcpStream> for PgConnect {
    type Stream = PgTlsStream;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<PgTlsStream, std::io::Error>> + Send>>;

    fn connect(self, stream: TcpStream) -> Self::Future {
      if let Some(saw_s) = &self.saw_s {
        saw_s.store(true, Ordering::Relaxed);
      }
      Box::pin(async move { Ok(PgTlsStream(self.connector.connect(self.server_name, stream).await?)) })
    }
  }

  /// Everything a Postgres handshake test needs: the proxy in front of a
  /// pgwire listener, the stub's TLS acceptor when the test wants a TLS
  /// server, and a client connector trusting the CA.
  struct PgStack {
    proxy_addr: SocketAddr,
    proxy: tokio::task::JoinHandle<()>,
    stub: Arc<TcpListener>,
    stub_port: u16,
    seen: Arc<std::sync::Mutex<Option<String>>>,
    acceptor: Option<TlsAcceptor>,
    connector: PgTls,
  }

  /// What the far side speaks, which the entry URL has to describe
  /// truthfully for the handshake to complete.
  #[derive(Clone, Copy, PartialEq, Eq)]
  enum Stub {
    /// A server without TLS: it answers `N` to an `SSLRequest`.
    Cleartext,
    /// A TLS server reached the libpq way, with no ALPN to negotiate.
    Tls,
    /// A PostgreSQL 17 direct-TLS server: the handshake comes first, and the
    /// `postgresql` identifier is mandatory on both ends.
    Direct,
    /// A TLS server that admits no client without a certificate the arkham
    /// CA signed: only an entry-supplied identity gets through.
    TlsRequiresClientAuth,
  }

  /// Both legs of a postgres rule from its two strings, both dialing the
  /// stub, with the needles the pg fixtures swap.
  fn pg_scope(port: u16, query: &str) -> PostgresScope {
    PostgresScope::from_strings(
      &format!("postgres://app:{FAKE}@localhost:{port}/stubdb"),
      &format!("postgres://app:{VALUE}@localhost:{port}/stubdb?{query}"),
    )
    .unwrap()
  }

  /// Start the stack for one `sslmode`/`sslnegotiation` shape and one kind of
  /// server.
  async fn pg_stack(ca: &CertAuthority, query: &str, server: Stub) -> PgStack {
    pg_stack_scope(ca, move |port| pg_scope(port, query), server).await
  }

  /// [`pg_stack`] with the entry scope built by hand, for entries whose
  /// facts do not all fit in a URL.
  async fn pg_stack_scope(ca: &CertAuthority, make_scope: impl Fn(u16) -> PostgresScope, server: Stub) -> PgStack {
    install_crypto_provider();
    let stub_cert = ca.generate_domain_cert("localhost").unwrap();
    let acceptor = match server {
      Stub::Cleartext => None,
      Stub::TlsRequiresClientAuth => Some({
        let (chain, key) = arkham_pki::ca::generate_domain_pair(ca, "localhost").unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build().unwrap();
        let config = rustls::ServerConfig::builder()
          .with_client_cert_verifier(verifier)
          .with_single_cert(chain, key)
          .unwrap();
        TlsAcceptor::from(Arc::new(config))
      }),
      Stub::Tls | Stub::Direct => Some({
        let mut config = (*stub_cert.server_config).clone();
        config.alpn_protocols = if server == Stub::Direct {
          vec![b"postgresql".to_vec()]
        } else {
          Vec::new()
        };
        TlsAcceptor::from(Arc::new(config))
      }),
    };
    let stub = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let stub_port = local_addr(&stub).port();
    let grants = vec![Grant::Postgres {
      credential: Credential {
        label: "pg".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      scope: Box::new(make_scope(stub_port)),
    }];
    let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, ca)).await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let mut client_config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    if server == Stub::Direct {
      // A direct-TLS client offers the same identifier the server requires.
      client_config.alpn_protocols = vec![b"postgresql".to_vec()];
    }
    let connector = PgTls {
      connector: TlsConnector::from(Arc::new(client_config)),
    };
    PgStack {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      seen: Arc::new(std::sync::Mutex::new(None)),
      acceptor,
      connector,
    }
  }

  /// Serve one Postgres connection on the stub listener, TLS or not.
  fn serve_stub(stack: &PgStack) -> tokio::task::JoinHandle<Result<(), String>> {
    let query = Arc::new(StubQueryHandler {
      seen: Arc::clone(&stack.seen),
    });
    let acceptor = stack.acceptor.clone();
    let stub = Arc::clone(&stack.stub);
    tokio::spawn(async move {
      let (conn, _) = stub.accept().await.map_err(|err| format!("accept: {err}"))?;
      pgwire::tokio::process_socket(conn, acceptor, StubHandlers { query })
        .await
        .map_err(|err| format!("pgwire server: {err}"))
    })
  }

  /// Run one statement through the proxy as the real client, returning the
  /// row's token and the statement the server saw.
  async fn round_trip(stack: &PgStack, connect: &str) -> Result<(String, Option<String>), String> {
    round_trip_with(stack, connect, stack.connector.clone()).await
  }

  /// [`round_trip`] with the client's TLS connector replaced.
  async fn round_trip_with(stack: &PgStack, connect: &str, mut connector: PgTls) -> Result<(String, Option<String>), String> {
    let mut stream = TcpStream::connect(stack.proxy_addr)
      .await
      .map_err(|err| format!("proxy connect: {err}"))?;
    stream
      .write_all(format!("CONNECT localhost:{} HTTP/1.1\r\nHost: localhost\r\n\r\n", stack.stub_port).as_bytes())
      .await
      .map_err(|err| format!("CONNECT: {err}"))?;
    let mut head = [0u8; 19];
    stream.read_exact(&mut head).await.map_err(|err| format!("CONNECT head: {err}"))?;
    if &head != b"HTTP/1.1 200 OK\r\n\r\n" {
      return Err(format!("CONNECT reply: {}", String::from_utf8_lossy(&head)));
    }
    let config: tokio_postgres::Config = format!("host=localhost port={} user=stubuser dbname=stubdb {connect}", stack.stub_port)
      .parse()
      .map_err(|err| format!("config: {err}"))?;
    let tls = connector
      .make_tls_connect("localhost")
      .map_err(|err| format!("client tls: {err}"))?;
    let (client, connection) = config
      .connect_raw(stream, tls)
      .await
      .map_err(|err| format!("client connect: {err}"))?;
    let conn_task = tokio::spawn(async move {
      let _ = connection.await;
    });
    let rows = client
      .simple_query(&format!("SELECT '{FAKE}'"))
      .await
      .map_err(|err| format!("query: {err}"))?;
    let mut token = None;
    for message in rows {
      if let tokio_postgres::SimpleQueryMessage::Row(row) = message {
        token = row.get("token").map(ToString::to_string);
      }
    }
    conn_task.abort();
    let token = token.ok_or_else(|| "no row came back".to_string())?;
    let seen = stack.seen.lock().unwrap().clone();
    Ok((token, seen))
  }

  /// Assert one happy round trip: fake in, real upstream, fake back.
  async fn assert_round_trip(stack: &PgStack, connect: &str) {
    let stub_task = serve_stub(stack);
    let (token, seen) = round_trip(stack, connect).await.unwrap();
    assert_eq!(token, FAKE, "the row must carry the fake");
    assert_eq!(
      seen.as_deref(),
      Some(format!("SELECT '{VALUE}'").as_str()),
      "the server must see the real value"
    );
    let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
    stack.proxy.abort();
  }

  #[tokio::test]
  async fn postgres_tls_classic_negotiation_round_trip() {
    // libpq's SSLRequest, on a TLS server: the shape every client uses.
    let ca = CertAuthority::generate().unwrap();
    let stack = pg_stack(&ca, "sslmode=require", Stub::Tls).await;
    assert_round_trip(&stack, "sslmode=require").await;
  }

  /// The entry's `sslcert`/`sslkey` pair is the proxy's identity to the
  /// server: this stub admits no one without a client certificate the
  /// arkham CA signed, so the round trip only completes when the upstream
  /// leg presents the entry's.
  #[tokio::test]
  async fn postgres_entry_presents_its_client_identity_to_the_server() {
    use rama::crypto::pem::PemEncode as _;
    let ca = CertAuthority::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (chain, key) = arkham_pki::ca::generate_client_pair(&ca, "arkham-client").unwrap();
    let mut cert_pem = Vec::new();
    for cert in &chain {
      cert_pem.extend_from_slice(cert.to_pem().as_bytes());
    }
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, key.to_pem()).unwrap();
    let query = format!("sslmode=require&sslcert={}&sslkey={}", cert_path.display(), key_path.display());
    let stack = pg_stack(&ca, &query, Stub::TlsRequiresClientAuth).await;
    assert_round_trip(&stack, "sslmode=require").await;
  }

  /// `sslrootcert=system` names the platform trust store, not the arkham
  /// CA: a verify-full entry holds the self-signed stub against it and
  /// the session cannot complete, proving the store was loaded and enforced.
  #[tokio::test]
  async fn postgres_verify_full_system_store_rejects_the_stub() {
    let ca = CertAuthority::generate().unwrap();
    let stack = pg_stack(&ca, "sslmode=verify-full&sslrootcert=system", Stub::Tls).await;
    let stub_task = serve_stub(&stack);
    round_trip(&stack, "sslmode=require").await.unwrap_err();
    let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
    stack.proxy.abort();
  }

  /// A silent upstream — TCP accepted, `SSLRequest` never answered — must
  /// close the leg inside the entry-configured budget instead of holding
  /// the connection forever.
  #[tokio::test]
  async fn postgres_silent_upstream_closes_within_the_budget() {
    let ca = CertAuthority::generate().unwrap();
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    tokio::spawn(async move {
      let (_stream, _) = stub.accept().await.unwrap();
      tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let grants = vec![Grant::Postgres {
      credential: Credential {
        label: "pg".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      scope: Box::new(pg_scope(stub_port, "sslmode=require")),
    }];
    let state = test_state_with_budget(grants, Vec::new(), &ca, 1);
    let (proxy_addr, _proxy) = run_proxy_with(state).await;

    let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
    guest
      .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut head = [0u8; 19];
    guest.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    let config: tokio_postgres::Config = format!("host=localhost port={stub_port} user=stubuser dbname=stubdb sslmode=disable")
      .parse()
      .unwrap();
    let opened = tokio::time::timeout(Duration::from_secs(3), config.connect_raw(guest, tokio_postgres::NoTls))
      .await
      .expect("the budget must close the leg");
    assert!(
      opened.is_err(),
      "a cleartext guest must see the leg close while the upstream stays silent"
    );
  }

  /// `guest_tls_mode = "mtls"` on a postgres entry: arkham asks the guest
  /// for a client certificate and admits only ones its own CA signs. A
  /// client with a arkham-CA-signed identity gets through; one without is
  /// refused by the guest handshake itself.
  #[tokio::test]
  async fn postgres_guest_mtls_admits_only_ca_signed_guests() {
    let ca = CertAuthority::generate().unwrap();
    let stack = pg_stack_scope(
      &ca,
      |port| PostgresScope {
        downstream: PostgresLeg {
          host: "localhost".to_string(),
          port,
          user: Some("app".to_string()),
          password: secrecy::SecretString::from(FAKE),
          database: None,
        },
        upstream: PostgresLeg {
          host: "localhost".to_string(),
          port,
          user: Some("app".to_string()),
          password: secrecy::SecretString::from(VALUE),
          database: None,
        },
        ssl: SslMode::Prefer,
        negotiation: SslNegotiation::Postgres,
        root_cert: None,
        client_cert: None,
        client_key: None,
        guest_tls: GuestTlsMode::Mtls,
      },
      Stub::Tls,
    )
    .await;

    // Present a arkham-CA-signed identity: the session completes.
    let stub_task = serve_stub(&stack);
    let (chain, key) = arkham_pki::ca::generate_client_pair(&ca, "guest").unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_client_auth_cert(chain, key)
      .unwrap();
    let connector = PgTls {
      connector: TlsConnector::from(Arc::new(client_config)),
    };
    let (token, seen) = round_trip_with(&stack, "sslmode=require", connector).await.unwrap();
    assert_eq!(token, FAKE, "the row must carry the fake");
    assert_eq!(seen.as_deref(), Some(format!("SELECT '{VALUE}'").as_str()));
    let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;

    // No client identity: arkham's own handshake refuses the guest.
    let stub_task = serve_stub(&stack);
    round_trip(&stack, "sslmode=require").await.unwrap_err();
    let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
    stack.proxy.abort();
  }

  /// `sslmode=allow` with a cleartext guest: the upstream leg stays
  /// cleartext — the greeting relays on with no `SSLRequest` in front of it.
  #[tokio::test]
  async fn postgres_allow_with_a_cleartext_guest_never_asks_upstream_for_tls() {
    let ca = CertAuthority::generate().unwrap();
    let spy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let spy_port = spy.local_addr().unwrap().port();
    let seen = tokio::spawn(async move {
      let (mut stream, _) = spy.accept().await.unwrap();
      let mut buf = [0u8; 8];
      stream.read_exact(&mut buf).await.expect("the upstream must receive 8 bytes");
      buf
    });
    let grants = vec![Grant::Postgres {
      credential: Credential {
        label: "pg".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      scope: Box::new(pg_scope(spy_port, "sslmode=allow")),
    }];
    let state = test_state_with_budget(grants, Vec::new(), &ca, 10);
    let (proxy_addr, _proxy) = run_proxy_with(state).await;

    let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
    guest
      .write_all(format!("CONNECT localhost:{spy_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut head = [0u8; 19];
    guest.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    let config: tokio_postgres::Config = format!("host=localhost port={spy_port} user=stubuser dbname=stubdb sslmode=disable")
      .parse()
      .unwrap();
    let opened = config.connect_raw(guest, tokio_postgres::NoTls).await;
    let upstream_first8 = tokio::time::timeout(Duration::from_secs(5), seen)
      .await
      .expect("the spy must see the opening")
      .unwrap();
    assert!(opened.is_err(), "the spy closes after the startup, so the session cannot finish");
    assert_eq!(
      &upstream_first8[4..8],
      &196_608u32.to_be_bytes(),
      "allow with a cleartext guest must relay a protocol 3.0 startup"
    );
  }

  /// `sslmode=allow` with a guest that asked for TLS: the upstream leg
  /// escalates too — the first bytes upstream are the `SSLRequest`.
  #[tokio::test]
  async fn postgres_allow_with_a_tls_guest_escalates_upstream_to_tls() {
    let ca = CertAuthority::generate().unwrap();
    let spy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let spy_port = spy.local_addr().unwrap().port();
    let seen = tokio::spawn(async move {
      let (mut stream, _) = spy.accept().await.unwrap();
      let mut buf = [0u8; 8];
      let _ = stream.read_exact(&mut buf).await;
      buf
    });
    let grants = vec![Grant::Postgres {
      credential: Credential {
        label: "pg".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      scope: Box::new(pg_scope(spy_port, "sslmode=allow")),
    }];
    let state = test_state_with_budget(grants, Vec::new(), &ca, 10);
    let (proxy_addr, _proxy) = run_proxy_with(state).await;

    let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
    guest
      .write_all(format!("CONNECT localhost:{spy_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut head = [0u8; 19];
    guest.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let mut connector = PgTls {
      connector: TlsConnector::from(guest_client_config(roots, Alpn::None)),
    };
    let mut tls = connector.make_tls_connect("localhost").unwrap();
    let saw_s = Arc::new(AtomicBool::new(false));
    tls.saw_s = Some(Arc::clone(&saw_s));
    let config: tokio_postgres::Config = format!("host=localhost port={spy_port} user=stubuser dbname=stubdb sslmode=require")
      .parse()
      .unwrap();
    let opened = config.connect_raw(guest, tls).await;
    let upstream_first8 = tokio::time::timeout(Duration::from_secs(5), seen)
      .await
      .expect("the spy must see the opening")
      .unwrap();
    assert!(saw_s.load(Ordering::Relaxed), "the proxy must answer S before the guest starts TLS");
    assert!(
      opened.is_err(),
      "the guest's TLS handshake cannot finish because the spy never answers upstream"
    );
    assert_eq!(
      &upstream_first8[4..8],
      &pgwire::messages::startup::SslRequest::BODY_MAGIC_NUMBER.to_be_bytes(),
      "allow with a TLS guest must ask the server for TLS"
    );
  }

  #[tokio::test]
  async fn postgres_tls_direct_negotiation_round_trip() {
    // PostgreSQL 17 direct TLS: no SSLRequest, `postgresql` in ALPN.
    let ca = CertAuthority::generate().unwrap();
    let stack = pg_stack(&ca, "sslmode=require&sslnegotiation=direct", Stub::Direct).await;
    assert_round_trip(&stack, "sslmode=require sslnegotiation=direct").await;
  }

  #[tokio::test]
  async fn postgres_prefer_uses_tls_when_the_server_offers_it() {
    let ca = CertAuthority::generate().unwrap();
    let stack = pg_stack(&ca, "sslmode=prefer", Stub::Tls).await;
    assert_round_trip(&stack, "sslmode=prefer").await;
  }

  #[tokio::test]
  async fn postgres_prefer_falls_back_when_the_server_refuses_tls() {
    // The other half of `prefer`: a server that answers `N` still gets the
    // session, which is what makes the mode usable against cleartext servers.
    let ca = CertAuthority::generate().unwrap();
    let stack = pg_stack(&ca, "sslmode=prefer", Stub::Cleartext).await;
    assert_round_trip(&stack, "sslmode=prefer").await;
  }

  #[tokio::test]
  async fn postgres_verify_full_round_trip_against_the_entry_anchor() {
    let ca = CertAuthority::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let anchor = dir.path().join("root.pem");
    std::fs::write(&anchor, ca.cert_pem()).unwrap();
    let stack = pg_stack(&ca, &format!("sslmode=verify-full&sslrootcert={}", anchor.display()), Stub::Tls).await;
    // The client states its own policy; this one has no `verify-full` of its
    // own, and it is the entry that asks the proxy to verify.
    assert_round_trip(&stack, "sslmode=require").await;
  }

  #[tokio::test]
  async fn postgres_tls_client_on_a_cleartext_entry_still_reaches_the_server() {
    // The entry says the far side is cleartext; the guest asks for TLS
    // anyway, and a real server would have answered `S` too.
    let ca = CertAuthority::generate().unwrap();
    let stack = pg_stack(&ca, "sslmode=disable", Stub::Cleartext).await;
    assert_round_trip(&stack, "sslmode=require").await;
  }

  #[tokio::test]
  async fn postgres_cleartext_client_on_a_tls_entry_still_reaches_the_server() {
    // The entry says the far side needs TLS; the guest opens cleartext.
    let ca = CertAuthority::generate().unwrap();
    let stack = pg_stack(&ca, "sslmode=require", Stub::Tls).await;
    assert_round_trip(&stack, "sslmode=disable").await;
  }

  #[tokio::test]
  async fn postgres_require_closes_when_the_server_refuses_tls() {
    // A cleartext-only server under an entry that requires TLS: no session,
    // and no statement — and no credential — reaches the server.
    let ca = CertAuthority::generate().unwrap();
    let stack = pg_stack(&ca, "sslmode=require", Stub::Cleartext).await;
    let stub_task = serve_stub(&stack);
    assert!(
      round_trip(&stack, "sslmode=require").await.is_err(),
      "a refused TLS leg cannot carry a session"
    );
    assert_eq!(stack.seen.lock().unwrap().as_deref(), None, "no statement may reach the server");
    let _ = tokio::time::timeout(Duration::from_secs(10), stub_task).await;
    stack.proxy.abort();
  }
}
