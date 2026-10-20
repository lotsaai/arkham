//! End-to-end proxy tests: real clients through the MITM against real
//! stub servers, per protocol and per transport.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arkham_config::grants::{
  Credential, EndpointScope, Grant, GuestTlsMode, PostgresLeg, PostgresScope, RedisScope, ResolvedConfig, Scheme, SslMode, SslNegotiation,
};
use arkham_config::{PluginDirection, ResolvedPlugin};
use arkham_pki::ca::{CertAuthority, install_crypto_provider};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::{ProxyState, bind_explicit, parse_authority, serve, serve_connect_stream, serve_transparent_stream};
use crate::relay::relay_guarded;
use crate::transports::engine::{Direction, Http, Rewritten, Wire};

mod amqp;
mod http;
mod https;
mod ldap;
mod nats;
mod plugin;
mod postgres;
mod redis;
mod smtp;
mod tcp;

/// Test helper: bound address of a listener.
fn local_addr(listener: &TcpListener) -> SocketAddr {
  listener.local_addr().expect("listener has an address")
}

/// Resolve one connection-string rule with `guest_tls_mode = mtls`, the
/// same path `serve` uses. `Err` is the cleartext-fake rejection.
fn resolve_mtls_grants(env: &str, fake: &str, real: &str) -> Result<Vec<Grant>, Box<arkham_config::Error>> {
  use std::collections::BTreeMap;

  use arkham_config::config::{AppConfig, HostTlsCfg, IfMissing, ProxyCfg, WorkspaceCfg};
  use arkham_config::grants::resolve;
  use secrecy::SecretString;

  let mut tls = BTreeMap::new();
  tls.insert(
    env.to_string(),
    HostTlsCfg {
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls_mode: GuestTlsMode::Mtls,
      guest_cert: None,
      guest_key: None,

      upstream_port: None,
    },
  );
  let mut rules = BTreeMap::new();
  rules.insert(
    "t".to_string(),
    arkham_config::RuleCfg {
      env: env.to_string(),
      value: Some(SecretString::from(fake)),
      real: Some(SecretString::from(real)),
      generated: false,
      fnox_key: None,
      allow: Vec::new(),
      pattern: None,
      registry: None,
      oauth2: None,
      ssh: BTreeMap::new(),
      tls,
      if_missing: IfMissing::default(),
    },
  );
  let cfg = AppConfig {
    proxy: ProxyCfg {
      listen: "127.0.0.1:8080".parse().unwrap(),
      ca_file: None,
      ssh_host_key: None,
      ssh_known_hosts: None,
      root_certs: Vec::new(),
      handshake_timeout_secs: 10,
    },
    workspace: WorkspaceCfg::default(),
    rules,
    plugins: BTreeMap::new(),
    tools: BTreeMap::new(),
  };
  resolve(&cfg).map(|resolved| resolved.grants).map_err(Box::new)
}

/// Three-byte H2 frame-length prefix (big-endian, capped at 24 bits).
fn h2_len(len: usize) -> [u8; 3] {
  u32::try_from(len).expect("frame length fits 24 bits").to_be_bytes()[1..4]
    .try_into()
    .expect("three bytes")
}

fn test_state() -> Arc<ProxyState> {
  test_state_with(Vec::new(), &CertAuthority::generate().unwrap())
}

fn test_state_with(grants: Vec<Grant>, ca: &CertAuthority) -> Arc<ProxyState> {
  test_state_with_plugins(grants, Vec::new(), ca)
}

fn test_state_with_plugins(grants: Vec<Grant>, plugins: Vec<ResolvedPlugin>, ca: &CertAuthority) -> Arc<ProxyState> {
  test_state_with_budget(grants, plugins, ca, 10)
}

/// [`test_state_with_plugins`] with an explicit handshake budget, for the
/// tests that pin timeout behavior.
fn test_state_with_budget(
  grants: Vec<Grant>,
  plugins: Vec<ResolvedPlugin>,
  ca: &CertAuthority,
  handshake_timeout_secs: u64,
) -> Arc<ProxyState> {
  install_crypto_provider();
  Arc::new(
    ProxyState::new(
      ResolvedConfig {
        proxy: arkham_config::config::ProxyCfg {
          listen: "127.0.0.1:0".parse().unwrap(),
          ca_file: None,
          ssh_host_key: None,
          ssh_known_hosts: None,
          root_certs: Vec::new(),
          handshake_timeout_secs,
        },
        grants,
        plugins,
      },
      ca,
    )
    .unwrap(),
  )
}

async fn run_proxy_with(state: Arc<ProxyState>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
  let listener = bind_explicit("127.0.0.1:0".parse().unwrap()).await.unwrap();
  let addr = listener.local_addr().unwrap();
  let handle = tokio::spawn(async move {
    serve(listener, state).await;
  });
  (addr, handle)
}

async fn run_proxy() -> (SocketAddr, tokio::task::JoinHandle<()>) {
  run_proxy_with(test_state()).await
}

/// Read until the HTTP head is complete, then return all bytes read so far.
async fn read_head_from<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
  let mut buf = Vec::new();
  let mut chunk = [0u8; 4096];
  loop {
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
      .await
      .unwrap()
      .unwrap();
    assert!(n > 0, "unexpected EOF waiting for head");
    buf.extend_from_slice(&chunk[..n]);
    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
      return buf;
    }
  }
}

struct MitmFixture {
  proxy_addr: SocketAddr,
  proxy: tokio::task::JoinHandle<()>,
  stub: TcpListener,
  stub_port: u16,
  stub_acceptor: TlsAcceptor,
  connector: TlsConnector,
}

/// ALPN a fixture's TLS pair negotiates: what a real client offers and a real
/// server selects. The pump frames an HTTPS scope by this and by nothing
/// else, so [`Alpn::None`] models a protocol that is not HTTP.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Alpn {
  /// `http/1.1`, the ordinary HTTPS negotiation.
  Http1,
  /// `h2`.
  H2,
  /// No protocol agreed.
  None,
}

impl Alpn {
  fn protocols(self) -> Vec<Vec<u8>> {
    match self {
      Alpn::Http1 => vec![b"http/1.1".to_vec()],
      Alpn::H2 => vec![b"h2".to_vec()],
      Alpn::None => Vec::new(),
    }
  }
}

/// Stub server config that selects `alpn`, like a real HTTPS server.
fn stub_server_config(base: &rustls::ServerConfig, alpn: Alpn) -> rustls::ServerConfig {
  let mut config = base.clone();
  config.alpn_protocols = alpn.protocols();
  config
}

/// Guest client config that offers `alpn`, like a real HTTPS client.
fn guest_client_config(roots: rustls::RootCertStore, alpn: Alpn) -> Arc<rustls::ClientConfig> {
  let mut config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
  config.alpn_protocols = alpn.protocols();
  Arc::new(config)
}

/// Proxy + TLS stub presenting a arkham-signed localhost cert; client
/// connector trusts the arkham CA. Grants built with the stub port.
async fn mitm_fixture(make_grants: impl Fn(u16) -> Vec<Grant>) -> MitmFixture {
  mitm_fixture_alpn(make_grants, |_| Vec::new(), Alpn::Http1).await
}

/// [`mitm_fixture`] negotiating `h2`.
async fn mitm_fixture_h2(make_grants: impl Fn(u16) -> Vec<Grant>) -> MitmFixture {
  mitm_fixture_alpn(make_grants, |_| Vec::new(), Alpn::H2).await
}

/// [`mitm_fixture`] with no ALPN agreed at all.
async fn mitm_fixture_no_alpn(make_grants: impl Fn(u16) -> Vec<Grant>) -> MitmFixture {
  mitm_fixture_alpn(make_grants, |_| Vec::new(), Alpn::None).await
}

/// [`mitm_fixture`] plus plugin fixtures built with the stub port.
async fn mitm_fixture_with_plugins(
  make_grants: impl Fn(u16) -> Vec<Grant>,
  make_plugins: impl Fn(u16) -> Vec<ResolvedPlugin>,
) -> MitmFixture {
  mitm_fixture_alpn(make_grants, make_plugins, Alpn::Http1).await
}

/// [`mitm_fixture_with_plugins`] negotiating `h2`.
async fn mitm_fixture_with_plugins_h2(
  make_grants: impl Fn(u16) -> Vec<Grant>,
  make_plugins: impl Fn(u16) -> Vec<ResolvedPlugin>,
) -> MitmFixture {
  mitm_fixture_alpn(make_grants, make_plugins, Alpn::H2).await
}

/// Fixture body shared by the flavors above.
async fn mitm_fixture_alpn(
  make_grants: impl Fn(u16) -> Vec<Grant>,
  make_plugins: impl Fn(u16) -> Vec<ResolvedPlugin>,
  alpn: Alpn,
) -> MitmFixture {
  install_crypto_provider();
  let ca = CertAuthority::generate().unwrap();
  let ca_der = ca.cert_der().clone();
  let stub_cert = ca.generate_domain_cert("localhost").unwrap();
  let stub_acceptor = TlsAcceptor::from(Arc::new(stub_server_config(&stub_cert.server_config, alpn)));
  let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let stub_port = local_addr(&stub).port();
  let mut grants = make_grants(stub_port);
  // Egress trusts webpki plus per-entry bundles only: fixture scopes ride
  // the arkham bundle explicitly, exactly like production rules must.
  let bundle_dir = tempfile::tempdir().unwrap();
  let bundle = bundle_dir.path().join("arkham-ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  for grant in &mut grants {
    let Grant::Token { allow, .. } = grant else { continue };
    for scope in allow {
      if scope.scheme == Scheme::Https && scope.root_cert.is_none() {
        scope.root_cert = Some(bundle.clone());
      }
    }
  }
  let plugins = make_plugins(stub_port);
  let (proxy_addr, proxy) = run_proxy_with(test_state_with_plugins(grants, plugins, &ca)).await;
  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca_der).unwrap();
  let connector = TlsConnector::from(guest_client_config(roots, alpn));
  MitmFixture {
    proxy_addr,
    proxy,
    stub,
    stub_port,
    stub_acceptor,
    connector,
  }
}

fn localhost_grant(port: u16, fake: &str, value: &str) -> Vec<Grant> {
  vec![Grant::Token {
    credential: Credential {
      label: "t".into(),
      fake: fake.into(),
      value: secrecy::SecretString::from(value.to_string()),
    },
    allow: vec![EndpointScope {
      scheme: Scheme::Https,
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

/// CONNECT through the proxy and complete a client TLS handshake.
async fn mitm_client_tls(proxy_addr: SocketAddr, stub_port: u16, connector: &TlsConnector) -> tokio_rustls::client::TlsStream<TcpStream> {
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
  let server_name = ServerName::try_from("localhost".to_string()).unwrap();
  tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client))
    .await
    .unwrap()
    .unwrap()
}

/// Read a full Content-Length body given head bytes already read.
async fn read_body<S: AsyncRead + Unpin>(tls: &mut S, head_bytes: &[u8], len: usize) -> Vec<u8> {
  let head_end = head_bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
  let mut body = Vec::from(&head_bytes[head_end..]);
  while body.len() < len {
    let mut chunk = vec![0u8; len - body.len()];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk))
      .await
      .unwrap()
      .unwrap();
    assert!(n > 0, "unexpected EOF waiting for body");
    body.extend_from_slice(&chunk[..n]);
  }
  body
}
