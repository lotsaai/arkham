//! Protocol transports. This root is protocol-blind: it holds the traits —
//! one per responsibility — the stream a transport is handed, and the
//! shared substitution engine. Each protocol vertical implements the
//! responsibilities it owns; the composition root (lib.rs) retains the
//! strategies, and the picker (identity.rs) routes one stream to one
//! strategy in one place.

pub mod amqp;
pub mod engine;
pub mod http;
pub mod ldap;
pub mod nats;
pub mod postgres;
pub mod redis;
pub mod smtp;
pub mod ssh;
pub mod tcp;
pub mod tls;

use std::path::Path;
use std::sync::Arc;

use arkham_config::grants::{Grant, GuestTlsMode, RootCert};
use arkham_pki::ca::CertAuthority;
use dashmap::DashMap;
use rustls::client::WantsClientCert;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ConfigBuilder, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::Error;
use crate::connection::client_identity;
use crate::identity::CandidateParams;
use crate::mint::MintHandle;
use rama::tls::client::ClientAuth;

use self::tls::{cached_leaf, cached_leaf_mtls, cached_roots};

/// One candidate stream handed to a transport: the guest stream, the
/// dispatch params, and the scope the grants stated for it.
pub(crate) struct ServeStream<'a, G, S> {
  /// The guest's stream, plus any bytes the ingress already read.
  pub(crate) guest: G,
  /// Targets, identity material, and the shared state.
  pub(crate) params: CandidateParams<'a>,
  /// The typed scope this protocol's grants carry.
  pub(crate) scope: &'a S,
}

/// Serving one stream for one protocol: the dispatchable strategy.
pub(crate) trait Transport: Send + Sync {
  /// The typed scope this protocol's grants carry.
  type Scope: Sync;

  /// Settle both legs of one candidate stream and pump it.
  ///
  /// # Errors
  ///
  /// Returns an error when a leg cannot be settled; malformed guest
  /// traffic closes quietly instead.
  fn serve<G>(&self, stream: ServeStream<'_, G, Self::Scope>) -> impl Future<Output = Result<(), Error>>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static;
}

/// Terminating the guest's TLS and handshaking the real server.
///
/// The handshake bodies are shared. A protocol supplies its cache, the
/// diagnostic label, and how its scope names trust and identity. It overrides
/// ALPN or [`TlsHalves::client_builder`] only when its wire law differs.
pub(crate) trait TlsHalves: Send + Sync {
  /// The typed scope this protocol's grants carry.
  type Scope: Sync;

  /// CA that signs guest leaves.
  fn ca(&self) -> &CertAuthority;

  /// Guest leaf cache, keyed by name.
  fn leaves(&self) -> &DashMap<String, Arc<ServerConfig>>;

  /// Upstream trust-anchor cache.
  fn roots(&self) -> &DashMap<RootCert, Arc<RootCertStore>>;

  /// Protocol word used in the shared TLS errors. `redis` prints `guest redis TLS`.
  fn tls_label(&self) -> &'static str;

  /// Trust anchor the scope names. `None` is the platform store for the shared builder.
  fn root_cert<'a>(&self, scope: &'a Self::Scope) -> Option<&'a RootCert>;

  /// Client certificate and key, present together or not at all.
  fn client_paths<'a>(&self, scope: &'a Self::Scope) -> Option<(&'a Path, &'a Path)>;

  /// ALPN offered to the guest. `None` offers nothing.
  fn guest_alpn(&self) -> Option<&'static [u8]> {
    None
  }

  /// ALPN offered upstream. `None` offers nothing.
  fn server_alpn(&self, _scope: &Self::Scope) -> Option<&'static [u8]> {
    None
  }

  /// Rustls client builder after verification is chosen and before client identity.
  ///
  /// The default verifies the chain and the host name against [`TlsHalves::root_cert`],
  /// or the platform store when the scope names none.
  ///
  /// # Errors
  ///
  /// Returns an error when the trust anchor cannot be read.
  fn client_builder(&self, scope: &Self::Scope) -> Result<ConfigBuilder<ClientConfig, WantsClientCert>, Error> {
    let root = self.root_cert(scope).cloned().unwrap_or(RootCert::System);
    let roots = cached_roots(self.roots(), &root)?;
    Ok(ClientConfig::builder().with_root_certificates(roots))
  }

  /// Client configuration for the upstream handshake, including identity.
  ///
  /// # Errors
  ///
  /// Returns an error when the trust anchor or the client identity cannot be read.
  fn client_config(&self, scope: &Self::Scope) -> Result<ClientConfig, Error> {
    with_client_identity(self.client_builder(scope)?, self.client_paths(scope))
  }

  /// Terminate the guest's TLS with a leaf minted for `name`.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted or the handshake fails.
  async fn accept_guest<G>(&self, name: &str, guest: G, guest_tls: GuestTlsMode) -> Result<ServerTlsStream<G>, Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    let alpn = self.guest_alpn();
    let config = match guest_tls {
      GuestTlsMode::Tls => cached_leaf(self.ca(), self.leaves(), name, alpn)?,
      GuestTlsMode::Mtls => cached_leaf_mtls(self.ca(), self.leaves(), name, alpn)?,
    };
    TlsAcceptor::from(config).accept(guest).await.map_err(|source| Error::GuestTls {
      protocol: self.tls_label(),
      source,
    })
  }

  /// Handshake the real server.
  ///
  /// # Errors
  ///
  /// Returns an error when the named trust anchor cannot be read, when the
  /// server name is unusable, or when the handshake fails.
  async fn connect_server<S>(&self, scope: &Self::Scope, server_name: &str, server: S) -> Result<ClientTlsStream<S>, Error>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let mut config = self.client_config(scope)?;
    if let Some(alpn) = self.server_alpn(scope) {
      config.alpn_protocols = vec![alpn.to_vec()];
    }
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| Error::ServerName {
      protocol: self.tls_label(),
      source: err.into(),
    })?;
    TlsConnector::from(Arc::new(config))
      .connect(name, server)
      .await
      .map_err(|source| Error::ServerTls {
        protocol: self.tls_label(),
        source,
      })
  }
}

/// Install a client certificate when the scope names both paths.
///
/// # Errors
///
/// Returns an error when the identity cannot be read or rustls rejects it.
fn with_client_identity(
  builder: ConfigBuilder<ClientConfig, WantsClientCert>,
  identity: Option<(&Path, &Path)>,
) -> Result<ClientConfig, Error> {
  match identity {
    Some((cert, key)) => {
      let ClientAuth::Single(data) = client_identity(cert, key)? else {
        return Err(Error::EmptyClientIdentity { path: cert.to_path_buf() });
      };
      builder
        .with_client_auth_cert(data.cert_chain.clone(), data.private_key.clone_key())
        .map_err(|source| Error::ClientIdentity {
          path: cert.to_path_buf(),
          source,
        })
    }
    None => Ok(builder.with_no_client_auth()),
  }
}

/// Borrowed construction context for a framing pair: grants authorize,
/// plugins hook, and the connection identity scopes both.
pub(crate) struct PairCtx<'a> {
  /// Grant source for eligible pairs.
  pub(crate) grants: &'a [Grant],
  /// Connection endpoint host.
  pub(crate) host: &'a str,
  /// Connection endpoint port.
  pub(crate) port: u16,
  /// Per-connection plugin registry.
  pub(crate) plugins: &'a arkham_plugin::Registry,
  /// Runtime token-mint handle; `None` keeps value-swap-only behavior.
  pub(crate) mint: Option<MintHandle>,
}

#[cfg(test)]
mod tests {
  use std::path::{Path, PathBuf};
  use std::sync::Arc;
  use std::time::Duration;

  use arkham_config::grants::{GuestTlsMode, RootCert};
  use arkham_pki::ca::{CertAuthority, generate_domain_pair, install_crypto_provider, load_or_generate_client_pair};
  use dashmap::DashMap;
  use rustls::pki_types::ServerName;
  use rustls::{ClientConfig, RootCertStore, ServerConfig};
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
  use tokio::net::{TcpListener, TcpStream};
  use tokio_rustls::{TlsAcceptor, TlsConnector};

  use super::TlsHalves;
  use crate::Error;

  struct Material {
    root: Option<RootCert>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
  }

  struct Halves {
    ca: CertAuthority,
    leaves: DashMap<String, Arc<ServerConfig>>,
    roots: DashMap<RootCert, Arc<RootCertStore>>,
    alpn: Option<&'static [u8]>,
  }

  impl TlsHalves for Halves {
    type Scope = Material;

    fn ca(&self) -> &CertAuthority {
      &self.ca
    }

    fn leaves(&self) -> &DashMap<String, Arc<ServerConfig>> {
      &self.leaves
    }

    fn roots(&self) -> &DashMap<RootCert, Arc<RootCertStore>> {
      &self.roots
    }

    fn tls_label(&self) -> &'static str {
      "shared"
    }

    fn guest_alpn(&self) -> Option<&'static [u8]> {
      self.alpn
    }

    fn server_alpn(&self, _scope: &Material) -> Option<&'static [u8]> {
      self.alpn
    }

    fn root_cert<'a>(&self, scope: &'a Material) -> Option<&'a RootCert> {
      scope.root.as_ref()
    }

    fn client_paths<'a>(&self, scope: &'a Material) -> Option<(&'a Path, &'a Path)> {
      match (&scope.cert, &scope.key) {
        (Some(cert), Some(key)) => Some((cert.as_path(), key.as_path())),
        _ => None,
      }
    }
  }

  struct Fixture {
    halves: Halves,
    dir: tempfile::TempDir,
    root: RootCert,
  }

  impl Fixture {
    fn new(alpn: Option<&'static [u8]>) -> Self {
      install_crypto_provider();
      let ca = CertAuthority::generate().expect("ca");
      let dir = tempfile::tempdir().expect("tempdir");
      let path = dir.path().join("ca.pem");
      std::fs::write(&path, ca.cert_pem()).expect("ca pem");
      Self {
        halves: Halves {
          ca,
          leaves: DashMap::new(),
          roots: DashMap::new(),
          alpn,
        },
        root: RootCert::Path(path),
        dir,
      }
    }

    fn material(&self, identity: bool) -> Material {
      let (cert, key) = if identity {
        let (cert, key) = load_or_generate_client_pair(self.halves.ca(), self.dir.path(), "proxy").expect("client pair");
        (Some(cert), Some(key))
      } else {
        (None, None)
      };
      Material {
        root: Some(self.root.clone()),
        cert,
        key,
      }
    }
  }

  fn trusting_client(ca: &CertAuthority, alpn: Option<&[u8]>) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der().clone()).expect("anchor");
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    if let Some(alpn) = alpn {
      config.alpn_protocols = vec![alpn.to_vec()];
    }
    TlsConnector::from(Arc::new(config))
  }

  fn demanding_server(ca: &CertAuthority, name: &str) -> Arc<ServerConfig> {
    let (chain, key) = generate_domain_pair(ca, name).expect("server leaf");
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der().clone()).expect("anchor");
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
      .build()
      .expect("verifier");
    let config = ServerConfig::builder()
      .with_client_cert_verifier(verifier)
      .with_single_cert(chain, key)
      .expect("server config");
    Arc::new(config)
  }

  async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });
    let (server, _) = listener.accept().await.expect("accept");
    (client.await.expect("client"), server)
  }

  async fn within<T>(work: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), work).await.expect("handshake")
  }

  #[tokio::test]
  async fn shared_halves_accept_offers_alpn_only_when_the_protocol_sets_it() {
    for (alpn, offered, agreed) in [
      (None, Some(&b"postgresql"[..]), None),
      (Some(&b"postgresql"[..]), Some(&b"postgresql"[..]), Some(&b"postgresql"[..])),
    ] {
      let fixture = Fixture::new(alpn);
      let (client, server) = pair().await;
      let connector = trusting_client(fixture.halves.ca(), offered);
      let name = ServerName::try_from("db.example".to_string()).expect("name");
      let accepted = fixture.halves.accept_guest("db.example", server, GuestTlsMode::Tls);
      let connected = connector.connect(name, client);
      let (accepted, connected) = within(async { tokio::join!(accepted, connected) }).await;
      let mut accepted = accepted.expect("guest accept");
      let mut connected = connected.expect("guest client");
      assert_eq!(accepted.get_ref().1.alpn_protocol(), agreed);
      connected.write_all(b"ping").await.expect("write");
      connected.flush().await.expect("flush");
      let mut buf = [0u8; 4];
      accepted.read_exact(&mut buf).await.expect("read");
      assert_eq!(&buf, b"ping");
    }
  }

  #[tokio::test]
  async fn shared_halves_connect_verifies_chain_and_name() {
    let fixture = Fixture::new(None);
    let scope = fixture.material(false);
    let server_config = fixture
      .halves
      .ca()
      .generate_domain_cert("upstream.example")
      .expect("leaf")
      .server_config;
    let (client, server) = pair().await;
    let acceptor = TlsAcceptor::from(server_config);
    let connected = fixture.halves.connect_server(&scope, "upstream.example", client);
    let accepted = acceptor.accept(server);
    let (connected, accepted) = within(async { tokio::join!(connected, accepted) }).await;
    let mut connected = connected.expect("upstream connect");
    let mut accepted = accepted.expect("upstream server");
    connected.write_all(b"ping").await.expect("write");
    connected.flush().await.expect("flush");
    let mut buf = [0u8; 4];
    accepted.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"ping");

    let other = CertAuthority::generate().expect("other ca");
    let foreign = other.generate_domain_cert("upstream.example").expect("foreign leaf").server_config;
    let (client, server) = pair().await;
    let connected = fixture.halves.connect_server(&scope, "upstream.example", client);
    let accepted = TlsAcceptor::from(foreign).accept(server);
    let (connected, _) = within(async { tokio::join!(connected, accepted) }).await;
    let err = connected.expect_err("untrusted upstream");
    assert!(matches!(err, Error::ServerTls { protocol: "shared", .. }), "{err}");
  }

  #[tokio::test]
  async fn shared_halves_connect_presents_the_scope_client_certificate() {
    let fixture = Fixture::new(None);
    let scope = fixture.material(true);
    let server_config = demanding_server(fixture.halves.ca(), "upstream.example");
    let (client, server) = pair().await;
    let connected = fixture.halves.connect_server(&scope, "upstream.example", client);
    let accepted = TlsAcceptor::from(server_config).accept(server);
    let (connected, accepted) = within(async { tokio::join!(connected, accepted) }).await;
    connected.expect("mtls upstream");
    let accepted = accepted.expect("server");
    assert!(accepted.get_ref().1.peer_certificates().is_some());

    let bare = fixture.material(false);
    let server_config = demanding_server(fixture.halves.ca(), "upstream.example");
    let (client, server) = pair().await;
    let connected = fixture.halves.connect_server(&bare, "upstream.example", client);
    let accepted = TlsAcceptor::from(server_config).accept(server);
    let (connected, accepted) = within(async { tokio::join!(connected, accepted) }).await;
    // TLS 1.3 finishes the client flight before the server can reject a missing certificate.
    connected.expect("client flight");
    accepted.expect_err("server requires a client certificate");
  }

  #[tokio::test]
  async fn shared_halves_connect_rejects_an_unusable_server_name() {
    let fixture = Fixture::new(None);
    let scope = fixture.material(false);
    let (client, _server) = tokio::io::duplex(16);
    let err = fixture
      .halves
      .connect_server(&scope, "bad host", client)
      .await
      .expect_err("server name");
    assert!(matches!(err, Error::ServerName { protocol: "shared", .. }), "{err}");
  }

  #[tokio::test]
  async fn shared_halves_mtls_accept_rejects_a_guest_without_a_certificate() {
    let fixture = Fixture::new(None);
    let (client, server) = pair().await;
    let connector = trusting_client(fixture.halves.ca(), None);
    let name = ServerName::try_from("db.example".to_string()).expect("name");
    let accepted = fixture.halves.accept_guest("db.example", server, GuestTlsMode::Mtls);
    let connected = connector.connect(name, client);
    let (accepted, _) = within(async { tokio::join!(accepted, connected) }).await;
    let err = accepted.expect_err("mtls guest");
    assert!(matches!(err, Error::GuestTls { protocol: "shared", .. }), "{err}");
  }
}
