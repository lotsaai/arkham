//! Shared TLS legs: guest accept, upstream connect, and the handshake budget.

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use dashmap::DashMap;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, ServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_pki::ca::CertAuthority;
use arkham_pki::ca::generate_domain_pair;
use rama::tls::client::ClientAuth;

use crate::identity::client_identity;
use crate::{Error, GuestTlsMode, RootCert};

/// Leaf for one name, cached.
///
/// # Errors
///
/// Returns an error when the leaf cannot be minted.
pub fn cached_leaf(
  ca: &CertAuthority,
  leaves: &DashMap<String, Arc<ServerConfig>>,
  sni: &str,
  alpn: Option<&[u8]>,
) -> Result<Arc<ServerConfig>, Error> {
  let cache_key = leaf_cache_key(sni, alpn, false);
  if let Some(config) = leaves.get(&cache_key) {
    return Ok(config.clone());
  }
  let mut config = (*ca.generate_domain_cert(sni)?.server_config).clone();
  if let Some(alpn) = alpn {
    config.alpn_protocols = vec![alpn.to_vec()];
  }
  let config = Arc::new(config);
  leaves.insert(cache_key, Arc::clone(&config));
  Ok(config)
}

/// `mtls` variant of [`cached_leaf`]: the same leaf shape, presented by a
/// config that demands a client certificate this arkham's CA can verify.
///
/// # Errors
///
/// Returns an error when the leaf cannot be minted or the verifier cannot
/// be built.
pub fn cached_leaf_mtls(
  ca: &CertAuthority,
  leaves: &DashMap<String, Arc<ServerConfig>>,
  sni: &str,
  alpn: Option<&[u8]>,
) -> Result<Arc<ServerConfig>, Error> {
  let cache_key = leaf_cache_key(sni, alpn, true);
  if let Some(config) = leaves.get(&cache_key) {
    return Ok(config.clone());
  }
  let (chain, key_der) = generate_domain_pair(ca, sni)?;
  let mut roots = RootCertStore::empty();
  roots
    .add(ca.cert_der().clone())
    .map_err(|err| Error::MtlsGuestRoots { source: err })?;
  let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
    .build()
    .map_err(|err| Error::MtlsGuestVerifier { source: err.into() })?;
  let mut config = rustls::server::ServerConfig::builder()
    .with_client_cert_verifier(verifier)
    .with_single_cert(chain, key_der)
    .map_err(|err| Error::MtlsLeaf { source: err })?;
  if let Some(alpn) = alpn {
    config.alpn_protocols = vec![alpn.to_vec()];
  }
  let config = Arc::new(config);
  leaves.insert(cache_key, Arc::clone(&config));
  Ok(config)
}

/// Trust anchors for one upstream leg, read once per [`RootCert`].
///
/// # Errors
///
/// Returns an error when the anchor cannot be read or holds no certificates.
pub fn cached_roots(roots: &DashMap<RootCert, Arc<RootCertStore>>, root: &RootCert) -> Result<Arc<RootCertStore>, Error> {
  if let Some(store) = roots.get(root) {
    return Ok(store.clone());
  }
  let store = match root {
    RootCert::Path(path) => {
      let pem = std::fs::read(path).map_err(|err| Error::SslRootCert {
        path: path.clone(),
        source: err.into(),
      })?;
      let mut store = RootCertStore::empty();
      let mut anchors = 0usize;
      for cert in CertificateDer::pem_slice_iter(&pem) {
        let cert = cert.map_err(|err| Error::SslRootCert {
          path: path.clone(),
          source: err.into(),
        })?;
        store.add(cert).map_err(|err| Error::SslRootCert {
          path: path.clone(),
          source: err.into(),
        })?;
        anchors += 1;
      }
      if anchors == 0 {
        return Err(Error::EmptyRootCert { path: path.clone() });
      }
      store
    }
    // The platform trust store. An unreadable or empty store fails closed
    // rather than silently verifying nothing.
    RootCert::System => {
      let mut native = rustls_native_certs::load_native_certs();
      if !native.errors.is_empty() {
        return Err(Error::SystemStore {
          source: native.errors.remove(0).into(),
        });
      }
      let mut store = RootCertStore::empty();
      for cert in native.certs {
        store.add(cert).map_err(|err| Error::SystemStore { source: err.into() })?;
      }
      if store.is_empty() {
        return Err(Error::EmptySystemStore);
      }
      store
    }
  };
  let store = Arc::new(store);
  roots.insert(root.clone(), Arc::clone(&store));
  Ok(store)
}

fn leaf_cache_key(sni: &str, alpn: Option<&[u8]>, mtls: bool) -> String {
  let alpn = alpn.map(|bytes| bytes.escape_ascii().to_string()).unwrap_or_default();
  format!("{sni}|{}|{alpn}", if mtls { 'm' } else { 't' })
}

/// How an upstream certificate is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verify {
  /// Chain and host name. A missing root uses the platform store.
  Full,
  /// libpq. A missing root accepts the certificate. A present root checks
  /// the chain, and the host name only when `name` is set.
  Libpq { name: bool },
}

/// What one upstream handshake needs. The caller already decided that this leg speaks TLS.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamTls<'a> {
  pub server_name: &'a str,
  pub root: Option<&'a RootCert>,
  pub verify: Verify,
  pub client_cert: Option<&'a Path>,
  pub client_key: Option<&'a Path>,
  pub alpn: Option<&'a [u8]>,
}

/// One side after the handshake budget. Plaintext stays the original stream.
pub enum Leg<P, T> {
  Plain(P),
  Tls(T),
}

/// Shared guest and upstream TLS legs. Protocols differ by ALPN and by [`Verify`].
pub struct TlsLegs {
  ca: CertAuthority,
  leaves: DashMap<String, Arc<ServerConfig>>,
  roots: DashMap<RootCert, Arc<RootCertStore>>,
  provider: Arc<CryptoProvider>,
}

impl TlsLegs {
  pub fn new(ca: &CertAuthority) -> Result<Self, Error> {
    Ok(Self {
      ca: CertAuthority::load(&ca.cert_pem(), &ca.key_pem())?,
      leaves: DashMap::new(),
      roots: DashMap::new(),
      provider: CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
    })
  }

  pub async fn accept_guest<G>(
    &self,
    name: &str,
    guest: G,
    mode: GuestTlsMode,
    alpn: Option<&[u8]>,
  ) -> Result<ServerTlsStream<G>, Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    let config = match mode {
      GuestTlsMode::Tls => cached_leaf(&self.ca, &self.leaves, name, alpn)?,
      GuestTlsMode::Mtls => cached_leaf_mtls(&self.ca, &self.leaves, name, alpn)?,
    };
    TlsAcceptor::from(config)
      .accept(guest)
      .await
      .map_err(|err| Error::GuestTls { source: err })
  }

  pub async fn connect_upstream<S>(&self, request: &UpstreamTls<'_>, server: S) -> Result<ClientTlsStream<S>, Error>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let server_name = ServerName::try_from(request.server_name.to_string()).map_err(|err| Error::TlsServerName { source: err.into() })?;
    let mut config = match request.verify {
      Verify::Full => {
        let root = request.root.cloned().unwrap_or(RootCert::System);
        let roots = cached_roots(&self.roots, &root)?;
        with_identity(
          ClientConfig::builder().with_root_certificates(roots),
          request.client_cert,
          request.client_key,
        )?
      }
      Verify::Libpq { name } => {
        let roots = match request.root {
          Some(root) => Some(cached_roots(&self.roots, root)?),
          None => None,
        };
        let verifier = EgressCertVerifier {
          roots,
          check_name: name,
          provider: Arc::clone(&self.provider),
        };
        let builder = ClientConfig::builder()
          .dangerous()
          .with_custom_certificate_verifier(Arc::new(verifier));
        with_identity(builder, request.client_cert, request.client_key)?
      }
    };
    if let Some(alpn) = request.alpn {
      config.alpn_protocols = vec![alpn.to_vec()];
    }
    TlsConnector::from(Arc::new(config))
      .connect(server_name, server)
      .await
      .map_err(|err| Error::ServerTls { source: err })
  }
}

fn with_identity(builder: impl IdentityBuilder, cert: Option<&Path>, key: Option<&Path>) -> Result<ClientConfig, Error> {
  match (cert, key) {
    (Some(cert), Some(key)) => {
      let ClientAuth::Single(data) = client_identity(cert, key)? else {
        return Err(Error::EmptyClientIdentity { path: cert.to_path_buf() });
      };
      builder
        .with_cert(data.cert_chain.clone(), data.private_key.clone_key())
        .map_err(|err| Error::ClientIdentity {
          path: cert.to_path_buf(),
          source: err,
        })
    }
    _ => Ok(builder.with_none()),
  }
}

trait IdentityBuilder {
  fn with_cert(
    self,
    chain: Vec<CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
  ) -> Result<ClientConfig, RustlsError>;

  fn with_none(self) -> ClientConfig;
}

impl IdentityBuilder for rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert> {
  fn with_cert(
    self,
    chain: Vec<CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
  ) -> Result<ClientConfig, RustlsError> {
    self.with_client_auth_cert(chain, key)
  }

  fn with_none(self) -> ClientConfig {
    self.with_no_client_auth()
  }
}

pub async fn finish<T>(budget: Duration, handshake: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
  match tokio::time::timeout(budget, handshake).await {
    Ok(result) => result,
    Err(_elapsed) => Err(Error::HandshakeTimeout),
  }
}

impl<P, T> AsyncRead for Leg<P, T>
where
  P: AsyncRead + Unpin,
  T: AsyncRead + Unpin,
{
  fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(inner) => Pin::new(inner).poll_read(cx, buf),
      Self::Tls(inner) => Pin::new(inner).poll_read(cx, buf),
    }
  }
}

impl<P, T> AsyncWrite for Leg<P, T>
where
  P: AsyncWrite + Unpin,
  T: AsyncWrite + Unpin,
{
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
    match self.get_mut() {
      Self::Plain(inner) => Pin::new(inner).poll_write(cx, buf),
      Self::Tls(inner) => Pin::new(inner).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(inner) => Pin::new(inner).poll_flush(cx),
      Self::Tls(inner) => Pin::new(inner).poll_flush(cx),
    }
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(inner) => Pin::new(inner).poll_shutdown(cx),
      Self::Tls(inner) => Pin::new(inner).poll_shutdown(cx),
    }
  }
}

/// Egress verification for a libpq-shaped upstream.
///
/// libpq verifies nothing when no trust anchor is named, which is what makes
/// `require` usable against a private server. It verifies the chain once one
/// is named, and it checks the host name only for `verify-full`.
#[derive(Debug)]
struct EgressCertVerifier {
  roots: Option<Arc<RootCertStore>>,
  check_name: bool,
  provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for EgressCertVerifier {
  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    _ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, RustlsError> {
    let Some(roots) = self.roots.as_ref() else {
      return Ok(ServerCertVerified::assertion());
    };
    let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
    rustls::client::verify_server_cert_signed_by_trust_anchor(
      &cert,
      roots,
      intermediates,
      now,
      self.provider.signature_verification_algorithms.all,
    )?;
    if self.check_name {
      rustls::client::verify_server_name(&cert, server_name)?;
    }
    Ok(ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.provider.signature_verification_algorithms.supported_schemes()
  }
}
