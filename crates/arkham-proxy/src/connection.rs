//! Connection layer: guest adapters, the terminated-TLS pump, dialing.
//! Knows bytes and TLS; nothing of wire formats.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use rama::error::BoxError;
use rama::extensions::{Extension, Extensions, ExtensionsRef};
use rama::net::address::{Host, HostWithPort};
use rama::net::client::ConnectorTarget;
use rama::net::socket::SocketOptions;
use rama::service::service_fn;
use rama::tcp::client::TcpStreamConnector;
use rama::tcp::stream::TokioTcpStream;
use rama::tls::boring::client::ConnectorConfigClientAuth;
use rama::tls::boring::core::ssl::{SslCredential, SslRef, SslVerifyMode};
use rama::tls::boring::core::x509::X509;
use rama::tls::boring::core::x509::store::X509Store;
use rama::tls::boring::proxy::client_auth::{
  TlsMitmClientAuthInput, TlsMitmClientAuthPlan, TlsMitmClientAuthPolicy, TlsMitmClientIdentity,
};
use rama::tls::client::{ClientAuth, ClientAuthData};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::Error as PemError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use arkham_config::grants::{EndpointScope, GuestTlsMode};

use crate::Error;
use crate::identity::{Hello, read_client_hello};
use crate::mint::MintBucket;
/// Guest-side adapter: any tokio stream plus a rama extension map. The relay
/// reads the [`ConnectorTarget`] identity from these extensions to derive
/// egress SNI and verification identity.
pub(crate) struct GuestIo<S> {
  inner: S,
  extensions: Extensions,
}

impl<S> GuestIo<S> {
  pub(crate) fn with_target(inner: S, identity: &str, port: u16) -> Result<Self, Error> {
    let host: Host = identity.parse().map_err(|err: <Host as FromStr>::Err| Error::BadIdentity {
      identity: identity.to_string(),
      source: err,
    })?;
    let extensions = Extensions::new();
    extensions.insert(ConnectorTarget(HostWithPort::new(host, port)));
    Ok(Self { inner, extensions })
  }

  pub(crate) fn bare(inner: S) -> Self {
    Self {
      inner,
      extensions: Extensions::new(),
    }
  }

  /// Record the MITM client-auth policy the relay enforces on both legs.
  pub(crate) fn with_client_auth_policy(self, policy: TlsMitmClientAuthPolicy) -> Self {
    self.extensions.insert(policy);
    self
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for GuestIo<S> {
  fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GuestIo<S> {
  fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}
impl<S> ExtensionsRef for GuestIo<S> {
  fn extensions(&self) -> &Extensions {
    &self.extensions
  }
}

/// Load an upstream client identity (mTLS) from the entry's PEM paths: the
/// certificate chain and its key, ready for the relay's egress. Only the
/// entry names this identity; nothing invents one.
pub(crate) fn client_identity(cert: &Path, key: &Path) -> Result<ClientAuth, Error> {
  let cert_bytes = std::fs::read(cert).map_err(|err| Error::ReadFile {
    path: cert.to_path_buf(),
    source: err,
  })?;
  let key_bytes = std::fs::read(key).map_err(|err| Error::ReadFile {
    path: key.to_path_buf(),
    source: err,
  })?;
  let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|err| Error::GuestCertificate {
      path: cert.to_path_buf(),
      source: err.into(),
    })?;
  if chain.is_empty() {
    return Err(Error::EmptyChain { path: cert.to_path_buf() });
  }
  let private = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|err| Error::ClientKey {
    path: key.to_path_buf(),
    source: err.into(),
  })?;
  Ok(ClientAuth::Single(ClientAuthData {
    cert_chain: chain,
    private_key: private,
  }))
}

/// Per-connection MITM client-auth policy for one https scope: the entry's
/// upstream identity when upstream requests one, a guest-certificate demand
/// in `Mtls` mode, and an explicit empty answer otherwise. The empty plan
/// matters: with no policy the relay rejects an upstream certificate
/// request outright, while every ordinary TLS client answers it empty and
/// carries on — which is what servers that request without requiring (like
/// a kube apiserver) expect.
pub(crate) fn client_auth_policy(scope: &EndpointScope, trust: &X509Store) -> Result<Option<TlsMitmClientAuthPolicy>, Error> {
  let auth = match (&scope.client_cert, &scope.client_key) {
    (Some(cert), Some(key)) => Some(client_identity(cert, key)?),
    (Some(_) | None, None) | (None, Some(_)) => None,
  };
  match (scope.guest_tls, auth) {
    (GuestTlsMode::Tls, None) => Ok(Some(TlsMitmClientAuthPolicy::new(service_fn(|_: TlsMitmClientAuthInput| async {
      Ok::<_, std::convert::Infallible>(TlsMitmClientAuthPlan::fixed(None))
    })))),
    (GuestTlsMode::Tls, Some(auth)) => TlsMitmClientAuthPolicy::try_from(auth)
      .map(Some)
      .map_err(|err| Error::ClientAuthPolicy { source: err }),
    (GuestTlsMode::Mtls, auth) => mtls_policy(trust, auth).map(Some),
  }
}

/// Policy demanding a guest certificate trusted by `store`, offering the
/// entry's upstream identity only when upstream requests one (`None` admits
/// the guest without an egress identity).
fn mtls_policy(store: &X509Store, auth: Option<ClientAuth>) -> Result<TlsMitmClientAuthPolicy, Error> {
  let credential: Option<SslCredential> = auth
    .map(|auth| {
      let configured = ConnectorConfigClientAuth::try_from(auth).map_err(|err| Error::ClientAuthPolicy { source: err })?;
      SslCredential::try_from(configured).map_err(|err| Error::ClientAuthPolicy { source: err })
    })
    .transpose()?;
  let store = store.clone();
  Ok(TlsMitmClientAuthPolicy::new(service_fn(move |input: TlsMitmClientAuthInput| {
    let credential = if input.request.is_some() { credential.clone() } else { None };
    let store = store.clone();
    async move { Ok::<_, std::convert::Infallible>(TlsMitmClientAuthPlan::fixed(credential).with_ingress_trust(store)) }
  })))
}

/// One https grant that covers the destination, when several do.
#[derive(Clone)]
pub(crate) struct HttpsCandidate {
  /// Index into the config grant list.
  pub(crate) index: usize,
  /// Grant label. The decoy leaf is `{label}.guest.crt` beside `client_cert`.
  pub(crate) label: String,
  /// Real upstream client certificate, when the grant names one.
  pub(crate) client_cert: Option<PathBuf>,
  /// Real upstream client key, when the grant names one.
  pub(crate) client_key: Option<PathBuf>,
  /// Whether this grant admits a guest certificate.
  pub(crate) guest_tls: GuestTlsMode,
}

/// Grants the handshake selected for this connection. Indices into the
/// config grant list. Absent on the single-grant path.
#[derive(Debug)]
pub(crate) struct SelectedHttps {
  /// Selected grant indices.
  pub(crate) indices: Vec<usize>,
}

impl Extension for SelectedHttps {}

/// Client-auth policy for several https grants on one server. A guest
/// certificate selects the mutual-TLS grant whose decoy leaf matches.
/// No certificate selects the plain TLS grants. An unknown certificate
/// fails the handshake.
pub(crate) fn selecting_client_auth(candidates: Vec<HttpsCandidate>, trust: &X509Store, host: &str, port: u16) -> TlsMitmClientAuthPolicy {
  let ask = candidates.iter().any(|candidate| candidate.guest_tls == GuestTlsMode::Mtls);
  let trust = trust.clone();
  let host = host.to_string();
  TlsMitmClientAuthPolicy::new(service_fn(move |input: TlsMitmClientAuthInput| {
    let candidates = candidates.clone();
    let extensions = input.extensions.clone();
    let requested = input.request.is_some();
    let trust = trust.clone();
    let host = host.clone();
    async move {
      let resolver = service_fn(move |identity: TlsMitmClientIdentity| {
        let candidates = candidates.clone();
        let extensions = extensions.clone();
        let host = host.clone();
        async move {
          let presented = match identity.leaf() {
            Some(leaf) => Some(leaf.to_der().map_err(|err| Error::ClientAuthPolicy { source: err.into() })?),
            None => None,
          };
          let (indices, auth) = select_https(&candidates, presented.as_deref(), &host, port)?;
          extensions.insert(SelectedHttps { indices });
          let credential = match (requested, auth) {
            (true, Some(auth)) => Some(upstream_credential(auth)?),
            _ => None,
          };
          Ok::<_, Error>(credential)
        }
      });
      let plan = TlsMitmClientAuthPlan::new(resolver);
      let plan = if ask {
        plan.with_ingress(move |ssl: &mut SslRef| {
          ssl.set_verify_cert_store(trust).map_err(|err| -> BoxError { err.into() })?;
          ssl.set_verify(SslVerifyMode::PEER);
          Ok(())
        })
      } else {
        plan
      };
      Ok::<_, std::convert::Infallible>(plan)
    }
  }))
}

fn select_https(
  candidates: &[HttpsCandidate],
  presented: Option<&[u8]>,
  host: &str,
  port: u16,
) -> Result<(Vec<usize>, Option<ClientAuth>), Error> {
  if let Some(presented) = presented {
    let mut matched = Vec::new();
    for candidate in candidates.iter().filter(|candidate| candidate.guest_tls == GuestTlsMode::Mtls) {
      let Some(expected) = guest_leaf_der(candidate)? else {
        continue;
      };
      if expected == presented {
        matched.push(candidate);
      }
    }
    let Some(chosen) = matched.first().copied() else {
      return Err(Error::UnmappedGuestCert {
        host: host.to_string(),
        port,
      });
    };
    if matched.len() != 1 {
      return Err(Error::AmbiguousGuestCert {
        host: host.to_string(),
        port,
      });
    }
    return Ok((vec![chosen.index], upstream_identity(chosen)?));
  }
  let plain: Vec<&HttpsCandidate> = candidates
    .iter()
    .filter(|candidate| candidate.guest_tls == GuestTlsMode::Tls)
    .collect();
  if plain.is_empty() {
    return Err(Error::UnmappedGuestCert {
      host: host.to_string(),
      port,
    });
  }
  let indices = plain.iter().map(|candidate| candidate.index).collect();
  Ok((indices, shared_upstream(&plain, host, port)?))
}

fn guest_leaf_der(candidate: &HttpsCandidate) -> Result<Option<Vec<u8>>, Error> {
  let Some(cert) = &candidate.client_cert else {
    return Ok(None);
  };
  let path = cert.with_file_name(format!("{}.guest.crt", candidate.label));
  let bytes = match std::fs::read(&path) {
    Ok(bytes) => bytes,
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
    Err(source) => return Err(Error::ReadFile { path, source }),
  };
  let leaf = X509::from_pem(&bytes).map_err(|err| Error::GuestCertificate {
    path: path.clone(),
    source: Box::new(err),
  })?;
  leaf.to_der().map(Some).map_err(|err| Error::GuestCertificate {
    path,
    source: Box::new(err),
  })
}

fn upstream_identity(candidate: &HttpsCandidate) -> Result<Option<ClientAuth>, Error> {
  match (&candidate.client_cert, &candidate.client_key) {
    (Some(cert), Some(key)) => client_identity(cert, key).map(Some),
    _ => Ok(None),
  }
}

fn shared_upstream(candidates: &[&HttpsCandidate], host: &str, port: u16) -> Result<Option<ClientAuth>, Error> {
  let mut paths: Option<(Option<PathBuf>, Option<PathBuf>)> = None;
  for candidate in candidates {
    let pair = (candidate.client_cert.clone(), candidate.client_key.clone());
    match &paths {
      None => paths = Some(pair),
      Some(seen) if seen == &pair => {}
      Some(_) => {
        return Err(Error::HttpsClientSplit {
          host: host.to_string(),
          port,
        });
      }
    }
  }
  match paths {
    Some((Some(cert), Some(key))) => client_identity(&cert, &key).map(Some),
    _ => Ok(None),
  }
}

fn upstream_credential(auth: ClientAuth) -> Result<SslCredential, Error> {
  let configured = ConnectorConfigClientAuth::try_from(auth).map_err(|err| Error::ClientAuthPolicy { source: err })?;
  SslCredential::try_from(configured).map_err(|err| Error::ClientAuthPolicy { source: err })
}

/// Failure loading an upstream CA bundle for one entry's extra egress trust.
#[derive(Debug, Error)]
pub enum TrustAnchorsError {
  /// The bundle file could not be read.
  #[error("read `{path}`: {source}")]
  Read {
    /// Bundle path that failed to read.
    path: PathBuf,
    /// The read failure.
    #[source]
    source: std::io::Error,
  },
  /// The bundle file holds no parseable PEM certificates.
  #[error("certificate `{path}`: {source}")]
  Parse {
    /// Bundle path that failed to parse.
    path: PathBuf,
    /// The parse failure.
    #[source]
    source: PemError,
  },
  /// The bundle file holds zero certificates.
  #[error("`{path}` holds no certificates")]
  Empty {
    /// Empty bundle path.
    path: PathBuf,
  },
}

/// Load an upstream CA bundle for one entry's extra egress trust: the PEM
/// certificates at `path`, additive to the global egress trust. Only the
/// entry names this bundle; nothing invents one.
pub(crate) fn trust_anchors(path: &Path) -> Result<Vec<CertificateDer<'static>>, TrustAnchorsError> {
  let bytes = std::fs::read(path).map_err(|source| TrustAnchorsError::Read { path: path.into(), source })?;
  let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
    .collect::<Result<_, _>>()
    .map_err(|source| TrustAnchorsError::Parse { path: path.into(), source })?;
  if chain.is_empty() {
    return Err(TrustAnchorsError::Empty { path: path.into() });
  }
  Ok(chain)
}

/// Dial upstream, applying the fwmark when set (TUN self-exclusion).
/// Mark failures are fatal: silently unmarked dials would loop back into TUN.
///
/// # Errors
///
/// Returns an error when DNS resolution fails, when every resolved address
/// fails to connect within the overall budget, or when applying the fwmark
/// fails.
pub(crate) async fn dial_marked(host: &str, port: u16, fwmark: Option<u32>) -> std::io::Result<TcpStream> {
  const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
  // One total budget across DNS + every address attempt: N blackholed
  // addresses must cost 10s total, not 10s each.
  let deadline = tokio::time::Instant::now() + DIAL_TIMEOUT;
  let mut last_err = std::io::Error::new(std::io::ErrorKind::NotFound, "DNS returned no addresses");
  let addrs = tokio::time::timeout(DIAL_TIMEOUT, tokio::net::lookup_host((host, port)))
    .await
    .map_err(|_elapsed| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS lookup timed out"))??;
  for addr in addrs {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
      last_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "dial budget exhausted");
      break;
    }
    match tokio::time::timeout(remaining, dial_one(addr, fwmark)).await {
      Ok(Ok(stream)) => return Ok(stream),
      Ok(Err(err)) => last_err = err,
      Err(_) => {
        last_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP dial timed out");
      }
    }
  }
  Err(last_err)
}

async fn dial_one(addr: SocketAddr, fwmark: Option<u32>) -> std::io::Result<TcpStream> {
  if fwmark.is_none() {
    return TcpStream::connect(addr).await;
  }
  let opts = Arc::new(SocketOptions {
    mark: fwmark,
    ..SocketOptions::default_tcp()
  });
  // The mark lives on the fd, so the tokio stream converts losslessly.
  opts.connect(addr).await.map(TokioTcpStream::from).map_err(std::io::Error::other)
}

/// A stream prefixed with already-read bytes (replays `initial_buf` first).
pub(crate) struct Prefixed<S> {
  prefix: Vec<u8>,
  pos: usize,
  inner: S,
}

impl<S> Prefixed<S> {
  pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
    Self { prefix, pos: 0, inner }
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
  fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    if self.pos < self.prefix.len() {
      let remaining = &self.prefix[self.pos..];
      let n = remaining.len().min(buf.remaining());
      buf.put_slice(&remaining[..n]);
      self.pos += n;
      return Poll::Ready(Ok(()));
    }
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
  fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

/// Read a guest `ClientHello` under the budget, enforce the authority/SNI
/// match, and mint-gate the leaf. The protocol verticals share this
/// opening; the tuple is `(hello bytes, mint identity, server name)`.
///
/// `None` closes the connection: no hello, a mismatched SNI, no name to
/// mint for, or the burst guard tripping as an error.
pub(crate) async fn guest_tls_opening<G>(
  guest: &mut G,
  initial: &[u8],
  budget: std::time::Duration,
  host: Option<&str>,
  mint: &MintBucket,
) -> Result<Option<(Vec<u8>, String, String)>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let Some(read) = read_client_hello(guest, initial, budget).await? else {
    return Ok(None);
  };
  let (hello_buf, sni) = match read {
    Hello::Named { buf, sni, .. } => (buf, Some(sni)),
    Hello::Unnamed { buf, .. } => (buf, None),
  };
  if let (Some(authority), Some(sni)) = (host, sni.as_deref())
    && !sni.eq_ignore_ascii_case(authority)
  {
    tracing::debug!(authority, sni, "CONNECT authority differs from SNI; closing");
    return Ok(None);
  }
  let mut server_name = host.map(ToString::to_string);
  server_name = server_name.or_else(|| sni.clone());
  // The leaf has to carry the name the guest verified, so the guest's own
  // SNI wins and the authority is the fallback for a hello without one.
  let Some(identity) = sni.or_else(|| server_name.clone()) else {
    tracing::debug!("guest TLS with no name to mint for; closing");
    return Ok(None);
  };
  if !mint.allow() {
    return Err(Error::BurstExceeded {
      identity: identity.clone(),
    });
  }
  Ok(Some((hello_buf, identity, server_name.unwrap_or_default())))
}
#[cfg(test)]
mod tests {
  use base64::Engine as _;
  use rama::tls::boring::core::x509::store::X509StoreBuilder;

  use super::*;
  use arkham_config::grants::Scheme;
  use arkham_pki::ca::CertAuthority;

  fn tls_scope() -> EndpointScope {
    EndpointScope {
      scheme: Scheme::Https,
      host: "localhost".parse().unwrap(),
      port: 443,
      client_cert: None,
      client_key: None,
      root_cert: None,
      guest_tls: GuestTlsMode::Tls,
    }
  }

  fn test_trust() -> X509Store {
    let ca = CertAuthority::generate().unwrap();
    let (crt, _) = ca.boring_pair().unwrap();
    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(&crt).unwrap();
    builder.build()
  }

  #[test]
  fn anonymous_scopes_carry_an_explicit_empty_client_auth_plan() {
    let policy = client_auth_policy(&tls_scope(), &test_trust()).expect("policy builds");
    assert!(
      policy.is_some(),
      "anonymous legs must answer an upstream certificate request empty instead of dying"
    );
  }

  fn pem_block(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
  }

  fn identity_files(key_pem: &str) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let ca = CertAuthority::generate().expect("ca");
    let (cert, key) = arkham_pki::ca::load_or_generate_client_pair(&ca, dir.path(), "client").expect("pair");
    std::fs::write(&key, key_pem).expect("key");
    (dir, cert, key)
  }

  #[test]
  fn unknown_private_key_label_stays_an_error() {
    let (_dir, cert, key) = identity_files(&pem_block("OPENSSH PRIVATE KEY", b"not-a-key"));
    let err = client_identity(&cert, &key).expect_err("unknown label");
    assert!(
      matches!(err, crate::Error::ClientKey { .. }),
      "an unrecognized label stays a key parse error"
    );
  }
}
