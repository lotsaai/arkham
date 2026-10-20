//! Connection layer: guest adapters, the terminated-TLS pump, dialing.
//! Knows bytes and TLS; nothing of wire formats.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use rama::extensions::{Extensions, ExtensionsRef};
use rama::net::address::{Host, HostWithPort};
use rama::net::client::ConnectorTarget;
use rama::net::socket::SocketOptions;
use rama::service::service_fn;
use rama::tcp::client::TcpStreamConnector;
use rama::tcp::stream::TokioTcpStream;
use rama::tls::boring::client::ConnectorConfigClientAuth;
use rama::tls::boring::core::ssl::{SslCredential, SslRef, SslVerifyMode};
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

use arkham_config::grants::{EndpointScope, Grant, GuestTlsMode, Scheme};

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

/// One https grant that can be chosen for a destination shared by several grants.
#[derive(Clone)]
pub(crate) struct HttpsCandidate {
  /// Grant this candidate selects.
  pub(crate) grant: Grant,
  /// Guest TLS mode of the matching allow entry.
  pub(crate) guest_tls: GuestTlsMode,
  /// DER of the guest leaf this grant's client pair expects, when it has one.
  pub(crate) leaf: Option<Vec<u8>>,
}

/// DER of the first certificate in `{stem}.guest.crt` beside `client_cert`.
///
/// Pair grants materialize that sibling.
///
/// # Errors
///
/// Returns an error when the sibling file exists but cannot be read or holds
/// no certificate.
pub(crate) fn guest_leaf_der(client_cert: &Path) -> Result<Option<Vec<u8>>, Error> {
  let Some(name) = client_cert.file_name().and_then(|name| name.to_str()) else {
    return Ok(None);
  };
  let Some(stem) = name.strip_suffix(".client.crt") else {
    return Ok(None);
  };
  let path = client_cert.with_file_name(format!("{stem}.guest.crt"));
  if !path.is_file() {
    return Ok(None);
  }
  let bytes = std::fs::read(&path).map_err(|source| Error::ReadFile {
    path: path.clone(),
    source,
  })?;
  let mut certs = CertificateDer::pem_slice_iter(&bytes);
  let Some(first) = certs.next() else {
    return Err(Error::EmptyChain { path });
  };
  let der = first.map_err(|err| Error::GuestCertificate {
    path,
    source: Box::new(err),
  })?;
  Ok(Some(der.as_ref().to_vec()))
}

/// Policy for several https grants on one destination.
///
/// A presented certificate selects the matching grant. No certificate selects
/// the `Tls` grants. `choose_https` stores that choice in `selected`.
pub(crate) fn optional_client_auth_policy(
  candidates: Vec<HttpsCandidate>,
  trust: &X509Store,
  host: &str,
  port: u16,
  selected: Arc<Mutex<Vec<Grant>>>,
) -> TlsMitmClientAuthPolicy {
  let store = trust.clone();
  let host = host.to_string();
  TlsMitmClientAuthPolicy::new(service_fn(move |input: TlsMitmClientAuthInput| {
    let wants_upstream = input.request.is_some();
    let candidates = candidates.clone();
    let selected = Arc::clone(&selected);
    let store = store.clone();
    let host = host.clone();
    async move {
      let plan = TlsMitmClientAuthPlan::new(service_fn(move |identity: TlsMitmClientIdentity| {
        let candidates = candidates.clone();
        let selected = Arc::clone(&selected);
        let host = host.clone();
        async move { choose_https(&identity, &candidates, wants_upstream, &host, port, &selected) }
      }))
      .with_ingress(move |ssl: &mut SslRef| {
        ssl.set_verify_cert_store(store)?;
        ssl.set_verify(SslVerifyMode::PEER);
        Ok(())
      });
      Ok::<_, std::convert::Infallible>(plan)
    }
  }))
}

fn choose_https(
  identity: &TlsMitmClientIdentity,
  candidates: &[HttpsCandidate],
  wants_upstream: bool,
  host: &str,
  port: u16,
  selected: &Mutex<Vec<Grant>>,
) -> Result<Option<SslCredential>, Error> {
  let grants = match identity.leaf() {
    None => bearer_grants(candidates, host, port)?,
    Some(leaf) => {
      let der = leaf.to_der().map_err(|err| Error::ClientAuthPolicy { source: Box::new(err) })?;
      let matched: Vec<&HttpsCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.leaf.as_ref() == Some(&der))
        .collect();
      match matched.as_slice() {
        [] => {
          return Err(Error::UnmatchedClientCert {
            host: host.to_string(),
            port,
          });
        }
        [one] => vec![one.grant.clone()],
        many => {
          return Err(Error::AmbiguousHttpsGrants {
            host: host.to_string(),
            port,
            labels: grant_labels(many),
          });
        }
      }
    }
  };
  let credential = if wants_upstream && grants.len() == 1 {
    upstream_credential(&grants[0], host, port)?
  } else {
    None
  };
  *selected.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = grants;
  Ok(credential)
}

fn bearer_grants(candidates: &[HttpsCandidate], host: &str, port: u16) -> Result<Vec<Grant>, Error> {
  let bearer: Vec<&HttpsCandidate> = candidates
    .iter()
    .filter(|candidate| candidate.guest_tls == GuestTlsMode::Tls)
    .collect();
  if bearer.is_empty() {
    return Err(Error::ClientCertRequired {
      host: host.to_string(),
      port,
    });
  }
  if let Some(labels) = colliding_fakes(&bearer) {
    return Err(Error::AmbiguousHttpsGrants {
      host: host.to_string(),
      port,
      labels,
    });
  }
  Ok(bearer.into_iter().map(|candidate| candidate.grant.clone()).collect())
}

fn colliding_fakes(candidates: &[&HttpsCandidate]) -> Option<String> {
  let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
  for candidate in candidates {
    let Some(credential) = candidate.grant.credential() else {
      continue;
    };
    groups.entry(credential.fake.as_str()).or_default().push(credential.label.as_str());
  }
  let labels = groups.into_values().find(|labels| labels.len() > 1)?;
  let mut labels: Vec<&str> = labels;
  labels.sort_unstable();
  Some(labels.join(", "))
}

fn grant_labels(candidates: &[&HttpsCandidate]) -> String {
  let mut labels: Vec<&str> = candidates
    .iter()
    .filter_map(|candidate| candidate.grant.credential().map(|credential| credential.label.as_str()))
    .collect();
  labels.sort_unstable();
  labels.join(", ")
}

fn upstream_credential(grant: &Grant, host: &str, port: u16) -> Result<Option<SslCredential>, Error> {
  let Some(scope) = grant.endpoint(Scheme::Https, Some(host), port) else {
    return Ok(None);
  };
  let (Some(cert), Some(key)) = (&scope.client_cert, &scope.client_key) else {
    return Ok(None);
  };
  let auth = client_identity(cert, key)?;
  let configured = ConnectorConfigClientAuth::try_from(auth).map_err(|err| Error::ClientAuthPolicy { source: err })?;
  let credential = SslCredential::try_from(configured).map_err(|err| Error::ClientAuthPolicy { source: err })?;
  Ok(Some(credential))
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
  use rama::tls::boring::core::x509::store::X509StoreBuilder;

  use super::*;
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
}
