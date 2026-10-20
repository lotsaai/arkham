//! Explicit proxy core: CONNECT splice, TLS intercept relay.

use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rama::Service;
use rama::crypto::pki_types::CertificateDer;
use rama::error::BoxError;
use rama::net::address::SocketAddress;
use rama::net::socket::SocketOptions;
use rama::net::socket::opts::Domain;
use rama::rt::Executor;
pub use rama::tcp::server::TcpListener as RamaTcpListener;
use rama::tcp::stream::TcpStream as RamaTcpStream;
use rama::tls::boring::core::x509::store::{X509Store, X509StoreBuilder};
use rama::tls::boring::proxy::TlsMitmEgressServerAuth;
use rama::tls::boring::proxy::TlsMitmRelay;
use rama::tls::boring::proxy::cert_issuer::{CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer};
use rama::tls::client::{ClientAuth, ServerVerifyMode};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::connection::dial_marked;
use crate::identity::{Expect, expect};
use crate::mint::{MintBucket, MintHandle, MintStore};
use crate::transports::PairCtx;
use crate::transports::http::{MAX_HEAD, http_pair};
use arkham_config::grants::{Grant, ResolvedConfig, Scheme};
use arkham_pki::ca::CertAuthority;
pub(crate) use relay::relay_guarded;

mod connection;
#[cfg(test)]
mod e2e;
mod error;
mod identity;
mod mint;
mod transports;

mod relay;

use identity::CandidateParams;
use transports::amqp::AmqpTransport;
use transports::http::{HttpTransport, HttpsTransport};
use transports::ldap::LdapTransport;
use transports::nats::NatsTransport;
use transports::postgres::PostgresTransport;
use transports::redis::RedisTransport;
use transports::smtp::SmtpTransport;
use transports::ssh::SshTransport;
use transports::tcp::TcpTransport;
/// One HTTPS MITM relay shape: cached in-memory leaf issuer.
type HttpsRelay = TlsMitmRelay<CachedBoringMitmCertIssuer<InMemoryBoringMitmCertIssuer>>;

pub use connection::TrustAnchorsError;
pub use error::Error;

/// Shared proxy state: live config snapshot, boring MITM relays, and the
/// issuance burst guard.
///
/// Config is write-once (no reload path), so a plain `Arc` — no lock, no
/// swap. Leaf issuance runs inside the boring relay's cached issuer, and the
/// [`MintBucket`] bounds remote-triggered issuance per MITM arm entry.
/// Entries naming `root_cert` get their own relay extending the global
/// egress trust with that bundle; everything else shares `relay`.
pub struct ProxyState {
  config: Arc<ResolvedConfig>,
  /// Guest certificate chains named by the grants, read once.
  guest_certs: Arc<DashMap<PathBuf, Arc<Vec<CertificateDer<'static>>>>>,
  /// Upstream client identities named by the grants, read once.
  identities: Arc<DashMap<PathBuf, ClientAuth>>,
  relay: HttpsRelay,
  extra_relays: HashMap<PathBuf, HttpsRelay>,
  mtls_trust: X509Store,
  http: Arc<HttpTransport>,
  https: Arc<HttpsTransport>,
  tcp: Arc<TcpTransport>,
  ssh: Arc<SshTransport>,
  postgres: Arc<PostgresTransport>,
  redis: Arc<RedisTransport>,
  smtp: Arc<SmtpTransport>,
  ldap: Arc<LdapTransport>,
  nats: Arc<NatsTransport>,
  amqp: Arc<AmqpTransport>,
  mint: MintBucket,
  /// Runtime token-mint store, shared across connections.
  mint_store: Arc<crate::mint::MintStore>,
  fwmark: Option<u32>,
  plugins: Arc<arkham_plugin::Registry>,
}

impl std::fmt::Debug for ProxyState {
  /// `ResolvedConfig` derives `Debug`, and `Grant`'s `value` is a
  /// `SecretString` that renders as `SecretBox<str>`, so real secrets never
  /// reach a log line through here.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ProxyState")
      .field("config", &self.config)
      .field("fwmark", &self.fwmark)
      .field("plugins", &self.plugins)
      .finish_non_exhaustive()
  }
}

/// One MITM relay on `ca`'s leaves: webpki egress trust extended with `extra`
fn https_relay(ca: &CertAuthority, extra: &[CertificateDer<'static>]) -> Result<HttpsRelay, Error> {
  let (crt, key) = ca.boring_pair()?;
  let mut egress = TlsMitmEgressServerAuth::new()
    .with_server_verify(ServerVerifyMode::Auto)
    .with_webpki_roots();
  if !extra.is_empty() {
    egress = egress
      .try_with_extra_server_trust_anchors(extra.iter().cloned())
      .map_err(|err| Error::EgressTrustAnchors { source: err })?;
  }
  Ok(TlsMitmRelay::new_cached_in_memory(crt, key).with_egress_server_auth(egress))
}

/// Read every bundle, guest leaf, and client pair the grants name.
///
/// A missing guest leaf is not an error: that grant has no certificate to match.
/// A named trust bundle that is missing or empty fails here.
///
/// # Errors
///
/// Returns an error when a named file cannot be read or a bundle holds no certificate.
fn warm_grant_files(
  resolved: &ResolvedConfig,
  guest_certs: &DashMap<PathBuf, Arc<Vec<CertificateDer<'static>>>>,
  identities: &DashMap<PathBuf, ClientAuth>,
) -> Result<(), Error> {
  for path in &resolved.proxy.root_certs {
    require_bundle(guest_certs, path)?;
  }
  for grant in &resolved.grants {
    let Grant::Token { credential, allow, .. } = grant else {
      continue;
    };
    for scope in allow {
      if let Some(path) = &scope.root_cert {
        require_bundle(guest_certs, path)?;
      }
      if let Some(cert) = &scope.client_cert {
        let leaf = cert.with_file_name(arkham_config::context::guest_cert_file(&credential.label));
        crate::transports::tls::cached_guest_certs(guest_certs, &leaf)?;
      }
      if let (Some(cert), Some(key)) = (&scope.client_cert, &scope.client_key) {
        crate::transports::tls::cached_client_identity(identities, cert, key)?;
      }
    }
  }
  Ok(())
}

/// A trust bundle named by config. Missing and empty files fail.
///
/// # Errors
///
/// Returns an error when `path` cannot be read, does not parse, or holds no certificate.
fn require_bundle(cache: &DashMap<PathBuf, Arc<Vec<CertificateDer<'static>>>>, path: &Path) -> Result<(), Error> {
  match crate::transports::tls::cached_guest_certs(cache, path)? {
    Some(certs) if certs.is_empty() => Err(connection::TrustAnchorsError::Empty { path: path.to_path_buf() }.into()),
    Some(_) => Ok(()),
    None => Err(
      connection::TrustAnchorsError::Read {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "trust bundle not found"),
      }
      .into(),
    ),
  }
}

/// Certificates already stored for `path` by [`warm_grant_files`].
///
/// # Errors
///
/// Returns an error when `path` was not part of the warm-up.
fn loaded_anchors(cache: &DashMap<PathBuf, Arc<Vec<CertificateDer<'static>>>>, path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
  cache
    .get(path)
    .map(|certs| certs.iter().cloned().collect())
    .ok_or_else(|| Error::UnknownTrustBundle { path: path.to_path_buf() })
}

/// Distinct `root_cert` bundles named by endpoint rules, first-seen order.
fn entry_anchors(resolved: &ResolvedConfig) -> Vec<PathBuf> {
  let mut seen = Vec::new();
  for grant in &resolved.grants {
    let Grant::Token { allow, .. } = grant else { continue };
    for scope in allow {
      if let Some(path) = &scope.root_cert
        && !seen.contains(path)
      {
        seen.push(path.clone());
      }
    }
  }
  seen
}

impl ProxyState {
  /// Build state from resolved config and the CA. The boring pair comes from
  /// [`CertAuthority::boring_pair`]; egress trust is webpki, extended globally
  /// by `root_certs` bundles and per entry by `root_cert` bundles. The arkham
  /// CA signs guest-facing leaves only. Verification is always on: this proxy
  /// swaps real secrets upstream, so a network attacker with an untrusted
  /// cert must fail closed.
  ///
  /// # Errors
  ///
  /// Returns an error when the CA pair fails to convert to boring types,
  /// when the egress trust policy rejects its anchors, when a trust bundle
  /// cannot be read, when the CA cannot be read back for leaf minting, or
  /// when a configured plugin cannot be loaded.
  pub fn new(resolved: ResolvedConfig, ca: &CertAuthority) -> Result<Self, Error> {
    let plugins = Arc::new(arkham_plugin::Registry::load(&resolved.plugins)?);
    let guest_certs = Arc::new(DashMap::new());
    let identities = Arc::new(DashMap::new());
    warm_grant_files(&resolved, &guest_certs, &identities)?;
    let mut global = Vec::new();
    for path in &resolved.proxy.root_certs {
      global.extend(loaded_anchors(&guest_certs, path)?);
    }
    let relay = https_relay(ca, &global)?;
    let mut extra_relays = HashMap::new();
    for path in entry_anchors(&resolved) {
      let mut anchors = global.clone();
      anchors.extend(loaded_anchors(&guest_certs, &path)?);
      let extra_relay = https_relay(ca, &anchors).map_err(|source| Error::EntryTrustBundle {
        path: path.clone(),
        source: Box::new(source),
      })?;
      extra_relays.insert(path, extra_relay);
    }
    // Trust for the `mtls` guest leg: the same CA that mints the leaves.
    // Per-connection policies built from it demand a guest certificate.
    let (crt, _) = ca.boring_pair()?;
    let mut trust = X509StoreBuilder::new().map_err(|source| Error::MtlsTrustStore { source: source.into() })?;
    trust
      .add_cert(&crt)
      .map_err(|source| Error::MtlsTrustAnchor { source: source.into() })?;
    let mtls_trust = trust.build();
    let postgres = Arc::new(PostgresTransport::new(ca)?);
    let redis = Arc::new(RedisTransport::new(ca)?);
    let smtp = Arc::new(SmtpTransport::new(ca)?);
    let ldap = Arc::new(LdapTransport::new(ca)?);
    let nats = Arc::new(NatsTransport::new(ca)?);
    let amqp = Arc::new(AmqpTransport::new(ca)?);
    Ok(Self {
      config: Arc::new(resolved),
      guest_certs,
      identities,
      relay,
      extra_relays,
      mtls_trust,
      http: Arc::new(HttpTransport),
      https: Arc::new(HttpsTransport),
      tcp: Arc::new(TcpTransport),
      ssh: Arc::new(SshTransport::default()),
      postgres,
      redis,
      smtp,
      ldap,
      nats,
      amqp,
      mint: MintBucket::new(),
      mint_store: Arc::new(MintStore::default()),
      fwmark: None,
      plugins,
    })
  }

  #[cfg(target_os = "linux")]
  /// Mark upstream sockets so the capture backend's policy routing bypasses
  /// them (`tun` and `tproxy` alike).
  #[must_use]
  pub fn with_fwmark(mut self, mark: u32) -> Self {
    self.fwmark = Some(mark);
    self
  }

  /// Load the current config snapshot.
  #[must_use]
  pub fn snapshot(&self) -> Arc<ResolvedConfig> {
    Arc::clone(&self.config)
  }

  /// Handle to the runtime token-mint store for new connections.
  #[must_use]
  pub(crate) fn mint_handle(&self) -> MintHandle {
    MintHandle::new(Arc::clone(&self.mint_store))
  }

  /// `SO_MARK` for upstream sockets (`None` = unmarked).
  #[must_use]
  pub fn fwmark(&self) -> Option<u32> {
    self.fwmark
  }
}

/// Box an error for a rama service error, preserving its debug chain.
pub(crate) fn into_box_error(err: &impl Debug) -> BoxError {
  BoxError::from(format!("{err:?}"))
}
/// Serve the explicit listener until its executor shuts down. Accept errors
/// are logged by the listener loop and never end the process.
pub async fn serve(listener: RamaTcpListener, state: Arc<ProxyState>) {
  listener.serve(ExplicitService { state }).await;
}

/// Bind the explicit listener with rama socket options: plain TCP socket for
/// the configured address, bound and listening, ready to serve. Backlog
/// matches `std` (128).
///
/// # Errors
///
/// Returns an error when the socket cannot be built, bound, or marked
/// listening.
pub async fn bind_explicit(addr: SocketAddr) -> Result<RamaTcpListener, Error> {
  let domain = if addr.is_ipv4() { Domain::IPv4 } else { Domain::IPv6 };
  let socket = SocketOptions {
    address: Some(SocketAddress::from(addr)),
    ..SocketOptions::default_tcp()
  }
  .try_build_socket(domain)
  .map_err(|err| Error::ListenSocket { source: err.into() })?;
  socket.listen(128).map_err(|err| Error::Listen { source: err.into() })?;
  RamaTcpListener::bind_socket(socket, Executor::default())
    .await
    .map_err(|err| Error::Bind { source: err })
}

/// Explicit ingress service: HTTP head dispatch (CONNECT vs forward).
/// Per-connection failures close quietly with a debug log.
#[derive(Debug, Clone)]
struct ExplicitService {
  state: Arc<ProxyState>,
}

impl Service<RamaTcpStream> for ExplicitService {
  type Output = ();
  type Error = std::convert::Infallible;

  async fn serve(&self, input: RamaTcpStream) -> Result<Self::Output, Self::Error> {
    let client = TcpStream::from(input);
    let peer = client.peer_addr().ok();
    if let Err(err) = dispatch(client, &self.state).await {
      tracing::debug!(?peer, ?err, "connection failed");
    }
    Ok(())
  }
}

async fn dispatch(mut client: TcpStream, state: &ProxyState) -> Result<(), Error> {
  let snapshot = state.snapshot();
  let head = read_head(&mut client, Duration::from_secs(snapshot.proxy.handshake_timeout_secs)).await?;
  let mut headers = [httparse::EMPTY_HEADER; 64];
  let mut request = httparse::Request::new(&mut headers);
  let parsed = request.parse(&head)?;
  if !parsed.is_complete() {
    return Ok(()); // over cap without a full head: close, no response
  }
  let (Some(method), Some(target)) = (request.method, request.path) else {
    return Ok(()); // malformed request line: close, no response
  };
  if method.eq_ignore_ascii_case("connect") {
    let Some((host, port)) = parse_authority(target, None) else {
      return Ok(());
    };
    let tail = head_tail(&head).to_vec();
    if expect(&snapshot.grants, Some(&host), port) == Expect::Splice {
      let mut upstream = dial_marked(&host, port, state.fwmark).await?;
      client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
      // Client bytes already read past the head (pipelined payloads) must not
      // be dropped: replay them upstream before splicing.
      if !tail.is_empty() {
        upstream.write_all(&tail).await?;
      }
      tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
      return Ok(());
    }
    client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
    serve_connect_stream(client, state, &snapshot, &host, port, &tail).await
  } else {
    forward_arm(client, &head, target, state, &snapshot).await
  }
}
/// Bytes after the HTTP head boundary, if any (pipelined client data).
fn head_tail(head: &[u8]) -> &[u8] {
  head.windows(4).position(|w| w == b"\r\n\r\n").map_or(&[], |pos| &head[pos + 4..])
}

/// Serve a post-200 CONNECT stream: peek TLS vs plain, resolve the identity
/// from the CONNECT authority (enforced against the SNI), then
/// MITM / splice / machines as appropriate. `initial` replays pipelined
/// bytes read past the CONNECT head.
///
/// # Errors
///
/// Returns an error when peeking fails, or when the upstream dial fails.
/// SNI mismatch and empty input close quietly (`Ok(())`), never errors.
pub async fn serve_connect_stream<G>(
  guest: G,
  state: &ProxyState,
  snapshot: &ResolvedConfig,
  host: &str,
  port: u16,
  initial: &[u8],
) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  expect(&snapshot.grants, Some(host), port)
    .serve(
      guest,
      CandidateParams {
        state,
        snapshot,
        dial_host: host,
        port,
        host: Some(host),
        raw_host: host,
        initial,
      },
    )
    .await
}

/// Serve a transparently captured stream (TUN/TPROXY/eBPF leg): peek TLS vs
/// plain, resolve the identity from the SNI or the HTTP `Host` head,
/// then MITM / splice / machines as appropriate. `dial_host` is the upstream
/// TCP target, `raw_host` the hostname for tcp:// grant matching.
///
/// # Errors
///
/// Returns an error when peeking fails, or when the upstream dial fails.
/// Empty input closes quietly (`Ok(())`), never errors.
pub async fn serve_transparent_stream<G>(
  guest: G,
  state: &ProxyState,
  snapshot: &ResolvedConfig,
  dial_host: &str,
  port: u16,
  raw_host: &str,
) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  expect(&snapshot.grants, None, port)
    .serve(
      guest,
      CandidateParams {
        state,
        snapshot,
        dial_host,
        port,
        host: None,
        raw_host,
        initial: &[],
      },
    )
    .await
}

async fn forward_arm(mut client: TcpStream, head: &[u8], target: &str, state: &ProxyState, snapshot: &ResolvedConfig) -> Result<(), Error> {
  let remainder = target.get(..7).filter(|p| p.eq_ignore_ascii_case("http://")).map(|_| &target[7..]);
  let Some(remainder) = remainder else {
    return Ok(()); // origin-form / unknown scheme: close
  };
  let authority = remainder.split('/').next().unwrap_or("");
  let Some((host, port)) = parse_authority(authority, Some(80)) else {
    return Ok(());
  };
  let upstream = dial_marked(&host, port, state.fwmark).await?;
  if !snapshot.grants.iter().any(|grant| grant.matches(Scheme::Http, &host, port)) {
    // No http grant: splice byte-identical, streaming, no machine buffering.
    let mut upstream = upstream;
    upstream.write_all(head).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    return Ok(());
  }
  let ctx = PairCtx {
    grants: &snapshot.grants,
    host: &host,
    port,
    plugins: &state.plugins,
    mint: Some(state.mint_handle()),
  };
  let (mut downstream_machine, mut upstream_machine) = http_pair(&ctx);
  relay_guarded(client, upstream, &mut downstream_machine, &mut upstream_machine, head, &[]).await
}

/// Read until the end of the HTTP head (`\r\n\r\n`) or `MAX_HEAD` bytes.
/// Returns whatever was read; caller checks completeness. Bounded by the
/// handshake timeout: this runs pre-auth on unauthenticated client bytes.
async fn read_head(stream: &mut TcpStream, budget: Duration) -> Result<Vec<u8>, Error> {
  tokio::time::timeout(budget, read_head_inner(stream))
    .await
    .map_err(|_elapsed| Error::HeadTimeout)?
}

async fn read_head_inner(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
  let mut buf = Vec::new();
  let mut chunk = [0u8; 8192];
  loop {
    let n = stream.read(&mut chunk).await?;
    if n == 0 {
      break;
    }
    buf.extend_from_slice(&chunk[..n]);
    if buf.len() > MAX_HEAD {
      break;
    }
    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
      break;
    }
  }
  Ok(buf)
}

/// Parse `host:port` authority via the `url` crate (dummy `http` scheme for
/// structure; the scheme itself is meaningless here). `default_port` fills
/// a missing port; without one the port is required. Returns `(host, port)`.
/// Unbracketed IPv6, userinfo, and paths are rejected — callers close
/// quietly on `None`.
fn parse_authority(authority: &str, default_port: Option<u16>) -> Option<(String, u16)> {
  if authority.contains(['/', '?', '#', '@']) {
    return None;
  }
  let url = url::Url::parse(&format!("http://{authority}")).ok()?;
  let host = match url.host()? {
    url::Host::Domain(domain) => domain.to_string(),
    url::Host::Ipv4(addr) => addr.to_string(),
    url::Host::Ipv6(addr) => addr.to_string(),
  };
  let port = url.port().or(default_port)?;
  Some((host, port))
}
