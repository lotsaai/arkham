//! HTTP vertical: the `https://` MITM arm, the `http://` cleartext arm, the
//! per-connection substitution service, and the HTTP/1 + HTTP/2 framing
//! machines — everything http owns.

pub(crate) mod h2;
pub(crate) mod machine;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rama::Service;
use rama::error::BoxError;
use rama::extensions::ExtensionsRef;
use rama::io::BridgeIo;
use rama::net::tls::ApplicationProtocol;
use rama::tls::boring::TlsStream;
use rama::tls::boring::proxy::TlsMitmRelayService;
use rama::tls::client::NegotiatedTlsParameters;
use rama::tls::server::InputWithClientHello;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::{EndpointScope, Grant, Scheme};
use arkham_plugin::Direction as HookDirection;

use super::PairCtx;
use super::{ServeStream, Transport};
use crate::Error;
use crate::connection::{GuestIo, Prefixed, client_auth_policy, dial_marked};
use crate::identity::{CandidateParams, Hello, read_client_hello, read_http_head};
use crate::into_box_error;
use crate::mint::MintHandle;
use crate::relay::relay_guarded;
use crate::transports::engine::{Direction, H2, Http, Raw, sibling_upstream_pairs};
use crate::transports::tcp::{self, raw_tcp_pair};
use crate::transports::tls::cached_guest_certs;

/// The `https://` transport: terminate the guest's TLS, dial upstream, and
/// pump the framed substitution through the boring MITM relay.
#[derive(Debug, Default)]
pub(crate) struct HttpsTransport;

impl Transport for HttpsTransport {
  type Scope = ();

  async fn serve<G>(&self, ServeStream { mut guest, params, .. }: ServeStream<'_, G, ()>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let CandidateParams {
      state,
      snapshot,
      dial_host,
      port,
      host,
      initial,
      ..
    } = params;
    let budget = Duration::from_secs(snapshot.proxy.handshake_timeout_secs);
    let Some(read) = read_client_hello(&mut guest, initial, budget).await? else {
      return Ok(());
    };
    let (buf, sni, parsed) = match read {
      Hello::Named { buf, sni, hello } => (buf, Some(sni), Some(hello)),
      Hello::Unnamed { buf, hello } => (buf, None, hello),
    };
    if let (Some(authority), Some(sni)) = (host, sni.as_deref())
      && !sni.eq_ignore_ascii_case(authority)
    {
      tracing::debug!(authority, sni, "CONNECT authority differs from SNI; closing");
      return Ok(());
    }
    let identity = host.or(sni.as_deref()).unwrap_or(dial_host);
    let hits: Vec<(Grant, EndpointScope)> = snapshot
      .grants
      .iter()
      .filter_map(|grant| {
        grant
          .endpoint(Scheme::Https, Some(identity), port)
          .map(|scope| (grant.clone(), scope.clone()))
      })
      .collect();
    if hits.is_empty() {
      return tcp::splice(guest, dial_host, port, state.fwmark, &buf).await;
    }
    let root_cert = shared_root(&state.guest_certs, &hits, identity, port)?;
    let identity = identity.to_string();
    if !state.mint.allow() {
      return Err(Error::BurstExceeded {
        identity: identity.clone(),
      });
    }
    let scope = agreed_scope(&hits, &identity, port)?;
    let dial_port = scope.upstream_port.unwrap_or(port);
    let policy = client_auth_policy(&state.identities, scope, &state.mtls_trust)?;
    let upstream = dial_marked(dial_host, dial_port, state.fwmark).await?;
    let mut guest_io = GuestIo::with_target(Prefixed::new(buf, guest), &identity, port)?;
    if let Some(policy) = policy {
      guest_io = guest_io.with_client_auth_policy(policy);
    }
    let bridge = BridgeIo(guest_io, GuestIo::bare(upstream));
    let grants: Vec<Grant> = hits.iter().map(|(grant, _)| grant.clone()).collect();
    let redact = grants_for_dial(&snapshot.grants, &identity, dial_port);
    let pump = SubstitutionService {
      redact,
      grants,
      identity,
      port,
      dial_port,
      plugins: Arc::clone(&state.plugins),
      mint: Some(state.mint_handle()),
    };
    let relay = match &root_cert {
      None => state.relay.clone(),
      Some(path) => state
        .extra_relays
        .get(path)
        .cloned()
        .ok_or_else(|| Error::UnknownTrustBundle { path: path.clone() })?,
    };
    let relay = TlsMitmRelayService::new(relay, pump);
    match parsed {
      Some(hello) => relay
        .serve(InputWithClientHello {
          input: bridge,
          client_hello: hello,
        })
        .await
        .map_err(|err| Error::MitmRelay { source: err.into() }),
      None => relay.serve(bridge).await.map_err(|err| Error::MitmRelay { source: err.into() }),
    }
  }
}

/// The `http://` transport: cleartext, the `Host` head names the peer.
#[derive(Debug, Default)]
pub(crate) struct HttpTransport;

impl Transport for HttpTransport {
  type Scope = ();

  /// The `http://` arm: a head that never completes is not HTTP, so the
  /// connection closes; a host the config does not name falls to the raw
  /// scopes for this destination.
  async fn serve<G>(&self, ServeStream { mut guest, params, .. }: ServeStream<'_, G, ()>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let CandidateParams {
      state,
      snapshot,
      dial_host,
      port,
      raw_host,
      initial,
      ..
    } = params;
    let budget = Duration::from_secs(snapshot.proxy.handshake_timeout_secs);
    let Some((head, head_host, head_port)) = read_http_head(&mut guest, initial, budget, port).await? else {
      return Ok(());
    };
    let named = snapshot
      .grants
      .iter()
      .any(|grant| grant.endpoint(Scheme::Http, Some(&head_host), head_port).is_some());
    let upstream = dial_marked(dial_host, port, state.fwmark).await?;
    let ctx = PairCtx {
      grants: &snapshot.grants,
      redact: &snapshot.grants,
      host: if named { &head_host } else { raw_host },
      port: if named { head_port } else { port },
      plugins: &state.plugins,
      mint: Some(state.mint_handle()),
    };
    if named {
      let (mut downstream_machine, mut upstream_machine) = http_pair(&ctx);
      relay_guarded(guest, upstream, &mut downstream_machine, &mut upstream_machine, &head, &[]).await
    } else {
      let (mut downstream_machine, mut upstream_machine) = raw_tcp_pair(&ctx);
      relay_guarded(guest, upstream, &mut downstream_machine, &mut upstream_machine, &head, &[]).await
    }
  }
}

#[derive(Debug, Clone)]
pub(crate) struct SubstitutionService {
  grants: Vec<Grant>,
  redact: Vec<Grant>,
  identity: String,
  port: u16,
  dial_port: u16,
  plugins: Arc<arkham_plugin::Registry>,
  mint: Option<MintHandle>,
}

/// The trust bundle every hit names.
///
/// Equal paths are one bundle and are not read again. Two different paths
/// are one bundle when they hold the same certificates. A hit with a bundle
/// and a hit without one are different bundles.
fn shared_root(
  bundles: &DashMap<PathBuf, Arc<Vec<CertificateDer<'static>>>>,
  hits: &[(Grant, EndpointScope)],
  host: &str,
  port: u16,
) -> Result<Option<PathBuf>, Error> {
  let mut missing = false;
  let mut chosen: Option<PathBuf> = None;
  for (_, scope) in hits {
    let Some(path) = &scope.root_cert else {
      if chosen.is_some() {
        return Err(split_trust(host, port));
      }
      missing = true;
      continue;
    };
    if missing {
      return Err(split_trust(host, port));
    }
    match &chosen {
      None => chosen = Some(path.clone()),
      Some(seen) if seen == path => {}
      Some(seen) if bundle_bytes(bundles, seen)? == bundle_bytes(bundles, path)? => {}
      Some(_) => return Err(split_trust(host, port)),
    }
  }
  Ok(chosen)
}

fn bundle_bytes(bundles: &DashMap<PathBuf, Arc<Vec<CertificateDer<'static>>>>, path: &Path) -> Result<Vec<Vec<u8>>, Error> {
  let Some(certs) = cached_guest_certs(bundles, path)? else {
    return Err(Error::UnknownTrustBundle { path: path.to_path_buf() });
  };
  if certs.is_empty() {
    return Err(Error::EmptyChain { path: path.to_path_buf() });
  }
  let mut anchors: Vec<Vec<u8>> = certs.iter().map(|cert| cert.as_ref().to_vec()).collect();
  anchors.sort_unstable();
  Ok(anchors)
}

fn split_trust(host: &str, port: u16) -> Error {
  Error::SplitTrustBundle {
    host: host.to_string(),
    port,
  }
}

fn agreed_scope<'a>(hits: &'a [(Grant, EndpointScope)], host: &str, port: u16) -> Result<&'a EndpointScope, Error> {
  let Some((_, first)) = hits.first() else {
    return Err(ambiguous_grants(hits, host, port));
  };
  let same = hits.iter().all(|(_, scope)| {
    scope.client_cert == first.client_cert
      && scope.client_key == first.client_key
      && scope.guest_tls == first.guest_tls
      && scope.upstream_port == first.upstream_port
  });
  if same { Ok(first) } else { Err(ambiguous_grants(hits, host, port)) }
}

fn grants_for_dial(grants: &[Grant], host: &str, dial_port: u16) -> Vec<Grant> {
  grants
    .iter()
    .filter(|grant| grant.shares_upstream(Scheme::Https, host, dial_port))
    .cloned()
    .collect()
}

fn ambiguous_grants(hits: &[(Grant, EndpointScope)], host: &str, port: u16) -> Error {
  let mut labels: Vec<&str> = hits
    .iter()
    .filter_map(|(grant, _)| grant.credential().map(|credential| credential.label.as_str()))
    .collect();
  labels.sort_unstable();
  Error::AmbiguousHttpsGrants {
    host: host.to_string(),
    port,
    labels: labels.join(", "),
  }
}

impl<GI, GE> Service<BridgeIo<TlsStream<GI>, TlsStream<GE>>> for SubstitutionService
where
  GI: AsyncRead + AsyncWrite + Unpin + Send + 'static + ExtensionsRef,
  GE: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  type Output = ();
  type Error = BoxError;

  async fn serve(&self, input: BridgeIo<TlsStream<GI>, TlsStream<GE>>) -> Result<Self::Output, Self::Error> {
    self.dispatch(input).await.map_err(|err| into_box_error(&err))
  }
}

impl SubstitutionService {
  async fn dispatch<GI, GE>(&self, input: BridgeIo<TlsStream<GI>, TlsStream<GE>>) -> Result<(), Error>
  where
    GI: AsyncRead + AsyncWrite + Unpin + Send + 'static + ExtensionsRef,
    GE: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let BridgeIo(guest_tls, server_tls) = input;
    let alpn = negotiated_alpn(&guest_tls);
    self.pump(guest_tls, server_tls, &[], alpn.as_deref()).await
  }

  async fn pump<G, S>(&self, guest: G, server: S, prefix: &[u8], alpn: Option<&[u8]>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let ctx = PairCtx {
      grants: &self.grants,
      redact: &self.redact,
      host: &self.identity,
      port: self.port,
      plugins: &self.plugins,
      mint: self.mint.clone(),
    };
    // HTTP/2 over TLS is defined by its ALPN identifier (RFC 9113 §3.1), so an unnegotiated connection is
    // never HTTP/2.
    let extra = sibling_upstream_pairs(&self.redact, Scheme::Https, &self.identity, self.port, self.dial_port);
    match alpn {
      Some(proto) if proto == ApplicationProtocol::HTTP_2.as_bytes() => {
        let (mut downstream_machine, mut upstream_machine) = https_h2_pair(&ctx);
        upstream_machine.extend_redaction(&extra);
        relay_guarded(guest, server, &mut downstream_machine, &mut upstream_machine, prefix, &[]).await
      }
      Some(proto) if proto == ApplicationProtocol::HTTP_11.as_bytes() => {
        let (mut downstream_machine, mut upstream_machine) = https_pair(&ctx);
        upstream_machine.extend_redaction(&extra);
        relay_guarded(guest, server, &mut downstream_machine, &mut upstream_machine, prefix, &[]).await
      }
      _ => {
        let (mut downstream_machine, mut upstream_machine) = raw_tls_pair(&ctx);
        upstream_machine.extend_redaction(&extra);
        relay_guarded(guest, server, &mut downstream_machine, &mut upstream_machine, prefix, &[]).await
      }
    }
  }
}

fn negotiated_alpn<GI>(guest: &TlsStream<GI>) -> Option<Vec<u8>>
where
  GI: ExtensionsRef,
{
  guest
    .extensions()
    .get_ref::<NegotiatedTlsParameters>()
    .and_then(|params| params.application_layer_protocol.as_ref())
    .map(|proto| proto.as_bytes().to_vec())
}

/// Both directions for a cleartext HTTP connection.
pub(crate) fn http_pair(ctx: &PairCtx<'_>) -> (Http, Http) {
  (
    Http::new(
      ctx.grants,
      Scheme::Http,
      ctx.host,
      ctx.port,
      Direction::Downstream,
      ctx.plugins.select(Scheme::Http, ctx.host, ctx.port, HookDirection::Request),
      ctx.mint.clone(),
    ),
    Http::new(
      ctx.grants,
      Scheme::Http,
      ctx.host,
      ctx.port,
      Direction::Upstream,
      ctx.plugins.select(Scheme::Http, ctx.host, ctx.port, HookDirection::Response),
      ctx.mint.clone(),
    ),
  )
}

/// Both directions behind terminated TLS, HTTP/1 framing.
pub(crate) fn https_pair(ctx: &PairCtx<'_>) -> (Http, Http) {
  (
    Http::new(
      ctx.grants,
      Scheme::Https,
      ctx.host,
      ctx.port,
      Direction::Downstream,
      ctx.plugins.select(Scheme::Https, ctx.host, ctx.port, HookDirection::Request),
      ctx.mint.clone(),
    ),
    Http::new(
      ctx.redact,
      Scheme::Https,
      ctx.host,
      ctx.port,
      Direction::Upstream,
      ctx.plugins.select(Scheme::Https, ctx.host, ctx.port, HookDirection::Response),
      ctx.mint.clone(),
    ),
  )
}

/// Both directions behind terminated TLS, HTTP/2 framing.
pub(crate) fn https_h2_pair(ctx: &PairCtx<'_>) -> (H2, H2) {
  (
    H2::new(
      ctx.grants,
      Scheme::Https,
      ctx.host,
      ctx.port,
      Direction::Downstream,
      ctx.plugins.select(Scheme::Https, ctx.host, ctx.port, HookDirection::Request),
      ctx.mint.clone(),
    ),
    H2::new(
      ctx.redact,
      Scheme::Https,
      ctx.host,
      ctx.port,
      Direction::Upstream,
      ctx.plugins.select(Scheme::Https, ctx.host, ctx.port, HookDirection::Response),
      ctx.mint.clone(),
    ),
  )
}

/// Terminated TLS without HTTP structure: raw equal-length swap on https
/// grants.
pub(crate) fn raw_tls_pair(ctx: &PairCtx<'_>) -> (Raw, Raw) {
  (
    Raw::new(ctx.grants, Scheme::Https, ctx.host, ctx.port, Direction::Downstream),
    Raw::new(ctx.redact, Scheme::Https, ctx.host, ctx.port, Direction::Upstream),
  )
}

/// Cap for one client head: over this without a complete head, the bytes are
/// not a request head, so the reader stops instead of buffering an unbounded
/// drip.
pub(crate) const MAX_HEAD: usize = 64 * 1024;

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::grants::{Credential, GuestTlsMode};
  use arkham_pki::ca::CertAuthority;
  use secrecy::SecretString;

  fn hit(port: u16, root: Option<std::path::PathBuf>) -> (Grant, EndpointScope) {
    let grant = Grant::Token {
      credential: Credential {
        label: "user".into(),
        fake: "fake".into(),
        value: SecretString::from("real".to_string()),
      },
      allow: Vec::new(),
      pattern: None,
      oauth2: None,
    };
    let scope = EndpointScope {
      scheme: Scheme::Https,
      host: "127.0.0.1".parse().unwrap(),
      port,
      client_cert: None,
      client_key: None,
      root_cert: root,
      guest_tls: GuestTlsMode::Tls,

      upstream_port: None,
    };
    (grant, scope)
  }

  #[test]
  fn same_certificates_at_two_paths_are_one_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CertAuthority::generate().unwrap();
    let first = dir.path().join("a.pem");
    let second = dir.path().join("b.pem");
    std::fs::write(&first, ca.cert_pem()).unwrap();
    std::fs::write(&second, ca.cert_pem()).unwrap();
    let hits = vec![hit(6443, Some(first.clone())), hit(6443, Some(second.clone()))];
    let bundles = DashMap::new();
    let chosen = shared_root(&bundles, &hits, "127.0.0.1", 6443).expect("identical certificates agree");
    assert_eq!(chosen.as_deref(), Some(first.as_path()));
  }

  #[test]
  fn different_certificates_are_a_split_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("a.pem");
    let second = dir.path().join("b.pem");
    std::fs::write(&first, CertAuthority::generate().unwrap().cert_pem()).unwrap();
    std::fs::write(&second, CertAuthority::generate().unwrap().cert_pem()).unwrap();
    let hits = vec![hit(6443, Some(first.clone())), hit(6443, Some(second.clone()))];
    let bundles = DashMap::new();
    let err = shared_root(&bundles, &hits, "127.0.0.1", 6443).expect_err("different certificates disagree");
    assert!(matches!(err, Error::SplitTrustBundle { port: 6443, .. }), "{err}");
  }
}
