//! HTTP vertical: the `https://` MITM arm, the `http://` cleartext arm, the
//! per-connection substitution service, and the HTTP/1 + HTTP/2 framing
//! machines — everything http owns.

pub(crate) mod h2;
pub(crate) mod machine;

use std::sync::Arc;
use std::time::Duration;

use rama::Service;
use rama::error::BoxError;
use rama::extensions::ExtensionsRef;
use rama::io::BridgeIo;
use rama::tls::boring::TlsStream;
use rama::tls::boring::proxy::TlsMitmRelayService;
use rama::tls::client::NegotiatedTlsParameters;
use rama::tls::server::InputWithClientHello;
use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::{ResolvedConfig, Scheme};

use arkham_plugin::Direction as HookDirection;
use rama::net::tls::ApplicationProtocol;

use super::PairCtx;
use super::{ServeStream, Transport};
use crate::Error;
use crate::connection::{GuestIo, Prefixed, client_auth_policy, dial_marked};
use crate::identity::{CandidateParams, Hello, read_client_hello, read_http_head};
use crate::into_box_error;
use crate::mint::MintStore;
use crate::relay::relay_guarded;
use crate::transports::engine::{Direction, H2, Http, Raw};
use crate::transports::tcp;
use crate::transports::tcp::raw_tcp_pair;

/// The `https://` transport: terminate the guest's TLS, dial upstream, and
/// pump the framed substitution through the boring MITM relay.
#[derive(Debug, Default)]
pub(crate) struct HttpsTransport;

impl Transport for HttpsTransport {
  type Scope = ();

  /// The `https://` MITM arm. Bytes that never complete a hello cannot be
  /// served here, and an identity no scope names is copied.
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
      // A complete hello without SNI still carries the client's ALPN and
      // fingerprint: mirror it instead of falling back to boring defaults,
      // which negotiate no ALPN and drop framed substitution.
      Hello::Unnamed { buf, hello } => (buf, None, hello),
    };
    if let (Some(authority), Some(sni)) = (host, sni.as_deref())
      && !sni.eq_ignore_ascii_case(authority)
    {
      tracing::debug!(authority, sni, "CONNECT authority differs from SNI; closing");
      return Ok(());
    }
    // Transparent capture of an IP-literal client (kubectl against an
    // address) carries no SNI, so the captured destination is the identity
    // to mint for. A grant that does not name it still splices below.
    let identity = host.or(sni.as_deref()).unwrap_or(dial_host);
    let Some(scope) = snapshot
      .grants
      .iter()
      .find_map(|grant| grant.endpoint(Scheme::Https, Some(identity), port))
    else {
      // No https scope names this identity: nothing to substitute.
      return tcp::splice(guest, dial_host, port, state.fwmark, &buf).await;
    };
    let identity = identity.to_string();
    if !state.mint.allow() {
      return Err(Error::BurstExceeded {
        identity: identity.clone(),
      });
    }
    let upstream = dial_marked(dial_host, port, state.fwmark).await?;
    let guest_io = GuestIo::with_target(Prefixed::new(buf, guest), &identity, port)?;
    // The entry can name the proxy's upstream client identity, and the rule
    // can demand a guest certificate: the relay reads the resulting policy
    // off the guest leg's extensions and enforces it on both legs.
    let mut guest_io = guest_io;
    if let Some(policy) = client_auth_policy(scope, &state.mtls_trust)? {
      guest_io = guest_io.with_client_auth_policy(policy);
    }
    let bridge = BridgeIo(guest_io, GuestIo::bare(upstream));
    let pump = SubstitutionService {
      snapshot: state.snapshot(),
      identity,
      port,
      plugins: Arc::clone(&state.plugins),
      mint: Some(state.mint_store()),
    };
    // Entries naming `root_cert` ride their own relay extending the global
    // egress trust; the map was built from this same config, so a miss is
    // a bug, failed closed.
    let relay = match &scope.root_cert {
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
      host: if named { &head_host } else { raw_host },
      port: if named { head_port } else { port },
      plugins: &state.plugins,
      mint: Some(state.mint_store()),
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

/// The https vertical's per-connection substitution service: the boring
/// MITM relay terminates both legs and hands the paired TLS streams here,
/// where the negotiated ALPN picks the framing and the substitution
/// machines pump. A struct, not a closure, because rama's relay calls a
/// `Service` and the guest-side stream type belongs to the caller.
/// Decoded-request middleware is deliberately not used: a `Request<Body>`
/// round-trips through the HTTP codec and would break the byte-identical
/// guarantee the verbatim tests pin.
#[derive(Debug, Clone)]
pub(crate) struct SubstitutionService {
  snapshot: Arc<ResolvedConfig>,
  identity: String,
  port: u16,
  plugins: Arc<arkham_plugin::Registry>,
  mint: Option<MintStore>,
}

impl<GI, GE> Service<BridgeIo<TlsStream<GI>, TlsStream<GE>>> for SubstitutionService
where
  GI: AsyncRead + AsyncWrite + Unpin + Send + 'static + ExtensionsRef,
  GE: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  type Output = ();
  type Error = BoxError;

  async fn serve(&self, input: BridgeIo<TlsStream<GI>, TlsStream<GE>>) -> Result<Self::Output, Self::Error> {
    let BridgeIo(mut guest_tls, mut server_tls) = input;
    // The scope that matched selected TLS termination; framing picks the legs.
    // Schemes below are grant scopes (authorization), never selection.
    let ctx = PairCtx {
      grants: &self.snapshot.grants,
      host: &self.identity,
      port: self.port,
      plugins: &self.plugins,
      mint: self.mint.clone(),
    };
    // The relay handshook the upstream leg before the guest's, and answered
    // the guest with what that leg agreed, so this one fact frames both
    // directions. Nothing here reads a plaintext byte.
    let negotiated = guest_tls
      .extensions()
      .get_ref::<NegotiatedTlsParameters>()
      .and_then(|params| params.application_layer_protocol.as_ref());
    // One negotiated protocol frames both directions. That choice is the only
    // thing that proves the plaintext is HTTP: a flow that agreed neither
    // `h2` nor `http/1.1` relays raw, where the equal-length grants for this
    // scope still swap and no framing is invented for bytes nobody claimed.
    // HTTP/2 over TLS is defined by its ALPN identifier (RFC 9113 §3.1), so
    // an unnegotiated connection is never HTTP/2.
    match negotiated {
      Some(proto) if proto.as_bytes() == ApplicationProtocol::HTTP_2.as_bytes() => {
        let (mut downstream_machine, mut upstream_machine) = https_h2_pair(&ctx);
        relay_guarded(
          &mut guest_tls,
          &mut server_tls,
          &mut downstream_machine,
          &mut upstream_machine,
          &[],
          &[],
        )
        .await
        .map_err(|err| into_box_error(&err))
      }
      Some(proto) if proto.as_bytes() == ApplicationProtocol::HTTP_11.as_bytes() => {
        let (mut downstream_machine, mut upstream_machine) = https_pair(&ctx);
        relay_guarded(
          &mut guest_tls,
          &mut server_tls,
          &mut downstream_machine,
          &mut upstream_machine,
          &[],
          &[],
        )
        .await
        .map_err(|err| into_box_error(&err))
      }
      _ => {
        let (mut downstream_machine, mut upstream_machine) = raw_tls_pair(&ctx);
        relay_guarded(
          &mut guest_tls,
          &mut server_tls,
          &mut downstream_machine,
          &mut upstream_machine,
          &[],
          &[],
        )
        .await
        .map_err(|err| into_box_error(&err))
      }
    }
  }
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
      ctx.grants,
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
      ctx.grants,
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
    Raw::new(ctx.grants, Scheme::Https, ctx.host, ctx.port, Direction::Upstream),
  )
}

/// Cap for one client head: over this without a complete head, the bytes are
/// not a request head, so the reader stops instead of buffering an unbounded
/// drip.
pub(crate) const MAX_HEAD: usize = 64 * 1024;
