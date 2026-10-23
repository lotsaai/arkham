use std::time::Duration;

use secrecy::ExposeSecret as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;

use arkham_amqp::{Amqp, SaslSwap};
use arkham_config::grants::{AmqpScope, Grant, GuestTlsMode};
use arkham_wire::engine::Direction;
use arkham_wire::tls::TlsLegs;

use super::PairCtx;
use super::{ServeStream, Transport};
use crate::Error;
use crate::connection::{Prefixed, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::relay::relay_guarded;
use crate::transports::tls::{UpstreamTls, Verify, finish};

#[derive(Debug, Default)]
pub(crate) struct AmqpTransport;

impl Transport for AmqpTransport {
  type Scope = AmqpScope;

  async fn serve<G>(&self, ServeStream { mut guest, params, scope }: ServeStream<'_, G, AmqpScope>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let CandidateParams {
      state,
      snapshot,
      host,
      port,
      initial,
      ..
    } = params;
    let budget = Duration::from_secs(snapshot.proxy.handshake_timeout_secs);
    let mut server_name = host.map(ToString::to_string);
    let guest_head = initial.to_vec();
    let mut guest_tls: Option<(Vec<u8>, String)> = None;
    if scope.is_downstream_tls {
      let authority = host.or(Some(scope.downstream.host.as_str()));
      let Some((hello_buf, identity, sni_name)) = guest_tls_opening(&mut guest, initial, budget, authority, &state.mint).await? else {
        return Ok(());
      };
      server_name = Some(sni_name);
      guest_tls = Some((hello_buf, identity));
    }

    let upstream = dial_marked(&scope.upstream.host, scope.upstream.port, state.fwmark).await?;
    let matched_name = server_name
      .as_deref()
      .filter(|name| scope.downstream.host.eq_ignore_ascii_case(name));
    let ctx = PairCtx {
      grants: &snapshot.grants,
      host: matched_name.unwrap_or(scope.downstream.host.as_str()),
      port,
      plugins: &state.plugins,
      mint: Some(state.mint_handle()),
    };
    let legs = &state.legs;
    relay_settled(
      OpenGuest {
        stream: guest,
        head: guest_head,
        tls: guest_tls,
      },
      upstream,
      scope,
      &ctx,
      legs,
      budget,
    )
    .await
  }
}

struct OpenGuest<G> {
  stream: G,
  head: Vec<u8>,
  tls: Option<(Vec<u8>, String)>,
}

async fn relay_settled<G, S>(
  guest: OpenGuest<G>,
  upstream: S,
  scope: &AmqpScope,
  ctx: &PairCtx<'_>,
  legs: &TlsLegs,
  budget: Duration,
) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let OpenGuest { stream, head, tls } = guest;
  let upstream_name = scope.upstream.host.as_str();
  match (tls, scope.is_upstream_tls) {
    (None, false) => relay(Prefixed::new(head, stream), upstream, ctx).await,
    (Some((hello_buf, identity)), false) => {
      let plain = accept_guest(legs, &identity, Prefixed::new(hello_buf, stream), scope.guest_tls, budget).await?;
      relay(plain, upstream, ctx).await
    }
    (None, true) => {
      let plain = connect_server(legs, scope, upstream_name, upstream, budget).await?;
      relay(Prefixed::new(head, stream), plain, ctx).await
    }
    (Some((hello_buf, identity)), true) => {
      let guest_plain = accept_guest(legs, &identity, Prefixed::new(hello_buf, stream), scope.guest_tls, budget).await?;
      let server_plain = connect_server(legs, scope, upstream_name, upstream, budget).await?;
      relay(guest_plain, server_plain, ctx).await
    }
  }
}

async fn accept_guest<G>(legs: &TlsLegs, name: &str, guest: G, mode: GuestTlsMode, budget: Duration) -> Result<ServerTlsStream<G>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  finish(budget, legs.accept_guest(name, guest, mode, None))
    .await
    .map_err(Error::from)
}

async fn connect_server<S>(
  legs: &TlsLegs,
  scope: &AmqpScope,
  server_name: &str,
  server: S,
  budget: Duration,
) -> Result<ClientTlsStream<S>, Error>
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let root = scope.root_cert.as_ref();
  let client_cert = scope.client_cert.as_deref();
  let client_key = scope.client_key.as_deref();
  finish(budget, async move {
    legs
      .connect_upstream(
        &UpstreamTls {
          server_name,
          root,
          verify: Verify::Full,
          client_cert,
          client_key,
          alpn: None,
        },
        server,
      )
      .await
  })
  .await
  .map_err(Error::from)
}

async fn relay<G, S>(guest: G, server: S, ctx: &PairCtx<'_>) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let (mut downstream, mut upstream) = amqp_pair(ctx)?;
  relay_guarded(guest, server, &mut downstream, &mut upstream, &[], &[]).await
}

fn sasl_swap(grants: &[Grant], host: &str, port: u16) -> Option<SaslSwap> {
  grants.iter().find_map(|grant| {
    let scope = grant.amqp(Some(host), port)?;
    let label = grant.credential().map(|credential| credential.label.clone()).unwrap_or_default();
    Some(SaslSwap {
      label,
      fake: scope.downstream.password.expose_secret().as_bytes().to_vec(),
      user: scope.upstream.user.as_bytes().to_vec(),
      real: scope.upstream.password.expose_secret().as_bytes().to_vec(),
    })
  })
}

fn amqp_pair(ctx: &PairCtx<'_>) -> Result<(Amqp, Amqp), Error> {
  let swap = sasl_swap(ctx.grants, ctx.host, ctx.port);
  Ok((
    Amqp::new(swap.clone(), Direction::Downstream)?,
    Amqp::new(swap, Direction::Upstream)?,
  ))
}
