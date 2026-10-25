pub(crate) mod machine;

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::{AmqpScope, RootCert};

use super::PairCtx;
use super::{ServeStream, TlsCache, TlsHalves, Transport, within};
use crate::Error;
use crate::connection::{Prefixed, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::relay::relay_guarded;
use crate::transports::engine::{Amqp, Direction};

#[derive(Debug, Clone)]
pub(crate) struct AmqpTransport {
  tls: TlsCache,
}

impl AmqpTransport {
  /// Share the proxy TLS cache.
  pub(crate) fn new(tls: TlsCache) -> Self {
    Self { tls }
  }
}

impl TlsHalves for AmqpTransport {
  type Scope = AmqpScope;

  fn tls(&self) -> &TlsCache {
    &self.tls
  }

  fn tls_label(&self) -> &'static str {
    "amqp"
  }

  fn root_cert<'a>(&self, scope: &'a AmqpScope) -> Option<&'a RootCert> {
    scope.root_cert.as_ref()
  }

  fn client_paths<'a>(&self, scope: &'a AmqpScope) -> Option<(&'a Path, &'a Path)> {
    Some((scope.client_cert.as_deref()?, scope.client_key.as_deref()?))
  }
}

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
      mint: Some(state.mint_store()),
    };
    self
      .relay_settled(
        OpenGuest {
          stream: guest,
          head: guest_head,
          tls: guest_tls,
        },
        upstream,
        scope,
        &ctx,
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

impl AmqpTransport {
  async fn relay_settled<G, S>(
    &self,
    guest: OpenGuest<G>,
    upstream: S,
    scope: &AmqpScope,
    ctx: &PairCtx<'_>,
    budget: Duration,
  ) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let OpenGuest { stream, head, tls } = guest;
    let swap = true;
    let upstream_name = scope.upstream.host.as_str();
    match (tls, scope.is_upstream_tls) {
      (None, false) => relay(Prefixed::new(head, stream), upstream, ctx, swap).await,
      (Some((hello_buf, identity)), false) => {
        let plain = within(
          "amqp",
          budget,
          self.accept_guest(&identity, Prefixed::new(hello_buf, stream), scope.guest_tls),
        )
        .await?;
        relay(plain, upstream, ctx, swap).await
      }
      (None, true) => {
        let plain = within("amqp", budget, self.connect_server(scope, upstream_name, upstream)).await?;
        relay(Prefixed::new(head, stream), plain, ctx, swap).await
      }
      (Some((hello_buf, identity)), true) => {
        let guest_plain = within(
          "amqp",
          budget,
          self.accept_guest(&identity, Prefixed::new(hello_buf, stream), scope.guest_tls),
        )
        .await?;
        let server_plain = within("amqp", budget, self.connect_server(scope, upstream_name, upstream)).await?;
        relay(guest_plain, server_plain, ctx, swap).await
      }
    }
  }
}

async fn relay<G, S>(guest: G, server: S, ctx: &PairCtx<'_>, swap: bool) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let (mut downstream, mut upstream) = amqp_pair(ctx, swap)?;
  relay_guarded(guest, server, &mut downstream, &mut upstream, &[], &[]).await
}

pub(crate) fn amqp_pair(ctx: &PairCtx<'_>, swap: bool) -> Result<(Amqp, Amqp), Error> {
  Ok((
    Amqp::new(ctx.grants, ctx.host, ctx.port, Direction::Downstream, swap)?,
    Amqp::new(ctx.grants, ctx.host, ctx.port, Direction::Upstream, false)?,
  ))
}
