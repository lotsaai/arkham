pub(crate) mod machine;

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::{AmqpScope, RootCert};

use super::PairCtx;
use super::{ServeStream, TlsCache, TlsHalves, Transport, matched_host, open_flagged, pair_ctx, settle_legs};
use crate::Error;
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

  async fn serve<G>(&self, ServeStream { guest, params, scope }: ServeStream<'_, G, AmqpScope>) -> Result<(), Error>
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
    let Some(opened) = open_flagged(
      guest,
      initial,
      budget,
      host,
      (scope.downstream.host.as_str(), scope.is_downstream_tls),
      (scope.upstream.host.as_str(), scope.upstream.port, state.fwmark),
      &state.mint,
    )
    .await?
    else {
      return Ok(());
    };
    let ctx = pair_ctx(
      &snapshot.grants,
      matched_host(opened.server_name.as_deref(), scope.downstream.host.as_str()),
      port,
      &state.plugins,
      state.mint_store(),
    );
    let swap = true;
    let settled = settle_legs(
      self,
      opened.guest_tls,
      scope.is_upstream_tls,
      (opened.guest, opened.guest_head),
      opened.upstream,
      scope,
      (scope.guest_tls, scope.upstream.host.as_str(), Some(("amqp", budget))),
    )
    .await?;
    super::relay_settled!(settled, relay, &ctx, swap)
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
