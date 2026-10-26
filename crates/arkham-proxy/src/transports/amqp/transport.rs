use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::{AmqpScope, GuestTlsMode, RootCert};

use super::super::PairCtx;
use super::super::{ServeStream, TlsCache, TlsHalves, Transport, matched_host, open_flagged};
use crate::Error;
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

  fn guest_tls(&self, scope: &AmqpScope) -> GuestTlsMode {
    scope.guest_tls
  }

  fn upstream_host<'a>(&self, scope: &'a AmqpScope) -> &'a str {
    scope.upstream.host.as_str()
  }
}

impl Transport for AmqpTransport {
  type Scope = AmqpScope;

  async fn serve<G>(&self, ServeStream { guest, params, scope }: ServeStream<'_, G, AmqpScope>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let budget = Duration::from_secs(params.snapshot.proxy.handshake_timeout_secs);
    let Some(mut opened) = open_flagged(guest, &params, scope).await? else {
      return Ok(());
    };
    let server_name = opened.server_name.take();
    let ctx = PairCtx::new(&params, matched_host(server_name.as_deref(), scope.downstream.host.as_str()));
    let swap = true;
    let settled = self.settle(scope, opened, Some(budget)).await?;
    super::super::relay_settled!(settled, relay, &ctx, swap)
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
