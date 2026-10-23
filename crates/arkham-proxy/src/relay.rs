pub(crate) use arkham_wire::relay::{RelayEnd, RelayUpgrade, log_hits};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::Error;
use arkham_wire::engine::Wire;

pub(crate) async fn relay_guarded<G, S, M>(
  guest: G,
  server: S,
  downstream: &mut M,
  upstream: &mut M,
  first: &[u8],
  upstream_first: &[u8],
) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  arkham_wire::relay::relay_guarded(guest, server, downstream, upstream, first, upstream_first)
    .await
    .map_err(Into::into)
}

pub(crate) async fn relay_stop<G, S, M>(
  guest: G,
  server: S,
  downstream: &mut M,
  upstream: &mut M,
  first: &[u8],
  upstream_first: &[u8],
) -> Result<RelayEnd<G, S>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  arkham_wire::relay::relay_stop(guest, server, downstream, upstream, first, upstream_first)
    .await
    .map_err(Into::into)
}
