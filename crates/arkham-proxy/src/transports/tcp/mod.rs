//! TCP vertical: the raw framing machine and the serve arm — everything
//! tcp owns. `splice` is the decline path every vertical hands to.

pub(crate) mod machine;

use arkham_config::grants::Scheme;

use super::PairCtx;
use super::{ServeStream, Transport};
use crate::Error;
use crate::connection::dial_marked;
use crate::identity::CandidateParams;
use crate::relay::relay_guarded;
use crate::transports::engine::{Direction, Raw};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};

/// The `tcp://` transport: opaque bytes, equal-length substitution.
#[derive(Debug, Default)]
pub(crate) struct TcpTransport;

impl Transport for TcpTransport {
  type Scope = ();

  /// The `tcp://` arm: nothing is read, the machines scan as the stream
  /// arrives.
  async fn serve<G>(&self, ServeStream { guest, params, .. }: ServeStream<'_, G, ()>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
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
    let upstream = dial_marked(dial_host, port, state.fwmark).await?;
    let ctx = PairCtx {
      grants: &snapshot.grants,
      redact: &snapshot.grants,
      host: raw_host,
      port,
      plugins: &state.plugins,
      mint: Some(state.mint_handle()),
    };
    let (mut downstream_machine, mut upstream_machine) = raw_tcp_pair(&ctx);
    relay_guarded(guest, upstream, &mut downstream_machine, &mut upstream_machine, initial, &[]).await
  }
}

/// Copy bytes unchanged, replaying whatever was already read past the ingress
/// head so no guest byte is dropped. Every vertical that declines a stream
/// hands it here.
pub(crate) async fn splice<G>(mut guest: G, dial_host: &str, port: u16, fwmark: Option<u32>, read: &[u8]) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let mut upstream = dial_marked(dial_host, port, fwmark).await?;
  if !read.is_empty() {
    upstream.write_all(read).await?;
  }
  tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
  Ok(())
}

/// Cleartext non-HTTP bytes: raw equal-length swap on tcp grants.
pub(crate) fn raw_tcp_pair(ctx: &PairCtx<'_>) -> (Raw, Raw) {
  (
    Raw::new(ctx.grants, Scheme::Tcp, ctx.host, ctx.port, Direction::Downstream),
    Raw::new(ctx.grants, Scheme::Tcp, ctx.host, ctx.port, Direction::Upstream),
  )
}
