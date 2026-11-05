//! TCP leg: accept what the `connect4` hook redirected here and run it through
//! the shared substitution machinery.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::Error;
use crate::flow::{FlowTables, PROTO_TCP};
use arkham_proxy::{ProxyState, serve_captured_stream};
use tokio::net::{TcpListener, TcpStream};

/// Accept redirected connections forever.
///
/// The listener is a plain loopback socket: `connect4` already rewrote the
/// destination, so no `IP_TRANSPARENT` is involved. Each accepted connection's
/// original destination is looked up and handed to [`serve_captured_stream`]
/// exactly the way the TPROXY leg does — the SNI is the TLS identity, and for
/// transparent capture there is no CONNECT authority to enforce.
pub(crate) async fn serve(
  port: u16,
  flows: FlowTables,
  state: Arc<ProxyState>,
  upstream_override: Option<SocketAddr>,
) -> Result<(), Error> {
  let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
  loop {
    let (stream, peer) = listener.accept().await?;
    let flows = flows.clone();
    let state = Arc::clone(&state);
    tokio::spawn(async move {
      if let Err(err) = one(stream, peer, &flows, &state, upstream_override).await {
        tracing::debug!(%peer, ?err, "ebpf tcp connection failed");
      }
    });
  }
}

/// One captured connection.
async fn one(
  stream: TcpStream,
  peer: SocketAddr,
  flows: &FlowTables,
  state: &ProxyState,
  upstream_override: Option<SocketAddr>,
) -> Result<(), Error> {
  // No map entry means the flow was not redirected (or aged out of the LRU).
  // The socket is connected to us either way, so there is nowhere else to send
  // it: close quietly, matching the repo's convention for malformed capture.
  let Some(captured) = flows.original(peer, PROTO_TCP)? else {
    tracing::debug!(%peer, "no recorded destination for captured tcp flow; closing");
    return Ok(());
  };
  let dial = upstream_override.unwrap_or(captured.destination);
  let dial_host = dial.ip().to_string();
  serve_captured_stream(stream, state, captured.cgroup_id, &dial_host, dial.port(), &dial_host).await?;
  Ok(())
}
