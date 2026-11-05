//! TCP leg: accept what the `connect4` hook redirected here and run it through
//! the shared substitution machinery.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::Error;
use crate::cgroup_id_of_pid;
use crate::flow::{FlowTables, PROTO_TCP, retained_cgroup};
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
  let live = live_cgroup(&stream, peer);
  let Some(cgroup) = retained_cgroup(captured.cgroup_id, live) else {
    tracing::debug!(%peer, recorded = captured.cgroup_id, live, "captured tcp cgroup does not match the live socket; closing");
    return Ok(());
  };
  let dial = upstream_override.unwrap_or(captured.destination);
  let dial_host = dial.ip().to_string();
  serve_captured_stream(stream, state, cgroup, &dial_host, dial.port(), &dial_host).await?;
  Ok(())
}

/// Cgroup of the process that owns the client socket behind `peer`.
///
/// The accepted socket's peer credentials are not available for TCP.
/// `/proc/net/tcp` names the client's socket inode, and that inode's fd is
/// the process whose cgroup must match the map entry. `0` means the process
/// could not be identified, which the caller treats as "not this flow".
fn live_cgroup(stream: &TcpStream, peer: SocketAddr) -> u64 {
  let Ok(local) = stream.local_addr() else {
    return 0;
  };
  let Some(inode) = established_inode(peer, local) else {
    return 0;
  };
  let Some(pid) = pid_for_socket(inode) else {
    return 0;
  };
  cgroup_id_of_pid(pid)
}

/// Inode of the established client socket whose local address is `client`
/// and whose remote address is the listener `local`.
fn established_inode(client: SocketAddr, local: SocketAddr) -> Option<u64> {
  let client = proc_tcp_addr(client)?;
  let local = proc_tcp_addr(local)?;
  let text = std::fs::read_to_string("/proc/net/tcp").ok()?;
  for line in text.lines().skip(1) {
    let mut cols = line.split_whitespace();
    let _slot = cols.next()?;
    let loc = cols.next()?;
    let rem = cols.next()?;
    let state = cols.next()?;
    if !loc.eq_ignore_ascii_case(&client) || !rem.eq_ignore_ascii_case(&local) || state != "01" {
      continue;
    }
    // tx, tr, retrnsmt, uid, timeout, then inode.
    return cols.nth(5).and_then(|inode| inode.parse().ok());
  }
  None
}

/// `local_address` column of `/proc/net/tcp` for an IPv4 socket.
fn proc_tcp_addr(addr: SocketAddr) -> Option<String> {
  let std::net::IpAddr::V4(ip) = addr.ip() else {
    return None;
  };
  let ip = u32::from(ip).swap_bytes();
  Some(format!("{ip:08X}:{:04X}", addr.port()))
}

/// Process that holds a socket fd for `inode`.
fn pid_for_socket(inode: u64) -> Option<u32> {
  let needle = format!("socket:[{inode}]");
  let entries = std::fs::read_dir("/proc").ok()?;
  for entry in entries.flatten() {
    let name = entry.file_name();
    let Some(text) = name.to_str() else {
      continue;
    };
    let Ok(pid) = text.parse::<u32>() else {
      continue;
    };
    let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
      continue;
    };
    for fd in fds.flatten() {
      if std::fs::read_link(fd.path()).is_ok_and(|target| target.to_string_lossy() == needle) {
        return Some(pid);
      }
    }
  }
  None
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn the_accepted_peer_cgroup_is_the_connectors() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let connector = tokio::spawn(async move {
      let _client = TcpStream::connect(addr).await.unwrap();
      let _ = release_rx.await;
    });
    let (stream, peer) = listener.accept().await.unwrap();
    let live = live_cgroup(&stream, peer);
    assert_eq!(live, cgroup_id_of_pid(std::process::id()));
    assert_ne!(live, 0);
    drop(release_tx);
    connector.await.unwrap();
  }
}
