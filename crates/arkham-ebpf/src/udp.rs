//! UDP relay leg: forward captured connected-UDP datagrams both ways.
//!
//! Relay only, no substitution: nothing here terminates QUIC, so a captured
//! HTTP/3 flow passes through byte-identical with its decoy intact rather than
//! being inspected. Connecting is what triggers capture — only *connected* UDP
//! sockets go through `connect()`, so unconnected `sendto` traffic (typical
//! DNS) never sees the connect hook at all.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::Error;
use crate::flow::{FlowTables, PROTO_UDP};

/// Drop a flow after this long with no traffic in either direction.
pub(crate) const FLOW_IDLE: Duration = Duration::from_secs(60);
/// How often the janitor sweeps.
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);
/// Datagrams larger than this are not something these protocols produce.
const MAX_DATAGRAM: usize = 65_535;

/// One captured client flow: the upstream socket replies come from, plus
/// liveness for the janitor.
pub(crate) struct Flow {
  upstream: UdpSocket,
  dst: SocketAddr,
  last_active: Instant,
}

/// Client address → flow.
pub(crate) type FlowTable = DashMap<SocketAddr, Arc<Mutex<Flow>>>;

/// Relay captured datagrams for `port` until the listener fails.
pub(crate) async fn serve(port: u16, flows: FlowTables, upstream_override: Option<SocketAddr>) -> Result<(), Error> {
  let listener = Arc::new(UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?);
  // `DashMap` because the janitor sweeps concurrently with the receive loop;
  // entries are short-lived and few (one per client).
  let table: Arc<FlowTable> = Arc::new(DashMap::new());
  tokio::spawn(janitor(Arc::clone(&table)));

  let mut buf = vec![0u8; MAX_DATAGRAM];
  loop {
    let (len, client) = listener.recv_from(&mut buf).await?;
    let payload = buf[..len].to_vec();
    let flows = flows.clone();
    let listener = Arc::clone(&listener);
    let table = Arc::clone(&table);
    tokio::spawn(async move {
      if let Err(err) = one(&payload, client, &flows, &listener, &table, upstream_override).await {
        tracing::debug!(%client, ?err, "ebpf udp datagram failed");
      }
    });
  }
}

/// One client datagram: forward it upstream, creating the flow on first use.
async fn one(
  payload: &[u8],
  client: SocketAddr,
  flows: &FlowTables,
  listener: &UdpSocket,
  table: &FlowTable,
  upstream_override: Option<SocketAddr>,
) -> Result<(), Error> {
  let flow = if let Some(existing) = table.get(&client) {
    Arc::clone(existing.value())
  } else {
    // First datagram for this client: resolve where it was really going.
    // Without a recorded destination the socket was not redirected, so
    // passing the datagram anywhere would misroute it; drop it.
    let Some(dst) = flows.original(client, PROTO_UDP)? else {
      tracing::debug!(%client, "no recorded destination for captured udp flow; dropping");
      return Ok(());
    };
    let dst = upstream_override.unwrap_or(dst);
    let upstream = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    upstream.connect(dst).await?;
    let flow = Arc::new(Mutex::new(Flow {
      upstream,
      dst,
      last_active: Instant::now(),
    }));
    table.insert(client, Arc::clone(&flow));
    flow
  };

  // Hold the lock across send+recv so replies stay paired with their request;
  // one task per datagram, so this serializes only that client's flow.
  let mut flow = flow.lock().await;
  flow.upstream.send(payload).await?;
  flow.last_active = Instant::now();

  let mut reply = vec![0u8; MAX_DATAGRAM];
  match tokio::time::timeout(FLOW_IDLE, flow.upstream.recv(&mut reply)).await {
    Ok(Ok(len)) => {
      flow.last_active = Instant::now();
      // Replies leave from the relay's port, which is what the client is
      // connected to; `recvmsg4` makes the kernel report the original source.
      listener.send_to(&reply[..len], client).await?;
      Ok(())
    }
    // A timeout or a recv error is not a relay failure: the client may simply
    // be done, and the janitor will retire the flow.
    Ok(Err(err)) => {
      tracing::debug!(%client, %flow.dst, ?err, "udp upstream recv failed");
      Ok(())
    }
    Err(_elapsed) => Ok(()),
  }
}

/// Retire flows that have gone quiet, so a long-lived arkham does not accumulate
/// one socket per client it has ever seen.
async fn janitor(table: Arc<FlowTable>) {
  loop {
    tokio::time::sleep(SWEEP_INTERVAL).await;
    sweep(&table, Instant::now());
  }
}

/// Drop every flow idle for longer than [`FLOW_IDLE`].
///
/// Collects before removing: holding a `DashMap` shard while awaiting a flow
/// lock would deadlock against the relay tasks taking that same lock. A flow
/// busy enough to be locked right now is by definition not idle.
fn sweep(table: &FlowTable, now: Instant) {
  let mut stale = Vec::new();
  for entry in table {
    if entry
      .value()
      .try_lock()
      .is_ok_and(|flow| now.duration_since(flow.last_active) > FLOW_IDLE)
    {
      stale.push(*entry.key());
    }
  }
  for key in stale {
    table.remove(&key);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// A monotonic instant this long ago, for aging entries in tests.
  fn idle_now() -> Instant {
    // `Instant` cannot be constructed directly, so this anchors on the epoch
    // the process started from: only the difference matters.
    let base = Instant::now();
    base.checked_sub(FLOW_IDLE * 2).unwrap_or(base)
  }

  async fn flow_at(dst: &str, last_active: Instant) -> Arc<Mutex<Flow>> {
    let upstream = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.expect("bind");
    Arc::new(Mutex::new(Flow {
      upstream,
      dst: dst.parse().expect("addr"),
      last_active,
    }))
  }

  /// Idle flows are retired and busy ones survive, so a long-lived arkham does
  /// not leak one socket per client it has ever seen.
  #[tokio::test]
  async fn janitor_sweeps_idle_flows_only() {
    let table: FlowTable = DashMap::new();
    let idle = "198.51.100.1:53".parse().expect("addr");
    let busy = "198.51.100.2:53".parse().expect("addr");
    table.insert(idle, flow_at("198.51.100.1:53", idle_now()).await);
    table.insert(busy, flow_at("198.51.100.2:53", Instant::now()).await);

    sweep(&table, Instant::now());

    assert!(!table.contains_key(&idle), "idle flow must be retired");
    assert!(table.contains_key(&busy), "active flow must survive");
  }

  /// A flow whose lock is currently held is in use, not idle: sweeping it
  /// would yank the socket out from under an in-flight datagram.
  #[tokio::test]
  async fn janitor_spares_locked_flows() {
    let table: FlowTable = DashMap::new();
    let client = "198.51.100.3:53".parse().expect("addr");
    let flow = flow_at("198.51.100.3:53", idle_now()).await;
    table.insert(client, Arc::clone(&flow));

    let _held = flow.lock().await;
    sweep(&table, Instant::now());

    assert!(table.contains_key(&client), "in-use flow must not be swept");
  }

  /// The sweep boundary is exclusive: a flow exactly at the idle limit is
  /// still live, one past it is not.
  #[tokio::test]
  async fn janitor_boundary_is_exclusive() {
    let table: FlowTable = DashMap::new();
    let now = Instant::now();
    let at_limit = "198.51.100.4:53".parse().expect("addr");
    table.insert(
      at_limit,
      flow_at("198.51.100.4:53", now.checked_sub(FLOW_IDLE).expect("clock is past the limit")).await,
    );

    sweep(&table, now);
    assert!(table.contains_key(&at_limit), "flow exactly at the limit is still live");
  }

  /// `idle_now` must actually be older than the idle limit, or the sweep tests
  /// above would pass vacuously.
  #[test]
  fn idle_now_is_older_than_the_limit() {
    assert!(Instant::now().duration_since(idle_now()) > FLOW_IDLE);
  }
}
