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

use aya::maps::{MapData, RingBuf};
use dashmap::DashMap;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::Error;
use crate::flow::{CapturedFlow, PROTO_UDP};
use crate::{FlowKey, OrigDst};

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

/// Client address and socket cookie → flow.
pub(crate) type FlowTable = DashMap<(SocketAddr, u64), Arc<Mutex<Flow>>>;

#[repr(C)]
#[derive(Clone, Copy)]
struct UdpPacketHeader {
  cookie: u64,
  orig: OrigDst,
  key: FlowKey,
  packet_len: u32,
  gso_size: u32,
  _pad: [u8; 4],
}

const _: () = {
  assert!(std::mem::size_of::<UdpPacketHeader>() == 80);
  assert!(std::mem::offset_of!(UdpPacketHeader, orig) == 8);
  assert!(std::mem::offset_of!(UdpPacketHeader, key) == 48);
  assert!(std::mem::offset_of!(UdpPacketHeader, packet_len) == 68);
  assert!(std::mem::offset_of!(UdpPacketHeader, gso_size) == 72);
  assert!(std::mem::offset_of!(UdpPacketHeader, _pad) == 76);
};

fn decode_packet(record: &[u8]) -> Option<(UdpPacketHeader, &[u8])> {
  let size = std::mem::size_of::<UdpPacketHeader>();
  let bytes = record.get(..size)?;
  // SAFETY: the header contains only integer fields, and the slice has its full size.
  let header = unsafe { bytes.as_ptr().cast::<UdpPacketHeader>().read_unaligned() };
  if header.orig.proto != PROTO_UDP || !matches!(header.orig.family, 2 | 10) || header.key.family != u16::from(header.orig.family) {
    return None;
  }
  let packet = record.get(size..size.checked_add(header.packet_len as usize)?)?;
  let parsed = etherparse::SlicedPacket::from_ip(packet).ok()?;
  let etherparse::TransportSlice::Udp(udp) = parsed.transport.as_ref()? else {
    return None;
  };
  let payload = if header.gso_size == 0 {
    udp.payload()
  } else {
    parsed.ip_payload()?.payload.get(8..)?
  };
  Some((header, payload))
}

async fn drain(listener: Arc<UdpSocket>) -> Result<(), Error> {
  let mut buf = [0; 1];
  loop {
    listener.recv_from(&mut buf).await?;
  }
}

pub(crate) async fn serve(
  listener4: UdpSocket,
  listener6: Option<UdpSocket>,
  mut ring: AsyncFd<RingBuf<MapData>>,
  upstream_override: Option<SocketAddr>,
) -> Result<(), Error> {
  let listener4 = Arc::new(listener4);
  let listener6 = listener6.map(Arc::new);
  let table: Arc<FlowTable> = Arc::new(DashMap::new());
  let mut interval = tokio::time::interval(SWEEP_INTERVAL);
  let mut tasks = tokio::task::JoinSet::new();
  let drain4 = drain(Arc::clone(&listener4));
  let drain6 = async {
    match &listener6 {
      Some(listener) => drain(Arc::clone(listener)).await,
      None => std::future::pending().await,
    }
  };
  tokio::pin!(drain4, drain6);
  loop {
    tokio::select! {
      result = &mut drain4 => return result,
      result = &mut drain6 => return result,
      result = ring.readable_mut() => {
        let mut guard = result?;
        while let Some(item) = guard.get_inner_mut().next() {
          let Some((header, payload)) = decode_packet(&item) else {
            tracing::warn!("invalid captured udp packet");
            continue;
          };
          let peer = OrigDst {
            ip: header.key.ip,
            port: u32::from(header.key.port.to_be()),
            proto: PROTO_UDP,
            family: header.orig.family,
            _pad: [0; 10],
            cgroup_id: 0,
          }.socket_addr();
          let listener = if peer.is_ipv4() {
            Arc::clone(&listener4)
          } else if let Some(listener) = &listener6 {
            Arc::clone(listener)
          } else {
            continue;
          };
          let segment = if header.gso_size == 0 { payload.len().max(1) } else { header.gso_size as usize };
          let payload = payload.to_vec();
          let table = Arc::clone(&table);
          tasks.spawn(async move {
            let captured = CapturedFlow { cookie: header.cookie, destination: header.orig.socket_addr(), cgroup_id: header.orig.cgroup_id };
            if let Err(err) = one(&payload, segment, peer, captured, &listener, &table, upstream_override).await {
              tracing::debug!(%peer, ?err, "ebpf udp datagram failed");
            }
          });
        }
        guard.clear_ready();
      }
      _ = tasks.join_next(), if !tasks.is_empty() => {}
      _ = interval.tick() => sweep(&table, Instant::now()),
    }
  }
}

/// One client datagram: forward it upstream, creating the flow on first use.
async fn one(
  payload: &[u8],
  segment: usize,
  client: SocketAddr,
  captured: CapturedFlow,
  listener: &UdpSocket,
  table: &FlowTable,
  upstream_override: Option<SocketAddr>,
) -> Result<(), Error> {
  let key = (client, captured.cookie);
  let flow = if let Some(existing) = table.get(&key) {
    Arc::clone(existing.value())
  } else {
    let dst = upstream_override.unwrap_or(captured.destination);
    let bind = if dst.is_ipv4() {
      std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
      std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    let upstream = UdpSocket::bind((bind, 0)).await?;
    upstream.connect(dst).await?;
    let flow = Arc::new(Mutex::new(Flow {
      upstream,
      dst,
      last_active: Instant::now(),
    }));
    Arc::clone(table.entry(key).or_insert(flow).value())
  };

  // Hold the lock across send+recv so replies stay paired with their request;
  // one task per datagram, so this serializes only that client's flow.
  let mut flow = flow.lock().await;
  if payload.is_empty() {
    flow.upstream.send(payload).await?;
  } else {
    for chunk in payload.chunks(segment) {
      flow.upstream.send(chunk).await?;
    }
  }
  flow.last_active = Instant::now();

  let mut reply = vec![0u8; MAX_DATAGRAM];
  for _ in 0..payload.len().div_ceil(segment).max(1) {
    match tokio::time::timeout(FLOW_IDLE, flow.upstream.recv(&mut reply)).await {
      Ok(Ok(len)) => {
        flow.last_active = Instant::now();
        let bytes = reply
          .get(..len)
          .ok_or_else(|| std::io::Error::other("udp reply exceeds receive buffer"))?;
        listener.send_to(bytes, client).await?;
      }
      Ok(Err(err)) => {
        tracing::debug!(%client, %flow.dst, ?err, "udp upstream recv failed");
        break;
      }
      Err(_elapsed) => break,
    }
  }
  Ok(())
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

  fn idle_now() -> Instant {
    Instant::now()
      .checked_sub(FLOW_IDLE * 2)
      .expect("clock is past twice the idle limit")
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
    let idle = ("198.51.100.1:53".parse().expect("addr"), 1);
    let busy = (idle.0, 2);
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
    let client = ("198.51.100.3:53".parse().expect("addr"), 3);
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
    let at_limit = ("198.51.100.4:53".parse().expect("addr"), 4);
    table.insert(
      at_limit,
      flow_at("198.51.100.4:53", now.checked_sub(FLOW_IDLE).expect("clock is past the limit")).await,
    );

    sweep(&table, now);
    assert!(table.contains_key(&at_limit), "flow exactly at the limit is still live");
  }

  #[test]
  fn idle_now_is_older_than_the_limit() {
    assert!(Instant::now().duration_since(idle_now()) > FLOW_IDLE);
  }
}
