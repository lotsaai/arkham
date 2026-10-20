//! TCP connection tracker (mirror of microsandbox tcp/connection.rs):
//! SYNs create smoltcp listener sockets; established connections relay
//! through mpsc channels to per-connection tokio tasks.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::IpListenEndpoint;
use tokio::sync::mpsc;

const TCP_RX_BUF: usize = 65536;
const TCP_TX_BUF: usize = 65536;
const MAX_TCP_CONNS: usize = 256;
const CHANNEL_CAP: usize = 32;
const RELAY_BUF: usize = 16384;

pub(crate) enum TaskMsg {
  Data(Vec<u8>),
  Fin,
  Abort,
}

struct TcpConn {
  src: SocketAddr,
  dst: SocketAddr,
  /// Socket → task sender; dropped (None) once the guest FIN is relayed.
  to_proxy: Option<mpsc::Sender<Vec<u8>>>,
  from_proxy: mpsc::Receiver<TaskMsg>,
  /// Channel ends for the task, taken when ESTABLISHED.
  channels: Option<(mpsc::Receiver<Vec<u8>>, mpsc::Sender<TaskMsg>)>,
  read_pending: Option<Vec<u8>>,
  write_pending: Option<(Vec<u8>, usize)>,
}

pub(crate) struct NewTcpConn {
  pub dst: SocketAddr,
  pub from_guest: mpsc::Receiver<Vec<u8>>,
  pub to_guest: mpsc::Sender<TaskMsg>,
}

#[derive(Default)]
pub(super) struct TcpTracker {
  conns: HashMap<SocketHandle, TcpConn>,
  keys: HashSet<(SocketAddr, SocketAddr)>,
}

impl TcpTracker {
  pub(super) fn has_socket_for(&self, src: &SocketAddr, dst: &SocketAddr) -> bool {
    self.keys.contains(&(*src, *dst))
  }

  /// Create a LISTEN socket on the exact dst ip+port. False at the cap.
  pub(super) fn create_socket(&mut self, src: SocketAddr, dst: SocketAddr, sockets: &mut SocketSet<'_>) -> bool {
    if self.conns.len() >= MAX_TCP_CONNS {
      return false;
    }
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF]);
    let mut socket = tcp::Socket::new(rx_buf, tx_buf);
    let endpoint = IpListenEndpoint {
      addr: Some(dst.ip().into()),
      port: dst.port(),
    };
    if socket.listen(endpoint).is_err() {
      return false;
    }
    let handle = sockets.add(socket);
    let (to_proxy_tx, from_guest_rx) = mpsc::channel(CHANNEL_CAP);
    let (to_guest_tx, from_proxy_rx) = mpsc::channel(CHANNEL_CAP);
    self.keys.insert((src, dst));
    self.conns.insert(
      handle,
      TcpConn {
        src,
        dst,
        to_proxy: Some(to_proxy_tx),
        from_proxy: from_proxy_rx,
        channels: Some((from_guest_rx, to_guest_tx)),
        read_pending: None,
        write_pending: None,
      },
    );
    true
  }

  /// Shuttle bytes between sockets and task channels.
  pub(super) fn relay(&mut self, sockets: &mut SocketSet<'_>) {
    let mut buf = [0u8; RELAY_BUF];
    for (&handle, conn) in &mut self.conns {
      if conn.channels.is_some() {
        continue;
      }
      let socket = sockets.get_mut::<tcp::Socket>(handle);
      if matches!(socket.state(), tcp::State::Closed) {
        continue; // left for cleanup
      }

      // Task → socket: abort wins, then stream bytes, then graceful exit.
      let mut abort = false;
      let mut fin = false;
      let mut task_gone = false;
      while conn.write_pending.is_none() && !abort && !fin && !task_gone {
        match conn.from_proxy.try_recv() {
          Ok(TaskMsg::Abort) => abort = true,
          Ok(TaskMsg::Fin) => fin = true,
          Ok(TaskMsg::Data(data)) => {
            if socket.can_send() {
              match socket.send_slice(&data) {
                Ok(written) if written < data.len() => {
                  conn.write_pending = Some((data, written));
                }
                Err(_) => conn.write_pending = Some((data, 0)),
                _ => {}
              }
            } else {
              conn.write_pending = Some((data, 0));
            }
          }
          Err(mpsc::error::TryRecvError::Empty) => break,
          Err(mpsc::error::TryRecvError::Disconnected) => task_gone = true,
        }
      }
      // Finish a partial write from an earlier pass.
      if let Some((data, offset)) = &mut conn.write_pending
        && socket.can_send()
        && let Ok(written) = socket.send_slice(&data[*offset..])
      {
        *offset += written;
        if *offset >= data.len() {
          conn.write_pending = None;
        }
      }
      if abort {
        // Best-effort drain: bytes already accepted must not vanish silently
        // behind the RST.
        while let Some((data, offset)) = &mut conn.write_pending {
          if !socket.can_send() {
            break;
          }
          let Ok(written) = socket.send_slice(&data[*offset..]) else {
            break;
          };
          *offset += written;
          if *offset >= data.len() {
            conn.write_pending = None;
          }
        }
        socket.abort();
        continue;
      }
      if (fin || task_gone) && conn.write_pending.is_none() {
        socket.close();
        continue;
      }

      // Socket → task, with natural backpressure (full channel leaves
      // bytes in the socket buffer, closing the guest window).
      if let Some(to_proxy) = &conn.to_proxy {
        if let Some(pending) = conn.read_pending.take()
          && let Err(err) = to_proxy.try_send(pending)
        {
          conn.read_pending = Some(err.into_inner());
        }
        if conn.read_pending.is_none() {
          while socket.can_recv() {
            match socket.recv_slice(&mut buf) {
              Ok(n) if n > 0 => {
                if let Err(err) = to_proxy.try_send(buf[..n].to_vec()) {
                  conn.read_pending = Some(err.into_inner());
                  break;
                }
              }
              _ => break,
            }
          }
        }
        // Guest FIN fully relayed: drop the sender so the task sees EOF.
        // Server → guest stays open until the task exits (above).
        if matches!(socket.state(), tcp::State::CloseWait) && conn.read_pending.is_none() && !socket.can_recv() {
          conn.to_proxy = None;
        }
      }
    }
  }

  pub(super) fn take_new(&mut self, sockets: &mut SocketSet<'_>) -> Vec<NewTcpConn> {
    let mut new = Vec::new();
    for (&handle, conn) in &mut self.conns {
      if conn.channels.is_none() {
        continue;
      }
      let socket = sockets.get::<tcp::Socket>(handle);
      if matches!(socket.state(), tcp::State::Established | tcp::State::CloseWait)
        && let Some((from_guest, to_guest)) = conn.channels.take()
      {
        new.push(NewTcpConn {
          dst: conn.dst,
          from_guest,
          to_guest,
        });
      }
    }
    new
  }

  /// Evict Closed sockets (`TimeWait` lingers in smoltcp by design).
  pub(super) fn cleanup(&mut self, sockets: &mut SocketSet<'_>) {
    let keys = &mut self.keys;
    self.conns.retain(|&handle, conn| {
      let socket = sockets.get::<tcp::Socket>(handle);
      if matches!(socket.state(), tcp::State::Closed) {
        keys.remove(&(conn.src, conn.dst));
        sockets.remove(handle);
        false
      } else {
        true
      }
    });
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::{IpAddr, Ipv4Addr};

  use smoltcp::iface::{Config, Interface};
  use smoltcp::time::Instant;
  use smoltcp::wire::{HardwareAddress, IpCidr};

  use crate::classify::{IP_PROTO_TCP, IpPacket, classify_packet};
  use crate::phy::TunPhy;
  use crate::udp::ipv4_checksum;

  const GUEST: [u8; 4] = [10, 98, 76, 2];
  const SERVER: [u8; 4] = [93, 184, 216, 34];

  fn sock(ip: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
  }

  /// Minimal TCP/IPv4 segment builder with valid checksums (smoltcp
  /// validates both on ingress).
  fn segment(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
      panic!("v4 only");
    };
    let total = 20 + 20 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    pkt[8] = 64;
    pkt[9] = IP_PROTO_TCP;
    pkt[12..16].copy_from_slice(&s.octets());
    pkt[16..20].copy_from_slice(&d.octets());
    let ip_csum = ipv4_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    pkt[20..22].copy_from_slice(&src.port().to_be_bytes());
    pkt[22..24].copy_from_slice(&dst.port().to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack.to_be_bytes());
    pkt[32] = 0x50; // data offset 5
    pkt[33] = flags;
    pkt[34..36].copy_from_slice(&64240u16.to_be_bytes()); // window
    pkt[40..].copy_from_slice(payload);
    let tcp_csum = tcp_checksum(s, d, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tcp_csum.to_be_bytes());
    pkt
  }

  fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for ip in [src, dst] {
      for pair in ip.octets().as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
      }
    }
    sum += u32::from(IP_PROTO_TCP);
    sum += u32::try_from(segment.len()).unwrap();
    let (chunks, remainder) = segment.as_chunks::<2>();
    for pair in chunks {
      sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let Some(&last) = remainder.first() {
      sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap()
  }
  struct ParsedTcp {
    flags: u8,
    seq: u32,
    ack: u32,
    payload: Vec<u8>,
  }

  fn parse_tcp(pkt: &[u8]) -> ParsedTcp {
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    let tcp = &pkt[ihl..];
    let off = ((tcp[12] >> 4) as usize) * 4;
    ParsedTcp {
      flags: tcp[13],
      seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
      ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
      payload: tcp[off..].to_vec(),
    }
  }

  fn test_iface() -> (TunPhy, Interface, SocketSet<'static>) {
    let mut phy = TunPhy::default();
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut phy, Instant::now());
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
      let _ = addrs.push(IpCidr::new(Ipv4Addr::new(10, 98, 76, 1).into(), 24));
    });
    iface.routes_mut().add_default_ipv4_route(Ipv4Addr::new(10, 98, 76, 1)).unwrap();
    (phy, iface, SocketSet::new(vec![]))
  }

  /// Full TCP lifecycle through the real smoltcp stack without a TUN
  /// device: handshake, spawn, both relay directions, FIN dance, cleanup.
  #[test]
  fn tcp_stack_handshake_relay_and_close() {
    let (mut phy, mut iface, mut sockets) = test_iface();
    let mut tracker = TcpTracker::default();
    let src = sock(GUEST, 45678);
    let dst = sock(SERVER, 80);

    // SYN → socket created, smoltcp answers SYN-ACK.
    let syn = segment(src, dst, 1000, 0, 0x02, b"");
    assert!(matches!(classify_packet(&syn), IpPacket::Tcp { syn: true, .. }));
    assert!(tracker.create_socket(src, dst, &mut sockets));
    phy.rx.push_back(syn);
    iface.poll(Instant::now(), &mut phy, &mut sockets);
    let synack = parse_tcp(&phy.tx.pop_front().expect("SYN-ACK"));
    assert_eq!(synack.flags & 0x12, 0x12);
    assert_eq!(synack.ack, 1001);
    let server_seq = synack.seq;

    // ACK → established → spawn.
    phy.rx.push_back(segment(src, dst, 1001, server_seq + 1, 0x10, b""));
    iface.poll(Instant::now(), &mut phy, &mut sockets);
    let mut news = tracker.take_new(&mut sockets);
    assert_eq!(news.len(), 1);
    let mut conn = news.pop().unwrap();
    assert_eq!(conn.dst, dst);

    // Guest data → relay → task channel.
    phy.rx.push_back(segment(src, dst, 1001, server_seq + 1, 0x10, b"hello"));
    iface.poll(Instant::now(), &mut phy, &mut sockets);
    tracker.relay(&mut sockets);
    assert_eq!(conn.from_guest.try_recv().unwrap(), b"hello");

    // Task data → relay → guest segment.
    conn.to_guest.try_send(TaskMsg::Data(b"world".to_vec())).unwrap();
    tracker.relay(&mut sockets);
    iface.poll(Instant::now(), &mut phy, &mut sockets);
    let mut saw_world = false;
    while let Some(pkt) = phy.tx.pop_front() {
      if parse_tcp(&pkt).payload == b"world" {
        saw_world = true;
      }
    }
    assert!(saw_world, "guest must receive the task bytes");

    // Guest FIN → task sees EOF (channel disconnects).
    phy.rx.push_back(segment(src, dst, 1006, server_seq + 6, 0x11, b""));
    iface.poll(Instant::now(), &mut phy, &mut sockets);
    tracker.relay(&mut sockets);
    conn.from_guest.try_recv().unwrap_err();

    // Task exit → FIN to guest.
    drop(conn.to_guest);
    tracker.relay(&mut sockets);
    iface.poll(Instant::now(), &mut phy, &mut sockets);
    let mut saw_fin = false;
    while let Some(pkt) = phy.tx.pop_front() {
      if parse_tcp(&pkt).flags & 0x01 != 0 {
        saw_fin = true;
      }
    }
    assert!(saw_fin, "guest must see our FIN");

    // Abort path → Closed → cleanup evicts socket + key.
    let handle = *tracker.conns.keys().next().unwrap();
    sockets.get_mut::<tcp::Socket>(handle).abort();
    tracker.cleanup(&mut sockets);
    assert!(tracker.conns.is_empty());
    assert!(tracker.keys.is_empty());
    assert_eq!(sockets.iter().count(), 0);
  }

  #[test]
  fn untracked_rst_and_cap_behavior() {
    let (mut phy, mut iface, mut sockets) = test_iface();
    let mut tracker = TcpTracker::default();
    // Non-SYN to unknown tuple: feed → smoltcp RSTs.
    let pkt = segment(sock(GUEST, 1111), sock(SERVER, 9999), 1, 0, 0x10, b"");
    phy.rx.push_back(pkt);
    iface.poll(Instant::now(), &mut phy, &mut sockets);
    let rst = parse_tcp(&phy.tx.pop_front().expect("RST"));
    assert_ne!(rst.flags & 0x04, 0);
    // Cap: 256 sockets max.
    for i in 0..300 {
      tracker.create_socket(sock(GUEST, 20000 + i), sock(SERVER, 80), &mut sockets);
    }
    assert_eq!(tracker.conns.len(), 256);
  }
}
