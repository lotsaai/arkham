//! `arkham fwd`: exposure sidecar of the generated compose stack.
//!
//! The agent service shares arkham's network namespace, so a loopback-bound
//! listener inside the agent is invisible to the host — only the shared
//! namespace's own wildcard-bound listeners are directly reachable at the
//! compose bridge IP. A container cannot publish ports for a netns it merely
//! joins, and the publishings that exist belong to the arkham service and are
//! fixed at create, so ad-hoc dev-server ports need a forwarder.
//!
//! This sidecar is that forwarder, and a sidecar is all it is: the generated
//! stack runs `arkham fwd` with `network_mode: "service:arkham"` (the shared
//! netns, whose every listener shows up in `/proc/net/tcp`) and
//! `pid: "service:agent"` (only the agent's processes are visible, so only
//! they can ever be attributed a listener). Every poll it:
//!
//! 1. collects the LISTEN rows of `/proc/net/tcp` and `/proc/net/tcp6` whose
//!    local address is loopback;
//! 2. attributes each socket inode through `/proc/<pid>/fd`, which covers
//!    agent-side processes only because of the PID namespace — arkham's
//!    capture and explicit-proxy listeners and docker's embedded DNS are
//!    structurally unattributable here and are never forwarded, without any
//!    port having to be named;
//! 3. forwards the survivors on the netns's own bridge address — the one
//!    docker publishes and the host already reaches — by holding
//!    `<bridge-ip>:<port>` and relaying raw bytes to the loopback address the
//!    row names. A specific bind is what lets the forwarder coexist with the
//!    agent's loopback listener on the same port: two listeners on different
//!    specific addresses share a port freely, while a wildcard bind would
//!    collide with the agent's own socket no matter what options are set.
//!    Payloads are never inspected, and forwarders are reaped when the
//!    backing listener disappears.
//!
//! Two listeners on one port bound to different loopback addresses collide —
//! the shared netns has one bridge IP to expose — and are logged and skipped
//! rather than remapped.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use eyre::WrapErr as _;
use tokio::io::copy_bidirectional;
use tokio::sync::Mutex;

const POLL: Duration = Duration::from_millis(500);

/// The netns's own addresses the sidecar exposes on: the docker bridge IP
/// per address family. v4 is required — the stack's publishings and the
/// bridge route the host uses are v4 — and v6 is taken when the netns has a
/// global address at all.
struct Binds {
  /// First non-loopback IPv4 address of the netns.
  v4: IpAddr,
  /// First non-loopback, non-link-local IPv6 address, when there is one.
  v6: Option<IpAddr>,
}

impl Binds {
  /// The address to expose on for a listener of `upstream`'s family.
  fn for_family(&self, family: IpAddr) -> Option<IpAddr> {
    match family {
      IpAddr::V4(_) => Some(self.v4),
      IpAddr::V6(_) => self.v6,
    }
  }
}

/// One loopback LISTEN row of the shared namespace.
#[derive(Debug)]
struct Row {
  addr: IpAddr,
  port: u16,
  /// Socket inode, the key attribution resolves through `/proc/<pid>/fd`.
  inode: u64,
}

/// One forwarder: a specific listener on the netns's bridge address plus the
/// loopback address behind it.
struct Forwarder {
  /// Where relays connect; a changed address re-creates the forwarder.
  upstream: SocketAddr,
  /// The accept loop, holding the listener. Dropped forwarders abort it,
  /// which drops the listener.
  acceptor: tokio::task::JoinHandle<()>,
  /// Active relays, aborted on drop: a backing listener that vanished kills
  /// every relay anyway, and aborting keeps the reaping immediate.
  conns: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Drop for Forwarder {
  fn drop(&mut self) {
    self.acceptor.abort();
    if let Ok(mut conns) = self.conns.try_lock() {
      for conn in conns.drain(..) {
        conn.abort();
      }
    }
  }
}

/// Run the sidecar forever: poll the LISTEN tables, reconcile, sleep.
///
/// # Errors
///
/// Returns an error when the LISTEN tables cannot be read at all — the
/// sidecar cannot decide anything without them — or when the netns carries no
/// non-loopback IPv4 address to expose on. Per-listener failures (an
/// unattributable row, a bind conflict, a family the netns has no address
/// for) are logged and skipped instead.
pub(crate) async fn run() -> eyre::Result<()> {
  let Some((v4, v6)) = bridge_addresses()? else {
    eyre::bail!("no non-loopback IPv4 address in this netns to expose on");
  };
  let binds = Binds { v4, v6 };
  tracing::info!(
    v4 = %binds.v4,
    v6 = ?binds.v6,
    "forwarding agent-owned loopback listeners on the netns's own addresses"
  );
  let mut forwarders: BTreeMap<u16, Forwarder> = BTreeMap::new();
  loop {
    reconcile(&mut forwarders, &binds, desired_listeners()?).await;
    tokio::time::sleep(POLL).await;
  }
}

/// The loopback LISTEN rows of the shared netns, attributed to agent-side
/// processes, keyed by port. Two loopback rows sharing a port collide — the
/// shared netns has one bridge IP to expose — and are logged and skipped.
///
/// # Errors
///
/// Propagates unreadable `/proc/net/tcp*` tables.
fn desired_listeners() -> eyre::Result<BTreeMap<u16, IpAddr>> {
  let mut rows = parse_table("/proc/net/tcp")?;
  rows.extend(parse_table("/proc/net/tcp6")?);
  let mut grouped: BTreeMap<u16, Vec<&Row>> = BTreeMap::new();
  for row in &rows {
    grouped.entry(row.port).or_default().push(row);
  }
  let mut desired = BTreeMap::new();
  for (port, group) in grouped {
    let addresses: std::collections::BTreeSet<IpAddr> = group.iter().map(|row| row.addr).collect();
    if addresses.len() > 1 {
      tracing::warn!(
        port,
        ?addresses,
        "two listeners share this port on different loopback addresses; the shared netns has one bridge IP to expose, so neither is forwarded"
      );
      continue;
    }
    let Some(row) = group.first() else {
      continue;
    };
    if !attributable(row.inode) {
      tracing::trace!(port, inode = row.inode, "loopback listener is not agent-owned; not forwarded");
      continue;
    }
    desired.insert(port, row.addr);
  }
  Ok(desired)
}

/// Stop every forwarder whose backing listener is gone or moved, and start
/// one for every newly attributable port.
async fn reconcile(forwarders: &mut BTreeMap<u16, Forwarder>, binds: &Binds, desired: BTreeMap<u16, IpAddr>) {
  let stale: Vec<u16> = forwarders
    .iter()
    .filter_map(|(port, forwarder)| {
      let stale = desired
        .get(port)
        .is_none_or(|addr| SocketAddr::new(*addr, *port) != forwarder.upstream);
      stale.then_some(*port)
    })
    .collect();
  for port in stale {
    if let Some(forwarder) = forwarders.remove(&port) {
      tracing::info!(port, upstream = %forwarder.upstream, "backing listener gone or moved; reaping forwarder");
      drop(forwarder);
    }
  }
  for (port, addr) in desired {
    if forwarders.contains_key(&port) {
      continue;
    }
    let upstream = SocketAddr::new(addr, port);
    let Some(bind) = binds.for_family(addr) else {
      tracing::debug!(port, %upstream, "this netns has no address of that family to expose on; port not forwarded");
      continue;
    };
    match start(bind, upstream).await {
      Ok(forwarder) => {
        tracing::info!(port, %bind, %upstream, "forwarding agent-owned loopback listener");
        forwarders.insert(port, forwarder);
      }
      // Something already holds this port on the bridge address — a wildcard
      // listener, which is directly reachable, or the same-port ceiling. The
      // port is skipped, and a transient conflict (a listener still starting
      // up) is retried on the next poll.
      Err(err) => tracing::debug!(port, %upstream, %err, "cannot hold the listener; port not forwarded"),
    }
  }
}

/// Bind `bind` and relay raw bytes to `upstream` for every accepted
/// connection, until dropped.
///
/// # Errors
///
/// Propagates the bind failure.
async fn start(bind: IpAddr, upstream: SocketAddr) -> eyre::Result<Forwarder> {
  let listener = tokio::net::TcpListener::bind(SocketAddr::new(bind, upstream.port())).await?;
  let conns = Arc::new(Mutex::new(Vec::<tokio::task::JoinHandle<()>>::new()));
  let shared = Arc::clone(&conns);
  let acceptor = tokio::spawn(async move {
    loop {
      let Ok((mut client, _)) = listener.accept().await else {
        return;
      };
      let shared = Arc::clone(&shared);
      let conn = tokio::spawn(async move {
        if let Ok(mut server) = tokio::net::TcpStream::connect(upstream).await {
          let _ = copy_bidirectional(&mut client, &mut server).await;
        }
      });
      // Finished relays are dead weight; prune before pushing so the list
      // holds only what a reap still has to close.
      let mut conns = shared.lock().await;
      conns.retain(|conn| !conn.is_finished());
      conns.push(conn);
    }
  });
  Ok(Forwarder { upstream, acceptor, conns })
}

/// The netns's own bridge addresses: the first non-loopback IPv4 address and
/// the first non-loopback, non-link-local IPv6 address of any live interface,
/// in interface order — in the shared netns that is the compose bridge's
/// `eth0`, the address docker publishes to and the host reaches directly.
///
/// # Errors
///
/// Propagates the `getifaddrs` failure; the `Ok` tuple carries what the netns
/// has, and an absent v4 means there is nothing to expose on.
fn bridge_addresses() -> eyre::Result<Option<(IpAddr, Option<IpAddr>)>> {
  let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
  // SAFETY: `getifaddrs` writes the list head and nothing else the caller
  // owns; the list is freed by `IfAddrs::drop` before this function returns.
  if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
    return Err(std::io::Error::last_os_error()).wrap_err("getifaddrs");
  }
  let list = IfAddrs(head);
  let mut v4 = None;
  let mut v6 = None;
  let mut cursor = list.0;
  loop {
    // SAFETY: `cursor` is null or points at a node of the list `list` owns.
    let entry = unsafe { cursor.as_ref() };
    let Some(entry) = entry else {
      break;
    };
    cursor = entry.ifa_next;
    // SAFETY: `ifa_addr` is null or points at an address that lives as long
    // as the entry does.
    let raw = unsafe { entry.ifa_addr.as_ref() };
    let Some(raw) = raw else {
      continue;
    };
    match i32::from(raw.sa_family) {
      libc::AF_INET if v4.is_none() => {
        // SAFETY: an AF_INET entry stores a `sockaddr_in` at `ifa_addr`.
        let sa = unsafe { entry.ifa_addr.cast::<libc::sockaddr_in>().as_ref() };
        let Some(sa) = sa else {
          continue;
        };
        let addr = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
        if !addr.is_loopback() && !addr.is_link_local() {
          v4 = Some(addr.into());
        }
      }
      libc::AF_INET6 if v6.is_none() => {
        // SAFETY: an AF_INET6 entry stores a `sockaddr_in6` at `ifa_addr`.
        let sa = unsafe { entry.ifa_addr.cast::<libc::sockaddr_in6>().as_ref() };
        let Some(sa) = sa else {
          continue;
        };
        // The in6_addr is an opaque byte array, so the octets are the octets.
        let bytes = sa.sin6_addr.s6_addr;
        let addr = Ipv6Addr::new(
          u16::from_be_bytes([bytes[0], bytes[1]]),
          u16::from_be_bytes([bytes[2], bytes[3]]),
          u16::from_be_bytes([bytes[4], bytes[5]]),
          u16::from_be_bytes([bytes[6], bytes[7]]),
          u16::from_be_bytes([bytes[8], bytes[9]]),
          u16::from_be_bytes([bytes[10], bytes[11]]),
          u16::from_be_bytes([bytes[12], bytes[13]]),
          u16::from_be_bytes([bytes[14], bytes[15]]),
        );
        if !addr.is_loopback() && !is_v6_link_local(&addr) {
          v6 = Some(addr.into());
        }
      }
      _ => {}
    }
  }
  Ok(v4.map(|v4| (v4, v6)))
}

/// `getifaddrs`'s list, freed on drop.
struct IfAddrs(*mut libc::ifaddrs);

impl Drop for IfAddrs {
  fn drop(&mut self) {
    // SAFETY: the pointer came from `getifaddrs` and is still alive.
    unsafe { libc::freeifaddrs(self.0) };
  }
}

/// `fe80::/10`, the only IPv6 scope a forwarding target must not be.
fn is_v6_link_local(addr: &Ipv6Addr) -> bool {
  let [first, second, ..] = addr.octets();
  first == 0xFE && second & 0xC0 == 0x80
}

/// The LISTEN rows of one table whose local address is loopback.
///
/// # Errors
///
/// Propagates the read failure.
fn parse_table(path: &str) -> eyre::Result<Vec<Row>> {
  let text = std::fs::read_to_string(path).wrap_err_with(|| format!("read {path}"))?;
  let mut rows = Vec::new();
  for line in text.lines().skip(1) {
    let fields: Vec<&str> = line.split_whitespace().collect();
    // `sl local rem st tx:rx tr:when retrnsmt uid timeout inode`: the inode
    // is the tenth column and `0A` is `TCP_LISTEN`.
    let (Some(&"0A"), Some(local), Some(&inode_hex)) = (fields.get(3), fields.get(1), fields.get(9)) else {
      continue;
    };
    let Some((addr_hex, port_hex)) = local.split_once(':') else {
      continue;
    };
    let Ok(port) = u16::from_str_radix(port_hex, 16) else {
      continue;
    };
    // The kernel prints each 32-bit group of the address as the native
    // integer read from memory, so every group is byte-reversed from the
    // numeric address — the same encoding `arkham-ebpf`'s `decode_addr`
    // spells out.
    let addr = match addr_hex.len() {
      8 => {
        let Ok(raw) = u32::from_str_radix(addr_hex, 16) else {
          continue;
        };
        IpAddr::V4(Ipv4Addr::from(u32::from_be(raw)))
      }
      32 => {
        let mut octets = [0u8; 16];
        let mut decoded = true;
        for (slot, at) in octets.as_chunks_mut::<4>().0.iter_mut().zip((0..32).step_by(8)) {
          if let Ok(raw) = u32::from_str_radix(&addr_hex[at..at + 8], 16) {
            slot.copy_from_slice(&u32::from_be(raw).to_be_bytes());
          } else {
            decoded = false;
            break;
          }
        }
        if !decoded {
          continue;
        }
        IpAddr::V6(Ipv6Addr::from(octets))
      }
      _ => continue,
    };
    if !addr.is_loopback() {
      continue;
    }
    let Ok(inode) = inode_hex.parse::<u64>() else {
      continue;
    };
    rows.push(Row { addr, port, inode });
  }
  Ok(rows)
}

/// Whether the agent's processes — the only ones this sidecar can see, being
/// inside their PID namespace — hold the socket `inode`.
///
/// Anything unattributable is never forwarded: arkham's capture and
/// explicit-proxy listeners and docker's embedded DNS are held by processes
/// no `/proc/<pid>/fd` scan can reach from here.
fn attributable(inode: u64) -> bool {
  let Ok(processes) = std::fs::read_dir("/proc") else {
    return false;
  };
  for process in processes.flatten() {
    let Ok(fds) = std::fs::read_dir(process.path().join("fd")) else {
      continue; // unreadable or vanished; the pid was never ours to judge
    };
    for fd in fds.flatten() {
      let Ok(target) = std::fs::read_link(fd.path()) else {
        continue;
      };
      if socket_inode(&target.to_string_lossy()) == Some(inode) {
        return true;
      }
    }
  }
  false
}

/// The inode of a `socket:[<inode>]` fd link; `None` for anything else.
fn socket_inode(target: &str) -> Option<u64> {
  target.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

#[cfg(test)]
mod tests {
  use super::*;

  /// The LISTEN rows of a fixed snapshot decode to the listeners `ss`
  /// reports: one loopback v4 row with its kernel-side hex encoding and
  /// inode, one wildcard row that must not survive the loopback filter, and
  /// one non-LISTEN row that must not survive the state filter.
  #[test]
  fn the_proc_table_decodes_listen_rows_with_kernel_encodings() {
    let dir = tempfile::tempdir().unwrap();
    let table = dir.path().join("tcp");
    std::fs::write(
      &table,
      concat!(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        "   0: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000 65534        0 36755 1 x 100 0 0 10 0\n",
        "   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 36756 1 x 100 0 0 10 0\n",
        "   2: 0100007F:1539 3600007F:0035 01 00000000:00000000 00:00000000 00000000     0        0 36757 1 x 100 0 0 10 0\n",
      ),
    )
    .unwrap();
    let rows = parse_table(table.to_str().unwrap()).unwrap();
    assert_eq!(rows.len(), 1, "only the loopback LISTEN row survives: {rows:?}");
    assert_eq!(rows[0].addr.to_string(), "127.0.0.1");
    assert_eq!(rows[0].port, 5432);
    assert_eq!(rows[0].inode, 36755);
  }

  /// A v6 loopback row decodes through the same native-integer encoding as
  /// the v4 one: the kernel prints each 32-bit group swapped, so `::1` ends
  /// in `01000000`.
  #[test]
  fn the_v6_table_decodes_the_loopback_address() {
    let dir = tempfile::tempdir().unwrap();
    let table = dir.path().join("tcp6");
    std::fs::write(
      &table,
      concat!(
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        "   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 65534        0 38465 1 x 100 0 0 10 0\n",
        "   1: 00000000000000000000000000000000:115C 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 38466 1 x 100 0 0 10 0\n",
      ),
    )
    .unwrap();
    let rows = parse_table(table.to_str().unwrap()).unwrap();
    assert_eq!(rows.len(), 1, "the wildcard `::` row is not loopback: {rows:?}");
    assert_eq!(rows[0].addr.to_string(), "::1");
    assert_eq!(rows[0].port, 631);
    assert_eq!(rows[0].inode, 38465);
  }

  /// An fd link names its socket; anything else is not a socket row.
  #[test]
  fn socket_fd_links_yield_their_inode() {
    assert_eq!(socket_inode("socket:[36755]"), Some(36_755));
    assert_eq!(socket_inode("anon_inode:[eventfd]"), None);
    assert_eq!(socket_inode("socket:[x]"), None);
    assert_eq!(socket_inode("socket:["), None);
  }

  /// A forwarder relays bytes to its loopback upstream while coexisting with
  /// it: the bind address is a different specific address from the agent's
  /// loopback listener, which is the combination a wildcard bind can never
  /// offer (the kernel refuses wildcard-and-specific on one port).
  #[tokio::test]
  async fn a_forwarder_relays_bytes_to_its_upstream() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = upstream.local_addr().unwrap();
    let echo = tokio::spawn(async move {
      let (mut conn, _) = upstream.accept().await.unwrap();
      let mut buf = [0u8; 16];
      let n = conn.read(&mut buf).await.unwrap();
      conn.write_all(&buf[..n]).await.unwrap();
      conn.shutdown().await.unwrap();
    });
    let bind = Ipv4Addr::new(127, 0, 0, 2);
    let forwarder = start(bind.into(), addr).await.unwrap();
    let mut client = tokio::net::TcpStream::connect(SocketAddr::from((bind, addr.port()))).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    echo.await.unwrap();
    drop(forwarder);
  }
}
