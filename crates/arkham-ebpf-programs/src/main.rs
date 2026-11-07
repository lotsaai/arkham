//! Arkham's eBPF capture programs: cgroup hooks that redirect outbound
//! connections to arkham's loopback listeners, stashing the original
//! destination in maps the userspace loader reads back.
//!
//! Mechanism, per connection:
//!
//! 1. `connect4` and `connect6` record the destination under the socket cookie
//!    and rewrite it to the corresponding loopback listener.
//! 2. `capture_egress` indexes the socket cookie and connecting cgroup by the
//!    client's local address and port, which the listener sees as its peer.
//! 3. `recvmsg4` and `recvmsg6` rewrite the *source* address a connected UDP socket observes,
//!    so replies that physically come from arkham's listener still look like
//!    they came from the address the client connected to.
//! 4. `release_flow` deletes the maps when the socket closes. It looks the
//!    4-tuple up by socket cookie, because this hook cannot read `src_port`.
//!
//! No netfilter, no policy routes, no `IP_TRANSPARENT`: the kernel's own socket
//! address rewrite is the whole mechanism.
//!
//! Indexing lives in `capture_egress` rather than a `sock_ops` program because
//! `bpf_sock_ops` has no UDP opcode — the kernel's `BPF_SOCK_OPS_*` enum
//! contains only TCP callbacks, so connected UDP would never be indexed. Egress
//! sees every protocol, and runs after the socket's source port has been
//! autobound, which is exactly when the 4-tuple is final.

#![no_std]
#![no_main]

use aya_ebpf::{
  EbpfContext as _,
  helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_netns_cookie, bpf_get_socket_cookie},
  macros::{cgroup_skb, cgroup_sock, cgroup_sock_addr, map},
  maps::{Array, LruHashMap},
  programs::{SkBuffContext, SockAddrContext, SockContext},
};

/// Loader-provided configuration: map key 0.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
  /// PID of the arkham process, so its own dials are never captured.
  /// Meaningful only outside a PID namespace: inside one, the pid the kernel
  /// reports is not the pid the process sees, which is what `proxy_cgroup`
  /// covers.
  pub proxy_pid: u32,
  /// Explicit padding: the layout is an ABI with the userspace half, and no
  /// byte may be left to the compiler.
  pub _pad: [u8; 4],
  /// Cgroup id of the loader's own cgroup, as
  /// `bpf_get_current_cgroup_id` reports it. Zero means unknown, leaving the
  /// pid as the only guard.
  pub proxy_cgroup: u64,
  /// Loopback port the connect hooks rewrite TCP destinations to.
  pub tcp_port: u32,
  /// Loopback port the connect hooks rewrite UDP destinations to.
  pub udp_port: u32,
  /// Netns cookie of the loader's own network namespace, as
  /// `SO_NETNS_COOKIE` reports it. Connects from a different network
  /// namespace — the containers the agent spawns — are never rewritten.
  /// Zero means unknown, disabling the guard: the pid and cgroup checks
  /// then carry exclusion alone.
  pub netns_cookie: u64,
  /// How many of `bypass_nets`/`bypass_lens` are valid, `0..=MAX_BYPASS`.
  /// Destinations inside one of those CIDRs are never rewritten: they fail
  /// or succeed on their own routing instead of fake-succeeding into the
  /// listener. The loader fills this with its own non-loopback addresses
  /// (as `/32`s) plus the operator's podman-range overrides, so local
  /// relays and nested-namespace addresses stop transiting the proxy.
  pub bypass_count: u32,
  /// Bypass networks in host byte order (`u32::from(Ipv4Addr)`), masked to
  /// their prefix length by the loader. Compared against the destination
  /// after `u32::from_be`, which undoes the kernel's address encoding.
  pub bypass_nets: [u32; MAX_BYPASS],
  /// Prefix lengths, `1..=32`, one per network above.
  pub bypass_lens: [u8; MAX_BYPASS],
  /// Explicit tail padding: the layout is an ABI with the userspace half.
  pub _pad2: [u8; 4],
}

/// How many bypass CIDRs `Config` carries. Eight covers the loader's own
/// addresses (usually one) plus a handful of podman ranges and manual
/// overrides; a bounded array keeps the match loop unrollable for the
/// verifier, where a variable-length map would cost a second lookup path.
pub const MAX_BYPASS: usize = 8;

/// Original destination recorded before the rewrite. Address fields retain
/// the kernel's network byte order for the receive hooks.
///
/// `cgroup_id` is sampled in `connect()`, which runs in the connecting task.
/// `capture_egress` copies that field. A later packet, including a softirq
/// retransmit, must not replace it with whichever task happens to be current.
///
/// All padding is explicit to keep the kernel and userspace map ABI identical.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OrigDst {
  /// Destination address, in the kernel's `user_ip4` or `user_ip6` encoding.
  pub ip: [u32; 4],
  /// Destination port, network byte order in the low 16 bits.
  pub port: u32,
  /// `IPPROTO_TCP` or `IPPROTO_UDP`. Kept so userspace can reject a flow whose
  /// socket has been reused for the other protocol.
  pub proto: u8,
  /// Address family, followed by explicit padding.
  pub family: u8,
  pub _pad: [u8; 10],
  /// Cgroup id of the connecting task, from `bpf_get_current_cgroup_id`.
  pub cgroup_id: u64,
}

/// Flow key: the client's local 4-tuple, which is the peer address arkham's
/// listener observes.
///
/// Deliberately no protocol field: an egress hook sees the IP header's protocol
/// byte only via packet data, and deriving it would cost a bounds-checked load
/// plus CAP_BPF-scoped data access. Two redirected sockets would have to share
/// the same local port across TCP and UDP to collide, and userspace rejects
/// that by checking the recorded [`OrigDst::proto`] — failing closed.
///
/// The trailing padding is an explicit field, not `repr(C)`'s implicit padding:
/// this is a map *key*, compared byte for byte by the kernel, so every byte has
/// to be written deterministically on both sides. Implicit padding would be
/// left uninitialized by the struct literals, and a difference in those bytes
/// between the insert and the lookup would make the lookup miss.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
  /// Local address in the kernel's socket address encoding.
  pub ip: [u32; 4],
  /// Local port, host byte order (the kernel reports it unswapped).
  pub port: u16,
  /// Socket address family.
  pub family: u16,
}

/// `IPPROTO_TCP`.
const IPPROTO_TCP: u32 = 6;
/// `IPPROTO_UDP`.
const IPPROTO_UDP: u32 = 17;
/// `AF_INET`.
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;

/// How many concurrent redirected sockets to remember.
const MAX_ENTRIES: u32 = 16_384;

#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

/// cookie → original destination.
#[map]
static ORIG_DST: LruHashMap<u64, OrigDst> = LruHashMap::with_max_entries(MAX_ENTRIES, 0);

/// Cookie plus the cgroup id of the process that connected.
///
/// Both fields are `u64`, so the layout has no padding. Userspace duplicates
/// this struct; the two sides cannot share a type.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowRecord {
  /// Socket cookie, the key into `ORIG_DST`.
  pub cookie: u64,
  /// `bpf_get_current_cgroup_id` for the connecting process.
  pub cgroup_id: u64,
}

/// client's local 4-tuple → cookie and cgroup.
#[map]
static FLOW: LruHashMap<FlowKey, FlowRecord> = LruHashMap::with_max_entries(MAX_ENTRIES, 0);

/// cookie → the `FLOW` key, so `release_flow` can delete it.
///
/// `sock_release` may read the socket cookie and may not read `src_port`.
/// The egress hook records the key under the cookie it already holds.
#[map]
static COOKIE_FLOW: LruHashMap<u64, FlowKey> = LruHashMap::with_max_entries(MAX_ENTRIES, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
  loop {}
}

/// True when this process is arkham itself, or the config has not been written
/// yet (map key 0 absent). Failing closed keeps arkham's own upstream dials out
/// of the capture loop, which would otherwise recurse.
///
/// The pid check is per *thread group*, not per thread: the tgid is the
/// process id the loader writes into `CONFIG`. A PID namespace translates
/// ids, so a containerized arkham never matches on pid — the cgroup id, which
/// no namespace translates, is what carries the guard there.
#[inline(always)]
fn is_proxy() -> bool {
  let Some(config) = CONFIG.get(0) else {
    return true;
  };
  if bpf_get_current_pid_tgid().wrapping_shr(32) as u32 == config.proxy_pid {
    return true;
  }
  if config.proxy_cgroup == 0 {
    return false;
  }
  // SAFETY: querying the current cgroup id has no preconditions.
  let cgroup = unsafe { bpf_get_current_cgroup_id() };
  cgroup == config.proxy_cgroup
}

/// `127.0.0.1` in the kernel's address encoding (`user_ip4` / `skc_rcv_saddr`).
#[inline(always)]
fn loopback_addr() -> u32 {
  // The kernel stores addresses byte-reversed from host integers, so the host
  // value is swapped on the way in and out.
  u32::from_be(0x7F00_0001)
}

/// True when `addr` is any `127.0.0.0/8` address, in the kernel's encoding.
#[inline(always)]
fn is_loopback(addr: u32) -> bool {
  u32::from_be(addr) & 0xFF00_0000 == 0x7F00_0000
}

/// True when the destination is in one of the loader's bypass CIDRs, in the
/// kernel's address encoding.
///
/// The loader stores networks masked to their prefix in host order, so the
/// destination is decoded with `u32::from_be` first and the top `len` bits
/// compared. A zero `len` matches everything and a `len` past 32 matches
/// nothing — the loader never writes either (it rejects prefix 0), so those
/// arms only guard against a stale or hand-written map.
#[inline(always)]
fn is_bypassed(addr: u32) -> bool {
  let Some(config) = CONFIG.get(0) else {
    return false;
  };
  let dst = u32::from_be(addr);
  let count = if config.bypass_count as usize > MAX_BYPASS {
    MAX_BYPASS
  } else {
    config.bypass_count as usize
  };
  let mut i = 0;
  while i < count {
    let len = config.bypass_lens[i];
    if len == 0 {
      return true;
    }
    if len <= 32 {
      let net = config.bypass_nets[i];
      if len >= 32 {
        if dst == net {
          return true;
        }
      } else if dst.wrapping_shr(32 - u32::from(len)) == net.wrapping_shr(32 - u32::from(len)) {
        return true;
      }
    }
    i += 1;
  }
  false
}

#[inline(always)]
fn tcp_port() -> Option<u32> {
  CONFIG.get(0).map(|config| config.tcp_port)
}

#[inline(always)]
fn udp_port() -> Option<u32> {
  CONFIG.get(0).map(|config| config.udp_port)
}

/// Rewrite one `connect()` to arkham's loopback listener, remembering where the
/// client actually meant to go.
///
/// Returns 1 on every path: 1 is allow, 0 is deny, and this backend never
/// denies — anything not redirected proceeds to its real destination.
// Specialize the family so LLVM keeps context accesses at verifier-approved constant offsets.
fn redirect<const FAMILY: u32>(ctx: &SockAddrContext, listener_port: u32) -> i32 {
  let addr = ctx.sock_addr;
  // SAFETY: the kernel passes a valid, live `bpf_sock_addr` for this hook.
  let (family, protocol, port) = unsafe { ((*addr).user_family, (*addr).protocol, (*addr).user_port) };
  let ip = if FAMILY == AF_INET {
    let ip = unsafe { (*addr).user_ip4 };
    if is_loopback(ip) || is_bypassed(ip) {
      return 1;
    }
    [ip, 0, 0, 0]
  } else if FAMILY == AF_INET6 {
    let ip = unsafe { (*addr).user_ip6 };
    if ip == [0, 0, 0, u32::to_be(1)] {
      return 1;
    }
    let [a, b, c, d] = ip;
    if a == 0 && b == 0 && c == u32::to_be(0xffff) && (is_loopback(d) || is_bypassed(d)) {
      return 1;
    }
    ip
  } else {
    return 1;
  };
  // SAFETY: `ctx.as_ptr()` is the context the kernel supplied to this hook.
  let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
  if cookie == 0 {
    return 1;
  }
  // SAFETY: querying the current cgroup id has no preconditions. This hook
  // runs in the connecting task, which is the id the project registry keys.
  let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
  let orig = OrigDst {
    ip,
    port,
    proto: protocol as u8,
    family: family as u8,
    _pad: [0; 10],
    cgroup_id,
  };
  if ORIG_DST.insert(cookie, orig, 0).is_err() {
    return 1;
  }
  // SAFETY: as above; only the destination being rewritten.
  unsafe {
    if FAMILY == AF_INET {
      (*addr).user_ip4 = loopback_addr();
    } else {
      (*addr).user_ip6 = [0, 0, 0, u32::to_be(1)];
    }
    (*addr).user_port = u16::to_be(listener_port as u16) as u32;
  }
  1
}

/// `connect4`: redirect a client's `connect()` into arkham.
///
/// This is where TLS, plain HTTP and connected UDP all get captured, because
/// every one of them reaches the network through `connect()`. Non-TCP/UDP
/// protocols are allowed through untouched.
#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
  connect::<AF_INET>(ctx)
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
  connect::<AF_INET6>(ctx)
}

#[inline(always)]
fn connect<const FAMILY: u32>(ctx: SockAddrContext) -> i32 {
  if is_proxy() {
    return 1;
  }
  // Containers the captured processes spawn — inner compose stacks, podman
  // inside the agent — run in their own network namespaces. Only sockets in
  // the loader's own namespace are captured: the cgroup subtree spans those
  // namespaces, while tproxy and tun capture one netns each. `0` disables
  // the guard on a kernel too old to read the cookie.
  if let Some(config) = CONFIG.get(0) {
    if config.netns_cookie != 0 {
      // SAFETY: the kernel supplied a live context for this hook; the helper
      // reads the connecting socket's netns cookie from it.
      let cookie = unsafe { bpf_get_netns_cookie(ctx.as_ptr()) };
      if cookie != config.netns_cookie {
        return 1;
      }
    }
  }
  // SAFETY: the kernel supplies a live `bpf_sock_addr` for this hook.
  let protocol = unsafe { (*ctx.sock_addr).protocol };
  let listener = match protocol {
    IPPROTO_TCP => tcp_port(),
    IPPROTO_UDP => udp_port(),
    _ => None,
  };
  match listener {
    Some(port) => redirect::<FAMILY>(&ctx, port),
    None => 1,
  }
}

/// `recvmsg4`: make replies that arkham relays look like they came from the
/// address the socket is connected to.
///
/// Without this a connected UDP client would drop every reply: the datagram
/// physically arrives from `127.0.0.1:<relay port>` while the socket is
/// connected to the real server, and the kernel would filter it as a
/// mismatched source.
#[cgroup_sock_addr(recvmsg4)]
pub fn recvmsg4(ctx: SockAddrContext) -> i32 {
  recvmsg::<AF_INET>(ctx)
}

#[cgroup_sock_addr(recvmsg6)]
pub fn recvmsg6(ctx: SockAddrContext) -> i32 {
  recvmsg::<AF_INET6>(ctx)
}

#[inline(always)]
fn recvmsg<const FAMILY: u32>(ctx: SockAddrContext) -> i32 {
  let addr = ctx.sock_addr;
  // SAFETY: the kernel supplies a live `bpf_sock_addr` for this hook.
  let loopback = unsafe {
    if FAMILY == AF_INET {
      is_loopback((*addr).user_ip4)
    } else if FAMILY == AF_INET6 {
      (*addr).user_ip6 == [0, 0, 0, u32::to_be(1)]
    } else {
      false
    }
  };
  if !loopback {
    return 1;
  }
  // SAFETY: `ctx.as_ptr()` is the context the kernel supplied to this hook.
  let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
  if cookie == 0 {
    return 1;
  }
  // SAFETY: the map is not shared mutably with userspace while a datagram is
  // being received, and the value is copied out before use.
  let Some(orig) = (unsafe { ORIG_DST.get(cookie) }) else {
    return 1;
  };
  // SAFETY: as above; only the reported source is being restored.
  unsafe {
    if FAMILY == AF_INET {
      let [ip, _, _, _] = orig.ip;
      (*addr).user_ip4 = ip;
    } else {
      let [a, b, c, d] = orig.ip;
      core::ptr::write_volatile(&raw mut (*addr).user_ip6[0], a);
      core::ptr::write_volatile(&raw mut (*addr).user_ip6[1], b);
      core::ptr::write_volatile(&raw mut (*addr).user_ip6[2], c);
      core::ptr::write_volatile(&raw mut (*addr).user_ip6[3], d);
    }
    (*addr).user_port = orig.port;
  }
  1
}

/// `capture_egress`: index the redirected flow by the client's local 4-tuple,
/// so userspace can resolve an accepted connection back to its original
/// destination.
///
/// Only flows that `connect4` actually redirected are recorded — hence the
/// `ORIG_DST` lookup — so unconnected UDP (typical DNS) keeps its own
/// addressing and is never touched. The cgroup id is copied from that record
/// rather than sampled here: egress can run in softirq, where `current` is
/// not the connecting task.
#[cgroup_skb(egress)]
pub fn capture_egress(ctx: SkBuffContext) -> i32 {
  if is_proxy() {
    return 1;
  }
  let family = ctx.skb.family();
  if family != AF_INET && family != AF_INET6 {
    return 1;
  }
  // SAFETY: `ctx.as_ptr()` is the context the kernel supplied to this hook.
  let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
  if cookie == 0 {
    return 1;
  }
  // SAFETY: the entry is copied out before use. The cgroup id inside it was
  // stored by `connect4`, so this insert does not sample `current`.
  let Some(orig) = (unsafe { ORIG_DST.get(cookie) }) else {
    return 1;
  };
  let key = FlowKey {
    ip: if family == AF_INET {
      [unsafe { core::ptr::read_volatile(&raw const (*ctx.skb.skb).local_ip4) }, 0, 0, 0]
    } else {
      unsafe {
        [
          core::ptr::read_volatile(&raw const (*ctx.skb.skb).local_ip6[0]),
          core::ptr::read_volatile(&raw const (*ctx.skb.skb).local_ip6[1]),
          core::ptr::read_volatile(&raw const (*ctx.skb.skb).local_ip6[2]),
          core::ptr::read_volatile(&raw const (*ctx.skb.skb).local_ip6[3]),
        ]
      }
    },
    port: ctx.skb.local_port() as u16,
    family: family as u16,
  };
  let _ = COOKIE_FLOW.insert(cookie, key, 0);
  let _ = FLOW.insert(
    key,
    FlowRecord {
      cookie,
      cgroup_id: orig.cgroup_id,
    },
    0,
  );
  1
}

/// `release_flow`: drop the maps for a socket that is going away.
///
/// `FLOW` is keyed by the local 4-tuple and `ORIG_DST` by the socket cookie.
/// Neither entry is useful after `close`, and a reused source port would
/// otherwise be attributed to the cgroup that connected last time. Loopback
/// connects never insert, so there is nothing for them to delete.
#[cgroup_sock(sock_release)]
pub fn release_flow(ctx: SockContext) -> i32 {
  if is_proxy() {
    return 1;
  }
  // SAFETY: `ctx.as_ptr()` is the context the kernel supplied to this hook.
  let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
  if cookie == 0 {
    return 1;
  }
  // SAFETY: the value is copied out before either map is updated.
  if let Some(key) = unsafe { COOKIE_FLOW.get(cookie) }.copied() {
    // SAFETY: the record is read before the map is modified.
    if unsafe { FLOW.get(&key) }.is_some_and(|record| record.cookie == cookie) {
      let _ = FLOW.remove(&key);
    }
  }
  let _ = COOKIE_FLOW.remove(&cookie);
  let _ = ORIG_DST.remove(&cookie);
  1
}
