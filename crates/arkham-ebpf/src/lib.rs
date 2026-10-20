//! eBPF capture backend: userspace half.
//!
//! Kernel-side programs (`arkham-ebpf-programs`) rewrite outbound connection
//! destinations to this crate's loopback listeners and stash the original
//! destination in BPF maps. This crate reads those maps and feeds the accepted
//! streams into the same substitution machinery every other backend uses.
//!
//! Nothing here touches netfilter or the routing table: the exclusion mechanism
//! is the cgroup a program is attached to, plus the recorded proxy PID.

use arkham_proxy::ProxyState;
use aya::{
  Ebpf,
  maps::{Array, MapData},
  programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSockAddr},
};
use std::fs::File;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

mod error;
mod flow;
mod tcp;
mod udp;

pub use error::Error;
/// Loopback port the TCP leg listens on. Also written into the BPF `CONFIG`
/// map, which is what actually sends connections here.
pub const TCP_LISTEN_PORT: u16 = 15000;
/// Loopback port the UDP relay listens on.
pub const UDP_LISTEN_PORT: u16 = 15001;

/// The `--ebpf-cgroup` value meaning "the cgroup this process's own cgroup
/// lives under", resolved at startup. A compose stack that gives both services
/// one `cgroup_parent` names no host path and uses this instead: the docker
/// daemon resolves that parent relative to its own cgroup root, so an absolute
/// path baked at generation time is wrong wherever the daemon is nested.
pub const ENCLOSING: &str = "enclosing";

/// Where cgroup v2 is mounted; the mount point the resolved path is built on.
const CGROUP2_MOUNT: &str = "/sys/fs/cgroup";

/// Resolve the cgroup enclosing this process: the parent of its own cgroup.
///
/// `/proc/self/cgroup` holds this process's path inside the cgroup v2 tree
/// (`0::<path>`), relative to the mount. The parent directory is the cgroup
/// shared with sibling containers, which is what a stack that sets one
/// `cgroup_parent` on both services wants attached. arkham is a member of the
/// attached subtree here, so the recorded proxy PID is what keeps its own
/// sockets out of the capture loop.
fn enclosing_cgroup() -> Result<PathBuf, Error> {
  let content = std::fs::read_to_string("/proc/self/cgroup").map_err(|err| Error::ReadCgroupFile { origin: err })?;
  let own = own_cgroup_path(&content).ok_or(Error::NotCgroupV2)?;
  enclosing_from(&own).ok_or_else(|| Error::NoEnclosingCgroup { path: own.clone() })
}

/// This process's own path in the cgroup v2 tree, from the `0::<path>` line.
fn own_cgroup_path(content: &str) -> Option<PathBuf> {
  content.lines().find_map(|line| line.strip_prefix("0::")).map(PathBuf::from)
}

/// The cgroup directory enclosing `own`, mounted at [`CGROUP2_MOUNT`]. `None`
/// when there is nothing worth attaching to: the cgroup root itself, or one of
/// its direct children, where the parent is that root.
fn enclosing_from(own: &Path) -> Option<PathBuf> {
  let parent = own.parent()?;
  if parent == Path::new("/") {
    return None;
  }
  // `join` with an absolute path would replace the mount instead of extending
  // it, so the leading slash comes off first.
  Some(Path::new(CGROUP2_MOUNT).join(parent.strip_prefix("/").ok()?))
}

/// The compiled programs, embedded at build time by `build.rs`.
static PROGRAMS: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/arkham-ebpf-programs"));

/// Test overrides over [`run_ebpf`], mirroring `tproxy::Options`.
#[derive(Debug, Default)]
pub(crate) struct Options {
  /// cgroup directory to attach the programs to. Required in production: a
  /// default would capture every process on the machine.
  pub cgroup: Option<PathBuf>,
  /// Dial this address instead of the captured destination (stub upstream).
  pub upstream_override: Option<SocketAddr>,
  /// TCP listener port (tests avoid collisions).
  pub tcp_port: Option<u16>,
  /// UDP listener port (tests avoid collisions).
  pub udp_port: Option<u16>,
  /// Signalled once the programs are attached and the listeners are accepting.
  pub ready: Option<tokio::sync::oneshot::Sender<()>>,
  /// Which process the programs skip, so arkham's own upstream dials are never
  /// re-captured.
  pub self_exclusion: SelfExclusion,
  /// Extra bypass CIDRs as `(network, prefix_len)`, from `--ebpf-bypass`.
  /// The loader always adds its own non-loopback addresses (as `/32`s) and
  /// best-effort podman ranges on top; see [`build_bypass`].
  pub bypass: Vec<(Ipv4Addr, u8)>,
  /// File holding runtime bypass CIDRs, one per line, re-read while capture
  /// runs. The agent entrypoint rewrites it from `podman network inspect`;
  /// absent means no runtime entries, never an error.
  pub bypass_file: Option<PathBuf>,
}

/// How many bypass CIDRs [`Config`] carries. Must match
/// `arkham-ebpf-programs::MAX_BYPASS`; the layout test pins both sides.
pub(crate) const MAX_BYPASS: usize = 8;

/// How often the bypass file is re-read while capture runs. Podman networks
/// are created at human scale, so seconds of delay are invisible — and a
/// shared-volume file is polled rather than watched, because inotify over
/// container mounts is unreliable.
const BYPASS_POLL: Duration = Duration::from_secs(5);

/// Which process the programs skip.
///
/// The programs compare this against `bpf_get_current_pid_tgid() >> 32` and
/// let a match through unredirected. Production has exactly one state, so a
/// load that excludes nothing cannot be asked for by accident.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum SelfExclusion {
  /// Skip this process. What every production run uses.
  #[default]
  Proxy,
  /// Skip nothing, so even this process's own sockets are captured.
  ///
  /// Sound only when arkham's own dials cannot be re-captured: the live tests
  /// dial a loopback stub, and the programs never rewrite a loopback
  /// destination, so there is no loop to fall into. In a production run this
  /// would capture arkham's own upstream connections and recurse — which is why
  /// it exists only for tests, and why production code cannot name it.
  #[cfg(test)]
  Nothing,
}

impl SelfExclusion {
  /// The value written to the programs' `CONFIG` map.
  ///
  /// "Skip nothing" is 0 because no real process has tgid 0: the idle task
  /// never issues socket calls, so the comparison can never match. Inside a
  /// PID namespace this pid never matches what the kernel reports either —
  /// the cgroup id in [`Config`] is the guard that carries that case.
  fn pid(self) -> u32 {
    match self {
      Self::Proxy => std::process::id(),
      #[cfg(test)]
      Self::Nothing => 0,
    }
  }
}

/// The id of this process's own cgroup, as `bpf_get_current_cgroup_id`
/// reports it: the kernfs inode of the cgroup directory. A PID namespace
/// translates ids, so a containerized arkham never matches the pid guard —
/// the cgroup id has no namespace of its own. `0` means it could not be
/// determined, leaving the pid as the only guard.
fn own_cgroup_id() -> u64 {
  use std::os::unix::fs::MetadataExt as _;
  let Ok(content) = std::fs::read_to_string("/proc/self/cgroup") else {
    return 0;
  };
  let Some(own) = own_cgroup_path(&content) else {
    return 0;
  };
  // `join` with an absolute path would replace the mount instead of extending
  // it, so the leading slash comes off first.
  let Ok(relative) = own.strip_prefix("/") else {
    return 0;
  };
  std::fs::metadata(Path::new(CGROUP2_MOUNT).join(relative)).map_or(0, |meta| meta.ino())
}

/// The netns cookie of this process's own network namespace, as
/// `SO_NETNS_COOKIE` reports it — the same value `bpf_get_netns_cookie`
/// reports for a socket in that namespace, so the two sides compare
/// apples to apples. `0` means it could not be read (kernel older than
/// 5.5, `CONFIG_NET_NS` unset), which disables the guard and restores the
/// pre-cookie behavior: only the pid and cgroup checks exclude, and every
/// namespace under the attached cgroup is captured.
fn own_netns_cookie() -> u64 {
  use std::os::fd::AsRawFd as _;
  let Ok(socket) = std::net::UdpSocket::bind(("127.0.0.1", 0)) else {
    return 0;
  };
  let mut cookie = 0u64;
  let Ok(mut size) = libc::socklen_t::try_from(std::mem::size_of::<u64>()) else {
    return 0;
  };
  // SAFETY: the fd is owned by `socket`, and the option reads exactly
  // `size` bytes into `cookie`, a valid u64 slot.
  let ok = unsafe {
    libc::getsockopt(
      socket.as_raw_fd(),
      libc::SOL_SOCKET,
      libc::SO_NETNS_COOKIE,
      (&raw mut cookie).cast(),
      (&raw mut size).cast(),
    )
  } == 0;
  if !ok || size as usize != std::mem::size_of::<u64>() {
    tracing::debug!(ok, size, "netns cookie unreadable: the netns guard stays off");
    return 0;
  }
  cookie
}
/// Parse one `--ebpf-bypass` CIDR (`10.89.0.0/16`) into `(network, prefix_len)`.
///
/// The single parser for bypass CIDRs: the face uses it as the clap
/// `value_parser`, so an invalid entry fails the CLI before capture starts
/// and the loader never parses twice. The network need not be masked —
/// [`Config::from_bypass`] masks it — but the prefix must be `1..=32`: `0`
/// would bypass all capture, which is never what an override means.
///
/// # Errors
///
/// Returns a message for a missing `/`, an unparseable address, or a prefix
/// outside `1..=32`.
pub fn parse_bypass_cidr(s: &str) -> Result<(Ipv4Addr, u8), String> {
  let (addr, len) = s
    .split_once('/')
    .ok_or_else(|| format!("expected CIDR `address/prefix_len`, got `{s}`"))?;
  let addr: Ipv4Addr = addr.parse().map_err(|_source| format!("invalid bypass network address `{addr}`"))?;
  let len: u8 = len.parse().map_err(|_source| format!("invalid bypass prefix length `{len}`"))?;
  if len == 0 || len > 32 {
    return Err(format!("bypass prefix length must be 1..=32, got `{len}`"));
  }
  Ok((addr, len))
}

/// Host-order mask for `len` prefix bits: `mask_prefix(24)` is `255.255.255.0`.
/// A zero length masks nothing; the loader never stores it (it rejects prefix
/// `0`), so this arm only guards the helper itself.
pub(crate) fn mask_prefix(len: u8) -> u32 {
  if len == 0 {
    0
  } else if len >= 32 {
    u32::MAX
  } else {
    u32::MAX << (32 - len)
  }
}

/// Assemble the bypass list [`configure`] writes: explicit `--ebpf-bypass`
/// CIDRs, then the bypass file's entries, then this netns's own non-loopback
/// addresses (as `/32`s) and best-effort podman ranges.
///
/// Explicit entries always survive: they state intent, so truncation drops
/// automatic entries first, then file entries, and warns. An explicit list
/// longer than [`MAX_BYPASS`] is kept whole here and refused loudly by
/// [`Config::from_bypass`] instead — silently dropping an override would
/// reintroduce the fake-success hang it was named to prevent.
pub(crate) fn build_bypass(mut explicit: Vec<(Ipv4Addr, u8)>, mut file: Vec<(Ipv4Addr, u8)>) -> Vec<(Ipv4Addr, u8)> {
  explicit.sort();
  explicit.dedup();
  file.sort();
  file.dedup();
  file.retain(|entry| !explicit.contains(entry));
  let mut automatic: Vec<(Ipv4Addr, u8)> = local_ipv4_addrs().into_iter().map(|addr| (addr, 32)).collect();
  automatic.extend(podman_cidrs());
  automatic.sort();
  automatic.dedup();
  automatic.retain(|entry| !explicit.contains(entry) && !file.contains(entry));
  let mut out = explicit;
  for (tier, name) in [(file, "bypass-file"), (automatic, "discovered")] {
    let room = MAX_BYPASS.saturating_sub(out.len());
    if tier.len() > room {
      tracing::warn!(
        kept = out.len(),
        dropped = tier.len() - room,
        max = MAX_BYPASS,
        tier = name,
        "more bypass CIDRs than the programs carry: keeping the higher-precedence entries"
      );
      out.extend(tier.into_iter().take(room));
    } else {
      out.extend(tier);
    }
  }
  out
}

/// Read runtime bypass CIDRs from `path`: one `address/prefix` per line,
/// `#` comments and blank lines ignored.
///
/// A missing file is the ordinary "no runtime entries yet" case — the agent
/// writes it after arkham starts — so it reads as empty without a log. Any
/// other read failure degrades the same way with a debug log: capture must
/// not fail for a file it only consults. Unparseable lines are skipped with
/// a warning naming the line, so one bad entry never hides the rest.
fn read_bypass_file(path: &Path) -> Vec<(Ipv4Addr, u8)> {
  match std::fs::read_to_string(path) {
    Ok(content) => parse_bypass_file(&content, path),
    Err(err) if err.kind() == ErrorKind::NotFound => Vec::new(),
    Err(err) => {
      tracing::debug!(path = %path.display(), %err, "bypass file unreadable: runtime entries stay empty");
      Vec::new()
    }
  }
}

/// Every valid CIDR in bypass-file `content`. Split out for tests: the
/// watcher skips this entirely when the raw bytes are unchanged.
fn parse_bypass_file(content: &str, path: &Path) -> Vec<(Ipv4Addr, u8)> {
  let mut out = Vec::new();
  for (index, line) in content.lines().enumerate() {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
      continue;
    }
    match parse_bypass_cidr(line) {
      Ok(cidr) => out.push(cidr),
      Err(detail) => tracing::warn!(path = %path.display(), line = index + 1, %detail, "ignoring invalid bypass-file entry"),
    }
  }
  out
}

/// Owns the `getifaddrs` list head and frees the whole list on drop.
struct IfaddrsList(*mut libc::ifaddrs);

impl Drop for IfaddrsList {
  fn drop(&mut self) {
    // SAFETY: the pointer is the head `getifaddrs` wrote.
    unsafe { libc::freeifaddrs(self.0) };
  }
}

/// This netns's own non-loopback IPv4 addresses, one `/32` each in the bypass
/// list: dials at the devenv by bridge IP (pasta relays, `fwd`-exposed ports)
/// keep their own routing instead of taking a double hop through the proxy.
/// Empty when the addresses cannot be listed — capture then proceeds without
/// the local bypass rather than failing the backend for it.
fn local_ipv4_addrs() -> Vec<Ipv4Addr> {
  let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
  // SAFETY: `getifaddrs` writes the list head and nothing else the caller
  // owns; every node is freed before this function returns.
  if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
    tracing::debug!("getifaddrs failed: the local-address bypass stays empty");
    return Vec::new();
  }
  let _list = IfaddrsList(head);
  let mut out = Vec::new();
  let mut cursor = head;
  loop {
    // SAFETY: `cursor` is null or a node of the list `_list` owns.
    let entry = unsafe { cursor.as_ref() };
    let Some(entry) = entry else {
      break;
    };
    cursor = entry.ifa_next;
    // SAFETY: `entry` is a live `ifaddrs` node owned by `_list`, and its
    // `ifa_addr` is null or points to a `sockaddr` the kernel wrote for it.
    if i32::from(unsafe { entry.ifa_addr.as_ref() }.map_or(0, |addr| addr.sa_family)) != libc::AF_INET {
      continue;
    }
    // SAFETY: an AF_INET entry stores a `sockaddr_in` at `ifa_addr`.
    let Some(sa) = (unsafe { entry.ifa_addr.cast::<libc::sockaddr_in>().as_ref() }) else {
      continue;
    };
    let addr = decode_addr(sa.sin_addr.s_addr);
    if !addr.is_loopback() && !out.contains(&addr) {
      out.push(addr);
    }
  }
  out
}

/// Podman-managed CIDRs, best-effort: every `subnet` in the podman network
/// definition files this mount namespace can see.
///
/// A loader sharing the agent's mounts (host runs, shared volumes) discovers
/// the ranges on its own; a loader in the arkham service container cannot see
/// the agent container's files, so inner-podman ranges still need an explicit
/// `--ebpf-bypass`. Unreadable files and unparseable entries are skipped with
/// a debug log — discovery is opportunistic, never fatal.
fn podman_cidrs() -> Vec<(Ipv4Addr, u8)> {
  let mut out = Vec::new();
  for dir in podman_network_dirs() {
    let Ok(entries) = std::fs::read_dir(&dir) else {
      continue;
    };
    for entry in entries.flatten() {
      if entry.path().extension().is_none_or(|ext| ext != "json") {
        continue;
      }
      let Ok(content) = std::fs::read_to_string(entry.path()) else {
        continue;
      };
      out.extend(podman_subnets_in(&content));
    }
  }
  out
}

/// Where podman keeps network definitions: the user config tree plus the
/// system one. Runtime state under `/run` carries no subnet definitions, so
/// only definition files are worth scanning.
fn podman_network_dirs() -> Vec<PathBuf> {
  let mut dirs = Vec::new();
  if let Some(home) = std::env::var_os("HOME") {
    dirs.push(PathBuf::from(home).join(".config/containers/podman/networks"));
  }
  dirs.push(PathBuf::from("/etc/containers/networks"));
  dirs.push(PathBuf::from("/usr/local/etc/containers/networks"));
  dirs
}

/// Every `"subnet": "A.B.C.D/L"` value in one network definition file.
/// A string scan, not a JSON parse: the files are small, the key is stable,
/// and a scan never fails the load on an unknown schema version.
fn podman_subnets_in(content: &str) -> Vec<(Ipv4Addr, u8)> {
  let mut out = Vec::new();
  for chunk in content.split("\"subnet\"").skip(1) {
    // The value is the first quoted string after the key: ` : "10.89.0.0/24"`.
    let Some(quoted) = chunk.split('"').nth(1) else {
      continue;
    };
    match parse_bypass_cidr(quoted) {
      Ok(cidr) => out.push(cidr),
      Err(detail) => tracing::debug!(subnet = quoted, %detail, "ignoring unparseable podman subnet"),
    }
  }
  out
}

/// Render a bypass list for the startup log: `10.89.0.0/16, 172.21.0.2/32`.
fn bypass_debug(bypass: &[(Ipv4Addr, u8)]) -> Vec<String> {
  bypass.iter().map(|(addr, len)| format!("{addr}/{len}")).collect()
}

/// Attach the capture programs and serve captured traffic forever.
///
/// `cgroup` is the directory whose member processes get captured. arkham itself
/// must live outside it, or its own upstream dials would be redirected back
/// into it; the recorded proxy PID is a second guard against that.
///
/// `bypass` holds extra `(network, prefix_len)` CIDRs `connect4` never
/// rewrites — podman ranges, usually, from `--ebpf-bypass`. The loader always
/// adds its own non-loopback addresses (as `/32`s) on top, so local relays
/// stop transiting the proxy without anyone naming them.
///
/// `bypass_file` names a file with runtime CIDRs, one per line, that the
/// loader re-reads while capture runs: podman networks are created inside
/// the agent long after arkham starts, so no startup flag can name them. The
/// agent entrypoint rewrites that file from `podman network inspect`; `None`
/// means no runtime entries. Every applied list is logged, so a stale or
/// surprising bypass is visible in arkham's own logs.
///
/// # Errors
///
/// Fails when the embedded object cannot be loaded, the `CONFIG` map cannot be
/// written, the cgroup cannot be opened or attached to, or either listener
/// cannot be bound. Every one of these is fatal for capture, so they surface
/// rather than degrade: a silent failure here would leave traffic flowing
/// unproxied while the operator believes it is captured.
pub async fn run_ebpf(
  state: Arc<ProxyState>,
  cgroup: PathBuf,
  bypass: Vec<(Ipv4Addr, u8)>,
  bypass_file: Option<PathBuf>,
) -> Result<(), Error> {
  run_ebpf_with(
    Options {
      cgroup: Some(cgroup),
      bypass,
      bypass_file,
      ..Options::default()
    },
    state,
  )
  .await
}

pub(crate) async fn run_ebpf_with(options: Options, state: Arc<ProxyState>) -> Result<(), Error> {
  let cgroup = match options.cgroup.as_deref() {
    Some(path) if path == Path::new(ENCLOSING) => enclosing_cgroup()?,
    Some(path) => path.to_path_buf(),
    None => return Err(Error::NoCgroup),
  };
  let tcp_port = options.tcp_port.unwrap_or(TCP_LISTEN_PORT);
  let udp_port = options.udp_port.unwrap_or(UDP_LISTEN_PORT);
  // The file is read once here so a list the agent already wrote applies
  // from the first connection; the watcher below picks up later rewrites.
  let file_initial = options.bypass_file.as_deref().map_or_else(Vec::new, read_bypass_file);
  let bypass = build_bypass(options.bypass.clone(), file_initial);

  let mut bpf = Ebpf::load(PROGRAMS).map_err(|err| Error::LoadPrograms { origin: err })?;
  configure(&mut bpf, tcp_port, udp_port, options.self_exclusion, &bypass).map_err(|err| Error::WriteConfigMap { origin: err.into() })?;

  // `bpf` is held on the stack for as long as this task lives, so the programs
  // stay attached: dropping `Ebpf` detaches them and unloads them, which means
  // there is no kernel residue and nothing to clean up on exit.
  attach(&mut bpf, &cgroup).map_err(|err| Error::AttachCgroup {
    path: cgroup.clone(),
    origin: err.into(),
  })?;

  let flow = flow::FlowTables::from_bpf(&mut bpf)?;
  if let Some(ready) = options.ready {
    let _ = ready.send(());
  }
  tracing::info!(tcp_port, udp_port, cgroup = %cgroup.display(), bypass = ?bypass_debug(&bypass), "ebpf capturing");
  // The file watcher only exists when a bypass file was named; without one
  // the backend is two legs as before. Its `CONFIG` rewrites apply to the
  // live programs with no reattach, so a podman network created mid-run
  // stops being captured within one poll.
  let watcher = options.bypass_file.map(|path| BypassWatch {
    path,
    explicit: options.bypass,
    proxy_pid: options.self_exclusion.pid(),
    proxy_cgroup: own_cgroup_id(),
    tcp_port,
    udp_port,
    netns_cookie: own_netns_cookie(),
  });
  // All three legs run for the life of the process; whichever fails first
  // fails the backend, and `main` treats that as fatal because capture was
  // requested. The watcher itself never fails — a bad file only means stale
  // entries until the next poll — so in practice it runs forever.
  if let Some(watch) = watcher {
    tokio::select! {
      result = tcp::serve(tcp_port, flow.clone(), state, options.upstream_override) => result,
      result = udp::serve(udp_port, flow, options.upstream_override) => result,
      result = watch.run(&mut bpf, bypass) => result,
    }
  } else {
    tokio::select! {
      result = tcp::serve(tcp_port, flow.clone(), state, options.upstream_override) => result,
      result = udp::serve(udp_port, flow, options.upstream_override) => result,
    }
  }
}
/// Write the loader-side configuration the programs read at runtime.
///
/// `bypass` is the output of [`build_bypass`]: explicit `--ebpf-bypass` CIDRs,
/// then the bypass file's entries, then the loader's own addresses and
/// discovered podman ranges.
fn configure(bpf: &mut Ebpf, tcp_port: u16, udp_port: u16, self_exclusion: SelfExclusion, bypass: &[(Ipv4Addr, u8)]) -> Result<(), Error> {
  let netns_cookie = own_netns_cookie();
  if netns_cookie == 0 {
    tracing::warn!(
      "could not read this process's netns cookie (SO_NETNS_COOKIE): connect4 captures every namespace under the attached cgroup"
    );
  }
  let config = Config::from_bypass(self_exclusion.pid(), own_cgroup_id(), tcp_port, udp_port, netns_cookie, bypass)?;
  write_config_map(bpf, &config)
}

/// Write one `CONFIG` entry. Split from [`configure`] so the bypass watcher
/// can rewrite the entry while the programs run: map updates apply to live
/// programs without reattaching anything.
fn write_config_map(bpf: &mut Ebpf, config: &Config) -> Result<(), Error> {
  let map = bpf.map_mut("CONFIG").ok_or(Error::MapMissing { name: "CONFIG" })?;
  let mut map: Array<&mut MapData, Config> = map.try_into().map_err(|err| Error::UnexpectedMapType {
    name: "CONFIG",
    origin: err,
  })?;
  map.set(0, *config, 0).map_err(|err| Error::SetConfig { origin: err })
}

/// Live bypass-file tracking: re-reads the file, rebuilds the merged list,
/// and rewrites the programs' `CONFIG` entry when it changed — so podman
/// networks created inside the agent long after arkham starts stop being
/// captured without anyone restarting arkham.
///
/// Only the bypass entries are rebuilt per poll; the pid, cgroup, ports, and
/// netns cookie are startup facts that cannot change under a running loader.
struct BypassWatch {
  /// File the agent rewrites from `podman network inspect`, one CIDR per line.
  path: PathBuf,
  /// `--ebpf-bypass` entries: highest precedence, rebuilt around every time.
  explicit: Vec<(Ipv4Addr, u8)>,
  /// Everything [`configure`] wrote at startup except the bypass list.
  proxy_pid: u32,
  proxy_cgroup: u64,
  tcp_port: u16,
  udp_port: u16,
  netns_cookie: u64,
}

impl BypassWatch {
  /// Poll the file forever, applying its entries on change. Unchanged bytes
  /// are not even parsed, so a steady file costs one small read per [`BYPASS_POLL`].
  ///
  /// Every failure degrades to "try again next poll" with a log, never to a
  /// backend exit: a missing or malformed file means stale bypass entries,
  /// not broken capture, and the next poll retries. `from_bypass` cannot fail
  /// here — the explicit list passed [`configure`] at startup, and file plus
  /// discovered entries are capped by [`build_bypass`] — so its error arm
  /// only guards against future construction changes.
  async fn run(&self, bpf: &mut Ebpf, initial: Vec<(Ipv4Addr, u8)>) -> Result<(), Error> {
    let mut last = initial;
    let mut last_raw: Option<String> = None;
    loop {
      tokio::time::sleep(BYPASS_POLL).await;
      let raw = match std::fs::read_to_string(&self.path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == ErrorKind::NotFound => String::new(),
        Err(err) => {
          tracing::debug!(path = %self.path.display(), %err, "bypass file unreadable: keeping the applied list");
          continue;
        }
      };
      if last_raw.as_deref() == Some(raw.as_str()) {
        continue;
      }
      last_raw = Some(raw.clone());
      let merged = build_bypass(self.explicit.clone(), parse_bypass_file(&raw, &self.path));
      if merged == last {
        continue;
      }
      match Config::from_bypass(
        self.proxy_pid,
        self.proxy_cgroup,
        self.tcp_port,
        self.udp_port,
        self.netns_cookie,
        &merged,
      ) {
        Ok(config) => match write_config_map(bpf, &config) {
          Ok(()) => {
            tracing::info!(path = %self.path.display(), bypass = ?bypass_debug(&merged), "ebpf bypass list updated");
            last = merged;
          }
          Err(err) => tracing::warn!(path = %self.path.display(), %err, "bypass update failed: retrying on the next poll"),
        },
        Err(err) => tracing::warn!(path = %self.path.display(), %err, "bypass update refused: retrying on the next poll"),
      }
    }
  }
}

/// Configuration map layout; must match `arkham-ebpf-programs::Config`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Config {
  /// PID of this process, so the programs can skip its own dials. Only
  /// meaningful outside a PID namespace: inside one the pid the kernel-side
  /// guard compares is not the pid this process sees.
  pub proxy_pid: u32,
  /// Explicit padding: the layout is an ABI with `arkham-ebpf-programs`, and
  /// no byte may be left to the compiler.
  pub _pad: [u8; 4],
  /// Id of this process's own cgroup, or 0 when unknown: the guard a
  /// namespace cannot translate, which is what carries the container case.
  pub proxy_cgroup: u64,
  /// Port `connect4` rewrites TCP destinations to.
  pub tcp_port: u32,
  /// Port `connect4` rewrites UDP destinations to.
  pub udp_port: u32,
  /// Netns cookie of this process's network namespace, or 0 when unknown:
  /// connects from other namespaces — the containers the agent spawns — are
  /// then still rewritten.
  pub netns_cookie: u64,
  /// How many of `bypass_nets`/`bypass_lens` are valid.
  pub bypass_count: u32,
  /// Bypass networks in host byte order, masked to their prefix length.
  pub bypass_nets: [u32; MAX_BYPASS],
  /// One prefix length per network above, `1..=32`.
  pub bypass_lens: [u8; MAX_BYPASS],
  /// Explicit tail padding: the layout is an ABI, no byte left to the compiler.
  pub _pad2: [u8; 4],
}

impl Config {
  /// Build a validated [`Config`], masking each bypass network to its prefix.
  ///
  /// # Errors
  ///
  /// Returns [`Error::ListenPortsZero`] for a zero listen port and
  /// [`Error::InvalidBypassPrefix`] for a prefix outside `1..=32` or more
  /// entries than [`MAX_BYPASS`].
  fn from_bypass(
    proxy_pid: u32,
    proxy_cgroup: u64,
    tcp_port: u16,
    udp_port: u16,
    netns_cookie: u64,
    bypass: &[(Ipv4Addr, u8)],
  ) -> Result<Self, Error> {
    if tcp_port == 0 || udp_port == 0 {
      return Err(Error::ListenPortsZero);
    }
    let bypass_count = match u8::try_from(bypass.len()) {
      Ok(count) if usize::from(count) <= MAX_BYPASS => u32::from(count),
      _ => return Err(Error::TooManyBypasses { count: bypass.len() }),
    };
    let mut nets = [0u32; MAX_BYPASS];
    let mut lens = [0u8; MAX_BYPASS];
    for (i, (addr, len)) in bypass.iter().enumerate() {
      if *len == 0 || *len > 32 {
        return Err(Error::InvalidBypassPrefix { prefix: *len });
      }
      nets[i] = u32::from(*addr) & mask_prefix(*len);
      lens[i] = *len;
    }
    Ok(Self {
      proxy_pid,
      _pad: [0; 4],
      proxy_cgroup,
      tcp_port: u32::from(tcp_port),
      udp_port: u32::from(udp_port),
      netns_cookie,
      bypass_count,
      bypass_nets: nets,
      bypass_lens: lens,
      _pad2: [0; 4],
    })
  }
}

// SAFETY: `Config` is `repr(C)` and contains only integers, so any bit pattern
// is a valid value and it can cross the map boundary as bytes.
unsafe impl aya::Pod for Config {}

/// Address encoding the kernel uses in `bpf_sock_addr.user_ip4` and in
/// `sock_common.skc_rcv_saddr`: the address bytes sit in memory in network
/// order, so the value read as a native `u32` is byte-reversed from the
/// numeric address. Both conversions below are that reversal, spelled out so
/// the two directions cannot drift apart.
pub(crate) fn decode_addr(raw: u32) -> Ipv4Addr {
  Ipv4Addr::from(u32::from_be(raw))
}

/// Inverse of [`decode_addr`].
pub(crate) fn encode_addr(addr: Ipv4Addr) -> u32 {
  u32::from(addr).to_be()
}

/// Port encoding the kernel uses in `bpf_sock_addr.user_port`, which holds
/// the port in network byte order in its low 16 bits.
pub(crate) fn decode_port(raw: u32) -> u16 {
  let low = raw & u32::from(u16::MAX);
  let [lo, hi, _, _] = low.to_le_bytes();
  u16::from_be(u16::from_le_bytes([lo, hi]))
}

/// Inverse of [`decode_port`].
///
/// The programs do this conversion themselves, so nothing on the loader path
/// needs it; it exists so the round-trip tests can assert both directions
/// against one encoding.
#[cfg(test)]
pub(crate) fn encode_port(port: u16) -> u32 {
  u32::from(u16::to_be(port))
}

/// Original destination recorded by `connect4` before it rewrote the address.
///
/// Every byte is spelled out, including padding, so the layout is identical on
/// both sides of the map regardless of how either compiler would pad the
/// struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct OrigDst {
  /// Destination address, in the kernel's `user_ip4` encoding.
  pub ip: u32,
  /// Destination port, in the kernel's `user_port` encoding.
  pub port: u32,
  /// `IPPROTO_TCP` (6) or `IPPROTO_UDP` (17).
  pub proto: u8,
  /// Padding, mirroring `arkham-ebpf-programs::OrigDst`.
  pub _pad: [u8; 3],
}

// SAFETY: `repr(C)`, integer fields only.
unsafe impl aya::Pod for OrigDst {}

impl OrigDst {
  /// The recorded destination as a socket address.
  pub(crate) fn socket_addr(&self) -> SocketAddr {
    SocketAddr::from((decode_addr(self.ip), decode_port(self.port)))
  }
}

/// Key indexing a redirected flow by the client's local 4-tuple, which is the
/// peer address arkham's listener observes. Must match
/// `arkham-ebpf-programs::FlowKey`, byte for byte: the kernel compares map keys
/// as raw bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FlowKey {
  /// Local address, in the kernel's `skc_rcv_saddr` encoding.
  pub ip: u32,
  /// Local port, host byte order: the kernel stores `skc_num` unswapped.
  pub port: u16,
  /// Padding, always zero. Explicit so the lookup key cannot differ from the
  /// inserted one in bytes the kernel compares but Rust never writes.
  pub _pad: [u8; 2],
}

// SAFETY: `repr(C)`, integer fields only.
unsafe impl aya::Pod for FlowKey {}

impl FlowKey {
  /// Key for a connection whose peer address is `peer`, as reported by
  /// `accept()` or `recv_from()`. The hook records the client's local 4-tuple,
  /// and for a loopback redirect that is exactly the address the server leg
  /// sees as its peer.
  pub(crate) fn from_peer(peer: SocketAddr) -> Option<Self> {
    let std::net::IpAddr::V4(ip) = peer.ip() else {
      return None;
    };
    Some(Self {
      ip: encode_addr(ip),
      port: peer.port(),
      _pad: [0; 2],
    })
  }
}

/// Attach every capture program to `cgroup`.
///
/// The links live inside the loaded object, so keeping `bpf` alive keeps the
/// programs attached; there are no handles to hold here.
fn attach(bpf: &mut Ebpf, cgroup: &std::path::Path) -> Result<(), Error> {
  let file = File::open(cgroup).map_err(|err| Error::OpenCgroup {
    path: cgroup.to_path_buf(),
    origin: err,
  })?;
  let mode = CgroupAttachMode::Single;
  attach_sock_addr(bpf, "connect4", &file, mode)?;
  attach_sock_addr(bpf, "recvmsg4", &file, mode)?;
  let program: &mut CgroupSkb = bpf
    .program_mut("capture_egress")
    .ok_or_else(|| Error::ProgramMissing {
      name: "capture_egress".to_string(),
    })?
    .try_into()
    .map_err(|err| Error::UnexpectedProgramType {
      name: "capture_egress".to_string(),
      origin: err,
    })?;
  program.load().map_err(|err| Error::LoadProgram {
    name: "capture_egress".to_string(),
    origin: err,
  })?;
  program
    .attach(&file, CgroupSkbAttachType::Egress, mode)
    .map_err(|err| Error::AttachProgram {
      name: "capture_egress".to_string(),
      origin: err,
    })?;
  Ok(())
}

/// Load and attach one `cgroup_sock_addr` program.
///
/// The attach type comes from the program's own section name, which `load`
/// reads, so nothing about it needs passing here.
fn attach_sock_addr(bpf: &mut Ebpf, name: &str, cgroup: &File, mode: CgroupAttachMode) -> Result<(), Error> {
  let program: &mut CgroupSockAddr = bpf
    .program_mut(name)
    .ok_or_else(|| Error::ProgramMissing { name: name.to_string() })?
    .try_into()
    .map_err(|err| Error::UnexpectedProgramType {
      name: name.to_string(),
      origin: err,
    })?;
  program.load().map_err(|err| Error::LoadProgram {
    name: name.to_string(),
    origin: err,
  })?;
  program.attach(cgroup, mode).map_err(|err| Error::AttachProgram {
    name: name.to_string(),
    origin: err,
  })?;
  Ok(())
}

#[cfg(test)]
mod live;

#[cfg(test)]
mod tests {
  use super::*;

  /// The stack hands arkham `--ebpf-cgroup enclosing` instead of a host path:
  /// the docker daemon resolves `cgroup_parent` relative to its own cgroup
  /// root, so the slice's fs path depends on where the daemon is nested. The
  /// resolution below has to land on the cgroup both containers share.
  #[test]
  fn the_own_cgroup_path_is_parsed_from_the_v2_line() {
    let own = own_cgroup_path("0::/arkham.slice/arkham-x.slice/docker-abc.scope\n").unwrap();
    assert_eq!(own, PathBuf::from("/arkham.slice/arkham-x.slice/docker-abc.scope"));
    assert!(own_cgroup_path("2:cpu:/\n1:name=systemd:/\n").is_none());
    assert!(own_cgroup_path("").is_none());
  }

  #[test]
  fn the_enclosing_cgroup_is_the_parent_of_this_processes_own_cgroup() {
    let own = own_cgroup_path("0::/arkham.slice/arkham-x.slice/docker-abc.scope\n").unwrap();
    assert_eq!(own, PathBuf::from("/arkham.slice/arkham-x.slice/docker-abc.scope"));
    assert_eq!(
      enclosing_from(&own).unwrap(),
      PathBuf::from("/sys/fs/cgroup/arkham.slice/arkham-x.slice"),
      "arkham's own scope is one level under the slice both services share"
    );

    // Nothing to attach to without capturing the machine: the cgroup root and
    // its direct children have the root as their parent.
    assert!(enclosing_from(Path::new("/")).is_none());
    assert!(enclosing_from(Path::new("/docker-abc.scope")).is_none());

    // A cgroup v1 layout has no `0::` line, and neither does an empty file.
    assert!(own_cgroup_path("2:cpu:/\n1:name=systemd:/\n").is_none());
    assert!(own_cgroup_path("").is_none());
  }

  /// `user_ip4` carries the address bytes in network order, so a raw read is
  /// byte-reversed from the numeric address. Getting this backwards silently
  /// routes every captured connection to the wrong host.
  #[test]
  fn addr_encoding_round_trips_through_the_kernel_layout() {
    for addr in [Ipv4Addr::LOCALHOST, Ipv4Addr::new(93, 184, 216, 34), Ipv4Addr::new(198, 51, 100, 7)] {
      assert_eq!(decode_addr(encode_addr(addr)), addr);
    }
    // Spelled out for one address so a regression in either direction fails
    // with an obvious value rather than an opaque round-trip mismatch: the
    // bytes of 127.0.0.1 in memory, read as a little-endian native integer.
    assert_eq!(encode_addr(Ipv4Addr::LOCALHOST).to_le_bytes(), [127, 0, 0, 1]);
    assert_eq!(decode_addr(u32::from_le_bytes([127, 0, 0, 1])), Ipv4Addr::LOCALHOST);
  }

  /// `user_port` holds the port in network order in its low 16 bits.
  #[test]
  fn port_encoding_round_trips_through_the_kernel_layout() {
    for port in [1u16, 53, 443, TCP_LISTEN_PORT, UDP_LISTEN_PORT, u16::MAX] {
      assert_eq!(decode_port(encode_port(port)), port);
    }
    assert_eq!(encode_port(TCP_LISTEN_PORT), u32::from(TCP_LISTEN_PORT.to_be()));
  }

  /// Bits above the low 16 are dropped. A dirty high half still decodes to the port.
  #[test]
  fn decode_port_truncates_a_dirty_high_half() {
    let port = 443u16;
    let raw = encode_port(port) | 0xA5A5_0000;
    assert_eq!(decode_port(raw), port);
    assert_eq!(decode_port(0), 0);
    assert_eq!(decode_port(u32::MAX), u16::MAX);
  }

  /// The listener's own address must decode back to the loopback address the
  /// programs rewrite destinations to.
  #[test]
  fn rewritten_destination_decodes_to_loopback() {
    let orig = OrigDst {
      ip: encode_addr(Ipv4Addr::LOCALHOST),
      port: encode_port(TCP_LISTEN_PORT),
      proto: 6,
      _pad: [0; 3],
    };
    assert_eq!(orig.socket_addr(), SocketAddr::from(([127, 0, 0, 1], TCP_LISTEN_PORT)));
  }

  /// A flow key built from an accepted connection's peer must decode back to
  /// that peer: the hook records the same tuple the listener later reads.
  #[test]
  fn flow_key_matches_the_peer_address() {
    let peer = SocketAddr::from(([93, 184, 216, 34], 54321));
    let key = FlowKey::from_peer(peer).expect("v4 peer");
    assert_eq!(decode_addr(key.ip), Ipv4Addr::new(93, 184, 216, 34));
    assert_eq!(key.port, 54321);
  }

  /// An IPv6 peer must be reported as unkeyable rather than silently keyed on
  /// a truncated address: the capture hooks are `connect4`/`recvmsg4` only, so
  /// no IPv6 flow ever carries an `OrigDst` to look up.
  #[test]
  fn flow_key_rejects_ipv6() {
    let peer = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 443));
    assert!(FlowKey::from_peer(peer).is_none());
  }

  /// The map keys and values cross the kernel boundary as raw bytes, so their
  /// sizes and offsets are an ABI with `arkham-ebpf-programs`. These assertions
  /// are what turns a silent layout drift into a build failure.
  #[test]
  fn map_layouts_are_fully_specified() {
    use std::mem::{align_of, offset_of, size_of};

    // 4 + 2 + 2 explicit padding: no room left for compiler-inserted bytes.
    assert_eq!(size_of::<FlowKey>(), 8);
    assert_eq!(align_of::<FlowKey>(), 4);
    assert_eq!(offset_of!(FlowKey, ip), 0);
    assert_eq!(offset_of!(FlowKey, port), 4);
    assert_eq!(offset_of!(FlowKey, _pad), 6);

    assert_eq!(size_of::<OrigDst>(), 12);
    assert_eq!(offset_of!(OrigDst, ip), 0);
    assert_eq!(offset_of!(OrigDst, port), 4);
    assert_eq!(offset_of!(OrigDst, proto), 8);
    assert_eq!(offset_of!(OrigDst, _pad), 9);
    assert_eq!(size_of::<Config>(), 80);
    assert_eq!(align_of::<Config>(), 8);
    assert_eq!(offset_of!(Config, proxy_pid), 0);
    assert_eq!(offset_of!(Config, _pad), 4);
    assert_eq!(offset_of!(Config, proxy_cgroup), 8);
    assert_eq!(offset_of!(Config, tcp_port), 16);
    assert_eq!(offset_of!(Config, udp_port), 20);
    assert_eq!(offset_of!(Config, netns_cookie), 24);
    assert_eq!(offset_of!(Config, bypass_count), 32);
    assert_eq!(offset_of!(Config, bypass_nets), 36);
    assert_eq!(offset_of!(Config, bypass_lens), 68);
    assert_eq!(offset_of!(Config, _pad2), 76);
  }

  #[test]
  fn config_validation_rejects_zero_ports() {
    let pid = SelfExclusion::Proxy.pid();
    let cgroup = own_cgroup_id();
    let cookie = own_netns_cookie();
    Config::from_bypass(pid, cgroup, TCP_LISTEN_PORT, UDP_LISTEN_PORT, cookie, &[]).expect("a fully populated config builds");
    Config::from_bypass(pid, cgroup, 0, UDP_LISTEN_PORT, cookie, &[]).unwrap_err();
    Config::from_bypass(pid, cgroup, TCP_LISTEN_PORT, 0, cookie, &[]).unwrap_err();
  }

  /// Bypass networks are masked to their prefix on the way in: the kernel
  /// compares top bits, so a host address in `--ebpf-bypass` must still match
  /// its range. Prefixes outside `1..=32` and overlong lists are refused
  /// rather than written half-meaningfully.
  #[test]
  fn bypass_entries_are_masked_and_validated() {
    let config = Config::from_bypass(
      1,
      2,
      TCP_LISTEN_PORT,
      UDP_LISTEN_PORT,
      3,
      &[(Ipv4Addr::new(10, 89, 0, 4), 16), (Ipv4Addr::new(172, 21, 0, 2), 32)],
    )
    .expect("two valid bypasses build");
    assert_eq!(config.bypass_count, 2);
    assert_eq!(config.bypass_nets[0], u32::from(Ipv4Addr::new(10, 89, 0, 0)));
    assert_eq!(config.bypass_lens[0], 16);
    assert_eq!(config.bypass_nets[1], u32::from(Ipv4Addr::new(172, 21, 0, 2)));
    assert_eq!(config.bypass_lens[1], 32);

    for bad in [(Ipv4Addr::new(10, 0, 0, 0), 0), (Ipv4Addr::new(10, 0, 0, 0), 33)] {
      Config::from_bypass(1, 2, TCP_LISTEN_PORT, UDP_LISTEN_PORT, 3, &[bad]).unwrap_err();
    }
    let too_many = vec![(Ipv4Addr::new(10, 0, 0, 0), 8); MAX_BYPASS + 1];
    Config::from_bypass(1, 2, TCP_LISTEN_PORT, UDP_LISTEN_PORT, 3, &too_many).unwrap_err();
  }

  /// `--ebpf-bypass` parsing accepts host addresses with a prefix and rejects
  /// everything else — most importantly prefix `0`, which would bypass all
  /// capture.
  #[test]
  fn bypass_cidr_parsing_accepts_ranges_and_rejects_nonsense() {
    assert_eq!(parse_bypass_cidr("10.89.0.0/16"), Ok((Ipv4Addr::new(10, 89, 0, 0), 16)));
    assert_eq!(parse_bypass_cidr("172.21.0.2/32"), Ok((Ipv4Addr::new(172, 21, 0, 2), 32)));
    for bad in ["10.89.0.0", "10.89.0.0/0", "10.89.0.0/33", "10.89.0.0/abc", "999.0.0.0/16", ""] {
      assert!(parse_bypass_cidr(bad).is_err(), "`{bad}` must not parse");
    }
  }

  /// The podman scan reads `subnet` values out of network definition files
  /// and skips what it cannot parse, so one odd file never hides the rest.
  #[test]
  fn podman_subnets_are_scanned_from_definition_files() {
    let content = r#"{"subnets": [{"subnet": "10.89.0.0/24", "gateway": "10.89.0.1"},
      {"subnet": "fd00::/64", "gateway": "fd00::1"}, {"subnet": "nonsense"}]}"#;
    assert_eq!(podman_subnets_in(content), vec![(Ipv4Addr::new(10, 89, 0, 0), 24)]);
    assert_eq!(podman_subnets_in("{}"), [] as [(std::net::Ipv4Addr, u8); 0]);
  }

  /// The bypass file holds one CIDR per line: comments and blanks are
  /// ignored, and one bad line never hides the rest.
  #[test]
  fn bypass_file_parsing_ignores_comments_and_bad_lines() {
    let path = Path::new("bypass");
    let content = "# podman networks, rewritten by the agent entrypoint\n\n10.89.0.0/16\n  172.21.0.2/32  \nnope\n10.0.0.0/0\n";
    assert_eq!(
      parse_bypass_file(content, path),
      vec![(Ipv4Addr::new(10, 89, 0, 0), 16), (Ipv4Addr::new(172, 21, 0, 2), 32)]
    );
    assert_eq!(parse_bypass_file("", path), [] as [(std::net::Ipv4Addr, u8); 0]);
    assert_eq!(parse_bypass_file("# only a comment\n", path), [] as [(std::net::Ipv4Addr, u8); 0]);
  }

  /// Assembling the bypass keeps every explicit entry no matter what the
  /// machine contributes: file entries and locals/podman ranges only fill
  /// the room the explicit list leaves, so an override can never be pushed
  /// out by a host with many interfaces. The assertions avoid naming machine
  /// state, which differs per host — they pin the explicit and file entries'
  /// survival, not the automatic tail.
  #[test]
  fn bypass_assembly_keeps_explicit_entries_within_capacity() {
    let explicit = vec![(Ipv4Addr::new(198, 51, 100, 7), 32), (Ipv4Addr::new(198, 51, 100, 7), 32)];
    let file = vec![(Ipv4Addr::new(10, 89, 0, 0), 16), (Ipv4Addr::new(198, 51, 100, 7), 32)];
    let assembled = build_bypass(explicit, file);
    assert!(
      assembled.contains(&(Ipv4Addr::new(198, 51, 100, 7), 32)),
      "explicit entries survive any machine state"
    );
    assert!(
      assembled.contains(&(Ipv4Addr::new(10, 89, 0, 0), 16)),
      "file entries survive any machine state"
    );
    assert_eq!(
      assembled
        .iter()
        .filter(|entry| **entry == (Ipv4Addr::new(198, 51, 100, 7), 32))
        .count(),
      1,
      "duplicates collapse to one entry, including across tiers"
    );
    assert!(assembled.len() <= MAX_BYPASS, "lower tiers fill only the room explicit leaves");

    // More explicit entries than the programs carry stay whole here and fail
    // loudly at `from_bypass`, instead of silently dropping an override.
    let many: Vec<(Ipv4Addr, u8)> = (0..10u8).map(|i| (Ipv4Addr::new(198, 51, 100, i), 32)).collect();
    let kept = build_bypass(many.clone(), Vec::new());
    assert!(
      many.iter().all(|entry| kept.contains(entry)),
      "no explicit entry is dropped by assembly"
    );
    assert!(
      Config::from_bypass(1, 2, TCP_LISTEN_PORT, UDP_LISTEN_PORT, 3, &kept).is_err(),
      "the overflow surfaces as an error, not a silent cut"
    );
  }

  /// Production must always exclude its own process: without it, arkham's
  /// upstream dials are captured and fed back into its own listener, forever.
  #[test]
  fn production_excludes_its_own_process() {
    let pid = SelfExclusion::Proxy.pid();
    assert_ne!(pid, 0, "tgid 0 is the idle task, which never issues socket calls");
    assert_eq!(pid, std::process::id());
    // The escape hatch is a distinct, deliberately-spelled value.
    assert_eq!(SelfExclusion::Nothing.pid(), 0);
    assert_ne!(SelfExclusion::Proxy, SelfExclusion::Nothing);
  }

  /// The embedded object must survive aya's own call relocation.
  ///
  /// This is the first thing `Ebpf::load` does after reading the ELF, and it
  /// needs no privileges — so it is the one part of the load path that can be
  /// checked in a normal `cargo test`. It catches the failure mode where a
  /// kernel helper is called through a hand-written `extern` block instead of
  /// aya's generated wrapper: the call keeps a `R_BPF_64_32` relocation that
  /// aya then tries to resolve as a *pc-relative internal call*, failing with
  /// `UnknownFunction` for the instruction's own address. The real thing then
  /// only surfaces as a confusing connect timeout inside a root-only live
  /// test.
  #[test]
  fn programs_relocate_their_calls() {
    let mut obj = aya_obj::Object::parse(PROGRAMS).expect("embedded object parses as ELF");
    let text_sections = obj.functions.keys().map(|(section_index, _)| *section_index).collect();
    obj
      .relocate_calls(&text_sections)
      .expect("every call must resolve; an unresolved helper extern is the usual cause");

    // All three attachment points must be present: a rename that drifted from
    // `attach()` would otherwise only fail on a root-only run.
    for name in ["connect4", "recvmsg4", "capture_egress"] {
      assert!(obj.programs.contains_key(name), "program `{name}` missing from the object");
    }
  }
}
