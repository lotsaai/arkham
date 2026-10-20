//! Live capture tests: these need root (`bpf(2)` plus cgroup writes) and are
//! run explicitly through `mise run test:ebpf`.
//!
//! They exercise the real kernel path — programs loaded and attached to a
//! cgroup the test creates — so they are the only tests that can catch a wrong
//! map layout, a wrong byte order, or an attach type the kernel rejects.
//!
//! Two things make them work as ordinary in-process tests rather than needing a
//! separate client process:
//!
//! - `SelfExclusion::Nothing` disables the PID check. With the real PID, this
//!   process's own client sockets would be "arkham's own" and never captured.
//! - the stub upstream sits on loopback, which the programs never rewrite. So
//!   arkham's own dials cannot be captured even with the PID check disabled:
//!   there is no loop for them to fall into.
//!
//! Every connect target is TEST-NET-2 (`198.51.100.0/24`), not loopback: the
//! programs deliberately skip loopback destinations, so a loopback client would
//! prove nothing about capture.

#![cfg(test)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arkham_config::config::ProxyCfg;
use arkham_config::grants::{Credential, EndpointScope, Grant, ResolvedConfig, Scheme};
use arkham_proxy::ProxyState;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::{Error, Options, SelfExclusion, run_ebpf_with};

/// Serializes the live tests: each one creates a host-wide cgroup.
static LIVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A named network namespace for one live test, deleted on drop.
struct TestNetns(String);

impl TestNetns {
  /// Create `/var/run/netns/<name>` via `ip netns add`, so `ip netns exec`
  /// can run helpers inside it.
  fn create(suffix: &str) -> Self {
    let name = format!("arkham-test-{}-{suffix}", std::process::id());
    run_ip(&["netns", "add", &name]);
    Self(name)
  }

  /// Run `command` inside this namespace, capturing its stdout.
  fn exec(&self, command: &str) -> std::process::Output {
    // `timeout` bounds the child itself: the awaiting side gives up on its own
    // deadline, but a wedged child would otherwise linger in the namespace and
    // hold up its removal.
    run_ip(&["netns", "exec", &self.0, "timeout", "10", "bash", "-c", command])
  }
}

impl Drop for TestNetns {
  fn drop(&mut self) {
    // Best-effort: a leftover namespace dies with its last process anyway.
    let _ = std::process::Command::new("ip").args(["netns", "del", &self.0]).output();
  }
}

/// Run `ip` with arguments, panicking on failure: live tests need a real
/// kernel setup, and a failed setup cannot yield a meaningful assertion.
fn run_ip(args: &[&str]) -> std::process::Output {
  std::process::Command::new("ip")
    .args(args)
    .output()
    .unwrap_or_else(|err| panic!("run ip {args:?}: {err}"))
}

/// Assert one `ip` invocation succeeded, with its stderr on failure.
fn expect_ip(args: &[&str]) {
  let out = run_ip(args);
  assert!(
    out.status.success(),
    "`ip {}` failed: {}",
    args.join(" "),
    String::from_utf8_lossy(&out.stderr)
  );
}

/// A cgroup for one live test, removed on drop.
///
/// The programs are attached here, so only processes the test places in it are
/// captured. That is the whole point of the eBPF backend, and it keeps the test
/// from disturbing the machine it runs on.
struct TestCgroup(std::path::PathBuf);

impl TestCgroup {
  /// Create `/sys/fs/cgroup/arkham-test-<pid>-<suffix>`.
  fn create(suffix: &str) -> Self {
    let path = std::path::PathBuf::from(format!("/sys/fs/cgroup/arkham-test-{}-{suffix}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap_or_else(|err| panic!("create cgroup {}: {err}", path.display()));
    Self(path)
  }

  fn path(&self) -> &std::path::Path {
    &self.0
  }

  /// Move `pid` into this cgroup, so its sockets get captured.
  fn admit(&self, pid: u32) {
    std::fs::write(self.0.join("cgroup.procs"), pid.to_string())
      .unwrap_or_else(|err| panic!("move pid {pid} into {}: {err}", self.0.display()));
  }
}

impl Drop for TestCgroup {
  fn drop(&mut self) {
    // The live test admits itself here. A cgroup that still has members
    // cannot be removed, so move them to the parent first. Programs must
    // already be detached: `stop_capture` joins the capture task before
    // this drop runs.
    if let Some(parent) = self.0.parent()
      && let Ok(procs) = std::fs::read_to_string(self.0.join("cgroup.procs"))
    {
      for pid in procs.split_whitespace() {
        let _ = std::fs::write(parent.join("cgroup.procs"), pid);
      }
    }
    let _ = std::fs::remove_dir(&self.0);
  }
}

/// A `ProxyState` with the given grants.
fn state_with(grants: Vec<Grant>, ca: &arkham_pki::ca::CertAuthority) -> Arc<ProxyState> {
  Arc::new(
    ProxyState::new(
      ResolvedConfig {
        proxy: ProxyCfg {
          listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
          ca_file: None,
          ssh_host_key: None,
          ssh_known_hosts: None,
          root_certs: Vec::new(),
          handshake_timeout_secs: 10,
        },
        grants,
        plugins: Vec::new(),
      },
      ca,
    )
    .unwrap(),
  )
}

/// Start capture, move this process into its cgroup, and fail loudly if the
/// attach never came up.
async fn start_capture(
  cgroup: &TestCgroup,
  state: Arc<ProxyState>,
  upstream_override: Option<SocketAddr>,
  bypass: Vec<(Ipv4Addr, u8)>,
  bypass_file: Option<PathBuf>,
) -> JoinHandle<Result<(), Error>> {
  let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
  let capture = tokio::spawn(run_ebpf_with(
    Options {
      cgroup: Some(cgroup.path().to_path_buf()),
      upstream_override,
      self_exclusion: SelfExclusion::Nothing,
      ready: Some(ready_tx),
      bypass,
      bypass_file,
      ..Options::default()
    },
    state,
  ));
  // Surface attach errors here rather than at connect time. The three outcomes
  // are distinct and all matter: signalled means attached and accepting; a
  // dropped sender means the task died before it was ready; a timeout means it
  // is still not ready. Without telling the last two apart, a load or attach
  // failure shows up as an unrelated connect timeout — and a test asserting
  // that traffic is *not* captured would pass vacuously.
  match tokio::time::timeout(Duration::from_secs(5), ready_rx).await {
    Ok(Ok(())) => {}
    Ok(Err(_)) => {
      let result = capture.await.expect("capture task");
      panic!("capture task died before it was ready: {result:?}");
    }
    Err(_) => {
      let result = capture.await.expect("capture task");
      panic!("capture task not ready after 5s: {result:?}");
    }
  }
  cgroup.admit(std::process::id());
  capture
}

/// Abort the capture task and wait until it has dropped.
///
/// Dropping the `JoinHandle` does not unload the programs. They stay
/// attached to the test cgroup until the task itself is dropped, and the
/// cgroup directory cannot be removed while they are. Joining after abort
/// runs that drop before [`TestCgroup`] is dropped.
async fn stop_capture(capture: JoinHandle<Result<(), Error>>) {
  capture.abort();
  let _ = capture.await;
}

/// The TCP point of the backend: a captured connection is MITM'd, with
/// fake→real on the request and real→fake on the response.
///
/// The eBPF twin of `tproxy_live_tcp_mitm_substitutes`. The guest targets
/// TEST-NET-2 so the kernel capture path is real, while `upstream_override`
/// remaps arkham's own dial to a loopback stub.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes)"]
#[expect(clippy::too_many_lines, reason = "linear live-test script, split would obscure the flow")]
async fn ebpf_live_tcp_mitm_substitutes() {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const SNI: &str = "testebpf.invalid";
  const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

  let _live = LIVE_LOCK.lock().await;

  arkham_pki::ca::install_crypto_provider();
  let ca = arkham_pki::ca::CertAuthority::generate().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let bundle = dir.path().join("arkham-ca.pem");
  std::fs::write(&bundle, ca.cert_pem()).unwrap();
  let ca_der = ca.cert_der().clone();
  let stub_cert = arkham_pki::ca::generate_domain_cert(SNI, &ca).unwrap();
  let stub_acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&stub_cert.server_config));
  let stub = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  let stub_port = stub.local_addr().unwrap().port();

  let state = state_with(
    vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Https,
        host: SNI.parse().unwrap(),
        port: stub_port,
        client_cert: None,
        client_key: None,
        root_cert: Some(bundle),
        guest_tls: arkham_config::grants::GuestTlsMode::Tls,

        upstream_port: None,
      }],
      pattern: None,
      oauth2: None,
    }],
    &ca,
  );

  let cgroup = TestCgroup::create("tcp");
  let capture = start_capture(
    &cgroup,
    state,
    Some(SocketAddr::from((Ipv4Addr::LOCALHOST, stub_port))),
    Vec::new(),
    None,
  )
  .await;

  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = stub_acceptor.accept(conn).await.unwrap();
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
      let n = tls.read(&mut chunk).await.unwrap();
      head.extend_from_slice(&chunk[..n]);
    }
    let head_str = String::from_utf8(head).unwrap();
    // The upstream sees the real value: substitution happened in flight.
    assert!(head_str.contains(&format!("Bearer {VALUE}")), "{head_str}");
    let body = format!("echo:{VALUE}");
    tls
      .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
      .await
      .unwrap();
    tls.shutdown().await.unwrap();
  });

  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca_der).unwrap();
  let connector = tokio_rustls::TlsConnector::from(Arc::new(
    rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
  ));

  let tcp = match tokio::time::timeout(
    Duration::from_secs(10),
    tokio::net::TcpStream::connect(SocketAddr::from((DST, stub_port))),
  )
  .await
  {
    Ok(Ok(tcp)) => tcp,
    state => {
      let result = capture.await.expect("capture task");
      panic!("guest connect failed ({state:?}); capture task result: {result:?}");
    }
  };
  let server_name = rustls::pki_types::ServerName::try_from(SNI.to_string()).unwrap();
  let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
    .await
    .unwrap()
    .unwrap();
  tls
    .write_all(format!("GET /x HTTP/1.1\r\nHost: {SNI}\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
    .await
    .unwrap();

  let mut resp = Vec::new();
  let mut chunk = [0u8; 4096];
  while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
      .await
      .unwrap()
      .unwrap();
    resp.extend_from_slice(&chunk[..n]);
  }
  let head_end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
  let mut body = Vec::from(&resp[head_end..]);
  let expect = format!("echo:{FAKE}");
  while body.len() < expect.len() {
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
      .await
      .unwrap()
      .unwrap();
    body.extend_from_slice(&chunk[..n]);
  }
  // The response came back redacted: the guest never sees the real value.
  assert_eq!(body, expect.as_bytes());
  stub_task.await.unwrap();
  stop_capture(capture).await;
}

/// Connected UDP is relayed both ways, and the reply the client observes must
/// carry the *original* destination as its source.
///
/// That last part is the `recvmsg4` hook, and it is required: the reply
/// physically arrives from arkham's loopback listener, while the client's socket
/// is connected to TEST-NET-2, so without the rewrite the kernel would filter
/// it as a source mismatch and the receive below would time out.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes)"]
async fn ebpf_live_udp_relay_roundtrip() {
  const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);

  let _live = LIVE_LOCK.lock().await;

  arkham_pki::ca::install_crypto_provider();
  let ca = arkham_pki::ca::CertAuthority::generate().unwrap();
  // No grants: the UDP leg is a relay, and substitution plays no part in it.
  let state = state_with(Vec::new(), &ca);

  let stub = tokio::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  let stub_addr = stub.local_addr().unwrap();
  let stub_port = stub_addr.port();
  tokio::spawn(async move {
    let mut buf = [0u8; 2048];
    loop {
      let Ok((n, from)) = stub.recv_from(&mut buf).await else {
        return;
      };
      let mut reply = b"echo:".to_vec();
      reply.extend_from_slice(&buf[..n]);
      let _ = stub.send_to(&reply, from).await;
    }
  });

  let cgroup = TestCgroup::create("udp");
  let capture = start_capture(&cgroup, state, Some(stub_addr), Vec::new(), None).await;

  // Connected socket: only `connect()`ed UDP is captured at all, so this is the
  // shape the backend supports. An unconnected `sendto` would never be
  // redirected, which is why DNS is documented as untouched.
  let client = tokio::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  client.connect(SocketAddr::from((DST, stub_port))).await.unwrap();

  client.send(b"probe").await.unwrap();
  let mut reply = [0u8; 2048];
  let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut reply))
    .await
    .expect("relay reply within 5s; a timeout here usually means recvmsg4 did not restore the source")
    .unwrap();
  assert_eq!(&reply[..n], b"echo:probe");
  stop_capture(capture).await;
}

/// A captured connection with no matching grant is spliced byte-for-byte.
///
/// The property that keeps everything else on the network working: capture
/// must redirect, but it must not touch the bytes when no rule applies. Also
/// proves the capture path itself is live — the guest reaches a TEST-NET-2
/// address with no route, so the only way the sentinel arrives is that
/// `connect4` redirected it to arkham's listener.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes)"]
async fn ebpf_live_ungranted_tcp_splices_byte_identical() {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

  const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);
  const SENTINEL: &[u8] = b"plain-splice-sentinel";

  let _live = LIVE_LOCK.lock().await;

  arkham_pki::ca::install_crypto_provider();
  let ca = arkham_pki::ca::CertAuthority::generate().unwrap();
  // No grants at all, so nothing can match and the splice path is forced.
  let state = state_with(Vec::new(), &ca);

  let stub = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let mut buf = [0u8; 128];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], SENTINEL);
    // Echo back: the client must see the identical bytes.
    conn.write_all(&buf[..n]).await.unwrap();
    conn.shutdown().await.unwrap();
  });

  let cgroup = TestCgroup::create("splice");
  let capture = start_capture(
    &cgroup,
    state,
    Some(SocketAddr::from((Ipv4Addr::LOCALHOST, stub_port))),
    Vec::new(),
    None,
  )
  .await;

  let mut conn = tokio::time::timeout(
    Duration::from_secs(10),
    tokio::net::TcpStream::connect(SocketAddr::from((DST, stub_port))),
  )
  .await
  .expect("captured connect within 10s")
  .expect("connect4 must have redirected this to arkham's listener");
  conn.write_all(SENTINEL).await.unwrap();
  let mut echoed = vec![0u8; SENTINEL.len()];
  let _ = tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut echoed))
    .await
    .expect("spliced reply within 10s")
    .unwrap();
  assert_eq!(echoed, SENTINEL, "splice must be byte-identical");
  stub_task.await.unwrap();
  stop_capture(capture).await;
}

/// Unconnected `sendto` UDP — the shape every DNS resolver uses — is never
/// captured or relayed.
///
/// Capture is entered at `connect()`, so a socket that never connects has no
/// `ORIG_DST` entry: `capture_egress` records nothing for it and arkham never
/// learns of the flow. The observable is the reply's *source* — a `sendto` the
/// backend had relayed would come back from arkham's listener, not from the
/// stub; receiving it from the stub's own address proves nothing sat in the
/// middle.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes)"]
async fn ebpf_live_unconnected_udp_passes_through() {
  const SENTINEL: &[u8] = b"dns-shaped-sentinel";

  let _live = LIVE_LOCK.lock().await;

  arkham_pki::ca::install_crypto_provider();
  let ca = arkham_pki::ca::CertAuthority::generate().unwrap();
  let state = state_with(Vec::new(), &ca);

  // Loopback, and reached without `connect()`: the programs skip loopback
  // destinations, so nothing here can be rewritten — the point is that the
  // datagram still flows end to end with its own addressing intact.
  let stub = tokio::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  let stub_addr = stub.local_addr().unwrap();
  let stub_task = tokio::spawn(async move {
    let mut buf = [0u8; 2048];
    let (n, from) = stub.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], SENTINEL, "the stub must receive the untouched datagram");
    let _ = stub.send_to(b"dns-shaped-reply", from).await;
  });

  let cgroup = TestCgroup::create("udp-passthrough");
  let capture = start_capture(&cgroup, state, None, Vec::new(), None).await;

  // No `connect()` anywhere: this socket must reach the stub directly.
  let client = tokio::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  client.send_to(SENTINEL, stub_addr).await.unwrap();
  let mut reply = [0u8; 2048];
  let (n, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut reply))
    .await
    .expect("direct reply within 5s; a timeout means the datagram was captured instead")
    .unwrap();
  assert_eq!(&reply[..n], b"dns-shaped-reply");
  assert_eq!(
    from, stub_addr,
    "reply must come from the stub itself: a relayed datagram would arrive from arkham's listener"
  );
  stub_task.await.unwrap();
  stop_capture(capture).await;
}

/// A connection from a network namespace nested under the attached cgroup is
/// never rewritten, while a connection from arkham's own namespace still is.
///
/// This is the container case the cgroup attach cannot scope by itself: a
/// compose stack or podman inside the captured process creates its own
/// network namespaces, and cgroup membership spans them all. `connect4`
/// compares the connecting socket's netns cookie against the loader's — the
/// cookie the namespace cannot fake — and leaves foreign namespaces alone.
///
/// The two legs prove both halves in one test:
///
/// - the control dials TEST-NET-2 from arkham's own namespace: a sentinel that
///   round-trips through arkham's stub proves `connect4` rewrote it, so the
///   hooks are live and the guard is on;
/// - the nested leg dials the veth peer from inside the namespace: a rewrite
///   would land on `127.0.0.1:15000` *inside that namespace*, where nothing
///   listens, and the connect would fail. Reaching the stub in arkham's
///   namespace instead proves no rewrite happened.
///
/// Needs the `ip` (iproute2) and `bash` binaries in addition to root.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes, ip netns)"]
async fn ebpf_live_nested_netns_connect_is_not_captured() {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

  const SENTINEL: &[u8] = b"nested-netns-sentinel";
  /// arkham's own netns egress target (TEST-NET-2, no route — only capture
  /// can carry the sentinel).
  const OUTER_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
  /// The veth pair linking the two namespaces.
  const VETH_OUT: &str = "veth-out";
  const VETH_IN: &str = "veth-in";
  const VETH_OUT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 250, 0, 1);
  const VETH_IN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 250, 0, 2);

  let _live = LIVE_LOCK.lock().await;

  arkham_pki::ca::install_crypto_provider();
  let ca = arkham_pki::ca::CertAuthority::generate().unwrap();
  // No grants: both legs are relays, and substitution plays no part.
  let state = state_with(Vec::new(), &ca);

  // The namespace and its veth come first: the stub below binds the veth
  // peer's address, which cannot exist before the pair does. A pair left
  // behind by an interrupted run is removed first, best-effort — `ip link
  // add` is a hard failure on a name that is already taken.
  let cgroup = TestCgroup::create("nested");
  let netns = TestNetns::create("nested");
  let _ = run_ip(&["link", "del", VETH_IN]);
  let _ = run_ip(&["link", "del", VETH_OUT]);
  expect_ip(&["link", "add", VETH_OUT, "type", "veth", "peer", "name", VETH_IN]);
  expect_ip(&["link", "set", VETH_IN, "netns", &netns.0]);
  expect_ip(&["addr", "add", "10.250.0.1/30", "dev", VETH_OUT]);
  expect_ip(&["link", "set", VETH_OUT, "up"]);
  expect_ip(&["-n", &netns.0, "addr", "add", "10.250.0.2/30", "dev", VETH_IN]);
  expect_ip(&["-n", &netns.0, "link", "set", VETH_IN, "up"]);
  expect_ip(&["-n", &netns.0, "link", "set", "lo", "up"]);

  // Nested stub: lives in arkham's namespace on the veth peer, reachable from
  // the nested namespace without anything in the middle.
  let netns_stub = tokio::net::TcpListener::bind(SocketAddr::from((VETH_OUT_ADDR, 0))).await.unwrap();
  let netns_port = netns_stub.local_addr().unwrap().port();
  let netns_task = tokio::spawn(async move {
    let (mut conn, peer) = netns_stub.accept().await.unwrap();
    assert_eq!(
      peer.ip(),
      VETH_IN_ADDR,
      "the nested netns's veth address must dial the stub directly"
    );
    let mut buf = [0u8; 4];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    conn.write_all(b"pong").await.unwrap();
    conn.shutdown().await.unwrap();
  });

  // Control stub: loopback, reached only through arkham's splice, which dials
  // it via the upstream override. Loopback is never rewritten, so arkham's own
  // dial cannot loop.
  let control_stub = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  let control_port = control_stub.local_addr().unwrap().port();
  let control_task = tokio::spawn(async move {
    let (mut conn, _) = control_stub.accept().await.unwrap();
    let mut buf = [0u8; 128];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], SENTINEL);
    conn.write_all(&buf[..n]).await.unwrap();
    conn.shutdown().await.unwrap();
  });
  let capture = start_capture(
    &cgroup,
    state,
    Some(SocketAddr::from((Ipv4Addr::LOCALHOST, control_port))),
    Vec::new(),
    None,
  )
  .await;

  // Control: arkham's own namespace is captured as always. The sentinel can
  // only come back through arkham, so this proves the hooks fire and the
  // netns guard left arkham's own namespace in capture scope.
  let mut control = tokio::time::timeout(
    Duration::from_secs(10),
    tokio::net::TcpStream::connect(SocketAddr::from((OUTER_DST, control_port))),
  )
  .await
  .expect("captured connect within 10s")
  .expect("connect4 must have redirected arkham's netns egress to its listener");
  control.write_all(SENTINEL).await.unwrap();
  let mut echoed = vec![0u8; SENTINEL.len()];
  let _ = tokio::time::timeout(Duration::from_secs(10), control.read_exact(&mut echoed))
    .await
    .expect("spliced reply within 10s")
    .unwrap();
  assert_eq!(echoed, SENTINEL, "arkham's own netns must still be captured");
  control_task.await.unwrap();

  // Nested: the same cgroup, a different network namespace. connect4 must
  // leave the dial alone, so it reaches the stub across the veth pair; a
  // rewrite would target the namespace's own loopback, where nothing
  // listens, and the probe below would fail instead of printing `pong`. The
  // dialed address is the stub's, on the veth's outer side — a namespace's
  // own address is not a target. The probe reports its own cgroup first, so
  // a child that never inherited the attached cgroup cannot make the run
  // pass vacuously: a hook that never fired proves nothing.
  let cgroup_name = cgroup.path().file_name().unwrap_or_default().to_string_lossy().to_string();
  let script = format!(
    "set -e; cat /proc/self/cgroup >&2; exec 3<>/dev/tcp/{VETH_OUT_ADDR}/{netns_port}; printf ping >&3; IFS= read -r -N 4 reply <&3; printf %s \"$reply\""
  );
  let out = tokio::time::timeout(Duration::from_secs(10), tokio::task::spawn_blocking(move || netns.exec(&script)))
    .await
    .expect("nested-netns connect within 10s; a timeout here means connect4 rewrote it to the namespace's own loopback")
    .expect("ip netns exec runs");
  assert!(
    out.status.success(),
    "nested-netns probe failed: {}",
    String::from_utf8_lossy(&out.stderr)
  );
  assert!(
    String::from_utf8_lossy(&out.stderr).contains(&cgroup_name),
    "the probe must run inside the attached cgroup `{cgroup_name}`, or the hooks never fired for it and the pass below proves nothing: {}",
    String::from_utf8_lossy(&out.stderr)
  );
  assert_eq!(
    out.stdout, b"pong",
    "the nested connection must reach the stub directly, not through arkham"
  );
  netns_task.await.unwrap();
  stop_capture(capture).await;
}

/// A destination inside a configured bypass CIDR is never rewritten: the
/// connect is refused by the kernel itself instead of fake-succeeding into
/// arkham's listener.
///
/// The podman case from the agent devenv: `10.89.0.0/16` has no route from
/// the loader netns, so a rewrite handshakes instantly and then hangs until
/// the dial budget runs out. TEST-NET-2 stands in for the podman range here,
/// assigned to `lo` after the capture starts: the closed port refuses alike
/// on every machine, so the verdict never depends on the test machine's own
/// route for the range (blackholed on some, refused on others).
/// The control leg (TEST-NET-3, outside the bypass) round-trips through
/// arkham's stub first, proving the hooks are live — without it a dead
/// capture would make the bypassed leg below pass vacuously.
///
/// Needs root like every other live test in this file.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes)"]
async fn ebpf_live_bypass_cidr_is_not_captured() {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
  /// Inside the bypass: TEST-NET-2, also assigned to `lo` below so the
  /// kernel refuses it the same way on every machine.
  const BYPASSED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
  /// The same address as a host route for the `ip` setup below.
  const BYPASSED_CIDR: &str = "198.51.100.10/32";
  /// Outside the bypass: TEST-NET-3, captured as always.
  const CONTROL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
  const SENTINEL: &[u8] = b"bypass-control-sentinel";

  let _live = LIVE_LOCK.lock().await;

  arkham_pki::ca::install_crypto_provider();
  let ca = arkham_pki::ca::CertAuthority::generate().unwrap();
  // No grants: both legs are relays, and substitution plays no part.
  let state = state_with(Vec::new(), &ca);

  let stub = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let mut buf = [0u8; 128];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], SENTINEL);
    conn.write_all(&buf[..n]).await.unwrap();
    conn.shutdown().await.unwrap();
  });

  let cgroup = TestCgroup::create("bypass");
  let capture = start_capture(
    &cgroup,
    state,
    Some(SocketAddr::from((Ipv4Addr::LOCALHOST, stub_port))),
    vec![(Ipv4Addr::new(198, 51, 100, 0), 24)],
    None,
  )
  .await;

  // The bypassed address answers locally: assigning it to `lo` after the
  // capture started means the loader's own-address discovery cannot have
  // seen it — only the configured bypass covers it — and the closed port
  // refuses alike on every machine, whatever the ambient route for
  // TEST-NET-2 does (blackholed here, refused elsewhere). A stale address
  // from an interrupted run is removed first, best-effort.
  let _ = run_ip(&["addr", "del", BYPASSED_CIDR, "dev", "lo"]);
  expect_ip(&["addr", "add", BYPASSED_CIDR, "dev", "lo"]);

  // Control: outside the bypass the sentinel only comes back through arkham,
  // so this proves `connect4` rewrote it and the hooks are live.
  let mut control = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(SocketAddr::from((CONTROL, stub_port))))
    .await
    .expect("captured connect within 10s")
    .expect("connect4 must still rewrite destinations outside the bypass");
  control.write_all(SENTINEL).await.unwrap();
  let mut echoed = vec![0u8; SENTINEL.len()];
  let _ = tokio::time::timeout(Duration::from_secs(10), control.read_exact(&mut echoed))
    .await
    .expect("spliced reply within 10s")
    .unwrap();
  assert_eq!(echoed, SENTINEL, "destinations outside the bypass must still be captured");
  stub_task.await.unwrap();
  // Bypassed: the address is local now, so the kernel refuses the closed
  // port itself — the same verdict on every machine, whatever the ambient
  // route for TEST-NET-2 does. A rewrite would have handshaked instead (the
  // listener is up — the control just proved it), turning this `expect_err`
  // into a failure. The timeout only bounds the wait against a broken hook.
  let bypassed = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(SocketAddr::from((BYPASSED, stub_port)))).await;
  let err = bypassed
    .expect("a bypassed destination must fail fast against its own closed port")
    .expect_err("a bypassed destination must not be rewritten to arkham's listener");
  assert!(
    err.raw_os_error().is_some(),
    "the kernel reports its own errno for a bypassed dial: {err}"
  );
  // Best-effort: the next run removes a stale address up front anyway.
  let _ = run_ip(&["addr", "del", BYPASSED_CIDR, "dev", "lo"]);
  stop_capture(capture).await;
}

/// A connect at this netns's own non-loopback address reaches its listener
/// directly: no `ORIG_DST` entry, no proxy relay.
///
/// The pasta case from the agent devenv: podman relays dial the devenv by
/// bridge IP, and rewriting those dials sends every local connection on a
/// double hop through arkham — coupling local connectivity to proxy health.
/// The bypassed address is discovered, not configured: the loader lists its
/// own non-loopback addresses into the bypass itself, so the test names no
/// explicit CIDR and the veth pair stands in for the compose bridge.
///
/// The recorder on loopback is the tripwire for a relay: with an upstream
/// override set, a captured dial would land on the recorder, never on the
/// real stub. Needs `ip` and root like the nested-netns test above.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes, veth pair)"]
async fn ebpf_live_local_address_reaches_listener_directly() {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

  const VETH_OUT: &str = "veth-loc";
  const VETH_IN: &str = "veth-loc-peer";
  const VETH_OUT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 251, 0, 1);

  let _live = LIVE_LOCK.lock().await;

  arkham_pki::ca::install_crypto_provider();
  let ca = arkham_pki::ca::CertAuthority::generate().unwrap();
  // No grants: a captured dial would take the splice path to the override.
  let state = state_with(Vec::new(), &ca);

  // The pair first: the stub binds the outer address, and the loader must see
  // the address at startup to bypass it. Names distinct from the nested test
  // above, removed best-effort in case an interrupted run left them behind.
  let cgroup = TestCgroup::create("local-bypass");
  let _ = run_ip(&["link", "del", VETH_IN]);
  let _ = run_ip(&["link", "del", VETH_OUT]);
  expect_ip(&["link", "add", VETH_OUT, "type", "veth", "peer", "name", VETH_IN]);
  expect_ip(&["addr", "add", "10.251.0.1/30", "dev", VETH_OUT]);
  expect_ip(&["link", "set", VETH_OUT, "up"]);

  // The real stub on the netns's own address.
  let stub = TcpListener::bind(SocketAddr::from((VETH_OUT_ADDR, 0))).await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let stub_task = tokio::spawn(async move {
    let (mut conn, peer) = tokio::time::timeout(Duration::from_secs(10), stub.accept())
      .await
      .expect("direct connect within 10s; a timeout means connect4 rewrote the dial to arkham's listener")
      .unwrap();
    assert_eq!(
      peer.ip(),
      VETH_OUT_ADDR,
      "a relayed dial would arrive from arkham, not from the veth address"
    );
    let mut buf = [0u8; 4];
    conn.read_exact(&mut buf).await.unwrap();
    conn.write_all(b"pong").await.unwrap();
    conn.shutdown().await.unwrap();
  });

  // The tripwire: any captured dial lands here via the upstream override, so
  // an accept here means the bypass missed. Bound early (its address feeds
  // the capture below) but accepted late: the window must cover the dial,
  // not the seconds the loader takes to attach.
  let recorder = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.unwrap();
  let recorder_addr = recorder.local_addr().unwrap();

  // No explicit bypass: the loader's own-address discovery must cover the
  // veth address by itself.
  let capture = start_capture(&cgroup, state, Some(recorder_addr), Vec::new(), None).await;
  let recorder_task = tokio::spawn(async move { tokio::time::timeout(Duration::from_secs(2), recorder.accept()).await.is_err() });

  let mut conn = tokio::time::timeout(
    Duration::from_secs(10),
    TcpStream::connect(SocketAddr::from((VETH_OUT_ADDR, stub_port))),
  )
  .await
  .expect("direct connect within 10s")
  .expect("the netns's own address must not be captured");
  conn.write_all(b"ping").await.unwrap();
  let mut reply = [0u8; 4];
  conn.read_exact(&mut reply).await.unwrap();
  assert_eq!(&reply, b"pong");
  stub_task.await.unwrap();
  assert!(
    recorder_task.await.unwrap(),
    "the recorder must see no connection: the dial reached its listener directly, never through arkham"
  );
  stop_capture(capture).await;
}

/// A CIDR written to the bypass file mid-capture takes effect without a
/// restart: the next poll rewrites `CONFIG` and the address stops being
/// captured.
///
/// The podman lifecycle from the agent devenv: networks appear inside the
/// agent long after arkham starts, so only a runtime channel can cover them.
/// The control leg proves capture is live first; then the test writes the
/// file the way the agent entrypoint would and dials until the kernel
/// refuses the connect. Each still-captured attempt fake-succeeds and is
/// dropped unanswered, so the loop only exits when the bypass lands — and a
/// deadline bounds it, so a broken watcher fails the test instead of
/// hanging it.
///
/// Needs root like every other live test in this file.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes)"]
async fn ebpf_live_bypass_file_update_applies_without_restart() {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

  /// The "podman range": TEST-NET-1, captured until the file names it.
  const TARGET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
  /// Outside any bypass: TEST-NET-3, captured throughout.
  const CONTROL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
  const SENTINEL: &[u8] = b"bypass-file-sentinel";

  let _live = LIVE_LOCK.lock().await;

  arkham_pki::ca::install_crypto_provider();
  let ca = arkham_pki::ca::CertAuthority::generate().unwrap();
  // No grants: both legs are relays, and substitution plays no part.
  let state = state_with(Vec::new(), &ca);

  let stub = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let mut buf = [0u8; 128];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], SENTINEL);
    conn.write_all(&buf[..n]).await.unwrap();
    conn.shutdown().await.unwrap();
  });

  // The file starts without the range: everything is captured.
  let dir = tempfile::tempdir().unwrap();
  let file = dir.path().join("bypass");
  std::fs::write(&file, "# no podman networks yet\n").unwrap();

  let cgroup = TestCgroup::create("bypass-file");
  let capture = start_capture(
    &cgroup,
    state,
    Some(SocketAddr::from((Ipv4Addr::LOCALHOST, stub_port))),
    Vec::new(),
    Some(file.clone()),
  )
  .await;

  // Control: the sentinel only comes back through arkham, proving the hooks
  // are live before the file changes anything.
  let mut control = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(SocketAddr::from((CONTROL, stub_port))))
    .await
    .expect("captured connect within 10s")
    .expect("everything is captured while the file names nothing");
  control.write_all(SENTINEL).await.unwrap();
  let mut echoed = vec![0u8; SENTINEL.len()];
  let _ = tokio::time::timeout(Duration::from_secs(10), control.read_exact(&mut echoed))
    .await
    .expect("spliced reply within 10s")
    .unwrap();
  assert_eq!(echoed, SENTINEL);
  stub_task.await.unwrap();

  // A podman network appears: the agent rewrites the file, arkham's next poll
  // picks it up. Atomic write, like the entrypoint does.
  let tmp = dir.path().join("bypass.tmp");
  std::fs::write(&tmp, "198.51.100.0/24\n").unwrap();
  std::fs::rename(&tmp, &file).unwrap();

  let deadline = Instant::now() + Duration::from_secs(30);
  loop {
    if let Err(err) = TcpStream::connect(SocketAddr::from((TARGET, stub_port))).await {
      assert!(
        err.raw_os_error().is_some(),
        "the kernel reports its own errno once the bypass lands: {err}"
      );
      break;
    }
    // Still captured: drop the fake connection and wait for the next poll.
    assert!(Instant::now() < deadline, "bypass file update did not apply within 30s");
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
  stop_capture(capture).await;
}
