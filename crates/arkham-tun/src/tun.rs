//! TUN capture + userspace routing (sing-box role).
//!
//! Transparent capture: a TUN device + policy routing feeds guest packets
//! into a smoltcp stack (medium-ip, any-ip). TCP SYNs spawn sockets before
//! smoltcp sees them; established connections relay through mpsc channels
//! to tokio tasks that reuse the explicit-proxy MITM machinery. UDP is
//! handled outside smoltcp: DNS to the system resolver, QUIC dropped,
//! everything else relayed to its original destination.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpCidr};
use tokio::sync::{Notify, mpsc};

use crate::Error;
use crate::chan::ChanStream;
use crate::classify::{IpPacket, classify_packet};
use crate::phy::{TUN_MTU, TunPhy};
pub(crate) use crate::route::RouteGuard;
#[cfg(test)]
use crate::route::{RoutePlan, TABLE_MAIN, Undo};
use crate::route::{add_route, add_rule, capture_routes, capture_rules, capture_undos, link_index, netlink};
use crate::tracker::{NewTcpConn, TaskMsg, TcpTracker};
use crate::udp::{MAX_UDP_SESSIONS, UdpKey, udp_session_task, upstream_dns};
use arkham_proxy::{ProxyState, serve_transparent_stream};

/// `SO_MARK` for our own upstream sockets: policy routing sends marked
/// packets via the real gateway so they never loop back into TUN.
pub const FWMARK: u32 = 0x88;
const TUN_NAME: &str = "arkham0";
const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 98, 76, 1);
const TUN_PREFIX: u8 = 24;
const ROUTE_TABLE: u8 = 100;
const CHANNEL_CAP: usize = 32;

/// Create the TUN device, install policy routing, and capture forever.
///
/// # Errors
///
/// Returns an error when the TUN device cannot be opened, when policy routes
/// cannot be installed, or when the in-process stack fails to start.
pub async fn run_tun(state: Arc<ProxyState>) -> Result<(), Error> {
  run_tun_named(TUN_NAME, TUN_ADDR, true, None, state).await
}

/// Test overrides: custom interface name/addr, optional route install,
/// optional DNS upstream override (else /etc/resolv.conf).
pub(crate) async fn run_tun_named(
  name: &str,
  addr: Ipv4Addr,
  install_routes: bool,
  dns_override: Option<SocketAddr>,
  state: Arc<ProxyState>,
) -> Result<(), Error> {
  let mut config = tun::Configuration::default();
  config
    .tun_name(name)
    .address(addr)
    .netmask(Ipv4Addr::new(255, 255, 255, 0))
    .mtu(TUN_MTU)
    .up();
  let device = Arc::new(tun::create_as_async(&config).map_err(|err| Error::TunCreate { origin: err })?);
  let _guard = if install_routes {
    let handle = netlink()?;
    let tun_idx = link_index(&handle, name).await?;
    let lo_idx = link_index(&handle, "lo").await?;
    for plan in capture_routes(tun_idx, lo_idx) {
      add_route(&handle, ROUTE_TABLE, &plan).await?;
    }
    for plan in capture_rules(ROUTE_TABLE) {
      add_rule(&handle, &plan).await?;
    }
    Some(RouteGuard::new(capture_undos(ROUTE_TABLE)))
  } else {
    None
  };
  let dns_upstream = if let Some(addr) = dns_override {
    addr
  } else {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    upstream_dns(&text)
  };
  tracing::info!(tun = name, %addr, %dns_upstream, "capturing");
  run_loop(device, addr, dns_upstream, None, state).await
}

/// The capture loop: TUN ingress → smoltcp → relay/spawn/cleanup → TUN egress.
async fn run_loop(
  device: Arc<tun::AsyncDevice>,
  tun_addr: Ipv4Addr,
  dns_upstream: SocketAddr,
  upstream_override: Option<SocketAddr>,
  state: Arc<ProxyState>,
) -> Result<(), Error> {
  let mut phy = TunPhy::default();
  let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut phy, Instant::now());
  iface.set_any_ip(true);
  iface.update_ip_addrs(|addrs| {
    let _ = addrs.push(IpCidr::new(tun_addr.into(), TUN_PREFIX));
  });
  iface
    .routes_mut()
    .add_default_ipv4_route(tun_addr)
    .map_err(|_table| Error::RouteTableFull)?;
  let mut sockets = SocketSet::new(vec![]);
  let mut tracker = TcpTracker::default();
  let mut udp: HashMap<UdpKey, mpsc::Sender<Vec<u8>>> = HashMap::new();
  let mut buf = vec![0u8; 65536];
  let wake = Arc::new(Notify::new());
  loop {
    let delay = iface.poll_delay(Instant::now(), &sockets);
    let idle = delay.map_or(std::time::Duration::from_secs(1), |d| {
      std::time::Duration::from_micros(d.total_micros())
    });
    tokio::select! {
      biased;
      result = device.recv(&mut buf) => {
        let n = result?;
        ingress(Ingress {
          packet: &buf[..n],
          phy: &mut phy,
          tracker: &mut tracker,
          sockets: &mut sockets,
          udp: &mut udp,
          device: &device,
          state: &state,
          dns_upstream,
        });
      }
      // A connection task writing to the guest does not produce a TUN
      // packet. Without this, that write waits out `idle`.
      () = wake.notified() => {}
      () = tokio::time::sleep(idle) => {}
    }
    let now = Instant::now();
    iface.poll(now, &mut phy, &mut sockets);
    tracker.relay(&mut sockets);
    // Bytes relayed this turn are not on the wire until a poll sees them.
    iface.poll(now, &mut phy, &mut sockets);
    for conn in tracker.take_new(&mut sockets) {
      tokio::spawn(tun_conn_task(
        conn,
        upstream_override,
        Arc::clone(&state),
        Arc::clone(&wake),
      ));
    }
    tracker.cleanup(&mut sockets);
    while let Some(pkt) = phy.tx.pop_front() {
      device.send(&pkt).await?;
    }
  }
}

/// Per-packet ingress context: everything one TUN packet can touch.
struct Ingress<'a, 'b> {
  packet: &'a [u8],
  phy: &'a mut TunPhy,
  tracker: &'a mut TcpTracker,
  sockets: &'a mut SocketSet<'b>,
  udp: &'a mut HashMap<UdpKey, mpsc::Sender<Vec<u8>>>,
  device: &'a Arc<tun::AsyncDevice>,
  state: &'a Arc<ProxyState>,
  dns_upstream: SocketAddr,
}

fn ingress(ctx: Ingress<'_, '_>) {
  let Ingress {
    packet,
    phy,
    tracker,
    sockets,
    udp,
    device,
    state,
    dns_upstream,
  } = ctx;
  match classify_packet(packet) {
    IpPacket::Tcp { src, dst, syn } => {
      if syn && !tracker.has_socket_for(&src, &dst) {
        tracker.create_socket(src, dst, sockets);
      }
      // Feed regardless: untracked segments earn an RST from smoltcp.
      phy.rx.push_back(packet.to_vec());
    }
    IpPacket::Udp { src, dst, payload } => {
      // Nothing here terminates QUIC, so drop it: the client falls back to
      // TCP, where TLS is terminated and substitution works.
      if dst.port() == 443 {
        return;
      }
      // DNS goes to the system resolver; other UDP keeps its destination.
      let upstream = if dst.port() == 53 { dns_upstream } else { dst };
      forward_udp(udp, device, state, upstream, src, dst, payload);
    }
    IpPacket::Other => {}
  }
}

fn forward_udp(
  udp: &mut HashMap<UdpKey, mpsc::Sender<Vec<u8>>>,
  device: &Arc<tun::AsyncDevice>,
  state: &Arc<ProxyState>,
  upstream: SocketAddr,
  src: SocketAddr,
  dst: SocketAddr,
  payload: Vec<u8>,
) {
  let mut payload = payload;
  let key = (src, dst);
  if let Some(tx) = udp.get(&key) {
    match tx.try_send(payload) {
      Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => return, // UDP: drop on pressure, guest retries
      Err(mpsc::error::TrySendError::Closed(p)) => {
        payload = p;
        udp.remove(&key);
      }
    }
  }
  if udp.len() >= MAX_UDP_SESSIONS {
    udp.retain(|_, tx| !tx.is_closed());
    if udp.len() >= MAX_UDP_SESSIONS {
      return;
    }
  }
  let (tx, rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAP);
  if tx.try_send(payload).is_err() {
    return;
  }
  udp.insert(key, tx);
  tokio::spawn(udp_session_task(Arc::clone(device), upstream, src, dst, rx, state.fwmark()));
}

/// One captured TCP connection: sniff TLS vs plain, then serve through
/// the same candidate machinery as explicit CONNECT (no 200, no
/// authority check — the SNI itself is the identity).
/// `upstream_override` is a test override (DNS remap shape): dial this address
/// instead of the captured destination. None in production.
async fn tun_conn_task(conn: NewTcpConn, upstream_override: Option<SocketAddr>, state: Arc<ProxyState>, wake: Arc<Notify>) {
  let snapshot = state.snapshot();
  let dst = upstream_override.unwrap_or(conn.dst);
  let dial_host = dst.ip().to_string();
  let port = dst.port();
  let abort_tx = conn.to_guest.clone();
  let guest = ChanStream::new(conn.from_guest, conn.to_guest, wake);
  let result = serve_transparent_stream(guest, &state, &snapshot, &dial_host, port, &dial_host).await;
  if result.is_err() {
    // Dial/TLS failure: RST so the guest fails fast instead of hanging.
    let _ = abort_tx.send(TaskMsg::Abort).await;
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::IpAddr;
  use std::time::Duration;

  fn v4(ip: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(ip)), port)
  }

  use arkham_config::grants::{Credential, ResolvedConfig};
  use tokio_rustls as _;

  static LIVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

  fn live_enabled() -> bool {
    std::env::var("ARKHAM_TEST_TUN").is_ok()
  }

  fn make_tun(name: &str, addr: Ipv4Addr) -> Arc<tun::AsyncDevice> {
    let mut config = tun::Configuration::default();
    config
      .tun_name(name)
      .address(addr)
      .netmask(Ipv4Addr::new(255, 255, 255, 0))
      .mtu(1500)
      .up();
    Arc::new(tun::create_as_async(&config).unwrap())
  }

  fn test_state(grants: Vec<arkham_config::grants::Grant>, fwmark: Option<u32>) -> Arc<ProxyState> {
    arkham_pki::ca::install_crypto_provider();
    let ca = arkham_pki::ca::CertAuthority::generate().unwrap();
    let base = ProxyState::new(
      ResolvedConfig {
        proxy: arkham_config::config::ProxyCfg {
          listen: "127.0.0.1:0".parse().unwrap(),
          ca_file: None,
          root_certs: Vec::new(),
          ssh_host_key: None,
          ssh_known_hosts: None,
          handshake_timeout_secs: 10,
        },
        grants,
        plugins: Vec::new(),
      },
      &ca,
    )
    .unwrap();
    Arc::new(match fwmark {
      Some(mark) => base.with_fwmark(mark),
      None => base,
    })
  }

  #[tokio::test]
  #[ignore = "needs root + ARKHAM_TEST_TUN=1 (mutates host routes)"]
  async fn tun_live_udp_dns_roundtrip() {
    if !live_enabled() {
      return;
    }
    let _live = LIVE_LOCK.lock().await;
    // Stub resolver.
    let stub = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = stub.local_addr().unwrap();
    let stub_task = tokio::spawn(async move {
      let mut buf = [0u8; 512];
      let (n, from) = stub.recv_from(&mut buf).await.unwrap();
      assert_eq!(&buf[..n], b"QUERY-123");
      stub.send_to(b"REPLY-456", from).await.unwrap();
    });
    // Capture route for TEST-NET-2 only (no default override).
    let device = make_tun("arkhamut0", Ipv4Addr::new(10, 98, 77, 1));
    let nl = netlink().unwrap();
    let ut0 = link_index(&nl, "arkhamut0").await.unwrap();
    let ut0_route = RoutePlan {
      dst: Some((Ipv4Addr::new(198, 51, 100, 0), 24)),
      via: None,
      oif: ut0,
    };
    add_route(&nl, TABLE_MAIN, &ut0_route).await.unwrap();
    let _routes = RouteGuard::new(vec![Undo::DelRoute {
      table: TABLE_MAIN,
      plan: ut0_route,
    }]);
    let state = test_state(Vec::new(), None);
    let loop_task = tokio::spawn(run_loop(device, Ipv4Addr::new(10, 98, 77, 1), stub_addr, None, state));
    // Guest query via the kernel (proves TUN ingress + relay + egress).
    let guest = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    guest.connect(v4([198, 51, 100, 7], 53)).await.unwrap();
    guest.send(b"QUERY-123").await.unwrap();
    let mut reply = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(10), guest.recv(&mut reply))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&reply[..n], b"REPLY-456");
    stub_task.await.unwrap();
    // Join so the route guard runs before the test returns.
    loop_task.abort();
    let _ = loop_task.await;
  }

  #[tokio::test]
  #[ignore = "needs root + ARKHAM_TEST_TUN=1 (mutates host routes)"]
  #[expect(clippy::too_many_lines, reason = "linear live-test script, split would obscure the flow")]
  async fn tun_live_tcp_mitm_substitutes() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
    const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";
    const SNI: &str = "testtun.invalid";
    const DST: [u8; 4] = [198, 51, 100, 7];

    if !live_enabled() {
      return;
    }
    let _live = LIVE_LOCK.lock().await;

    arkham_pki::ca::install_crypto_provider();
    let ca = arkham_pki::ca::CertAuthority::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("arkham-ca.pem");
    std::fs::write(&bundle, ca.cert_pem()).unwrap();
    let ca_der = ca.cert_der().clone();
    let stub_cert = arkham_pki::ca::generate_domain_cert(SNI, &ca).unwrap();
    let stub_acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&stub_cert.server_config));
    // Stub on loopback: dial_override remaps arkham's upstream there (same
    // shape as the DNS remap). The guest still targets TEST-NET-2 so capture
    // is real — any host-local address would land in the kernel `local`
    // table (rule pref 0) and bypass the TUN entirely.
    let stub = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = stub.local_addr().unwrap().port();

    let grants = vec![arkham_config::grants::Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      allow: vec![arkham_config::grants::EndpointScope {
        scheme: arkham_config::grants::Scheme::Https,
        host: SNI.parse().unwrap(),
        port: stub_port,
        client_cert: None,
        client_key: None,
        root_cert: Some(bundle),
        guest_tls: arkham_config::grants::GuestTlsMode::Tls,
      }],
      pattern: None,
      oauth2: None,
    }];
    let state = Arc::new(
      ProxyState::new(
        ResolvedConfig {
          proxy: arkham_config::config::ProxyCfg {
            listen: "127.0.0.1:0".parse().unwrap(),
            ca_file: None,
            ssh_host_key: None,
            ssh_known_hosts: None,
            root_certs: Vec::new(),
            handshake_timeout_secs: 10,
          },
          grants,
          plugins: Vec::new(),
        },
        &ca,
      )
      .unwrap()
      .with_fwmark(FWMARK),
    );

    // Guest capture in main only.
    let device = make_tun("arkhamt0", Ipv4Addr::new(10, 98, 78, 1));
    let nl = netlink().unwrap();
    let tort0 = link_index(&nl, "arkhamt0").await.unwrap();
    let guest_route = RoutePlan {
      dst: Some((Ipv4Addr::new(198, 51, 100, 0), 24)),
      via: None,
      oif: tort0,
    };
    add_route(&nl, TABLE_MAIN, &guest_route).await.unwrap();
    let _routes = RouteGuard::new(vec![Undo::DelRoute {
      table: TABLE_MAIN,
      plan: guest_route,
    }]);
    let loop_task = tokio::spawn(run_loop(
      device,
      Ipv4Addr::new(10, 98, 78, 1),
      v4([127, 0, 0, 1], 53),
      Some(v4([127, 0, 0, 1], stub_port)),
      state,
    ));

    let stub_task = tokio::spawn(async move {
      use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let mut head = Vec::new();
      let mut chunk = [0u8; 4096];
      loop {
        let n = tls.read(&mut chunk).await.unwrap();
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
          break;
        }
      }
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Bearer {VALUE}")), "{head_str}");
      let body = format!("echo:{VALUE}");
      tls
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
        .await
        .unwrap();
      tls.shutdown().await.unwrap();
    });
    // Guest: TCP to the test IP, TLS SNI = grant hostname.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
      rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
    ));
    let tcp = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(v4(DST, stub_port)))
      .await
      .unwrap()
      .unwrap();
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
    loop {
      let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      resp.extend_from_slice(&chunk[..n]);
      if resp.windows(4).any(|w| w == b"\r\n\r\n") {
        break;
      }
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
    assert_eq!(body, expect.as_bytes());
    stub_task.await.unwrap();
    loop_task.abort();
    let _ = loop_task.await;
  }

  /// A guest-bound byte written while the capture loop is idle must arrive
  /// before the loop's idle wait. A full second here stacks across a NATS
  /// signing handshake until the client timer fires.
  #[tokio::test]
  #[ignore = "needs root + ARKHAM_TEST_TUN=1 (mutates host routes)"]
  async fn tun_live_idle_guest_write_is_prompt() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    if !live_enabled() {
      return;
    }
    let _live = LIVE_LOCK.lock().await;

    let stub = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    let device = make_tun("arkhami0", Ipv4Addr::new(10, 98, 79, 1));
    let nl = netlink().unwrap();
    let idx = link_index(&nl, "arkhami0").await.unwrap();
    let guest_route = RoutePlan {
      dst: Some((Ipv4Addr::new(198, 51, 100, 0), 24)),
      via: None,
      oif: idx,
    };
    add_route(&nl, TABLE_MAIN, &guest_route).await.unwrap();
    let _routes = RouteGuard::new(vec![Undo::DelRoute {
      table: TABLE_MAIN,
      plan: guest_route,
    }]);
    let state = test_state(Vec::new(), Some(FWMARK));
    let loop_task = tokio::spawn(run_loop(
      device,
      Ipv4Addr::new(10, 98, 79, 1),
      v4([127, 0, 0, 1], 53),
      Some(v4([127, 0, 0, 1], stub_port)),
      state,
    ));

    let accept = stub.accept();
    let guest = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(v4([198, 51, 100, 7], stub_port)))
      .await
      .unwrap()
      .unwrap();
    guest.set_nodelay(true).unwrap();
    let (server, _) = tokio::time::timeout(Duration::from_secs(10), accept).await.unwrap().unwrap();
    server.set_nodelay(true).unwrap();
    let mut guest = guest;
    let mut server = server;

    guest.write_all(b"ping").await.unwrap();
    let mut opened = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), server.read_exact(&mut opened))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&opened, b"ping");

    let mut samples = Vec::new();
    for step in 0..4u8 {
      tokio::time::sleep(Duration::from_millis(300)).await;
      let started = std::time::Instant::now();
      server.write_all(&[b'A' + step]).await.unwrap();
      let mut byte = [0u8; 1];
      tokio::time::timeout(Duration::from_secs(3), guest.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
      assert_eq!(byte[0], b'A' + step);
      samples.push(started.elapsed());
    }
    loop_task.abort();
    let _ = loop_task.await;
    let slow = samples.iter().any(|elapsed| *elapsed >= Duration::from_millis(200));
    assert!(!slow, "idle guest-bound byte waited on the capture loop: {samples:?}");
  }
}
