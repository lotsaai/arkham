//! Authenticated Unix-socket PROXY protocol v1 accept side.

use std::fs::Permissions;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rama::proxy::haproxy::protocol::v1;
use rama::proxy::haproxy::protocol::v2;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};
use tokio::net::{UnixListener, UnixStream};

use crate::Error;
use crate::ProxyState;
use crate::connection::Prefixed;
use crate::serve_transparent_stream;

/// Unix-domain handoff listener that admits one peer uid.
#[derive(Debug)]
pub struct HandoffListener {
  listener: UnixListener,
  allowed_uid: u32,
}

/// Bind a Unix-domain handoff listener.
///
/// Only a peer whose uid matches `allowed_uid` (the Network Extension or
/// daemon uid) is admitted. The check uses [`getpeereid`] on macOS/BSD and
/// `SO_PEERCRED` on Linux. This is not a TCP listener and not a shared
/// secret.
///
/// An existing file at `path` is removed first. The socket file is mode
/// `0o600` after bind.
///
/// # Errors
///
/// Returns an error when the path cannot be replaced, bound, or chmod'd.
///
/// [`getpeereid`]: https://man.freebsd.org/cgi/man.cgi?query=getpeereid
pub async fn bind_handoff(path: impl AsRef<Path>, allowed_uid: u32) -> Result<HandoffListener, Error> {
  let path = path.as_ref();
  match std::fs::remove_file(path) {
    Ok(()) => {}
    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
    Err(err) => return Err(err.into()),
  }
  let listener = UnixListener::bind(path)?;
  std::fs::set_permissions(path, Permissions::from_mode(0o600))?;
  Ok(HandoffListener { listener, allowed_uid })
}

/// Serve handoff connections until the listener stops.
///
/// A peer whose uid matches the listener's allowed uid and that writes a
/// PROXY protocol v1 TCP4 or TCP6 header is handed to
/// [`crate::serve_transparent_stream`] with the header destination as the
/// dial target. Any other peer or header is dropped. Accept errors are
/// logged and do not end the process.
pub async fn serve_handoff(listener: HandoffListener, state: Arc<ProxyState>) {
  let HandoffListener { listener, allowed_uid } = listener;
  loop {
    match listener.accept().await {
      Ok((stream, _)) => {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
          serve_one(stream, &state, allowed_uid).await;
        });
      }
      Err(err) => {
        tracing::debug!(?err, "handoff accept failed");
      }
    }
  }
}

fn handshake_budget(state: &ProxyState) -> Duration {
  Duration::from_secs(state.snapshot().proxy.handshake_timeout_secs)
}

async fn serve_one(stream: UnixStream, state: &ProxyState, allowed_uid: u32) {
  let peer = SocketPeer::observe(&stream, allowed_uid);
  let budget = handshake_budget(state);
  match peer.decide(stream, budget).await {
    Ok(Handoff::Serve(agent)) => {
      if let Err(err) = agent.serve(state).await {
        tracing::debug!(?err, "handoff connection failed");
      }
    }
    Ok(Handoff::Close(reason)) => {
      tracing::debug!(?reason, "handoff closed");
    }
    Err(err) => {
      tracing::debug!(?err, "handoff connection failed");
    }
  }
}

/// Kernel-attested peer identity for one accepted Unix socket.
#[derive(Debug)]
enum SocketPeer {
  Allowed,
  Forbidden { uid: u32 },
  Unproven,
}

impl SocketPeer {
  fn observe(stream: &UnixStream, allowed_uid: u32) -> Self {
    Self::from_uid(&peer_uid(stream), allowed_uid)
  }

  fn from_uid(uid: &io::Result<u32>, allowed_uid: u32) -> Self {
    match uid {
      Ok(uid) if *uid == allowed_uid => Self::Allowed,
      Ok(uid) => Self::Forbidden { uid: *uid },
      Err(_) => Self::Unproven,
    }
  }

  async fn decide<G>(self, stream: G, budget: Duration) -> Result<Handoff<G>, Error>
  where
    G: AsyncRead + Unpin,
  {
    match self {
      Self::Forbidden { uid } => Ok(Handoff::Close(CloseReason::ForbiddenPeer(uid))),
      Self::Unproven => Ok(Handoff::Close(CloseReason::UnprovenPeer)),
      Self::Allowed => read_header(stream, budget).await,
    }
  }
}

fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
  peer_ids_fd(stream.as_raw_fd()).map(|(uid, _gid)| uid)
}

#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "openbsd",
  target_os = "netbsd"
))]
fn peer_ids_fd(fd: i32) -> io::Result<(u32, u32)> {
  let mut uid: libc::uid_t = 0;
  let mut gid: libc::gid_t = 0;
  // SAFETY: `fd` is a live Unix socket borrowed from `UnixStream` for this call.
  let rc = unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) };
  if rc == 0 { Ok((uid, gid)) } else { Err(io::Error::last_os_error()) }
}

#[cfg(target_os = "linux")]
fn peer_ids_fd(fd: i32) -> io::Result<(u32, u32)> {
  let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
  // A length that does not fit `socklen_t` is an unproven peer. `from_uid`
  // maps this error there. It is not a reason to guess a uid.
  let Ok(expected) = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()) else {
    return Err(io::Error::other("ucred length does not fit socklen_t"));
  };
  let mut len = expected;
  // SAFETY: `fd` is a live Unix socket borrowed from `UnixStream` for this
  // call. `cred` and `len` are valid for a `SO_PEERCRED` `ucred` write.
  let rc = unsafe {
    libc::getsockopt(
      fd,
      libc::SOL_SOCKET,
      libc::SO_PEERCRED,
      std::ptr::from_mut(&mut cred).cast(),
      &raw mut len,
    )
  };
  if rc != 0 {
    return Err(io::Error::last_os_error());
  }
  // A short write would leave the zeroed uid in place. That uid is root.
  if len != expected {
    return Err(io::Error::other("SO_PEERCRED returned a short credential"));
  }
  Ok((cred.uid, cred.gid))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Destination(SocketAddr);

impl Destination {
  const fn new(ip: IpAddr, port: u16) -> Self {
    Self(SocketAddr::new(ip, port))
  }
}

enum Handoff<G> {
  Serve(Agent<G>),
  Close(CloseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReason {
  ForbiddenPeer(u32),
  UnprovenPeer,
  MissingHeader,
  Malformed,
  Version2,
  Unknown,
  TimedOut,
}

#[must_use = "drop closes the client without dialing"]
struct Agent<G> {
  destination: Destination,
  stream: Prefixed<G>,
}

impl<G> Agent<G>
where
  G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  async fn serve(self, state: &ProxyState) -> Result<(), Error> {
    // The header carries the original destination. It does not select a
    // project: Linux attribution is the cgroup id on the captured flow, and
    // this listener keeps the process snapshot.
    let snapshot = state.snapshot();
    let dial_host = self.destination.0.ip().to_string();
    let port = self.destination.0.port();
    serve_transparent_stream(self.stream, state, snapshot.as_ref(), &dial_host, port, &dial_host).await
  }
}

#[derive(Debug, PartialEq, Eq)]
enum Prefix {
  Pending,
  Tcp { destination: Destination, header_len: usize },
  Malformed,
  Version2,
  Unknown,
}

fn classify(buf: &[u8]) -> Prefix {
  if buf.is_empty() {
    return Prefix::Pending;
  }
  let sig = v2::PROTOCOL_PREFIX;
  if buf.starts_with(sig) {
    return Prefix::Version2;
  }
  if buf.len() < sig.len() && sig.starts_with(buf) {
    return Prefix::Pending;
  }
  match v1::Header::try_from(buf) {
    Ok(header) => match header.addresses {
      v1::Addresses::Tcp4(ip) => tcp_prefix(
        buf,
        Destination::new(IpAddr::V4(ip.destination_address), ip.destination_port),
        header.header.len(),
      ),
      v1::Addresses::Tcp6(ip) => tcp_prefix(
        buf,
        Destination::new(IpAddr::V6(ip.destination_address), ip.destination_port),
        header.header.len(),
      ),
      v1::Addresses::Unknown => Prefix::Unknown,
    },
    Err(err) if header_needs_more(&err) => Prefix::Pending,
    Err(_) => Prefix::Malformed,
  }
}

/// More bytes can still change this result.
///
/// `HeaderTooLong` is terminal, so a run of bytes with no `\r` stops when
/// rama says the header overflowed. `Partial`, `MissingPrefix`, and
/// `MissingNewLine` mean the line is not finished. Other incomplete errors,
/// such as `PROXY TCP4\r\n`, are a line rama already cut at `\r\n`. Later
/// bytes do not change that cut, so they close instead of waiting.
fn header_needs_more(err: &v1::BinaryParseError) -> bool {
  matches!(
    err,
    v1::BinaryParseError::Parse(v1::ParseError::Partial | v1::ParseError::MissingPrefix | v1::ParseError::MissingNewLine)
  )
}

fn tcp_prefix(buf: &[u8], destination: Destination, header_len: usize) -> Prefix {
  if buf.get(header_len..).is_some() {
    Prefix::Tcp { destination, header_len }
  } else {
    Prefix::Malformed
  }
}

async fn read_header<G>(stream: G, budget: Duration) -> Result<Handoff<G>, Error>
where
  G: AsyncRead + Unpin,
{
  match tokio::time::timeout(budget, read_header_inner(stream)).await {
    Ok(decided) => decided,
    Err(_elapsed) => Ok(Handoff::Close(CloseReason::TimedOut)),
  }
}

async fn read_header_inner<G>(mut stream: G) -> Result<Handoff<G>, Error>
where
  G: AsyncRead + Unpin,
{
  let mut buf = Vec::new();
  loop {
    match classify(&buf) {
      Prefix::Pending => {
        // Socket read size, not a header limit. Classify runs on whatever
        // this returns. A short rejected preamble has to leave the socket
        // before the close, or the client sees a reset instead of EOF.
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
          let reason = if buf.is_empty() {
            CloseReason::MissingHeader
          } else {
            CloseReason::Malformed
          };
          return Ok(Handoff::Close(reason));
        }
        let Some(got) = chunk.get(..n) else {
          return Ok(Handoff::Close(CloseReason::Malformed));
        };
        buf.extend_from_slice(got);
      }
      Prefix::Tcp { destination, header_len } => {
        let Some(tail) = buf.get(header_len..) else {
          return Ok(Handoff::Close(CloseReason::Malformed));
        };
        let stream = Prefixed::new(tail.to_vec(), stream);
        return Ok(Handoff::Serve(Agent { destination, stream }));
      }
      Prefix::Malformed => return Ok(Handoff::Close(CloseReason::Malformed)),
      Prefix::Version2 => return Ok(Handoff::Close(CloseReason::Version2)),
      Prefix::Unknown => return Ok(Handoff::Close(CloseReason::Unknown)),
    }
  }
}

#[cfg(test)]
mod tests {
  use std::net::{Ipv4Addr, Ipv6Addr};
  use std::pin::Pin;
  use std::task::{Context, Poll};

  use tokio::io::ReadBuf;

  use super::*;

  struct Explode;

  impl AsyncRead for Explode {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
      Poll::Ready(Err(std::io::Error::other("read on a rejected peer")))
    }
  }

  #[tokio::test]
  async fn forbidden_and_unproven_close_without_reading() {
    let budget = Duration::from_secs(10);
    let forbidden = SocketPeer::Forbidden { uid: 42 }.decide(Explode, budget).await.unwrap();
    assert!(matches!(forbidden, Handoff::Close(CloseReason::ForbiddenPeer(42))));
    let unproven = SocketPeer::Unproven.decide(Explode, budget).await.unwrap();
    assert!(matches!(unproven, Handoff::Close(CloseReason::UnprovenPeer)));
  }

  #[cfg(target_os = "linux")]
  #[tokio::test]
  async fn so_peercred_reports_the_process_uid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("handoff.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let client_path = path.clone();
    let client = tokio::spawn(async move { UnixStream::connect(client_path).await.unwrap() });
    let (server, _) = listener.accept().await.unwrap();
    // SAFETY: `getuid` takes no pointers and only reads this process's credential.
    let uid = unsafe { libc::getuid() };
    assert_eq!(peer_uid(&server).unwrap(), uid);
    assert!(matches!(SocketPeer::observe(&server, uid), SocketPeer::Allowed));
    assert!(matches!(
      SocketPeer::observe(&server, uid.wrapping_add(1)),
      SocketPeer::Forbidden { .. }
    ));
    drop(server);
    client.await.unwrap();
  }

  #[test]
  fn from_uid_admits_only_the_allowed_uid() {
    assert!(matches!(SocketPeer::from_uid(&Ok(501), 501), SocketPeer::Allowed));
    assert!(matches!(SocketPeer::from_uid(&Ok(502), 501), SocketPeer::Forbidden { uid: 502 }));
    let err = Err(io::Error::other("peer"));
    assert!(matches!(SocketPeer::from_uid(&err, 501), SocketPeer::Unproven));
  }

  #[test]
  fn classify_matches_the_header_table() {
    assert_eq!(classify(b""), Prefix::Pending);
    assert_eq!(classify(b"PROXY"), Prefix::Pending);

    let tcp4 = b"PROXY TCP4 203.0.113.9 127.0.0.1 443 40000\r\n";
    let dest_v4 = Destination::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000);
    assert_eq!(
      classify(tcp4),
      Prefix::Tcp {
        destination: dest_v4,
        header_len: tcp4.len(),
      },
    );
    assert_ne!(dest_v4.0.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));

    let mut with_tail = tcp4.to_vec();
    with_tail.extend_from_slice(b"HELLO");
    assert_eq!(
      classify(&with_tail),
      Prefix::Tcp {
        destination: dest_v4,
        header_len: tcp4.len(),
      },
    );

    let tcp6 = b"PROXY TCP6 2001:db8::1 ::1 1 443\r\n";
    assert_eq!(
      classify(tcp6),
      Prefix::Tcp {
        destination: Destination::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
        header_len: tcp6.len(),
      },
    );

    assert_eq!(classify(b"PROXY UNKNOWN\r\n"), Prefix::Unknown);
    assert_eq!(classify(b"PROXY UNKNOWN 1.2.3.4 5.6.7.8 9 10\r\n"), Prefix::Unknown);
    assert_eq!(classify(b"GET / HTTP/1.1\r\n\r\n"), Prefix::Malformed);
    assert_eq!(classify(v2::PROTOCOL_PREFIX), Prefix::Version2);
    let short = v2::PROTOCOL_PREFIX.get(..11).unwrap();
    assert_eq!(classify(short), Prefix::Pending);
    assert_eq!(classify(b"PROXY TCP4\r\n"), Prefix::Malformed);
    assert_eq!(classify(b"PROXY\r"), Prefix::Pending);

    let mut too_long = Vec::new();
    loop {
      too_long.push(b'P');
      if let Err(v1::BinaryParseError::Parse(v1::ParseError::HeaderTooLong)) = v1::Header::try_from(too_long.as_slice()) {
        assert_eq!(classify(&too_long), Prefix::Malformed);
        break;
      }
      assert!(too_long.len() < 4096, "rama never reported an overlong header");
    }

    let mut cr_without_lf = vec![b'P'; too_long.len().saturating_add(1)];
    cr_without_lf.push(b'\r');
    assert_eq!(classify(&cr_without_lf), Prefix::Pending);
  }
}
