//! Loopback PROXY protocol v1 accept side.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rama::Service;
use rama::proxy::haproxy::protocol::v1;
use rama::proxy::haproxy::protocol::v2;
use rama::tcp::server::TcpListener as RamaTcpListener;
use rama::tcp::stream::TcpStream as RamaTcpStream;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};
use tokio::net::TcpStream;

use crate::Error;
use crate::ProxyState;
use crate::connection::Prefixed;
use crate::serve_transparent_stream;

/// Bind the handoff listener.
///
/// Plain TCP, backlog 128, the same socket as [`crate::bind_explicit`].
/// The listen address is not required to be loopback. A peer that is not
/// loopback is rejected after accept.
///
/// # Errors
///
/// Returns an error when the socket cannot be built, bound, or marked
/// listening.
pub async fn bind_handoff(addr: SocketAddr) -> Result<RamaTcpListener, Error> {
  super::bind_explicit(addr).await
}

/// Serve handoff connections until the listener stops.
///
/// A loopback peer that writes a PROXY protocol v1 TCP4 or TCP6 header is
/// handed to [`crate::serve_transparent_stream`] with the header destination
/// as the dial target. Any other peer or header is dropped. Accept errors
/// are logged by the listener and do not end the process.
pub async fn serve_handoff(listener: RamaTcpListener, state: Arc<ProxyState>) {
  listener.serve(HandoffService { state }).await;
}

fn handshake_budget(state: &ProxyState) -> Duration {
  Duration::from_secs(state.snapshot().proxy.handshake_timeout_secs)
}

#[derive(Clone, Debug)]
struct HandoffService {
  state: Arc<ProxyState>,
}

impl Service<RamaTcpStream> for HandoffService {
  type Output = ();
  type Error = Infallible;

  async fn serve(&self, input: RamaTcpStream) -> Result<(), Infallible> {
    let client = TcpStream::from(input);
    let peer = SocketPeer::observe(&client.peer_addr());
    let budget = handshake_budget(&self.state);
    match peer.decide(client, budget).await {
      Ok(Handoff::Serve(agent)) => {
        if let Err(err) = agent.serve(&self.state).await {
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
    Ok(())
  }
}

#[derive(Debug)]
enum SocketPeer {
  Loopback(LoopbackPeer),
  Foreign(SocketAddr),
  Unproven,
}

impl SocketPeer {
  fn observe(peer: &std::io::Result<SocketAddr>) -> Self {
    match peer {
      Ok(addr) if addr.ip().is_loopback() => Self::Loopback(LoopbackPeer),
      Ok(addr) => Self::Foreign(*addr),
      Err(_) => Self::Unproven,
    }
  }

  async fn decide<G>(self, stream: G, budget: Duration) -> Result<Handoff<G>, Error>
  where
    G: AsyncRead + Unpin,
  {
    match self {
      Self::Foreign(addr) => Ok(Handoff::Close(CloseReason::ForeignPeer(addr))),
      Self::Unproven => Ok(Handoff::Close(CloseReason::UnprovenPeer)),
      Self::Loopback(peer) => read_header(stream, peer, budget).await,
    }
  }
}

#[derive(Debug)]
struct LoopbackPeer;

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
  ForeignPeer(SocketAddr),
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

async fn read_header<G>(stream: G, peer: LoopbackPeer, budget: Duration) -> Result<Handoff<G>, Error>
where
  G: AsyncRead + Unpin,
{
  let LoopbackPeer = peer;
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

  fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
  }

  #[tokio::test]
  async fn foreign_and_unproven_close_without_reading() {
    let budget = Duration::from_secs(10);
    let peer = addr("192.0.2.1:9");
    let foreign = SocketPeer::Foreign(peer).decide(Explode, budget).await.unwrap();
    assert!(matches!(foreign, Handoff::Close(CloseReason::ForeignPeer(found)) if found == peer));
    let unproven = SocketPeer::Unproven.decide(Explode, budget).await.unwrap();
    assert!(matches!(unproven, Handoff::Close(CloseReason::UnprovenPeer)));
  }

  #[test]
  fn observe_accepts_loopback_and_rejects_mapped() {
    assert!(matches!(SocketPeer::observe(&Ok(addr("127.0.0.1:1"))), SocketPeer::Loopback(_)));
    assert!(matches!(
      SocketPeer::observe(&Ok(addr("127.255.255.255:1"))),
      SocketPeer::Loopback(_)
    ));
    assert!(matches!(SocketPeer::observe(&Ok(addr("[::1]:1"))), SocketPeer::Loopback(_)));
    assert!(matches!(SocketPeer::observe(&Ok(addr("192.0.2.1:9"))), SocketPeer::Foreign(_)));
    assert!(matches!(
      SocketPeer::observe(&Ok(addr("[::ffff:127.0.0.1]:1"))),
      SocketPeer::Foreign(_)
    ));
    let err = Err(std::io::Error::other("peer"));
    assert!(matches!(SocketPeer::observe(&err), SocketPeer::Unproven));
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
