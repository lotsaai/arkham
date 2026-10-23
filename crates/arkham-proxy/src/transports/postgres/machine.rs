//! Postgres wire format: negotiation, pgwire greeting decode, then raw
//! equal-length relay.
//!
//! Steady state reuses [`Raw`]: pairs stay equal-length, so substitution
//! never reframes the byte stream. This wire owns the greeting:
//! negotiation answers, startup identity, and the fail-closed latch.
//! Parsing is pgwire, never hand-rolled.
//!
//! The negotiation helpers here are the transport half of the same protocol:
//! the bytes libpq uses to ask for TLS, on both legs. What each leg then does
//! with the answer is the connection layer's business.

use std::borrow::Cow;

use arkham_config::grants::{Grant, Scheme, SslNegotiation};
use bytes::BytesMut;
use pgwire::messages::DecodeContext;
use pgwire::messages::Message;
use pgwire::messages::startup::{GssEncRequest, SslRequest, Startup};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::Error;
use crate::transports::engine::{Direction, Hit, Raw, Rewritten, Wire, raw_new};

/// Cap for one greeting message. Real `StartupMessages` are hundreds of
/// bytes; anything past this is a drip or an attack, never a greeting.
pub(crate) const MAX_GREETING: usize = 16_384;

/// Greeting progress. Response legs skip it: servers open with
/// length-prefixed Authentication messages, already frame-safe.
enum PgState {
  /// Accumulating the first client message.
  Greeting {
    /// Bytes so far, bounded by [`MAX_GREETING`].
    buf: Vec<u8>,
  },
  /// Greeting done: delegate every chunk to the inner machine.
  Relay,
}

/// One Postgres direction leg.
pub(crate) struct Postgres {
  state: PgState,
  inner: Raw,
  reply: Option<Vec<u8>>,
  /// The upstream user, when the two legs of the rule name different users:
  /// the startup's `user` parameter is rewritten to it northbound.
  user_rewrite: Option<String>,
  closed: bool,
}

impl Postgres {
  /// Fresh leg. Response legs start in [`PgState::Relay`]: no greeting to
  /// parse server-side.
  pub(crate) fn new(grants: &[Grant], host: &str, port: u16, dir: Direction) -> Self {
    let state = match dir {
      Direction::Downstream => PgState::Greeting { buf: Vec::new() },
      Direction::Upstream => PgState::Relay,
    };
    Self {
      state,
      inner: raw_new(grants, Scheme::Postgres, host, port, dir),
      reply: None,
      user_rewrite: grants.iter().find_map(|grant| grant.postgres(Some(host), port)).and_then(|scope| {
        if scope.upstream.user.is_some() && scope.upstream.user != scope.downstream.user {
          scope.upstream.user.clone()
        } else {
          None
        }
      }),
      closed: false,
    }
  }

  /// Feed one request-leg chunk through the greeting parser. Upstream-bound
  /// bytes return here; guest-bound negotiation replies wait in
  /// [`Wire::take_reply`].
  async fn feed_greeting<'a>(&mut self, chunk: &'a [u8]) -> (Cow<'a, [u8]>, Vec<Hit>) {
    if chunk.is_empty() || matches!(self.state, PgState::Relay) {
      return self.inner_feed(chunk).await;
    }
    {
      let PgState::Greeting { buf } = &mut self.state else {
        return (Cow::Borrowed(&[]), Vec::new());
      };
      buf.extend_from_slice(chunk);
      if buf.len() > MAX_GREETING {
        self.closed = true;
        return (Cow::Borrowed(&[]), Vec::new());
      }
    }
    loop {
      let Some(len) = self.greeting_len() else {
        return (Cow::Borrowed(&[]), Vec::new());
      };
      if len == 8 {
        if !self.refuse_negotiation() {
          self.closed = true;
          return (Cow::Borrowed(&[]), Vec::new());
        }
        continue;
      }
      let mut msg = self.take_greeting(len);
      if !Self::read_startup(&msg) {
        self.closed = true;
        return (Cow::Borrowed(&[]), Vec::new());
      }
      if let Some(user) = self.user_rewrite.as_deref() {
        rewrite_startup_user(&mut msg, user);
      }
      self.state = PgState::Relay;
      let (out, mut hits) = self.inner_feed(&msg).await;
      let mut out = out.into_owned();
      let rest = self.take_rest();
      if !rest.is_empty() {
        let (tail, tail_hits) = self.inner_feed(&rest).await;
        out.extend_from_slice(&tail);
        hits.extend(tail_hits);
      }
      return (Cow::Owned(out), hits);
    }
  }

  /// Complete greeting length, if enough bytes arrived. `None` holds.
  /// Malformed lengths latch closed instead of stalling the connection.
  fn greeting_len(&mut self) -> Option<usize> {
    let PgState::Greeting { buf } = &self.state else {
      return Some(0);
    };
    if buf.len() < 4 {
      return None;
    }
    let len = u32::from_be_bytes(buf[..4].try_into().unwrap_or([0; 4])) as usize;
    if !(8..=MAX_GREETING).contains(&len) {
      self.closed = true;
      return Some(0);
    }
    if buf.len() < len { None } else { Some(len) }
  }

  /// Answer one 8-byte negotiation request with `N` and consume it.
  /// `false` is an unknown magic code: fail closed.
  fn refuse_negotiation(&mut self) -> bool {
    let PgState::Greeting { buf } = &mut self.state else {
      return false;
    };
    // pgwire identifies both negotiation shapes from the magic code;
    // anything else in this slot is not a greeting message at all.
    if !SslRequest::is_ssl_request_packet(&buf[..8]) && !GssEncRequest::is_gss_enc_request_packet(&buf[..8]) {
      return false;
    }
    buf.drain(..8);
    self.reply.get_or_insert_with(Vec::new).extend_from_slice(b"N");
    true
  }

  /// Remove the first `len` greeting bytes for parsing.
  fn take_greeting(&mut self, len: usize) -> Vec<u8> {
    let PgState::Greeting { buf } = &mut self.state else {
      return Vec::new();
    };
    buf.drain(..len).collect()
  }

  /// Remove pipelined bytes past the greeting for in-order relay.
  fn take_rest(&mut self) -> Vec<u8> {
    let PgState::Greeting { buf } = &mut self.state else {
      return Vec::new();
    };
    std::mem::take(buf)
  }

  /// Decode one `StartupMessage` with pgwire; `false` is undecodable, so the
  /// connection fails closed. Any protocol major that decodes relays: the
  /// parameter block is framed from here, never re-parsed.
  fn read_startup(msg: &[u8]) -> bool {
    let Some(tail) = msg.get(4..) else {
      return false;
    };
    let mut body = BytesMut::from(tail);
    Startup::decode_body(&mut body, tail.len(), &DecodeContext::default()).is_ok()
  }
}

/// Replace the startup `user` parameter value, re-framing the message: the
/// two legs of a database rule may name different users, and the server
/// expects the real side's spelling. Layout: `[len u32][protocol u32]` then
/// `key\0value\0` pairs.
fn rewrite_startup_user(msg: &mut Vec<u8>, user: &str) {
  let mut pos = 8;
  while pos + 5 < msg.len() {
    let Some(key_end) = msg[pos..].iter().position(|&b| b == 0).map(|at| pos + at) else {
      break;
    };
    let value_start = key_end + 1;
    let Some(value_end) = msg[value_start..].iter().position(|&b| b == 0).map(|at| value_start + at) else {
      break;
    };
    if &msg[pos..key_end] == b"user" {
      msg.splice(value_start..value_end, user.as_bytes().to_vec());
      let len = u32::try_from(msg.len()).unwrap_or(u32::MAX);
      msg[..4].copy_from_slice(&len.to_be_bytes());
      return;
    }
    pos = value_end + 1;
  }
}

#[cfg(test)]
impl Postgres {
  /// Fail-closed latch state.
  pub(crate) fn must_close(&self) -> bool {
    self.closed
  }
}

impl Postgres {
  /// Steady-state relay through [`Raw`], mapped onto the Cow shape the
  /// greeting parser shares.
  async fn inner_feed<'a>(&mut self, chunk: &'a [u8]) -> (Cow<'a, [u8]>, Vec<Hit>) {
    match self.inner.feed(chunk).await {
      (Rewritten::Emit(bytes), hits) => (bytes, hits),
      (Rewritten::Hold | Rewritten::Close, hits) => (Cow::Borrowed(&[]), hits),
    }
  }
}

impl Wire for Postgres {
  async fn feed<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    let (out, hits) = if matches!(self.state, PgState::Relay) {
      self.inner_feed(chunk).await
    } else {
      self.feed_greeting(chunk).await
    };
    let rewritten = if self.closed {
      Rewritten::Close
    } else if out.is_empty() {
      Rewritten::Hold
    } else {
      Rewritten::Emit(out)
    };
    (rewritten, hits)
  }

  /// Guest-bound negotiation reply (`N` to SSL/GSSENC requests). The pump
  /// drains this toward the guest after each downstream chunk.
  fn take_reply(&mut self) -> Option<Vec<u8>> {
    self.reply.take()
  }
}

#[cfg(test)]
async fn cow_feed<'a>(wire: &mut Postgres, chunk: &'a [u8]) -> (std::borrow::Cow<'a, [u8]>, Vec<Hit>) {
  match wire.feed(chunk).await {
    (Rewritten::Emit(bytes), hits) => (bytes, hits),
    (Rewritten::Hold | Rewritten::Close, hits) => (std::borrow::Cow::Borrowed(&[]), hits),
  }
}

/// Guest opening bytes on a Postgres scope, read before any framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GuestOpening {
  /// TLS follows. The buffer holds whatever arrived past the request, which
  /// may be a whole `ClientHello`, part of one, or nothing yet.
  Tls(Vec<u8>),
  /// Cleartext: the guest went straight to a message, and the greeting machine
  /// judges it from there. The buffer holds the bytes already read, which the
  /// machine has to see from the first one.
  Cleartext(Vec<u8>),
}

/// Read the guest's opening the way a real server does, because the guest's
/// transport is the guest's choice: answer an 8-byte `SSLRequest` with `S`,
/// refuse a GSSENC request with `N` (libpq asks for SSL next), and take a
/// `ClientHello` that arrives with no request at all as direct TLS
/// (PostgreSQL 17 and later). `None` when the guest closed or dripped past the
/// pre-auth budget.
///
/// # Errors
///
/// Returns an error when the guest stream fails to read or write.
pub(crate) async fn read_guest_opening<G: AsyncRead + AsyncWrite + Unpin>(
  guest: &mut G,
  initial: &[u8],
  budget: std::time::Duration,
) -> Result<Option<GuestOpening>, Error> {
  let mut buf = initial.to_vec();
  let mut chunk = [0u8; 256];
  let deadline = tokio::time::Instant::now() + budget;
  loop {
    if buf.first() == Some(&TLS_RECORD_HANDSHAKE) {
      return Ok(Some(GuestOpening::Tls(buf)));
    }
    if buf.len() >= NEGOTIATION_LEN {
      let request = &buf[..NEGOTIATION_LEN];
      if SslRequest::is_ssl_request_packet(request) {
        guest.write_all(b"S").await?;
        buf.drain(..NEGOTIATION_LEN);
        return Ok(Some(GuestOpening::Tls(buf)));
      }
      if GssEncRequest::is_gss_enc_request_packet(request) {
        guest.write_all(b"N").await?;
        buf.drain(..NEGOTIATION_LEN);
        continue;
      }
      // Some other 8 bytes: not a request, so the guest is opening with a
      // message. Only the greeting machine gets to judge its shape.
      return Ok(Some(GuestOpening::Cleartext(buf)));
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
      return Ok(None);
    }
    match tokio::time::timeout(remaining, guest.read(&mut chunk)).await {
      Ok(Ok(0)) | Err(_) => return Ok(None),
      Ok(Ok(read)) => buf.extend_from_slice(&chunk[..read]),
      Ok(Err(err)) => return Err(err.into()),
    }
  }
}

/// Ask the server for TLS the way the entry's URL states: the 8-byte
/// `SSLRequest` and its one-byte answer, or nothing at all for
/// `sslnegotiation=direct`, where the handshake is the first thing sent.
///
/// `false` is a server that answered `N`. What that means is the mode's
/// business, so this only reports it.
///
/// # Errors
///
/// Returns an error when the server stream fails to write or read.
pub(crate) async fn request_upstream_tls<S: AsyncRead + AsyncWrite + Unpin>(
  server: &mut S,
  negotiation: SslNegotiation,
  budget: std::time::Duration,
) -> Result<bool, Error> {
  if negotiation == SslNegotiation::Direct {
    return Ok(true);
  }
  server.write_all(&ssl_request()).await?;
  server.flush().await?;
  let mut answer = [0u8; 1];
  // A peer that accepts TCP and then never answers must fail closed inside
  // the budget, not hold the connection forever.
  tokio::time::timeout(budget, server.read_exact(&mut answer))
    .await
    .map_err(|_elapsed| Error::TlsRequestUnanswered)??;
  Ok(answer[0] == b'S')
}

/// The 8-byte `SSLRequest` as it goes on the wire: length, then the magic code
/// pgwire names.
fn ssl_request() -> [u8; NEGOTIATION_LEN] {
  let mut request = [0u8; NEGOTIATION_LEN];
  request[..4].copy_from_slice(&i32::try_from(NEGOTIATION_LEN).expect("NEGOTIATION_LEN fits an i32").to_be_bytes());
  request[4..].copy_from_slice(&SslRequest::BODY_MAGIC_NUMBER.to_be_bytes());
  request
}

/// Length of a Postgres negotiation request: a length word and a magic code.
const NEGOTIATION_LEN: usize = 8;
/// First byte of a TLS record carrying a handshake message, which is what a
/// direct-SSL client opens with.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::grants::{Credential, PostgresScope};
  use secrecy::SecretString;

  fn pg_grant() -> Grant {
    Grant::Postgres {
      credential: Credential {
        label: "pg".to_string(),
        fake: "FAKEFAKE".to_string(),
        value: SecretString::from("REALREAL"),
      },
      scope: Box::new(
        PostgresScope::from_strings(
          "postgres://app:FAKEFAKE@db.internal:5432",                 // betterleaks:allow
          "postgres://app:REALREAL@db.internal:5432?sslmode=disable", // betterleaks:allow
        )
        .unwrap(),
      ),
    }
  }

  fn request_leg() -> Postgres {
    Postgres::new(&[pg_grant()], "db.internal", 5432, Direction::Downstream)
  }

  fn startup(user: &str, database: &str) -> Vec<u8> {
    let mut body = 196_608_u32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user");
    body.push(0);
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    body.extend_from_slice(b"database");
    body.push(0);
    body.extend_from_slice(database.as_bytes());
    body.push(0);
    body.push(0);
    let mut msg = u32::try_from(body.len() + 4).unwrap_or(u32::MAX).to_be_bytes().to_vec();
    msg.extend_from_slice(&body);
    msg
  }

  #[tokio::test]
  async fn greeting_decodes_and_relays_untouched() {
    let mut machine = request_leg();
    let msg = startup("app", "main");
    let (out, _) = cow_feed(&mut machine, &msg).await;
    assert_eq!(out.as_ref(), msg.as_slice());
    assert!(!machine.must_close());
  }

  #[tokio::test]
  async fn split_greeting_holds_until_complete() {
    let mut machine = request_leg();
    let msg = startup("app", "main");
    let (out, _) = cow_feed(&mut machine, &msg[..5]).await;
    assert!(out.is_empty());
    assert!(!machine.must_close());
    let (out, _) = cow_feed(&mut machine, &msg[5..]).await;
    assert_eq!(out.as_ref(), msg.as_slice());
  }

  #[tokio::test]
  async fn ssl_request_gets_refusal_and_greeting_follows() {
    let mut machine = request_leg();
    let mut hello = 8u32.to_be_bytes().to_vec();
    hello.extend_from_slice(&80_877_103_u32.to_be_bytes());
    let greeting = startup("app", "main");
    hello.extend_from_slice(&greeting);
    let (out, _) = cow_feed(&mut machine, &hello).await;
    assert_eq!(out.as_ref(), greeting.as_slice());
    assert_eq!(machine.take_reply(), Some(b"N".to_vec()));
  }

  #[tokio::test]
  async fn oversize_greeting_latches_closed() {
    let mut machine = request_leg();
    let big = vec![0xffu8; MAX_GREETING + 1];
    let (_, _) = cow_feed(&mut machine, &big).await;
    assert!(machine.must_close());
  }

  #[tokio::test]
  async fn short_length_latches_closed() {
    let mut machine = request_leg();
    let (_, _) = cow_feed(&mut machine, &[0, 0, 0, 7, 0, 0, 0, 0]).await;
    assert!(machine.must_close());
  }

  #[tokio::test]
  async fn undecodable_startup_latches_closed() {
    let mut machine = request_leg();
    let mut msg = 12u32.to_be_bytes().to_vec();
    msg.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 0]);
    let (out, _) = cow_feed(&mut machine, &msg).await;
    assert!(out.is_empty());
    assert!(machine.must_close());
  }

  #[tokio::test]
  async fn steady_state_substitutes_equal_length_pairs() {
    let mut machine = request_leg();
    let msg = startup("app", "main");
    let (_, _) = cow_feed(&mut machine, &msg).await;
    let (out, hits) = cow_feed(&mut machine, b"FAKEFAKE").await;
    assert_eq!(out.as_ref(), b"REALREAL");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].label, "pg");
  }

  #[tokio::test]
  async fn response_leg_starts_in_relay() {
    let mut machine = Postgres::new(&[pg_grant()], "db.internal", 5432, Direction::Upstream);
    let (out, _) = cow_feed(&mut machine, b"R................").await;
    assert_eq!(out.as_ref(), b"R................");
  }
}
