//! AMQP wire format: SASL PLAIN rewrite over a streamed frame cursor.
//!
//! The 8-byte protocol header picks the framer: 0-9-1 frames (`type
//! channel size payload 0xCE`) or 1.0 frames (`size doff type channel`).
//! A frame is stored only when it is the one credential command (0-9-1
//! `connection.start-ok`, 1.0 `sasl-init` or the `sasl-response` that
//! carries a deferred initial response) or, upstream, a frame whose text can
//! echo a password (0-9-1 `connection.close` and `channel.close`, 1.0
//! `close`, `end`, and `detach`). That frame's own size is the bound. Every
//! other frame is counted down as it arrives.
//!
//! Downstream rewrites only when the upstream writer is TLS, and forwards
//! every byte unchanged after the credential frame. Upstream always redacts:
//! a password inside a rewritable text field becomes the decoy, and any other
//! occurrence closes the leg.

use std::borrow::Cow;
use std::str::FromStr;

use amq_protocol::auth::SASLMechanism;
use amq_protocol::frame::{AMQPFrame, WriteContext, gen_frame, parse_frame};
use amq_protocol::protocol::constants::{FRAME_END, FRAME_METHOD};
use amq_protocol::protocol::{AMQPClass, channel, connection};
use amq_protocol::types::ShortString;
use arkham_config::grants::Grant;
use fe2o3_amqp_types::definitions::Error as AmqpError;
use fe2o3_amqp_types::performatives::{Close, Detach, End};
use fe2o3_amqp_types::primitives::Binary;
use fe2o3_amqp_types::sasl::{SaslInit, SaslResponse};
use secrecy::ExposeSecret as _;
use serde_amqp::serde::{Deserialize, Serialize};

use crate::transports::engine::{
  CredentialPair, Direction, Hit, Location, Rewritten, Wire, find_new_match, needle_prefix_suffix_len, replace_bytes,
};

/// AMQP 0-9-1 protocol header.
const HEADER_091: &[u8] = b"AMQP\x00\x00\x09\x01";

/// AMQP 1.0 SASL layer header.
const HEADER_SASL: &[u8] = b"AMQP\x03\x01\x00\x00";

/// AMQP 1.0 protocol header, after the SASL layer or without one.
const HEADER_10: &[u8] = b"AMQP\x00\x01\x00\x00";

/// Length of every protocol header.
const HEADER_LEN: usize = 8;

/// First byte of every protocol header.
const HEADER_LEAD: u8 = b'A';

/// 0-9-1 frame header: type, channel, payload size.
const HEAD_091: usize = 7;

/// Class id and method id that open a 0-9-1 method payload.
const METHOD_IDS_091: usize = 4;

/// Offset of a 0-9-1 method id, after the class id.
const METHOD_AT_091: usize = HEAD_091 + 2;

/// 0-9-1 frame header plus the class and method ids of a method frame.
const METHOD_HEAD_091: usize = HEAD_091 + METHOD_IDS_091;

/// 0-9-1 `connection.start-ok` class and method ids.
const START_OK: (u16, u16) = (10, 11);

/// 0-9-1 `connection.close` class and method ids.
const CONNECTION_CLOSE: (u16, u16) = (10, 50);

/// 0-9-1 `channel.close` class and method ids.
const CHANNEL_CLOSE: (u16, u16) = (20, 40);

/// 1.0 fixed frame header: size, data offset, type, channel.
const HEAD_10: usize = 8;

/// 1.0 AMQP frame type.
const FRAME_AMQP: u8 = 0;

/// 1.0 SASL frame type.
const FRAME_SASL: u8 = 1;

/// 1.0 described-type constructor.
const DESCRIBED: u8 = 0x00;

/// 1.0 `smallulong` descriptor encoding: one code byte.
const SMALL_ULONG: u8 = 0x53;

/// 1.0 `ulong` descriptor encoding: eight code bytes.
const ULONG: u8 = 0x80;

/// 1.0 descriptor codes this machine stores a frame for.
const SASL_INIT: u64 = 0x41;
const SASL_RESPONSE: u64 = 0x43;
const DETACH: u64 = 0x16;
const END: u64 = 0x17;
const CLOSE: u64 = 0x18;

/// SASL mechanisms an AMQP client names. Only [`SaslMechanism::Plain`]
/// carries the password in a field this machine rewrites; every other
/// mechanism passes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SaslMechanism {
  /// `PLAIN`: `authzid NUL user NUL password`.
  Plain,
  /// `AMQPLAIN`: a field-table credential.
  Amqplain,
  /// `EXTERNAL`: the transport authenticates.
  External,
  /// `ANONYMOUS`: no credential.
  Anonymous,
  /// `RABBIT-CR-DEMO`: a challenge-response demo.
  RabbitCrDemo,
}

impl SaslMechanism {
  /// Whether a response under this mechanism is rewritten.
  pub(crate) fn swaps(self) -> bool {
    matches!(self, Self::Plain)
  }
}

impl FromStr for SaslMechanism {
  type Err = ();

  /// Parse a mechanism name with `amq-protocol`'s own list. A name it does
  /// not know is `Err` and passes through.
  fn from_str(name: &str) -> Result<Self, Self::Err> {
    Ok(match SASLMechanism::from_str(name).map_err(|_unknown| ())? {
      SASLMechanism::Plain => Self::Plain,
      SASLMechanism::AMQPlain => Self::Amqplain,
      SASLMechanism::External => Self::External,
      SASLMechanism::Anonymous => Self::Anonymous,
      SASLMechanism::RabbitCrDemo => Self::RabbitCrDemo,
    })
  }
}

/// One AMQP direction leg.
pub(crate) struct Amqp {
  down: Option<Down>,
  /// Upstream needle: the real password, replaced by the decoy.
  up: Option<CredentialPair>,
  framer: Framer,
  phase: Phase,
  /// Upstream needle hold-back. A window shorter than the secret, not a frame buffer.
  held: Vec<u8>,
  closed: bool,
}

/// Downstream rewrite facts. Present only when the swap is on.
struct Down {
  fake: Vec<u8>,
  user: Vec<u8>,
  real: Vec<u8>,
  label: String,
  /// A PLAIN `sasl-init` came without its initial response.
  awaiting_response: bool,
}

/// Which frame layout the protocol header selected.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Framer {
  V091,
  /// AMQP 1.0. `sasl` while the SASL layer runs: a protocol header may
  /// follow any of its frames.
  V10 {
    sasl: bool,
  },
}

/// Where the cursor is.
enum Phase {
  /// Protocol header bytes. At most eight.
  Header(Vec<u8>),
  /// One frame's header and the bytes that classify it.
  Head(Vec<u8>),
  /// One whole frame this machine rewrites. `total` is that frame's own size.
  Frame { buf: Vec<u8>, total: usize, kind: Kind },
  /// `left` bytes of the current frame, forwarded without storing.
  Forward(usize),
  /// No more framing: every byte passes.
  Opaque,
}

/// The frame a [`Phase::Frame`] stores.
#[derive(Clone, Copy)]
enum Kind {
  StartOk,
  SaslInit,
  SaslResponse,
  Close091,
  /// 1.0 `close`, `end`, or `detach`, by descriptor code.
  Error10(u64),
}

/// What a frame head says about its frame.
enum Classified {
  /// Absolute head length still required.
  Need(usize),
  /// Store the whole frame of `total` bytes.
  Hold { total: usize, kind: Kind },
  /// Forward the frame of `total` bytes, the head included.
  Forward { total: usize },
}

impl Amqp {
  /// Fresh leg. `swap` is downstream only: a PLAIN response is rewritten
  /// when the upstream writer is already TLS, and a cleartext upstream keeps
  /// the decoy. Upstream always redacts.
  pub(crate) fn new(grants: &[Grant], host: &str, port: u16, dir: Direction, swap: bool) -> Self {
    let found = grants.iter().find_map(|grant| {
      let scope = grant.amqp(Some(host), port)?;
      let label = grant.credential().map(|credential| credential.label.clone()).unwrap_or_default();
      Some((scope, label))
    });
    let down = match &found {
      Some((scope, label)) if dir == Direction::Downstream && swap => Some(Down {
        fake: scope.downstream.password.expose_secret().as_bytes().to_vec(),
        user: scope.upstream.user.as_bytes().to_vec(),
        real: scope.upstream.password.expose_secret().as_bytes().to_vec(),
        label: label.clone(),
        awaiting_response: false,
      }),
      _ => None,
    };
    let up = match found {
      Some((scope, label)) if dir == Direction::Upstream => Some(CredentialPair {
        needle: scope.upstream.password.expose_secret().as_bytes().to_vec(),
        replacement: scope.downstream.password.expose_secret().as_bytes().to_vec(),
        label,
      }),
      _ => None,
    };
    let phase = if down.is_some() || up.is_some() {
      Phase::Header(Vec::new())
    } else {
      Phase::Opaque
    };
    Self {
      down,
      up,
      framer: Framer::V091,
      phase,
      held: Vec::new(),
      closed: false,
    }
  }
}

impl Wire for Amqp {
  fn feed<'a>(&mut self, chunk: &'a [u8]) -> impl Future<Output = (Rewritten<'a>, Vec<Hit>)> + Send {
    std::future::ready(self.advance(chunk))
  }
}

impl Amqp {
  fn advance<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    if self.closed {
      return (Rewritten::Close, Vec::new());
    }
    if chunk.is_empty() {
      return self.finish();
    }
    if self.up.is_none() && matches!(self.phase, Phase::Opaque) {
      return (Rewritten::Emit(Cow::Borrowed(chunk)), Vec::new());
    }
    let mut input = chunk;
    let mut out = Vec::new();
    let mut hits = Vec::new();
    while !input.is_empty() {
      let before = input.len();
      // Every step consumes input; one that does not would drop bytes.
      if self.step(&mut input, &mut out, &mut hits).is_err() || input.len() == before {
        self.closed = true;
        return (Rewritten::Close, hits);
      }
    }
    if out.is_empty() {
      (Rewritten::Hold, hits)
    } else {
      (Rewritten::Emit(Cow::Owned(out)), hits)
    }
  }

  /// Empty input is end of stream. A partial header or frame closes and
  /// emits nothing for it. A held needle suffix is flushed; it is shorter
  /// than the secret, so it is not the secret.
  fn finish(&mut self) -> (Rewritten<'static>, Vec<Hit>) {
    let idle = match &self.phase {
      Phase::Header(buf) | Phase::Head(buf) => buf.is_empty(),
      Phase::Opaque => true,
      Phase::Frame { .. } | Phase::Forward(_) => false,
    };
    if !idle {
      self.closed = true;
      return (Rewritten::Close, Vec::new());
    }
    let flushed = std::mem::take(&mut self.held);
    if flushed.is_empty() {
      (Rewritten::Hold, Vec::new())
    } else {
      (Rewritten::Emit(Cow::Owned(flushed)), Vec::new())
    }
  }

  /// Advance one cursor step over `input`.
  fn step(&mut self, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), ()> {
    match std::mem::replace(&mut self.phase, Phase::Opaque) {
      Phase::Header(buf) => self.drive_header(buf, input, out, hits),
      Phase::Head(buf) => self.drive_head(buf, input, out, hits),
      Phase::Frame { buf, total, kind } => self.drive_frame(buf, total, kind, input, out, hits),
      Phase::Forward(left) => {
        self.phase = self.forward_rest(left, input, out)?;
        Ok(())
      }
      Phase::Opaque => self.opaque(input, out),
    }
  }

  /// Stop framing and pass the rest of `input` in this same step.
  fn opaque(&mut self, input: &mut &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    self.phase = Phase::Opaque;
    self.pass(input, out)?;
    *input = &[];
    Ok(())
  }

  /// Read one protocol header and pick the framer. A server that opens with
  /// a frame instead is 0-9-1. Any header the machine does not frame
  /// forwards the rest of the stream.
  fn drive_header(&mut self, mut buf: Vec<u8>, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), ()> {
    if buf.is_empty() && input.first().is_some_and(|lead| *lead != HEADER_LEAD) {
      if self.down.is_some() {
        return self.opaque(input, out);
      }
      self.framer = Framer::V091;
      return self.drive_head(Vec::new(), input, out, hits);
    }
    take(&mut buf, HEADER_LEN, input);
    if buf.len() < HEADER_LEN {
      self.phase = Phase::Header(buf);
      return Ok(());
    }
    self.pass(&buf, out)?;
    let framer = match (self.down.is_some(), buf.as_slice()) {
      (true, HEADER_091) => Some(Framer::V091),
      (_, HEADER_SASL) => Some(Framer::V10 { sasl: true }),
      (false, HEADER_10) => Some(Framer::V10 { sasl: false }),
      _ => None,
    };
    self.phase = match framer {
      Some(framer) => {
        self.framer = framer;
        Phase::Head(Vec::new())
      }
      None => Phase::Opaque,
    };
    Ok(())
  }

  /// Read one frame head until it classifies, then store, or forward and
  /// count down. During the 1.0 SASL layer a protocol header may stand where
  /// a frame would.
  fn drive_head(&mut self, mut buf: Vec<u8>, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), ()> {
    if buf.is_empty() && self.framer == (Framer::V10 { sasl: true }) && input.first() == Some(&HEADER_LEAD) {
      if self.down.is_some() {
        return self.opaque(input, out);
      }
      return self.drive_header(Vec::new(), input, out, hits);
    }
    loop {
      match self.classify(&buf)? {
        Classified::Need(need) => {
          if need <= buf.len() {
            return Err(());
          }
          if input.is_empty() {
            self.phase = Phase::Head(buf);
            return Ok(());
          }
          take(&mut buf, need, input);
        }
        Classified::Hold { total, kind } => return self.drive_frame(buf, total, kind, input, out, hits),
        Classified::Forward { total } => {
          self.pass(&buf, out)?;
          let left = total.checked_sub(buf.len()).ok_or(())?;
          self.phase = self.forward_rest(left, &mut &[][..], out)?;
          return Ok(());
        }
      }
    }
  }

  fn classify(&self, buf: &[u8]) -> Result<Classified, ()> {
    match self.framer {
      Framer::V091 => self.classify_091(buf),
      Framer::V10 { .. } => self.classify_10(buf),
    }
  }

  /// A 0-9-1 head: type, channel, size, then class and method of a method frame.
  fn classify_091(&self, buf: &[u8]) -> Result<Classified, ()> {
    let Some(size) = be_u32(buf, 3) else {
      return Ok(Classified::Need(HEAD_091));
    };
    let total = HEAD_091.checked_add(size).and_then(|len| len.checked_add(1)).ok_or(())?;
    if buf.first() != Some(&FRAME_METHOD) || size < METHOD_IDS_091 {
      return Ok(Classified::Forward { total });
    }
    let (Some(class), Some(method)) = (be_u16(buf, HEAD_091), be_u16(buf, METHOD_AT_091)) else {
      return Ok(Classified::Need(METHOD_HEAD_091));
    };
    let kind = match (class, method) {
      START_OK if self.down.is_some() => Kind::StartOk,
      CONNECTION_CLOSE | CHANNEL_CLOSE if self.up.is_some() => Kind::Close091,
      _ => return Ok(Classified::Forward { total }),
    };
    Ok(Classified::Hold { total, kind })
  }

  /// A 1.0 head: size, data offset, type, channel, then the performative's
  /// descriptor. A symbolic descriptor is forwarded and scanned.
  fn classify_10(&self, buf: &[u8]) -> Result<Classified, ()> {
    let (Some(total), Some(&doff), Some(&frame_type)) = (be_u32(buf, 0), buf.get(4), buf.get(5)) else {
      return Ok(Classified::Need(HEAD_10));
    };
    let body_at = usize::from(doff).checked_mul(4).ok_or(())?;
    if body_at < HEAD_10 || body_at > total {
      return Err(());
    }
    let forward = Classified::Forward { total };
    let wanted = match frame_type {
      FRAME_SASL => self.down.is_some(),
      FRAME_AMQP => self.up.is_some(),
      _ => false,
    };
    let code_at = body_at.checked_add(2).ok_or(())?;
    if !wanted || code_at > total {
      return Ok(forward);
    }
    let Some(&[constructor, encoding]) = buf.get(body_at..code_at) else {
      return Ok(Classified::Need(code_at));
    };
    let code_len = match (constructor, encoding) {
      (DESCRIBED, SMALL_ULONG) => 1,
      (DESCRIBED, ULONG) => 8,
      _ => return Ok(forward),
    };
    let code_end = code_at.checked_add(code_len).ok_or(())?;
    if code_end > total {
      return Ok(forward);
    }
    let Some(code_bytes) = buf.get(code_at..code_end) else {
      return Ok(Classified::Need(code_end));
    };
    let code = code_bytes.iter().fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    let kind = match (frame_type, code) {
      (FRAME_SASL, SASL_INIT) => Kind::SaslInit,
      (FRAME_SASL, SASL_RESPONSE) if self.down.as_ref().is_some_and(|down| down.awaiting_response) => Kind::SaslResponse,
      (FRAME_AMQP, DETACH | END | CLOSE) => Kind::Error10(code),
      _ => return Ok(forward),
    };
    Ok(Classified::Hold { total, kind })
  }

  /// Store one frame until it is whole, then rewrite it and move on.
  fn drive_frame(
    &mut self,
    mut buf: Vec<u8>,
    total: usize,
    kind: Kind,
    input: &mut &[u8],
    out: &mut Vec<u8>,
    hits: &mut Vec<Hit>,
  ) -> Result<(), ()> {
    take(&mut buf, total, input);
    if buf.len() < total {
      self.phase = Phase::Frame { buf, total, kind };
      return Ok(());
    }
    if self.framer == Framer::V091 && buf.last() != Some(&FRAME_END) {
      return Err(());
    }
    match kind {
      Kind::StartOk => {
        let rewritten = self.start_ok(&buf, hits)?;
        self.pass(rewritten.as_deref().unwrap_or(&buf), out)?;
        self.phase = Phase::Opaque;
      }
      Kind::SaslInit => {
        let (rewritten, deferred) = self.sasl_init(&buf, hits)?;
        self.pass(rewritten.as_deref().unwrap_or(&buf), out)?;
        self.phase = if deferred { Phase::Head(Vec::new()) } else { Phase::Opaque };
      }
      Kind::SaslResponse => {
        let rewritten = self.sasl_response(&buf, hits)?;
        self.pass(rewritten.as_deref().unwrap_or(&buf), out)?;
        self.phase = Phase::Opaque;
      }
      Kind::Close091 => {
        let redacted = self.close_091(&buf, hits)?;
        self.pass(redacted.as_deref().unwrap_or(&buf), out)?;
        self.phase = self.finish_frame(out);
      }
      Kind::Error10(code) => {
        let redacted = self.error_10(&buf, code, hits)?;
        self.pass(redacted.as_deref().unwrap_or(&buf), out)?;
        self.phase = self.finish_frame(out);
      }
    }
    Ok(())
  }

  /// A 0-9-1 `start-ok` carrying the decoy under PLAIN, re-encoded with the
  /// real user and password. `None` keeps the original bytes.
  fn start_ok(&self, buf: &[u8], hits: &mut Vec<Hit>) -> Result<Option<Vec<u8>>, ()> {
    let Some(down) = self.down.as_ref() else {
      return Err(());
    };
    let AMQPFrame::Method(channel, AMQPClass::Connection(connection::AMQPMethod::StartOk(mut start_ok))) = parse_whole(buf)? else {
      return Err(());
    };
    if !SaslMechanism::from_str(start_ok.mechanism.as_str()).is_ok_and(SaslMechanism::swaps) {
      return Ok(None);
    }
    let Some(token) = rewrite_plain(start_ok.response.as_bytes(), down) else {
      return Ok(None);
    };
    start_ok.response = token.into();
    let frame = encode_091(&AMQPFrame::Method(
      channel,
      AMQPClass::Connection(connection::AMQPMethod::StartOk(start_ok)),
    ))?;
    hits.push(Hit {
      label: down.label.clone(),
      location: Location::Body,
    });
    Ok(Some(frame))
  }

  /// A 1.0 `sasl-init`. PLAIN with the decoy is re-encoded with the real
  /// user and password; PLAIN with no initial response defers to the next
  /// `sasl-response` (`true`).
  fn sasl_init(&mut self, buf: &[u8], hits: &mut Vec<Hit>) -> Result<(Option<Vec<u8>>, bool), ()> {
    let mut init: SaslInit = decode_10(buf)?;
    let Some(down) = self.down.as_mut() else {
      return Err(());
    };
    if !SaslMechanism::from_str(init.mechanism.as_str()).is_ok_and(SaslMechanism::swaps) {
      return Ok((None, false));
    }
    let Some(response) = init.initial_response.as_ref() else {
      down.awaiting_response = true;
      return Ok((None, true));
    };
    let Some(token) = rewrite_plain(response, down) else {
      return Ok((None, false));
    };
    init.initial_response = Some(Binary::from(token));
    hits.push(Hit {
      label: down.label.clone(),
      location: Location::Body,
    });
    Ok((Some(encode_10(buf, &init)?), false))
  }

  /// The `sasl-response` that carries a deferred PLAIN initial response.
  fn sasl_response(&self, buf: &[u8], hits: &mut Vec<Hit>) -> Result<Option<Vec<u8>>, ()> {
    let mut response: SaslResponse = decode_10(buf)?;
    let Some(down) = self.down.as_ref() else {
      return Err(());
    };
    let Some(token) = rewrite_plain(&response.response, down) else {
      return Ok(None);
    };
    response.response = Binary::from(token);
    hits.push(Hit {
      label: down.label.clone(),
      location: Location::Body,
    });
    Ok(Some(encode_10(buf, &response)?))
  }

  /// A 0-9-1 `connection.close` or `channel.close` whose reply-text carries
  /// the real password, re-encoded with the decoy. A reply-text the decoy
  /// would push past 255 bytes cannot be encoded and closes.
  fn close_091(&self, buf: &[u8], hits: &mut Vec<Hit>) -> Result<Option<Vec<u8>>, ()> {
    let Some(pair) = self.up.as_ref().filter(|pair| find_new_match(buf, &pair.needle, 0)) else {
      return Ok(None);
    };
    let frame = match parse_whole(buf)? {
      AMQPFrame::Method(id, AMQPClass::Connection(connection::AMQPMethod::Close(mut close))) => {
        close.reply_text = redact_short(&close.reply_text, pair)?;
        AMQPFrame::Method(id, AMQPClass::Connection(connection::AMQPMethod::Close(close)))
      }
      AMQPFrame::Method(id, AMQPClass::Channel(channel::AMQPMethod::Close(mut close))) => {
        close.reply_text = redact_short(&close.reply_text, pair)?;
        AMQPFrame::Method(id, AMQPClass::Channel(channel::AMQPMethod::Close(close)))
      }
      _ => return Err(()),
    };
    hits.push(Hit {
      label: pair.label.clone(),
      location: Location::Body,
    });
    Ok(Some(encode_091(&frame)?))
  }

  /// A 1.0 `close`, `end`, or `detach` whose error description carries the
  /// real password, re-encoded with the decoy. A password anywhere else in
  /// the frame stays and closes in the scan.
  fn error_10(&self, buf: &[u8], code: u64, hits: &mut Vec<Hit>) -> Result<Option<Vec<u8>>, ()> {
    let Some(pair) = self.up.as_ref().filter(|pair| find_new_match(buf, &pair.needle, 0)) else {
      return Ok(None);
    };
    let frame = match code {
      CLOSE => {
        let mut close: Close = decode_10(buf)?;
        redact_error(close.error.as_mut(), pair).then(|| encode_10(buf, &close))
      }
      END => {
        let mut end: End = decode_10(buf)?;
        redact_error(end.error.as_mut(), pair).then(|| encode_10(buf, &end))
      }
      DETACH => {
        let mut detach: Detach = decode_10(buf)?;
        redact_error(detach.error.as_mut(), pair).then(|| encode_10(buf, &detach))
      }
      _ => None,
    };
    let Some(frame) = frame.transpose()? else {
      return Ok(None);
    };
    hits.push(Hit {
      label: pair.label.clone(),
      location: Location::Body,
    });
    Ok(Some(frame))
  }

  /// Stream `left` bytes from `input`. A 0-9-1 frame must end in `0xCE`.
  fn forward_rest(&mut self, left: usize, input: &mut &[u8], out: &mut Vec<u8>) -> Result<Phase, ()> {
    if left == 0 {
      return Ok(self.finish_frame(out));
    }
    let n = left.min(input.len());
    let chunk = input.get(..n).ok_or(())?;
    let left = left.saturating_sub(n);
    if left == 0 && self.framer == Framer::V091 && chunk.last() != Some(&FRAME_END) {
      return Err(());
    }
    self.pass(chunk, out)?;
    *input = input.get(n..).unwrap_or_default();
    Ok(if left == 0 { self.finish_frame(out) } else { Phase::Forward(left) })
  }

  /// The current frame is complete: release the needle suffix, because a
  /// finished frame cannot grow.
  fn finish_frame(&mut self, out: &mut Vec<u8>) -> Phase {
    out.extend(std::mem::take(&mut self.held));
    Phase::Head(Vec::new())
  }

  /// Downstream copies. Upstream scans with the needle hold-back and closes
  /// when the real password appears outside a field already rewritten.
  fn pass(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    let Some(pair) = self.up.as_ref().filter(|pair| !pair.needle.is_empty()) else {
      out.extend_from_slice(data);
      return Ok(());
    };
    let mut combined = std::mem::take(&mut self.held);
    combined.extend_from_slice(data);
    if find_new_match(&combined, &pair.needle, 0) {
      return Err(());
    }
    let tail = pair.needle.len().saturating_sub(1);
    let hold = needle_prefix_suffix_len(&combined, std::slice::from_ref(pair), tail);
    let emit = combined.len().saturating_sub(hold);
    let head = combined.get(..emit).ok_or(())?;
    out.extend_from_slice(head);
    self.held = combined.split_off(emit);
    Ok(())
  }
}

/// Move bytes from `input` into `buf` until it holds `want`.
fn take(buf: &mut Vec<u8>, want: usize, input: &mut &[u8]) {
  let n = want.saturating_sub(buf.len()).min(input.len());
  if let Some((head, rest)) = input.split_at_checked(n) {
    buf.extend_from_slice(head);
    *input = rest;
  }
}

fn be_u16(buf: &[u8], at: usize) -> Option<u16> {
  let bytes = buf.get(at..at.checked_add(2)?)?;
  Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

fn be_u32(buf: &[u8], at: usize) -> Option<usize> {
  let bytes = buf.get(at..at.checked_add(4)?)?;
  usize::try_from(u32::from_be_bytes(bytes.try_into().ok()?)).ok()
}

/// `authzid NUL user NUL password` with the decoy password, rebuilt with the
/// client's authzid and the upstream user and password. `None` for any
/// other token.
fn rewrite_plain(token: &[u8], down: &Down) -> Option<Vec<u8>> {
  let mut parts = token.splitn(3, |byte| *byte == 0);
  let (authzid, _user, password) = (parts.next()?, parts.next()?, parts.next()?);
  if password != down.fake.as_slice() {
    return None;
  }
  let nul = b"\0".as_slice();
  Some([authzid, nul, down.user.as_slice(), nul, down.real.as_slice()].concat())
}

/// One whole 0-9-1 frame through `amq-protocol`.
fn parse_whole(buf: &[u8]) -> Result<AMQPFrame, ()> {
  match parse_frame(buf) {
    Ok((&[], frame)) => Ok(frame),
    _ => Err(()),
  }
}

fn encode_091(frame: &AMQPFrame) -> Result<Vec<u8>, ()> {
  let written = gen_frame(frame)(WriteContext::from(Vec::new())).map_err(|_gen| ())?;
  Ok(written.into_inner().0)
}

/// Body offset of a whole 1.0 frame, from its data offset.
fn body_at(buf: &[u8]) -> Result<usize, ()> {
  let doff = buf.get(4).ok_or(())?;
  usize::from(*doff).checked_mul(4).ok_or(())
}

/// The performative of one whole 1.0 frame through `serde_amqp`.
fn decode_10<'de, T: Deserialize<'de>>(buf: &'de [u8]) -> Result<T, ()> {
  let body = buf.get(body_at(buf)?..).ok_or(())?;
  serde_amqp::from_slice(body).map_err(|_decode| ())
}

/// `performative` re-encoded into the frame `buf` came from: same data
/// offset, type, channel, and extended header, new size.
fn encode_10<T: Serialize>(buf: &[u8], performative: &T) -> Result<Vec<u8>, ()> {
  let at = body_at(buf)?;
  let body = serde_amqp::to_vec(performative).map_err(|_encode| ())?;
  let size = u32::try_from(at.checked_add(body.len()).ok_or(())?).map_err(|_wide| ())?;
  let mut frame = Vec::with_capacity(at.saturating_add(body.len()));
  frame.extend_from_slice(&size.to_be_bytes());
  frame.extend_from_slice(buf.get(4..at).ok_or(())?);
  frame.extend_from_slice(&body);
  Ok(frame)
}

/// A shortstr with the real password replaced by the decoy. `Err` when the
/// result no longer fits a shortstr.
fn redact_short(text: &ShortString, pair: &CredentialPair) -> Result<ShortString, ()> {
  let Some(bytes) = replace_bytes(text.as_str().as_bytes(), &pair.needle, &pair.replacement) else {
    return Ok(text.clone());
  };
  let text = String::from_utf8(bytes).map_err(|_utf8| ())?;
  ShortString::try_new(text).map_err(|_long| ())
}

/// Replace the real password inside an error description. `false` when
/// there was nothing to replace.
fn redact_error(error: Option<&mut AmqpError>, pair: &CredentialPair) -> bool {
  let Some(description) = error.and_then(|error| error.description.as_mut()) else {
    return false;
  };
  let Some(bytes) = replace_bytes(description.as_bytes(), &pair.needle, &pair.replacement) else {
    return false;
  };
  match String::from_utf8(bytes) {
    Ok(text) => {
      *description = text;
      true
    }
    Err(_utf8) => false,
  }
}

#[cfg(test)]
mod tests {
  use amq_protocol::frame::{AMQPFrame, WriteContext, gen_frame, parse_frame};
  use amq_protocol::protocol::{AMQPClass, connection};
  use amq_protocol::types::{AMQPValue, FieldTable};
  use arkham_config::grants::{AmqpScope, Credential, Grant};
  use fe2o3_amqp_types::primitives::{Binary, Symbol};
  use fe2o3_amqp_types::sasl::SaslInit;
  use secrecy::SecretString;

  use super::{Amqp, SaslMechanism};
  use crate::transports::engine::{Direction, Rewritten, Wire};

  const FAKE: &str = "arkham_fake_amqp_pass"; // betterleaks:allow
  const REAL: &str = "arkham_real_amqp_pass_longer_01"; // betterleaks:allow
  const HEADER_091: &[u8] = b"AMQP\x00\x00\x09\x01";
  const HEADER_SASL: &[u8] = b"AMQP\x03\x01\x00\x00";

  fn grants(real_scheme: &str) -> Vec<Grant> {
    let scope = AmqpScope::from_strings(
      &format!("amqp://agent:{FAKE}@mq:5672"),
      &format!("{real_scheme}://svc:{REAL}@mq:5672"),
    )
    .unwrap();
    vec![Grant::Amqp {
      credential: Credential {
        label: "amqp".into(),
        fake: FAKE.into(),
        value: SecretString::from(REAL),
      },
      scope: Box::new(scope),
    }]
  }

  fn down(swap: bool) -> Amqp {
    let real_scheme = if swap { "amqps" } else { "amqp" };
    Amqp::new(&grants(real_scheme), "mq", 5672, Direction::Downstream, swap)
  }

  fn up() -> Amqp {
    Amqp::new(&grants("amqps"), "mq", 5672, Direction::Upstream, false)
  }

  fn encode_frame(frame: &AMQPFrame) -> Vec<u8> {
    let (buf, _) = gen_frame(frame)(WriteContext::from(Vec::new())).unwrap().into_inner();
    buf
  }

  fn plain(user: &str, password: &str) -> Vec<u8> {
    format!("\0{user}\0{password}").into_bytes()
  }

  fn start_ok(mechanism: &str, response: Vec<u8>) -> Vec<u8> {
    let mut properties = FieldTable::default();
    properties.insert("product".into(), AMQPValue::LongString("arkham-test".into()));
    let mut bytes = HEADER_091.to_vec();
    bytes.extend(encode_frame(&AMQPFrame::Method(
      0,
      AMQPClass::Connection(connection::AMQPMethod::StartOk(connection::StartOk {
        client_properties: properties,
        mechanism: mechanism.into(),
        response: response.into(),
        locale: "en_US".into(),
      })),
    )));
    bytes
  }

  fn start_ok_response(bytes: &[u8]) -> (String, Vec<u8>) {
    let frame = bytes.strip_prefix(HEADER_091).expect("header first");
    let (rest, frame) = parse_frame(frame).unwrap();
    assert!(rest.is_empty(), "one frame");
    let AMQPFrame::Method(0, AMQPClass::Connection(connection::AMQPMethod::StartOk(ok))) = frame else {
      panic!("start-ok");
    };
    (ok.mechanism.as_str().to_string(), ok.response.as_bytes().to_vec())
  }

  fn sasl_init(mechanism: &str, response: Option<Vec<u8>>) -> Vec<u8> {
    let body = serde_amqp::to_vec(&SaslInit {
      mechanism: Symbol::from(mechanism),
      initial_response: response.map(Binary::from),
      hostname: Some("mq".into()),
    })
    .unwrap();
    let mut bytes = HEADER_SASL.to_vec();
    bytes.extend(u32::try_from(8 + body.len()).unwrap().to_be_bytes());
    bytes.extend([2, 1, 0, 0]);
    bytes.extend(body);
    bytes
  }

  fn sasl_init_response(bytes: &[u8]) -> Vec<u8> {
    let frame = bytes.strip_prefix(HEADER_SASL).expect("header first");
    let size = usize::try_from(u32::from_be_bytes(frame[..4].try_into().unwrap())).unwrap();
    assert_eq!(size, frame.len(), "one frame");
    let init: SaslInit = serde_amqp::from_slice(&frame[8..]).unwrap();
    init.initial_response.expect("initial response").into_vec()
  }

  fn close_091(reply_text: &str) -> Vec<u8> {
    encode_frame(&AMQPFrame::Method(
      0,
      AMQPClass::Connection(connection::AMQPMethod::Close(connection::Close {
        reply_code: 403,
        reply_text: reply_text.into(),
        class_id: 10,
        method_id: 11,
      })),
    ))
  }

  /// Feed `bytes` in one chunk, then end of stream. `None` when the leg closed.
  async fn run(wire: &mut Amqp, bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for chunk in [bytes, &[][..]] {
      match wire.feed(chunk).await.0 {
        Rewritten::Emit(emitted) => out.extend_from_slice(&emitted),
        Rewritten::Hold => {}
        Rewritten::Close => return None,
      }
    }
    Some(out)
  }

  fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle.as_bytes())
  }

  #[tokio::test]
  async fn amqp_plain_start_ok_swaps_a_longer_real_password_when_upstream_is_tls() {
    let wire = start_ok("PLAIN", plain("agent", FAKE));
    let out = run(&mut down(true), &wire).await.expect("emitted");
    let (mechanism, response) = start_ok_response(&out);
    assert_eq!(mechanism, "PLAIN");
    assert_eq!(response, plain("svc", REAL));
    assert!(!contains(&out, FAKE));
  }

  #[tokio::test]
  async fn amqp_plain_start_ok_keeps_the_decoy_when_upstream_is_cleartext() {
    let wire = start_ok("PLAIN", plain("agent", FAKE));
    let out = run(&mut down(false), &wire).await.expect("emitted");
    assert_eq!(out, wire);
    assert!(!contains(&out, REAL));
  }

  #[tokio::test]
  async fn amqp_amqplain_start_ok_passes_through_unchanged() {
    let wire = start_ok("AMQPLAIN", plain("agent", FAKE));
    let out = run(&mut down(true), &wire).await.expect("emitted");
    assert_eq!(out, wire);
    assert!(!contains(&out, REAL));
  }

  #[tokio::test]
  async fn amqp_sasl_init_plain_swaps_only_when_upstream_is_tls() {
    let wire = sasl_init("PLAIN", Some(plain("agent", FAKE)));
    let out = run(&mut down(true), &wire).await.expect("emitted");
    assert_eq!(sasl_init_response(&out), plain("svc", REAL));
    assert!(!contains(&out, FAKE));
    let out = run(&mut down(false), &wire).await.expect("emitted");
    assert_eq!(out, wire);
    assert!(!contains(&out, REAL));
  }

  #[tokio::test]
  async fn amqp_connection_close_reply_text_is_redacted_to_the_decoy() {
    let wire = close_091(&format!("ACCESS_REFUSED - password {REAL} refused"));
    let out = run(&mut up(), &wire).await.expect("emitted");
    assert!(!contains(&out, REAL));
    let (rest, frame) = parse_frame(out.as_slice()).unwrap();
    assert!(rest.is_empty(), "one frame");
    let AMQPFrame::Method(0, AMQPClass::Connection(connection::AMQPMethod::Close(close))) = frame else {
      panic!("connection.close");
    };
    assert_eq!(close.reply_text.as_str(), format!("ACCESS_REFUSED - password {FAKE} refused"));
  }

  #[tokio::test]
  async fn amqp_split_credential_at_eof_closes_without_panicking() {
    let wire = start_ok("PLAIN", plain("agent", FAKE));
    for cut in 1..wire.len() {
      let mut machine = down(true);
      let mut out = Vec::new();
      if let Rewritten::Emit(emitted) = machine.feed(&wire[..cut]).await.0 {
        out.extend_from_slice(&emitted);
      }
      let end = machine.feed(&[]).await.0;
      if cut == HEADER_091.len() {
        assert!(matches!(end, Rewritten::Hold), "a whole header ends cleanly");
        assert_eq!(out, HEADER_091);
        continue;
      }
      assert!(matches!(end, Rewritten::Close), "cut {cut}");
      assert!(HEADER_091.starts_with(&out), "cut {cut} emitted part of the credential frame");
    }
  }

  #[test]
  fn amqp_only_plain_swaps() {
    let plain: SaslMechanism = "PLAIN".parse().unwrap();
    assert!(plain.swaps());
    for name in ["AMQPLAIN", "EXTERNAL", "ANONYMOUS", "RABBIT-CR-DEMO"] {
      let mechanism: SaslMechanism = name.parse().unwrap();
      assert!(!mechanism.swaps(), "{name}");
    }
    "SCRAM-SHA-256".parse::<SaslMechanism>().unwrap_err();
  }
}
