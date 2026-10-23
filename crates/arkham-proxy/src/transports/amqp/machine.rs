use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::OnceLock;

use amq_protocol::auth::SASLMechanism;
use amq_protocol::frame::parsing::{parse_channel, parse_frame_type};
use amq_protocol::frame::{AMQPFrame, AMQPFrameType, ParserError, ProtocolVersion, WriteContext, gen_frame, parse_frame};
use amq_protocol::protocol::constants::{FRAME_BODY, FRAME_END, FRAME_HEADER, FRAME_METHOD};
use amq_protocol::protocol::{AMQPClass, channel, connection};
use amq_protocol::types::ShortString;
use amq_protocol::types::parsing::{parse_id, parse_long_long_uint, parse_long_uint, parse_short_uint};
use arkham_config::grants::Grant;
use fe2o3_amqp_types::definitions::{Error as AmqpError, MAJOR, MINOR, REVISION};
use fe2o3_amqp_types::performatives::{Close, Detach, End, MaxFrameSize, Open, Transfer};
use fe2o3_amqp_types::primitives::Binary;
use fe2o3_amqp_types::sasl::{SaslInit, SaslResponse};
use secrecy::ExposeSecret as _;
use serde_amqp::descriptor::Descriptor;
use serde_amqp::primitives::Symbol;
use serde_amqp::serde::de::DeserializeOwned;
use serde_amqp::serde::{Deserialize, Serialize};

use crate::transports::engine::{
  CredentialPair, Direction, Hit, Location, Rewritten, Wire, find_new_match, needle_prefix_suffix_len, replace_bytes,
};

/// Protocol header length. `parse_protocol_header` does not return a partial version.
const PROTOCOL_HEADER_LEN: usize = 8;

/// A credential or close frame is stored only up to this many bytes.
/// A larger body or transfer still withholds its tail. Anything else is forwarded.
pub(crate) const MAX_CREDENTIAL_FRAME: usize = 16_384;

/// Smallest `frame-max` an AMQP 0-9-1 peer can negotiate.
const MIN_FRAME_091: usize = 4096;

/// Smallest `max-frame-size` an AMQP 1.0 peer can negotiate.
const MIN_FRAME_10: usize = 512;

/// Retained payload bytes one connection may hold.
const CARRY_BYTES: usize = MAX_CREDENTIAL_FRAME;

/// Unfinished links one connection may remember.
const CARRY_ENTRIES: usize = 32;

const TYPE_CHANNEL_AND_SIZE: usize = 7;

const CLASS_AND_METHOD_IDS: usize = 4;

const FRAME_HEADER_10: usize = 8;

/// AMQP frame type. Not exported by `fe2o3-amqp-types`.
const FRAME_AMQP: u8 = 0;

/// SASL frame type. Not exported by `fe2o3-amqp-types`.
const FRAME_SASL: u8 = 1;

fn start_ok_ids() -> (u16, u16) {
  static IDS: OnceLock<(u16, u16)> = OnceLock::new();
  *IDS.get_or_init(|| {
    let method = connection::StartOk::default();
    (method.get_amqp_class_id(), method.get_amqp_method_id())
  })
}

fn connection_close_ids() -> (u16, u16) {
  static IDS: OnceLock<(u16, u16)> = OnceLock::new();
  *IDS.get_or_init(|| {
    let method = connection::Close::default();
    (method.get_amqp_class_id(), method.get_amqp_method_id())
  })
}

fn channel_close_ids() -> (u16, u16) {
  static IDS: OnceLock<(u16, u16)> = OnceLock::new();
  *IDS.get_or_init(|| {
    let method = channel::Close::default();
    (method.get_amqp_class_id(), method.get_amqp_method_id())
  })
}

fn sasl_init_code() -> Option<u64> {
  remembered(&SASL_INIT_CODE, &sample_sasl_init())
}

fn sasl_response_code() -> Option<u64> {
  remembered(&SASL_RESPONSE_CODE, &sample_sasl_response())
}

fn detach_code() -> Option<u64> {
  remembered(&DETACH_CODE, &sample_detach())
}

fn end_code() -> Option<u64> {
  remembered(&END_CODE, &sample_end())
}

fn close_code() -> Option<u64> {
  remembered(&CLOSE_CODE, &sample_close())
}

fn transfer_code() -> Option<u64> {
  remembered(&TRANSFER_CODE, &sample_transfer())
}

static SASL_INIT_CODE: OnceLock<u64> = OnceLock::new();
static SASL_RESPONSE_CODE: OnceLock<u64> = OnceLock::new();
static DETACH_CODE: OnceLock<u64> = OnceLock::new();
static END_CODE: OnceLock<u64> = OnceLock::new();
static CLOSE_CODE: OnceLock<u64> = OnceLock::new();
static TRANSFER_CODE: OnceLock<u64> = OnceLock::new();

fn remembered<T: Serialize>(slot: &OnceLock<u64>, sample: &T) -> Option<u64> {
  if let Some(code) = slot.get() {
    return Some(*code);
  }
  let code = encoded_code(sample)?;
  let _ = slot.set(code);
  Some(code)
}

fn encoded_code<T: Serialize>(sample: &T) -> Option<u64> {
  let encoded = serde_amqp::to_vec(sample).ok()?;
  match serde_amqp::from_slice::<Descriptor>(&encoded).ok()? {
    Descriptor::Code(code) => Some(code),
    Descriptor::Name(_) => None,
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SaslMechanism {
  Plain,
  Amqplain,
  External,
  Anonymous,
  RabbitCrDemo,
}

impl SaslMechanism {
  pub(crate) fn swaps(self) -> bool {
    matches!(self, Self::Plain)
  }
}

impl FromStr for SaslMechanism {
  type Err = ();

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

pub(crate) struct Amqp {
  down: Option<Down>,
  up: Option<CredentialPair>,
  framer: Framer,
  phase: Phase,
  carries: HashMap<Link, Carry>,
  /// Bytes withheld so a secret split across reads is visible before it is written.
  tail: Vec<u8>,
  /// Typed reason for the close, when the machine has one.
  fault: Option<crate::Error>,
  /// The next AMQP frame is the guest Open and must be lowered.
  lower_open: bool,
  closed: bool,
}

struct Down {
  fake: Vec<u8>,
  user: Vec<u8>,
  real: Vec<u8>,
  label: String,
  awaiting_response: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Framer {
  V091,
  /// AMQP 1.0. `sasl` while the SASL layer runs: a protocol header may
  /// follow any of its frames.
  V10 {
    sasl: bool,
  },
}

enum Phase {
  Header(Vec<u8>),
  Head(Vec<u8>),
  Frame { buf: Vec<u8>, total: usize, kind: Kind },
  Forward(Fwd),
  Opaque,
}

enum Fwd {
  Copy { left: usize },
  Scan { left: usize },
  Delay { left: usize, delay: Delay },
}

/// The unread tail of one body or transfer. `keep` is withheld. The frame on the wire is shorter.
struct Delay {
  link: Link,
  new_left: u64,
  emit_left: usize,
  keep_left: usize,
  keep: Vec<u8>,
  /// Write `FRAME_END` once `emit_left` hits zero. 0-9-1 only.
  end: bool,
  ended: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Link {
  channel: u16,
  handle: Option<u32>,
}

struct Carry {
  held: Vec<u8>,
  left: Option<u64>,
}

#[derive(Clone, Copy)]
enum Kind {
  StartOk,
  SaslInit,
  SaslResponse,
  Open,
  Close091,
  CloseEndDetach(u64),
  Scan,
}

enum InitRewrite {
  Unchanged,
  Rewritten(Vec<u8>),
  AwaitResponse,
}

enum Classified {
  AbsoluteHead(usize),
  Hold {
    total: usize,
    kind: Kind,
  },
  Forward {
    total: usize,
  },
  Message {
    total: usize,
    transfer: Option<Transfer>,
    payload_at: usize,
  },
}

enum OpenRewrite {
  Forward,
  Rewritten(Vec<u8>),
  Close,
}

impl Amqp {
  /// # Errors
  ///
  /// Returns [`crate::Error::AmqpSecretTooLong`] when the upstream password cannot fit in one
  /// 0-9-1 body frame under the protocol minimum frame size.
  pub(crate) fn new(grants: &[Grant], host: &str, port: u16, dir: Direction, swap: bool) -> Result<Self, crate::Error> {
    let found = grants.iter().find_map(|grant| {
      let scope = grant.amqp(Some(host), port)?;
      let label = grant.credential().map(|credential| credential.label.clone()).unwrap_or_default();
      Some((scope, label))
    });
    if let Some((scope, _)) = &found {
      secret_fits(scope.upstream.password.expose_secret().len())?;
    }
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
    Ok(Self {
      down,
      up,
      framer: Framer::V091,
      phase,
      carries: HashMap::new(),
      tail: Vec::new(),
      fault: None,
      lower_open: false,
      closed: false,
    })
  }
}

fn secret_fits(len: usize) -> Result<(), crate::Error> {
  let held = len.saturating_sub(1);
  let body = held.saturating_add(TYPE_CHANNEL_AND_SIZE.saturating_add(1));
  if body > MIN_FRAME_091 {
    return Err(crate::Error::AmqpSecretTooLong { len });
  }
  Ok(())
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
      if self.step(&mut input, &mut out, &mut hits).is_err() || input.len() == before {
        self.closed = true;
        if let Some(err) = self.close_reason() {
          tracing::debug!(error = %err, "amqp connection closed");
        }
        return (Rewritten::Close, hits);
      }
    }
    if out.is_empty() {
      (Rewritten::Hold, hits)
    } else {
      (Rewritten::Emit(Cow::Owned(out)), hits)
    }
  }

  fn finish(&mut self) -> (Rewritten<'static>, Vec<Hit>) {
    // An Open that never completed is still the guest's bytes. Emit them.
    // Any other unfinished frame is a protocol error and closes.
    let lower = std::mem::take(&mut self.lower_open);
    let phase = std::mem::replace(&mut self.phase, Phase::Opaque);
    let pending = match phase {
      Phase::Header(buf) | Phase::Head(buf) | Phase::Frame { buf, .. } if lower => Some(buf),
      other => {
        self.phase = other;
        None
      }
    };
    if let Some(buf) = pending {
      return if buf.is_empty() {
        (Rewritten::Hold, Vec::new())
      } else {
        (Rewritten::Emit(Cow::Owned(buf)), Vec::new())
      };
    }
    let idle = match &self.phase {
      Phase::Header(buf) | Phase::Head(buf) => buf.is_empty(),
      Phase::Opaque => true,
      Phase::Frame { .. } | Phase::Forward(_) => false,
    };
    if !idle || self.carries.values().any(|carry| !carry.held.is_empty()) {
      self.closed = true;
      return (Rewritten::Close, Vec::new());
    }
    let flushed = std::mem::take(&mut self.tail);
    if flushed.is_empty() {
      (Rewritten::Hold, Vec::new())
    } else {
      (Rewritten::Emit(Cow::Owned(flushed)), Vec::new())
    }
  }

  fn step(&mut self, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), ()> {
    match std::mem::replace(&mut self.phase, Phase::Opaque) {
      Phase::Header(buf) => self.drive_header(buf, input, out, hits),
      Phase::Head(buf) => self.drive_head(buf, input, out, hits),
      Phase::Frame { buf, total, kind } => self.drive_frame(buf, total, kind, input, out, hits),
      Phase::Forward(fwd) => {
        self.phase = self.forward_rest(fwd, input, out)?;
        Ok(())
      }
      Phase::Opaque => self.opaque(input, out),
    }
  }

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
    if buf.is_empty() && input.first().is_some_and(|lead| *lead != protocol_lead()) {
      if self.lower_open {
        self.refuse_open();
        return Err(());
      }
      if self.down.is_some() {
        return self.opaque(input, out);
      }
      self.framer = Framer::V091;
      return self.drive_head(Vec::new(), input, out, hits);
    }
    // `parse_protocol_header` returns Incomplete on a short slice and does not yield a partial version.
    take(&mut buf, PROTOCOL_HEADER_LEN, input);
    if buf.len() < PROTOCOL_HEADER_LEN {
      self.phase = Phase::Header(buf);
      return Ok(());
    }
    self.pass(&buf, out)?;
    let Some(framer) = header_framer(self.down.is_some(), &buf) else {
      if self.lower_open {
        self.refuse_open();
        return Err(());
      }
      self.phase = Phase::Opaque;
      return Ok(());
    };
    self.framer = framer;
    out.extend(std::mem::take(&mut self.tail));
    if self.down.is_some() && matches!(framer, Framer::V10 { sasl: false }) {
      self.lower_open = true;
    } else if self.lower_open {
      self.refuse_open();
      return Err(());
    }
    self.phase = Phase::Head(Vec::new());
    Ok(())
  }

  fn drive_head(&mut self, mut buf: Vec<u8>, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), ()> {
    if buf.is_empty() && self.framer == (Framer::V10 { sasl: true }) && input.first() == Some(&protocol_lead()) {
      if self.down.is_some() && !self.lower_open {
        return self.opaque(input, out);
      }
      return self.drive_header(Vec::new(), input, out, hits);
    }
    loop {
      let Ok(classified) = self.classify(&buf) else {
        self.refuse_open();
        return Err(());
      };
      match classified {
        Classified::AbsoluteHead(need) => {
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
          self.phase = self.begin_forward(&buf, total, input, out)?;
          return Ok(());
        }
        Classified::Message {
          total,
          transfer,
          payload_at,
        } => {
          self.phase = self.open_message(&buf, total, transfer, payload_at, input, out)?;
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

  fn classify_091(&self, buf: &[u8]) -> Result<Classified, ()> {
    let Some(size) = payload_len_091(buf)? else {
      return Ok(Classified::AbsoluteHead(TYPE_CHANNEL_AND_SIZE));
    };
    let total = TYPE_CHANNEL_AND_SIZE
      .checked_add(size)
      .and_then(|len| len.checked_add(1))
      .ok_or(())?;
    if buf.first() == Some(&FRAME_BODY) && self.up.is_some() {
      return Ok(Self::ready_message(self, buf, total, TYPE_CHANNEL_AND_SIZE, size, None));
    }
    let method = if buf.first() == Some(&FRAME_METHOD)
      && size >= CLASS_AND_METHOD_IDS
      && (self.up.is_some() || (self.down.is_some() && total <= MAX_CREDENTIAL_FRAME))
    {
      let method_head = TYPE_CHANNEL_AND_SIZE + CLASS_AND_METHOD_IDS;
      let Some(payload) = buf.get(TYPE_CHANNEL_AND_SIZE..) else {
        return Ok(Classified::AbsoluteHead(method_head));
      };
      match method_ids(payload)? {
        Some(pair) => Some(pair),
        None => return Ok(Classified::AbsoluteHead(method_head)),
      }
    } else {
      None
    };
    if let Some(pair) = method
      && self.up.is_some()
      && (pair == connection_close_ids() || pair == channel_close_ids())
      && total > MAX_CREDENTIAL_FRAME
    {
      return Err(());
    }
    if total > MAX_CREDENTIAL_FRAME {
      if self.up.is_some() && buf.first() == Some(&FRAME_HEADER) {
        let need = TYPE_CHANNEL_AND_SIZE.saturating_add(12);
        if buf.len() < need && need <= total {
          return Ok(Classified::AbsoluteHead(need));
        }
      }
      return Ok(Classified::Forward { total });
    }
    if let Some(pair) = method {
      if pair == start_ok_ids() && self.down.is_some() {
        return Ok(Classified::Hold {
          total,
          kind: Kind::StartOk,
        });
      }
      if self.up.is_some() && (pair == connection_close_ids() || pair == channel_close_ids()) {
        return Ok(Classified::Hold {
          total,
          kind: Kind::Close091,
        });
      }
    }
    if self.up.is_some() {
      return Ok(Classified::Hold { total, kind: Kind::Scan });
    }
    Ok(Classified::Forward { total })
  }

  fn classify_10(&self, buf: &[u8]) -> Result<Classified, ()> {
    let Some((after_size, total)) = frame_len_10(buf)? else {
      return Ok(Classified::AbsoluteHead(FRAME_HEADER_10));
    };
    if self.lower_open {
      return if !(FRAME_HEADER_10..=MAX_CREDENTIAL_FRAME).contains(&total) {
        Err(())
      } else if buf.len() < total {
        Ok(Classified::AbsoluteHead(total))
      } else {
        Ok(Classified::Hold { total, kind: Kind::Open })
      };
    }
    let Some((&doff, after_doff)) = after_size.split_first() else {
      return Ok(Classified::AbsoluteHead(FRAME_HEADER_10));
    };
    let Some(&frame_type) = after_doff.first() else {
      return Ok(Classified::AbsoluteHead(FRAME_HEADER_10));
    };
    let data_offset = usize::from(doff).checked_mul(4).ok_or(())?;
    if data_offset < FRAME_HEADER_10 || data_offset > total {
      return Err(());
    }
    let forward = Classified::Forward { total };
    if self.up.is_some() && frame_type == FRAME_AMQP {
      return self.classify_amqp(buf, total, data_offset, forward);
    }
    if total > MAX_CREDENTIAL_FRAME || frame_type != FRAME_SASL || self.down.is_none() || data_offset == total {
      return Ok(forward);
    }
    if buf.len() < data_offset {
      return Ok(Classified::AbsoluteHead(data_offset));
    }
    let end = buf.len().min(total);
    let Some(body) = buf.get(data_offset..end) else {
      return Ok(forward);
    };
    let budget = total.checked_sub(data_offset).ok_or(())?;
    let code = match descriptor_code(body, budget) {
      DescriptorRead::Code(code) => code,
      DescriptorRead::Forward => return Ok(forward),
      DescriptorRead::Need => {
        let need = buf.len().checked_add(1).ok_or(())?;
        if need > total {
          return Ok(forward);
        }
        return Ok(Classified::AbsoluteHead(need));
      }
    };
    let kind = if Some(code) == sasl_init_code() {
      Kind::SaslInit
    } else if Some(code) == sasl_response_code() && self.down.as_ref().is_some_and(|down| down.awaiting_response) {
      Kind::SaslResponse
    } else {
      return Ok(forward);
    };
    Ok(Classified::Hold { total, kind })
  }

  /// An AMQP frame with an upstream secret. A transfer that does not decode within
  /// [`MAX_CREDENTIAL_FRAME`] closes. A decoded close, end, or detach larger than that
  /// cap closes. A teardown that does not decode is forwarded.
  fn classify_amqp(&self, buf: &[u8], total: usize, data_offset: usize, forward: Classified) -> Result<Classified, ()> {
    if buf.len() < data_offset {
      return Ok(Classified::AbsoluteHead(data_offset));
    }
    let Some(body) = buf.get(data_offset..) else {
      return Ok(forward);
    };
    let budget = total.checked_sub(data_offset).ok_or(())?;
    let code = match descriptor_code(body, budget) {
      DescriptorRead::Code(code) => code,
      DescriptorRead::Forward => return Ok(Self::plain_amqp(total, forward)),
      DescriptorRead::Need => return Self::more_bytes(buf, total, data_offset, false),
    };
    let transfer = Some(code) == transfer_code();
    let teardown = Some(code) == detach_code() || Some(code) == end_code() || Some(code) == close_code();
    if !transfer && !teardown {
      return Ok(Self::plain_amqp(total, forward));
    }
    let Ok(perf) = consume_value(body, PERFORMATIVE_NESTING) else {
      return Self::more_bytes(buf, total, data_offset, transfer);
    };
    if transfer {
      let Some(encoded) = body.get(..perf) else {
        return Err(());
      };
      let decoded = match serde_amqp::from_slice::<Transfer>(encoded) {
        Ok(decoded) => decoded,
        Err(_decode) => {
          return if total > MAX_CREDENTIAL_FRAME {
            Err(())
          } else {
            Ok(Self::plain_amqp(total, forward))
          };
        }
      };
      let payload_at = data_offset.saturating_add(perf);
      let payload_len = total.checked_sub(payload_at).ok_or(())?;
      return Ok(Self::ready_message(self, buf, total, payload_at, payload_len, Some(decoded)));
    }
    if total <= MAX_CREDENTIAL_FRAME && buf.len() < total {
      return Ok(Classified::AbsoluteHead(total));
    }
    if total <= MAX_CREDENTIAL_FRAME {
      return Ok(Classified::Hold {
        total,
        kind: Kind::CloseEndDetach(code),
      });
    }
    Err(())
  }

  fn plain_amqp(total: usize, forward: Classified) -> Classified {
    if total > MAX_CREDENTIAL_FRAME {
      forward
    } else {
      Classified::Hold { total, kind: Kind::Scan }
    }
  }

  fn more_bytes(buf: &[u8], total: usize, data_offset: usize, close_at_cap: bool) -> Result<Classified, ()> {
    let need = buf.len().checked_add(1).ok_or(())?;
    let cap = data_offset.saturating_add(MAX_CREDENTIAL_FRAME);
    let forward = Classified::Forward { total };
    if need > cap || need > total {
      if close_at_cap && (need > cap || total > MAX_CREDENTIAL_FRAME) {
        return Err(());
      }
      return Ok(Self::plain_amqp(total, forward));
    }
    Ok(Classified::AbsoluteHead(need))
  }

  fn ready_message(
    machine: &Self,
    buf: &[u8],
    total: usize,
    payload_at: usize,
    payload_len: usize,
    transfer: Option<Transfer>,
  ) -> Classified {
    let head = machine.needle_room().min(payload_len);
    let need = if total <= MAX_CREDENTIAL_FRAME {
      total
    } else {
      payload_at.saturating_add(head)
    };
    if buf.len() < need {
      Classified::AbsoluteHead(need)
    } else {
      Classified::Message {
        total,
        transfer,
        payload_at,
      }
    }
  }

  fn needle_room(&self) -> usize {
    if let Some(pair) = &self.up {
      return pair.needle.len().saturating_sub(1);
    }
    self.down.as_ref().map_or(0, |down| down.real.len().saturating_sub(1))
  }

  fn drive_frame(
    &mut self,
    mut buf: Vec<u8>,
    total: usize,
    kind: Kind,
    input: &mut &[u8],
    out: &mut Vec<u8>,
    hits: &mut Vec<Hit>,
  ) -> Result<(), ()> {
    if total > MAX_CREDENTIAL_FRAME {
      self.phase = self.begin_forward(&buf, total, input, out)?;
      return Ok(());
    }
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
        out.extend_from_slice(rewritten.as_deref().unwrap_or(&buf));
        self.phase = Phase::Opaque;
      }
      Kind::SaslInit => {
        let outcome = self.sasl_init(&buf, hits)?;
        let await_response = matches!(outcome, InitRewrite::AwaitResponse);
        let frame = match outcome {
          InitRewrite::Rewritten(frame) => frame,
          InitRewrite::Unchanged | InitRewrite::AwaitResponse => buf,
        };
        out.extend_from_slice(&frame);
        if await_response {
          self.phase = Phase::Head(Vec::new());
        } else {
          self.lower_open = true;
          self.phase = Phase::Header(Vec::new());
        }
      }
      Kind::SaslResponse => {
        let rewritten = self.sasl_response(&buf, hits)?;
        out.extend_from_slice(rewritten.as_deref().unwrap_or(&buf));
        self.lower_open = true;
        self.phase = Phase::Header(Vec::new());
      }
      Kind::Open => {
        match self.rewrite_open(&buf) {
          OpenRewrite::Rewritten(frame) => out.extend_from_slice(&frame),
          OpenRewrite::Forward => out.extend_from_slice(&buf),
          OpenRewrite::Close => return Err(()),
        }
        self.lower_open = false;
        self.phase = Phase::Opaque;
      }
      Kind::Close091 => {
        self.forget_091(&buf);
        let redacted = self.close_091(&buf, hits)?;
        self.copy_scanned(redacted.as_deref().unwrap_or(&buf), out)?;
        self.phase = Phase::Head(Vec::new());
      }
      Kind::CloseEndDetach(code) => {
        self.forget_10(&buf, code);
        let redacted = self.error_10(&buf, code, hits)?;
        self.copy_scanned(redacted.as_deref().unwrap_or(&buf), out)?;
        self.phase = Phase::Head(Vec::new());
      }
      Kind::Scan => {
        self.on_scanned(&buf, out)?;
        self.phase = Phase::Head(Vec::new());
      }
    }
    Ok(())
  }

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

  fn sasl_init(&mut self, buf: &[u8], hits: &mut Vec<Hit>) -> Result<InitRewrite, ()> {
    let mut init: SaslInit = decode_10(buf)?;
    let Some(down) = self.down.as_mut() else {
      return Err(());
    };
    if !SaslMechanism::from_str(init.mechanism.as_str()).is_ok_and(SaslMechanism::swaps) {
      return Ok(InitRewrite::Unchanged);
    }
    let Some(response) = init.initial_response.as_ref() else {
      down.awaiting_response = true;
      return Ok(InitRewrite::AwaitResponse);
    };
    let Some(token) = rewrite_plain(response, down) else {
      return Ok(InitRewrite::Unchanged);
    };
    init.initial_response = Some(Binary::from(token));
    hits.push(Hit {
      label: down.label.clone(),
      location: Location::Body,
    });
    Ok(InitRewrite::Rewritten(encode_10(buf, &init, &[])?))
  }

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
    Ok(Some(encode_10(buf, &response, &[])?))
  }

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

  fn error_10(&self, buf: &[u8], code: u64, hits: &mut Vec<Hit>) -> Result<Option<Vec<u8>>, ()> {
    let Some(pair) = self.up.as_ref().filter(|pair| find_new_match(buf, &pair.needle, 0)) else {
      return Ok(None);
    };
    let frame = if Some(code) == close_code() {
      let mut close: Close = decode_10(buf)?;
      redact_error(close.error.as_mut(), pair).then(|| encode_10(buf, &close, &[]))
    } else if Some(code) == end_code() {
      let mut end: End = decode_10(buf)?;
      redact_error(end.error.as_mut(), pair).then(|| encode_10(buf, &end, &[]))
    } else if Some(code) == detach_code() {
      let mut detach: Detach = decode_10(buf)?;
      redact_error(detach.error.as_mut(), pair).then(|| encode_10(buf, &detach, &[]))
    } else {
      None
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

  fn pass(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    let Some(pair) = self.up.as_ref().filter(|pair| !pair.needle.is_empty()) else {
      out.extend_from_slice(data);
      return Ok(());
    };
    let mut combined = std::mem::take(&mut self.tail);
    combined.extend_from_slice(data);
    if memchr::memmem::find(&combined, &pair.needle).is_some() {
      return Err(());
    }
    let bound = pair.needle.len().saturating_sub(1);
    let hold = needle_prefix_suffix_len(&combined, std::slice::from_ref(pair), bound);
    let emit = combined.len().saturating_sub(hold);
    let Some(head) = combined.get(..emit) else {
      return Err(());
    };
    out.extend_from_slice(head);
    self.tail = combined.split_off(emit);
    Ok(())
  }

  fn suffix(&self, data: &[u8]) -> usize {
    let Some(pair) = self.up.as_ref() else {
      return 0;
    };
    let bound = pair.needle.len().saturating_sub(1);
    needle_prefix_suffix_len(data, std::slice::from_ref(pair), bound)
  }

  fn has_needle(&self, data: &[u8]) -> bool {
    self
      .up
      .as_ref()
      .is_some_and(|pair| !pair.needle.is_empty() && memchr::memmem::find(data, &pair.needle).is_some())
  }

  fn crosses(&self, keep: &[u8]) -> bool {
    if self.has_needle(keep) {
      return true;
    }
    let mut boundary = self.tail.clone();
    boundary.extend_from_slice(keep);
    self.has_needle(&boundary)
  }

  fn copy_scanned(&self, frame: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    if self.has_needle(frame) {
      return Err(());
    }
    out.extend_from_slice(frame);
    Ok(())
  }

  fn take_link(&mut self, link: Link) -> Carry {
    self.carries.remove(&link).unwrap_or(Carry {
      held: Vec::new(),
      left: None,
    })
  }

  fn store(&mut self, link: Link, new_left: u64, kept: Vec<u8>) -> Result<(), ()> {
    if new_left == 0 && kept.is_empty() {
      self.carries.remove(&link);
      return Ok(());
    }
    let old = self.carries.get(&link).map_or(0, carry_weight);
    let bytes = self
      .carries
      .values()
      .map(carry_weight)
      .sum::<usize>()
      .saturating_sub(old)
      .saturating_add(kept.len());
    let entries = self.carries.len() + usize::from(!self.carries.contains_key(&link));
    if bytes > CARRY_BYTES || entries > CARRY_ENTRIES {
      self.fault = Some(crate::Error::AmqpCarryBudget { bytes, entries });
      return Err(());
    }
    self.carries.insert(
      link,
      Carry {
        held: kept,
        left: (new_left > 0).then_some(new_left),
      },
    );
    Ok(())
  }

  /// The typed close, when the budget or another named failure produced one.
  fn close_reason(&self) -> Option<&crate::Error> {
    self.fault.as_ref()
  }

  /// Record [`crate::Error::AmqpOpenUnlowered`] when this leg still has to lower the Open.
  fn refuse_open(&mut self) {
    if self.lower_open && self.fault.is_none() {
      self.fault = Some(crate::Error::AmqpOpenUnlowered);
    }
  }

  /// Lower `max-frame-size` by the withheld prefix. A value that would fall
  /// below the protocol minimum closes. Any other failure to lower closes too.
  fn rewrite_open(&mut self, frame: &[u8]) -> OpenRewrite {
    if let Ok(done) = self.lower_frame(frame) {
      return done;
    }
    self.refuse_open();
    OpenRewrite::Close
  }

  fn lower_frame(&mut self, frame: &[u8]) -> Result<OpenRewrite, ()> {
    if frame.get(5) != Some(&FRAME_AMQP) {
      return Err(());
    }
    let at = data_offset(frame)?;
    if at < FRAME_HEADER_10 || at > frame.len() {
      return Err(());
    }
    let body = frame.get(at..).ok_or(())?;
    let perf = consume_value(body, PERFORMATIVE_NESTING)?;
    let mut open: Open = serde_amqp::from_slice(body.get(..perf).ok_or(())?).map_err(|_decode| ())?;
    let room = self.needle_room();
    if room == 0 {
      return Ok(OpenRewrite::Forward);
    }
    let offered = u32::try_from(usize::from(open.max_frame_size)).map_err(|_wide| ())?;
    let lowered = u32::try_from(room).ok().and_then(|room_u32| {
      offered
        .checked_sub(room_u32)
        .filter(|value| u32::try_from(MIN_FRAME_10).is_ok_and(|min| *value >= min))
    });
    let Some(lowered) = lowered else {
      self.fault = Some(crate::Error::AmqpFrameMax { offered, room });
      return Err(());
    };
    open.max_frame_size = MaxFrameSize(lowered);
    Ok(OpenRewrite::Rewritten(encode_10(frame, &open, body.get(perf..).unwrap_or(&[]))?))
  }

  fn forget_091(&mut self, buf: &[u8]) {
    let Ok(channel) = channel_091(buf) else {
      return;
    };
    let Ok(payload) = frame_payload(Framer::V091, buf) else {
      return;
    };
    let Ok(Some(pair)) = method_ids(payload) else {
      return;
    };
    if pair == connection_close_ids() {
      self.carries.clear();
    } else if pair == channel_close_ids() {
      let link = Link { channel, handle: None };
      self.carries.remove(&link);
    }
  }

  fn forget_10(&mut self, buf: &[u8], code: u64) {
    if Some(code) == close_code() {
      self.carries.clear();
      return;
    }
    let Ok(channel) = channel_10(buf) else {
      self.carries.clear();
      return;
    };
    if Some(code) == end_code() {
      self.carries.retain(|link, _| link.channel != channel);
      return;
    }
    if Some(code) != detach_code() {
      return;
    }
    let Some(handle) = detach_handle(buf) else {
      self.carries.retain(|link, _| link.channel != channel);
      return;
    };
    let link = Link {
      channel,
      handle: Some(handle),
    };
    self.carries.remove(&link);
  }

  fn on_scanned(&mut self, frame: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    if self.up.is_none() {
      out.extend_from_slice(frame);
      return Ok(());
    }
    if matches!(self.framer, Framer::V091) && matches!(parse_frame_type(frame), Ok((_, AMQPFrameType::Header))) {
      let payload = frame_payload(self.framer, frame)?;
      self.arm_size(channel_091(frame)?, content_body_size(payload)?)?;
    }
    self.pass(frame, out)?;
    out.extend(std::mem::take(&mut self.tail));
    Ok(())
  }

  fn arm_size(&mut self, channel: u16, body_size: u64) -> Result<(), ()> {
    let link = Link { channel, handle: None };
    if let Some(carry) = self.carries.get(&link)
      && (carry.left.is_some_and(|left| left > 0) || !carry.held.is_empty())
    {
      return Err(());
    }
    self.store(link, body_size, Vec::new())
  }

  fn open_message(
    &mut self,
    buf: &[u8],
    total: usize,
    transfer: Option<Transfer>,
    payload_at: usize,
    input: &mut &[u8],
    out: &mut Vec<u8>,
  ) -> Result<Phase, ()> {
    let mut opened = opened_message(buf, total, transfer, payload_at)?;
    if opened.aborted {
      self.carries.remove(&opened.link);
      return self.begin_forward(buf, total, input, out);
    }
    let Carry { held, left } = self.take_link(opened.link);
    let payload_u = u64::try_from(opened.payload_len).map_err(|_wide| ())?;
    (opened.continues, opened.left) = match left {
      Some(left) if payload_u > left => return Err(()),
      Some(left) => (left > payload_u, left.saturating_sub(payload_u)),
      None => (opened.more_flag, 0),
    };
    self.relay(buf, total, &mut opened, held, input, out)
  }

  /// Bytes to write now, and the suffix that stays on the link.
  fn release(&self, opened: &Opened, held: &[u8], payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let mut joined = Vec::with_capacity(held.len().saturating_add(payload.len()));
    joined.extend_from_slice(held);
    joined.extend_from_slice(payload);
    if self.has_needle(&joined) {
      return Err(());
    }
    let retain = if opened.continues { self.suffix(&joined) } else { 0 };
    let keep = joined.split_off(joined.len().saturating_sub(retain));
    Ok((joined, keep))
  }

  /// One release decision for a body and a transfer. The emitted bytes go out
  /// in the same 1.0 transfer, or as their own 0-9-1 body frame.
  fn relay(
    &mut self,
    buf: &[u8],
    total: usize,
    opened: &mut Opened,
    held: Vec<u8>,
    input: &mut &[u8],
    out: &mut Vec<u8>,
  ) -> Result<Phase, ()> {
    if self.has_needle(buf) {
      return Err(());
    }
    let new_left = opened.left;
    let k = if buf.len() < total {
      let watch = self.needle_room().min(opened.payload_len);
      let end = opened.payload_at.saturating_add(watch);
      let prefix = buf.get(opened.payload_at..end).ok_or(())?;
      let mut joined = Vec::with_capacity(held.len().saturating_add(prefix.len()));
      joined.extend_from_slice(&held);
      joined.extend_from_slice(prefix);
      if self.has_needle(&joined) {
        return Err(());
      }
      if opened.continues { watch } else { 0 }
    } else {
      let end = opened.payload_at.saturating_add(opened.payload_len);
      let payload = buf.get(opened.payload_at..end).ok_or(())?;
      let held_empty = held.is_empty();
      let (emit, keep) = self.release(opened, &held, payload)?;
      if opened.transfer.is_some() {
        if held_empty && keep.is_empty() {
          self.store(opened.link, new_left, Vec::new())?;
          return self.begin_forward(buf, total, input, out);
        }
        write_transfer(buf, opened, &emit, out)?;
        self.store(opened.link, new_left, keep)?;
        return Ok(Phase::Head(Vec::new()));
      }
      if opened.continues && emit.len() <= held.len() {
        Self::write_held(opened, &emit, out)?;
        self.store(opened.link, new_left, keep)?;
        return Ok(Phase::Head(Vec::new()));
      }
      if opened.continues { keep.len() } else { 0 }
    };
    if opened.transfer.is_some() {
      opened.lead = held;
      return self.withhold(buf, total, opened, (k, new_left), input, out);
    }
    Self::write_held(opened, &held, out)?;
    if k == 0 {
      self.store(opened.link, new_left, Vec::new())?;
      self.begin_forward(buf, total, input, out)
    } else {
      self.withhold(buf, total, opened, (k, new_left), input, out)
    }
  }

  fn write_held(opened: &Opened, held: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    if held.is_empty() {
      return Ok(());
    }
    let frame = encode_091(&AMQPFrame::Body(opened.link.channel, held.to_vec()))?;
    out.extend_from_slice(&frame);
    Ok(())
  }

  fn withhold(
    &mut self,
    buf: &[u8],
    total: usize,
    opened: &Opened,
    keep: (usize, u64),
    input: &mut &[u8],
    out: &mut Vec<u8>,
  ) -> Result<Phase, ()> {
    let (k, new_left) = keep;
    let send = opened.payload_len.saturating_sub(k);
    let have = buf.len().saturating_sub(opened.payload_at).min(opened.payload_len);
    let Some(payload) = buf.get(opened.payload_at..opened.payload_at.saturating_add(have)) else {
      return Err(());
    };
    if self.has_needle(payload) {
      return Err(());
    }
    let send_now = have.min(send);
    let Some((emit_now, keep_now)) = payload.split_at_checked(send_now) else {
      return Err(());
    };
    if send > 0 || opened.transfer.is_some() {
      write_prefix(buf, opened, total, k, out)?;
      self.pass(&opened.lead, out)?;
      self.pass(emit_now, out)?;
    }
    let mut delay = Delay {
      link: opened.link,
      new_left,
      emit_left: send.saturating_sub(send_now),
      keep_left: k.saturating_sub(keep_now.len()),
      keep: keep_now.to_vec(),
      end: opened.transfer.is_none() && send > 0,
      ended: false,
    };
    if delay.emit_left == 0 && delay.keep_left == 0 {
      self.seal(&mut delay, out)?;
    }
    if buf.len() == total {
      if delay.emit_left != 0 || delay.keep_left != 0 || (delay.end && !delay.ended) {
        return Err(());
      }
      self.store(delay.link, delay.new_left, delay.keep)?;
      return Ok(Phase::Head(Vec::new()));
    }
    let left = total.checked_sub(buf.len()).ok_or(())?;
    self.forward_rest(Fwd::Delay { left, delay }, input, out)
  }

  fn seal(&mut self, delay: &mut Delay, out: &mut Vec<u8>) -> Result<(), ()> {
    if self.crosses(&delay.keep) {
      return Err(());
    }
    out.extend(std::mem::take(&mut self.tail));
    if delay.end {
      out.push(FRAME_END);
    }
    delay.ended = true;
    Ok(())
  }

  fn begin_forward(&mut self, buf: &[u8], total: usize, input: &mut &[u8], out: &mut Vec<u8>) -> Result<Phase, ()> {
    let left = total.checked_sub(buf.len()).ok_or(())?;
    if self.up.is_none() {
      out.extend_from_slice(buf);
      return self.forward_rest(Fwd::Copy { left }, input, out);
    }
    if matches!(self.framer, Framer::V091)
      && buf.first() == Some(&FRAME_HEADER)
      && let Some(payload) = buf.get(TYPE_CHANNEL_AND_SIZE..).filter(|payload| payload.len() >= 12)
    {
      self.arm_size(channel_091(buf)?, content_body_size(payload)?)?;
    }
    self.pass(buf, out)?;
    self.forward_rest(Fwd::Scan { left }, input, out)
  }

  fn forward_rest(&mut self, mut fwd: Fwd, input: &mut &[u8], out: &mut Vec<u8>) -> Result<Phase, ()> {
    while fwd.left() > 0 && !input.is_empty() {
      let n = fwd.left().min(input.len());
      let Some(chunk) = input.get(..n) else {
        return Err(());
      };
      let chunk = chunk.to_vec();
      *input = input.get(n..).ok_or(())?;
      fwd.reduce(n);
      self.drive_fwd(&mut fwd, &chunk, out)?;
    }
    if fwd.left() == 0 {
      self.finish_fwd(fwd, out)?;
      Ok(Phase::Head(Vec::new()))
    } else {
      Ok(Phase::Forward(fwd))
    }
  }

  fn drive_fwd(&mut self, fwd: &mut Fwd, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    match fwd {
      Fwd::Copy { .. } => {
        out.extend_from_slice(chunk);
        Ok(())
      }
      Fwd::Scan { .. } => self.pass(chunk, out),
      Fwd::Delay { delay, .. } => self.drive_delay(delay, chunk, out),
    }
  }

  fn drive_delay(&mut self, delay: &mut Delay, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    let mut rest = chunk;
    if delay.emit_left > 0 {
      let n = rest.len().min(delay.emit_left);
      let Some(bytes) = rest.get(..n) else {
        return Err(());
      };
      self.pass(bytes, out)?;
      delay.emit_left = delay.emit_left.saturating_sub(n);
      rest = rest.get(n..).unwrap_or(&[]);
    }
    if delay.keep_left > 0 && !rest.is_empty() {
      let n = rest.len().min(delay.keep_left);
      let Some(bytes) = rest.get(..n) else {
        return Err(());
      };
      delay.keep.extend_from_slice(bytes);
      delay.keep_left = delay.keep_left.saturating_sub(n);
      rest = rest.get(n..).unwrap_or(&[]);
    }
    if delay.emit_left == 0 && delay.keep_left == 0 && !delay.ended {
      self.seal(delay, out)?;
    }
    if rest.is_empty() {
      return Ok(());
    }
    if delay.ended && delay.end && rest == [FRAME_END] {
      return Ok(());
    }
    Err(())
  }

  fn finish_fwd(&mut self, fwd: Fwd, out: &mut Vec<u8>) -> Result<(), ()> {
    match fwd {
      Fwd::Copy { left } => (left == 0).then_some(()).ok_or(()),
      Fwd::Scan { left } => {
        if left != 0 {
          return Err(());
        }
        out.extend(std::mem::take(&mut self.tail));
        Ok(())
      }
      Fwd::Delay { left, delay } => {
        if left != 0 || delay.emit_left != 0 || delay.keep_left != 0 || (delay.end && !delay.ended) {
          return Err(());
        }
        self.store(delay.link, delay.new_left, delay.keep)
      }
    }
  }
}

impl Fwd {
  fn left(&self) -> usize {
    match self {
      Fwd::Copy { left } | Fwd::Scan { left } | Fwd::Delay { left, .. } => *left,
    }
  }

  fn reduce(&mut self, n: usize) {
    let left = match self {
      Fwd::Copy { left } | Fwd::Scan { left } | Fwd::Delay { left, .. } => left,
    };
    *left = left.saturating_sub(n);
  }
}

fn opened_message(buf: &[u8], total: usize, transfer: Option<Transfer>, payload_at: usize) -> Result<Opened, ()> {
  let (channel, handle, tail, more_flag, aborted) = match &transfer {
    Some(transfer) => (channel_10(buf)?, Some(transfer.handle.0), 0, transfer.more, transfer.aborted),
    None => (channel_091(buf)?, None, 1, false, false),
  };
  Ok(Opened {
    link: Link { channel, handle },
    payload_at,
    payload_len: total.checked_sub(payload_at.saturating_add(tail)).ok_or(())?,
    more_flag,
    aborted,
    transfer,
    lead: Vec::new(),
    continues: false,
    left: 0,
  })
}

struct Opened {
  link: Link,
  payload_at: usize,
  payload_len: usize,
  more_flag: bool,
  aborted: bool,
  transfer: Option<Transfer>,
  /// Bytes spliced in front of this transfer's payload. Empty for 0-9-1.
  lead: Vec<u8>,
  /// The body or transfer still has bytes after this frame.
  continues: bool,
  /// Bytes still expected on this link after this frame.
  left: u64,
}

fn carry_weight(carry: &Carry) -> usize {
  carry.held.len()
}

fn write_transfer(buf: &[u8], opened: &Opened, payload: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
  let size = opened.payload_at.checked_add(payload.len()).ok_or(())?;
  let mut head = buf.get(..opened.payload_at).ok_or(())?.to_vec();
  let bytes = u32::try_from(size).map_err(|_wide| ())?;
  head.get_mut(..4).ok_or(())?.copy_from_slice(&bytes.to_be_bytes());
  out.extend_from_slice(&head);
  out.extend_from_slice(payload);
  Ok(())
}

fn write_prefix(buf: &[u8], opened: &Opened, total: usize, k: usize, out: &mut Vec<u8>) -> Result<(), ()> {
  if opened.transfer.is_none() {
    let send = opened.payload_len.saturating_sub(k);
    let mut head = buf.get(..TYPE_CHANNEL_AND_SIZE).ok_or(())?.to_vec();
    let size = u32::try_from(send).map_err(|_wide| ())?;
    head.get_mut(3..7).ok_or(())?.copy_from_slice(&size.to_be_bytes());
    out.extend_from_slice(&head);
    return Ok(());
  }
  let mut head = buf.get(..opened.payload_at).ok_or(())?.to_vec();
  let size = total.checked_sub(k).and_then(|len| len.checked_add(opened.lead.len())).ok_or(())?;
  let size = u32::try_from(size).map_err(|_wide| ())?;
  head.get_mut(..4).ok_or(())?.copy_from_slice(&size.to_be_bytes());
  out.extend_from_slice(&head);
  Ok(())
}

fn detach_handle(buf: &[u8]) -> Option<u32> {
  let offset = data_offset(buf).ok()?;
  let body = buf.get(offset..)?;
  let perf = consume_value(body, PERFORMATIVE_NESTING).ok()?;
  let encoded = body.get(..perf)?;
  serde_amqp::from_slice::<Detach>(encoded).ok().map(|detach| detach.handle.0)
}

enum DescriptorRead {
  Code(u64),
  Need,
  Forward,
}

fn protocol_lead() -> u8 {
  amq_protocol::protocol::metadata::NAME.as_bytes().first().copied().unwrap_or(0)
}

/// SASL header. `parse_protocol_header` accepts only protocol id 0, so id 3 never parses.
fn sasl_header() -> [u8; PROTOCOL_HEADER_LEN] {
  let mut bytes = [0u8; PROTOCOL_HEADER_LEN];
  for (slot, byte) in bytes.iter_mut().zip(amq_protocol::protocol::metadata::NAME.as_bytes()) {
    *slot = *byte;
  }
  if let Some(id) = bytes.get_mut(4) {
    *id = 3;
  }
  if let Some(major) = bytes.get_mut(5) {
    *major = MAJOR;
  }
  if let Some(minor) = bytes.get_mut(6) {
    *minor = MINOR;
  }
  if let Some(revision) = bytes.get_mut(7) {
    *revision = REVISION;
  }
  bytes
}

/// Class id, weight, then body size. Property flags follow those 12 bytes.
fn content_body_size(payload: &[u8]) -> Result<u64, ()> {
  let (rest, _) = parse_id(payload).map_err(|_parse| ())?;
  let (rest, _) = parse_short_uint(rest).map_err(|_parse| ())?;
  let (_, body_size) = parse_long_long_uint(rest).map_err(|_parse| ())?;
  Ok(body_size)
}

fn header_framer(downstream: bool, buf: &[u8]) -> Option<Framer> {
  if let Ok((rest, AMQPFrame::ProtocolHeader(version))) = parse_frame(buf) {
    if rest.is_empty() && downstream && version == ProtocolVersion::amqp_0_9_1() {
      return Some(Framer::V091);
    }
    if rest.is_empty() && version.major == MAJOR && version.minor == MINOR && version.revision == REVISION {
      return Some(Framer::V10 { sasl: false });
    }
  }
  if buf == sasl_header().as_slice() {
    return Some(Framer::V10 { sasl: true });
  }
  None
}

fn payload_len_091(buf: &[u8]) -> Result<Option<usize>, ()> {
  let after_type = match parse_frame_type(buf) {
    Ok((rest, _)) => rest,
    Err(ParserError::Incomplete(_)) => return Ok(None),
    Err(_) => match buf.get(1..) {
      Some(rest) => rest,
      None => return Ok(None),
    },
  };
  let after_channel = match parse_id(after_type) {
    Ok((rest, _)) => rest,
    Err(ParserError::Incomplete(_)) => return Ok(None),
    Err(_) => return Err(()),
  };
  long_uint(after_channel)
}

fn method_ids(payload: &[u8]) -> Result<Option<(u16, u16)>, ()> {
  let (rest, class_id) = match parse_id(payload) {
    Ok(parsed) => parsed,
    Err(ParserError::Incomplete(_)) => return Ok(None),
    Err(_) => return Err(()),
  };
  match parse_id(rest) {
    Ok((_, method_id)) => Ok(Some((class_id, method_id))),
    Err(ParserError::Incomplete(_)) => Ok(None),
    Err(_) => Err(()),
  }
}

fn frame_len_10(buf: &[u8]) -> Result<Option<(&[u8], usize)>, ()> {
  match parse_long_uint(buf) {
    Ok((rest, size)) => {
      let total = usize::try_from(size).map_err(|_wide| ())?;
      Ok(Some((rest, total)))
    }
    Err(ParserError::Incomplete(_)) => Ok(None),
    Err(_) => Err(()),
  }
}

fn long_uint(buf: &[u8]) -> Result<Option<usize>, ()> {
  match parse_long_uint(buf) {
    Ok((_, value)) => usize::try_from(value).map(Some).map_err(|_wide| ()),
    Err(ParserError::Incomplete(_)) => Ok(None),
    Err(_) => Err(()),
  }
}

fn descriptor_code(body: &[u8], budget: usize) -> DescriptorRead {
  // `read_bytes` allocates the declared symbol length before `read_exact`.
  // Measure that length against the frame first.
  match descriptor_width(body, budget) {
    DescriptorWidth::Forward => DescriptorRead::Forward,
    DescriptorWidth::Need => DescriptorRead::Need,
    DescriptorWidth::Ready(width) => {
      let Some(encoded) = body.get(..width) else {
        return DescriptorRead::Need;
      };
      match serde_amqp::from_slice::<Descriptor>(encoded) {
        Ok(descriptor) => match code_of(&descriptor) {
          Some(code) => DescriptorRead::Code(code),
          None => DescriptorRead::Forward,
        },
        Err(err) if descriptor_is_short(&err) => DescriptorRead::Need,
        Err(_) => DescriptorRead::Forward,
      }
    }
  }
}

enum DescriptorWidth {
  Ready(usize),
  Need,
  Forward,
}

fn descriptor_width(body: &[u8], budget: usize) -> DescriptorWidth {
  use serde_amqp::format_code::EncodingCodes;

  let Some(&marker) = body.first() else {
    return if budget > 0 {
      DescriptorWidth::Need
    } else {
      DescriptorWidth::Forward
    };
  };
  if !matches!(EncodingCodes::try_from(marker), Ok(EncodingCodes::DescribedType)) {
    return DescriptorWidth::Forward;
  }
  let Some(&code) = body.get(1) else {
    return if budget > 1 {
      DescriptorWidth::Need
    } else {
      DescriptorWidth::Forward
    };
  };
  match EncodingCodes::try_from(code) {
    Ok(EncodingCodes::Ulong0) => fixed_width(body, budget, 2),
    Ok(EncodingCodes::SmallUlong) => fixed_width(body, budget, 3),
    Ok(EncodingCodes::Ulong) => fixed_width(body, budget, 10),
    Ok(EncodingCodes::Sym8) => sym_width(body, budget, 3),
    Ok(EncodingCodes::Sym32) => sym_width(body, budget, 6),
    _ => DescriptorWidth::Forward,
  }
}

fn fixed_width(body: &[u8], budget: usize, width: usize) -> DescriptorWidth {
  if width > budget {
    DescriptorWidth::Forward
  } else if body.len() < width {
    DescriptorWidth::Need
  } else {
    DescriptorWidth::Ready(width)
  }
}

fn sym_width(body: &[u8], budget: usize, header: usize) -> DescriptorWidth {
  if header > budget {
    return DescriptorWidth::Forward;
  }
  if body.len() < header {
    return DescriptorWidth::Need;
  }
  let len = if header == 3 {
    body.get(2).copied().map(usize::from)
  } else {
    body.get(2..header).and_then(|raw| {
      let bytes = <[u8; 4]>::try_from(raw).ok()?;
      usize::try_from(u32::from_be_bytes(bytes)).ok()
    })
  };
  let Some(len) = len else {
    return if header == 3 {
      DescriptorWidth::Need
    } else {
      DescriptorWidth::Forward
    };
  };
  counted_width(body, budget, header, len)
}

fn counted_width(body: &[u8], budget: usize, header: usize, len: usize) -> DescriptorWidth {
  let Some(width) = header.checked_add(len) else {
    return DescriptorWidth::Forward;
  };
  if width > budget {
    DescriptorWidth::Forward
  } else if body.len() < width {
    DescriptorWidth::Need
  } else {
    DescriptorWidth::Ready(width)
  }
}

fn code_of(descriptor: &Descriptor) -> Option<u64> {
  match descriptor {
    Descriptor::Code(code) => Some(*code),
    Descriptor::Name(name) => symbolic_code(name.as_str()),
  }
}

fn symbolic_code(name: &str) -> Option<u64> {
  if type_accepts_name(name, &sample_sasl_init()) {
    sasl_init_code()
  } else if type_accepts_name(name, &sample_sasl_response()) {
    sasl_response_code()
  } else if type_accepts_name(name, &sample_detach()) {
    detach_code()
  } else if type_accepts_name(name, &sample_end()) {
    end_code()
  } else if type_accepts_name(name, &sample_close()) {
    close_code()
  } else if type_accepts_name(name, &sample_transfer()) {
    transfer_code()
  } else {
    None
  }
}

fn sample_sasl_init() -> SaslInit {
  SaslInit {
    mechanism: fe2o3_amqp_types::primitives::Symbol::default(),
    initial_response: None,
    hostname: None,
  }
}

fn sample_sasl_response() -> SaslResponse {
  SaslResponse {
    response: fe2o3_amqp_types::primitives::Binary::new(),
  }
}

fn sample_detach() -> Detach {
  Detach {
    handle: fe2o3_amqp_types::definitions::Handle::default(),
    closed: false,
    error: None,
  }
}

fn sample_end() -> End {
  End { error: None }
}

fn sample_close() -> Close {
  Close { error: None }
}

fn sample_transfer() -> Transfer {
  Transfer {
    handle: fe2o3_amqp_types::definitions::Handle::default(),
    delivery_id: None,
    delivery_tag: None,
    message_format: None,
    settled: None,
    more: false,
    rcv_settle_mode: None,
    state: None,
    resume: false,
    aborted: false,
    batchable: false,
  }
}

fn type_accepts_name<T>(name: &str, sample: &T) -> bool
where
  T: Serialize + DeserializeOwned,
{
  let Ok(encoded) = serde_amqp::to_vec(sample) else {
    return false;
  };
  let Some(code) = encoded_code(sample) else {
    return false;
  };
  let Ok(prefix) = serde_amqp::to_vec(&Descriptor::Code(code)) else {
    return false;
  };
  if !encoded.starts_with(&prefix) {
    return false;
  }
  let Some(tail) = encoded.get(prefix.len()..) else {
    return false;
  };
  let Ok(mut renamed) = serde_amqp::to_vec(&Descriptor::Name(Symbol::from(name))) else {
    return false;
  };
  renamed.extend_from_slice(tail);
  serde_amqp::from_slice::<T>(&renamed).is_ok()
}

fn descriptor_is_short(err: &serde_amqp::Error) -> bool {
  matches!(err, serde_amqp::Error::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof)
}

fn take(buf: &mut Vec<u8>, want: usize, input: &mut &[u8]) {
  let n = want.saturating_sub(buf.len()).min(input.len());
  if let Some((head, rest)) = input.split_at_checked(n) {
    buf.extend_from_slice(head);
    *input = rest;
  }
}

fn rewrite_plain(token: &[u8], down: &Down) -> Option<Vec<u8>> {
  let mut parts = token.splitn(3, |byte| *byte == 0);
  let (authzid, _user, password) = (parts.next()?, parts.next()?, parts.next()?);
  if password != down.fake.as_slice() {
    return None;
  }
  let nul = b"\0".as_slice();
  Some([authzid, nul, down.user.as_slice(), nul, down.real.as_slice()].concat())
}

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

fn data_offset(buf: &[u8]) -> Result<usize, ()> {
  let doff = buf.get(4).ok_or(())?;
  usize::from(*doff).checked_mul(4).ok_or(())
}

fn frame_payload(framer: Framer, frame: &[u8]) -> Result<&[u8], ()> {
  match framer {
    Framer::V091 => {
      let end_at = frame.len().checked_sub(1).ok_or(())?;
      if end_at < TYPE_CHANNEL_AND_SIZE || frame.get(end_at) != Some(&FRAME_END) {
        return Err(());
      }
      frame.get(TYPE_CHANNEL_AND_SIZE..end_at).ok_or(())
    }
    Framer::V10 { .. } => {
      let header_len = data_offset(frame)?;
      if header_len < FRAME_HEADER_10 || header_len > frame.len() {
        return Err(());
      }
      frame.get(header_len..).ok_or(())
    }
  }
}

fn channel_091(frame: &[u8]) -> Result<u16, ()> {
  let (after_type, _) = parse_frame_type(frame).map_err(|_parse| ())?;
  let (_, channel) = parse_channel(after_type).map_err(|_parse| ())?;
  Ok(channel.get_id())
}

fn channel_10(buf: &[u8]) -> Result<u16, ()> {
  let (after_size, _) = parse_long_uint(buf).map_err(|_parse| ())?;
  let Some((_, after_doff)) = after_size.split_first() else {
    return Err(());
  };
  let Some((_, after_type)) = after_doff.split_first() else {
    return Err(());
  };
  let (_, channel) = parse_channel(after_type).map_err(|_parse| ())?;
  Ok(channel.get_id())
}

fn decode_10<'de, T: Deserialize<'de>>(buf: &'de [u8]) -> Result<T, ()> {
  let body = buf.get(data_offset(buf)?..).ok_or(())?;
  consume_value(body, PERFORMATIVE_NESTING)?;
  serde_amqp::from_slice(body).map_err(|_decode| ())
}

/// Nested described values in the performatives this machine decodes.
/// Deeper input is rejected before `from_slice`.
const PERFORMATIVE_NESTING: usize = 8;

fn consume_value(buf: &[u8], nest: usize) -> Result<usize, ()> {
  if nest == 0 {
    return Err(());
  }
  let (&byte, rest) = buf.split_first().ok_or(())?;
  let code = serde_amqp::format_code::EncodingCodes::try_from(byte).map_err(|_code| ())?;
  let used = consume_payload(&code, rest, nest)?;
  used.checked_add(1).ok_or(())
}

fn consume_payload(code: &serde_amqp::format_code::EncodingCodes, buf: &[u8], nest: usize) -> Result<usize, ()> {
  use serde_amqp::format_code::EncodingCodes;
  match code {
    EncodingCodes::DescribedType => consume_described(buf, nest),
    EncodingCodes::Null
    | EncodingCodes::BooleanTrue
    | EncodingCodes::BooleanFalse
    | EncodingCodes::Uint0
    | EncodingCodes::Ulong0
    | EncodingCodes::List0 => Ok(0),
    EncodingCodes::Boolean
    | EncodingCodes::Ubyte
    | EncodingCodes::SmallUint
    | EncodingCodes::SmallUlong
    | EncodingCodes::Byte
    | EncodingCodes::SmallInt
    | EncodingCodes::SmallLong => fixed_payload(buf, 1),
    EncodingCodes::Ushort | EncodingCodes::Short => fixed_payload(buf, 2),
    EncodingCodes::Uint | EncodingCodes::Int | EncodingCodes::Float | EncodingCodes::Char | EncodingCodes::Decimal32 => {
      fixed_payload(buf, 4)
    }
    EncodingCodes::Ulong | EncodingCodes::Long | EncodingCodes::Double | EncodingCodes::Timestamp | EncodingCodes::Decimal64 => {
      fixed_payload(buf, 8)
    }
    EncodingCodes::Decimal128 | EncodingCodes::Uuid => fixed_payload(buf, 16),
    EncodingCodes::Vbin8 | EncodingCodes::Str8 | EncodingCodes::Sym8 => variable_payload(buf, 1),
    EncodingCodes::Vbin32 | EncodingCodes::Str32 | EncodingCodes::Sym32 => variable_payload(buf, 4),
    EncodingCodes::List8 => compound_payload(buf, 1, nest, false),
    EncodingCodes::Map8 => compound_payload(buf, 1, nest, true),
    EncodingCodes::List32 => compound_payload(buf, 4, nest, false),
    EncodingCodes::Map32 => compound_payload(buf, 4, nest, true),
    EncodingCodes::Array8 => array_payload(buf, 1, nest),
    EncodingCodes::Array32 => array_payload(buf, 4, nest),
  }
}

fn consume_described(buf: &[u8], nest: usize) -> Result<usize, ()> {
  let nest = nest.checked_sub(1).ok_or(())?;
  let descriptor = consume_value(buf, nest)?;
  let after = buf.get(descriptor..).ok_or(())?;
  let value = consume_value(after, nest)?;
  descriptor.checked_add(value).ok_or(())
}

fn fixed_payload(buf: &[u8], width: usize) -> Result<usize, ()> {
  if buf.len() < width { Err(()) } else { Ok(width) }
}

fn variable_payload(buf: &[u8], width: usize) -> Result<usize, ()> {
  let len = read_len(buf, width)?;
  let after = buf.get(width..).ok_or(())?;
  if len > after.len() {
    return Err(());
  }
  width.checked_add(len).ok_or(())
}

fn compound_payload(buf: &[u8], width: usize, nest: usize, map: bool) -> Result<usize, ()> {
  let size = read_len(buf, width)?;
  let after = buf.get(width..).ok_or(())?;
  if size > after.len() || size < width {
    return Err(());
  }
  let region = after.get(..size).ok_or(())?;
  let count = read_len(region, width)?;
  // `MapAccess::next_entry_seed` subtracts 2. An odd count wraps in release and reads the tail.
  if map && count % 2 != 0 {
    return Err(());
  }
  let mut elements = region.get(width..).ok_or(())?;
  if count > elements.len() {
    return Err(());
  }
  let nest = nest.checked_sub(1).ok_or(())?;
  for _ in 0..count {
    let used = consume_value(elements, nest)?;
    if used == 0 {
      return Err(());
    }
    elements = elements.get(used..).ok_or(())?;
  }
  width.checked_add(size).ok_or(())
}

fn array_payload(buf: &[u8], width: usize, nest: usize) -> Result<usize, ()> {
  use serde_amqp::format_code::EncodingCodes;
  let size = read_len(buf, width)?;
  let after = buf.get(width..).ok_or(())?;
  if size > after.len() || size < width {
    return Err(());
  }
  let region = after.get(..size).ok_or(())?;
  let count = read_len(region, width)?;
  let elements = region.get(width..).ok_or(())?;
  let Some((&ctor, elements)) = elements.split_first() else {
    return Err(());
  };
  let code = EncodingCodes::try_from(ctor).map_err(|_code| ())?;
  if matches!(
    code,
    EncodingCodes::DescribedType
      | EncodingCodes::List0
      | EncodingCodes::List8
      | EncodingCodes::List32
      | EncodingCodes::Map8
      | EncodingCodes::Map32
      | EncodingCodes::Array8
      | EncodingCodes::Array32
  ) {
    return Err(());
  }
  if matches!(
    code,
    EncodingCodes::Null
      | EncodingCodes::BooleanTrue
      | EncodingCodes::BooleanFalse
      | EncodingCodes::Uint0
      | EncodingCodes::Ulong0
      | EncodingCodes::List0
  ) {
    return width.checked_add(size).ok_or(());
  }
  let nest = nest.checked_sub(1).ok_or(())?;
  let mut elements = elements;
  for _ in 0..count {
    let used = consume_payload(&code, elements, nest)?;
    if used == 0 {
      return Err(());
    }
    elements = elements.get(used..).ok_or(())?;
  }
  width.checked_add(size).ok_or(())
}

fn read_len(buf: &[u8], width: usize) -> Result<usize, ()> {
  if width == 1 {
    return buf.first().copied().map(usize::from).ok_or(());
  }
  let bytes = <[u8; 4]>::try_from(buf.get(..4).ok_or(())?).map_err(|_len| ())?;
  usize::try_from(u32::from_be_bytes(bytes)).map_err(|_wide| ())
}

fn encode_10<T: Serialize>(buf: &[u8], performative: &T, payload: &[u8]) -> Result<Vec<u8>, ()> {
  let at = data_offset(buf)?;
  let body = serde_amqp::to_vec(performative).map_err(|_encode| ())?;
  let size = u32::try_from(
    at.checked_add(body.len())
      .and_then(|len| len.checked_add(payload.len()))
      .ok_or(())?,
  )
  .map_err(|_wide| ())?;
  // The original doff, type, channel, and extended header stay.
  let mut frame = Vec::with_capacity(at.saturating_add(body.len()).saturating_add(payload.len()));
  frame.extend_from_slice(&size.to_be_bytes());
  frame.extend_from_slice(buf.get(4..at).ok_or(())?);
  frame.extend_from_slice(&body);
  frame.extend_from_slice(payload);
  Ok(frame)
}

fn redact_short(text: &ShortString, pair: &CredentialPair) -> Result<ShortString, ()> {
  let Some(bytes) = replace_bytes(text.as_str().as_bytes(), &pair.needle, &pair.replacement) else {
    return Ok(text.clone());
  };
  let text = String::from_utf8(bytes).map_err(|_utf8| ())?;
  ShortString::try_new(text).map_err(|_long| ())
}

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
  use amq_protocol::frame::{AMQPContentHeader, AMQPFrame, WriteContext, gen_frame, parse_frame};
  use amq_protocol::protocol::basic::{self, AMQPProperties};
  use amq_protocol::protocol::{AMQPClass, channel, connection};
  use amq_protocol::types::parsing::parse_id;
  use amq_protocol::types::{AMQPValue, FieldTable};
  use arkham_config::grants::{AmqpScope, Credential, Grant};
  use fe2o3_amqp_types::definitions::Error as AmqpError;
  use fe2o3_amqp_types::definitions::{Handle, MAJOR, MINOR, REVISION};
  use fe2o3_amqp_types::messaging::{DeliveryState, Rejected};
  use fe2o3_amqp_types::performatives::{ChannelMax, Close, Detach, Flow, MaxFrameSize, Open, Transfer};
  use fe2o3_amqp_types::primitives::{Binary, Symbol};
  use fe2o3_amqp_types::sasl::SaslInit;
  use secrecy::SecretString;
  use serde_amqp::descriptor::Descriptor;
  use serde_amqp::serde::Serialize;

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
    Amqp::new(&grants(real_scheme), "mq", 5672, Direction::Downstream, swap).expect("secret fits")
  }

  fn up() -> Amqp {
    Amqp::new(&grants("amqps"), "mq", 5672, Direction::Upstream, false).expect("secret fits")
  }

  fn up_clear() -> Amqp {
    Amqp::new(&grants("amqp"), "mq", 5672, Direction::Upstream, false).expect("secret fits")
  }

  fn up_password(real: &str) -> Amqp {
    let scope = AmqpScope::from_strings(&format!("amqp://agent:{FAKE}@mq:5672"), &format!("amqps://svc:{real}@mq:5672")).unwrap();
    let grants = vec![Grant::Amqp {
      credential: Credential {
        label: "amqp".into(),
        fake: FAKE.into(),
        value: SecretString::from(real.to_owned()),
      },
      scope: Box::new(scope),
    }];
    Amqp::new(&grants, "mq", 5672, Direction::Upstream, false).expect("secret fits")
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

  fn password_split() -> (&'static [u8], &'static [u8]) {
    let prefix = "arkham_real_amqp_pass_";
    let rest = "longer_01";
    assert_eq!(prefix.len(), 22, "prefix length");
    assert_eq!(format!("{prefix}{rest}"), REAL);
    (prefix.as_bytes(), rest.as_bytes())
  }

  fn body_091(payload: &[u8]) -> Vec<u8> {
    body_on(1, payload)
  }

  fn body_on(channel: u16, payload: &[u8]) -> Vec<u8> {
    encode_frame(&AMQPFrame::Body(channel, payload.to_vec()))
  }

  fn content_header(channel: u16, body_size: u64) -> Vec<u8> {
    encode_frame(&AMQPFrame::Header(
      channel,
      AMQPContentHeader {
        class_id: 60,
        body_size,
        properties: AMQPProperties::default(),
      },
    ))
  }

  fn open_frame(max_frame_size: u32) -> Vec<u8> {
    let performative = serde_amqp::to_vec(&Open {
      container_id: "mq".into(),
      hostname: None,
      max_frame_size: MaxFrameSize(max_frame_size),
      channel_max: ChannelMax::default(),
      idle_time_out: None,
      outgoing_locales: None,
      incoming_locales: None,
      offered_capabilities: None,
      desired_capabilities: None,
      properties: None,
    })
    .unwrap();
    frame_10(0, 2, &performative, &[])
  }

  fn wide_transfer(channel: u16, more: bool, payload: &[u8]) -> Vec<u8> {
    let description = "e".repeat(200);
    let performative = serde_amqp::to_vec(&Transfer {
      handle: Handle(0),
      delivery_id: Some(2),
      delivery_tag: None,
      message_format: None,
      settled: None,
      more,
      rcv_settle_mode: None,
      state: Some(DeliveryState::Rejected(Rejected {
        error: Some(AmqpError {
          condition: fe2o3_amqp_types::definitions::AmqpError::InternalError.into(),
          description: Some(description),
          info: None::<Box<_>>,
        }),
      })),
      resume: false,
      aborted: false,
      batchable: false,
    })
    .unwrap();
    frame_10(channel, 128, &performative, payload)
  }

  fn frame_10(channel: u16, doff: u8, performative: &[u8], payload: &[u8]) -> Vec<u8> {
    let at = usize::from(doff).saturating_mul(4);
    let size = at + performative.len() + payload.len();
    let mut frame = vec![0; at];
    frame[..4].copy_from_slice(&u32::try_from(size).unwrap().to_be_bytes());
    frame[4] = doff;
    frame.extend_from_slice(performative);
    frame.extend_from_slice(payload);
    frame[6..8].copy_from_slice(&channel.to_be_bytes());
    frame
  }

  fn frame_is_transfer(frame: &[u8]) -> bool {
    let at = usize::from(frame.get(4).copied().unwrap_or(0)).saturating_mul(4);
    let Some(body) = frame.get(at..) else {
      return false;
    };
    let Ok(len) = super::consume_value(body, super::PERFORMATIVE_NESTING) else {
      return false;
    };
    body
      .get(..len)
      .is_some_and(|encoded| serde_amqp::from_slice::<Transfer>(encoded).is_ok())
  }

  fn tune(frame_max: u32) -> Vec<u8> {
    encode_frame(&AMQPFrame::Method(
      0,
      AMQPClass::Connection(connection::AMQPMethod::Tune(connection::Tune {
        channel_max: 2047,
        frame_max,
        heartbeat: 60,
      })),
    ))
  }

  fn tune_ok(frame_max: u32) -> Vec<u8> {
    encode_frame(&AMQPFrame::Method(
      0,
      AMQPClass::Connection(connection::AMQPMethod::TuneOk(connection::TuneOk {
        channel_max: 2047,
        frame_max,
        heartbeat: 60,
      })),
    ))
  }

  fn flow_frame(channel: u16) -> Vec<u8> {
    let performative = serde_amqp::to_vec(&Flow {
      next_incoming_id: None,
      incoming_window: 8,
      next_outgoing_id: 1,
      outgoing_window: 8,
      handle: None,
      delivery_count: None,
      link_credit: None,
      available: None,
      drain: false,
      echo: false,
      properties: None,
    })
    .unwrap();
    frame_10(channel, 2, &performative, &[])
  }

  fn abort_transfer(channel: u16) -> Vec<u8> {
    let performative = serde_amqp::to_vec(&Transfer {
      handle: Handle(0),
      delivery_id: Some(2),
      delivery_tag: None,
      message_format: None,
      settled: None,
      more: false,
      rcv_settle_mode: None,
      state: None,
      resume: false,
      aborted: true,
      batchable: false,
    })
    .unwrap();
    frame_10(channel, 2, &performative, &[])
  }

  fn count_transfers(bytes: &[u8]) -> usize {
    let mut rest = bytes.strip_prefix(&header_10()).unwrap_or(bytes);
    let mut count = 0usize;
    while rest.len() >= 8 {
      let size = usize::try_from(u32::from_be_bytes(rest[..4].try_into().unwrap())).unwrap();
      if size < 8 || size > rest.len() {
        break;
      }
      if frame_is_transfer(&rest[..size]) {
        count += 1;
      }
      rest = &rest[size..];
    }
    count
  }

  fn first_transfer_at(bytes: &[u8]) -> Option<usize> {
    let mut rest = bytes.strip_prefix(&header_10()).unwrap_or(bytes);
    let mut at = bytes.len().saturating_sub(rest.len());
    while rest.len() >= 8 {
      let size = usize::try_from(u32::from_be_bytes(rest[..4].try_into().unwrap())).unwrap();
      if size < 8 || size > rest.len() {
        break;
      }
      if frame_is_transfer(&rest[..size]) {
        return Some(at);
      }
      at = at.saturating_add(size);
      rest = &rest[size..];
    }
    None
  }

  fn channel_close(channel: u16) -> Vec<u8> {
    encode_frame(&AMQPFrame::Method(
      channel,
      AMQPClass::Channel(channel::AMQPMethod::Close(channel::Close {
        reply_code: 200,
        reply_text: "ok".into(),
        class_id: 0,
        method_id: 0,
      })),
    ))
  }

  fn detach_frame(channel: u16, handle: u32) -> Vec<u8> {
    let performative = serde_amqp::to_vec(&Detach {
      handle: Handle(handle),
      closed: true,
      error: None,
    })
    .unwrap();
    let size = 8 + performative.len();
    let mut frame = Vec::with_capacity(size);
    frame.extend(u32::try_from(size).unwrap().to_be_bytes());
    frame.push(2);
    frame.push(0);
    frame.extend(channel.to_be_bytes());
    frame.extend(performative);
    frame
  }

  fn ack(channel: u16) -> Vec<u8> {
    encode_frame(&AMQPFrame::Method(
      channel,
      AMQPClass::Basic(basic::AMQPMethod::Ack(basic::Ack {
        delivery_tag: 1,
        multiple: false,
      })),
    ))
  }

  fn transfer(channel: u16, more: bool, payload: &[u8]) -> Vec<u8> {
    transfer_on(channel, 0, more, payload)
  }

  fn transfer_on(channel: u16, handle: u32, more: bool, payload: &[u8]) -> Vec<u8> {
    transfer_tagged(channel, handle, more, None, payload)
  }

  fn transfer_tagged(channel: u16, handle: u32, more: bool, tag: Option<&[u8]>, payload: &[u8]) -> Vec<u8> {
    let performative = serde_amqp::to_vec(&Transfer {
      handle: Handle(handle),
      delivery_id: Some(1),
      delivery_tag: tag.map(Binary::from),
      message_format: None,
      settled: None,
      more,
      rcv_settle_mode: None,
      state: None,
      resume: false,
      aborted: false,
      batchable: false,
    })
    .unwrap();
    let size = 8 + performative.len() + payload.len();
    let mut frame = Vec::with_capacity(size);
    frame.extend(u32::try_from(size).unwrap().to_be_bytes());
    frame.push(2);
    frame.push(0);
    frame.extend(channel.to_be_bytes());
    frame.extend(performative);
    frame.extend_from_slice(payload);
    frame
  }

  fn body_payloads(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut payloads = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
      let Ok((next, frame)) = parse_frame(rest) else {
        break;
      };
      if next.len() >= rest.len() {
        break;
      }
      if let AMQPFrame::Body(_, payload) = frame {
        payloads.push(payload);
      }
      rest = next;
    }
    payloads
  }

  fn ends_with_secret_prefix(payload: &[u8]) -> bool {
    let secret = REAL.as_bytes();
    let max = payload.len().min(secret.len().saturating_sub(1));
    (1..=max).any(|len| payload.ends_with(&secret[..len]))
  }

  fn assert_no_secret_prefix(bytes: &[u8]) {
    for payload in body_payloads(bytes) {
      assert!(
        !ends_with_secret_prefix(&payload),
        "a delivered body ends with a prefix of the real secret"
      );
    }
    assert!(!contains(bytes, REAL), "guest bytes contain the password");
  }

  async fn feed_open(machine: &mut Amqp, chunk: &[u8]) -> Vec<u8> {
    match machine.feed(chunk).await.0 {
      Rewritten::Emit(emitted) => emitted.into_owned(),
      Rewritten::Hold => Vec::new(),
      Rewritten::Close => panic!("expected the machine to stay open"),
    }
  }

  fn header_10() -> [u8; 8] {
    let mut bytes = *b"AMQP\x00\x00\x00\x00";
    bytes[5] = MAJOR;
    bytes[6] = MINOR;
    bytes[7] = REVISION;
    bytes
  }

  fn bodies_spell_password(bytes: &[u8]) -> bool {
    let payloads = body_payloads(bytes);
    let password = REAL.as_bytes();
    for start in 0..payloads.len() {
      let mut joined = Vec::new();
      for payload in payloads.iter().skip(start) {
        joined.extend_from_slice(payload);
        if joined.as_slice() == password {
          return true;
        }
      }
    }
    false
  }

  fn method_ids_on_the_wire(frame: &[u8]) -> (u16, u16) {
    let payload = frame.get(7..).expect("method payload");
    let (rest, class_id) = parse_id(payload).unwrap();
    let (_, method_id) = parse_id(rest).unwrap();
    (class_id, method_id)
  }

  fn method_frame(class: AMQPClass) -> Vec<u8> {
    encode_frame(&AMQPFrame::Method(0, class))
  }

  fn numeric_descriptor<T: Serialize>(value: &T) -> u64 {
    let encoded = serde_amqp::to_vec(value).unwrap();
    let Descriptor::Code(code) = serde_amqp::from_slice(&encoded).unwrap() else {
      panic!("numeric descriptor");
    };
    code
  }

  #[test]
  fn class_and_method_ids_match_generated_frames() {
    let start_ok = method_frame(AMQPClass::Connection(connection::AMQPMethod::StartOk(
      connection::StartOk::default(),
    )));
    assert_eq!(method_ids_on_the_wire(&start_ok), super::start_ok_ids(), "start-ok");
    let connection_close = method_frame(AMQPClass::Connection(connection::AMQPMethod::Close(connection::Close::default())));
    assert_eq!(
      method_ids_on_the_wire(&connection_close),
      super::connection_close_ids(),
      "connection.close"
    );
    let channel_close = method_frame(AMQPClass::Channel(channel::AMQPMethod::Close(channel::Close::default())));
    assert_eq!(method_ids_on_the_wire(&channel_close), super::channel_close_ids(), "channel.close");
  }

  #[test]
  fn descriptor_codes_match_serialized_fe2o3_types() {
    assert_eq!(super::sasl_init_code(), Some(numeric_descriptor(&super::sample_sasl_init())));
    assert_eq!(
      super::sasl_response_code(),
      Some(numeric_descriptor(&super::sample_sasl_response()))
    );
    assert_eq!(super::detach_code(), Some(numeric_descriptor(&super::sample_detach())));
    assert_eq!(super::end_code(), Some(numeric_descriptor(&super::sample_end())));
    assert_eq!(super::close_code(), Some(numeric_descriptor(&super::sample_close())));
  }

  #[test]
  fn fe2o3_types_accept_their_descriptor_names() {
    assert!(super::type_accepts_name("amqp:sasl-init:list", &super::sample_sasl_init()));
    assert!(!super::type_accepts_name("amqp:sasl-response:list", &super::sample_sasl_init()));
    assert!(super::type_accepts_name("amqp:sasl-response:list", &super::sample_sasl_response()));
    assert!(super::type_accepts_name("amqp:detach:list", &super::sample_detach()));
    assert!(super::type_accepts_name("amqp:end:list", &super::sample_end()));
    assert!(super::type_accepts_name("amqp:close:list", &super::sample_close()));
    assert!(!super::type_accepts_name("amqp:close:list", &super::sample_end()));
  }

  #[test]
  fn symbol32_descriptor_past_the_frame_is_forwarded() {
    let mut body = vec![0x00, 0xb3];
    body.extend_from_slice(&80_000u32.to_be_bytes());
    assert!(matches!(super::descriptor_code(&body, body.len()), super::DescriptorRead::Forward));
  }

  #[test]
  fn symbol32_inside_a_performative_is_not_decoded() {
    let mut body = vec![0x00, 0x53, 0x41, 0xd0];
    let size = 4 + 1 + 4 + 1 + 1;
    body.extend_from_slice(&u32::try_from(size).unwrap().to_be_bytes());
    body.extend_from_slice(&3u32.to_be_bytes());
    body.push(0xb3);
    body.extend_from_slice(&80_000u32.to_be_bytes());
    body.extend_from_slice(&[0x40, 0x40]);
    super::consume_value(&body, super::PERFORMATIVE_NESTING).unwrap_err();
  }

  #[test]
  fn odd_map_count_with_a_long_tail_is_not_decoded() {
    let mut body = vec![0xc1, 7, 1, 0x40, 0xb0];
    body.extend_from_slice(&80_000u32.to_be_bytes());
    super::consume_value(&body, super::PERFORMATIVE_NESTING).unwrap_err();
  }

  #[test]
  fn even_map_of_two_nulls_fits() {
    let body = [0xc1, 3, 2, 0x40, 0x40];
    super::consume_value(&body, super::PERFORMATIVE_NESTING).unwrap();
  }

  #[test]
  fn encoded_sasl_init_fits_in_its_frame() {
    let body = serde_amqp::to_vec(&SaslInit {
      mechanism: Symbol::from("PLAIN"),
      initial_response: Some(Binary::from(plain("agent", FAKE))),
      hostname: Some("mq".into()),
    })
    .unwrap();
    super::consume_value(&body, super::PERFORMATIVE_NESTING).unwrap();
  }

  #[test]
  fn symbol32_prefix_inside_the_frame_waits() {
    let mut body = vec![0x00, 0xb3];
    body.extend_from_slice(&4u32.to_be_bytes());
    body.extend(b"am");
    assert!(matches!(super::descriptor_code(&body, 64), super::DescriptorRead::Need));
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
  async fn amqp_plain_start_ok_is_unchanged_when_swap_is_off() {
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
  async fn amqp_sasl_init_plain_follows_the_swap_flag() {
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

  #[tokio::test]
  async fn body_frames_split_across_two_reads_close_before_the_second_payload() {
    let (prefix, rest) = password_split();
    let header = content_header(1, u64::try_from(prefix.len() + rest.len()).unwrap());
    let frame_a = body_091(prefix);
    let frame_b = body_091(rest);
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header).await;
    assert_eq!(guest, header, "the content header is delivered");
    guest.extend(feed_open(&mut machine, &frame_a).await);
    assert_no_secret_prefix(&guest);
    assert!(
      !contains(&guest, std::str::from_utf8(prefix).unwrap()),
      "the real prefix was delivered"
    );
    let second = machine.feed(&frame_b).await.0;
    assert!(matches!(second, Rewritten::Close), "the completing body was delivered");
    assert!(!bodies_spell_password(&guest), "body payloads concatenate to the password");
  }

  #[tokio::test]
  async fn body_frames_cut_inside_the_second_header_close() {
    let (prefix, rest) = password_split();
    let header = content_header(1, u64::try_from(prefix.len() + rest.len()).unwrap());
    let frame_a = body_091(prefix);
    let frame_b = body_091(rest);
    let mut wire = header.clone();
    wire.extend_from_slice(&frame_a);
    wire.extend_from_slice(&frame_b);
    let cut = header.len() + frame_a.len() + 7;
    let (head, tail) = wire.split_at(cut);
    let mut machine = up();
    let guest = feed_open(&mut machine, head).await;
    assert_no_secret_prefix(&guest);
    assert!(
      !contains(&guest, std::str::from_utf8(prefix).unwrap()),
      "the real prefix was delivered"
    );
    assert!(
      matches!(machine.feed(tail).await.0, Rewritten::Close),
      "the second payload was delivered"
    );
    assert!(!bodies_spell_password(&guest), "body payloads concatenate to the password");
  }

  #[tokio::test]
  async fn body_frames_that_do_not_continue_the_password_stay_open() {
    let (prefix, _) = password_split();
    let header = content_header(1, u64::try_from(prefix.len() + 4).unwrap());
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header).await;
    guest.extend(feed_open(&mut machine, &body_091(prefix)).await);
    assert_no_secret_prefix(&guest);
    guest.extend(feed_open(&mut machine, &body_091(b"bbbb")).await);
    assert!(!contains(&guest, REAL), "guest bytes contain the password");
    let payloads = body_payloads(&guest);
    let mut joined = Vec::new();
    for payload in &payloads {
      joined.extend_from_slice(payload);
    }
    assert_eq!(joined, [prefix, b"bbbb"].concat(), "the finished body is delivered whole");
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn body_frames_on_another_channel_do_not_drop_the_held_suffix() {
    let (prefix, rest) = password_split();
    let header = content_header(1, u64::try_from(prefix.len() + rest.len()).unwrap());
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header).await;
    guest.extend(feed_open(&mut machine, &body_091(prefix)).await);
    let other = ack(2);
    let emitted = feed_open(&mut machine, &other).await;
    assert_eq!(emitted, other, "the other channel is forwarded");
    guest.extend(emitted);
    assert_no_secret_prefix(&guest);
    assert!(
      matches!(machine.feed(&body_091(rest)).await.0, Rewritten::Close),
      "the original channel completed the password"
    );
    assert!(
      !contains(&guest, std::str::from_utf8(prefix).unwrap()),
      "the real prefix was delivered"
    );
  }

  #[tokio::test]
  async fn a_merged_body_stays_inside_the_negotiated_frame_max() {
    let (prefix, _) = password_split();
    let filler = vec![b'q'; 40];
    let body_size = u64::try_from(prefix.len() + filler.len()).unwrap();
    let frame_max = 48u32;
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &tune(frame_max)).await;
    guest.extend(feed_open(&mut machine, &content_header(1, body_size)).await);
    guest.extend(feed_open(&mut machine, &body_091(prefix)).await);
    assert_no_secret_prefix(&guest);
    guest.extend(feed_open(&mut machine, &body_091(&filler)).await);
    let limit = usize::try_from(frame_max).unwrap();
    let mut joined = Vec::new();
    let mut rest = guest.as_slice();
    let mut saw_body = false;
    while !rest.is_empty() {
      let (next, frame) = parse_frame(rest).unwrap();
      assert!(rest.len() - next.len() <= limit, "a delivered frame exceeds frame-max");
      if let AMQPFrame::Body(_, payload) = frame {
        saw_body = true;
        joined.extend(payload);
      }
      rest = next;
    }
    assert!(saw_body, "the finished body was delivered");
    assert_eq!(joined, [prefix, filler.as_slice()].concat());
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn a_large_body_frame_holds_its_suffix_until_the_content_ends() {
    let (prefix, rest) = password_split();
    let mut payload = vec![b'z'; super::MAX_CREDENTIAL_FRAME];
    let start = payload.len() - prefix.len();
    payload[start..].copy_from_slice(prefix);
    let header = content_header(1, u64::try_from(payload.len() + rest.len()).unwrap());
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header).await;
    guest.extend(feed_open(&mut machine, &body_091(&payload)).await);
    assert_no_secret_prefix(&guest);
    assert!(
      !contains(&guest, std::str::from_utf8(prefix).unwrap()),
      "the real prefix was delivered"
    );
    assert!(matches!(machine.feed(&body_091(rest)).await.0, Rewritten::Close));
  }

  #[tokio::test]
  async fn transfer_frames_with_more_close_before_the_second_payload() {
    let (prefix, rest) = password_split();
    let frame_a = transfer(1, true, prefix);
    let frame_b = transfer(1, false, rest);
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    assert_eq!(guest, header_10());
    guest.extend(feed_open(&mut machine, &frame_a).await);
    let performative = serde_amqp::to_vec(&Transfer {
      handle: Handle(0),
      delivery_id: Some(1),
      delivery_tag: None,
      message_format: None,
      settled: None,
      more: true,
      rcv_settle_mode: None,
      state: None,
      resume: false,
      aborted: false,
      batchable: false,
    })
    .unwrap();
    let delivered = guest.split_off(header_10().len());
    let payload = delivered
      .get(8..)
      .and_then(|body| body.strip_prefix(performative.as_slice()))
      .unwrap_or(&delivered);
    assert!(
      !ends_with_secret_prefix(payload),
      "the transfer payload ends with a prefix of the real secret"
    );
    assert!(!contains(payload, std::str::from_utf8(prefix).unwrap()));
    assert!(
      matches!(machine.feed(&frame_b).await.0, Rewritten::Close),
      "the second transfer was delivered"
    );
    assert!(!contains(&guest, REAL));
  }

  fn wide_header(channel: u16, body_size: u64) -> Vec<u8> {
    let mut table = FieldTable::default();
    table.insert("x-pad".into(), AMQPValue::LongString("z".repeat(20 * 1024).into()));
    encode_frame(&AMQPFrame::Header(
      channel,
      AMQPContentHeader {
        class_id: 60,
        body_size,
        properties: AMQPProperties::default().with_headers(table),
      },
    ))
  }

  fn transfer_payloads(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut rest = bytes.strip_prefix(&header_10()).unwrap_or(bytes);
    let mut payloads = Vec::new();
    while rest.len() >= 8 {
      let size = usize::try_from(u32::from_be_bytes(rest[..4].try_into().unwrap())).unwrap();
      if size > rest.len() || size < 8 {
        break;
      }
      let body = &rest[8..size];
      let len = super::consume_value(body, super::PERFORMATIVE_NESTING).unwrap();
      payloads.push(body[len..].to_vec());
      rest = &rest[size..];
    }
    payloads
  }

  #[tokio::test]
  async fn a_wide_content_header_still_arms_hold_back() {
    let (prefix, rest) = password_split();
    let header = wide_header(1, u64::try_from(prefix.len() + rest.len()).unwrap());
    assert!(header.len() > super::MAX_CREDENTIAL_FRAME, "the header exceeds the whole-frame cap");
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header).await;
    assert_wide_header_holds(&mut machine, &header, &mut guest, prefix, rest).await;
  }

  #[tokio::test]
  async fn a_wide_content_header_split_inside_its_body_size_still_arms_hold_back() {
    let (prefix, rest) = password_split();
    let header = wide_header(1, u64::try_from(prefix.len() + rest.len()).unwrap());
    assert!(header.len() > super::MAX_CREDENTIAL_FRAME, "the header exceeds the whole-frame cap");
    let split = super::TYPE_CHANNEL_AND_SIZE + 3;
    assert!(split < super::TYPE_CHANNEL_AND_SIZE + 12, "the cut is inside the body size");
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header[..split]).await;
    guest.extend(feed_open(&mut machine, &header[split..]).await);
    assert_wide_header_holds(&mut machine, &header, &mut guest, prefix, rest).await;
  }

  async fn assert_wide_header_holds(machine: &mut Amqp, header: &[u8], guest: &mut Vec<u8>, prefix: &[u8], rest: &[u8]) {
    assert!(guest.starts_with(header), "the wide header is delivered");
    guest.extend(feed_open(machine, &body_091(prefix)).await);
    assert_no_secret_prefix(guest);
    assert!(
      !contains(guest, std::str::from_utf8(prefix).unwrap()),
      "the real prefix was delivered"
    );
    assert!(
      matches!(machine.feed(&body_091(rest)).await.0, Rewritten::Close),
      "the completing body was delivered"
    );
    assert!(!bodies_spell_password(guest), "body payloads concatenate to the password");
  }

  #[tokio::test]
  async fn a_small_client_frame_caps_a_merge_the_server_tune_would_allow() {
    let (prefix, _) = password_split();
    let filler = vec![b'q'; 40];
    let body_size = u64::try_from(prefix.len() + filler.len()).unwrap();
    let second = body_091(&filler);
    let limit = second.len();
    assert!(limit < 131_072, "the client frame is below the server tune");
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &tune(131_072)).await;
    guest.extend(feed_open(&mut machine, &content_header(1, body_size)).await);
    guest.extend(feed_open(&mut machine, &body_091(prefix)).await);
    assert_no_secret_prefix(&guest);
    guest.extend(feed_open(&mut machine, &second).await);
    let mut joined = Vec::new();
    let mut rest = guest.as_slice();
    while !rest.is_empty() {
      let (next, frame) = parse_frame(rest).unwrap();
      assert!(rest.len() - next.len() <= limit, "a delivered frame exceeds the client frame");
      if let AMQPFrame::Body(_, payload) = frame {
        joined.extend(payload);
      }
      rest = next;
    }
    assert_eq!(joined, [prefix, filler.as_slice()].concat());
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn opaque_split_secret_closes_before_the_second_read() {
    let (prefix, rest) = password_split();
    let header = *b"AMQP\x01\x01\x00\x00";
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header).await;
    assert_eq!(guest, header, "an unknown header is forwarded");
    guest.extend(feed_open(&mut machine, prefix).await);
    assert!(
      !contains(&guest, std::str::from_utf8(prefix).unwrap()),
      "the real prefix was delivered"
    );
    assert!(
      matches!(machine.feed(rest).await.0, Rewritten::Close),
      "the second read was delivered"
    );
    assert!(!contains(&guest, REAL));
  }

  #[tokio::test]
  async fn transfer_frames_that_do_not_continue_the_password_stay_open() {
    let (prefix, _) = password_split();
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    guest.extend(feed_open(&mut machine, &transfer(1, true, prefix)).await);
    guest.extend(feed_open(&mut machine, &transfer(1, false, b"bbbb")).await);
    let mut joined = Vec::new();
    for payload in transfer_payloads(&guest) {
      joined.extend(payload);
    }
    assert_eq!(joined, [prefix, b"bbbb"].concat(), "the held prefix is delivered intact");
    assert!(!contains(&guest, REAL));
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn transfers_on_two_handles_do_not_share_a_carry() {
    let (prefix, rest) = password_split();
    let other = b"other-link-bytes";
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    guest.extend(feed_open(&mut machine, &transfer_on(1, 0, true, prefix)).await);
    guest.extend(feed_open(&mut machine, &transfer_on(1, 1, false, other)).await);
    let payloads = transfer_payloads(&guest);
    assert!(
      !contains(&guest, std::str::from_utf8(prefix).unwrap()),
      "link A's prefix was delivered"
    );
    assert!(
      payloads.iter().any(|payload| payload.as_slice() == other),
      "link B was rewritten with link A's prefix"
    );
    assert!(
      matches!(machine.feed(&transfer_on(1, 0, false, rest)).await.0, Rewritten::Close),
      "link A's continuation was delivered"
    );
    assert!(!bodies_spell_password(&guest));
    assert!(!contains(&guest, REAL));
  }

  fn padded(len: usize, tail: &[u8]) -> Vec<u8> {
    let mut payload = vec![b'z'; len];
    let start = payload.len().saturating_sub(tail.len());
    payload[start..].copy_from_slice(tail);
    payload
  }

  fn assert_10_frames_within(bytes: &[u8], limit: usize) {
    let mut rest = bytes.strip_prefix(&header_10()).unwrap_or(bytes);
    while !rest.is_empty() {
      assert!(rest.len() >= 8, "a 1.0 header");
      let size = usize::try_from(u32::from_be_bytes(rest[..4].try_into().unwrap())).unwrap();
      assert!(size <= limit, "a delivered frame exceeds the limit");
      assert!(size <= rest.len() && size >= 8, "the size stays inside the buffer");
      rest = &rest[size..];
    }
  }

  #[tokio::test]
  async fn a_large_transfer_holds_its_suffix_across_a_second_large_transfer() {
    let (prefix, rest) = password_split();
    let first_payload = padded(super::MAX_CREDENTIAL_FRAME, prefix);
    let mut second_payload = rest.to_vec();
    second_payload.resize(super::MAX_CREDENTIAL_FRAME, b'q');
    let first = transfer_on(1, 0, true, &first_payload);
    let second = transfer_on(1, 0, false, &second_payload);
    assert!(
      first.len() > super::MAX_CREDENTIAL_FRAME,
      "the first transfer exceeds the whole-frame cap"
    );
    assert!(
      second.len() > super::MAX_CREDENTIAL_FRAME,
      "the second transfer exceeds the whole-frame cap"
    );
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    guest.extend(feed_open(&mut machine, &first).await);
    assert!(
      !contains(&guest, std::str::from_utf8(prefix).unwrap()),
      "the real prefix was delivered"
    );
    assert!(
      matches!(machine.feed(&second).await.0, Rewritten::Close),
      "the completing transfer was delivered"
    );
    assert!(!contains(&guest, REAL));
  }

  #[tokio::test]
  async fn a_held_prefix_is_prepended_to_a_following_large_transfer() {
    let (prefix, _) = password_split();
    let filler = vec![b'q'; super::MAX_CREDENTIAL_FRAME];
    let large = transfer_on(1, 0, false, &filler);
    assert!(
      large.len() > super::MAX_CREDENTIAL_FRAME,
      "the transfer exceeds the whole-frame cap"
    );
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    guest.extend(feed_open(&mut machine, &transfer_on(1, 0, true, prefix)).await);
    assert!(
      !contains(&guest, std::str::from_utf8(prefix).unwrap()),
      "the real prefix was delivered"
    );
    guest.extend(feed_open(&mut machine, &large).await);
    let mut joined = Vec::new();
    for payload in transfer_payloads(&guest) {
      joined.extend(payload);
    }
    assert_eq!(
      joined,
      [prefix, filler.as_slice()].concat(),
      "the held prefix precedes the large payload"
    );
    assert_10_frames_within(&guest, large.len().saturating_add(prefix.len()));
    assert!(!contains(&guest, REAL));
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn a_full_size_final_body_stays_within_the_replaced_frame() {
    let (prefix, _) = password_split();
    let filler = vec![b'q'; super::MAX_CREDENTIAL_FRAME];
    let last = body_091(&filler);
    assert!(
      last.len() > super::MAX_CREDENTIAL_FRAME,
      "the last body fills past the whole-frame cap"
    );
    let body_size = u64::try_from(prefix.len() + filler.len()).unwrap();
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &content_header(1, body_size)).await;
    guest.extend(feed_open(&mut machine, &body_091(prefix)).await);
    assert_no_secret_prefix(&guest);
    guest.extend(feed_open(&mut machine, &last).await);
    let mut joined = Vec::new();
    let mut rest = guest.as_slice();
    while !rest.is_empty() {
      let (next, frame) = parse_frame(rest).unwrap();
      assert!(
        rest.len() - next.len() <= last.len(),
        "a delivered frame exceeds the replaced frame"
      );
      if let AMQPFrame::Body(_, payload) = frame {
        joined.extend(payload);
      }
      rest = next;
    }
    assert_eq!(
      joined,
      [prefix, filler.as_slice()].concat(),
      "the held prefix precedes the final payload"
    );
    assert!(!contains(&guest, REAL));
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn detach_then_handle_reuse_drops_the_held_prefix() {
    let (prefix, _) = password_split();
    let fresh = b"bbbb";
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    guest.extend(feed_open(&mut machine, &transfer_on(1, 7, true, prefix)).await);
    assert!(
      !contains(&guest, std::str::from_utf8(prefix).unwrap()),
      "the real prefix was delivered"
    );
    guest.extend(feed_open(&mut machine, &detach_frame(1, 7)).await);
    guest.extend(feed_open(&mut machine, &transfer_on(1, 7, false, fresh)).await);
    let payloads = transfer_payloads(&guest);
    assert!(
      payloads.iter().any(|payload| payload.as_slice() == fresh),
      "the reused handle delivers its own payload"
    );
    assert!(
      !payloads
        .iter()
        .any(|payload| payload.windows(prefix.len()).any(|window| window == prefix)),
      "bytes from the detached delivery were prepended"
    );
    assert!(!contains(&guest, REAL));
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn channel_close_mid_body_lets_the_channel_reopen() {
    let (prefix, rest) = password_split();
    let again = b"bbbb";
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &content_header(1, u64::try_from(prefix.len() + rest.len()).unwrap())).await;
    guest.extend(feed_open(&mut machine, &body_091(prefix)).await);
    assert!(
      !contains(&guest, std::str::from_utf8(prefix).unwrap()),
      "the real prefix was delivered"
    );
    guest.extend(feed_open(&mut machine, &channel_close(1)).await);
    guest.extend(feed_open(&mut machine, &content_header(1, u64::try_from(again.len()).unwrap())).await);
    guest.extend(feed_open(&mut machine, &body_091(again)).await);
    let payloads = body_payloads(&guest);
    assert_eq!(payloads.last().map(Vec::as_slice), Some(again.as_slice()));
    assert!(
      !payloads
        .iter()
        .any(|payload| payload.windows(prefix.len()).any(|window| window == prefix)),
      "the closed channel's prefix was prepended"
    );
    assert!(!contains(&guest, REAL));
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn a_transfer_performative_past_the_cap_closes() {
    let mut body = vec![0x00, 0x53, 0x14];
    body.resize(super::MAX_CREDENTIAL_FRAME.saturating_add(64), 0xa0);
    let total = 8usize.saturating_add(body.len());
    let mut frame = Vec::with_capacity(total);
    frame.extend(u32::try_from(total).unwrap().to_be_bytes());
    frame.extend([2, 0, 0, 1]);
    frame.extend(body);
    assert!(frame.len() > super::MAX_CREDENTIAL_FRAME, "the performative exceeds the cap");
    let mut machine = up();
    let _guest = feed_open(&mut machine, &header_10()).await;
    assert!(
      matches!(machine.feed(&frame).await.0, Rewritten::Close),
      "an undecodable transfer was forwarded"
    );
  }

  #[tokio::test]
  async fn end_of_stream_with_a_held_prefix_closes() {
    let (prefix, rest) = password_split();
    let mut machine = up();
    let _header = feed_open(&mut machine, &content_header(1, u64::try_from(prefix.len() + rest.len()).unwrap())).await;
    let _body = feed_open(&mut machine, &body_091(prefix)).await;
    assert!(
      matches!(machine.feed(&[]).await.0, Rewritten::Close),
      "a held prefix was flushed at end of stream"
    );
  }

  #[tokio::test]
  async fn a_three_way_split_never_spells_the_password() {
    let parts: [&[u8]; 3] = [b"arkham_real_amqp_pass_", b"longer", b"_01"];
    let body_size = parts.iter().map(|part| part.len()).sum::<usize>();
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &content_header(1, u64::try_from(body_size).unwrap())).await;
    let mut closed = false;
    for part in parts {
      match machine.feed(&body_091(part)).await.0 {
        Rewritten::Emit(emitted) => guest.extend(emitted.into_owned()),
        Rewritten::Hold => {}
        Rewritten::Close => {
          closed = true;
          break;
        }
      }
    }
    assert!(closed, "the completing body was delivered");
    assert!(!contains(&body_payloads(&guest).concat(), REAL));
  }

  #[tokio::test]
  async fn a_three_way_transfer_split_never_spells_the_password() {
    let parts: [(&[u8], bool); 3] = [(b"arkham_real_amqp_pass_", true), (b"longer", true), (b"_01", false)];
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    let mut closed = false;
    for (part, more) in parts {
      match machine.feed(&transfer_on(1, 0, more, part)).await.0 {
        Rewritten::Emit(emitted) => guest.extend(emitted.into_owned()),
        Rewritten::Hold => {}
        Rewritten::Close => {
          closed = true;
          break;
        }
      }
    }
    assert!(closed, "the completing transfer was delivered");
    assert!(!contains(&transfer_payloads(&guest).concat(), REAL));
  }

  #[tokio::test]
  async fn a_released_prefix_does_not_add_a_transfer() {
    let (prefix, _) = password_split();
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    guest.extend(feed_open(&mut machine, &transfer(1, true, prefix)).await);
    guest.extend(feed_open(&mut machine, &transfer(1, false, b"bbbb")).await);
    assert_eq!(
      transfer_payloads(&guest).len(),
      2,
      "the guest saw a different number of transfers than the server sent"
    );
    assert_eq!(transfer_payloads(&guest).concat(), [prefix, b"bbbb"].concat());
    assert!(!contains(&guest, REAL));
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn a_wide_transfer_stays_inside_the_negotiated_max() {
    let (prefix, _) = password_split();
    let max = 4_096usize;
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    guest.extend(feed_open(&mut machine, &open_frame(u32::try_from(max).unwrap())).await);
    guest.extend(feed_open(&mut machine, &transfer(1, true, prefix)).await);
    let wide = wide_transfer(1, false, b"bbbb");
    assert!(wide.len() > super::MIN_FRAME_10 && wide.len() <= max, "frame is {}", wide.len());
    match machine.feed(&wide).await.0 {
      Rewritten::Emit(emitted) => guest.extend(emitted.into_owned()),
      Rewritten::Hold => {}
      Rewritten::Close => panic!("a frame inside max-frame-size closed the connection"),
    }
    let mut rest = guest.strip_prefix(header_10().as_slice()).unwrap_or(&guest);
    let mut transfers = 0usize;
    while rest.len() >= 8 {
      let size = usize::try_from(u32::from_be_bytes(rest[..4].try_into().unwrap())).unwrap();
      assert!(size <= max, "an emitted frame is {size} bytes");
      assert!(size <= rest.len() && size >= 8);
      let frame = &rest[..size];
      let at = usize::from(frame[4]).saturating_mul(4);
      if serde_amqp::from_slice::<Transfer>(&frame[at..]).is_ok() || frame_is_transfer(frame) {
        transfers += 1;
      }
      rest = &rest[size..];
    }
    assert_eq!(transfers, 2, "the guest saw a different number of transfers than the server sent");
    assert!(!contains(&guest, REAL));
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn a_released_body_is_its_own_frame() {
    let real = format!("{}uniq", "z".repeat(70));
    let held = "z".repeat(70);
    let mut guest_side = down(true);
    let mut client = start_ok("PLAIN", plain("agent", FAKE));
    client.extend(tune_ok(64));
    let _ = feed_open(&mut guest_side, &client).await;
    assert!(guest_side.take_peer_note().is_none(), "a tune-ok produced a peer note");
    let mut machine = up_password(&real);
    let mut guest = feed_open(&mut machine, &tune(131_072)).await;
    guest.extend(feed_open(&mut machine, &content_header(1, 74)).await);
    guest.extend(feed_open(&mut machine, &body_091(&[b'z'; 50])).await);
    guest.extend(feed_open(&mut machine, &body_091(&[b'z'; 20])).await);
    guest.extend(feed_open(&mut machine, &body_091(b"bbbb")).await);
    assert!(
      body_payloads(&guest).iter().any(|payload| payload.as_slice() == held.as_bytes()),
      "the released prefix was not its own body frame"
    );
    assert_eq!(body_payloads(&guest).concat(), [held.as_bytes(), b"bbbb"].concat());
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn held_bytes_over_the_budget_close() {
    let real = "p".repeat(449);
    let mut machine = up_password(&real);
    let held = real.as_bytes()[..448].to_vec();
    let _ = feed_open(&mut machine, &header_10()).await;
    let mut closed = false;
    for handle in 0..40u32 {
      match machine.feed(&transfer_on(1, handle, true, &held)).await.0 {
        Rewritten::Close => {
          closed = true;
          break;
        }
        Rewritten::Emit(_) | Rewritten::Hold => {}
      }
    }
    assert!(closed, "the carry map kept the held bytes");
    assert!(
      matches!(machine.close_reason(), Some(crate::Error::AmqpCarryBudget { .. })),
      "the close was not the carry budget"
    );
  }

  #[tokio::test]
  async fn too_many_carry_entries_close() {
    let mut machine = up();
    let _ = feed_open(&mut machine, &header_10()).await;
    let mut closed = false;
    for handle in 0..33u32 {
      match machine.feed(&transfer_on(1, handle, true, b"a")).await.0 {
        Rewritten::Close => {
          closed = true;
          break;
        }
        Rewritten::Emit(_) | Rewritten::Hold => {}
      }
    }
    assert!(closed, "the carry map kept every link");
    assert!(
      matches!(machine.close_reason(), Some(crate::Error::AmqpCarryBudget { .. })),
      "the close was not the carry budget"
    );
  }

  #[tokio::test]
  async fn a_transfer_just_over_the_cap_keeps_a_short_payload() {
    let tag = vec![b't'; 16_350];
    let middle = transfer_tagged(1, 0, true, Some(&tag), b"longer");
    assert!((16_387..=16_397).contains(&middle.len()), "the frame is {} bytes", middle.len());
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    guest.extend(feed_open(&mut machine, &transfer_on(1, 0, true, b"arkham_real_amqp_pass_")).await);
    match machine.feed(&middle).await.0 {
      Rewritten::Emit(emitted) => guest.extend(emitted.into_owned()),
      Rewritten::Hold => {}
      Rewritten::Close => panic!("the short payload closed early"),
    }
    let last = transfer_on(1, 0, false, b"_01");
    let mut closed = false;
    match machine.feed(&last).await.0 {
      Rewritten::Emit(emitted) => guest.extend(emitted.into_owned()),
      Rewritten::Hold => {}
      Rewritten::Close => closed = true,
    }
    assert!(!contains(&transfer_payloads(&guest).concat(), REAL));
    assert!(closed, "the completing transfer was delivered");
  }

  #[tokio::test]
  async fn a_zero_length_middle_frame_never_spells_the_password() {
    let (prefix, rest) = password_split();
    let body_size = u64::try_from(prefix.len() + rest.len()).unwrap();
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &content_header(1, body_size)).await;
    guest.extend(feed_open(&mut machine, &body_091(prefix)).await);
    guest.extend(feed_open(&mut machine, &body_091(&[])).await);
    assert!(
      matches!(machine.feed(&body_091(rest)).await.0, Rewritten::Close),
      "the completing body was delivered"
    );
    assert!(!contains(&body_payloads(&guest).concat(), REAL));
  }

  #[tokio::test]
  async fn a_large_close_closes_the_connection() {
    let performative = serde_amqp::to_vec(&Close { error: None }).unwrap();
    let total = super::MAX_CREDENTIAL_FRAME.saturating_add(1);
    let mut frame = Vec::with_capacity(total);
    frame.extend(u32::try_from(total).unwrap().to_be_bytes());
    frame.extend([2, 0, 0, 0]);
    frame.extend(performative);
    frame.resize(total, b'b');
    let mut machine = up();
    let _guest = feed_open(&mut machine, &header_10()).await;
    assert!(
      matches!(machine.feed(&frame).await.0, Rewritten::Close),
      "a close larger than 16 KiB was forwarded"
    );
  }

  #[test]
  fn a_secret_longer_than_the_minimum_frame_is_rejected() {
    let password = "p".repeat(4090);
    let scope = AmqpScope::from_strings(&format!("amqp://agent:{FAKE}@mq:5672"), &format!("amqps://svc:{password}@mq:5672")).unwrap();
    let grants = vec![Grant::Amqp {
      credential: Credential {
        label: "amqp".into(),
        fake: FAKE.into(),
        value: SecretString::from(password.clone()),
      },
      scope: Box::new(scope),
    }];
    assert!(matches!(
      Amqp::new(&grants, "mq", 5672, Direction::Upstream, false),
      Err(crate::Error::AmqpSecretTooLong { len }) if len == password.len()
    ));
  }

  #[tokio::test]
  async fn a_tune_ok_does_not_split_a_released_body() {
    let real = format!("{}uniq", "z".repeat(70));
    let held = "z".repeat(70);
    let mut guest_side = down(true);
    let mut client = start_ok("PLAIN", plain("agent", FAKE));
    client.extend(tune_ok(64));
    let forwarded = feed_open(&mut guest_side, &client).await;
    assert!(
      forwarded.windows(tune_ok(64).len()).any(|window| window == tune_ok(64)),
      "tune-ok was rewritten"
    );
    assert!(guest_side.take_peer_note().is_none(), "a tune-ok produced a peer note");
    let mut server = up_password(&real);
    let mut guest = feed_open(&mut server, &tune(131_072)).await;
    guest.extend(feed_open(&mut server, &content_header(1, 74)).await);
    guest.extend(feed_open(&mut server, &body_091(&[b'z'; 50])).await);
    guest.extend(feed_open(&mut server, &body_091(&[b'z'; 20])).await);
    guest.extend(feed_open(&mut server, &body_091(b"bbbb")).await);
    assert!(
      body_payloads(&guest).iter().any(|payload| payload.as_slice() == held.as_bytes()),
      "the released prefix was not its own body frame"
    );
    assert!(matches!(server.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn a_tune_ok_frame_max_of_zero_stays_open() {
    let real = format!("{}uniq", "z".repeat(70));
    let held = "z".repeat(70);
    let mut guest_side = down(true);
    let mut client = start_ok("PLAIN", plain("agent", FAKE));
    client.extend(tune_ok(0));
    let _ = feed_open(&mut guest_side, &client).await;
    assert!(guest_side.take_peer_note().is_none(), "tune-ok frame-max 0 produced a peer note");
    let mut server = up_password(&real);
    let mut guest = feed_open(&mut server, &tune(0)).await;
    guest.extend(feed_open(&mut server, &content_header(1, 74)).await);
    guest.extend(feed_open(&mut server, &body_091(&[b'z'; 50])).await);
    guest.extend(feed_open(&mut server, &body_091(&[b'z'; 20])).await);
    match server.feed(&body_091(b"bbbb")).await.0 {
      Rewritten::Emit(emitted) => guest.extend(emitted.into_owned()),
      Rewritten::Hold => {}
      Rewritten::Close => panic!("frame-max 0 closed the connection on the first release"),
    }
    assert!(
      body_payloads(&guest).iter().any(|payload| payload.as_slice() == held.as_bytes()),
      "an unlimited frame-max split or dropped the release"
    );
    assert!(matches!(server.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  fn hold_room() -> usize {
    REAL.len().saturating_sub(1)
  }

  fn forwarded_open_max(bytes: &[u8]) -> u32 {
    let header = header_10();
    let at = bytes
      .windows(header.len())
      .position(|window| window == header.as_slice())
      .expect("amqp header");
    let rest = &bytes[at + header.len()..];
    let size = usize::try_from(u32::from_be_bytes(rest[..4].try_into().unwrap())).unwrap();
    let frame = &rest[..size];
    let open: Open = serde_amqp::from_slice(&frame[8..]).expect("open");
    u32::try_from(usize::from(open.max_frame_size)).unwrap()
  }

  fn frame_of_len(more: bool, total: usize) -> (Vec<u8>, Vec<u8>) {
    let empty = transfer(1, more, b"");
    assert!(
      total > empty.len(),
      "frame of {total} cannot hold a performative of {}",
      empty.len()
    );
    let payload = vec![b'q'; total - empty.len()];
    (transfer(1, more, &payload), payload)
  }

  fn assert_frames_within(bytes: &[u8], limit: usize) {
    let mut rest = bytes.strip_prefix(header_10().as_slice()).unwrap_or(bytes);
    while rest.len() >= 8 {
      let size = usize::try_from(u32::from_be_bytes(rest[..4].try_into().unwrap())).unwrap();
      assert!(
        size <= limit && size <= rest.len() && size >= 8,
        "a frame of {size} bytes exceeds the guest max-frame-size {limit}"
      );
      rest = &rest[size..];
    }
  }

  async fn forward_open(max: u32) -> Vec<u8> {
    let mut guest_side = down(true);
    let mut client = sasl_init("PLAIN", Some(plain("agent", FAKE)));
    client.extend(header_10());
    client.extend(open_frame(max));
    feed_open(&mut guest_side, &client).await
  }

  fn after_sasl(tail: &[u8]) -> Vec<u8> {
    let mut client = sasl_init("PLAIN", Some(plain("agent", FAKE)));
    client.extend(header_10());
    client.extend(tail);
    client
  }

  async fn assert_open_unlowered(tail: &[u8]) {
    let mut guest_side = down(true);
    assert!(
      matches!(guest_side.feed(&after_sasl(tail)).await.0, Rewritten::Close),
      "an open that cannot be lowered was forwarded"
    );
    assert!(
      matches!(guest_side.close_reason(), Some(crate::Error::AmqpOpenUnlowered)),
      "the close was not the unlowered open"
    );
  }

  #[tokio::test]
  async fn an_undecodable_open_closes() {
    let performative = [0x00, 0x53, 0x10, 0x45, 0x00];
    assert_open_unlowered(&frame_10(0, 2, &performative, &[])).await;
  }

  #[tokio::test]
  async fn an_oversized_open_closes() {
    let total = u32::try_from(super::MAX_CREDENTIAL_FRAME.saturating_add(8)).unwrap();
    let mut frame = total.to_be_bytes().to_vec();
    frame.extend([2, 0, 0, 0]);
    assert_open_unlowered(&frame).await;
  }

  #[tokio::test]
  async fn a_bad_header_after_sasl_closes() {
    let mut guest_side = down(true);
    let mut client = sasl_init("PLAIN", Some(plain("agent", FAKE)));
    client.extend(b"AMQP\x02\x00\x00\x00");
    assert!(
      matches!(guest_side.feed(&client).await.0, Rewritten::Close),
      "a bad header after sasl was forwarded"
    );
    assert!(
      matches!(guest_side.close_reason(), Some(crate::Error::AmqpOpenUnlowered)),
      "the close was not the unlowered open"
    );
  }

  #[tokio::test]
  async fn a_frame_in_place_of_the_open_header_closes() {
    let mut guest_side = down(true);
    let sasl = sasl_init("PLAIN", Some(plain("agent", FAKE)));
    assert!(
      matches!(guest_side.feed(&sasl).await.0, Rewritten::Emit(_)),
      "sasl was not forwarded"
    );
    let frame = [0, 0, 0, 8, 2, 1, 0, 0];
    assert!(
      matches!(guest_side.feed(&frame).await.0, Rewritten::Close),
      "a frame where the open header belongs was forwarded"
    );
    assert!(
      matches!(guest_side.close_reason(), Some(crate::Error::AmqpOpenUnlowered)),
      "the close was not the unlowered open"
    );
  }

  #[tokio::test]
  async fn a_bad_open_doff_closes() {
    let frame = vec![0, 0, 0, 8, 0, 0, 0, 0];
    assert_open_unlowered(&frame).await;
  }

  #[tokio::test]
  async fn a_non_amqp_open_closes() {
    for frame_type in [1, 2] {
      let mut frame = open_frame(4_096);
      frame[5] = frame_type;
      assert_open_unlowered(&frame).await;
    }
  }

  #[tokio::test]
  async fn a_guest_without_sasl_lowers_the_open() {
    let room = u32::try_from(hold_room()).unwrap();
    let offered = 4_096u32;
    let mut guest_side = down(true);
    let mut client = header_10().to_vec();
    client.extend(open_frame(offered));
    let forwarded = feed_open(&mut guest_side, &client).await;
    assert_eq!(
      forwarded_open_max(&forwarded),
      offered - room,
      "a 1.0 open without sasl was not lowered"
    );
  }

  #[tokio::test]
  async fn a_cleartext_upstream_closes_on_the_real_password_like_tls() {
    let (prefix, rest) = password_split();
    let mut input = header_10().to_vec();
    input.extend(transfer(1, true, prefix));
    input.extend(transfer(1, false, rest));
    let mut clear = up_clear();
    let mut tls = up();
    assert!(
      matches!(clear.feed(&input).await.0, Rewritten::Close),
      "cleartext upstream delivered the password"
    );
    assert!(
      matches!(tls.feed(&input).await.0, Rewritten::Close),
      "tls upstream delivered the password"
    );
  }

  #[tokio::test]
  async fn a_cleartext_downstream_forwards_the_open_unchanged() {
    let mut guest_side = down(false);
    let client = after_sasl(&open_frame(4_096));
    let out = feed_open(&mut guest_side, &client).await;
    assert_eq!(out, client);
  }

  #[tokio::test]
  async fn a_guest_open_is_lowered_by_the_withheld_prefix() {
    let room = u32::try_from(hold_room()).unwrap();
    for offered in [542u32, 4_096] {
      let forwarded = forward_open(offered).await;
      assert_eq!(
        forwarded_open_max(&forwarded),
        offered - room,
        "open {offered} was not lowered by the withheld prefix"
      );
    }
  }

  #[tokio::test]
  async fn a_guest_open_below_the_minimum_after_the_prefix_closes() {
    let mut guest_side = down(true);
    let mut client = sasl_init("PLAIN", Some(plain("agent", FAKE)));
    client.extend(header_10());
    client.extend(open_frame(512));
    assert!(
      matches!(guest_side.feed(&client).await.0, Rewritten::Close),
      "an open of 512 was forwarded"
    );
    assert!(
      matches!(guest_side.close_reason(), Some(crate::Error::AmqpFrameMax { offered: 512, .. })),
      "the close was not the open headroom failure"
    );
  }

  #[tokio::test]
  async fn a_near_max_release_stays_inside_the_guest_open() {
    let guest_max = 4_096u32;
    let room = u32::try_from(hold_room()).unwrap();
    let lowered = guest_max - room;
    let forwarded = forward_open(guest_max).await;
    assert_eq!(forwarded_open_max(&forwarded), lowered);
    let (prefix, _) = password_split();
    let mut server = up();
    let mut guest = feed_open(&mut server, &header_10()).await;
    guest.extend(feed_open(&mut server, &transfer(1, true, prefix)).await);
    let (near, payload) = frame_of_len(false, usize::try_from(lowered).unwrap());
    assert_eq!(near.len(), usize::try_from(lowered).unwrap());
    guest.extend(feed_open(&mut server, &near).await);
    assert_frames_within(&guest, usize::try_from(guest_max).unwrap());
    assert_eq!(transfer_payloads(&guest).concat(), [prefix, payload.as_slice()].concat());
    assert!(!contains(&guest, REAL));
    assert!(matches!(server.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn a_streamed_message_filling_the_guest_max_stays_open_without_a_secret() {
    let guest_max = 32_768u32;
    let room = u32::try_from(hold_room()).unwrap();
    let lowered = guest_max - room;
    let forwarded = forward_open(guest_max).await;
    assert_eq!(forwarded_open_max(&forwarded), lowered);
    let (big, big_payload) = frame_of_len(true, super::MAX_CREDENTIAL_FRAME + 64);
    assert!(big.len() > super::MAX_CREDENTIAL_FRAME);
    let (fin, fin_payload) = frame_of_len(false, usize::try_from(lowered).unwrap());
    let mut server = up();
    let mut guest = feed_open(&mut server, &header_10()).await;
    guest.extend(feed_open(&mut server, &big).await);
    guest.extend(feed_open(&mut server, &fin).await);
    assert_frames_within(&guest, usize::try_from(guest_max).unwrap());
    assert_eq!(
      transfer_payloads(&guest).concat(),
      [big_payload.as_slice(), fin_payload.as_slice()].concat()
    );
    assert!(!contains(&guest, REAL));
    assert!(matches!(server.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn an_aborted_delivery_still_shows_the_transfer_already_sent() {
    let (prefix, _) = password_split();
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    guest.extend(feed_open(&mut machine, &transfer(1, true, prefix)).await);
    assert_eq!(count_transfers(&guest), 1, "the withheld transfer was not sent before the abort");
    guest.extend(feed_open(&mut machine, &abort_transfer(1)).await);
    assert_eq!(
      count_transfers(&guest),
      2,
      "the abort discarded the transfer the server already sent"
    );
    assert!(!contains(&guest, std::str::from_utf8(prefix).unwrap()));
    assert!(!contains(&guest, REAL));
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn a_detach_does_not_drop_the_transfer_sent_ahead_of_it() {
    let (prefix, _) = password_split();
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    guest.extend(feed_open(&mut machine, &transfer_on(1, 7, true, prefix)).await);
    let detach = detach_frame(1, 7);
    guest.extend(feed_open(&mut machine, &detach).await);
    let transfer_at = first_transfer_at(&guest).expect("the detach discarded the withheld transfer");
    let detach_at = guest
      .windows(detach.len())
      .position(|window| window == detach.as_slice())
      .expect("the detach was forwarded");
    assert!(transfer_at < detach_at, "the detach overtook the withheld transfer");
    assert!(!contains(&guest, std::str::from_utf8(prefix).unwrap()));
    guest.extend(feed_open(&mut machine, &transfer_on(1, 8, false, b"other")).await);
    assert_eq!(
      count_transfers(&guest),
      2,
      "the guest saw a different number of transfers than the server sent"
    );
    assert!(
      transfer_payloads(&guest).iter().any(|payload| payload.as_slice() == b"other"),
      "the later link was rewritten with the detached prefix"
    );
    assert!(!contains(&guest, REAL));
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn a_flow_cannot_overtake_a_withheld_transfer() {
    let (prefix, _) = password_split();
    let mut machine = up();
    let mut guest = feed_open(&mut machine, &header_10()).await;
    guest.extend(feed_open(&mut machine, &transfer(1, true, prefix)).await);
    let flow = flow_frame(1);
    guest.extend(feed_open(&mut machine, &flow).await);
    let transfer_at = first_transfer_at(&guest).expect("the flow was sent before the withheld transfer");
    let flow_at = guest
      .windows(flow.len())
      .position(|window| window == flow.as_slice())
      .expect("the flow was forwarded");
    assert!(transfer_at < flow_at, "the flow overtook the withheld transfer");
    assert!(!contains(&guest, std::str::from_utf8(prefix).unwrap()));
    guest.extend(feed_open(&mut machine, &transfer(1, false, b"bbbb")).await);
    let mut joined = Vec::new();
    for payload in transfer_payloads(&guest) {
      joined.extend(payload);
    }
    assert_eq!(joined, [prefix, b"bbbb"].concat(), "the flow dropped the withheld prefix");
    assert!(!contains(&guest, REAL));
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }
}
