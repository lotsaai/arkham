use std::borrow::Cow;
use std::str::FromStr;
use std::sync::OnceLock;

use amq_protocol::auth::SASLMechanism;
use amq_protocol::frame::parsing::parse_frame_type;
use amq_protocol::frame::{AMQPFrame, ParserError, ProtocolVersion, WriteContext, gen_frame, parse_frame};
use amq_protocol::protocol::constants::{FRAME_END, FRAME_METHOD};
use amq_protocol::protocol::{AMQPClass, channel, connection};
use amq_protocol::types::ShortString;
use amq_protocol::types::parsing::{parse_id, parse_long_uint};
use arkham_config::grants::Grant;
use fe2o3_amqp_types::definitions::{Error as AmqpError, MAJOR, MINOR, REVISION};
use fe2o3_amqp_types::performatives::{Close, Detach, End};
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
/// A larger declared size is forwarded and scanned.
pub(crate) const MAX_CREDENTIAL_FRAME: usize = 16_384;

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

static SASL_INIT_CODE: OnceLock<u64> = OnceLock::new();
static SASL_RESPONSE_CODE: OnceLock<u64> = OnceLock::new();
static DETACH_CODE: OnceLock<u64> = OnceLock::new();
static END_CODE: OnceLock<u64> = OnceLock::new();
static CLOSE_CODE: OnceLock<u64> = OnceLock::new();

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
  overlap: PayloadOverlap,
  overlap_channel: Option<u16>,
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
  Forward(Forward),
  Opaque,
}

struct Forward {
  left: usize,
  skip: usize,
  end: usize,
}

struct PayloadOverlap {
  bytes: Vec<u8>,
  sent: usize,
}

struct Parts<'a> {
  header: &'a [u8],
  payload: &'a [u8],
  end: &'a [u8],
}

#[derive(Clone, Copy)]
enum Kind {
  StartOk,
  SaslInit,
  SaslResponse,
  Close091,
  CloseEndDetach(u64),
}

enum InitRewrite {
  Unchanged,
  Rewritten(Vec<u8>),
  AwaitResponse,
}

enum Classified {
  AbsoluteHead(usize),
  Hold { total: usize, kind: Kind },
  Forward { total: usize, header: usize },
}

impl PayloadOverlap {
  fn new() -> Self {
    Self {
      bytes: Vec::new(),
      sent: 0,
    }
  }

  fn is_empty(&self) -> bool {
    self.bytes.is_empty()
  }

  fn scan(&mut self, payload: &[u8], pair: &CredentialPair, out: &mut Vec<u8>) -> Result<(), ()> {
    let mut combined = std::mem::take(&mut self.bytes);
    let old_sent = std::mem::replace(&mut self.sent, 0);
    combined.extend_from_slice(payload);
    if find_new_match(&combined, &pair.needle, 0) {
      return Err(());
    }
    let bound = pair.needle.len().saturating_sub(1);
    let hold = needle_prefix_suffix_len(&combined, std::slice::from_ref(pair), bound);
    let emit_end = combined.len().saturating_sub(hold);
    let emit_start = old_sent.min(emit_end);
    let Some(fresh) = combined.get(emit_start..emit_end) else {
      return Err(());
    };
    out.extend_from_slice(fresh);
    self.bytes = combined.split_off(emit_end);
    self.sent = old_sent.saturating_sub(emit_end);
    Ok(())
  }

  fn commit_frame(&mut self, out: &mut Vec<u8>) {
    let Some(tail) = self.bytes.get(self.sent..) else {
      return;
    };
    out.extend_from_slice(tail);
    self.sent = self.bytes.len();
  }

  fn flush_unsent(&mut self, out: &mut Vec<u8>) {
    self.commit_frame(out);
    self.bytes.clear();
    self.sent = 0;
  }

  fn discard_if_sent(&mut self) -> Result<(), ()> {
    if self.sent != self.bytes.len() {
      return Err(());
    }
    self.bytes.clear();
    self.sent = 0;
    Ok(())
  }
}

impl Amqp {
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
      overlap: PayloadOverlap::new(),
      overlap_channel: None,
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
    let mut flushed = Vec::new();
    self.overlap.flush_unsent(&mut flushed);
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
    self.emit_payload(input, out)?;
    *input = &[];
    Ok(())
  }

  /// Read one protocol header and pick the framer. A server that opens with
  /// a frame instead is 0-9-1. Any header the machine does not frame
  /// forwards the rest of the stream.
  fn drive_header(&mut self, mut buf: Vec<u8>, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), ()> {
    if buf.is_empty() && input.first().is_some_and(|lead| *lead != protocol_lead()) {
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
    out.extend_from_slice(&buf);
    self.phase = match header_framer(self.down.is_some(), &buf) {
      Some(framer) => {
        self.framer = framer;
        Phase::Head(Vec::new())
      }
      None => Phase::Opaque,
    };
    Ok(())
  }

  fn drive_head(&mut self, mut buf: Vec<u8>, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), ()> {
    if buf.is_empty() && self.framer == (Framer::V10 { sasl: true }) && input.first() == Some(&protocol_lead()) {
      if self.down.is_some() {
        return self.opaque(input, out);
      }
      return self.drive_header(Vec::new(), input, out, hits);
    }
    loop {
      match self.classify(&buf)? {
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
        Classified::Forward { total, header } => {
          self.phase = self.begin_forward(&buf, total, header, input, out)?;
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
    if total > MAX_CREDENTIAL_FRAME {
      return Ok(Classified::Forward {
        total,
        header: TYPE_CHANNEL_AND_SIZE,
      });
    }
    if buf.first() != Some(&FRAME_METHOD) || size < CLASS_AND_METHOD_IDS {
      return Ok(Classified::Forward {
        total,
        header: TYPE_CHANNEL_AND_SIZE,
      });
    }
    let method_head = TYPE_CHANNEL_AND_SIZE + CLASS_AND_METHOD_IDS;
    let Some(payload) = buf.get(TYPE_CHANNEL_AND_SIZE..) else {
      return Ok(Classified::AbsoluteHead(method_head));
    };
    let Some((class_id, method_id)) = method_ids(payload)? else {
      return Ok(Classified::AbsoluteHead(method_head));
    };
    let pair = (class_id, method_id);
    let kind = if pair == start_ok_ids() && self.down.is_some() {
      Kind::StartOk
    } else if (pair == connection_close_ids() || pair == channel_close_ids()) && self.up.is_some() {
      Kind::Close091
    } else {
      return Ok(Classified::Forward {
        total,
        header: TYPE_CHANNEL_AND_SIZE,
      });
    };
    Ok(Classified::Hold { total, kind })
  }

  fn classify_10(&self, buf: &[u8]) -> Result<Classified, ()> {
    let Some((after_size, total)) = frame_len_10(buf)? else {
      return Ok(Classified::AbsoluteHead(FRAME_HEADER_10));
    };
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
    let forward = Classified::Forward {
      total,
      header: data_offset,
    };
    if total > MAX_CREDENTIAL_FRAME {
      return Ok(forward);
    }
    let wanted = match frame_type {
      FRAME_SASL => self.down.is_some(),
      FRAME_AMQP => self.up.is_some(),
      _ => false,
    };
    if !wanted || data_offset == total {
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
    let kind = if frame_type == FRAME_SASL && Some(code) == sasl_init_code() {
      Kind::SaslInit
    } else if frame_type == FRAME_SASL
      && Some(code) == sasl_response_code()
      && self.down.as_ref().is_some_and(|down| down.awaiting_response)
    {
      Kind::SaslResponse
    } else if frame_type == FRAME_AMQP && (Some(code) == detach_code() || Some(code) == end_code() || Some(code) == close_code()) {
      Kind::CloseEndDetach(code)
    } else {
      return Ok(forward);
    };
    Ok(Classified::Hold { total, kind })
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
      let header = match self.framer {
        Framer::V091 => TYPE_CHANNEL_AND_SIZE,
        Framer::V10 { .. } => data_offset(&buf)?,
      };
      self.phase = self.begin_forward(&buf, total, header, input, out)?;
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
        self.phase = if await_response { Phase::Head(Vec::new()) } else { Phase::Opaque };
      }
      Kind::SaslResponse => {
        let rewritten = self.sasl_response(&buf, hits)?;
        out.extend_from_slice(rewritten.as_deref().unwrap_or(&buf));
        self.phase = Phase::Opaque;
      }
      Kind::Close091 => {
        let redacted = self.close_091(&buf, hits)?;
        self.emit_frame(redacted.as_deref().unwrap_or(&buf), out)?;
        self.phase = Phase::Head(Vec::new());
      }
      Kind::CloseEndDetach(code) => {
        let redacted = self.error_10(&buf, code, hits)?;
        self.emit_frame(redacted.as_deref().unwrap_or(&buf), out)?;
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
    Ok(InitRewrite::Rewritten(encode_10(buf, &init)?))
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
    Ok(Some(encode_10(buf, &response)?))
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
      redact_error(close.error.as_mut(), pair).then(|| encode_10(buf, &close))
    } else if Some(code) == end_code() {
      let mut end: End = decode_10(buf)?;
      redact_error(end.error.as_mut(), pair).then(|| encode_10(buf, &end))
    } else if Some(code) == detach_code() {
      let mut detach: Detach = decode_10(buf)?;
      redact_error(detach.error.as_mut(), pair).then(|| encode_10(buf, &detach))
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

  fn frame_end_len(&self) -> usize {
    match self.framer {
      Framer::V091 => 1,
      Framer::V10 { .. } => 0,
    }
  }

  fn channel_id(&self, header: &[u8]) -> Option<u16> {
    let start: usize = match self.framer {
      Framer::V091 => 1,
      Framer::V10 { .. } => 6,
    };
    let end = start.checked_add(2)?;
    let bytes = header.get(start..end)?;
    let array = <[u8; 2]>::try_from(bytes).ok()?;
    Some(u16::from_be_bytes(array))
  }

  fn note_channel(&mut self, channel: u16, payload_len: usize) -> Result<(), ()> {
    if payload_len == 0 {
      return Ok(());
    }
    if self.overlap.is_empty() || self.overlap_channel == Some(channel) {
      self.overlap_channel = Some(channel);
      return Ok(());
    }
    self.overlap.discard_if_sent()?;
    self.overlap_channel = Some(channel);
    Ok(())
  }

  fn emit_payload(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    let Some(pair) = self.up.as_ref().filter(|pair| !pair.needle.is_empty()) else {
      out.extend_from_slice(payload);
      return Ok(());
    };
    self.overlap.scan(payload, pair, out)
  }

  fn parts<'a>(&self, frame: &'a [u8]) -> Result<Parts<'a>, ()> {
    match self.framer {
      Framer::V091 => {
        let header = frame.get(..TYPE_CHANNEL_AND_SIZE).ok_or(())?;
        let end_at = frame.len().checked_sub(1).ok_or(())?;
        if end_at < TYPE_CHANNEL_AND_SIZE {
          return Err(());
        }
        let end = frame.get(end_at..).ok_or(())?;
        if end.first() != Some(&FRAME_END) {
          return Err(());
        }
        let payload = frame.get(TYPE_CHANNEL_AND_SIZE..end_at).ok_or(())?;
        Ok(Parts { header, payload, end })
      }
      Framer::V10 { .. } => {
        let header_len = data_offset(frame)?;
        if header_len < FRAME_HEADER_10 || header_len > frame.len() {
          return Err(());
        }
        let header = frame.get(..header_len).ok_or(())?;
        let payload = frame.get(header_len..).ok_or(())?;
        Ok(Parts { header, payload, end: &[] })
      }
    }
  }

  fn emit_frame(&mut self, frame: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    let parts = self.parts(frame)?;
    out.extend_from_slice(parts.header);
    if let Some(channel) = self.channel_id(parts.header) {
      self.note_channel(channel, parts.payload.len())?;
    }
    self.emit_payload(parts.payload, out)?;
    self.overlap.commit_frame(out);
    out.extend_from_slice(parts.end);
    Ok(())
  }

  fn begin_forward(&mut self, buf: &[u8], total: usize, header: usize, input: &mut &[u8], out: &mut Vec<u8>) -> Result<Phase, ()> {
    let end = self.frame_end_len();
    let copied = buf.get(..header).unwrap_or(buf);
    out.extend_from_slice(copied);
    let skip = header.saturating_sub(buf.len());
    let left = total.checked_sub(buf.len()).ok_or(())?;
    let payload_len = total.saturating_sub(header).saturating_sub(end);
    if let Some(channel) = self.channel_id(buf) {
      self.note_channel(channel, payload_len)?;
    }
    let early = buf.get(header..).unwrap_or_default();
    self.emit_payload(early, out)?;
    self.forward_rest(Forward { left, skip, end }, input, out)
  }

  fn forward_rest(&mut self, mut fwd: Forward, input: &mut &[u8], out: &mut Vec<u8>) -> Result<Phase, ()> {
    while fwd.left > 0 && !input.is_empty() {
      if fwd.skip > 0 {
        let n = fwd.skip.min(input.len()).min(fwd.left);
        let chunk = input.get(..n).ok_or(())?;
        out.extend_from_slice(chunk);
        *input = input.get(n..).ok_or(())?;
        fwd.skip = fwd.skip.saturating_sub(n);
        fwd.left = fwd.left.saturating_sub(n);
        continue;
      }
      let payload_left = fwd.left.saturating_sub(fwd.end);
      if payload_left > 0 {
        let n = payload_left.min(input.len());
        let chunk = input.get(..n).ok_or(())?;
        self.emit_payload(chunk, out)?;
        *input = input.get(n..).ok_or(())?;
        fwd.left = fwd.left.saturating_sub(n);
        continue;
      }
      let Some((&byte, rest)) = input.split_first() else {
        break;
      };
      if byte != FRAME_END {
        return Err(());
      }
      self.overlap.commit_frame(out);
      out.push(byte);
      *input = rest;
      fwd.left = fwd.left.saturating_sub(1);
      fwd.end = fwd.end.saturating_sub(1);
    }
    if fwd.left == 0 {
      self.overlap.commit_frame(out);
      Ok(Phase::Head(Vec::new()))
    } else {
      Ok(Phase::Forward(fwd))
    }
  }
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

fn header_framer(downstream: bool, buf: &[u8]) -> Option<Framer> {
  if let Ok((rest, AMQPFrame::ProtocolHeader(version))) = parse_frame(buf) {
    if rest.is_empty() && downstream && version == ProtocolVersion::amqp_0_9_1() {
      return Some(Framer::V091);
    }
    if rest.is_empty() && !downstream && version.major == MAJOR && version.minor == MINOR && version.revision == REVISION {
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
    Ok(EncodingCodes::Sym8) => sym8_width(body, budget),
    Ok(EncodingCodes::Sym32) => sym32_width(body, budget),
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

fn sym8_width(body: &[u8], budget: usize) -> DescriptorWidth {
  const HEADER: usize = 3;
  if HEADER > budget {
    return DescriptorWidth::Forward;
  }
  if body.len() < HEADER {
    return DescriptorWidth::Need;
  }
  let Some(len) = body.get(2).copied().map(usize::from) else {
    return DescriptorWidth::Need;
  };
  counted_width(body, budget, HEADER, len)
}

fn sym32_width(body: &[u8], budget: usize) -> DescriptorWidth {
  const HEADER: usize = 6;
  if HEADER > budget {
    return DescriptorWidth::Forward;
  }
  if body.len() < HEADER {
    return DescriptorWidth::Need;
  }
  let Some(len_bytes) = body.get(2..HEADER) else {
    return DescriptorWidth::Need;
  };
  let Ok(bytes) = <[u8; 4]>::try_from(len_bytes) else {
    return DescriptorWidth::Forward;
  };
  let Ok(len) = usize::try_from(u32::from_be_bytes(bytes)) else {
    return DescriptorWidth::Forward;
  };
  counted_width(body, budget, HEADER, len)
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

fn encode_10<T: Serialize>(buf: &[u8], performative: &T) -> Result<Vec<u8>, ()> {
  let at = data_offset(buf)?;
  let body = serde_amqp::to_vec(performative).map_err(|_encode| ())?;
  let size = u32::try_from(at.checked_add(body.len()).ok_or(())?).map_err(|_wide| ())?;
  // The original doff, type, channel, and extended header stay. No standalone encoder preserves them.
  let mut frame = Vec::with_capacity(at.saturating_add(body.len()));
  frame.extend_from_slice(&size.to_be_bytes());
  frame.extend_from_slice(buf.get(4..at).ok_or(())?);
  frame.extend_from_slice(&body);
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
  use amq_protocol::frame::{AMQPFrame, WriteContext, gen_frame, parse_frame};
  use amq_protocol::protocol::{AMQPClass, channel, connection};
  use amq_protocol::types::parsing::parse_id;
  use amq_protocol::types::{AMQPValue, FieldTable};
  use arkham_config::grants::{AmqpScope, Credential, Grant};
  use fe2o3_amqp_types::definitions::{MAJOR, MINOR, REVISION};
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
    encode_frame(&AMQPFrame::Body(1, payload.to_vec()))
  }

  fn header_10() -> [u8; 8] {
    let mut bytes = *b"AMQP\x00\x00\x00\x00";
    bytes[5] = MAJOR;
    bytes[6] = MINOR;
    bytes[7] = REVISION;
    bytes
  }

  fn frame_10(payload: &[u8]) -> Vec<u8> {
    let mut bytes = u32::try_from(payload.len().saturating_add(8)).unwrap().to_be_bytes().to_vec();
    bytes.extend([2, 0, 0, 0]);
    bytes.extend_from_slice(payload);
    bytes
  }

  fn bodies_spell_password(bytes: &[u8]) -> bool {
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

  async fn emit_open(machine: &mut Amqp, chunk: &[u8]) -> Vec<u8> {
    match machine.feed(chunk).await.0 {
      Rewritten::Emit(emitted) => emitted.into_owned(),
      Rewritten::Hold | Rewritten::Close => {
        panic!("expected the frame to be emitted while the machine stays open")
      }
    }
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

  #[tokio::test]
  async fn body_frames_split_across_two_reads_close_before_the_second_payload() {
    let (prefix, rest) = password_split();
    let frame_a = body_091(prefix);
    let frame_b = body_091(rest);
    let mut machine = up();
    let emitted = emit_open(&mut machine, &frame_a).await;
    assert_eq!(emitted, frame_a, "frame A is delivered whole");
    let mut guest = emitted;
    let second = machine.feed(&frame_b).await.0;
    let closed = matches!(second, Rewritten::Close);
    if let Rewritten::Emit(bytes) = &second {
      guest.extend_from_slice(bytes);
    }
    assert!(
      closed,
      "both frames were emitted and the machine stayed open (bodies spell the password: {})",
      bodies_spell_password(&guest)
    );
    assert!(!contains(&guest, REAL), "guest bytes contain the password");
    assert!(!bodies_spell_password(&guest), "body payloads concatenate to the password");
  }

  #[tokio::test]
  async fn body_frames_cut_inside_the_second_header_close() {
    let (prefix, rest) = password_split();
    let frame_a = body_091(prefix);
    let frame_b = body_091(rest);
    let mut wire = frame_a.clone();
    wire.extend_from_slice(&frame_b);
    let cut = frame_a.len().saturating_add(7);
    let (head, tail) = wire.split_at(cut);
    let mut machine = up();
    let emitted = emit_open(&mut machine, head).await;
    assert_eq!(emitted, head, "bytes before the second payload are delivered");
    let mut guest = emitted;
    let second = machine.feed(tail).await.0;
    let closed = matches!(second, Rewritten::Close);
    if let Rewritten::Emit(bytes) = &second {
      guest.extend_from_slice(bytes);
    }
    assert!(
      closed,
      "both frames were emitted and the machine stayed open (bodies spell the password: {})",
      bodies_spell_password(&guest)
    );
    assert!(!contains(&guest, REAL), "guest bytes contain the password");
    assert!(
      !bodies_spell_password(&guest),
      "body payloads returned before close concatenate to the password"
    );
  }

  #[tokio::test]
  async fn body_frames_that_do_not_continue_the_password_stay_open() {
    let (prefix, _) = password_split();
    let frame_a = body_091(prefix);
    let frame_b = body_091(b"bbbb");
    let mut machine = up();
    let emitted_a = emit_open(&mut machine, &frame_a).await;
    assert_eq!(emitted_a, frame_a);
    let emitted_b = emit_open(&mut machine, &frame_b).await;
    assert_eq!(emitted_b, frame_b);
    assert!(matches!(machine.feed(&[]).await.0, Rewritten::Hold), "machine stays open");
  }

  #[tokio::test]
  async fn body_frames_split_across_two_reads_close_before_the_second_payload_on_1_0() {
    let (prefix, rest) = password_split();
    let frame_a = frame_10(prefix);
    let frame_b = frame_10(rest);
    let mut machine = up();
    let header = emit_open(&mut machine, &header_10()).await;
    assert_eq!(header, header_10());
    let emitted = emit_open(&mut machine, &frame_a).await;
    assert_eq!(emitted, frame_a, "frame A is delivered whole");
    let mut guest = emitted;
    let second = machine.feed(&frame_b).await.0;
    let closed = matches!(second, Rewritten::Close);
    if let Rewritten::Emit(bytes) = &second {
      guest.extend_from_slice(bytes);
    }
    assert!(
      closed,
      "both frames were emitted and the machine stayed open (guest contains the password: {})",
      contains(&guest, REAL)
    );
    assert!(!contains(&guest, REAL), "guest bytes contain the password");
    assert_eq!(&guest[8..], prefix, "the delivered payload is only the prefix");
  }
}
