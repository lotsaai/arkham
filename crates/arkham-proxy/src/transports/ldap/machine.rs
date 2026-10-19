//! LDAP wire format: simple-bind password rewrite over a streamed BER cursor.
//!
//! Bytes go through [`Raw`] (downstream) or the engine's needle hold-back
//! (upstream). A message is not accumulated. The cursor peeks a bind only
//! until the simple password, and an extended operation only until the
//! `StartTLS` OID or the result code and diagnostic. Everything after that
//! is forwarded as it arrives, including a body whose header announced a
//! huge length. A message id wider than four bytes is forwarded and counted
//! down; its body is not peeked. The upstream needle suffix is released when
//! the message ends, because that frame cannot grow. A cleartext upstream
//! keeps the decoy. A diagnostic that still carries the real password closes
//! the leg.

use std::borrow::Cow;
use std::ops::Range;

use arkham_config::grants::{Grant, Scheme};
use rasn::prelude::OctetString;
use rasn_ldap::{ExtendedResponse, LdapMessage, LdapString, ProtocolOp, ResultCode};
use secrecy::ExposeSecret as _;

use crate::transports::engine::{
  CredentialPair, Direction, Hit, Location, Raw, Rewritten, Wire, find_new_match, needle_prefix_suffix_len, replace_bytes,
};

/// `StartTLS` extended operation OID (RFC 4511).
const STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

/// `APPLICATION 0` constructed: `BindRequest`.
const BIND_REQUEST_TAG: u8 = 0x60;

/// `APPLICATION 1` constructed: `BindResponse`.
const BIND_RESPONSE_TAG: u8 = 0x61;

/// `APPLICATION 23` constructed: `ExtendedRequest`.
const EXTENDED_REQUEST_TAG: u8 = 0x77;

/// `APPLICATION 24` constructed: `ExtendedResponse`.
const EXTENDED_RESPONSE_TAG: u8 = 0x78;

/// Context-specific primitive 0: simple password, or an extended-request name.
const CONTEXT_0: u8 = 0x80;

/// One LDAP direction leg.
pub(crate) struct Ldap {
  down: Option<Down>,
  up: Option<Up>,
  phase: Phase,
  /// Equal-length streamer. LDAP passwords differ in length, so this holds
  /// no pairs; it is the same forward path the other transports use.
  forward: Raw,
  /// Message id of a `StartTLS` request just framed.
  starttls: Option<u32>,
  /// Bytes that followed that request. They are the handshake, not more LDAP.
  prefix: Vec<u8>,
  /// `Some` once the extended response for [`Self::expect_starttls`] is complete.
  starttls_ok: Option<bool>,
  /// Result already parsed, waiting until that message is back at [`Phase::Head`].
  pending_starttls: Option<bool>,
  /// Upstream needle hold-back. Same window [`Raw`] keeps, not a frame buffer.
  held: Vec<u8>,
  closed: bool,
}

/// Downstream parse state.
struct Down {
  fake: String,
  real: String,
  downstream_dn: String,
  upstream_dn: String,
  label: String,
  /// Rewrite a matching simple bind. False while the upstream writer is cleartext.
  swap: bool,
}

/// Upstream redaction state.
struct Up {
  /// Needle is the real password; the replacement is the decoy.
  pair: CredentialPair,
  /// Message id whose extended response is the `StartTLS` result.
  expect_id: Option<u32>,
}

/// Where the cursor is. `Peek` holds only the credential or `StartTLS` bytes
/// still needed to decide. `Forward` counts down a body it does not store.
enum Phase {
  /// The next message header (tag and definite length). At most six bytes.
  Head(Vec<u8>),
  Peek(Peek),
  /// `left` body bytes still belong to the current message.
  Forward(usize),
  /// `left` bytes finish the `StartTLS` message; anything after is the handshake.
  Tail {
    left: usize,
    id: u32,
  },
}

/// Bytes of one bind or extended operation that the swap has not decided yet.
struct Peek {
  buf: Vec<u8>,
  /// Content bytes of the outer `SEQUENCE` not yet copied into `buf`.
  left: usize,
  /// End of the outer tag and length inside `buf`.
  header: usize,
  kind: Kind,
}

/// What the peeked bytes are for.
enum Kind {
  /// Message id and the `protocolOp` tag.
  Classify,
  /// Simple bind, downstream, swap on.
  Bind,
  /// Extended request, looking for `StartTLS`.
  ExtReq,
  /// Bind or extended response. Diagnostic redaction and the `StartTLS` result.
  Result,
}

/// One definite-length TLV header. The content bytes may still be unread.
struct Tl {
  tag: u8,
  /// Bytes from the start of this TLV through its length octets.
  header: usize,
  content_len: usize,
}

impl Tl {
  fn total(&self) -> Option<usize> {
    self.header.checked_add(self.content_len)
  }
}

/// How far a simple bind has been recognized.
enum BindParse {
  /// Absolute `buf` length still required before the next decision.
  Need(usize),
  /// Not a simple bind we rewrite. `buf` plus `left` is still the original message.
  Skip,
  Ready(BindCut),
}

/// Spans in the peeked bind, through the end of the simple password.
struct BindCut {
  msgid: Range<usize>,
  version: Range<usize>,
  dn: Range<usize>,
  password: Range<usize>,
}

/// How far an extended request has been recognized.
enum ExtParse {
  /// Absolute `buf` length still required before the next decision.
  Need(usize),
  Skip,
  StartTls {
    id: u32,
  },
}

/// How far a result message has been recognized.
enum ResultParse {
  /// Absolute `buf` length still required before the next decision.
  Need(usize),
  Skip,
  Ready(ResultCut),
}

/// One peek step. `Need` is an absolute index in the peek buffer.
enum Step {
  Need(usize),
  Done,
}

/// Classification of the message id and the `protocolOp` tag.
enum ClassAct {
  Need(usize),
  /// `kind` changed; parse that kind with the bytes already held.
  Continue,
  /// Not a bind, `StartTLS`, or result. Emit the peek and count the rest down.
  Forward,
}

/// Spans in a peeked bind or extended response, through the diagnostic.
struct ResultCut {
  id: u32,
  /// `true` when this is an extended response.
  extended: bool,
  msgid: Range<usize>,
  response_tag: u8,
  /// Absolute start of the response content.
  response_at: usize,
  before_diag: Range<usize>,
  diagnostic: Range<usize>,
  /// Bytes after the diagnostic that are still inside the response TLV.
  after_inside: usize,
}

impl Ldap {
  /// Fresh leg. `swap` is downstream only: a simple bind is rewritten when
  /// the upstream writer is already TLS. A cleartext upstream keeps the decoy.
  /// Upstream always redacts a diagnostic that carries the real password.
  pub(crate) fn new(grants: &[Grant], host: &str, port: u16, dir: Direction, swap: bool) -> Self {
    let down = if dir == Direction::Downstream {
      grants.iter().find_map(|grant| {
        let scope = grant.ldap(Some(host), port)?;
        Some(Down {
          fake: scope.downstream.password.expose_secret().to_string(),
          real: scope.upstream.password.expose_secret().to_string(),
          downstream_dn: scope.downstream.dn.clone(),
          upstream_dn: scope.upstream.dn.clone(),
          label: grant.credential().map(|credential| credential.label.clone()).unwrap_or_default(),
          swap,
        })
      })
    } else {
      None
    };
    let up = if dir == Direction::Upstream {
      grants.iter().find_map(|grant| {
        let scope = grant.ldap(Some(host), port)?;
        let real = scope.upstream.password.expose_secret().as_bytes().to_vec();
        let fake = scope.downstream.password.expose_secret().as_bytes().to_vec();
        let label = grant.credential().map(|credential| credential.label.clone()).unwrap_or_default();
        Some(Up {
          pair: CredentialPair {
            needle: real,
            replacement: fake,
            label,
          },
          expect_id: None,
        })
      })
    } else {
      None
    };
    Self {
      down,
      up,
      phase: Phase::Head(Vec::new()),
      forward: Raw::new(&[], Scheme::Ldap, host, port, dir),
      starttls: None,
      prefix: Vec::new(),
      starttls_ok: None,
      pending_starttls: None,
      held: Vec::new(),
      closed: false,
    }
  }

  /// Message id of a `StartTLS` request framed by the last `feed`, once.
  pub(crate) fn take_starttls(&mut self) -> Option<u32> {
    self.starttls.take()
  }

  /// Bytes after that request. The caller replays them into the handshake.
  pub(crate) fn take_prefix(&mut self) -> Vec<u8> {
    std::mem::take(&mut self.prefix)
  }

  /// The next extended response with `id` is the `StartTLS` result.
  pub(crate) fn expect_starttls(&mut self, id: u32) {
    if let Some(up) = self.up.as_mut() {
      up.expect_id = Some(id);
    }
  }

  /// `Some(true)` when the expected `StartTLS` response succeeded.
  ///
  /// The value appears only once that response is complete. A split success
  /// stays pending through `responseName` so the caller keeps reading.
  pub(crate) fn take_starttls_result(&mut self) -> Option<bool> {
    self.starttls_ok.take()
  }

  /// Message id and unread control bytes after a recognized `StartTLS` OID.
  /// The opening streams those bytes and does not store them.
  pub(crate) fn starttls_tail(&self) -> Option<(u32, usize)> {
    match self.phase {
      Phase::Tail { left, id } => Some((id, left)),
      Phase::Head(_) | Phase::Peek(_) | Phase::Forward(_) => None,
    }
  }
}

/// A success extended response for `id`, used when the upstream leg is
/// already TLS and the `StartTLS` request must not be forwarded.
///
/// # Errors
///
/// Returns the encoder error when the fixed success message cannot be encoded.
pub(crate) fn starttls_success(id: u32) -> Result<Vec<u8>, rasn::error::EncodeError> {
  let message = LdapMessage::new(
    id,
    ProtocolOp::ExtendedResp(ExtendedResponse {
      result_code: ResultCode::Success,
      matched_dn: LdapString::from(""),
      diagnostic_message: LdapString::from(""),
      referral: None,
      response_name: Some(OctetString::from_static(STARTTLS_OID)),
      response_value: None,
    }),
  );
  rasn::ber::encode(&message)
}

impl Wire for Ldap {
  async fn feed<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    if self.closed {
      return (Rewritten::Close, Vec::new());
    }
    if chunk.is_empty() {
      return self.finish();
    }
    let mut input = chunk;
    let mut out = Vec::new();
    let mut hits = Vec::new();
    while !input.is_empty() {
      let before = input.len();
      if self.step(&mut input, &mut out, &mut hits).await.is_err() {
        self.closed = true;
        return (Rewritten::Close, hits);
      }
      if input.len() == before {
        break;
      }
    }
    if out.is_empty() {
      (Rewritten::Hold, hits)
    } else {
      (Rewritten::Emit(Cow::Owned(out)), hits)
    }
  }
}

impl Ldap {
  /// Empty input is end of stream. A partial message closes. A held needle
  /// suffix is flushed; it is shorter than the secret, so it is not the secret.
  fn finish(&mut self) -> (Rewritten<'static>, Vec<Hit>) {
    let idle = matches!(&self.phase, Phase::Head(buf) if buf.is_empty());
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

  /// Advance one cursor step. Consumes from `input`, or leaves it alone when
  /// the peeked field is still short.
  async fn step(&mut self, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), ()> {
    match std::mem::replace(&mut self.phase, Phase::Head(Vec::new())) {
      Phase::Head(buf) => self.drive_head(buf, input),
      Phase::Peek(peek) => self.drive_peek(peek, input, out, hits).await,
      Phase::Forward(left) => {
        self.phase = self.forward_rest(left, input, out, hits).await?;
        Ok(())
      }
      Phase::Tail { left, id } => self.drive_tail(left, id, input, out, hits).await,
    }
  }

  /// Read the outer tag and definite length. A long announcement is only
  /// these few bytes; the body is not stored.
  fn drive_head(&mut self, mut buf: Vec<u8>, input: &mut &[u8]) -> Result<(), ()> {
    loop {
      match header_view(&buf)? {
        Some((content_len, header)) => {
          self.phase = Phase::Peek(Peek {
            buf,
            left: content_len,
            header,
            kind: Kind::Classify,
          });
          return Ok(());
        }
        None => {
          if !push_byte(&mut buf, input) {
            self.phase = Phase::Head(buf);
            return Ok(());
          }
        }
      }
    }
  }

  /// Peek until the bind password or the `StartTLS` fields are decided.
  /// A field that runs past the message closes. Bytes after the decision
  /// stay in `input` for the forward countdown.
  async fn drive_peek(&mut self, mut peek: Peek, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), ()> {
    loop {
      let need = match peek.kind {
        Kind::Classify => match self.classify(&mut peek)? {
          ClassAct::Need(need) => need,
          ClassAct::Continue => continue,
          ClassAct::Forward => {
            self.phase = self.release(std::mem::take(&mut peek.buf), peek.left, out, hits).await?;
            return Ok(());
          }
        },
        Kind::Bind => match self.bind(&mut peek, out, hits).await? {
          Step::Need(need) => need,
          Step::Done => return Ok(()),
        },
        Kind::ExtReq => match self.ext_req(&mut peek, input, out, hits).await? {
          Step::Need(need) => need,
          Step::Done => return Ok(()),
        },
        Kind::Result => match self.result(&mut peek, out, hits).await? {
          Step::Need(need) => need,
          Step::Done => return Ok(()),
        },
      };
      if peek.buf.len() >= need {
        return Err(());
      }
      let span = need.checked_sub(peek.buf.len()).ok_or(())?;
      if span > peek.left {
        return Err(());
      }
      if input.is_empty() {
        self.phase = Phase::Peek(peek);
        return Ok(());
      }
      let n = span.min(input.len());
      let Some(chunk) = input.get(..n) else {
        return Err(());
      };
      peek.buf.extend_from_slice(chunk);
      *input = input.get(n..).unwrap_or_default();
      peek.left = peek.left.saturating_sub(n);
    }
  }

  /// Classify the message id and `protocolOp`. A non-integer body closes
  /// downstream and is forwarded upstream: search results are not buffered.
  /// An id wider than four bytes is not a message this cursor rewrites, so
  /// both directions forward it and count the body down.
  fn classify(&mut self, peek: &mut Peek) -> Result<ClassAct, ()> {
    let class = match classify_op(&peek.buf, peek.header)? {
      Classified::Need(need) => return Ok(ClassAct::Need(need)),
      Classified::Wide => return Ok(ClassAct::Forward),
      Classified::NotInteger => {
        if self.down.is_some() {
          return Err(());
        }
        return Ok(ClassAct::Forward);
      }
      Classified::Op(class) => class,
    };
    if self
      .up
      .as_ref()
      .is_some_and(|up| up.expect_id == Some(class.id) && class.op != EXTENDED_RESPONSE_TAG)
    {
      return Err(());
    }
    if self.down.as_ref().is_some_and(|down| down.swap) && class.op == BIND_REQUEST_TAG {
      peek.kind = Kind::Bind;
    } else if self.down.is_some() && class.op == EXTENDED_REQUEST_TAG {
      peek.kind = Kind::ExtReq;
    } else if self.up.is_some() && (class.op == BIND_RESPONSE_TAG || class.op == EXTENDED_RESPONSE_TAG) {
      peek.kind = Kind::Result;
    } else {
      return Ok(ClassAct::Forward);
    }
    Ok(ClassAct::Continue)
  }

  /// Emit a matching simple bind, or hand any other bind to the countdown.
  async fn bind(&mut self, peek: &mut Peek, out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<Step, ()> {
    let Some(down) = self.down.as_ref() else {
      return Err(());
    };
    let fake_len = down.fake.len();
    match try_bind(&peek.buf, peek.header, fake_len)? {
      BindParse::Need(need) => Ok(Step::Need(need)),
      BindParse::Skip => {
        self.phase = self.release(std::mem::take(&mut peek.buf), peek.left, out, hits).await?;
        Ok(Step::Done)
      }
      BindParse::Ready(cut) => {
        let password = peek.buf.get(cut.password.clone()).ok_or(())?;
        if password != down.fake.as_bytes() {
          self.phase = self.release(std::mem::take(&mut peek.buf), peek.left, out, hits).await?;
          return Ok(Step::Done);
        }
        let rewritten = rewrite_bind(&peek.buf, &cut, down, peek.left)?;
        hits.push(Hit {
          label: down.label.clone(),
          location: Location::Body,
        });
        self.pass(&rewritten, out, hits).await?;
        // Empty input records the countdown. The caller's remaining `input`
        // is the controls; the next `step` consumes it.
        self.phase = self.forward_rest(peek.left, &mut &[][..], out, hits).await?;
        Ok(Step::Done)
      }
    }
  }

  /// Notice `StartTLS` and emit the request unchanged.
  async fn ext_req(&mut self, peek: &mut Peek, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<Step, ()> {
    match try_ext(&peek.buf, peek.header)? {
      ExtParse::Need(need) => Ok(Step::Need(need)),
      ExtParse::Skip => {
        self.phase = self.release(std::mem::take(&mut peek.buf), peek.left, out, hits).await?;
        Ok(Step::Done)
      }
      ExtParse::StartTls { id } => {
        self.pass(&peek.buf, out, hits).await?;
        if peek.left == 0 {
          self.prefix = input.to_vec();
          *input = &[];
          self.starttls = Some(id);
          self.phase = self.finish_message(out);
        } else {
          self.phase = Phase::Tail { left: peek.left, id };
        }
        Ok(Step::Done)
      }
    }
  }

  /// Redact a diagnostic that carries the real password, and record `StartTLS`.
  async fn result(&mut self, peek: &mut Peek, out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<Step, ()> {
    let Some(up) = self.up.as_ref() else {
      return Err(());
    };
    match try_result(&peek.buf, peek.header)? {
      ResultParse::Need(need) => Ok(Step::Need(need)),
      ResultParse::Skip => {
        self.phase = self.release(std::mem::take(&mut peek.buf), peek.left, out, hits).await?;
        Ok(Step::Done)
      }
      ResultParse::Ready(cut) => {
        if cut.extended && up.expect_id == Some(cut.id) {
          let ok = result_ok(&peek.buf, &cut)?;
          // `responseName` may still be unread. Publish once the message ends.
          self.pending_starttls = Some(ok);
          if let Some(up) = self.up.as_mut() {
            up.expect_id = None;
          }
        }
        let diagnostic = peek.buf.get(cut.diagnostic.clone()).ok_or(())?;
        let secret = self.up.as_ref().map(|up| up.pair.needle.clone()).ok_or(())?;
        if !contains_bytes(diagnostic, &secret) {
          if contains_bytes(&peek.buf, &secret) {
            return Err(());
          }
          self.phase = self.release(std::mem::take(&mut peek.buf), peek.left, out, hits).await?;
          return Ok(Step::Done);
        }
        let fake = self.up.as_ref().map(|up| up.pair.replacement.clone()).ok_or(())?;
        let label = self.up.as_ref().map(|up| up.pair.label.clone()).ok_or(())?;
        let rewritten = rewrite_diagnostic(&peek.buf, &cut, &secret, &fake, peek.left)?;
        hits.push(Hit {
          label,
          location: Location::Body,
        });
        self.pass(&rewritten, out, hits).await?;
        self.phase = self.forward_rest(peek.left, &mut &[][..], out, hits).await?;
        Ok(Step::Done)
      }
    }
  }

  /// Emit a peeked prefix, then count down the unread body without storing it.
  async fn release(&mut self, buf: Vec<u8>, left: usize, out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<Phase, ()> {
    self.pass(&buf, out, hits).await?;
    self.forward_rest(left, &mut &[][..], out, hits).await
  }

  /// Stream `left` bytes from `input`. Short input stays in [`Phase::Forward`].
  async fn forward_rest(&mut self, mut left: usize, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<Phase, ()> {
    let n = left.min(input.len());
    let Some(chunk) = input.get(..n) else {
      return Ok(Phase::Forward(left));
    };
    self.pass(chunk, out, hits).await?;
    *input = input.get(n..).unwrap_or_default();
    left = left.saturating_sub(n);
    if left == 0 {
      Ok(self.finish_message(out))
    } else {
      Ok(Phase::Forward(left))
    }
  }

  /// The current message is complete. Publish a pending `StartTLS` result and
  /// release the needle suffix: LDAP framing says this frame cannot grow.
  fn finish_message(&mut self, out: &mut Vec<u8>) -> Phase {
    if let Some(ok) = self.pending_starttls.take() {
      self.starttls_ok = Some(ok);
    }
    out.extend(std::mem::take(&mut self.held));
    Phase::Head(Vec::new())
  }

  /// Finish a `StartTLS` message, then park the handshake bytes.
  async fn drive_tail(&mut self, left: usize, id: u32, input: &mut &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), ()> {
    let n = left.min(input.len());
    let Some(chunk) = input.get(..n) else {
      self.phase = Phase::Tail { left, id };
      return Ok(());
    };
    self.pass(chunk, out, hits).await?;
    *input = input.get(n..).unwrap_or_default();
    let left = left.saturating_sub(n);
    if left == 0 {
      self.prefix = input.to_vec();
      *input = &[];
      self.starttls = Some(id);
      self.phase = self.finish_message(out);
    } else {
      self.phase = Phase::Tail { left, id };
    }
    Ok(())
  }

  /// Downstream copies through [`Raw`]. Upstream scans with the needle
  /// hold-back and closes when the real password appears outside a diagnostic
  /// we have already rewritten.
  async fn pass(&mut self, data: &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), ()> {
    if data.is_empty() {
      return Ok(());
    }
    if self.up.is_some() {
      return self.scan_up(data, out);
    }
    let (rewritten, found) = self.forward.feed(data).await;
    hits.extend(found);
    match rewritten {
      Rewritten::Emit(bytes) => {
        out.extend_from_slice(&bytes);
        Ok(())
      }
      Rewritten::Hold => Ok(()),
      Rewritten::Close => Err(()),
    }
  }

  /// Emit every byte that cannot still grow into the real password.
  /// A completed match closes the leg instead of forwarding the secret.
  fn scan_up(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    let Some(up) = self.up.as_ref() else {
      out.extend_from_slice(data);
      return Ok(());
    };
    if up.pair.needle.is_empty() {
      out.extend_from_slice(data);
      return Ok(());
    }
    let mut combined = std::mem::take(&mut self.held);
    combined.extend_from_slice(data);
    if find_new_match(&combined, &up.pair.needle, 0) {
      return Err(());
    }
    let tail = up.pair.needle.len().saturating_sub(1);
    let hold = needle_prefix_suffix_len(&combined, std::slice::from_ref(&up.pair), tail);
    let emit = combined.len().saturating_sub(hold);
    let Some(head) = combined.get(..emit) else {
      return Err(());
    };
    out.extend_from_slice(head);
    self.held = combined.split_off(emit);
    Ok(())
  }
}

/// Copy one content byte into `buf`. `false` when `input` is empty.
fn push_byte(buf: &mut Vec<u8>, input: &mut &[u8]) -> bool {
  let Some((byte, rest)) = input.split_first() else {
    return false;
  };
  buf.push(*byte);
  *input = rest;
  true
}

/// `(content length, header length)` of an outer definite-length `SEQUENCE`.
/// `Ok(None)` while the header is short. Indefinite length and illegal
/// lengths are `Err`. RFC 4511 is definite-length only.
fn header_view(buf: &[u8]) -> Result<Option<(usize, usize)>, ()> {
  let Some(&tag) = buf.first() else {
    return Ok(None);
  };
  if tag != 0x30 {
    return Err(());
  }
  let Some(tl) = read_tl(buf, 0)? else {
    return Ok(None);
  };
  Ok(Some((tl.content_len, tl.header)))
}

/// Message id and the following `protocolOp` tag, once both are in `buf`.
struct Class {
  id: u32,
  op: u8,
}

/// Message id plus the operation tag, or a reason to keep reading.
enum Classified {
  Need(usize),
  /// The first content tag is not an `INTEGER`.
  NotInteger,
  /// The message id is wider than four bytes. Forward it; do not peek the body.
  Wide,
  Op(Class),
}

/// A TLV header, or the absolute `buf` index that completes it.
enum TlWait {
  Need(usize),
  Ready(Tl),
}

fn classify_op(buf: &[u8], header: usize) -> Result<Classified, ()> {
  let id = match take_tl(buf, header)? {
    TlWait::Need(need) => return Ok(Classified::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  if id.tag != 0x02 {
    return Ok(Classified::NotInteger);
  }
  // Wider than a `u32`. The body is not requested: `Forward` counts it down.
  if id.content_len > 4 {
    return Ok(Classified::Wide);
  }
  let id_end = header.checked_add(id.total().ok_or(())?).ok_or(())?;
  if buf.len() < id_end {
    return Ok(Classified::Need(id_end));
  }
  let op_at = id_end;
  let Some(&op) = buf.get(op_at) else {
    return Ok(Classified::Need(op_at.checked_add(1).ok_or(())?));
  };
  let content_at = header.checked_add(id.header).ok_or(())?;
  let bytes = buf.get(content_at..id_end).ok_or(())?;
  Ok(Classified::Op(Class {
    id: parse_uint(bytes)?,
    op,
  }))
}

fn try_bind(buf: &[u8], header: usize, fake_len: usize) -> Result<BindParse, ()> {
  let id = match take_tl(buf, header)? {
    TlWait::Need(need) => return Ok(BindParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  let bind_at = header.checked_add(id.total().ok_or(())?).ok_or(())?;
  if buf.len() < bind_at {
    return Ok(BindParse::Need(bind_at));
  }
  let bind = match take_tl(buf, bind_at)? {
    TlWait::Need(need) => return Ok(BindParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  if bind.tag != BIND_REQUEST_TAG {
    return Ok(BindParse::Skip);
  }
  let mut cur = bind_at.checked_add(bind.header).ok_or(())?;
  let version = match take_tl(buf, cur)? {
    TlWait::Need(need) => return Ok(BindParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  if version.tag != 0x02 {
    return Ok(BindParse::Skip);
  }
  let version_end = cur.checked_add(version.total().ok_or(())?).ok_or(())?;
  if buf.len() < version_end {
    return Ok(BindParse::Need(version_end));
  }
  let version_span = cur..version_end;
  cur = version_end;
  let dn = match take_tl(buf, cur)? {
    TlWait::Need(need) => return Ok(BindParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  if dn.tag != 0x04 {
    return Ok(BindParse::Skip);
  }
  let dn_end = cur.checked_add(dn.total().ok_or(())?).ok_or(())?;
  if buf.len() < dn_end {
    return Ok(BindParse::Need(dn_end));
  }
  let dn_content = cur.checked_add(dn.header).ok_or(())?..dn_end;
  cur = dn_end;
  let auth = match take_tl(buf, cur)? {
    TlWait::Need(need) => return Ok(BindParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  if auth.tag != CONTEXT_0 || auth.content_len != fake_len {
    return Ok(BindParse::Skip);
  }
  let pw_end = cur.checked_add(auth.total().ok_or(())?).ok_or(())?;
  if buf.len() < pw_end {
    return Ok(BindParse::Need(pw_end));
  }
  let password = cur.checked_add(auth.header).ok_or(())?..pw_end;
  Ok(BindParse::Ready(BindCut {
    msgid: header..bind_at,
    version: version_span,
    dn: dn_content,
    password,
  }))
}

fn try_ext(buf: &[u8], header: usize) -> Result<ExtParse, ()> {
  let id = match take_tl(buf, header)? {
    TlWait::Need(need) => return Ok(ExtParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  let ext_at = header.checked_add(id.total().ok_or(())?).ok_or(())?;
  if buf.len() < ext_at {
    return Ok(ExtParse::Need(ext_at));
  }
  let ext = match take_tl(buf, ext_at)? {
    TlWait::Need(need) => return Ok(ExtParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  if ext.tag != EXTENDED_REQUEST_TAG {
    return Ok(ExtParse::Skip);
  }
  let name_at = ext_at.checked_add(ext.header).ok_or(())?;
  let name = match take_tl(buf, name_at)? {
    TlWait::Need(need) => return Ok(ExtParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  if name.tag != CONTEXT_0 {
    return Ok(ExtParse::Skip);
  }
  // Any other length cannot be the StartTLS OID, so the name body is not peeked.
  if name.content_len != STARTTLS_OID.len() {
    return Ok(ExtParse::Skip);
  }
  let name_end = name_at.checked_add(name.total().ok_or(())?).ok_or(())?;
  if buf.len() < name_end {
    return Ok(ExtParse::Need(name_end));
  }
  let content_at = name_at.checked_add(name.header).ok_or(())?;
  let oid = buf.get(content_at..name_end).ok_or(())?;
  let ext_content_end = name_at.checked_add(ext.content_len).ok_or(())?;
  if oid == STARTTLS_OID && name_end == ext_content_end {
    let id_bytes_at = header.checked_add(id.header).ok_or(())?;
    let id_bytes = buf.get(id_bytes_at..ext_at).ok_or(())?;
    return Ok(ExtParse::StartTls { id: parse_uint(id_bytes)? });
  }
  Ok(ExtParse::Skip)
}

fn try_result(buf: &[u8], header: usize) -> Result<ResultParse, ()> {
  let id = match take_tl(buf, header)? {
    TlWait::Need(need) => return Ok(ResultParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  let resp_at = header.checked_add(id.total().ok_or(())?).ok_or(())?;
  if buf.len() < resp_at {
    return Ok(ResultParse::Need(resp_at));
  }
  let resp = match take_tl(buf, resp_at)? {
    TlWait::Need(need) => return Ok(ResultParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  if resp.tag != BIND_RESPONSE_TAG && resp.tag != EXTENDED_RESPONSE_TAG {
    return Ok(ResultParse::Skip);
  }
  let mut cur = resp_at.checked_add(resp.header).ok_or(())?;
  let code = match take_tl(buf, cur)? {
    TlWait::Need(need) => return Ok(ResultParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  if code.tag != 0x0a {
    return Ok(ResultParse::Skip);
  }
  cur = cur.checked_add(code.total().ok_or(())?).ok_or(())?;
  if buf.len() < cur {
    return Ok(ResultParse::Need(cur));
  }
  let dn = match take_tl(buf, cur)? {
    TlWait::Need(need) => return Ok(ResultParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  if dn.tag != 0x04 {
    return Ok(ResultParse::Skip);
  }
  cur = cur.checked_add(dn.total().ok_or(())?).ok_or(())?;
  if buf.len() < cur {
    return Ok(ResultParse::Need(cur));
  }
  let diag_at = cur;
  let diag = match take_tl(buf, diag_at)? {
    TlWait::Need(need) => return Ok(ResultParse::Need(need)),
    TlWait::Ready(tl) => tl,
  };
  if diag.tag != 0x04 {
    return Ok(ResultParse::Skip);
  }
  let diag_end = diag_at.checked_add(diag.total().ok_or(())?).ok_or(())?;
  if buf.len() < diag_end {
    return Ok(ResultParse::Need(diag_end));
  }
  let response_at = resp_at.checked_add(resp.header).ok_or(())?;
  let diag_content = diag_at.checked_add(diag.header).ok_or(())?..diag_end;
  let consumed = diag_end.checked_sub(response_at).ok_or(())?;
  let after_inside = resp.content_len.checked_sub(consumed).ok_or(())?;
  let id_bytes = buf.get(header.checked_add(id.header).ok_or(())?..resp_at).ok_or(())?;
  Ok(ResultParse::Ready(ResultCut {
    id: parse_uint(id_bytes)?,
    extended: resp.tag == EXTENDED_RESPONSE_TAG,
    msgid: header..resp_at,
    response_tag: resp.tag,
    response_at,
    before_diag: response_at..diag_at,
    diagnostic: diag_content,
    after_inside,
  }))
}

/// `true` when the enumerated result code is success.
fn result_ok(buf: &[u8], cut: &ResultCut) -> Result<bool, ()> {
  let Some(code) = read_tl(buf, cut.response_at)? else {
    return Err(());
  };
  let start = cut.response_at.checked_add(code.header).ok_or(())?;
  let end = start.checked_add(code.content_len).ok_or(())?;
  let bytes = buf.get(start..end).ok_or(())?;
  Ok(parse_uint(bytes)? == 0)
}

/// Rebuild a simple bind with the real password and, when the DN matches
/// the downstream grant, the upstream DN. `controls` is the unread tail of
/// the outer sequence and is not part of the bind.
fn rewrite_bind(buf: &[u8], cut: &BindCut, down: &Down, controls: usize) -> Result<Vec<u8>, ()> {
  let dn = buf.get(cut.dn.clone()).ok_or(())?;
  let new_dn: &[u8] = if dn == down.downstream_dn.as_bytes() && down.downstream_dn != down.upstream_dn {
    down.upstream_dn.as_bytes()
  } else {
    dn
  };
  let mut bind_content = Vec::new();
  bind_content.extend_from_slice(buf.get(cut.version.clone()).ok_or(())?);
  write_tlv(&mut bind_content, 0x04, new_dn)?;
  write_tlv(&mut bind_content, CONTEXT_0, down.real.as_bytes())?;
  let mut bind_tlv = Vec::new();
  bind_tlv.push(BIND_REQUEST_TAG);
  write_len(&mut bind_tlv, bind_content.len())?;
  bind_tlv.extend_from_slice(&bind_content);
  let msgid = buf.get(cut.msgid.clone()).ok_or(())?;
  let seq_len = msgid.len().checked_add(bind_tlv.len()).ok_or(())?.checked_add(controls).ok_or(())?;
  let mut out = Vec::new();
  out.push(0x30);
  write_len(&mut out, seq_len)?;
  out.extend_from_slice(msgid);
  out.extend_from_slice(&bind_tlv);
  Ok(out)
}

/// Replace the real password inside the diagnostic and retarget the lengths
/// that enclose it. Bytes after the diagnostic are streamed unchanged.
fn rewrite_diagnostic(buf: &[u8], cut: &ResultCut, real: &[u8], fake: &[u8], left: usize) -> Result<Vec<u8>, ()> {
  let diagnostic = buf.get(cut.diagnostic.clone()).ok_or(())?;
  let Some(replaced) = replace_bytes(diagnostic, real, fake) else {
    return Err(());
  };
  if find_new_match(&replaced, real, 0) {
    return Err(());
  }
  let mut response_content = Vec::new();
  response_content.extend_from_slice(buf.get(cut.before_diag.clone()).ok_or(())?);
  write_tlv(&mut response_content, 0x04, &replaced)?;
  let response_len = response_content.len().checked_add(cut.after_inside).ok_or(())?;
  let mut response_tlv = Vec::new();
  response_tlv.push(cut.response_tag);
  write_len(&mut response_tlv, response_len)?;
  response_tlv.extend_from_slice(&response_content);
  let msgid = buf.get(cut.msgid.clone()).ok_or(())?;
  let controls = left.checked_sub(cut.after_inside).ok_or(())?;
  let seq_len = msgid
    .len()
    .checked_add(response_tlv.len())
    .ok_or(())?
    .checked_add(cut.after_inside)
    .ok_or(())?
    .checked_add(controls)
    .ok_or(())?;
  let mut out = Vec::new();
  out.push(0x30);
  write_len(&mut out, seq_len)?;
  out.extend_from_slice(msgid);
  out.extend_from_slice(&response_tlv);
  Ok(out)
}

/// Header at `at`, or how many `buf` bytes complete that header.
fn take_tl(buf: &[u8], at: usize) -> Result<TlWait, ()> {
  if let Some(need) = header_need(buf, at)? {
    return Ok(TlWait::Need(need));
  }
  match read_tl(buf, at)? {
    Some(tl) => Ok(TlWait::Ready(tl)),
    None => Err(()),
  }
}

/// Absolute `buf` index that finishes the TLV header at `at`.
/// `Ok(None)` when that header is already complete. Indefinite length is `Err`.
fn header_need(buf: &[u8], at: usize) -> Result<Option<usize>, ()> {
  if buf.get(at).is_none() {
    return Ok(Some(at.checked_add(1).ok_or(())?));
  }
  let len_at = at.checked_add(1).ok_or(())?;
  let Some(&len_byte) = buf.get(len_at) else {
    return Ok(Some(len_at.checked_add(1).ok_or(())?));
  };
  if len_byte == 0x80 {
    return Err(());
  }
  if len_byte < 0x80 {
    return Ok(None);
  }
  let octets = usize::from(len_byte & 0x7f);
  if octets == 0 || octets > 4 {
    return Err(());
  }
  let end = len_at.checked_add(1).ok_or(())?.checked_add(octets).ok_or(())?;
  if buf.len() < end { Ok(Some(end)) } else { Ok(None) }
}

/// Tag and definite length at `at`. The content itself may be absent.
fn read_tl(buf: &[u8], at: usize) -> Result<Option<Tl>, ()> {
  let Some(&tag) = buf.get(at) else {
    return Ok(None);
  };
  let len_at = at.checked_add(1).ok_or(())?;
  let Some(&len_byte) = buf.get(len_at) else {
    return Ok(None);
  };
  if len_byte == 0x80 {
    return Err(());
  }
  if len_byte < 0x80 {
    let header = 2usize;
    return Ok(Some(Tl {
      tag,
      header,
      content_len: usize::from(len_byte),
    }));
  }
  let octets = usize::from(len_byte & 0x7f);
  if octets == 0 || octets > 4 {
    return Err(());
  }
  let header = 2usize.checked_add(octets).ok_or(())?;
  let end = at.checked_add(header).ok_or(())?;
  if buf.len() < end {
    return Ok(None);
  }
  let mut content_len = 0usize;
  let Some(bytes) = buf.get(len_at.checked_add(1).ok_or(())?..end) else {
    return Err(());
  };
  for byte in bytes {
    content_len = content_len.checked_shl(8).ok_or(())?.checked_add(usize::from(*byte)).ok_or(())?;
  }
  Ok(Some(Tl { tag, header, content_len }))
}

fn write_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) -> Result<(), ()> {
  out.push(tag);
  write_len(out, content.len())?;
  out.extend_from_slice(content);
  Ok(())
}

fn write_len(out: &mut Vec<u8>, len: usize) -> Result<(), ()> {
  if len < 0x80 {
    let Some(byte) = u8::try_from(len).ok() else {
      return Err(());
    };
    out.push(byte);
    return Ok(());
  }
  let bytes = len.to_be_bytes();
  let Some(start) = bytes.iter().position(|byte| *byte != 0) else {
    return Err(());
  };
  let rest = bytes.get(start..).ok_or(())?;
  let Some(octets) = u8::try_from(rest.len()).ok() else {
    return Err(());
  };
  out.push(0x80 | octets);
  out.extend_from_slice(rest);
  Ok(())
}

fn parse_uint(bytes: &[u8]) -> Result<u32, ()> {
  if bytes.is_empty() || bytes.len() > 4 {
    return Err(());
  }
  let mut value = 0u32;
  for byte in bytes {
    value = value.checked_shl(8).ok_or(())?.checked_add(u32::from(*byte)).ok_or(())?;
  }
  Ok(value)
}

/// `true` when `needle` occurs in `hay`. An empty needle never matches.
fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
  if needle.is_empty() || hay.len() < needle.len() {
    return false;
  }
  hay.windows(needle.len()).any(|window| window == needle)
}

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::grants::{Credential, GuestTlsMode, LdapScope};
  use rasn_ldap::{AuthenticationChoice, BindRequest};
  use secrecy::SecretString;

  const FAKE_PW: &str = "arkham_fake_ldap_pass"; // betterleaks:allow
  const REAL_PW: &str = "arkham_real_ldap_pass_01"; // betterleaks:allow
  const DN: &str = "cn=Directory Manager";

  fn scope(downstream_dn: &str, upstream_dn: &str) -> LdapScope {
    LdapScope::from_strings(
      &format!("ldap://{}:{FAKE_PW}@ldap:389", encode_user(downstream_dn)),
      &format!("ldap://{}:{REAL_PW}@ldap:389", encode_user(upstream_dn)),
    )
    .unwrap()
  }

  fn encode_user(dn: &str) -> String {
    dn.replace('=', "%3D").replace(' ', "%20").replace(',', "%2C")
  }

  fn grant(downstream_dn: &str, upstream_dn: &str) -> Vec<Grant> {
    let parsed = scope(downstream_dn, upstream_dn);
    vec![Grant::Ldap {
      credential: Credential {
        label: "ldap".into(),
        fake: FAKE_PW.into(),
        value: SecretString::from(REAL_PW),
      },
      scope: Box::new(parsed),
    }]
  }

  fn down() -> Ldap {
    Ldap::new(&grant(DN, DN), "ldap", 389, Direction::Downstream, true)
  }

  fn up() -> Ldap {
    Ldap::new(&grant(DN, DN), "ldap", 389, Direction::Upstream, false)
  }

  fn bind_frame(id: u32, dn: &str, password: &str) -> Vec<u8> {
    let message = LdapMessage::new(
      id,
      ProtocolOp::BindRequest(BindRequest::new(
        3,
        LdapString::from(dn),
        AuthenticationChoice::Simple(OctetString::from(password.as_bytes())),
      )),
    );
    rasn::ber::encode(&message).unwrap()
  }

  fn starttls_frame(id: u32) -> Vec<u8> {
    let message = LdapMessage::new(
      id,
      ProtocolOp::ExtendedReq(rasn_ldap::ExtendedRequest {
        request_name: OctetString::from_static(STARTTLS_OID),
        request_value: None,
      }),
    );
    rasn::ber::encode(&message).unwrap()
  }

  fn bind_response(id: u32, diagnostic: &str) -> Vec<u8> {
    let message = LdapMessage::new(
      id,
      ProtocolOp::BindResponse(rasn_ldap::BindResponse::new(
        ResultCode::InvalidCredentials,
        LdapString::from(""),
        LdapString::from(diagnostic),
        None,
        None,
      )),
    );
    rasn::ber::encode(&message).unwrap()
  }

  async fn emit(machine: &mut Ldap, chunk: &[u8]) -> Vec<u8> {
    match machine.feed(chunk).await.0 {
      Rewritten::Emit(bytes) => bytes.into_owned(),
      other => panic!("expected emit, got hold/close: {}", matches!(other, Rewritten::Hold)),
    }
  }

  async fn collect(machine: &mut Ldap, chunk: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match machine.feed(chunk).await.0 {
      Rewritten::Emit(bytes) => out.extend_from_slice(&bytes),
      Rewritten::Hold => {}
      Rewritten::Close => panic!("close"),
    }
    out
  }

  #[tokio::test]
  async fn simple_bind_swaps_a_different_length_password() {
    let frame = bind_frame(1, DN, FAKE_PW);
    let mut machine = down();
    let out = emit(&mut machine, &frame).await;
    let message: LdapMessage = rasn::ber::decode(&out).unwrap();
    let ProtocolOp::BindRequest(request) = message.protocol_op else {
      panic!("bind");
    };
    let AuthenticationChoice::Simple(password) = request.authentication else {
      panic!("simple");
    };
    assert_eq!(password.as_ref(), REAL_PW.as_bytes());
    assert_ne!(frame.len(), out.len());
    assert!(!contains_bytes(&out, FAKE_PW.as_bytes()));
  }

  #[tokio::test]
  async fn bind_split_across_chunks_swaps_the_whole_password() {
    let frame = bind_frame(7, DN, FAKE_PW);
    for cut in 0..frame.len() {
      let mut machine = down();
      let mut acc = collect(&mut machine, &frame[..cut]).await;
      acc.extend(collect(&mut machine, &frame[cut..]).await);
      let message: LdapMessage = rasn::ber::decode(&acc).unwrap();
      let ProtocolOp::BindRequest(request) = message.protocol_op else {
        panic!("bind at cut {cut}");
      };
      let AuthenticationChoice::Simple(password) = request.authentication else {
        panic!("simple at cut {cut}");
      };
      assert_eq!(password.as_ref(), REAL_PW.as_bytes(), "cut {cut}");
    }
  }

  #[tokio::test]
  async fn cleartext_bind_forwards_the_decoy() {
    let frame = bind_frame(1, DN, FAKE_PW);
    let mut machine = Ldap::new(&grant(DN, DN), "ldap", 389, Direction::Downstream, false);
    let out = emit(&mut machine, &frame).await;
    assert_eq!(out, frame);
  }

  #[tokio::test]
  async fn starttls_is_noticed_while_the_password_stays_put() {
    let mut bytes = bind_frame(1, DN, FAKE_PW);
    bytes.extend_from_slice(&starttls_frame(2));
    let mut machine = Ldap::new(&grant(DN, DN), "ldap", 389, Direction::Downstream, false);
    let out = emit(&mut machine, &bytes).await;
    assert_eq!(out, bytes);
    assert_eq!(machine.take_starttls(), Some(2));
  }

  #[tokio::test]
  async fn bind_controls_survive_the_swap() {
    let mut message = LdapMessage::new(
      3,
      ProtocolOp::BindRequest(BindRequest::new(
        3,
        LdapString::from(DN),
        AuthenticationChoice::Simple(OctetString::from(FAKE_PW.as_bytes())),
      )),
    );
    message.controls = Some(vec![rasn_ldap::Control::new(
      OctetString::from_static(b"1.2.840.113556.1.4.319"),
      true,
      Some(OctetString::from_static(b"page")),
    )]);
    let frame = rasn::ber::encode(&message).unwrap();
    let mut machine = down();
    let out = emit(&mut machine, &frame).await;
    let decoded: LdapMessage = rasn::ber::decode(&out).unwrap();
    assert_eq!(decoded.controls, message.controls);
    let ProtocolOp::BindRequest(request) = decoded.protocol_op else {
      panic!("bind");
    };
    let AuthenticationChoice::Simple(password) = request.authentication else {
      panic!("simple");
    };
    assert_eq!(password.as_ref(), REAL_PW.as_bytes());
  }

  #[tokio::test]
  async fn decoy_that_is_a_substring_of_the_dn_still_swaps() {
    let dn = "cn=Directory Manager";
    let fake = "cn";
    let real = "cn-real-secret";
    let parsed = LdapScope::from_strings(
      &format!("ldap://{}:{fake}@ldap:389", encode_user(dn)),
      &format!("ldap://{}:{real}@ldap:389", encode_user(dn)),
    )
    .unwrap();
    let grants = vec![Grant::Ldap {
      credential: Credential {
        label: "ldap".into(),
        fake: fake.into(),
        value: SecretString::from(real),
      },
      scope: Box::new(parsed),
    }];
    let mut machine = Ldap::new(&grants, "ldap", 389, Direction::Downstream, true);
    let out = emit(&mut machine, &bind_frame(1, dn, fake)).await;
    let message: LdapMessage = rasn::ber::decode(&out).unwrap();
    let ProtocolOp::BindRequest(request) = message.protocol_op else {
      panic!("bind");
    };
    let AuthenticationChoice::Simple(password) = request.authentication else {
      panic!("simple");
    };
    assert_eq!(password.as_ref(), real.as_bytes());
    assert_eq!(request.name.0, dn);
  }

  #[tokio::test]
  async fn many_small_messages_stream() {
    let frame = bind_frame(1, DN, "not-the-decoy");
    let mut bytes = Vec::new();
    while bytes.len() <= 64 * 1024 {
      bytes.extend_from_slice(&frame);
    }
    let mut machine = down();
    let out = emit(&mut machine, &bytes).await;
    assert_eq!(out, bytes);
  }

  #[tokio::test]
  async fn downstream_announced_length_streams() {
    let mut msg = vec![0x30, 0x84, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x01, 0x63];
    msg.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    let mut machine = down();
    let out = emit(&mut machine, &msg).await;
    assert_eq!(out, msg);
  }

  #[tokio::test]
  async fn indefinite_length_closes() {
    let mut machine = down();
    let (rewritten, _) = machine.feed(&[0x30, 0x80]).await;
    assert!(matches!(rewritten, Rewritten::Close));
  }

  #[tokio::test]
  async fn upstream_message_larger_than_a_bind_is_forwarded() {
    let content_len = 64 * 1024 + 1;
    let mut frame = vec![0x30, 0x84];
    let len = u32::try_from(content_len).unwrap();
    frame.extend_from_slice(&len.to_be_bytes());
    frame.resize(frame.len() + content_len, 0x00);
    let mut machine = up();
    let out = emit(&mut machine, &frame).await;
    assert_eq!(out, frame);
  }

  #[tokio::test]
  async fn upstream_announced_length_streams() {
    // Content length is 16 MiB + 1. Those bytes are not collected. A short
    // body is forwarded with the header; the unread tail is a countdown.
    let header = [0x30, 0x84, 0x01, 0x00, 0x00, 0x01];
    let body = [0x00, 0x01, 0x02, 0x03];
    let mut expect = header.to_vec();
    expect.extend_from_slice(&body);
    let mut machine = up();
    let out = emit(&mut machine, &expect).await;
    assert_eq!(out, expect);

    // The header alone has no message id yet, so it stays in the peek.
    // The next chunk is still not held until the announced length arrives.
    let mut split = up();
    let (first, _) = split.feed(&header).await;
    assert!(matches!(first, Rewritten::Hold));
    let out = emit(&mut split, &body).await;
    assert_eq!(out, expect);
  }

  #[tokio::test]
  async fn upstream_non_secret_message_is_not_decoded() {
    let frame = [0x30, 0x06, 0x02, 0x01, 0x01, 0x42, 0x01, 0x00];
    let mut machine = up();
    let out = emit(&mut machine, &frame).await;
    assert_eq!(out, frame);
  }

  #[tokio::test]
  async fn unreadable_starttls_response_closes() {
    let frame = [0x30, 0x06, 0x02, 0x01, 0x04, 0x42, 0x01, 0x00];
    let mut machine = up();
    machine.expect_starttls(4);
    let (rewritten, _) = machine.feed(&frame).await;
    assert!(matches!(rewritten, Rewritten::Close));
  }

  #[tokio::test]
  async fn non_matching_password_is_byte_identical() {
    let frame = bind_frame(1, DN, "not-the-decoy");
    let mut machine = down();
    let out = emit(&mut machine, &frame).await;
    assert_eq!(out, frame);
  }

  #[tokio::test]
  async fn differing_dns_swap_with_the_password() {
    let mut machine = Ldap::new(&grant(DN, "cn=svc,dc=example,dc=com"), "ldap", 389, Direction::Downstream, true);
    let out = emit(&mut machine, &bind_frame(1, DN, FAKE_PW)).await;
    let message: LdapMessage = rasn::ber::decode(&out).unwrap();
    let ProtocolOp::BindRequest(request) = message.protocol_op else {
      panic!("bind");
    };
    assert_eq!(request.name.0, "cn=svc,dc=example,dc=com");
  }

  #[tokio::test]
  async fn extended_request_with_a_long_name_is_not_held() {
    // The request name announces 64 KiB. That body is not the StartTLS OID,
    // so it is counted down instead of peeked. Four following bytes emit now.
    let mut msg = vec![
      0x30, 0x84, 0x00, 0x01, 0x00, 0x0f, // outer content length 65551
      0x02, 0x01, 0x01, // message id 1
      0x77, 0x84, 0x00, 0x01, 0x00, 0x06, // extended request, content 65542
      0x80, 0x84, 0x00, 0x01, 0x00, 0x00, // name length 65536
    ];
    msg.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    let mut machine = Ldap::new(&grant(DN, DN), "ldap", 389, Direction::Downstream, false);
    let out = emit(&mut machine, &msg).await;
    assert_eq!(out, msg);
  }

  #[tokio::test]
  async fn starttls_request_is_byte_identical_and_stops_the_buffer() {
    let frame = starttls_frame(4);
    let extra = b"\x16handshake";
    let mut bytes = frame.clone();
    bytes.extend_from_slice(extra);
    let mut machine = down();
    let out = emit(&mut machine, &bytes).await;
    assert_eq!(out, frame);
    assert_eq!(machine.take_starttls(), Some(4));
    assert_eq!(machine.take_prefix(), extra);
  }

  #[tokio::test]
  async fn diagnostic_real_password_is_redacted() {
    let frame = bind_response(1, &format!("rejected {REAL_PW}"));
    let mut machine = up();
    let out = emit(&mut machine, &frame).await;
    assert!(!contains_bytes(&out, REAL_PW.as_bytes()));
    assert!(contains_bytes(&out, FAKE_PW.as_bytes()));
    let message: LdapMessage = rasn::ber::decode(&out).unwrap();
    let ProtocolOp::BindResponse(response) = message.protocol_op else {
      panic!("bind response");
    };
    assert_eq!(response.diagnostic_message.0, format!("rejected {FAKE_PW}"));
  }

  #[tokio::test]
  async fn starttls_response_parks_the_following_handshake() {
    let response = starttls_success(4).unwrap();
    let mut frame = response.clone();
    let handshake = [0x16, 0x03, 0x03];
    frame.extend_from_slice(&handshake);
    let mut machine = up();
    machine.expect_starttls(4);
    let out = emit(&mut machine, &frame).await;
    assert_eq!(out, response);
    assert_eq!(machine.take_starttls_result(), Some(true));
    assert_eq!(machine.take_prefix(), handshake);
  }

  #[tokio::test]
  async fn starttls_success_is_reported() {
    let frame = {
      let message = LdapMessage::new(
        4,
        ProtocolOp::ExtendedResp(ExtendedResponse {
          result_code: ResultCode::Success,
          matched_dn: LdapString::from(""),
          diagnostic_message: LdapString::from(""),
          referral: None,
          response_name: Some(OctetString::from_static(STARTTLS_OID)),
          response_value: None,
        }),
      );
      rasn::ber::encode(&message).unwrap()
    };
    let mut machine = up();
    machine.expect_starttls(4);
    let out = emit(&mut machine, &frame).await;
    assert_eq!(out, frame);
    assert_eq!(machine.take_starttls_result(), Some(true));
  }

  #[tokio::test]
  async fn starttls_success_waits_until_the_message_is_complete() {
    let frame = {
      let message = LdapMessage::new(
        4,
        ProtocolOp::ExtendedResp(ExtendedResponse {
          result_code: ResultCode::Success,
          matched_dn: LdapString::from(""),
          diagnostic_message: LdapString::from(""),
          referral: None,
          response_name: Some(OctetString::from_static(STARTTLS_OID)),
          response_value: None,
        }),
      );
      rasn::ber::encode(&message).unwrap()
    };
    let mut machine = up();
    machine.expect_starttls(4);
    let mut out = Vec::new();
    for (index, byte) in frame.iter().enumerate() {
      out.extend(collect(&mut machine, std::slice::from_ref(byte)).await);
      if index + 1 < frame.len() {
        assert_eq!(machine.take_starttls_result(), None, "byte {index}");
      }
    }
    assert_eq!(out, frame);
    assert_eq!(machine.take_starttls_result(), Some(true));
  }

  #[tokio::test]
  async fn complete_response_flushes_a_held_password_prefix() {
    // The real password starts with `a`. A finished diagnostic ending in that
    // byte must not stay in the needle window while the server is still open.
    let frame = bind_response(1, "invalid data");
    assert_eq!(frame.last().copied(), Some(b'a'));
    let mut machine = up();
    let mut out = collect(&mut machine, &frame[..frame.len() - 1]).await;
    out.extend(collect(&mut machine, &frame[frame.len() - 1..]).await);
    assert_eq!(out, frame);
    let next = [0x30, 0x06, 0x02, 0x01, 0x02, 0x42, 0x01, 0x00];
    let out = emit(&mut machine, &next).await;
    assert_eq!(out, next);
  }

  #[tokio::test]
  async fn wide_message_id_is_forwarded_without_peeking() {
    let small = [0x30, 0x0a, 0x02, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55, 0x42, 0x01, 0x00];
    for mut machine in [down(), up()] {
      let out = emit(&mut machine, &small).await;
      assert_eq!(out, small);
    }
    // The id announces 64 KiB. Those bytes are not pulled into the peek.
    let mut huge = vec![
      0x30, 0x84, 0x00, 0x01, 0x00, 0x06, // outer content 65542
      0x02, 0x84, 0x00, 0x01, 0x00, 0x00, // integer content 65536
      0x11, 0x22, 0x33, 0x44,
    ];
    for mut machine in [down(), up()] {
      let out = emit(&mut machine, &huge).await;
      assert_eq!(out, huge);
    }
    huge.extend_from_slice(&[0x55, 0x66]);
    let split = huge.len() - 2;
    let mut machine = up();
    let out = emit(&mut machine, &huge[..split]).await;
    assert_eq!(out, &huge[..split]);
    let out = emit(&mut machine, &huge[split..]).await;
    assert_eq!(out, &huge[split..]);
  }

  fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    thread_local! {
      static RT: tokio::runtime::Runtime =
        tokio::runtime::Builder::new_current_thread().build().unwrap();
    }
    RT.with(|rt| rt.block_on(fut))
  }

  proptest::proptest! {
    #[test]
    fn arbitrary_bytes_do_not_panic(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..128)) {
      let mut downstream = down();
      let mut upstream = up();
      block_on(async {
        let _ = downstream.feed(&bytes).await;
        let _ = upstream.feed(&bytes).await;
        let _ = downstream.feed(&[]).await;
        let _ = upstream.feed(&[]).await;
      });
    }
  }

  #[test]
  fn scope_fields_are_used() {
    let parsed = scope(DN, DN);
    assert_eq!(parsed.downstream.port, 389);
    assert!(!parsed.is_downstream_tls);
    let _ = parsed.guest_tls;
    assert_eq!(parsed.guest_tls, GuestTlsMode::Tls);
  }
}
