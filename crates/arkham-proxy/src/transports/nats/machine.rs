//! NATS wire format: one [`Framer`] cuts both directions into command lines
//! and counted payloads.
//!
//! Downstream, CONNECT is buffered only while the server leg is TLS, so the
//! swap can see every field. A cleartext leg forwards CONNECT as it arrives.
//! Past [`MAX_COMMAND`] the bytes already held and the rest of that line go
//! out untouched, and the session stays open. When the server leg is TLS,
//! every auth method rewrites the CONNECT fields [`NatsAuth::fields`] lists,
//! and only when each of those fields holds the decoy. A method that signs
//! does that after the first INFO nonce is armed and the guest signature
//! verifies under the decoy public key. Every other byte,
//! including PUB and HPUB payloads, streams as it arrives.
//!
//! Verbs follow the protocol message table. Operation names are case
//! insensitive, so `SUB` and `sub` are the same command.
//! <https://docs.nats.io/reference/reference-protocols/nats-protocol>
//!
//! | Message | Sent by |
//! | --- | --- |
//! | `CONNECT`, `PUB`, `HPUB`, `SUB`, `UNSUB` | client |
//! | `INFO`, `MSG`, `HMSG`, `+OK`, `-ERR` | server |
//! | `PING`, `PONG` | both |
//!
//! The streaming framer stays. `watermelon-proto` 0.2.1 `StreamDecoder::decode`
//! returns `ServerOp` only, and it copies each control line and payload into
//! its `BytesMut` read buffer, refusing a declared length above `MAX_MSG_LEN`
//! (128 MiB). `ClientOp` is passed to `encode` and `enqueue_write_op` and has
//! no decoder. `decode_msg`, `decode_hmsg`, and `decode_headers` are private.
//! Counted payloads here have to stream, so that decoder cannot sit on the relay.
//!
//! Delimiter and newline scans use `memchr` 2.8 (`memchr`, `memchr2`) on the
//! current slice. That crate's finders take at most three needles and have no
//! "byte not in this set" search, so the four delimiters (space, tab, CR, LF)
//! are the nearer of two `memchr2` hits, and a run of delimiters is skipped by
//! a walk. A digit run uses `atoi` 2 `u64::from_radix_10_checked` on the
//! contiguous bytes already in the slice. A count split across chunks keeps
//! the `u64` already parsed and scales it; the digit bytes are not stored.
//! `lexical-core` 1.0 `parse` and `parse_partial` also need one contiguous
//! slice and report nothing `atoi` does not already return.
//!
//! INFO's `tls_required`, `tls_available`, and `tls_verify` come from actson
//! 2.1.0. The verb is still the framer's first piece. Object bytes go into
//! `PushJsonFeeder`, and names and bools are taken at depth 1. That crate
//! keeps the current token in `current_buffer` until the event, and the
//! feeder queues at most 1024 bytes, so a token stops at [`MAX_COMMAND`].
//! A cleartext line whose object does not end, and whose `tls_required`
//! was not true, closes. The INFO line is not stored. The verdict is ready
//! when the line piece includes LF.
//!
//! Upstream, delimited lines (INFO, -ERR, +OK, PING, PONG) redact the real
//! value back to the decoy. MSG and HMSG payloads are counted down and never
//! rewritten: a payload that carries the real value closes the leg.

use std::borrow::Cow;
use std::collections::BTreeMap;

use actson::feeder::PushJsonFeeder;
use actson::{JsonEvent, JsonParser};
use arkham_config::grants::{FieldPresence, Grant, NatsAuth, NatsField, NatsSeed};
use atoi::FromRadix10Checked as _;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use secrecy::ExposeSecret as _;
use serde_json::{Map, Value};
use strum::{EnumIter, EnumString, IntoEnumIterator as _, IntoStaticStr};

use crate::transports::engine::{
  CredentialPair, Hit, Location, Raw, Rewritten, Wire, find_new_match, max_tail_size, needle_prefix_suffix_len,
};

/// Longest CONNECT line a TLS downstream leg buffers before forwarding the
/// rest of that line unchanged.
pub(crate) const MAX_COMMAND: usize = 16 * 1024;

/// The two bytes that must follow every counted payload.
const CRLF: &[u8] = b"\r\n";

/// First INFO `nonce`. Empty is not a value.
#[derive(Debug)]
struct Nonce(String);

impl Nonce {
  fn parse(raw: &str) -> Option<Self> {
    if raw.is_empty() { None } else { Some(Self(raw.to_string())) }
  }

  fn as_bytes(&self) -> &[u8] {
    self.0.as_bytes()
  }
}

/// Nonce captured from the opening INFO. Only [`NonceSlot::Ready`] may sign.
#[derive(Debug)]
enum NonceSlot {
  /// `server_info` has not armed this leg.
  Pending,
  /// The opening INFO had no nonce.
  Absent,
  /// The opening INFO's nonce.
  Ready(Nonce),
}

/// Commands a client sends.
#[derive(Debug, Clone, Copy, EnumIter, EnumString, IntoStaticStr)]
#[strum(serialize_all = "UPPERCASE", ascii_case_insensitive)]
enum ClientVerb {
  Connect,
  Pub,
  Hpub,
  Sub,
  Unsub,
  Ping,
  Pong,
}

impl ClientVerb {
  fn framing(self) -> Framing {
    match self {
      Self::Connect => Framing::Credential,
      Self::Pub | Self::Hpub => Framing::Counted,
      Self::Sub | Self::Unsub | Self::Ping | Self::Pong => Framing::Line,
    }
  }
}

/// Commands a server sends.
#[derive(Debug, Clone, Copy, EnumIter, EnumString, IntoStaticStr)]
#[strum(serialize_all = "UPPERCASE", ascii_case_insensitive)]
enum ServerVerb {
  Info,
  Msg,
  Hmsg,
  #[strum(serialize = "+OK")]
  Ok,
  #[strum(serialize = "-ERR")]
  Err,
  Ping,
  Pong,
}

impl ServerVerb {
  fn framing(self) -> Framing {
    match self {
      Self::Msg | Self::Hmsg => Framing::Counted,
      Self::Info | Self::Ok | Self::Err | Self::Ping | Self::Pong => Framing::Line,
    }
  }
}

/// How the bytes after a verb are cut.
#[derive(Debug, Clone, Copy)]
enum Framing {
  /// CONNECT: one line, held whole so the swap sees every field.
  Credential,
  /// A head line whose last token counts the payload bytes after it.
  Counted,
  /// One line through LF. An unknown verb is a line.
  Line,
}

/// Which verb set a framer reads.
#[derive(Debug, Clone, Copy)]
enum Side {
  Client,
  Server,
}

impl Side {
  fn framing(self, verb: &[u8]) -> Framing {
    let Ok(verb) = std::str::from_utf8(verb) else {
      return Framing::Line;
    };
    match self {
      Self::Client => verb.parse::<ClientVerb>().map_or(Framing::Line, ClientVerb::framing),
      Self::Server => verb.parse::<ServerVerb>().map_or(Framing::Line, ServerVerb::framing),
    }
  }

  fn longest_verb(self) -> usize {
    match self {
      Self::Client => ClientVerb::iter().map(|verb| <&str>::from(verb).len()).max(),
      Self::Server => ServerVerb::iter().map(|verb| <&str>::from(verb).len()).max(),
    }
    .unwrap_or_default()
  }
}

fn is_delimiter(byte: u8) -> bool {
  matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// Nearest space, tab, CR, or LF. `memchr` finds at most three needles, so
/// this is the nearer of two searches and keeps no buffer of its own.
fn delimiter_at(haystack: &[u8]) -> Option<usize> {
  let spaced = memchr::memchr2(b' ', b'\t', haystack);
  let broken = memchr::memchr2(b'\r', b'\n', haystack);
  match (spaced, broken) {
    (Some(left), Some(right)) => Some(left.min(right)),
    (Some(at), None) | (None, Some(at)) => Some(at),
    (None, None) => None,
  }
}

/// Bytes of a leading delimiter run. `memchr` has no search for a byte
/// outside a set, so this walks.
fn leading_delimiters(haystack: &[u8]) -> usize {
  haystack.iter().position(|byte| !is_delimiter(*byte)).unwrap_or(haystack.len())
}

/// The last token of a counted head, read as the line streams.
#[derive(Debug, Default)]
struct TrailingCount {
  token: Token,
  /// The last finished token, `None` when it was not a decimal count.
  last: Option<u64>,
}

#[derive(Debug, Default, Clone, Copy)]
enum Token {
  #[default]
  Between,
  Digits(u64),
  Word,
}

impl TrailingCount {
  fn push_slice(&mut self, bytes: &[u8]) {
    let mut rest = bytes;
    while !rest.is_empty() {
      if rest.first().is_some_and(|byte| is_delimiter(*byte)) {
        self.close_token();
        let skip = leading_delimiters(rest);
        rest = rest.get(skip..).unwrap_or(&[]);
        continue;
      }
      let end = delimiter_at(rest).unwrap_or(rest.len());
      if let Some(token) = rest.get(..end).filter(|token| !token.is_empty()) {
        self.absorb(token);
      }
      let Some(after) = rest.get(end..) else {
        return;
      };
      rest = after;
    }
  }

  fn close_token(&mut self) {
    match self.token {
      Token::Between => {}
      Token::Digits(value) => self.last = Some(value),
      Token::Word => self.last = None,
    }
    self.token = Token::Between;
  }

  /// `token` holds no delimiter. A finished number stays a `u64`; the digits
  /// themselves are the caller's slice.
  fn absorb(&mut self, token: &[u8]) {
    if matches!(self.token, Token::Word) {
      return;
    }
    let (parsed, used) = u64::from_radix_10_checked(token);
    if used != token.len() {
      self.token = Token::Word;
      return;
    }
    let Some(parsed) = parsed else {
      self.token = Token::Word;
      return;
    };
    let prefix = match self.token {
      Token::Digits(value) => value,
      Token::Between => 0,
      Token::Word => return,
    };
    let combined = if prefix == 0 {
      Some(parsed)
    } else {
      u32::try_from(used)
        .ok()
        .and_then(|exp| 10u64.checked_pow(exp))
        .and_then(|scale| prefix.checked_mul(scale).and_then(|scaled| scaled.checked_add(parsed)))
    };
    self.token = match combined {
      Some(value) => Token::Digits(value),
      None => Token::Word,
    };
  }
}

/// Where the framer is inside the current command.
#[derive(Debug)]
enum FramePhase {
  /// Verb bytes before the first delimiter. Never longer than the longest verb.
  Head(Vec<u8>),
  /// The rest of a command line, through LF.
  Line { framing: Framing, count: TrailingCount },
  /// Payload bytes a counted command still owes.
  Body(u64),
  /// The part of the CRLF after a payload not yet seen.
  Trailer(&'static [u8]),
}

/// One cut of the input.
#[derive(Debug)]
enum Piece<'a> {
  /// Command-line bytes. `end` once the LF is included.
  Line { framing: Framing, bytes: Cow<'a, [u8]>, end: bool },
  /// Payload or trailer bytes of a counted command. `end` once the trailer is complete.
  Body { bytes: &'a [u8], end: bool },
}

#[derive(Debug)]
enum Next<'a> {
  Piece(Piece<'a>),
  /// The input is consumed.
  Spent,
  /// A counted head without a count, or a payload not followed by CRLF.
  Malformed,
}

/// NATS framing for one direction. Only the verb is held; lines and payloads
/// are cut out of the caller's input.
#[derive(Debug)]
struct Framer {
  side: Side,
  /// Longest verb `side` knows. A longer head is an unknown verb.
  bound: usize,
  phase: FramePhase,
}

impl Framer {
  fn new(side: Side) -> Self {
    Self {
      side,
      bound: side.longest_verb(),
      phase: FramePhase::Head(Vec::new()),
    }
  }

  /// Cut the next piece off `input`.
  fn next_piece<'a>(&mut self, input: &mut &'a [u8]) -> Next<'a> {
    if input.is_empty() {
      return Next::Spent;
    }
    match std::mem::replace(&mut self.phase, FramePhase::Head(Vec::new())) {
      FramePhase::Head(head) => self.head(head, input),
      FramePhase::Line { framing, count } => self.line(framing, count, input),
      FramePhase::Body(left) => self.body(left, input),
      FramePhase::Trailer(want) => self.trailer(want, input),
    }
  }

  fn head<'a>(&mut self, mut head: Vec<u8>, input: &mut &'a [u8]) -> Next<'a> {
    let room = self.bound.saturating_sub(head.len());
    let window = input.get(..room.saturating_add(1)).unwrap_or(input);
    let delimiter = delimiter_at(window);
    let overflow = delimiter.is_none() && window.len() > room;
    let take = delimiter.unwrap_or_else(|| room.min(input.len()));
    let Some((verb, rest)) = input.split_at_checked(take) else {
      return Next::Malformed;
    };
    head.extend_from_slice(verb);
    *input = rest;
    let framing = if delimiter.is_some() {
      self.side.framing(&head)
    } else if overflow {
      Framing::Line
    } else {
      self.phase = FramePhase::Head(head);
      return Next::Spent;
    };
    self.phase = FramePhase::Line {
      framing,
      count: TrailingCount::default(),
    };
    Next::Piece(Piece::Line {
      framing,
      bytes: Cow::Owned(head),
      end: false,
    })
  }

  fn line<'a>(&mut self, framing: Framing, mut count: TrailingCount, input: &mut &'a [u8]) -> Next<'a> {
    let newline = memchr::memchr(b'\n', input);
    let take = newline.map_or(input.len(), |at| at.saturating_add(1));
    let Some((bytes, rest)) = input.split_at_checked(take) else {
      return Next::Malformed;
    };
    *input = rest;
    if matches!(framing, Framing::Counted) {
      count.push_slice(bytes);
    }
    let end = newline.is_some();
    if !end {
      self.phase = FramePhase::Line { framing, count };
    } else if matches!(framing, Framing::Counted) {
      self.phase = match count.last {
        Some(0) => FramePhase::Trailer(CRLF),
        Some(left) => FramePhase::Body(left),
        None => return Next::Malformed,
      };
    }
    Next::Piece(Piece::Line {
      framing,
      bytes: Cow::Borrowed(bytes),
      end,
    })
  }

  fn body<'a>(&mut self, left: u64, input: &mut &'a [u8]) -> Next<'a> {
    let take = usize::try_from(left).map_or(input.len(), |left| left.min(input.len()));
    let Some((bytes, rest)) = input.split_at_checked(take) else {
      return Next::Malformed;
    };
    let Some(left) = u64::try_from(take).ok().and_then(|took| left.checked_sub(took)) else {
      return Next::Malformed;
    };
    *input = rest;
    self.phase = if left == 0 {
      FramePhase::Trailer(CRLF)
    } else {
      FramePhase::Body(left)
    };
    Next::Piece(Piece::Body { bytes, end: false })
  }

  fn trailer<'a>(&mut self, want: &'static [u8], input: &mut &'a [u8]) -> Next<'a> {
    let take = want.len().min(input.len());
    let (Some((got, rest)), Some((expected, more))) = (input.split_at_checked(take), want.split_at_checked(take)) else {
      return Next::Malformed;
    };
    if got != expected {
      return Next::Malformed;
    }
    *input = rest;
    let end = more.is_empty();
    if !end {
      self.phase = FramePhase::Trailer(more);
    }
    Next::Piece(Piece::Body { bytes: got, end })
  }

  fn at_boundary(&self) -> bool {
    matches!(&self.phase, FramePhase::Head(head) if head.is_empty())
  }

  fn take_head(&mut self) -> Vec<u8> {
    match &mut self.phase {
      FramePhase::Head(head) => std::mem::take(head),
      FramePhase::Line { .. } | FramePhase::Body(_) | FramePhase::Trailer(_) => Vec::new(),
    }
  }
}

/// The leg must close: a malformed frame, or the real value inside a payload.
#[derive(Debug)]
struct CloseLeg;

/// One NATS direction leg.
pub(crate) enum Nats {
  Down(Down),
  Up(Box<Up>),
  /// A leg that closed stays closed.
  Closed,
}

impl Nats {
  /// Guest-to-server leg. `swap` is true only when the server writer is
  /// already TLS. A cleartext server leg keeps the decoy.
  pub(crate) fn downstream(grants: &[Grant], host: &str, port: u16, swap: bool) -> Self {
    let policy = if swap {
      let auths: Vec<SwapGrant> = grants
        .iter()
        .filter_map(|grant| {
          let scope = grant.nats(Some(host), port)?;
          let label = grant.credential()?.label.clone();
          Some(SwapGrant {
            label,
            auth: scope.auth.clone(),
          })
        })
        .collect();
      if auths.is_empty() {
        Policy::Forward
      } else {
        Policy::Swap { auths }
      }
    } else {
      Policy::Forward
    };
    Self::Down(Down {
      framer: Framer::new(Side::Client),
      policy,
      connect: Vec::new(),
      spilling: false,
      nonce: NonceSlot::Pending,
    })
  }

  /// Server-to-guest leg. Lines redact every real auth field. Payloads close on it.
  pub(crate) fn upstream(grants: &[Grant], host: &str, port: u16) -> Self {
    let pairs = upstream_pairs(grants, host, port);
    Self::Up(Box::new(Up {
      framer: Framer::new(Side::Server),
      lines: Raw::from_pairs(pairs.clone()),
      guard: Guard {
        bound: max_tail_size(&pairs),
        pairs,
        held: Vec::new(),
      },
      info: InfoWatch::default(),
    }))
  }

  /// TLS verdict of the INFO line whose LF was just framed, once.
  ///
  /// `None` until that LF, and `None` again after the verdict is taken.
  /// A line that is not INFO does not become ready.
  pub(crate) fn take_info_tls(&mut self) -> Option<InfoVerdict> {
    match self {
      Self::Up(up) => up.info.ready.take(),
      Self::Down(_) | Self::Closed => None,
    }
  }
}

impl Wire for Nats {
  async fn feed<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    let mut hits = Vec::new();
    let result = match self {
      Self::Down(down) => down.feed(chunk, &mut hits),
      Self::Up(up) => up.feed(chunk, &mut hits).await,
      Self::Closed => Err(CloseLeg),
    };
    match result {
      Ok(out) if out.is_empty() => (Rewritten::Hold, hits),
      Ok(out) => (Rewritten::Emit(Cow::Owned(out)), hits),
      Err(CloseLeg) => {
        *self = Self::Closed;
        (Rewritten::Close, hits)
      }
    }
  }
}

/// One NATS grant that covers this endpoint. Several can share a host and port.
#[derive(Debug)]
struct SwapGrant {
  label: String,
  auth: NatsAuth,
}

/// Whether CONNECT carries the real values.
#[derive(Debug)]
enum Policy {
  /// The server leg is cleartext: CONNECT keeps the decoy.
  Forward,
  /// The server leg is TLS. Each grant is tried until one CONNECT matches.
  Swap { auths: Vec<SwapGrant> },
}

impl Policy {
  fn swap(&self, line: &[u8], nonce: &NonceSlot) -> Option<(Vec<u8>, Hit)> {
    let Self::Swap { auths } = self else {
      return None;
    };
    auths.iter().find_map(|grant| {
      let swapped = swap_connect(line, &grant.auth, nonce)?;
      Some((
        swapped,
        Hit {
          label: grant.label.clone(),
          location: Location::Header,
        },
      ))
    })
  }
}

/// Move the first INFO nonce from the server leg onto the client leg.
///
/// A second call keeps the nonce already stored. A leg that is not [`Nats::Up`]
/// yields nothing. A leg that is not [`Nats::Down`] accepts nothing.
pub(crate) fn arm_opening(up: &mut Nats, down: &mut Nats) {
  let Nats::Up(up) = up else {
    return;
  };
  let Nats::Down(down) = down else {
    return;
  };
  if !matches!(down.nonce, NonceSlot::Pending) {
    return;
  }
  down.nonce = match up.info.nonce.take() {
    Some(nonce) => NonceSlot::Ready(nonce),
    None => NonceSlot::Absent,
  };
}

/// Real values to hide from the guest: every mapped auth field whose fake
/// and real differ. An unchanged username is not a needle, so a payload
/// that names it stays open.
fn upstream_pairs(grants: &[Grant], host: &str, port: u16) -> Vec<CredentialPair> {
  let mut pairs = Vec::new();
  for grant in grants {
    let Some(scope) = grant.nats(Some(host), port) else {
      continue;
    };
    let Some(credential) = grant.credential() else {
      continue;
    };
    for (fake, real) in redaction_pairs(&scope.auth) {
      if fake == real || fake.is_empty() || real.is_empty() {
        continue;
      }
      pairs.push(CredentialPair {
        needle: real.into_bytes(),
        replacement: fake.into_bytes(),
        label: credential.label.clone(),
      });
    }
  }
  pairs
}

/// Real values a server line may echo, paired with the decoy. Longer real
/// values come first, so a user JWT is replaced before the public key it
/// contains.
fn redaction_pairs(auth: &NatsAuth) -> Vec<(String, String)> {
  let mut pairs: Vec<(String, String)> = auth
    .fields()
    .into_iter()
    .map(|field| (field.pair.fake.clone(), field.pair.real.expose_secret().to_string()))
    .collect();
  if let Some((fake, real)) = auth.concealed() {
    pairs.push((fake.to_string(), real.to_string()));
  }
  pairs.retain(|(fake, real)| !fake.is_empty() && !real.is_empty() && fake != real);
  pairs.sort_by_key(|pair| std::cmp::Reverse(pair.1.len()));
  pairs
}

/// `line` with the real values, when its JSON parses and every auth field
/// holds the decoy. A method that signs also checks the guest signature and
/// writes a new one. `None` forwards the line unchanged.
fn swap_connect(line: &[u8], auth: &NatsAuth, nonce: &NonceSlot) -> Option<Vec<u8>> {
  let nonce = if auth.signer().is_some() {
    let NonceSlot::Ready(nonce) = nonce else {
      return None;
    };
    Some(nonce.as_bytes())
  } else {
    None
  };
  rewrite_connect(line, |fields| apply_auth(fields, auth, nonce))
}

/// One CONNECT edit for every auth method. Field checks, the signature
/// step, and the value swap share this function.
fn apply_auth(fields: &mut Map<String, Value>, auth: &NatsAuth, nonce: Option<&[u8]>) -> Option<()> {
  let sign = auth.signer().map(|sign| (sign.verify.to_string(), sign.seed.clone()));
  for name in auth.forbidden() {
    if fields.contains_key(name.as_str()) {
      return None;
    }
  }
  let plan = auth.fields();
  for field in &plan {
    match (field.presence, fields.get(field.name.as_str())) {
      (FieldPresence::Required, Some(Value::String(value))) if value == &field.pair.fake => {}
      (FieldPresence::Optional, None) => {}
      (FieldPresence::Optional, Some(Value::String(value))) if value == &field.pair.fake => {}
      _ => return None,
    }
  }
  if let Some((verify, seed)) = sign {
    let nonce = nonce?;
    let sig = fields.get(NatsField::Sig.as_str()).and_then(Value::as_str)?;
    // nats-server 2.15 tries raw URL base64, then standard. nats.js 2.29 signs
    // with `btoa`, which is the standard alphabet. The rewritten `sig` stays raw URL.
    let raw = decode_sig(sig)?;
    if !NatsSeed::verify(&verify, nonce, &raw) {
      return None;
    }
    let signed = seed.sign(nonce)?;
    fields.insert(NatsField::Sig.as_str().to_string(), Value::String(sig_b64(&signed)));
  }
  for field in &plan {
    let key = field.name.as_str();
    if field.presence == FieldPresence::Required || fields.contains_key(key) {
      fields.insert(key.to_string(), Value::String(field.pair.real.expose_secret().to_string()));
    }
  }
  Some(())
}

fn sig_b64(raw: &[u8]) -> String {
  URL_SAFE_NO_PAD.encode(raw)
}

/// Guest `sig` bytes. Raw URL base64 first, then standard base64.
fn decode_sig(sig: &str) -> Option<Vec<u8>> {
  URL_SAFE_NO_PAD.decode(sig).or_else(|_err| STANDARD.decode(sig)).ok()
}

/// One sorted-key re-encode of a CONNECT line. `edit` returns `None` to forward.
fn rewrite_connect(line: &[u8], edit: impl FnOnce(&mut Map<String, Value>) -> Option<()>) -> Option<Vec<u8>> {
  let body = line.strip_suffix(b"\n")?;
  let body = body.strip_suffix(b"\r").unwrap_or(body);
  let ending = line.get(body.len()..)?;
  let verb_end = delimiter_at(body)?;
  let (verb, args) = body.split_at_checked(verb_end)?;
  let json_at = leading_delimiters(args);
  if json_at == args.len() {
    return None;
  }
  let (gap, json) = args.split_at_checked(json_at)?;
  let mut fields: Map<String, Value> = serde_json::from_slice(json).ok()?;
  edit(&mut fields)?;
  // fnox pulls in serde_json `preserve_order` for workspace builds only, so
  // the key order is fixed here instead of depending on feature unification.
  let sorted: BTreeMap<&str, &Value> = fields.iter().map(|(key, value)| (key.as_str(), value)).collect();
  let json = serde_json::to_vec(&sorted).ok()?;
  let mut out = Vec::with_capacity(line.len().saturating_add(json.len()));
  out.extend_from_slice(verb);
  out.extend_from_slice(gap);
  out.extend_from_slice(&json);
  out.extend_from_slice(ending);
  Some(out)
}

/// Guest-to-server state.
#[derive(Debug)]
pub(crate) struct Down {
  framer: Framer,
  policy: Policy,
  /// CONNECT bytes held for a swap. Empty unless [`Policy::Swap`] is still
  /// under [`MAX_COMMAND`].
  connect: Vec<u8>,
  /// This CONNECT line passed the cap. The rest of it is forwarded.
  spilling: bool,
  /// Opening INFO nonce. [`NonceSlot::Pending`] until [`arm_opening`].
  nonce: NonceSlot,
}

impl Down {
  /// Empty input is end of stream: a held verb or a partial CONNECT leaves
  /// unchanged. A partial CONNECT is never swapped.
  fn feed(&mut self, chunk: &[u8], hits: &mut Vec<Hit>) -> Result<Vec<u8>, CloseLeg> {
    if chunk.is_empty() {
      let mut out = std::mem::take(&mut self.connect);
      out.append(&mut self.framer.take_head());
      return Ok(out);
    }
    let mut input = chunk;
    let mut out = Vec::new();
    loop {
      match self.framer.next_piece(&mut input) {
        Next::Spent => return Ok(out),
        Next::Malformed => return Err(CloseLeg),
        Next::Piece(Piece::Line {
          framing: Framing::Credential,
          bytes,
          end,
        }) => self.credential(&bytes, end, &mut out, hits),
        Next::Piece(Piece::Line {
          framing: Framing::Counted | Framing::Line,
          bytes,
          ..
        }) => out.extend_from_slice(&bytes),
        Next::Piece(Piece::Body { bytes, .. }) => out.extend_from_slice(bytes),
      }
    }
  }

  /// One piece of a CONNECT line.
  ///
  /// A cleartext leg forwards the piece. A TLS leg holds it until the line
  /// ends, unless the hold would pass [`MAX_COMMAND`]: then the bytes
  /// already held and the rest of the line go out unchanged.
  fn credential(&mut self, bytes: &[u8], end: bool, out: &mut Vec<u8>, hits: &mut Vec<Hit>) {
    if self.spilling || matches!(self.policy, Policy::Forward) {
      out.extend_from_slice(bytes);
      if end {
        self.spilling = false;
      }
      return;
    }
    if self.connect.len().saturating_add(bytes.len()) > MAX_COMMAND {
      out.append(&mut self.connect);
      out.extend_from_slice(bytes);
      self.spilling = !end;
      return;
    }
    self.connect.extend_from_slice(bytes);
    if end {
      let line = std::mem::take(&mut self.connect);
      match self.policy.swap(&line, &self.nonce) {
        Some((swapped, hit)) => {
          out.extend_from_slice(&swapped);
          hits.push(hit);
        }
        None => out.extend_from_slice(&line),
      }
    }
  }
}

/// TLS flags from one completed INFO object. Absent fields stay false.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct InfoTls {
  /// INFO `tls_required`.
  pub(crate) tls_required: bool,
  /// INFO `tls_available`.
  pub(crate) tls_available: bool,
  /// INFO `tls_verify`.
  pub(crate) tls_verify: bool,
}

/// What a finished INFO line says about TLS on a cleartext upstream.
#[derive(Debug)]
pub(crate) enum InfoVerdict {
  /// The object ended, or `tls_required` was already true.
  Flags(InfoTls),
  /// The object did not end, and `tls_required` was not true.
  Unreadable,
}

/// Which INFO bool a key names.
#[derive(Clone, Copy)]
enum TlsKey {
  Required,
  Available,
  Verify,
}

/// A depth-1 INFO key the parser keeps.
#[derive(Clone, Copy)]
enum InfoKey {
  Tls(TlsKey),
  Nonce,
}

/// actson events for one INFO object.
///
/// `current_buffer` holds the open token and the feeder holds unread input.
/// [`open_len`](Self::open_len) stops that pair at [`MAX_COMMAND`].
struct InfoParse {
  parser: JsonParser<PushJsonFeeder>,
  /// Bytes handed to the feeder.
  fed: usize,
  /// [`JsonParser::parsed_bytes`] at the previous event.
  mark: usize,
  depth: u32,
  key: Option<InfoKey>,
  tls: InfoTls,
  /// First depth-1 `nonce` string. Empty is not stored.
  nonce: Option<Nonce>,
  /// The first `nonce` field was seen, even when its value was empty.
  nonce_seen: bool,
  ended: bool,
  failed: bool,
}

impl InfoParse {
  fn new() -> Self {
    Self {
      parser: JsonParser::new(PushJsonFeeder::new()),
      fed: 0,
      mark: 0,
      depth: 0,
      key: None,
      tls: InfoTls::default(),
      nonce: None,
      nonce_seen: false,
      ended: false,
      failed: false,
    }
  }

  fn push(&mut self, bytes: &[u8]) {
    for &byte in bytes {
      if self.failed {
        return;
      }
      self.drain_while_full();
      if self.failed || self.open_len() >= MAX_COMMAND {
        self.failed = true;
        return;
      }
      if self.parser.feeder.push_byte(byte).is_err() {
        self.failed = true;
        return;
      }
      self.fed = self.fed.saturating_add(1);
    }
  }

  fn drain_while_full(&mut self) {
    while self.parser.feeder.is_full() && !self.failed {
      let before = self.parser.parsed_bytes();
      self.step();
      if self.failed {
        return;
      }
      if self.parser.parsed_bytes() == before && self.parser.feeder.is_full() {
        self.failed = true;
        return;
      }
    }
  }

  fn step(&mut self) {
    match self.parser.next_event() {
      Ok(Some(JsonEvent::NeedMoreInput) | None) => {}
      Ok(Some(event)) => {
        self.mark = self.parser.parsed_bytes();
        self.on_event(event);
      }
      Err(_) => self.failed = true,
    }
  }

  fn finish(mut self) -> (InfoVerdict, Option<Nonce>) {
    if !self.failed {
      self.parser.feeder.done();
      loop {
        match self.parser.next_event() {
          Ok(None) => break,
          Ok(Some(JsonEvent::NeedMoreInput)) | Err(_) => {
            self.failed = true;
            break;
          }
          Ok(Some(event)) => {
            self.mark = self.parser.parsed_bytes();
            self.on_event(event);
            if self.failed {
              break;
            }
          }
        }
      }
    }
    let verdict = if self.tls.tls_required || self.ended {
      InfoVerdict::Flags(self.tls)
    } else {
      InfoVerdict::Unreadable
    };
    let nonce = if self.failed { None } else { self.nonce };
    (verdict, nonce)
  }

  /// Parsed bytes of the open token, plus bytes still sitting in the feeder.
  fn open_len(&self) -> usize {
    let parsed = self.parser.parsed_bytes();
    let queued = self.fed.saturating_sub(parsed);
    parsed.saturating_sub(self.mark).saturating_add(queued)
  }

  fn on_event(&mut self, event: JsonEvent) {
    match event {
      JsonEvent::StartObject | JsonEvent::StartArray => {
        self.depth = self.depth.saturating_add(1);
      }
      JsonEvent::EndObject | JsonEvent::EndArray => {
        self.depth = self.depth.saturating_sub(1);
        if self.depth == 0 && matches!(event, JsonEvent::EndObject) {
          self.ended = true;
        }
      }
      JsonEvent::FieldName => self.note_name(),
      JsonEvent::ValueTrue | JsonEvent::ValueFalse => self.note_bool(matches!(event, JsonEvent::ValueTrue)),
      JsonEvent::ValueString => self.note_string(),
      JsonEvent::ValueInt | JsonEvent::ValueFloat | JsonEvent::ValueNull => self.key = None,
      JsonEvent::NeedMoreInput => {}
    }
  }

  fn note_name(&mut self) {
    if self.depth != 1 {
      self.key = None;
      return;
    }
    match self.parser.current_str() {
      Ok(name) if name.len() > MAX_COMMAND => {
        self.failed = true;
        self.key = None;
      }
      Ok(name) => self.key = info_key(name.as_bytes()),
      Err(_) => {
        self.failed = true;
        self.key = None;
      }
    }
  }

  fn note_bool(&mut self, value: bool) {
    if self.depth == 1
      && let Some(InfoKey::Tls(key)) = self.key
    {
      match key {
        TlsKey::Required => self.tls.tls_required = value,
        TlsKey::Available => self.tls.tls_available = value,
        TlsKey::Verify => self.tls.tls_verify = value,
      }
    }
    self.key = None;
  }

  fn note_string(&mut self) {
    let text = match self.parser.current_str() {
      Ok(text) if text.len() > MAX_COMMAND => {
        self.failed = true;
        self.key = None;
        return;
      }
      Ok(text) => text,
      Err(_) => {
        self.failed = true;
        self.key = None;
        return;
      }
    };
    if self.depth == 1 && matches!(self.key, Some(InfoKey::Nonce)) && !self.nonce_seen {
      self.nonce_seen = true;
      if !self.failed {
        self.nonce = Nonce::parse(text);
      }
    }
    self.key = None;
  }
}

fn info_key(raw: &[u8]) -> Option<InfoKey> {
  match raw {
    b"tls_required" => Some(InfoKey::Tls(TlsKey::Required)),
    b"tls_available" => Some(InfoKey::Tls(TlsKey::Available)),
    b"tls_verify" => Some(InfoKey::Tls(TlsKey::Verify)),
    b"nonce" => Some(InfoKey::Nonce),
    _ => None,
  }
}

/// Server verb plus the TLS verdict of an INFO line in progress.
struct InfoWatch {
  /// The next line piece is a verb.
  expect_verb: bool,
  /// This command is INFO and its LF has not arrived.
  active: bool,
  /// Set when an INFO line reaches LF. Taken once.
  ready: Option<InfoVerdict>,
  parse: Option<InfoParse>,
  /// Nonce from the first INFO line that reached LF.
  nonce: Option<Nonce>,
  /// That first INFO line has been committed.
  opening_done: bool,
}

impl Default for InfoWatch {
  fn default() -> Self {
    Self {
      expect_verb: true,
      active: false,
      ready: None,
      parse: None,
      nonce: None,
      opening_done: false,
    }
  }
}

impl InfoWatch {
  fn note(&mut self, bytes: &[u8], end: bool) {
    if self.expect_verb {
      self.expect_verb = false;
      self.active = is_info_verb(bytes);
      if self.active {
        self.parse = Some(InfoParse::new());
      }
    } else if self.active
      && let Some(parse) = self.parse.as_mut()
    {
      parse.push(bytes);
    }
    if end {
      if self.active && self.ready.is_none() {
        let (verdict, nonce) = match self.parse.take() {
          Some(parse) => parse.finish(),
          None => (InfoVerdict::Unreadable, None),
        };
        self.ready = Some(verdict);
        if !self.opening_done {
          self.nonce = nonce;
          self.opening_done = true;
        }
      }
      self.active = false;
      self.parse = None;
      self.expect_verb = true;
    }
  }
}

fn is_info_verb(bytes: &[u8]) -> bool {
  let Ok(text) = std::str::from_utf8(bytes) else {
    return false;
  };
  matches!(text.parse::<ServerVerb>(), Ok(ServerVerb::Info))
}

/// Server-to-guest state.
pub(crate) struct Up {
  framer: Framer,
  /// Delimited lines, flushed at each LF.
  lines: Raw,
  /// Counted heads and payloads.
  guard: Guard,
  /// TLS flags from the INFO line, filled as its pieces arrive.
  info: InfoWatch,
}

impl Up {
  /// Empty input is end of stream: nothing is held at a frame boundary, and
  /// a stream that ends mid-frame closes.
  async fn feed(&mut self, chunk: &[u8], hits: &mut Vec<Hit>) -> Result<Vec<u8>, CloseLeg> {
    if chunk.is_empty() {
      return if self.framer.at_boundary() { Ok(Vec::new()) } else { Err(CloseLeg) };
    }
    let mut input = chunk;
    let mut out = Vec::new();
    loop {
      match self.framer.next_piece(&mut input) {
        Next::Spent => return Ok(out),
        Next::Malformed => return Err(CloseLeg),
        Next::Piece(Piece::Line { framing, bytes, end }) => {
          self.info.note(&bytes, end);
          match framing {
            Framing::Counted => self.guard.push(&bytes, &mut out)?,
            Framing::Line | Framing::Credential => {
              if !bytes.is_empty() {
                redact(&mut self.lines, &bytes, &mut out, hits).await?;
              }
              if end {
                redact(&mut self.lines, &[], &mut out, hits).await?;
              }
            }
          }
        }
        Next::Piece(Piece::Body { bytes, end }) => {
          self.guard.push(bytes, &mut out)?;
          if end {
            self.guard.release(&mut out);
          }
        }
      }
    }
  }
}

/// Feed one line piece through the redactor. Empty `bytes` flushes it.
async fn redact(lines: &mut Raw, bytes: &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Result<(), CloseLeg> {
  let (rewritten, found) = lines.feed(bytes).await;
  hits.extend(found);
  match rewritten {
    Rewritten::Emit(emitted) => {
      out.extend_from_slice(&emitted);
      Ok(())
    }
    Rewritten::Hold => Ok(()),
    Rewritten::Close => Err(CloseLeg),
  }
}

/// Needle scan over counted bytes. A payload is the publisher's data, so it
/// is never rewritten: the real value there closes the leg.
struct Guard {
  pairs: Vec<CredentialPair>,
  bound: usize,
  /// Suffix that could still grow into a real value.
  held: Vec<u8>,
}

impl Guard {
  fn push(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), CloseLeg> {
    if data.is_empty() {
      return Ok(());
    }
    let mut combined = std::mem::take(&mut self.held);
    combined.extend_from_slice(data);
    if self.pairs.iter().any(|pair| find_new_match(&combined, &pair.needle, 0)) {
      return Err(CloseLeg);
    }
    let hold = needle_prefix_suffix_len(&combined, &self.pairs, self.bound);
    let emit = combined.len().saturating_sub(hold);
    self.held = combined.split_off(emit);
    out.append(&mut combined);
    Ok(())
  }

  /// The frame ended, so its held suffix cannot grow.
  fn release(&mut self, out: &mut Vec<u8>) {
    out.append(&mut self.held);
  }
}

#[cfg(test)]
mod tests {
  use arkham_config::grants::Grant;
  use pretty_assertions::assert_eq;

  use strum::IntoEnumIterator as _;

  use super::{ClientVerb, MAX_COMMAND, Nats, ServerVerb};
  use crate::transports::engine::{Rewritten, Wire};
  use crate::transports::nats::fixtures::{mint_user, nats_grants};

  const FAKE_PASS: &str = "arkham_fake_nats_pass"; // betterleaks:allow
  const REAL_PASS: &str = "real-nats-pass-is-longer"; // betterleaks:allow
  const FAKE_TOKEN: &str = "arkham_fake_nats_token"; // betterleaks:allow
  const REAL_TOKEN: &str = "real-nats-token"; // betterleaks:allow

  /// The verb tables are the protocol message list.
  /// <https://docs.nats.io/reference/reference-protocols/nats-protocol>
  /// says operation names are case insensitive.
  #[test]
  fn verbs_match_the_protocol_spec() {
    let client: Vec<&str> = ClientVerb::iter().map(<&str>::from).collect();
    assert_eq!(client, ["CONNECT", "PUB", "HPUB", "SUB", "UNSUB", "PING", "PONG"]);
    let server: Vec<&str> = ServerVerb::iter().map(<&str>::from).collect();
    assert_eq!(server, ["INFO", "MSG", "HMSG", "+OK", "-ERR", "PING", "PONG"]);
    assert!(matches!("connect".parse::<ClientVerb>(), Ok(ClientVerb::Connect)));
    assert!(matches!("hmsg".parse::<ServerVerb>(), Ok(ServerVerb::Hmsg)));
  }

  fn user_pass() -> Vec<Grant> {
    nats_grants(
      &format!("nats://agent:{FAKE_PASS}@nats.internal:4222"),
      &format!("tls://agent:{REAL_PASS}@nats.upstream:4222"),
    )
  }

  fn token() -> Vec<Grant> {
    nats_grants(
      &format!("nats://{FAKE_TOKEN}@nats.internal:4222"),
      &format!("tls://{REAL_TOKEN}@nats.upstream:4222"),
    )
  }

  fn down(grants: &[Grant], swap: bool) -> Nats {
    Nats::downstream(grants, "nats.internal", 4222, swap)
  }

  fn up(grants: &[Grant]) -> Nats {
    Nats::upstream(grants, "nats.internal", 4222)
  }

  #[derive(Debug, PartialEq, Eq)]
  enum Out {
    Emit(String),
    Hold,
    Close,
  }

  /// One feed, as the relay sees it: what reaches the peer and how many hits.
  async fn feed(machine: &mut Nats, chunk: &[u8]) -> (Out, usize) {
    let (rewritten, hits) = machine.feed(chunk).await;
    let out = match rewritten {
      Rewritten::Emit(bytes) => Out::Emit(String::from_utf8_lossy(&bytes).into_owned()),
      Rewritten::Hold => Out::Hold,
      Rewritten::Close => Out::Close,
    };
    (out, hits.len())
  }

  fn emit(text: &str) -> Out {
    Out::Emit(text.to_string())
  }

  fn user_connect(user: &str, pass: &str) -> String {
    format!("CONNECT {{\"verbose\":false,\"user\":\"{user}\",\"pass\":\"{pass}\",\"name\":\"agent-app\"}}\r\n")
  }

  #[tokio::test]
  async fn cleartext_upstream_forwards_the_decoy_connect() {
    let grants = user_pass();
    let mut machine = down(&grants, false);
    let connect = user_connect("agent", FAKE_PASS);
    assert_eq!(feed(&mut machine, connect.as_bytes()).await, (emit(&connect), 0));
  }

  #[tokio::test]
  async fn tls_upstream_swaps_user_and_pass_in_connect() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    let input = format!("{}PING\r\n", user_connect("agent", FAKE_PASS));
    let swapped = format!("CONNECT {{\"name\":\"agent-app\",\"pass\":\"{REAL_PASS}\",\"user\":\"agent\",\"verbose\":false}}\r\nPING\r\n");
    assert_eq!(feed(&mut machine, input.as_bytes()).await, (emit(&swapped), 1));
  }

  #[tokio::test]
  async fn tls_upstream_swaps_the_auth_token_with_a_lowercase_verb() {
    let grants = token();
    let mut machine = down(&grants, true);
    let input = format!("connect {{\"auth_token\":\"{FAKE_TOKEN}\",\"jwt\":\"eyJ0\",\"sig\":\"c2ln\"}}\r\n");
    let swapped = format!("connect {{\"auth_token\":\"{REAL_TOKEN}\",\"jwt\":\"eyJ0\",\"sig\":\"c2ln\"}}\r\n");
    assert_eq!(feed(&mut machine, input.as_bytes()).await, (emit(&swapped), 1));
  }

  #[tokio::test]
  async fn connect_swaps_only_when_every_auth_field_is_the_decoy() {
    let grants = user_pass();
    for connect in [
      user_connect("someone-else", FAKE_PASS),
      format!("CONNECT {{\"user\":\"agent\",\"pass\":\"typed\",\"name\":\"{FAKE_PASS}\"}}\r\n"),
      format!("CONNECT {{\"user\":\"agent\",\"pass\":\"{FAKE_PASS}\"\r\n"),
    ] {
      let mut machine = down(&grants, true);
      assert_eq!(feed(&mut machine, connect.as_bytes()).await, (emit(&connect), 0), "{connect}");
    }
  }

  #[tokio::test]
  async fn partial_connect_at_eof_is_forwarded_unswapped() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    let partial = format!("CONNECT {{\"user\":\"agent\",\"pass\":\"{FAKE_PASS}\"}}");
    assert_eq!(feed(&mut machine, partial.as_bytes()).await, (Out::Hold, 0));
    assert_eq!(feed(&mut machine, &[]).await, (emit(&partial), 0));
  }

  #[tokio::test]
  async fn pub_payload_streams_without_a_swap() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    let payload = user_connect("agent", FAKE_PASS);
    let payload = payload.trim_end();
    let head = format!("PUB orders {}\r\n", payload.len());
    let (first, rest) = payload.split_at(20);
    assert_eq!(
      feed(&mut machine, format!("{head}{first}").as_bytes()).await,
      (emit(&format!("{head}{first}")), 0)
    );
    assert_eq!(
      feed(&mut machine, format!("{rest}\r\n").as_bytes()).await,
      (emit(&format!("{rest}\r\n")), 0)
    );
    let hpub = format!("HPUB orders 12 14\r\nNATS/1.0\r\n\r\nhi\r\n{}", user_connect("agent", FAKE_PASS));
    let swapped = format!(
      "HPUB orders 12 14\r\nNATS/1.0\r\n\r\nhi\r\nCONNECT {{\"name\":\"agent-app\",\"pass\":\"{REAL_PASS}\",\"user\":\"agent\",\"verbose\":false}}\r\n"
    );
    assert_eq!(feed(&mut machine, hpub.as_bytes()).await, (emit(&swapped), 1));
  }

  #[tokio::test]
  async fn message_holding_the_real_password_closes_the_server_leg() {
    let grants = user_pass();
    let mut machine = up(&grants);
    let head = format!("MSG orders 1 {}\r\n", REAL_PASS.len());
    let (first, rest) = REAL_PASS.split_at(9);
    assert_eq!(feed(&mut machine, format!("{head}{first}").as_bytes()).await, (emit(&head), 0));
    assert_eq!(feed(&mut machine, format!("{rest}\r\n").as_bytes()).await, (Out::Close, 0));
    assert_eq!(feed(&mut machine, b"PING\r\n").await, (Out::Close, 0));
    let mut machine = up(&grants);
    let hmsg = format!("HMSG orders 1 12 {}\r\nNATS/1.0\r\n\r\n{REAL_PASS}\r\n", 12 + REAL_PASS.len());
    assert_eq!(feed(&mut machine, hmsg.as_bytes()).await, (Out::Close, 0));
  }

  #[tokio::test]
  async fn real_username_is_redacted_on_lines_and_closes_a_payload() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222", // betterleaks:allow
      "tls://real-nats-user:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let mut machine = up(&grants);
    let err = "-ERR 'user real-nats-user'\r\n";
    assert_eq!(feed(&mut machine, err.as_bytes()).await, (emit("-ERR 'user agent'\r\n"), 1));
    let mut machine = up(&grants);
    let body = "real-nats-user";
    let msg = format!("MSG orders 1 {}\r\n{body}\r\n", body.len());
    assert_eq!(feed(&mut machine, msg.as_bytes()).await, (Out::Close, 0));
    let mut machine = up(&user_pass());
    let same = format!("MSG orders 1 {}\r\nagent\r\n", "agent".len());
    assert_eq!(feed(&mut machine, same.as_bytes()).await, (emit(&same), 0));
  }

  #[tokio::test]
  async fn server_lines_redact_the_real_password_and_messages_pass() {
    let grants = user_pass();
    let mut machine = up(&grants);
    let info = "INFO {\"server_id\":\"N1\",\"tls_required\":true}\r\n";
    assert_eq!(feed(&mut machine, info.as_bytes()).await, (emit(info), 0));
    let err = format!("-ERR 'bad pass {REAL_PASS}'\r\n");
    assert_eq!(
      feed(&mut machine, err.as_bytes()).await,
      (emit(&format!("-ERR 'bad pass {FAKE_PASS}'\r\n")), 1)
    );
    let msg = format!("MSG orders 1 {}\r\n{FAKE_PASS}\r\n+OK\r\n", FAKE_PASS.len());
    assert_eq!(feed(&mut machine, msg.as_bytes()).await, (emit(&msg), 0));
  }

  #[tokio::test]
  async fn eof_flushes_a_held_head_downstream_and_closes_mid_frame_upstream() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    assert_eq!(feed(&mut machine, b"PU").await, (Out::Hold, 0));
    assert_eq!(feed(&mut machine, &[]).await, (emit("PU"), 0));
    let mut machine = up(&grants);
    assert_eq!(feed(&mut machine, b"+OK\r\n").await, (emit("+OK\r\n"), 0));
    assert_eq!(feed(&mut machine, &[]).await, (Out::Hold, 0));
    let mut machine = up(&grants);
    assert_eq!(feed(&mut machine, b"MSG orders 1 5\r\nhe").await, (emit("MSG orders 1 5\r\nhe"), 0));
    assert_eq!(feed(&mut machine, &[]).await, (Out::Close, 0));
  }

  #[tokio::test]
  async fn counted_body_not_followed_by_crlf_closes() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    let smuggled = format!("PUB orders 2\r\n{}", user_connect("agent", FAKE_PASS));
    assert_eq!(feed(&mut machine, smuggled.as_bytes()).await, (Out::Close, 0));
    let mut machine = up(&grants);
    assert_eq!(feed(&mut machine, b"MSG orders 1 2\r\nokXX").await, (Out::Close, 0));
    let mut machine = down(&grants, true);
    assert_eq!(feed(&mut machine, b"PUB orders\r\n").await, (Out::Close, 0));
  }

  #[tokio::test]
  async fn connect_longer_than_the_cap_is_forwarded() {
    let grants = user_pass();
    let name = "a".repeat(MAX_COMMAND);
    let line = format!("CONNECT {{\"user\":\"agent\",\"pass\":\"{FAKE_PASS}\",\"name\":\"{name}\"}}\r\n");
    let follow = user_connect("agent", FAKE_PASS);
    let swapped = format!("CONNECT {{\"name\":\"agent-app\",\"pass\":\"{REAL_PASS}\",\"user\":\"agent\",\"verbose\":false}}\r\n");
    let input = format!("{line}{follow}");
    let mut machine = down(&grants, true);
    assert_eq!(feed(&mut machine, input.as_bytes()).await, (emit(&format!("{line}{swapped}")), 1));
    let (head, tail) = line.split_at(32);
    let mut machine = down(&grants, true);
    assert_eq!(feed(&mut machine, head.as_bytes()).await, (Out::Hold, 0));
    assert_eq!(
      feed(&mut machine, format!("{tail}{follow}").as_bytes()).await,
      (emit(&format!("{line}{swapped}")), 1)
    );
  }

  #[tokio::test]
  async fn oversize_connect_one_byte_at_a_time_is_forwarded() {
    let grants = user_pass();
    let name = "a".repeat(MAX_COMMAND);
    let line = format!("CONNECT {{\"user\":\"agent\",\"pass\":\"{FAKE_PASS}\",\"name\":\"{name}\"}}\r\n");
    let follow = user_connect("agent", FAKE_PASS);
    let swapped = format!("CONNECT {{\"name\":\"agent-app\",\"pass\":\"{REAL_PASS}\",\"user\":\"agent\",\"verbose\":false}}\r\n");
    let input = format!("{line}{follow}");
    let mut machine = down(&grants, true);
    let mut out = String::new();
    let mut hits = 0usize;
    for byte in input.bytes() {
      let (got, found) = feed(&mut machine, &[byte]).await;
      assert_ne!(got, Out::Close);
      hits = hits.saturating_add(found);
      if let Out::Emit(emitted) = got {
        out.push_str(&emitted);
      }
    }
    let (tail, found) = feed(&mut machine, &[]).await;
    assert_ne!(tail, Out::Close);
    hits = hits.saturating_add(found);
    if let Out::Emit(emitted) = tail {
      out.push_str(&emitted);
    }
    assert_eq!(hits, 1);
    assert_eq!(out, format!("{line}{swapped}"));
  }

  #[tokio::test]
  async fn cleartext_connect_streams_without_buffering() {
    let grants = user_pass();
    let mut machine = down(&grants, false);
    let partial = format!("CONNECT {{\"pass\":\"{FAKE_PASS}\"");
    assert_eq!(feed(&mut machine, partial.as_bytes()).await, (emit(&partial), 0));
    let mut machine = down(&grants, false);
    let huge = format!("CONNECT {{\"name\":\"{}\"", "a".repeat(MAX_COMMAND));
    assert_eq!(feed(&mut machine, huge.as_bytes()).await, (emit(&huge), 0));
  }

  use arkham_config::grants::NatsSeed;
  use base64::Engine as _;

  struct Minted {
    raw: String,
    seed: NatsSeed,
  }

  fn minted() -> Minted {
    let (raw, seed) = mint_user();
    Minted { raw, seed }
  }

  fn b64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
  }

  fn user_jwt(public: &str) -> String {
    let header = b64(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let payload = b64(format!(r#"{{"sub":"{public}"}}"#).as_bytes());
    format!("{header}.{payload}.{}", b64(b"sig"))
  }

  fn sig_of(seed: &NatsSeed, nonce: &[u8]) -> String {
    b64(&seed.sign(nonce).expect("seed signs"))
  }

  fn nkey_grants(fake: &Minted, real: &Minted) -> Vec<Grant> {
    nats_grants(
      &format!("nats://nkey:{}@nats.internal:4222", fake.raw),
      &format!("tls://nkey:{}@nats.upstream:4222", real.raw),
    )
  }

  fn jwt_grants(fake: &Minted, real: &Minted, fake_jwt: &str, real_jwt: &str) -> Vec<Grant> {
    nats_grants(
      &format!("nats://creds:{}:{fake_jwt}@nats.internal:4222", fake.raw),
      &format!("tls://creds:{}:{real_jwt}@nats.upstream:4222", real.raw),
    )
  }

  fn nkey_line(public: &str, sig: &str) -> String {
    format!("CONNECT {{\"nkey\":\"{public}\",\"sig\":\"{sig}\",\"verbose\":false}}\r\n")
  }

  fn jwt_line(jwt: &str, sig: &str) -> String {
    format!("CONNECT {{\"jwt\":\"{jwt}\",\"sig\":\"{sig}\",\"verbose\":false}}\r\n")
  }

  fn text_of(out: Out) -> String {
    let Out::Emit(text) = out else {
      panic!("expected the line, got {out:?}");
    };
    text
  }

  async fn arm_info(up: &mut Nats, down: &mut Nats, info: &str) {
    let (out, hits) = feed(up, info.as_bytes()).await;
    assert_eq!(hits, 0);
    assert!(matches!(out, Out::Emit(_)), "{out:?}");
    super::arm_opening(up, down);
  }

  fn assert_original(out: &str, original: &str, real_public: &str, real_sig: &str) {
    assert_eq!(out, original);
    assert!(!out.contains(real_public), "{out}");
    assert!(!out.contains(real_sig), "{out}");
  }

  #[tokio::test]
  async fn present_non_string_nkey_is_left_unchanged() {
    let fake = minted();
    let real = minted();
    let fake_jwt = user_jwt(fake.seed.public_key());
    let real_jwt = user_jwt(real.seed.public_key());
    let grants = jwt_grants(&fake, &real, &fake_jwt, &real_jwt);
    let nonce = b"N0NCE";
    let sig = sig_of(&fake.seed, nonce);
    for nkey in ["null", "1", "{}"] {
      let line = format!("CONNECT {{\"jwt\":\"{fake_jwt}\",\"nkey\":{nkey},\"sig\":\"{sig}\"}}\r\n");
      let mut down = down(&grants, true);
      let mut up = up(&grants);
      arm_info(&mut up, &mut down, "INFO {\"nonce\":\"N0NCE\"}\r\n").await;
      let (out, hits) = feed(&mut down, line.as_bytes()).await;
      assert_eq!(hits, 0, "{nkey}");
      assert_eq!(text_of(out), line, "{nkey}");
    }
    let line = format!("CONNECT {{\"jwt\":\"{fake_jwt}\",\"sig\":\"{sig}\"}}\r\n");
    let mut down = down(&grants, true);
    let mut up = up(&grants);
    arm_info(&mut up, &mut down, "INFO {\"nonce\":\"N0NCE\"}\r\n").await;
    let (out, hits) = feed(&mut down, line.as_bytes()).await;
    assert_eq!(hits, 1);
    assert!(text_of(out).contains(real_jwt.as_str()));
  }

  /// A password grant and an nkey grant can share one host and port. The
  /// CONNECT fields pick the grant. The password grant is first here, which
  /// is the integration file order.
  #[tokio::test]
  async fn nkey_connect_swaps_when_a_password_grant_is_first() {
    let fake = minted();
    let real = minted();
    let mut grants = user_pass();
    grants.extend(nkey_grants(&fake, &real));
    let nonce = b"N0NCE";
    let mut guest_down = down(&grants, true);
    let mut guest_up = up(&grants);
    arm_info(&mut guest_up, &mut guest_down, "INFO {\"nonce\":\"N0NCE\"}\r\n").await;
    let line = nkey_line(fake.seed.public_key(), &sig_of(&fake.seed, nonce));
    let (out, hits) = feed(&mut guest_down, line.as_bytes()).await;
    let out = text_of(out);
    assert_eq!(hits, 1, "{out}");
    let value: serde_json::Value = serde_json::from_str(out.trim().strip_prefix("CONNECT").expect("verb")).expect("json");
    assert_eq!(value.get("nkey").and_then(serde_json::Value::as_str), Some(real.seed.public_key()));
    let sig = value.get("sig").and_then(serde_json::Value::as_str).expect("sig");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig).expect("sig bytes");
    assert!(NatsSeed::verify(real.seed.public_key(), nonce, &raw));
    assert!(!out.contains(fake.seed.public_key()), "{out}");
    let mut pass_down = down(&grants, true);
    let input = user_connect("agent", FAKE_PASS);
    let swapped = format!("CONNECT {{\"name\":\"agent-app\",\"pass\":\"{REAL_PASS}\",\"user\":\"agent\",\"verbose\":false}}\r\n");
    assert_eq!(feed(&mut pass_down, input.as_bytes()).await, (emit(&swapped), 1));
  }

  #[tokio::test]
  async fn ready_nonce_swaps_a_verifying_nkey_connect() {
    let fake = minted();
    let real = minted();
    let grants = nkey_grants(&fake, &real);
    let nonce = b"N0NCE";
    let mut down = down(&grants, true);
    let mut up = up(&grants);
    arm_info(&mut up, &mut down, "INFO {\"nonce\":\"N0NCE\",\"server_id\":\"N1\"}\r\n").await;
    arm_info(&mut up, &mut down, "INFO {\"nonce\":\"OTHER\"}\r\n").await;
    let line = nkey_line(fake.seed.public_key(), &sig_of(&fake.seed, nonce));
    let (out, hits) = feed(&mut down, line.as_bytes()).await;
    let out = text_of(out);
    assert_eq!(hits, 1);
    let value: serde_json::Value = serde_json::from_str(out.trim().strip_prefix("CONNECT").expect("verb")).expect("json");
    assert_eq!(value.get("nkey").and_then(serde_json::Value::as_str), Some(real.seed.public_key()));
    let sig = value.get("sig").and_then(serde_json::Value::as_str).expect("sig");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig).expect("sig bytes");
    assert!(NatsSeed::verify(real.seed.public_key(), nonce, &raw));
    assert!(!NatsSeed::verify(real.seed.public_key(), b"OTHER", &raw));
    assert!(!out.contains(fake.seed.public_key()), "{out}");
    assert!(!out.contains(&fake.raw), "{out}");
    assert!(!out.contains(&real.raw), "{out}");
  }

  /// `nkeyAuthenticator` in nats.js 2.29.3 encodes `sig` with standard base64.
  #[tokio::test]
  async fn standard_base64_sig_still_swaps_a_verifying_nkey() {
    let fake = minted();
    let real = minted();
    let grants = nkey_grants(&fake, &real);
    let nonce = b"N0NCE";
    let mut guest_down = down(&grants, true);
    let mut guest_up = up(&grants);
    arm_info(&mut guest_up, &mut guest_down, "INFO {\"nonce\":\"N0NCE\"}\r\n").await;
    let raw = fake.seed.sign(nonce).expect("fake seed signs");
    let sig = base64::engine::general_purpose::STANDARD.encode(&raw);
    assert!(sig.ends_with('='), "standard base64 of a 64-byte signature is padded");
    let line = nkey_line(fake.seed.public_key(), &sig);
    let (out, hits) = feed(&mut guest_down, line.as_bytes()).await;
    let out = text_of(out);
    assert_eq!(hits, 1, "{out}");
    let value: serde_json::Value = serde_json::from_str(out.trim().strip_prefix("CONNECT").expect("verb")).expect("json");
    assert_eq!(value.get("nkey").and_then(serde_json::Value::as_str), Some(real.seed.public_key()));
    let swapped = value.get("sig").and_then(serde_json::Value::as_str).expect("sig");
    assert!(
      !swapped.contains('=') && !swapped.contains('+') && !swapped.contains('/'),
      "{swapped}"
    );
    let swapped_raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(swapped).expect("sig bytes");
    assert!(NatsSeed::verify(real.seed.public_key(), nonce, &swapped_raw));
  }

  #[tokio::test]
  async fn bad_sig_pending_and_absent_forward_the_nkey_line() {
    let fake = minted();
    let real = minted();
    let grants = nkey_grants(&fake, &real);
    let nonce = b"N0NCE";
    let good = sig_of(&fake.seed, nonce);
    let bad = sig_of(&fake.seed, b"OTHER");
    let real_sig = sig_of(&real.seed, nonce);
    let cases = [
      nkey_line(fake.seed.public_key(), &bad),
      format!("CONNECT {{\"nkey\":\"{}\",\"verbose\":false}}\r\n", fake.seed.public_key()),
      nkey_line("not-the-fake-public", &good),
    ];
    for line in cases {
      let mut down = down(&grants, true);
      let mut up = up(&grants);
      arm_info(&mut up, &mut down, "INFO {\"nonce\":\"N0NCE\"}\r\n").await;
      let (out, hits) = feed(&mut down, line.as_bytes()).await;
      assert_eq!(hits, 0, "{line}");
      assert_original(&text_of(out), &line, real.seed.public_key(), &real_sig);
    }
    let line = nkey_line(fake.seed.public_key(), &good);
    let mut pending = down(&grants, true);
    let (out, hits) = feed(&mut pending, line.as_bytes()).await;
    assert_eq!(hits, 0);
    assert_original(&text_of(out), &line, real.seed.public_key(), &real_sig);
    let mut absent_down = down(&grants, true);
    let mut absent_up = up(&grants);
    arm_info(&mut absent_up, &mut absent_down, "INFO {\"server_id\":\"N1\"}\r\n").await;
    let (out, hits) = feed(&mut absent_down, line.as_bytes()).await;
    assert_eq!(hits, 0);
    assert_original(&text_of(out), &line, real.seed.public_key(), &real_sig);
  }

  /// `jwtAuthenticator` and `credsAuthenticator` in nats.js 2.29.3 return
  /// `{jwt, nkey, sig}`. A `nkey` equal to the decoy public key is rewritten
  /// to the real public key. A foreign `nkey` is forwarded with the line.
  #[tokio::test]
  async fn user_jwt_swaps_a_matching_nkey_and_forwards_a_foreign_one() {
    let fake = minted();
    let real = minted();
    let fake_jwt = user_jwt(fake.seed.public_key());
    let real_jwt = user_jwt(real.seed.public_key());
    let grants = jwt_grants(&fake, &real, &fake_jwt, &real_jwt);
    let nonce = b"N0NCE";
    let mut guest_down = down(&grants, true);
    let mut guest_up = up(&grants);
    arm_info(&mut guest_up, &mut guest_down, "INFO {\"nonce\":\"N0NCE\"}\r\n").await;
    let line = jwt_line(&fake_jwt, &sig_of(&fake.seed, nonce));
    let (out, hits) = feed(&mut guest_down, line.as_bytes()).await;
    let out = text_of(out);
    assert_eq!(hits, 1);
    let value: serde_json::Value = serde_json::from_str(out.trim().strip_prefix("CONNECT").expect("verb")).expect("json");
    assert_eq!(value.get("jwt").and_then(serde_json::Value::as_str), Some(real_jwt.as_str()));
    assert!(value.get("nkey").is_none());
    let sig = value.get("sig").and_then(serde_json::Value::as_str).expect("sig");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig).expect("sig bytes");
    assert!(NatsSeed::verify(real.seed.public_key(), nonce, &raw));
    assert!(!out.contains(&fake_jwt), "{out}");
    let matching = format!(
      "CONNECT {{\"jwt\":\"{fake_jwt}\",\"nkey\":\"{}\",\"sig\":\"{}\",\"verbose\":false}}\r\n",
      fake.seed.public_key(),
      sig_of(&fake.seed, nonce)
    );
    let mut matching_down = down(&grants, true);
    let mut matching_up = up(&grants);
    arm_info(&mut matching_up, &mut matching_down, "INFO {\"nonce\":\"N0NCE\"}\r\n").await;
    let (out, hits) = feed(&mut matching_down, matching.as_bytes()).await;
    let out = text_of(out);
    assert_eq!(hits, 1, "{out}");
    let value: serde_json::Value = serde_json::from_str(out.trim().strip_prefix("CONNECT").expect("verb")).expect("json");
    assert_eq!(value.get("jwt").and_then(serde_json::Value::as_str), Some(real_jwt.as_str()));
    assert_eq!(value.get("nkey").and_then(serde_json::Value::as_str), Some(real.seed.public_key()));
    let sig = value.get("sig").and_then(serde_json::Value::as_str).expect("sig");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig).expect("sig bytes");
    assert!(NatsSeed::verify(real.seed.public_key(), nonce, &raw));
    assert!(!out.contains(&fake_jwt), "{out}");
    assert!(!out.contains(fake.seed.public_key()), "{out}");
    let foreign = format!(
      "CONNECT {{\"jwt\":\"{fake_jwt}\",\"nkey\":\"not-the-fake-public\",\"sig\":\"{}\",\"verbose\":false}}\r\n",
      sig_of(&fake.seed, nonce)
    );
    let mut foreign_down = down(&grants, true);
    let mut foreign_up = up(&grants);
    arm_info(&mut foreign_up, &mut foreign_down, "INFO {\"nonce\":\"N0NCE\"}\r\n").await;
    let (out, hits) = feed(&mut foreign_down, foreign.as_bytes()).await;
    assert_eq!(hits, 0);
    assert_eq!(text_of(out), foreign);
    assert!(!foreign.contains(&real_jwt));
  }

  #[tokio::test]
  async fn nkey_connect_with_jwt_is_forwarded() {
    let fake = minted();
    let real = minted();
    let grants = nkey_grants(&fake, &real);
    let nonce = b"N0NCE";
    let line = format!(
      "CONNECT {{\"jwt\":\"eyJleHRyYQ\",\"nkey\":\"{}\",\"sig\":\"{}\",\"verbose\":false}}\r\n",
      fake.seed.public_key(),
      sig_of(&fake.seed, nonce)
    );
    let mut down = down(&grants, true);
    let mut up = up(&grants);
    arm_info(&mut up, &mut down, "INFO {\"nonce\":\"N0NCE\"}\r\n").await;
    let (out, hits) = feed(&mut down, line.as_bytes()).await;
    assert_eq!(hits, 0);
    assert_original(&text_of(out), &line, real.seed.public_key(), &sig_of(&real.seed, nonce));
  }

  #[tokio::test]
  async fn user_pass_still_swaps_while_the_nonce_is_pending() {
    let grants = user_pass();
    let mut machine = down(&grants, true);
    let input = user_connect("agent", FAKE_PASS);
    let swapped = format!("CONNECT {{\"name\":\"agent-app\",\"pass\":\"{REAL_PASS}\",\"user\":\"agent\",\"verbose\":false}}\r\n");
    assert_eq!(feed(&mut machine, input.as_bytes()).await, (emit(&swapped), 1));
  }

  #[tokio::test]
  async fn cleartext_forwards_the_guest_nkey_line() {
    let fake = minted();
    let real = minted();
    let grants = nkey_grants(&fake, &real);
    let line = nkey_line(fake.seed.public_key(), &sig_of(&fake.seed, b"N0NCE"));
    let mut down = down(&grants, false);
    let mut up = up(&grants);
    arm_info(&mut up, &mut down, "INFO {\"nonce\":\"N0NCE\"}\r\n").await;
    let (out, hits) = feed(&mut down, line.as_bytes()).await;
    assert_eq!(hits, 0);
    assert_eq!(text_of(out), line);
    assert!(!line.contains(real.seed.public_key()));
  }

  #[tokio::test]
  async fn server_lines_redact_the_real_public_key_jwt_and_seed() {
    let fake = minted();
    let real = minted();
    let nkey = nkey_grants(&fake, &real);
    let mut machine = up(&nkey);
    let err = format!("-ERR '{}'\r\n", real.seed.public_key());
    let (out, hits) = feed(&mut machine, err.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(text_of(out), format!("-ERR '{}'\r\n", fake.seed.public_key()));
    let fake_jwt = user_jwt(fake.seed.public_key());
    let real_jwt = user_jwt(real.seed.public_key());
    let jwt = jwt_grants(&fake, &real, &fake_jwt, &real_jwt);
    let mut machine = up(&jwt);
    let err = format!("-ERR '{real_jwt}'\r\n");
    let (out, hits) = feed(&mut machine, err.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(text_of(out), format!("-ERR '{fake_jwt}'\r\n"));
    let mut machine = up(&nkey);
    let err = format!("-ERR '{}'\r\n", real.raw);
    let (out, hits) = feed(&mut machine, err.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(text_of(out), format!("-ERR '{}'\r\n", fake.raw));
    let mut machine = up(&jwt);
    let err = format!("-ERR '{}'\r\n", real.raw);
    let (out, hits) = feed(&mut machine, err.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(text_of(out), format!("-ERR '{}'\r\n", fake.raw));
  }

  #[tokio::test]
  async fn payload_with_the_real_jwt_or_seed_closes() {
    let fake = minted();
    let real = minted();
    let fake_jwt = user_jwt(fake.seed.public_key());
    let real_jwt = user_jwt(real.seed.public_key());
    let jwt = jwt_grants(&fake, &real, &fake_jwt, &real_jwt);
    let nkey = nkey_grants(&fake, &real);
    let mut machine = up(&jwt);
    let msg = format!("MSG orders 1 {}\r\n{real_jwt}\r\n", real_jwt.len());
    assert_eq!(feed(&mut machine, msg.as_bytes()).await.0, Out::Close);
    let mut machine = up(&jwt);
    let msg = format!("MSG orders 1 {}\r\n{}\r\n", real.seed.public_key().len(), real.seed.public_key());
    assert_eq!(feed(&mut machine, msg.as_bytes()).await.0, Out::Close);
    let mut machine = up(&jwt);
    let msg = format!("MSG orders 1 {}\r\n{}\r\n", real.raw.len(), real.raw);
    assert_eq!(feed(&mut machine, msg.as_bytes()).await.0, Out::Close);
    let mut machine = up(&nkey);
    let msg = format!("MSG orders 1 {}\r\n{}\r\n", real.raw.len(), real.raw);
    assert_eq!(feed(&mut machine, msg.as_bytes()).await.0, Out::Close);
  }

  #[tokio::test]
  async fn nkey_connect_past_the_cap_is_forwarded() {
    let fake = minted();
    let real = minted();
    let grants = nkey_grants(&fake, &real);
    let nonce = b"N0NCE";
    let sig = sig_of(&fake.seed, nonce);
    let name = "a".repeat(MAX_COMMAND);
    let line = format!(
      "CONNECT {{\"name\":\"{name}\",\"nkey\":\"{}\",\"sig\":\"{sig}\"}}\r\n",
      fake.seed.public_key()
    );
    assert!(line.len() > MAX_COMMAND);
    let follow = nkey_line(fake.seed.public_key(), &sig);
    let mut down = down(&grants, true);
    let mut up = up(&grants);
    arm_info(&mut up, &mut down, "INFO {\"nonce\":\"N0NCE\"}\r\n").await;
    let (out, hits) = feed(&mut down, format!("{line}{follow}").as_bytes()).await;
    let out = text_of(out);
    let swapped = nkey_line(real.seed.public_key(), &sig_of(&real.seed, nonce));
    assert_eq!(hits, 1);
    assert_eq!(out, format!("{line}{swapped}"));
    assert!(!line.contains(real.seed.public_key()));
    assert!(!line.contains(&sig_of(&real.seed, nonce)));
  }
}
