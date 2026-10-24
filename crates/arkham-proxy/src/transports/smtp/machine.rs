//! SMTP wire format: AUTH credential rewrite, then the shared relay.
//!
//! Downstream buffers one command line, capped like a Redis command.
//! [`smtp_proto::Request::parse`] classifies that line: the verb, the AUTH
//! mechanism, and a `BDAT` size. `AUTH PLAIN`, `AUTH LOGIN`, `AUTH XOAUTH2`,
//! and `AUTH OAUTHBEARER` reframe to the upstream spelling at any length,
//! inline or on the continuation line after a `334`. The SASL payload itself
//! stays local, because the parser does not swap credentials. `DATA` stays a
//! command until the matching upstream reply is a final `354`; a `530` or
//! `503` leaves the next command in command mode. The body then passes bytes
//! until the terminating dot, holding back only the suffix that might still
//! grow into `\r\n.\r\n`. `BDAT n` passes the next `n` octets and nothing
//! more. Every other command is forwarded as it arrives. Upstream redacts
//! through [`Raw`], including a real password longer than its decoy. A `334`
//! challenge is not rewritten. Replies stay on [`Raw`]: smtp-proto parses
//! them only through a receiver that buffers.
//!
//! `AUTH CRAM-MD5` and `AUTH DIGEST-MD5` are challenge-response mechanisms
//! and are relayed unchanged.

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use arkham_config::grants::{Grant, Scheme};
use base64::Engine as _;
use secrecy::ExposeSecret as _;
use smtp_proto::{AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2, Request};

use crate::transports::engine::{Direction, Hit, Location, Raw, Rewritten, Wire};

/// Cap for one buffered AUTH line. A real AUTH command is a few kilobytes;
/// anything past this is a drip or an attack, never an auth command.
pub(crate) const MAX_COMMAND: usize = 16_384;

/// Local reply when the upstream leg is already TLS and the guest asks for
/// `STARTTLS`. The command is not written into that encrypted leg.
const STARTTLS_READY: &[u8] = b"220 2.0.0 Ready to start TLS\r\n";

/// Terminator of a `DATA` body: the CRLF that ends the previous line, a
/// single dot, and the CRLF that ends the dot line.
const DATA_END: &[u8] = b"\r\n.\r\n";

/// SASL field separator used by XOAUTH2 and OAUTHBEARER (RFC 7628).
const SASL_SEP: u8 = 0x01;

/// One SMTP direction leg.
pub(crate) struct Smtp {
  /// Parse state. `None` on the response leg.
  down: Option<Down>,
  /// Reply redaction. `None` on the request leg.
  raw: Option<Raw>,
  /// Command and `DATA` reply accounting, shared by the two legs.
  gate: Arc<DataGate>,
  /// Upstream reply-line cursor. The request leg leaves it at rest.
  scan: ReplyScan,
}

/// Downstream parse state.
struct Down {
  /// Incomplete AUTH or command line. Payloads never land here.
  buf: Vec<u8>,
  /// Suffix of a `DATA` body that may still grow into [`DATA_END`].
  tail: Vec<u8>,
  phase: Phase,
  /// AUTH payloads are rewritten when this is set. Cleartext and TLS both set it.
  protected: bool,
  creds: Option<Creds>,
  /// Guest-bound bytes queued for [`Wire::take_reply`].
  reply: Option<Vec<u8>>,
  closed: bool,
  /// Shared with the upstream leg.
  gate: Arc<DataGate>,
}

/// Commands sent downstream and the final replies that answer them.
///
/// `DATA` is one command. Its reply is the final line whose sequence
/// number matches, a `354` or a refusal. The numbers are monotonic, so a
/// reply that is still unread when a later command is forwarded still
/// answers the earlier command.
struct DataGate {
  cmds: AtomicU32,
  replies: AtomicU32,
  /// Command number of an outstanding `DATA`, or `0`.
  data_cmd: AtomicU32,
  /// The matching reply was a final `354`.
  accepted: AtomicBool,
}

impl DataGate {
  fn new() -> Self {
    Self {
      cmds: AtomicU32::new(0),
      replies: AtomicU32::new(0),
      data_cmd: AtomicU32::new(0),
      accepted: AtomicBool::new(false),
    }
  }

  /// Record one line that expects a reply. Returns its command number.
  fn note_outbound(&self) -> u32 {
    let next = self.cmds.load(Ordering::Relaxed).saturating_add(1);
    self.cmds.store(next, Ordering::Release);
    next
  }

  /// `cmd` is a `DATA` command waiting for its reply.
  fn note_data(&self, cmd: u32) {
    self.data_cmd.store(cmd, Ordering::Release);
  }

  /// The message body ended. The server's `250` answers this line.
  fn note_body_end(&self) {
    let _cmd = self.note_outbound();
  }

  /// One final reply line. A final `354` for the outstanding `DATA`
  /// opens the body; any other code for that command leaves it closed.
  fn on_final_reply(&self, code: [u8; 3]) {
    let cmds = self.cmds.load(Ordering::Acquire);
    let prev = self.replies.load(Ordering::Acquire);
    if prev >= cmds {
      return;
    }
    let next = prev.saturating_add(1);
    self.replies.store(next, Ordering::Release);
    if self.data_cmd.load(Ordering::Acquire) != next {
      return;
    }
    if code == *b"354" {
      self.accepted.store(true, Ordering::Release);
    } else {
      self.data_cmd.store(0, Ordering::Release);
    }
  }

  /// Take the `354` permit. `false` leaves the phase in command mode.
  fn take_accepted(&self) -> bool {
    self.accepted.swap(false, Ordering::AcqRel)
  }
}

/// Cursor over one upstream reply line. Four bytes decide the line;
/// the rest is skipped. Nothing here retains reply text.
#[derive(Default)]
struct ReplyScan {
  /// `0..3` collect the status code, `3` waits for the separator, `4`
  /// skips the remainder of the line.
  at: u8,
  code: [u8; 3],
  /// This line already decided whether it was a final reply.
  settled: bool,
}

/// Where the next client bytes sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
  /// A command verb.
  Command,
  /// Base64 SASL PLAIN payload after a bare `AUTH PLAIN`.
  Plain,
  /// Base64 username after a bare `AUTH LOGIN`.
  LoginUser,
  /// Base64 password after the LOGIN username.
  LoginPass,
  /// Base64 XOAUTH2 or OAUTHBEARER payload after a bare `AUTH`.
  Bearer,
  /// Message body after `DATA`, until the terminating dot line.
  Data {
    /// True until a body byte has been committed, so a leading `.\r\n`
    /// (empty body) is the terminator.
    at_start: bool,
  },
  /// The next `remaining` octets are a `BDAT` chunk, passed unchanged.
  Bdat {
    /// Octets still to pass.
    remaining: u64,
  },
}

/// The credential pair one grant contributes to this connection.
struct Creds {
  fake_user: Vec<u8>,
  real_user: Vec<u8>,
  fake_pass: Vec<u8>,
  real_pass: Vec<u8>,
  label: String,
}

impl Smtp {
  /// Fresh leg. A direction with no covering grant still frames `DATA` and
  /// `BDAT`; it just has nothing to swap. Upstream is always [`Raw`].
  pub(crate) fn new(grants: &[Grant], host: &str, port: u16, dir: Direction) -> Self {
    let creds = grants.iter().find_map(|grant| {
      let scope = grant.smtp(Some(host), port)?;
      Some(Creds {
        fake_user: scope.downstream.user.as_bytes().to_vec(),
        real_user: scope.upstream.user.as_bytes().to_vec(),
        fake_pass: scope.downstream.password.expose_secret().as_bytes().to_vec(),
        real_pass: scope.upstream.password.expose_secret().as_bytes().to_vec(),
        label: grant.credential().map(|credential| credential.label.clone()).unwrap_or_default(),
      })
    });
    let gate = Arc::new(DataGate::new());
    match dir {
      Direction::Downstream => Self {
        down: Some(Down {
          buf: Vec::new(),
          tail: Vec::new(),
          phase: Phase::Command,
          protected: false,
          creds,
          reply: None,
          closed: false,
          gate: Arc::clone(&gate),
        }),
        raw: None,
        gate,
        scan: ReplyScan::default(),
      },
      Direction::Upstream => Self {
        down: None,
        raw: Some(Raw::length_changing(grants, Scheme::Smtp, host, port, Direction::Upstream)),
        gate,
        scan: ReplyScan::default(),
      },
    }
  }

  /// Both legs share one [`DataGate`]. The downstream leg counts
  /// commands; the upstream leg reads the reply that answers `DATA`.
  pub(crate) fn share_data_gate(downstream: &Smtp, upstream: &mut Smtp) {
    upstream.gate = Arc::clone(&downstream.gate);
  }

  /// Allow AUTH rewriting for the rest of the session.
  pub(crate) fn set_protected(&mut self, protected: bool) {
    if let Some(down) = self.down.as_mut() {
      down.protected = protected;
    }
  }

  /// True while the next guest line is an AUTH continuation, not a verb.
  pub(crate) fn awaiting_auth_payload(&self) -> bool {
    matches!(
      self.down.as_ref().map(|down| down.phase),
      Some(Phase::Plain | Phase::LoginUser | Phase::LoginPass | Phase::Bearer)
    )
  }

  /// Queue the local `STARTTLS` acceptance. The opening drains it with
  /// [`Wire::take_reply`] and writes it before the guest handshake.
  pub(crate) fn queue_starttls_ready(&mut self) {
    if let Some(down) = self.down.as_mut() {
      down.reply = Some(STARTTLS_READY.to_vec());
    }
  }

  /// Feed one downstream chunk. Command lines stay in `buf` until they end.
  /// `DATA` and `BDAT` payloads are emitted as they arrive.
  fn feed_down(&mut self, chunk: &[u8]) -> (Vec<u8>, Vec<Hit>) {
    let Some(down) = self.down.as_mut() else {
      return (chunk.to_vec(), Vec::new());
    };
    if down.closed {
      return (Vec::new(), Vec::new());
    }
    arm_data(down);
    let mut out = Vec::new();
    let mut hits = Vec::new();
    if chunk.is_empty() {
      flush_down(down, &mut out, &mut hits);
      return (out, hits);
    }
    match down.phase {
      Phase::Data { .. } | Phase::Bdat { .. } => {
        drive_payload(down, chunk, &mut out);
        if is_line_phase(down.phase) {
          drain_lines(down, &mut out, &mut hits);
        }
      }
      _ => {
        down.buf.extend_from_slice(chunk);
        drain_lines(down, &mut out, &mut hits);
      }
    }
    (out, hits)
  }
}

impl Wire for Smtp {
  async fn feed<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    if self.down.is_some() {
      let (out, hits) = self.feed_down(chunk);
      let closed = self.down.as_ref().is_some_and(|down| down.closed);
      let rewritten = if closed {
        Rewritten::Close
      } else if out.is_empty() && !chunk.is_empty() {
        Rewritten::Hold
      } else {
        Rewritten::Emit(Cow::Owned(out))
      };
      return (rewritten, hits);
    }
    if self.raw.is_some() && !chunk.is_empty() {
      observe_chunk(&mut self.scan, &self.gate, chunk);
    }
    if let Some(raw) = self.raw.as_mut() {
      return raw.feed(chunk).await;
    }
    (Rewritten::Emit(Cow::Borrowed(chunk)), Vec::new())
  }

  fn take_reply(&mut self) -> Option<Vec<u8>> {
    self.down.as_mut().and_then(|down| down.reply.take())
  }
}

fn is_line_phase(phase: Phase) -> bool {
  matches!(
    phase,
    Phase::Command | Phase::Plain | Phase::LoginUser | Phase::LoginPass | Phase::Bearer
  )
}

/// A final `354` for `DATA` opens the body on the next downstream chunk.
fn arm_data(down: &mut Down) {
  if down.phase != Phase::Command || !down.gate.take_accepted() {
    return;
  }
  down.tail.clear();
  down.phase = Phase::Data { at_start: true };
}

/// Walk one upstream chunk. The status code is the first bytes of a
/// line; the password, if any, is later and is not what this records.
fn observe_chunk(scan: &mut ReplyScan, gate: &DataGate, chunk: &[u8]) {
  for byte in chunk {
    observe_byte(scan, gate, *byte);
  }
}

fn observe_byte(scan: &mut ReplyScan, gate: &DataGate, byte: u8) {
  if byte == b'\n' {
    if !scan.settled {
      gate.on_final_reply(reply_code(scan));
    }
    *scan = ReplyScan::default();
    return;
  }
  if scan.at >= 4 {
    return;
  }
  if scan.at < 3 {
    if let Some(slot) = scan.code.get_mut(usize::from(scan.at)) {
      *slot = byte;
    }
    scan.at = scan.at.saturating_add(1);
    return;
  }
  scan.at = 4;
  if byte == b'-' {
    scan.settled = true;
    return;
  }
  gate.on_final_reply(scan.code);
  scan.settled = true;
}

fn reply_code(scan: &ReplyScan) -> [u8; 3] {
  if scan.at >= 3 { scan.code } else { [0, 0, 0] }
}

fn flush_down(down: &mut Down, out: &mut Vec<u8>, hits: &mut Vec<Hit>) {
  match down.phase {
    Phase::Data { .. } => out.extend_from_slice(&std::mem::take(&mut down.tail)),
    Phase::Bdat { .. } => {}
    _ => {
      let rest = std::mem::take(&mut down.buf);
      if !rest.is_empty() {
        let (line, found) = rewrite_down_line(&rest, down);
        out.extend_from_slice(&line);
        hits.extend(found);
      }
    }
  }
}

/// Take complete lines out of `buf`. A line that enters `DATA` or `BDAT`
/// consumes the bytes that followed it in this chunk as payload.
fn drain_lines(down: &mut Down, out: &mut Vec<u8>, hits: &mut Vec<Hit>) {
  loop {
    if down.closed {
      return;
    }
    if !is_line_phase(down.phase) {
      let pending = std::mem::take(&mut down.buf);
      if pending.is_empty() {
        if matches!(down.phase, Phase::Bdat { remaining: 0 }) {
          down.phase = Phase::Command;
          continue;
        }
        return;
      }
      drive_payload(down, &pending, out);
      if !is_line_phase(down.phase) {
        return;
      }
      continue;
    }
    let Some(end) = line_end(&down.buf) else {
      if down.buf.len() > MAX_COMMAND {
        down.closed = true;
      }
      return;
    };
    if end > MAX_COMMAND {
      down.closed = true;
      return;
    }
    let line: Vec<u8> = down.buf.drain(..end).collect();
    let (rewritten, found) = rewrite_down_line(&line, down);
    out.extend_from_slice(&rewritten);
    hits.extend(found);
  }
}

/// Pass a `DATA` body or a `BDAT` chunk. Leftover bytes after the payload
/// land back in the line buffer.
fn drive_payload(down: &mut Down, input: &[u8], out: &mut Vec<u8>) {
  match down.phase {
    Phase::Bdat { remaining } => {
      if remaining == 0 {
        down.phase = Phase::Command;
        down.buf.extend_from_slice(input);
        return;
      }
      let want = match usize::try_from(remaining) {
        Ok(n) => n.min(input.len()),
        Err(_) => input.len(),
      };
      let Some(taken) = input.get(..want) else {
        down.closed = true;
        return;
      };
      out.extend_from_slice(taken);
      let Ok(got) = u64::try_from(want) else {
        down.closed = true;
        return;
      };
      let left = remaining.saturating_sub(got);
      let rest = input.get(want..).unwrap_or(&[]);
      if left == 0 {
        down.phase = Phase::Command;
        down.buf.extend_from_slice(rest);
      } else {
        down.phase = Phase::Bdat { remaining: left };
      }
    }
    Phase::Data { mut at_start } => {
      let (emitted, done, leftover) = consume_data(&mut down.tail, &mut at_start, input);
      out.extend_from_slice(&emitted);
      if done {
        down.phase = Phase::Command;
        down.tail.clear();
        down.buf.extend_from_slice(&leftover);
        down.gate.note_body_end();
      } else {
        down.phase = Phase::Data { at_start };
      }
    }
    Phase::Command | Phase::Plain | Phase::LoginUser | Phase::LoginPass | Phase::Bearer => {}
  }
}

/// Emit `input`, keeping only a suffix that is still a proper prefix of the
/// `DATA` terminator. `done` carries the bytes that followed the terminator.
fn consume_data(tail: &mut Vec<u8>, at_start: &mut bool, input: &[u8]) -> (Vec<u8>, bool, Vec<u8>) {
  let mut emit = Vec::new();
  let mut held = std::mem::take(tail);
  for (index, byte) in input.iter().copied().enumerate() {
    held.push(byte);
    if terminator_ready(&held, *at_start) {
      emit.extend_from_slice(&held);
      let next = index.saturating_add(1);
      let leftover = input.get(next..).unwrap_or(&[]).to_vec();
      *at_start = false;
      return (emit, true, leftover);
    }
    shed_prefix(&mut held, &mut emit, at_start);
  }
  *tail = held;
  (emit, false, Vec::new())
}

fn terminator_ready(held: &[u8], at_start: bool) -> bool {
  held == DATA_END || (at_start && held == b".\r\n")
}

/// Emit leading bytes that can no longer grow into the terminator.
fn shed_prefix(held: &mut Vec<u8>, emit: &mut Vec<u8>, at_start: &mut bool) {
  let mut keep_from = 0;
  while keep_from < held.len() && !held_is_prefix(held.get(keep_from..).unwrap_or(&[]), *at_start) {
    keep_from = keep_from.saturating_add(1);
    *at_start = false;
  }
  if keep_from > 0 {
    emit.extend_from_slice(held.get(..keep_from).unwrap_or(&[]));
    held.drain(..keep_from);
  }
}

fn held_is_prefix(held: &[u8], at_start: bool) -> bool {
  if held.is_empty() || DATA_END.starts_with(held) {
    return true;
  }
  at_start && matches!(held, b"." | b".\r")
}

/// Rewrite one complete downstream line and advance the AUTH phase.
fn rewrite_down_line(line: &[u8], down: &mut Down) -> (Vec<u8>, Vec<Hit>) {
  if !is_line_phase(down.phase) {
    return (line.to_vec(), Vec::new());
  }
  let cmd = down.gate.note_outbound();
  let body = line_body(line);
  if body == b"*" {
    down.phase = Phase::Command;
    return (line.to_vec(), Vec::new());
  }
  if down.phase != Phase::Command && is_command(line) {
    down.phase = Phase::Command;
  }
  let protected = down.protected;
  match down.phase {
    Phase::Plain => {
      down.phase = Phase::Command;
      let Some(creds) = down.creds.as_ref() else {
        return (line.to_vec(), Vec::new());
      };
      rewrite_plain_line(line, creds, protected)
    }
    Phase::LoginUser => {
      down.phase = Phase::LoginPass;
      let Some(creds) = down.creds.as_ref() else {
        return (line.to_vec(), Vec::new());
      };
      rewrite_token_line(line, &creds.fake_user, &creds.real_user, creds, protected)
    }
    Phase::LoginPass => {
      down.phase = Phase::Command;
      let Some(creds) = down.creds.as_ref() else {
        return (line.to_vec(), Vec::new());
      };
      rewrite_token_line(line, &creds.fake_pass, &creds.real_pass, creds, protected)
    }
    Phase::Bearer => {
      down.phase = Phase::Command;
      let Some(creds) = down.creds.as_ref() else {
        return (line.to_vec(), Vec::new());
      };
      rewrite_bearer_line(line, creds, protected)
    }
    Phase::Command => rewrite_command(line, down, cmd),
    Phase::Data { .. } | Phase::Bdat { .. } => (line.to_vec(), Vec::new()),
  }
}

/// A command line, or an `AUTH` line with its mechanism and initial response.
fn rewrite_command(line: &[u8], down: &mut Down, cmd: u32) -> (Vec<u8>, Vec<Hit>) {
  let Some(request) = parse_command(line) else {
    return (line.to_vec(), Vec::new());
  };
  match request {
    Request::Data => {
      down.gate.note_data(cmd);
      (line.to_vec(), Vec::new())
    }
    Request::Bdat { chunk_size, .. } => {
      let Ok(remaining) = u64::try_from(chunk_size) else {
        return (line.to_vec(), Vec::new());
      };
      down.phase = Phase::Bdat { remaining };
      (line.to_vec(), Vec::new())
    }
    Request::Auth {
      mechanism,
      initial_response,
    } => rewrite_auth(line, down, mechanism, &initial_response),
    _ => (line.to_vec(), Vec::new()),
  }
}

/// `AUTH` classified by [`smtp_proto`]. `=` is the empty initial response.
fn rewrite_auth(line: &[u8], down: &mut Down, mechanism: u64, initial: &str) -> (Vec<u8>, Vec<Hit>) {
  let ending = line_ending(line);
  let initial = if initial.is_empty() || initial == "=" {
    None
  } else {
    Some(initial.as_bytes())
  };
  match mechanism {
    AUTH_PLAIN => {
      let Some(arg) = initial else {
        down.phase = Phase::Plain;
        return (line.to_vec(), Vec::new());
      };
      let protected = down.protected;
      let Some(creds) = down.creds.as_ref() else {
        return (line.to_vec(), Vec::new());
      };
      rewrite_auth_arg(line, b"PLAIN", arg, ending, creds, protected, rewrite_plain_raw)
    }
    AUTH_LOGIN => {
      let Some(arg) = initial else {
        down.phase = Phase::LoginUser;
        return (line.to_vec(), Vec::new());
      };
      let protected = down.protected;
      let Some(creds) = down.creds.as_ref() else {
        return (line.to_vec(), Vec::new());
      };
      let (rewritten, hits) = rewrite_token_line(&join_line(arg, ending), &creds.fake_user, &creds.real_user, creds, protected);
      down.phase = Phase::LoginPass;
      let arg_body = line_body(&rewritten);
      (join_auth(b"LOGIN", Some(arg_body), ending), hits)
    }
    AUTH_XOAUTH2 => rewrite_bearer(line, down, b"XOAUTH2", initial, ending),
    AUTH_OAUTHBEARER => rewrite_bearer(line, down, b"OAUTHBEARER", initial, ending),
    _ => (line.to_vec(), Vec::new()),
  }
}

/// XOAUTH2 and OAUTHBEARER share one payload shape.
fn rewrite_bearer(line: &[u8], down: &mut Down, mech: &[u8], initial: Option<&[u8]>, ending: &[u8]) -> (Vec<u8>, Vec<Hit>) {
  let Some(arg) = initial else {
    down.phase = Phase::Bearer;
    return (line.to_vec(), Vec::new());
  };
  let protected = down.protected;
  let Some(creds) = down.creds.as_ref() else {
    return (line.to_vec(), Vec::new());
  };
  rewrite_auth_arg(line, mech, arg, ending, creds, protected, rewrite_bearer_raw)
}

/// Size on `BDAT <n> [LAST]`. A line the parser rejects is `None`.
#[cfg(test)]
fn bdat_octets(line: &[u8]) -> Option<u64> {
  match parse_command(line)? {
    Request::Bdat { chunk_size, .. } => u64::try_from(chunk_size).ok(),
    _ => None,
  }
}

/// One SMTP command, parsed from the line already in the AUTH buffer.
/// Anything the parser rejects is forwarded unchanged.
fn parse_command(line: &[u8]) -> Option<Request<Cow<'_, str>>> {
  if !line.contains(&b'\n') {
    return None;
  }
  Request::parse(&mut line.iter()).ok()
}

/// `STARTTLS`, as the parser names it.
pub(super) fn is_starttls(line: &[u8]) -> bool {
  matches!(parse_command(line), Some(Request::StartTls))
}

/// Pre-transaction commands the cleartext opening still forwards itself.
/// Transaction commands belong to the relay.
pub(super) fn is_opening_command(line: &[u8]) -> bool {
  matches!(
    parse_command(line),
    Some(
      Request::Ehlo { .. }
        | Request::Helo { .. }
        | Request::Help { .. }
        | Request::Vrfy { .. }
        | Request::Expn { .. }
        | Request::Noop { .. }
        | Request::Rset
        | Request::Auth { .. }
        | Request::Quit
    )
  )
}

/// Replace the initial-response argument of an `AUTH` line.
fn rewrite_auth_arg(
  line: &[u8],
  mech: &[u8],
  arg: &[u8],
  ending: &[u8],
  creds: &Creds,
  protected: bool,
  rewrite: fn(&[u8], &Creds, bool) -> Option<Vec<u8>>,
) -> (Vec<u8>, Vec<Hit>) {
  let Some(raw) = b64_decode(arg) else {
    return (line.to_vec(), Vec::new());
  };
  let Some(rewritten) = rewrite(&raw, creds, protected) else {
    return (line.to_vec(), Vec::new());
  };
  (join_auth(mech, Some(&b64_encode(&rewritten)), ending), vec![hit(creds)])
}

/// A continuation line carrying a SASL PLAIN payload.
fn rewrite_plain_line(line: &[u8], creds: &Creds, protected: bool) -> (Vec<u8>, Vec<Hit>) {
  let body = line_body(line);
  let Some(raw) = b64_decode(body) else {
    return (line.to_vec(), Vec::new());
  };
  let Some(rewritten) = rewrite_plain_raw(&raw, creds, protected) else {
    return (line.to_vec(), Vec::new());
  };
  let mut out = b64_encode(&rewritten);
  out.extend_from_slice(line_ending(line));
  (out, vec![hit(creds)])
}

/// A continuation line whose whole payload is one token (LOGIN user or password).
fn rewrite_token_line(line: &[u8], from: &[u8], to: &[u8], creds: &Creds, protected: bool) -> (Vec<u8>, Vec<Hit>) {
  if !protected || from == to {
    return (line.to_vec(), Vec::new());
  }
  let Some(raw) = b64_decode(line_body(line)) else {
    return (line.to_vec(), Vec::new());
  };
  if raw.as_slice() != from {
    return (line.to_vec(), Vec::new());
  }
  let mut out = b64_encode(to);
  out.extend_from_slice(line_ending(line));
  (out, vec![hit(creds)])
}

/// A continuation line carrying an XOAUTH2 or OAUTHBEARER payload.
fn rewrite_bearer_line(line: &[u8], creds: &Creds, protected: bool) -> (Vec<u8>, Vec<Hit>) {
  let Some(raw) = b64_decode(line_body(line)) else {
    return (line.to_vec(), Vec::new());
  };
  let Some(rewritten) = rewrite_bearer_raw(&raw, creds, protected) else {
    return (line.to_vec(), Vec::new());
  };
  let mut out = b64_encode(&rewritten);
  out.extend_from_slice(line_ending(line));
  (out, vec![hit(creds)])
}

/// SASL PLAIN: `authzid NUL authcid NUL password`.
fn rewrite_plain_raw(raw: &[u8], creds: &Creds, protected: bool) -> Option<Vec<u8>> {
  if !protected {
    return None;
  }
  let (zid, cid, pass) = split_plain(raw)?;
  let mut cid_out = cid.to_vec();
  let mut pass_out = pass.to_vec();
  let mut hit = false;
  if pass == creds.fake_pass.as_slice() && creds.fake_pass != creds.real_pass {
    pass_out.clone_from(&creds.real_pass);
    hit = true;
  }
  if cid == creds.fake_user.as_slice() && creds.fake_user != creds.real_user {
    cid_out.clone_from(&creds.real_user);
    hit = true;
  }
  if !hit {
    return None;
  }
  let mut out = Vec::with_capacity(
    zid
      .len()
      .saturating_add(cid_out.len())
      .saturating_add(pass_out.len())
      .saturating_add(2),
  );
  out.extend_from_slice(zid);
  out.push(0);
  out.extend_from_slice(&cid_out);
  out.push(0);
  out.extend_from_slice(&pass_out);
  Some(out)
}

/// XOAUTH2 (`user=…\x01auth=Bearer …\x01\x01`) and OAUTHBEARER
/// (`n,a=…,\x01…auth=Bearer …\x01\x01`). The bearer token is the password.
fn rewrite_bearer_raw(raw: &[u8], creds: &Creds, protected: bool) -> Option<Vec<u8>> {
  if !protected {
    return None;
  }
  let mut spans: Vec<(usize, usize, Vec<u8>)> = Vec::new();
  if creds.fake_pass != creds.real_pass
    && let Some((start, end)) = marked_span(raw, b"auth=Bearer ", |byte| byte == SASL_SEP)
    && raw.get(start..end) == Some(creds.fake_pass.as_slice())
  {
    spans.push((start, end, creds.real_pass.clone()));
  }
  if creds.fake_user != creds.real_user {
    if let Some((start, end)) = marked_span(raw, b"user=", |byte| byte == SASL_SEP)
      && raw.get(start..end) == Some(creds.fake_user.as_slice())
    {
      spans.push((start, end, creds.real_user.clone()));
    }
    if let Some((start, end)) = marked_span(raw, b"n,a=", |byte| byte == b',' || byte == SASL_SEP)
      && raw.get(start..end) == Some(creds.fake_user.as_slice())
    {
      spans.push((start, end, creds.real_user.clone()));
    }
  }
  if spans.is_empty() {
    return None;
  }
  spans.sort_by_key(|(start, _, _)| *start);
  let mut out = raw.to_vec();
  for (start, end, repl) in spans.into_iter().rev() {
    if start <= end && end <= out.len() {
      out.splice(start..end, repl);
    }
  }
  Some(out)
}

/// Byte range of the field after `marker`, ending at the first byte `ends` accepts.
fn marked_span(raw: &[u8], marker: &[u8], ends: impl Fn(u8) -> bool) -> Option<(usize, usize)> {
  if marker.is_empty() || raw.len() < marker.len() {
    return None;
  }
  let pos = raw.windows(marker.len()).position(|window| window == marker)?;
  let start = pos.saturating_add(marker.len());
  let rest = raw.get(start..)?;
  let end = rest
    .iter()
    .position(|byte| ends(*byte))
    .map_or(raw.len(), |at| start.saturating_add(at));
  Some((start, end))
}

fn hit(creds: &Creds) -> Hit {
  Hit {
    label: creds.label.clone(),
    location: Location::BasicAuth,
  }
}

/// Three NUL-separated SASL PLAIN fields.
fn split_plain(raw: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
  let mut parts = raw.split(|byte| *byte == 0);
  let zid = parts.next()?;
  let cid = parts.next()?;
  let pass = parts.next()?;
  parts.next().is_none().then_some((zid, cid, pass))
}

fn b64_decode(text: &[u8]) -> Option<Vec<u8>> {
  let text = trim_ascii(text);
  if text.is_empty() || text == b"=" {
    return None;
  }
  base64::engine::general_purpose::STANDARD
    .decode(text)
    .ok()
    .or_else(|| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text).ok())
}

fn b64_encode(raw: &[u8]) -> Vec<u8> {
  base64::engine::general_purpose::STANDARD.encode(raw).into_bytes()
}

fn join_auth(mech: &[u8], arg: Option<&[u8]>, ending: &[u8]) -> Vec<u8> {
  let mut out = b"AUTH ".to_vec();
  out.extend_from_slice(mech);
  if let Some(arg) = arg {
    out.push(b' ');
    out.extend_from_slice(arg);
  }
  out.extend_from_slice(ending);
  out
}

fn join_line(body: &[u8], ending: &[u8]) -> Vec<u8> {
  let mut out = body.to_vec();
  out.extend_from_slice(ending);
  out
}

fn is_command(line: &[u8]) -> bool {
  parse_command(line).is_some()
}

/// Index just past the line ending, when `buf` holds one.
fn line_end(buf: &[u8]) -> Option<usize> {
  buf.iter().position(|byte| *byte == b'\n').map(|at| at.saturating_add(1))
}

fn line_body(line: &[u8]) -> &[u8] {
  line.strip_suffix(b"\r\n").or_else(|| line.strip_suffix(b"\n")).unwrap_or(line)
}

fn line_ending(line: &[u8]) -> &[u8] {
  if line.ends_with(b"\r\n") {
    b"\r\n"
  } else if line.ends_with(b"\n") {
    b"\n"
  } else {
    b""
  }
}

fn trim_ascii(text: &[u8]) -> &[u8] {
  let start = text.iter().position(|byte| !byte.is_ascii_whitespace()).unwrap_or(text.len());
  let end = text
    .iter()
    .rposition(|byte| !byte.is_ascii_whitespace())
    .map_or(start, |at| at.saturating_add(1));
  text.get(start..end).unwrap_or(&[])
}

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::grants::{Credential, GuestTlsMode, SmtpLeg, SmtpScope};
  use secrecy::SecretString;

  const FAKE_USER: &str = "agent@demo.test";
  const REAL_USER: &str = "agent@demo.test";
  const FAKE_PASS: &str = "fake-smtp-pass"; // betterleaks:allow
  const REAL_PASS: &str = "real-smtp-pass"; // betterleaks:allow

  fn scope(fake_user: &str, real_user: &str, fake_pass: &str, real_pass: &str) -> SmtpScope {
    SmtpScope {
      downstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: fake_user.into(),
        password: SecretString::from(fake_pass),
      },
      is_downstream_tls: false,
      upstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: real_user.into(),
        password: SecretString::from(real_pass),
      },
      is_upstream_tls: false,
      starttls_required: true,
      root_cert: None,
      client_cert: None,
      client_key: None,
      guest_tls: GuestTlsMode::default(),
    }
  }

  fn grant(fake_user: &str, real_user: &str) -> Vec<Grant> {
    grant_pass(fake_user, real_user, FAKE_PASS, REAL_PASS)
  }

  fn grant_pass(fake_user: &str, real_user: &str, fake_pass: &str, real_pass: &str) -> Vec<Grant> {
    vec![Grant::Smtp {
      credential: Credential {
        label: "smtp".into(),
        fake: fake_pass.into(),
        value: SecretString::from(real_pass),
      },
      scope: Box::new(scope(fake_user, real_user, fake_pass, real_pass)),
    }]
  }

  fn down() -> Smtp {
    let mut machine = Smtp::new(&grant(FAKE_USER, REAL_USER), "mail", 587, Direction::Downstream);
    machine.set_protected(true);
    machine
  }

  fn up() -> Smtp {
    Smtp::new(&grant(FAKE_USER, REAL_USER), "mail", 587, Direction::Upstream)
  }

  /// Downstream and upstream legs that share the `DATA` reply permit.
  fn pair() -> (Smtp, Smtp) {
    let down_leg = down();
    let mut up_leg = up();
    Smtp::share_data_gate(&down_leg, &mut up_leg);
    (down_leg, up_leg)
  }

  async fn emit(machine: &mut Smtp, chunk: &[u8]) -> (Vec<u8>, usize) {
    match machine.feed(chunk).await {
      (Rewritten::Emit(bytes), hits) => (bytes.into_owned(), hits.len()),
      (Rewritten::Hold, hits) => (Vec::new(), hits.len()),
      (Rewritten::Close, _) => panic!("line closed the machine"),
    }
  }

  /// Downstream tests use [`emit`]. Upstream [`Raw`] may hold a suffix; this
  /// flushes it so a complete reply is asserted whole.
  async fn emit_flushed(machine: &mut Smtp, chunk: &[u8]) -> (Vec<u8>, usize) {
    let (mut out, hits) = emit(machine, chunk).await;
    let (rest, more) = emit(machine, &[]).await;
    out.extend_from_slice(&rest);
    (out, hits.saturating_add(more))
  }

  fn plain(user: &str, pass: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"))
  }

  #[tokio::test]
  async fn plain_inline_swaps_the_password() {
    let mut machine = down();
    let line = format!("AUTH PLAIN {}\r\n", plain(FAKE_USER, FAKE_PASS));
    let (out, hits) = emit(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(out, format!("AUTH PLAIN {}\r\n", plain(REAL_USER, REAL_PASS)).into_bytes());
  }

  #[tokio::test]
  async fn plain_inline_swaps_a_different_user() {
    let mut machine = Smtp::new(&grant("guest@demo.test", "real@demo.test"), "mail", 587, Direction::Downstream);
    machine.set_protected(true);
    let line = format!("AUTH PLAIN {}\r\n", plain("guest@demo.test", FAKE_PASS));
    let (out, hits) = emit(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(out, format!("AUTH PLAIN {}\r\n", plain("real@demo.test", REAL_PASS)).into_bytes());
  }

  #[tokio::test]
  async fn plain_continuation_swaps_the_second_line() {
    let mut machine = down();
    let (cmd, hits) = emit(&mut machine, b"AUTH PLAIN\r\n").await;
    assert_eq!(cmd, b"AUTH PLAIN\r\n");
    assert_eq!(hits, 0);
    let payload = format!("{}\r\n", plain(FAKE_USER, FAKE_PASS));
    let (out, hits) = emit(&mut machine, payload.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(out, format!("{}\r\n", plain(REAL_USER, REAL_PASS)).into_bytes());
  }

  #[tokio::test]
  async fn plain_before_protect_is_forwarded_unchanged() {
    let mut machine = Smtp::new(&grant(FAKE_USER, REAL_USER), "mail", 587, Direction::Downstream);
    machine.set_protected(false);
    let line = format!("AUTH PLAIN {}\r\n", plain(FAKE_USER, FAKE_PASS));
    let (out, hits) = emit(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 0);
    assert_eq!(out, line.as_bytes());
  }

  #[tokio::test]
  async fn login_two_step_swaps_the_password_line() {
    let mut machine = down();
    let (cmd, _) = emit(&mut machine, b"AUTH LOGIN\r\n").await;
    assert_eq!(cmd, b"AUTH LOGIN\r\n");
    let user = base64::engine::general_purpose::STANDARD.encode(FAKE_USER);
    let (user_out, user_hits) = emit(&mut machine, format!("{user}\r\n").as_bytes()).await;
    assert_eq!(user_hits, 0, "the same user is not a hit");
    assert_eq!(user_out, format!("{user}\r\n").into_bytes());
    let pass = base64::engine::general_purpose::STANDARD.encode(FAKE_PASS);
    let (out, hits) = emit(&mut machine, format!("{pass}\r\n").as_bytes()).await;
    assert_eq!(hits, 1);
    let real = base64::engine::general_purpose::STANDARD.encode(REAL_PASS);
    assert_eq!(out, format!("{real}\r\n").into_bytes());
  }

  #[tokio::test]
  async fn login_inline_username_then_password() {
    let mut machine = down();
    let user = base64::engine::general_purpose::STANDARD.encode(FAKE_USER);
    let (cmd, _) = emit(&mut machine, format!("AUTH LOGIN {user}\r\n").as_bytes()).await;
    assert_eq!(cmd, format!("AUTH LOGIN {user}\r\n").into_bytes());
    let pass = base64::engine::general_purpose::STANDARD.encode(FAKE_PASS);
    let (out, hits) = emit(&mut machine, format!("{pass}\r\n").as_bytes()).await;
    assert_eq!(hits, 1);
    let real = base64::engine::general_purpose::STANDARD.encode(REAL_PASS);
    assert_eq!(out, format!("{real}\r\n").into_bytes());
  }

  #[tokio::test]
  async fn xoauth2_swaps_the_bearer() {
    let mut machine = down();
    let raw = format!("user={FAKE_USER}\x01auth=Bearer {FAKE_PASS}\x01\x01");
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
    let (out, hits) = emit(&mut machine, format!("AUTH XOAUTH2 {encoded}\r\n").as_bytes()).await;
    assert_eq!(hits, 1);
    let expect = format!("user={REAL_USER}\x01auth=Bearer {REAL_PASS}\x01\x01");
    let encoded = base64::engine::general_purpose::STANDARD.encode(expect.as_bytes());
    assert_eq!(out, format!("AUTH XOAUTH2 {encoded}\r\n").into_bytes());
  }

  #[tokio::test]
  async fn oauthbearer_swaps_the_bearer() {
    let mut machine = Smtp::new(&grant("guest@demo.test", "real@demo.test"), "mail", 587, Direction::Downstream);
    machine.set_protected(true);
    let raw = format!("n,a=guest@demo.test,\x01host=mail\x01auth=Bearer {FAKE_PASS}\x01\x01");
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
    let (out, hits) = emit(&mut machine, format!("AUTH OAUTHBEARER {encoded}\r\n").as_bytes()).await;
    assert_eq!(hits, 1);
    let expect = format!("n,a=real@demo.test,\x01host=mail\x01auth=Bearer {REAL_PASS}\x01\x01");
    let encoded = base64::engine::general_purpose::STANDARD.encode(expect.as_bytes());
    assert_eq!(out, format!("AUTH OAUTHBEARER {encoded}\r\n").into_bytes());
  }

  #[tokio::test]
  async fn wrong_password_is_unchanged() {
    let mut machine = down();
    let line = format!("AUTH PLAIN {}\r\n", plain(FAKE_USER, "not-the-decoy"));
    let (out, hits) = emit(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 0);
    assert_eq!(out, line.as_bytes());
    assert!(!out.windows(REAL_PASS.len()).any(|window| window == REAL_PASS.as_bytes()));
  }

  #[tokio::test]
  async fn cram_md5_is_forwarded() {
    let mut machine = down();
    let line = b"AUTH CRAM-MD5\r\n";
    let (out, hits) = emit(&mut machine, line).await;
    assert_eq!(hits, 0);
    assert_eq!(out, line);
  }

  #[tokio::test]
  async fn star_cancels_and_the_next_command_is_a_command() {
    let mut machine = down();
    let _ = emit(&mut machine, b"AUTH PLAIN\r\n").await;
    let (cancel, _) = emit(&mut machine, b"*\r\n").await;
    assert_eq!(cancel, b"*\r\n");
    let (ehlo, hits) = emit(&mut machine, b"EHLO client\r\n").await;
    assert_eq!(hits, 0);
    assert_eq!(ehlo, b"EHLO client\r\n");
  }

  #[tokio::test]
  async fn response_redacts_the_real_password() {
    let mut machine = up();
    let line = format!("535 5.7.8 authentication failed for {REAL_PASS}\r\n");
    let (out, hits) = emit_flushed(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 1);
    assert_eq!(out, format!("535 5.7.8 authentication failed for {FAKE_PASS}\r\n").into_bytes());
    assert!(!out.windows(REAL_PASS.len()).any(|window| window == REAL_PASS.as_bytes()));
  }

  #[tokio::test]
  async fn response_redacts_the_password_and_leaves_the_username() {
    let mut machine = Smtp::new(&grant("guest@demo.test", "a"), "mail", 587, Direction::Upstream);
    let line = format!("535 5.7.8 a rejected {REAL_PASS}\r\n");
    let (out, hits) = emit_flushed(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 1);
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("535 5.7.8 a rejected"), "{text}");
    assert!(text.contains(FAKE_PASS), "{text}");
    assert!(!text.contains(REAL_PASS), "{text}");
  }

  #[tokio::test]
  async fn ehlo_reply_keeps_chunking() {
    let mut machine = up();
    let reply = b"250-mail.demo.test\r\n250-PIPELINING\r\n250 CHUNKING\r\n";
    let (out, hits) = emit_flushed(&mut machine, reply).await;
    assert_eq!(hits, 0);
    assert_eq!(out, reply);
  }

  #[tokio::test]
  async fn challenge_334_is_left_unchanged() {
    let mut machine = up();
    let payload = format!("{{\"status\":\"400\",\"scope\":\"{REAL_PASS}\"}}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    let line = format!("334 {encoded}\r\n");
    let (out, hits) = emit_flushed(&mut machine, line.as_bytes()).await;
    assert_eq!(hits, 0);
    assert_eq!(out, line.as_bytes());
  }

  #[tokio::test]
  async fn data_passes_until_the_dot_line() {
    let (mut down_leg, mut up_leg) = pair();
    let (cmd, hits) = emit(&mut down_leg, b"DATA\r\n").await;
    assert_eq!(hits, 0);
    assert_eq!(cmd, b"DATA\r\n");
    let _ = emit(&mut up_leg, b"354 go ahead\r\n").await;
    let (out, _) = emit(&mut down_leg, b"hello\r\n.\r\nQUIT\r\n").await;
    assert_eq!(out, b"hello\r\n.\r\nQUIT\r\n");
  }

  #[tokio::test]
  async fn data_holds_a_split_terminator() {
    let (mut down_leg, mut up_leg) = pair();
    let _ = emit(&mut down_leg, b"DATA\r\n").await;
    let _ = emit(&mut up_leg, b"354 go ahead\r\n").await;
    let (head, _) = emit(&mut down_leg, b"hello\r\n.").await;
    assert_eq!(head, b"hello");
    let (tail, _) = emit(&mut down_leg, b"\r\nQUIT\r\n").await;
    assert_eq!(tail, b"\r\n.\r\nQUIT\r\n");
  }

  #[tokio::test]
  async fn empty_data_body_ends_on_the_leading_dot() {
    let (mut down_leg, mut up_leg) = pair();
    let _ = emit(&mut down_leg, b"DATA\r\n").await;
    let _ = emit(&mut up_leg, b"354 go ahead\r\n").await;
    let (out, _) = emit(&mut down_leg, b".\r\nNOOP\r\n").await;
    assert_eq!(out, b".\r\nNOOP\r\n");
  }

  /// A `530` or `503` answers `DATA`. The following `AUTH` is still a command.
  #[tokio::test]
  async fn rejected_data_keeps_the_next_auth() {
    let line = format!("AUTH PLAIN {}\r\n", plain(FAKE_USER, FAKE_PASS));
    let real = format!("AUTH PLAIN {}\r\n", plain(REAL_USER, REAL_PASS));
    for refusal in [
      b"530 5.7.0 Authentication required\r\n".as_slice(),
      b"503 5.5.1 Need recipient\r\n".as_slice(),
    ] {
      let (mut down_leg, mut up_leg) = pair();
      let (cmd, _) = emit(&mut down_leg, b"DATA\r\n").await;
      assert_eq!(cmd, b"DATA\r\n");
      let _ = emit(&mut up_leg, refusal).await;
      let (out, hits) = emit(&mut down_leg, line.as_bytes()).await;
      assert_eq!(hits, 1, "{}", String::from_utf8_lossy(refusal));
      assert_eq!(out, real.as_bytes());
    }
  }

  /// `MAIL` and `RCPT` replies are not the `DATA` reply. The body opens
  /// on the third final line when that line is `354`.
  #[tokio::test]
  async fn data_body_waits_for_the_matching_354() {
    let (mut down_leg, mut up_leg) = pair();
    let _ = emit(&mut down_leg, b"MAIL FROM:<a@b>\r\n").await;
    let _ = emit(&mut down_leg, b"RCPT TO:<c@d>\r\n").await;
    let _ = emit(&mut down_leg, b"DATA\r\n").await;
    let _ = emit(&mut up_leg, b"250 2.1.0 ok\r\n").await;
    let (early, _) = emit(&mut down_leg, b"hello\r\n.").await;
    assert_eq!(early, b"hello\r\n", "an earlier 250 must not open the body");

    let (mut down_leg, mut up_leg) = pair();
    let _ = emit(&mut down_leg, b"MAIL FROM:<a@b>\r\n").await;
    let _ = emit(&mut up_leg, b"250 2.1.0 ok\r\n").await;
    let _ = emit(&mut down_leg, b"RCPT TO:<c@d>\r\n").await;
    let _ = emit(&mut up_leg, b"250 2.1.5 ok\r\n").await;
    let _ = emit(&mut down_leg, b"DATA\r\n").await;
    let _ = emit(&mut up_leg, b"354-go\r\n354 go ahead\r\n").await;
    let (head, _) = emit(&mut down_leg, b"hello\r\n.").await;
    assert_eq!(head, b"hello");
  }

  #[tokio::test]
  async fn response_redacts_a_longer_real_password() {
    const LONG_REAL: &str = "real-smtp-pass-extended"; // betterleaks:allow
    let mut machine = Smtp::new(
      &grant_pass(FAKE_USER, REAL_USER, FAKE_PASS, LONG_REAL),
      "mail",
      587,
      Direction::Upstream,
    );
    let line = format!("535 5.7.8 authentication failed for {LONG_REAL}\r\n");
    let split = line.find(LONG_REAL).unwrap().saturating_add(4);
    let (head, head_hits) = emit(&mut machine, line.as_bytes().get(..split).unwrap_or(&[])).await;
    let (tail, tail_hits) = emit_flushed(&mut machine, line.as_bytes().get(split..).unwrap_or(&[])).await;
    let mut out = head;
    out.extend_from_slice(&tail);
    let text = String::from_utf8(out).unwrap();
    assert!(head_hits.saturating_add(tail_hits) >= 1, "{text}");
    assert!(text.contains(FAKE_PASS), "{text}");
    assert!(!text.contains(LONG_REAL), "{text}");
    assert!(text.starts_with("535 "), "{text}");
  }

  #[tokio::test]
  async fn bdat_passes_exactly_n_bytes() {
    let mut machine = down();
    let (head, _) = emit(&mut machine, b"BDAT 5\r\nhe").await;
    assert_eq!(head, b"BDAT 5\r\nhe");
    let (tail, _) = emit(&mut machine, b"lloNOOP\r\n").await;
    assert_eq!(tail, b"lloNOOP\r\n");
    let (last, _) = emit(&mut machine, b"BDAT 0 LAST\r\n").await;
    assert_eq!(last, b"BDAT 0 LAST\r\n");
  }

  #[test]
  fn bdat_size_is_the_octet_count() {
    assert_eq!(bdat_octets(b"BDAT 5\r\n"), Some(5));
    assert_eq!(bdat_octets(b"bdat 0 LAST\r\n"), Some(0));
    assert_eq!(bdat_octets(b"BDAT\r\n"), None);
    assert_eq!(bdat_octets(b"BDAT LAST\r\n"), None);
    assert_eq!(bdat_octets(b"DATA\r\n"), None);
  }

  #[tokio::test]
  async fn a_command_split_across_chunks_rewrites_whole() {
    let mut machine = down();
    let line = format!("AUTH PLAIN {}\r\n", plain(FAKE_USER, FAKE_PASS));
    let (first, _) = emit(&mut machine, &line.as_bytes()[..8]).await;
    assert_eq!(first.as_slice(), b"");
    let (rest, hits) = emit(&mut machine, &line.as_bytes()[8..]).await;
    assert_eq!(hits, 1);
    assert_eq!(rest, format!("AUTH PLAIN {}\r\n", plain(REAL_USER, REAL_PASS)).into_bytes());
  }

  mod arbitrary {
    use super::*;
    use proptest::prelude::*;

    proptest! {
      #[test]
      fn arbitrary_bytes_do_not_panic(chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..80), 0..6)) {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
          let mut down = Smtp::new(&grant(FAKE_USER, REAL_USER), "mail", 587, Direction::Downstream);
          down.set_protected(true);
          let mut up_leg = Smtp::new(&grant(FAKE_USER, REAL_USER), "mail", 587, Direction::Upstream);
          Smtp::share_data_gate(&down, &mut up_leg);
          for chunk in &chunks {
            let _ = down.feed(chunk).await;
            let _ = up_leg.feed(chunk).await;
          }
          let _ = down.feed(&[]).await;
          let _ = up_leg.feed(&[]).await;
        });
      }
    }
  }
}
