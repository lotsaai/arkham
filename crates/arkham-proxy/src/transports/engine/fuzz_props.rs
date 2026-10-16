//! Property and fuzz tests: adversarial byte streams through the
//! substitution machines (HTTP, SMTP, LDAP, and AMQP), the SNI parser, and grant parsing.
//!
//! Two families:
//! - **Invariants** (valid framing, adversarial splits): a token split
//!   across any arrival boundary must recombine and substitute whole;
//!   fixed-length bodies must not drift; chunked output must re-parse.
//!   LDAP uses the same cut loop at 256 cases: one shot, random cuts, and
//!   one byte at a time must match, the real password must stay off the
//!   guest-bound leg, and every run ends with the empty EOF flush.
//! - **Crash resistance** (arbitrary bytes): no input, arrival split, or
//!   pipelining combination may panic or hang.
//!
//! Tests are sync: async machine entry points run on a current-thread
//! tokio runtime via `block_on` (no timers, no IO — the machines are
//! deterministic over the byte input alone).
use proptest::prelude::*;

use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

use arkham_config::grants::{Credential, Grant, GuestTlsMode, Scheme, SmtpLeg, SmtpScope};
use base64::Engine as _;
use secrecy::SecretString;

use crate::transports::smtp::{GuestLeg, MAX_COMMAND, Smtp, acceptance_reply, plain_guest};

use super::super::amqp::machine::MAX_CREDENTIAL_FRAME;
use super::{Amqp, Direction, Http, Ldap, Raw, Rewritten, Wire};
use crate::transports::http::h2::{H2, H2_PREFACE};

/// Needle decoy (request-direction needle) and its real value.
const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn grants() -> Vec<Grant> {
  vec![Grant::Token {
    credential: Credential {
      label: "github".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE),
    },
    allow: vec!["https://*".parse().expect("grant")],
    pattern: None,
    oauth2: None,
  }]
}

fn req_machine() -> Http {
  Http::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Downstream, None, None)
}

fn resp_machine() -> Http {
  Http::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Upstream, None, None)
}

fn h2_req_machine() -> H2 {
  H2::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Downstream, None, None)
}

fn h2_resp_machine() -> H2 {
  H2::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Upstream, None, None)
}

impl Rewritten<'_> {
  fn emit_bytes(self) -> Vec<u8> {
    match self {
      Self::Emit(bytes) => bytes.into_owned(),
      _ => Vec::new(),
    }
  }
}

fn block_on<F>(fut: F) -> F::Output
where
  F: std::future::Future,
{
  thread_local! {
    static RT: tokio::runtime::Runtime =
      tokio::runtime::Builder::new_current_thread().build().expect("test runtime");
  }
  RT.with(|rt| rt.block_on(fut))
}

/// Drain a machine over `splits` (ascending cuts into `data`, implied
/// final cut at `data.len()`), then one empty EOF flush. Concatenated
/// output, total hit count.
fn run_split<M: Wire>(m: &mut M, data: &[u8], splits: &[usize]) -> (Vec<u8>, usize) {
  let (out, hits, _) = run_split_parts(m, data, splits);
  (out, hits)
}

/// [`run_split`] plus whether any feed returned [`Rewritten::Close`].
fn run_split_parts<M: Wire>(m: &mut M, data: &[u8], splits: &[usize]) -> (Vec<u8>, usize, bool) {
  let mut out = Vec::new();
  let mut hits = 0;
  let mut prev = 0;
  let mut closed = false;
  for &cut in splits.iter().chain(std::iter::once(&data.len())) {
    // A relay only calls with non-empty chunks; an empty call is the
    // EOF flush. Skip cuts that would produce an interior empty call.
    if cut > prev {
      let (rewritten, chunk_hits) = block_on(m.feed(&data[prev..cut]));
      closed |= matches!(rewritten, Rewritten::Close);
      out.extend_from_slice(&rewritten.emit_bytes());
      hits += chunk_hits.len();
      prev = cut;
    }
  }
  if prev < data.len() {
    let (rewritten, chunk_hits) = block_on(m.feed(&data[prev..]));
    closed |= matches!(rewritten, Rewritten::Close);
    out.extend_from_slice(&rewritten.emit_bytes());
    hits += chunk_hits.len();
  }
  let (rewritten, chunk_hits) = block_on(m.feed(&[]));
  closed |= matches!(rewritten, Rewritten::Close);
  out.extend_from_slice(&rewritten.emit_bytes());
  hits += chunk_hits.len();
  (out, hits, closed)
}

/// Drain an H2 machine the same way.
fn run_split_h2<M: Wire>(m: &mut M, data: &[u8], splits: &[usize]) -> (Vec<u8>, usize) {
  run_split(m, data, splits)
}

/// One request head + fixed body with the needle spliced into `payload` at
/// `at`; body length is exact.
fn fixed_message(payload: &[u8], at: usize) -> Vec<u8> {
  let mut body = Vec::with_capacity(payload.len() + FAKE.len());
  body.extend_from_slice(&payload[..at]);
  body.extend_from_slice(FAKE.as_bytes());
  body.extend_from_slice(&payload[at..]);
  let head = format!("POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n", body.len());
  let mut out = head.into_bytes();
  out.extend_from_slice(&body);
  out
}

/// Chunked-encode `body` in `chunk`-sized pieces.
fn chunked_encode(body: &[u8], chunk: usize) -> Vec<u8> {
  let mut msg = Vec::new();
  let mut off = 0;
  while off < body.len() {
    let take = chunk.min(body.len() - off);
    msg.extend_from_slice(format!("{take:X}\r\n").as_bytes());
    msg.extend_from_slice(&body[off..off + take]);
    msg.extend_from_slice(b"\r\n");
    off += take;
  }
  msg.extend_from_slice(b"0\r\n\r\n");
  msg
}

/// Decode a chunked body (payload bytes only) from `msg[head_end..]`.
fn chunked_decode(msg: &[u8], head_end: usize) -> Option<Vec<u8>> {
  let mut got = Vec::new();
  let mut pos = head_end;
  loop {
    let rel = msg[pos..].windows(2).position(|w| w == b"\r\n")? + pos;
    let size_str = String::from_utf8_lossy(&msg[pos..rel]);
    let size = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("0"), 16).ok()?;
    pos = rel + 2;
    if size == 0 {
      return Some(got);
    }
    if msg.len() < pos + size + 2 {
      return None;
    }
    got.extend_from_slice(&msg[pos..pos + size]);
    pos += size + 2;
  }
}

/// H2 request preface + static-encoded HEADERS frame opening stream 1.
/// Indexed static-table fields only: :method POST (3), :path / (4).
fn h2_request_head() -> Vec<u8> {
  let block: &[u8] = &[0x83, 0x84];
  let mut out = H2_PREFACE.to_vec();
  append_h2_frame(&mut out, 0x1, 0x4, 1, block);
  out
}

/// H2 response HEADERS frame: indexed :status 200 (8) on stream 1.
fn h2_response_head() -> Vec<u8> {
  let mut out = Vec::new();
  append_h2_frame(&mut out, 0x1, 0x4, 1, &[0x88]);
  out
}

/// Append one H2 frame.
fn append_h2_frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
  let len = u32::try_from(payload.len()).expect("frame length fits u32");
  out.extend_from_slice(&len.to_be_bytes()[1..4]);
  out.push(kind);
  out.push(flags);
  out.extend_from_slice(&stream.to_be_bytes());
  out.extend_from_slice(payload);
}

fn collect_h2_data(out: &[u8]) -> Vec<u8> {
  let mut got = Vec::new();
  // Request-direction output starts with the echoed connection preface.
  let mut pos = if out.starts_with(H2_PREFACE) { H2_PREFACE.len() } else { 0 };
  while out.len() - pos >= 9 {
    let len = ((out[pos] as usize) << 16) | ((out[pos + 1] as usize) << 8) | out[pos + 2] as usize;
    if out.len() - pos < 9 + len {
      break;
    }
    if out[pos + 3] == 0x0 {
      got.extend_from_slice(&out[pos + 9..pos + 9 + len]);
    }
    pos += 9 + len;
  }
  got
}

fn h1_head_end(msg: &[u8]) -> usize {
  msg.windows(4).position(|w| w == b"\r\n\r\n").expect("head boundary") + 4
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(256))]

  /// Raw TCP: a needle split across any two arrivals recombines and
  /// substitutes whole; the fake never survives on the wire.
  #[test]
  fn prop_raw_split_token_substitutes_whole(
    pre in proptest::collection::vec(any::<u8>(), 0..64),
    suffix in proptest::collection::vec(any::<u8>(), 0..64),
  ) {
    let grants = vec![Grant::Token {

      credential: Credential {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE),
      },
      allow: vec!["tcp://*:1".parse().expect("grant")],
      pattern: None,
      oauth2: None,
    }];
    let mut m = Raw::new(&grants, Scheme::Tcp, "h", 1, Direction::Downstream);
    let mid = FAKE.len() / 2;
    let mut data = pre.clone();
    data.extend_from_slice(&FAKE.as_bytes()[..mid]);
    let mut splits = vec![data.len()];
    data.extend_from_slice(&FAKE.as_bytes()[mid..]);
    data.extend_from_slice(&suffix);
    splits.push(data.len());

    let (out, _) = run_split(&mut m, &data, &splits);
    prop_assert!(out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()), "token lost");
    prop_assert!(!out.windows(FAKE.len()).any(|w| w == FAKE.as_bytes()), "fake survived");
  }

  /// H1 fixed body: any split of the arrivals yields exactly the
  /// substituted body — same total length (framing preserved), token
  /// whole, fake gone.
  #[test]
  fn prop_h1_fixed_split_invariant(
    payload in proptest::collection::vec(0u8..0x80, 0..64),
    at in 0usize..64,
    cuts in proptest::collection::vec(0usize..160, 0..4),
  ) {
    let data = fixed_message(&payload, at.min(payload.len()));
    let head_len = h1_head_end(&data);
    let mut cuts: Vec<usize> = cuts.into_iter().map(|c| c.min(data.len())).collect();
    cuts.sort_unstable();
    let mut m = req_machine();
    let (out, _) = run_split(&mut m, &data, &cuts);
    prop_assert!(!m.must_close(), "equal-length swap must not fail closed");
    prop_assert_eq!(out.len(), data.len(), "fixed framing must not drift");
    prop_assert_eq!(&out[head_len..], [ &payload[..at.min(payload.len())], VALUE.as_bytes(), &payload[at.min(payload.len())..] ].concat());
    prop_assert!(!out.windows(FAKE.len()).any(|w| w == FAKE.as_bytes()), "fake leaked");
  }

  /// H1 chunked: any chunking of a needle-bearing body, fed through any
  /// arrival split, decodes back to exactly the substituted payload.
  #[test]
  fn prop_h1_chunked_roundtrip(
    payload in proptest::collection::vec(0u8..0x80, 0..256),
    at in 0usize..256,
    chunk in 1usize..64,
    cut in 0usize..600,
  ) {
    let mut body = Vec::with_capacity(payload.len() + FAKE.len());
    let at = at.min(payload.len());
    body.extend_from_slice(&payload[..at]);
    body.extend_from_slice(FAKE.as_bytes());
    body.extend_from_slice(&payload[at..]);
    let want: Vec<u8> = [&payload[..at], VALUE.as_bytes(), &payload[at..]].concat();
    let mut msg = b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    msg.extend_from_slice(&chunked_encode(&body, chunk));
    let head_end = h1_head_end(&msg);

    let mut m = req_machine();
    let (out, _) = run_split(&mut m, &msg, &[cut.min(msg.len())]);
    prop_assert!(!m.must_close(), "equal-length swap must not fail closed");
    let got = chunked_decode(&out, head_end).expect("valid chunked framing");
    prop_assert_eq!(got, want, "case: payload={:?} at={} chunk={} cut={}", payload, at, chunk, cut);
    prop_assert!(out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()), "token lost: case: payload={:?} at={} chunk={} cut={}", payload, at, chunk, cut);
    prop_assert!(!out.windows(FAKE.len()).any(|w| w == FAKE.as_bytes()), "fake leaked: case: payload={:?} at={} chunk={} cut={}", payload, at, chunk, cut);
  }

  /// H1 pipelining: two complete messages in one arrival (or split at any
  /// cut) both substitute — the spill loop must re-enter Head state
  /// cleanly, never drop or duplicate the boundary bytes.
  #[test]
  fn prop_h1_pipelined_messages_substitute(
    fill_a in proptest::collection::vec(0u8..0x80, 0..48),
    fill_b in proptest::collection::vec(0u8..0x80, 0..48),
    cut in 0usize..600,
  ) {
    let a_body = [fill_a.as_slice(), FAKE.as_bytes()].concat();
    let b_body = [FAKE.as_bytes(), fill_b.as_slice()].concat();
    let mut msg = format!("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n", a_body.len()).into_bytes();
    msg.extend_from_slice(&a_body);
    msg.extend_from_slice(format!("POST /b HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n", b_body.len()).as_bytes());
    msg.extend_from_slice(&b_body);

    let mut m = req_machine();
    let (out, _) = run_split(&mut m, &msg, &[cut.min(msg.len())]);
    prop_assert!(!m.must_close());
    prop_assert_eq!(out.len(), msg.len(), "pipelined framing must not drift");
    prop_assert_eq!(out.windows(FAKE.len()).filter(|w| *w == FAKE.as_bytes()).count(), 0, "fake leaked");
    // Both bodies substituted: two distinct VALUE occurrences on the wire.
    prop_assert_eq!(out.windows(VALUE.len()).filter(|w| *w == VALUE.as_bytes()).count(), 2, "case: fill_a={:?} fill_b={:?} cut={}", fill_a, fill_b, cut);
  }

  /// H1 chunked with chunk extensions: legal framing the parser must
  /// accept (size line split on `;`) while re-chunking without them.
  #[test]
  fn prop_h1_chunked_extensions_roundtrip(
    payload in proptest::collection::vec(0u8..0x80, 0..128),
    at in 0usize..128,
    cut in 0usize..400,
  ) {
    let at = at.min(payload.len());
    let body: Vec<u8> = [&payload[..at], FAKE.as_bytes(), &payload[at..]].concat();
    let want: Vec<u8> = [&payload[..at], VALUE.as_bytes(), &payload[at..]].concat();
    let mut msg = b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    let mut off = 0;
    while off < body.len() {
      let take = 7.min(body.len() - off);
      msg.extend_from_slice(format!("{take:X};q=1\r\n").as_bytes());
      msg.extend_from_slice(&body[off..off + take]);
      msg.extend_from_slice(b"\r\n");
      off += take;
    }
    msg.extend_from_slice(b"0\r\n\r\n");
    let head_end = h1_head_end(&msg);

    let mut m = req_machine();
    let (out, _) = run_split(&mut m, &msg, &[cut.min(msg.len())]);
    prop_assert!(!m.must_close());
    let got = chunked_decode(&out, head_end).expect("valid chunked framing");
    prop_assert_eq!(got, want, "case: payload={:?} at={} cut={}", payload, at, cut);
  }

  /// H1 close-delimited response: any split still redacts the whole
  /// needle at EOF.
  #[test]
  fn prop_h1_close_delimited_redacts_at_eof(
    payload in proptest::collection::vec(0u8..0x80, 0..64),
    at in 0usize..64,
    cut in 0usize..160,
  ) {
    let mut body = Vec::with_capacity(payload.len() + VALUE.len());
    let at = at.min(payload.len());
    body.extend_from_slice(&payload[..at]);
    body.extend_from_slice(VALUE.as_bytes());
    body.extend_from_slice(&payload[at..]);
    let mut msg = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n".to_vec();
    msg.extend_from_slice(&body);
    let head_end = h1_head_end(&msg);

    let mut m = resp_machine();
    let (out, _) = run_split(&mut m, &msg, &[cut.min(msg.len())]);
    prop_assert!(!m.must_close(), "redaction is equal-length; close is for scan-only leaks");
    prop_assert_eq!(&out[head_end..], [ &payload[..at], FAKE.as_bytes(), &payload[at..] ].concat());
    prop_assert!(!out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()), "real value leaked");
  }

  /// H2: needle-bearing body split across DATA frames at any frame size,
  /// fed through any arrival split — concatenated DATA payloads equal
  /// the substituted body, no needle sliced or leaked.
  #[test]
  fn prop_h2_data_split_invariant(
    payload in proptest::collection::vec(0u8..0x80, 0..256),
    at in 0usize..256,
    frame_len in 1usize..128,
    cuts in proptest::collection::vec(0usize..1200, 0..4),
  ) {
    let mut body = Vec::with_capacity(payload.len() + FAKE.len());
    let at = at.min(payload.len());
    body.extend_from_slice(&payload[..at]);
    body.extend_from_slice(FAKE.as_bytes());
    body.extend_from_slice(&payload[at..]);
    let want: Vec<u8> = [&payload[..at], VALUE.as_bytes(), &payload[at..]].concat();

    let mut msg = h2_request_head();
    let mut off = 0;
    loop {
      let take = frame_len.min(body.len().saturating_sub(off));
      let last = off + take >= body.len();
      let flags = u8::from(last);
      append_h2_frame(&mut msg, 0x0, flags, 1, &body[off..off + take]);
      off += take;
      if last {
        break;
      }
    }
    let mut cuts: Vec<usize> = cuts.into_iter().map(|c| c.min(msg.len())).collect();
    cuts.sort_unstable();

    let mut m = h2_req_machine();
    let (out, _) = run_split_h2(&mut m, &msg, &cuts);
    let got = collect_h2_data(&out);
    prop_assert_eq!(got, want, "case: payload={:?} at={} frame_len={} cuts={:?}", payload, at, frame_len, cuts);
    prop_assert!(!out.windows(FAKE.len()).any(|w| w == FAKE.as_bytes()), "fake leaked: case: payload={:?} at={} frame_len={} cuts={:?}", payload, at, frame_len, cuts);
  }

  /// H2 response leg: redaction holds for frames arriving whole or split.
  #[test]
  fn prop_h2_response_redacts_across_splits(
    payload in proptest::collection::vec(0u8..0x80, 0..128),
    at in 0usize..128,
    frame_len in 1usize..64,
    cut in 0usize..600,
  ) {
    let mut body = Vec::with_capacity(payload.len() + VALUE.len());
    let at = at.min(payload.len());
    body.extend_from_slice(&payload[..at]);
    body.extend_from_slice(VALUE.as_bytes());
    body.extend_from_slice(&payload[at..]);

    let mut msg = h2_response_head();
    let mut off = 0;
    loop {
      let take = frame_len.min(body.len().saturating_sub(off));
      let last = off + take >= body.len();
      let flags = u8::from(last);
      append_h2_frame(&mut msg, 0x0, flags, 1, &body[off..off + take]);
      off += take;
      if last {
        break;
      }
    }

    let mut m = h2_resp_machine();
    let (out, _) = run_split_h2(&mut m, &msg, &[cut.min(msg.len())]);
    let got = collect_h2_data(&out);
    let want: Vec<u8> = [&payload[..at], FAKE.as_bytes(), &payload[at..]].concat();
    prop_assert_eq!(got, want, "DATA payloads must equal the redacted body");
    prop_assert!(!out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()), "real value leaked");
  }

  /// Crash resistance, H1: arbitrary bytes on either leg through any
  /// single split — no panic, EOF flush terminates.
  #[test]
  fn prop_h1_arbitrary_no_panic(
    data in proptest::collection::vec(any::<u8>(), 0..1024),
    cut in 0usize..1024,
    dir in 0u8..2,
  ) {
    let mut m = if dir == 0 { req_machine() } else { resp_machine() };
    let _ = run_split(&mut m, &data, &[cut.min(data.len())]);
    let _ = m.must_close();
  }

  /// Crash resistance, H2: arbitrary bytes on either leg — preface
  /// mismatch degrades opaque, framing garbage never panics.
  #[test]
  fn prop_h2_arbitrary_no_panic(
    data in proptest::collection::vec(any::<u8>(), 0..1024),
    cut in 0usize..1024,
    dir in 0u8..2,
  ) {
    let mut m = if dir == 0 { h2_req_machine() } else { h2_resp_machine() };
    let _ = run_split_h2(&mut m, &data, &[cut.min(data.len())]);
    let _ = m.must_close();
  }

  /// Crash resistance, SNI: arbitrary bytes never panic the ClientHello
  /// walker.
  #[test]
  fn prop_sni_arbitrary_no_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
    let _ = crate::identity::hello_sni(&data);
  }

  /// Crash resistance, grants: arbitrary strings parse or reject
  /// cleanly, and a valid entry round-trips through matching.
  #[test]
  fn prop_grant_parse_no_panic(s in ".*") {
    if let Ok(scope) = s.parse::<arkham_config::grants::EndpointScope>() {
      let host = match &scope.host {
        arkham_config::grants::HostPat::Any => "anything.example".to_string(),
        arkham_config::grants::HostPat::Wildcard(pattern) => {
          let suffix = pattern.strip_prefix("*.").unwrap_or(pattern);
          format!("sub.{suffix}")
        }
        arkham_config::grants::HostPat::Exact(host) => host.clone(),
      };
      assert!(
        arkham_config::grants::uri_match(
          std::slice::from_ref(&scope),
          scope.scheme,
          &host,
          scope.port,
        ),
        "entry `{s}` must match the host its own pattern derives"
      );
    }
  }
}

const SMTP_FAKE_USER: &str = "guest@demo.test";
const SMTP_REAL_USER: &str = "owner@demo.test";

#[derive(Clone, Copy, Debug)]
enum SmtpMech {
  Plain,
  Login,
  Xoauth2,
  Bearer,
}

enum SmtpStep {
  Down(Vec<u8>),
  Up(Vec<u8>),
}

struct SmtpSession {
  steps: Vec<SmtpStep>,
  real: String,
  fake: String,
  /// Bytes the swapped AUTH must place on the upstream wire.
  swapped: Vec<u8>,
  /// AUTH line planted in the DATA body. It must pass unchanged.
  body_line: Vec<u8>,
  bdat: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Arrival<'a> {
  Whole,
  Cuts(&'a [usize]),
  Bytes,
}

fn smtp_b64(raw: &[u8]) -> String {
  base64::engine::general_purpose::STANDARD.encode(raw)
}

fn smtp_plain_token(user: &str, pass: &str) -> String {
  smtp_b64(format!("\0{user}\0{pass}").as_bytes())
}

fn smtp_xoauth_token(user: &str, pass: &str) -> String {
  smtp_b64(format!("user={user}\u{1}auth=Bearer {pass}\u{1}\u{1}").as_bytes())
}

fn smtp_bearer_token(user: &str, pass: &str) -> String {
  smtp_b64(format!("n,a={user},\u{1}host=mail\u{1}auth=Bearer {pass}\u{1}\u{1}").as_bytes())
}

fn smtp_line(text: &str) -> Vec<u8> {
  let mut out = text.as_bytes().to_vec();
  out.extend_from_slice(b"\r\n");
  out
}

fn smtp_grants(fake_pass: &str, real_pass: &str) -> Vec<Grant> {
  let scope = SmtpScope {
    downstream: SmtpLeg {
      host: "mail".into(),
      port: 587,
      user: SMTP_FAKE_USER.into(),
      password: SecretString::from(fake_pass),
    },
    is_downstream_tls: false,
    upstream: SmtpLeg {
      host: "mail".into(),
      port: 587,
      user: SMTP_REAL_USER.into(),
      password: SecretString::from(real_pass),
    },
    is_upstream_tls: false,
    starttls_required: true,
    root_cert: None,
    client_cert: None,
    client_key: None,
    guest_tls: GuestTlsMode::default(),
  };
  vec![Grant::Smtp {
    credential: Credential {
      label: "smtp".into(),
      fake: fake_pass.into(),
      value: SecretString::from(real_pass),
    },
    scope: Box::new(scope),
  }]
}

fn smtp_machines(fake_pass: &str, real_pass: &str) -> (Smtp, Smtp) {
  let grants = smtp_grants(fake_pass, real_pass);
  let mut down = Smtp::new(&grants, "mail", 587, Direction::Downstream);
  down.set_protected(true);
  let mut up = Smtp::new(&grants, "mail", 587, Direction::Upstream);
  Smtp::share_data_gate(&down, &mut up);
  (down, up)
}

fn smtp_count(hay: &[u8], needle: &[u8]) -> usize {
  if needle.is_empty() || hay.len() < needle.len() {
    return 0;
  }
  hay.windows(needle.len()).filter(|window| *window == needle).count()
}

fn smtp_contains(hay: &[u8], needle: &[u8]) -> bool {
  smtp_count(hay, needle) > 0
}

/// `q…` is the decoy and `z…` is the real password, so neither collides with SMTP verbs.
fn smtp_tagged(prefix: char, chars: &[char]) -> String {
  let mut out = String::with_capacity(chars.len().saturating_add(1));
  out.push(prefix);
  for ch in chars {
    out.push(*ch);
  }
  out
}

fn smtp_session(
  mech: SmtpMech,
  inline: bool,
  fake_chars: &[char],
  real_chars: &[char],
  body_len: usize,
  bdat_len: usize,
  multiline_354: bool,
) -> SmtpSession {
  let fake = smtp_tagged('q', fake_chars);
  let real = smtp_tagged('z', real_chars);
  let mut steps = Vec::new();
  steps.push(SmtpStep::Down(smtp_line("EHLO mail.example")));
  steps.push(SmtpStep::Up(smtp_line(&format!("250-{real}"))));
  steps.push(SmtpStep::Up(smtp_line("250 mail")));
  let swapped = smtp_auth_steps(&mut steps, mech, inline, &fake, &real);
  steps.push(SmtpStep::Up(smtp_line(&format!("535 5.7.8 {real}"))));
  steps.push(SmtpStep::Down(smtp_line("DATA")));
  if multiline_354 {
    steps.push(SmtpStep::Up(smtp_line("354-go")));
  }
  steps.push(SmtpStep::Up(smtp_line("354 go")));
  let body_line = smtp_line(&format!("AUTH PLAIN {}", smtp_plain_token(SMTP_FAKE_USER, &fake)));
  let mut body = vec![b'n'; body_len];
  body.extend_from_slice(&body_line);
  body.extend_from_slice(b".\r\n");
  steps.push(SmtpStep::Down(body));
  steps.push(SmtpStep::Up(smtp_line("250 queued")));
  let bdat = vec![0x7f; bdat_len];
  let mut bdat_step = smtp_line(&format!("BDAT {bdat_len}"));
  bdat_step.extend_from_slice(&bdat);
  bdat_step.extend_from_slice(&smtp_line("NOOP"));
  steps.push(SmtpStep::Down(bdat_step));
  SmtpSession {
    steps,
    real,
    fake,
    swapped,
    body_line,
    bdat,
  }
}

fn smtp_auth_steps(steps: &mut Vec<SmtpStep>, mech: SmtpMech, inline: bool, fake: &str, real: &str) -> Vec<u8> {
  let user_b64 = smtp_b64(SMTP_FAKE_USER.as_bytes());
  let pass_b64 = smtp_b64(fake.as_bytes());
  let real_user_b64 = smtp_b64(SMTP_REAL_USER.as_bytes());
  let real_pass_b64 = smtp_b64(real.as_bytes());
  match (mech, inline) {
    (SmtpMech::Plain, true) => {
      steps.push(SmtpStep::Down(smtp_line(&format!(
        "AUTH PLAIN {}",
        smtp_plain_token(SMTP_FAKE_USER, fake)
      ))));
      smtp_plain_token(SMTP_REAL_USER, real).into_bytes()
    }
    (SmtpMech::Plain, false) => {
      steps.push(SmtpStep::Down(smtp_line("AUTH PLAIN")));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&smtp_plain_token(SMTP_FAKE_USER, fake))));
      smtp_plain_token(SMTP_REAL_USER, real).into_bytes()
    }
    (SmtpMech::Login, true) => {
      steps.push(SmtpStep::Down(smtp_line(&format!("AUTH LOGIN {user_b64}"))));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&pass_b64)));
      format!("{real_user_b64}\r\n{real_pass_b64}").into_bytes()
    }
    (SmtpMech::Login, false) => {
      steps.push(SmtpStep::Down(smtp_line("AUTH LOGIN")));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&user_b64)));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&pass_b64)));
      format!("{real_user_b64}\r\n{real_pass_b64}").into_bytes()
    }
    (SmtpMech::Xoauth2, true) => {
      steps.push(SmtpStep::Down(smtp_line(&format!(
        "AUTH XOAUTH2 {}",
        smtp_xoauth_token(SMTP_FAKE_USER, fake)
      ))));
      smtp_xoauth_token(SMTP_REAL_USER, real).into_bytes()
    }
    (SmtpMech::Xoauth2, false) => {
      steps.push(SmtpStep::Down(smtp_line("AUTH XOAUTH2")));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&smtp_xoauth_token(SMTP_FAKE_USER, fake))));
      smtp_xoauth_token(SMTP_REAL_USER, real).into_bytes()
    }
    (SmtpMech::Bearer, true) => {
      steps.push(SmtpStep::Down(smtp_line(&format!(
        "AUTH OAUTHBEARER {}",
        smtp_bearer_token(SMTP_FAKE_USER, fake)
      ))));
      smtp_bearer_token(SMTP_REAL_USER, real).into_bytes()
    }
    (SmtpMech::Bearer, false) => {
      steps.push(SmtpStep::Down(smtp_line("AUTH OAUTHBEARER")));
      steps.push(SmtpStep::Up(smtp_line("334 go")));
      steps.push(SmtpStep::Down(smtp_line(&smtp_bearer_token(SMTP_FAKE_USER, fake))));
      smtp_bearer_token(SMTP_REAL_USER, real).into_bytes()
    }
  }
}

struct SmtpEmitted {
  down: Vec<u8>,
  up: Vec<u8>,
  closed: bool,
}

fn drive_smtp(session: &SmtpSession, arrival: Arrival<'_>) -> SmtpEmitted {
  let (mut down, mut up) = smtp_machines(&session.fake, &session.real);
  let mut emitted = SmtpEmitted {
    down: Vec::new(),
    up: Vec::new(),
    closed: false,
  };
  for step in &session.steps {
    let data = match step {
      SmtpStep::Down(bytes) | SmtpStep::Up(bytes) => bytes.as_slice(),
    };
    let splits = smtp_splits(data, arrival);
    let (bytes, _, closed) = match step {
      SmtpStep::Down(_) => run_split_parts(&mut down, data, &splits),
      SmtpStep::Up(_) => run_split_parts(&mut up, data, &splits),
    };
    match step {
      SmtpStep::Down(_) => emitted.down.extend_from_slice(&bytes),
      SmtpStep::Up(_) => emitted.up.extend_from_slice(&bytes),
    }
    emitted.closed |= closed;
    if emitted.closed {
      break;
    }
  }
  emitted
}

fn smtp_splits(data: &[u8], arrival: Arrival<'_>) -> Vec<usize> {
  match arrival {
    Arrival::Whole => Vec::new(),
    Arrival::Cuts(cuts) => {
      let mut points: Vec<usize> = cuts.iter().copied().filter(|cut| *cut > 0 && *cut < data.len()).collect();
      points.sort_unstable();
      points.dedup();
      points
    }
    Arrival::Bytes => (1..data.len()).collect(),
  }
}

fn smtp_first_diff(left: &[u8], right: &[u8]) -> Option<usize> {
  let shared = left.len().min(right.len());
  left
    .get(..shared)
    .unwrap_or(&[])
    .iter()
    .zip(right.get(..shared).unwrap_or(&[]))
    .position(|(lhs, rhs)| lhs != rhs)
    .or_else(|| (left.len() != right.len()).then_some(shared))
}

/// Greeting bytes and the index where `pass` starts.
/// `at` is an offset in the final line. `MAX_COMMAND - 4` places the
/// password after a command-sized prefix.
fn smtp_greeting(continuations: u8, at: usize, pass: &str) -> (Vec<u8>, usize) {
  let mut out = Vec::new();
  for _ in 0..continuations {
    out.extend_from_slice(b"220-wait\r\n");
  }
  let mut line = b"220 ".to_vec();
  if line.len() < at {
    line.resize(at, b'x');
  }
  let pass_at = out.len().saturating_add(line.len());
  line.extend_from_slice(pass.as_bytes());
  line.extend_from_slice(b"\r\n");
  out.extend_from_slice(&line);
  (out, pass_at)
}

struct SmtpOpening {
  code: Option<[u8; 3]>,
  guest: Vec<u8>,
  rest: Vec<u8>,
}

/// One reply stream. Each poll yields bytes up to the next cut, then
/// pends once before the following poll. The waker is woken so
/// `block_on` resumes.
struct CutPend {
  data: Vec<u8>,
  cuts: Vec<usize>,
  at: usize,
  reads: usize,
  pends: usize,
  arm_pend: bool,
}

impl CutPend {
  fn new(data: Vec<u8>, cuts: &[usize]) -> Self {
    let mut cuts: Vec<usize> = cuts.iter().copied().filter(|cut| *cut > 0 && *cut < data.len()).collect();
    cuts.sort_unstable();
    cuts.dedup();
    Self {
      data,
      cuts,
      at: 0,
      reads: 0,
      pends: 0,
      arm_pend: false,
    }
  }
}

impl AsyncRead for CutPend {
  fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    if self.arm_pend {
      self.arm_pend = false;
      self.pends = self.pends.saturating_add(1);
      cx.waker().wake_by_ref();
      return Poll::Pending;
    }
    if buf.remaining() == 0 {
      return Poll::Ready(Ok(()));
    }
    let Some(rest) = self.data.get(self.at..) else {
      return Poll::Ready(Ok(()));
    };
    if rest.is_empty() {
      return Poll::Ready(Ok(()));
    }
    let end = self.cuts.iter().copied().find(|cut| *cut > self.at).unwrap_or(self.data.len());
    let n = end.saturating_sub(self.at).min(buf.remaining());
    if n == 0 {
      return Poll::Ready(Err(std::io::Error::other("reply cut produced an empty read")));
    }
    let Some(chunk) = rest.get(..n) else {
      return Poll::Ready(Ok(()));
    };
    buf.put_slice(chunk);
    self.at = self.at.saturating_add(n);
    self.reads = self.reads.saturating_add(1);
    self.arm_pend = self.at < self.data.len();
    Poll::Ready(Ok(()))
  }
}

fn smtp_read_opening(up: &mut Smtp, reader: &mut CutPend, lead: &[u8]) -> Result<SmtpOpening, crate::Error> {
  block_on(async {
    let mut guest = plain_guest(Cursor::new(Vec::new()));
    let done = acceptance_reply(reader, up, &mut guest, lead).await?;
    let guest = match guest {
      GuestLeg::Plain(cursor) => cursor.into_inner(),
      GuestLeg::Tls(_) => Vec::new(),
    };
    Ok(SmtpOpening {
      code: done.code,
      guest,
      rest: done.rest,
    })
  })
}

fn smtp_feed_reply(fake: &str, real: &str, greet: &[u8], arrival: Arrival<'_>) -> (Vec<u8>, bool) {
  let grants = smtp_grants(fake, real);
  let mut up = Smtp::new(&grants, "mail", 587, Direction::Upstream);
  let splits = smtp_splits(greet, arrival);
  let (out, _, closed) = run_split_parts(&mut up, greet, &splits);
  (out, closed)
}

fn smtp_distinct(fake: &[char], real: &[char]) -> bool {
  let fake = smtp_tagged('q', fake);
  let real = smtp_tagged('z', real);
  fake != real && !fake.contains(real.as_str()) && !real.contains(fake.as_str())
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(256))]

  /// AUTH, a multiline reply, DATA, and BDAT survive every arrival split
  /// from [`run_split`]. The real password is absent from guest-bound bytes.
  /// It may be shorter or longer than the decoy.
  #[test]
  fn prop_session_chunks_match_and_hide_the_real_password(
    mech in prop_oneof![Just(SmtpMech::Plain), Just(SmtpMech::Login), Just(SmtpMech::Xoauth2), Just(SmtpMech::Bearer)],
    inline in any::<bool>(),
    fake_chars in proptest::collection::vec(prop::char::range('a', 'z'), 6..12),
    real_chars in prop_oneof![
      proptest::collection::vec(prop::char::range('a', 'z'), 3..6),
      proptest::collection::vec(prop::char::range('a', 'z'), 16..28),
    ],
    body_len in 0usize..12,
    bdat_len in 0usize..12,
    multiline_354 in any::<bool>(),
    cuts in proptest::collection::vec(0usize..480, 0..5),
  ) {
    prop_assume!(smtp_distinct(&fake_chars, &real_chars));
    let session = smtp_session(mech, inline, &fake_chars, &real_chars, body_len, bdat_len, multiline_354);
    let whole = drive_smtp(&session, Arrival::Whole);
    let split = drive_smtp(&session, Arrival::Cuts(&cuts));
    let bytes = drive_smtp(&session, Arrival::Bytes);
    prop_assert!(!whole.closed && !split.closed && !bytes.closed, "a generated session closed the machine");
    prop_assert_eq!(smtp_first_diff(&whole.down, &split.down), None, "downstream split diverged, lens {} {}", whole.down.len(), split.down.len());
    prop_assert_eq!(smtp_first_diff(&whole.up, &split.up), None, "upstream split diverged, lens {} {}", whole.up.len(), split.up.len());
    prop_assert_eq!(smtp_first_diff(&whole.down, &bytes.down), None, "downstream bytes diverged, lens {} {}", whole.down.len(), bytes.down.len());
    prop_assert_eq!(smtp_first_diff(&whole.up, &bytes.up), None, "upstream bytes diverged, lens {} {}", whole.up.len(), bytes.up.len());
    let real = session.real.as_bytes();
    let fake = session.fake.as_bytes();
    prop_assert!(!whole.up.windows(real.len()).any(|window| window == real), "real password reached the guest");
    prop_assert!(!split.up.windows(real.len()).any(|window| window == real), "real password reached the guest on a split");
    prop_assert!(!bytes.up.windows(real.len()).any(|window| window == real), "real password reached the guest one byte at a time");
    prop_assert_eq!(smtp_count(&whole.up, fake), 2, "both reply copies of the password should become the decoy");
    prop_assert!(smtp_contains(&whole.down, &session.swapped), "AUTH did not swap onto the upstream wire");
    prop_assert!(smtp_contains(&whole.down, &session.body_line), "DATA body was rewritten");
    prop_assert!(session.bdat.is_empty() || smtp_contains(&whole.down, &session.bdat), "BDAT octets were dropped");
  }
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(256))]

  /// A reply cut at any offset is still one opening reply. The reader
  /// splits at those cuts and pends between them. Bytes after the final
  /// newline are the next read.
  #[test]
  fn prop_reply_cut_keeps_the_opening_in_sync(
    fake_chars in proptest::collection::vec(prop::char::range('a', 'z'), 6..10),
    real_chars in prop_oneof![
      proptest::collection::vec(prop::char::range('a', 'z'), 3..6),
      proptest::collection::vec(prop::char::range('a', 'z'), 16..24),
    ],
    continuations in 0u8..3,
    small_pad in 0usize..24,
    straddling in any::<bool>(),
    cuts in proptest::collection::vec(0usize..20_000, 0..4),
  ) {
    prop_assume!(smtp_distinct(&fake_chars, &real_chars));
    let fake = smtp_tagged('q', &fake_chars);
    let real = smtp_tagged('z', &real_chars);
    let at = if straddling { MAX_COMMAND.saturating_sub(4) } else { 4usize.saturating_add(small_pad) };
    let (greet, pass_at) = smtp_greeting(continuations, at, &real);
    let line_cut = pass_at.saturating_sub(at).saturating_add(MAX_COMMAND);
    prop_assume!(pass_at < greet.len());
    let mut cuts = cuts;
    cuts.push(line_cut);
    cuts.push(pass_at);
    cuts.push(pass_at.saturating_add(1));

    let (whole, whole_closed) = smtp_feed_reply(&fake, &real, &greet, Arrival::Whole);
    let (split, split_closed) = smtp_feed_reply(&fake, &real, &greet, Arrival::Cuts(&cuts));
    let (bytes, bytes_closed) = smtp_feed_reply(&fake, &real, &greet, Arrival::Bytes);
    let (mut down, mut up) = smtp_machines(&fake, &real);
    prop_assert!(!whole_closed && !split_closed && !bytes_closed, "the reply closed the upstream machine");
    prop_assert_eq!(smtp_first_diff(&whole, &split), None, "reply split diverged at the cut");
    prop_assert_eq!(smtp_first_diff(&whole, &bytes), None, "reply bytes diverged");
    prop_assert!(!whole.windows(real.len()).any(|window| window == real.as_bytes()), "real password survived a whole reply");
    prop_assert!(!split.windows(real.len()).any(|window| window == real.as_bytes()), "real password survived a cut");
    prop_assert!(!bytes.windows(real.len()).any(|window| window == real.as_bytes()), "real password survived one-byte reads");
    prop_assert!(whole.windows(fake.len()).any(|window| window == fake.as_bytes()), "the decoy did not replace the password");

    let mut stream = greet.clone();
    stream.extend_from_slice(b"250 ok\r\n");
    let mut reader = CutPend::new(stream, &cuts);
    let first = smtp_read_opening(&mut up, &mut reader, &[]).expect("greeting");
    prop_assert!(!reader.cuts.is_empty(), "the greeting had no interior cut");
    prop_assert!(
      reader.pends >= 1,
      "reply reader pends {}, reads {}",
      reader.pends,
      reader.reads
    );
    prop_assert_eq!(first.code, Some(*b"220"), "the final line decides the opening");
    prop_assert!(!first.guest.windows(6).any(|window| window == b"250 ok"), "the next reply was written with the greeting");
    prop_assert!(!first.guest.windows(real.len()).any(|window| window == real.as_bytes()), "guest saw the real password");
    prop_assert!(first.guest.windows(fake.len()).any(|window| window == fake.as_bytes()), "guest missed the decoy");
    prop_assert_eq!(&first.guest, &whole, "reader chunks diverged from one feed");
    let second = smtp_read_opening(&mut up, &mut reader, &first.rest).expect("next reply");
    prop_assert_eq!(second.code, Some(*b"250"), "the following reply was no longer in sync");
    prop_assert!(second.guest.windows(6).any(|window| window == b"250 ok"), "the following reply was dropped");

    let mut closed = false;
    let (_, _, data_closed) = run_split_parts(&mut down, b"DATA\r\n", &[]);
    closed |= data_closed;
    let (_, _, reply_closed) = run_split_parts(&mut up, b"354 go\r\n", &[]);
    closed |= reply_closed;
    let mut body = b"AUTH PLAIN ".to_vec();
    body.extend_from_slice(smtp_plain_token(SMTP_FAKE_USER, &fake).as_bytes());
    body.extend_from_slice(b"\r\n.\r\n");
    let (data_out, _, body_closed) = run_split_parts(&mut down, &body, &[]);
    closed |= body_closed;
    let body_marker = smtp_plain_token(SMTP_FAKE_USER, &fake);
    prop_assert!(!closed, "DATA after the opening closed the machine");
    prop_assert!(data_out.windows(body_marker.len()).any(|window| window == body_marker.as_bytes()), "DATA after the opening was parsed as AUTH");
  }
}

/// LDAP decoy and real simple-bind passwords. Lengths differ on purpose.
const LDAP_FAKE: &str = "arkham_fake_ldap_pass"; // betterleaks:allow
const LDAP_REAL: &str = "arkham_real_ldap_pass_01"; // betterleaks:allow
const LDAP_DN: &str = "cn=Directory Manager";
const LDAP_STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

/// One direction the LDAP properties drive. Guest-bound output is [`LdapLeg::Up`].
#[derive(Clone, Copy, Debug)]
enum LdapLeg {
  DownSwap,
  DownClear,
  Up,
}

fn ldap_grants() -> Vec<Grant> {
  let user = LDAP_DN.replace('=', "%3D").replace(' ', "%20").replace(',', "%2C");
  let fake = format!("ldap://{user}:{LDAP_FAKE}@ldap:389");
  let real = format!("ldap://{user}:{LDAP_REAL}@ldap:389");
  let scope = arkham_config::grants::LdapScope::from_strings(&fake, &real).expect("ldap scope");
  vec![Grant::Ldap {
    credential: Credential {
      label: "ldap".into(),
      fake: LDAP_FAKE.into(),
      value: secrecy::SecretString::from(LDAP_REAL),
    },
    scope: Box::new(scope),
  }]
}

fn ldap_leg(leg: LdapLeg) -> Ldap {
  let grants = ldap_grants();
  match leg {
    LdapLeg::DownSwap => Ldap::new(&grants, "ldap", 389, Direction::Downstream, true),
    LdapLeg::DownClear => Ldap::new(&grants, "ldap", 389, Direction::Downstream, false),
    LdapLeg::Up => Ldap::new(&grants, "ldap", 389, Direction::Upstream, false),
  }
}

fn ldap_expecting(id: u32) -> Ldap {
  let mut machine = ldap_leg(LdapLeg::Up);
  machine.expect_starttls(id);
  machine
}

struct LdapFed {
  out: Vec<u8>,
  closed: bool,
  starttls: Option<bool>,
}

/// Drain an LDAP cursor the way [`run_split`] drains HTTP, then one empty EOF flush.
///
/// A finished message already released a held needle suffix. EOF still runs
/// `finish`: it emits a suffix that release left behind, and it closes a
/// partial message.
fn run_ldap(mut machine: Ldap, data: &[u8], splits: &[usize]) -> LdapFed {
  let mut out = Vec::new();
  let mut closed = false;
  let mut prev = 0usize;
  for &cut in splits.iter().chain(std::iter::once(&data.len())) {
    if cut > prev && cut <= data.len() {
      let (rewritten, _) = block_on(machine.feed(&data[prev..cut]));
      match rewritten {
        Rewritten::Emit(bytes) => out.extend_from_slice(&bytes),
        Rewritten::Hold => {}
        Rewritten::Close => closed = true,
      }
      prev = cut;
    }
  }
  let (rewritten, _) = block_on(machine.feed(&[]));
  match rewritten {
    Rewritten::Emit(bytes) => out.extend_from_slice(&bytes),
    Rewritten::Hold => {}
    Rewritten::Close => closed = true,
  }
  LdapFed {
    out,
    closed,
    starttls: machine.take_starttls_result(),
  }
}

fn ldap_splits_match(machine: impl Fn() -> Ldap, data: &[u8], cuts: &[usize]) -> Result<(), TestCaseError> {
  let once = run_ldap(machine(), data, &[]);
  let split = run_ldap(machine(), data, cuts);
  let byte_cuts: Vec<usize> = (1..data.len()).collect();
  let byte = run_ldap(machine(), data, &byte_cuts);
  prop_assert_eq!(&once.out, &split.out);
  prop_assert_eq!(&once.out, &byte.out);
  prop_assert_eq!(once.closed, split.closed);
  prop_assert_eq!(once.closed, byte.closed);
  prop_assert_eq!(once.starttls, split.starttls);
  prop_assert_eq!(once.starttls, byte.starttls);
  prop_assert!(!once.closed);
  Ok(())
}

fn ldap_contains(hay: &[u8], needle: &[u8]) -> bool {
  !needle.is_empty() && hay.len() >= needle.len() && hay.windows(needle.len()).any(|window| window == needle)
}

fn ber_len(len: usize) -> Vec<u8> {
  if len < 0x80 {
    return vec![u8::try_from(len).expect("short length")];
  }
  if len <= 0xff {
    return vec![0x81, u8::try_from(len).expect("one-byte length")];
  }
  let len = u16::try_from(len).expect("two-byte length");
  vec![
    0x82,
    u8::try_from(len >> 8).expect("length high"),
    u8::try_from(len & 0xff).expect("length low"),
  ]
}

fn ber_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(content.len().saturating_add(3));
  out.push(tag);
  out.extend(ber_len(content.len()));
  out.extend_from_slice(content);
  out
}

fn ldap_message(id: u32, op: rasn_ldap::ProtocolOp) -> Vec<u8> {
  rasn::ber::encode(&rasn_ldap::LdapMessage::new(id, op)).expect("ldap frame")
}

fn ldap_bind(id: u32, password: &str) -> Vec<u8> {
  ldap_message(
    id,
    rasn_ldap::ProtocolOp::BindRequest(rasn_ldap::BindRequest::new(
      3,
      rasn_ldap::LdapString::from(LDAP_DN),
      rasn_ldap::AuthenticationChoice::Simple(rasn::prelude::OctetString::from(password.as_bytes())),
    )),
  )
}

fn ldap_bind_response(id: u32, diagnostic: &str) -> Vec<u8> {
  ldap_message(
    id,
    rasn_ldap::ProtocolOp::BindResponse(rasn_ldap::BindResponse::new(
      rasn_ldap::ResultCode::InvalidCredentials,
      rasn_ldap::LdapString::from(""),
      rasn_ldap::LdapString::from(diagnostic),
      None,
      None,
    )),
  )
}

fn ldap_starttls_response(id: u32) -> Vec<u8> {
  ldap_message(
    id,
    rasn_ldap::ProtocolOp::ExtendedResp(rasn_ldap::ExtendedResponse {
      result_code: rasn_ldap::ResultCode::Success,
      matched_dn: rasn_ldap::LdapString::from(""),
      diagnostic_message: rasn_ldap::LdapString::from(""),
      referral: None,
      response_name: Some(rasn::prelude::OctetString::from_static(LDAP_STARTTLS_OID)),
      response_value: None,
    }),
  )
}

fn ldap_wide(id: &[u8], tail: &[u8]) -> Vec<u8> {
  let mut content = ber_tlv(0x02, id);
  content.extend_from_slice(tail);
  ber_tlv(0x30, &content)
}

fn ldap_forwarded(id: u8, payload: &[u8]) -> Vec<u8> {
  let mut content = ber_tlv(0x02, &[id]);
  content.extend(ber_tlv(0x64, payload));
  ber_tlv(0x30, &content)
}

/// Text that cannot spell either LDAP password. Both start with `a`.
fn ldap_plain() -> impl Strategy<Value = String> {
  proptest::string::string_regex("[b-z]{0,8}").expect("plain text")
}

fn ldap_safe_message() -> impl Strategy<Value = Vec<u8>> {
  prop_oneof![
    (1u8..=127).prop_map(|id| ldap_bind(u32::from(id), LDAP_FAKE)),
    (1u8..=127).prop_map(|id| ldap_bind(u32::from(id), "guest-pass")),
    (1u8..=127, ldap_plain()).prop_map(|(id, text)| ldap_bind_response(u32::from(id), &text)),
    (1u8..=127).prop_map(|id| ldap_bind_response(u32::from(id), &format!("rejected {LDAP_REAL}"))),
    (1u8..=127, 1usize..LDAP_REAL.len()).prop_map(|(id, k)| {
      let prefix = LDAP_REAL.get(..k).unwrap_or(LDAP_REAL);
      ldap_bind_response(u32::from(id), prefix)
    }),
    (
      proptest::collection::vec(any::<u8>(), 5..=8),
      proptest::collection::vec(any::<u8>(), 0..16)
    )
      .prop_map(|(id, tail)| ldap_wide(&id, &tail)),
    (1u8..=127).prop_map(|id| ldap_starttls_response(u32::from(id))),
  ]
}

#[derive(Clone, Debug)]
enum LdapSecret {
  Diagnostic { id: u8, pad: String },
  Body { id: u8, pre: Vec<u8>, post: Vec<u8> },
  Wide { id: Vec<u8>, pre: Vec<u8>, post: Vec<u8> },
}

fn ldap_secret_frame(place: &LdapSecret) -> Vec<u8> {
  match place {
    LdapSecret::Diagnostic { id, pad } => ldap_bind_response(u32::from(*id), &format!("{pad}{LDAP_REAL}")),
    LdapSecret::Body { id, pre, post } => {
      let mut payload = Vec::with_capacity(pre.len().saturating_add(LDAP_REAL.len()).saturating_add(post.len()));
      payload.extend_from_slice(pre);
      payload.extend_from_slice(LDAP_REAL.as_bytes());
      payload.extend_from_slice(post);
      ldap_forwarded(*id, &payload)
    }
    LdapSecret::Wide { id, pre, post } => {
      let mut tail = Vec::with_capacity(pre.len().saturating_add(LDAP_REAL.len()).saturating_add(post.len()));
      tail.extend_from_slice(pre);
      tail.extend_from_slice(LDAP_REAL.as_bytes());
      tail.extend_from_slice(post);
      ldap_wide(id, &tail)
    }
  }
}

/// A proper prefix of an accepted frame is not idle. EOF must close it, and
/// every cut must agree on the bytes emitted before that close.
fn ldap_truncated_closes_alike(machine: impl Fn() -> Ldap, data: &[u8], cuts: &[usize]) -> Result<(), TestCaseError> {
  let once = run_ldap(machine(), data, &[]);
  let split = run_ldap(machine(), data, cuts);
  let byte_cuts: Vec<usize> = (1..data.len()).collect();
  let byte = run_ldap(machine(), data, &byte_cuts);
  prop_assert!(once.closed);
  prop_assert_eq!(once.closed, split.closed);
  prop_assert_eq!(once.closed, byte.closed);
  prop_assert_eq!(&once.out, &split.out);
  prop_assert_eq!(&once.out, &byte.out);
  Ok(())
}

fn ldap_hides_real(data: &[u8], cuts: &[usize]) -> Result<(), TestCaseError> {
  let once = run_ldap(ldap_leg(LdapLeg::Up), data, &[]);
  let split = run_ldap(ldap_leg(LdapLeg::Up), data, cuts);
  let byte_cuts: Vec<usize> = (1..data.len()).collect();
  let byte = run_ldap(ldap_leg(LdapLeg::Up), data, &byte_cuts);
  for out in [&once.out, &split.out, &byte.out] {
    prop_assert!(!ldap_contains(out, LDAP_REAL.as_bytes()));
  }
  Ok(())
}

#[test]
fn ldap_truncated_prefix_closes_on_eof_for_every_cut() {
  let frame = ldap_bind_response(1, "invalid");
  let prefix = &frame[..frame.len() - 1];
  let once = run_ldap(ldap_leg(LdapLeg::Up), prefix, &[]);
  assert!(once.closed, "a partial LDAP message must close on EOF");
  let byte_cuts: Vec<usize> = (1..prefix.len()).collect();
  let byte = run_ldap(ldap_leg(LdapLeg::Up), prefix, &byte_cuts);
  assert_eq!(once.closed, byte.closed);
  assert_eq!(once.out, byte.out);
}

const AMQP_FAKE: &str = "arkham_fake_amqp_pass"; // betterleaks:allow
const AMQP_REAL: &str = "arkham_real_amqp_pass_longer_01"; // betterleaks:allow
const AMQP_HEADER_091: &[u8] = b"AMQP\x00\x00\x09\x01";
const AMQP_HEADER_SASL: &[u8] = b"AMQP\x03\x01\x00\x00";
const AMQP_HEADER_10: &[u8] = b"AMQP\x00\x01\x00\x00";

#[derive(Clone, Copy, Debug)]
enum AmqpLeg {
  DownSwap,
  DownClear,
  Up,
}

fn amqp_leg(leg: AmqpLeg) -> Amqp {
  let real_scheme = if matches!(leg, AmqpLeg::DownClear) { "amqp" } else { "amqps" };
  let scope = arkham_config::grants::AmqpScope::from_strings(
    &format!("amqp://agent:{AMQP_FAKE}@mq:5672"),
    &format!("{real_scheme}://svc:{AMQP_REAL}@mq:5672"),
  )
  .expect("amqp scope");
  let grants = vec![Grant::Amqp {
    credential: Credential {
      label: "amqp".into(),
      fake: AMQP_FAKE.into(),
      value: secrecy::SecretString::from(AMQP_REAL),
    },
    scope: Box::new(scope),
  }];
  match leg {
    AmqpLeg::DownSwap => Amqp::new(&grants, "mq", 5672, Direction::Downstream, true),
    AmqpLeg::DownClear => Amqp::new(&grants, "mq", 5672, Direction::Downstream, false),
    AmqpLeg::Up => Amqp::new(&grants, "mq", 5672, Direction::Upstream, false),
  }
}

fn run_amqp(leg: AmqpLeg, data: &[u8], cuts: &[usize]) -> (Vec<u8>, bool) {
  let mut sorted = cuts.to_vec();
  sorted.sort_unstable();
  let (out, _, closed) = run_split_parts(&mut amqp_leg(leg), data, &sorted);
  (out, closed)
}

fn amqp_splits_match(leg: AmqpLeg, data: &[u8], cuts: &[usize]) -> Result<(Vec<u8>, bool), TestCaseError> {
  let once = run_amqp(leg, data, &[]);
  let split = run_amqp(leg, data, cuts);
  let byte_cuts: Vec<usize> = (1..data.len()).collect();
  let byte = run_amqp(leg, data, &byte_cuts);
  prop_assert_eq!(&once, &split);
  prop_assert_eq!(&once, &byte);
  Ok(once)
}

fn amqp_091(frame: &amq_protocol::frame::AMQPFrame) -> Vec<u8> {
  let written = amq_protocol::frame::gen_frame(frame)(amq_protocol::frame::WriteContext::from(Vec::new())).expect("0-9-1 frame");
  written.into_inner().0
}

fn amqp_plain(password: &str) -> Vec<u8> {
  format!("\0agent\0{password}").into_bytes()
}

fn amqp_start_ok(mechanism: &str, response: &[u8]) -> Vec<u8> {
  use amq_protocol::protocol::{AMQPClass, connection};
  amqp_091(&amq_protocol::frame::AMQPFrame::Method(
    0,
    AMQPClass::Connection(connection::AMQPMethod::StartOk(connection::StartOk {
      client_properties: amq_protocol::types::FieldTable::default(),
      mechanism: mechanism.into(),
      response: response.to_vec().into(),
      locale: "en_US".into(),
    })),
  ))
}

fn amqp_close_091(on_channel: bool, text: &str) -> Vec<u8> {
  use amq_protocol::protocol::{AMQPClass, channel, connection};
  let class = if on_channel {
    AMQPClass::Channel(channel::AMQPMethod::Close(channel::Close {
      reply_code: 403,
      reply_text: text.into(),
      class_id: 20,
      method_id: 10,
    }))
  } else {
    AMQPClass::Connection(connection::AMQPMethod::Close(connection::Close {
      reply_code: 403,
      reply_text: text.into(),
      class_id: 10,
      method_id: 11,
    }))
  };
  amqp_091(&amq_protocol::frame::AMQPFrame::Method(u16::from(on_channel), class))
}

fn amqp_oversize_method(class: u16, method: u16) -> Vec<u8> {
  let payload = MAX_CREDENTIAL_FRAME;
  let mut frame = Vec::with_capacity(payload.saturating_add(8));
  frame.push(1);
  frame.extend_from_slice(&0u16.to_be_bytes());
  frame.extend_from_slice(&u32::try_from(payload).expect("payload").to_be_bytes());
  frame.extend_from_slice(&class.to_be_bytes());
  frame.extend_from_slice(&method.to_be_bytes());
  frame.resize(payload.saturating_add(7), b'b');
  frame.push(0xCE);
  frame
}

fn amqp_oversize_performative(frame_type: u8, code: u8) -> Vec<u8> {
  let total = MAX_CREDENTIAL_FRAME.saturating_add(8);
  let mut frame = Vec::with_capacity(total);
  frame.extend_from_slice(&u32::try_from(total).expect("size").to_be_bytes());
  frame.extend([2, frame_type, 0, 0]);
  frame.extend([0x00, 0x53, code]);
  frame.resize(total, b'b');
  frame
}

fn amqp_oversize_clean(leg: AmqpLeg, sasl: bool, on_channel: bool) -> Vec<u8> {
  match (leg, sasl) {
    (AmqpLeg::Up, false) => amqp_oversize_method(if on_channel { 20 } else { 10 }, if on_channel { 40 } else { 50 }),
    (AmqpLeg::Up, true) => {
      let mut out = AMQP_HEADER_10.to_vec();
      out.extend(amqp_oversize_performative(0, 0x18));
      out
    }
    (_, false) => {
      let mut out = AMQP_HEADER_091.to_vec();
      out.extend(amqp_oversize_method(10, 11));
      out
    }
    (_, true) => {
      let mut out = AMQP_HEADER_SASL.to_vec();
      out.extend(amqp_oversize_performative(1, 0x41));
      out
    }
  }
}

fn amqp_10(frame_type: u8, body: &[u8]) -> Vec<u8> {
  let size = u32::try_from(body.len().saturating_add(8)).expect("1.0 frame size");
  let mut out = size.to_be_bytes().to_vec();
  out.extend([2, frame_type, 0, 0]);
  out.extend_from_slice(body);
  out
}

fn amqp_sasl_init(mechanism: &str, response: Option<Vec<u8>>) -> Vec<u8> {
  let init = fe2o3_amqp_types::sasl::SaslInit {
    mechanism: mechanism.into(),
    initial_response: response.map(fe2o3_amqp_types::primitives::Binary::from),
    hostname: Some("mq".into()),
  };
  amqp_10(1, &serde_amqp::to_vec(&init).expect("sasl-init"))
}

fn amqp_sasl_response(response: Vec<u8>) -> Vec<u8> {
  let response = fe2o3_amqp_types::sasl::SaslResponse {
    response: fe2o3_amqp_types::primitives::Binary::from(response),
  };
  amqp_10(1, &serde_amqp::to_vec(&response).expect("sasl-response"))
}

fn amqp_sasl_outcome() -> Vec<u8> {
  let outcome = fe2o3_amqp_types::sasl::SaslOutcome {
    code: fe2o3_amqp_types::sasl::SaslCode::Ok,
    additional_data: None,
  };
  amqp_10(1, &serde_amqp::to_vec(&outcome).expect("sasl-outcome"))
}

#[derive(Clone, Copy, Debug)]
enum AmqpErrorFrame {
  Close,
  End,
  Detach,
}

fn amqp_error_10(frame: AmqpErrorFrame, description: &str) -> Vec<u8> {
  use fe2o3_amqp_types::definitions::{AmqpError, Error, Handle};
  use fe2o3_amqp_types::performatives::{Close, Detach, End};
  let error = Some(Error {
    condition: AmqpError::UnauthorizedAccess.into(),
    description: Some(description.into()),
    info: None,
  });
  let body = match frame {
    AmqpErrorFrame::Close => serde_amqp::to_vec(&Close { error }),
    AmqpErrorFrame::End => serde_amqp::to_vec(&End { error }),
    AmqpErrorFrame::Detach => serde_amqp::to_vec(&Detach {
      handle: Handle(0),
      closed: true,
      error,
    }),
  };
  amqp_10(0, &body.expect("1.0 error performative"))
}

fn amqp_transfer_10(payload: &[u8]) -> Vec<u8> {
  let mut body = vec![0x00, 0x53, 0x14];
  body.extend_from_slice(payload);
  amqp_10(0, &body)
}

fn splice_symbol(body: &[u8], name: &str, wide: bool) -> Vec<u8> {
  assert!(body.len() >= 3 && body[0] == 0x00 && body[1] == 0x53, "numeric descriptor");
  let mut out = Vec::with_capacity(body.len().saturating_add(name.len()));
  out.push(0x00);
  let bytes = name.as_bytes();
  if wide {
    out.push(0xb3);
    out.extend(u32::try_from(bytes.len()).expect("symbol length").to_be_bytes());
  } else {
    out.push(0xa3);
    out.push(u8::try_from(bytes.len()).expect("symbol8 length"));
  }
  out.extend_from_slice(bytes);
  out.extend_from_slice(&body[3..]);
  out
}

fn splice_frame_symbol(frame: &[u8], name: &str, wide: bool) -> Vec<u8> {
  let body = frame.get(8..).expect("1.0 body");
  let mut out = frame.get(..8).expect("1.0 head").to_vec();
  out.extend(splice_symbol(body, name, wide));
  let size = u32::try_from(out.len()).expect("frame size");
  out[..4].copy_from_slice(&size.to_be_bytes());
  out
}

fn symbolic_open(header: &[u8], frame: &[u8], name: &str, wide: bool) -> Vec<u8> {
  let mut out = header.to_vec();
  out.extend(splice_frame_symbol(frame, name, wide));
  out
}

fn amqp_symbol_overrun(wide: bool) -> Vec<u8> {
  let mut body = vec![0x00];
  if wide {
    body.push(0xb3);
    body.extend(50u32.to_be_bytes());
  } else {
    body.push(0xa3);
    body.push(50);
  }
  body.extend_from_slice(b"amqp:sasl-init:list");
  let mut out = AMQP_HEADER_SASL.to_vec();
  out.extend(amqp_10(1, &body));
  out
}

#[test]
fn amqp_symbolic_descriptors_rewrite_under_every_split() {
  let swapped = [b"\0svc\0".as_slice(), AMQP_REAL.as_bytes()].concat();
  for wide in [false, true] {
    let init = symbolic_open(
      AMQP_HEADER_SASL,
      &amqp_sasl_init("PLAIN", Some(amqp_plain(AMQP_FAKE))),
      "amqp:sasl-init:list",
      wide,
    );
    let (out, closed) = amqp_splits_match(AmqpLeg::DownSwap, &init, &[4, 11]).expect("sasl-init splits");
    assert!(!closed, "wide={wide} sasl-init closed");
    assert!(ldap_contains(&out, &swapped), "wide={wide} sasl-init kept the decoy");
    assert!(!ldap_contains(&out, AMQP_FAKE.as_bytes()), "wide={wide} sasl-init leaked the decoy");

    let mut deferred = symbolic_open(AMQP_HEADER_SASL, &amqp_sasl_init("PLAIN", None), "amqp:sasl-init:list", wide);
    deferred.extend(splice_frame_symbol(
      &amqp_sasl_response(amqp_plain(AMQP_FAKE)),
      "amqp:sasl-response:list",
      wide,
    ));
    let (out, closed) = amqp_splits_match(AmqpLeg::DownSwap, &deferred, &[6, 15]).expect("sasl-response splits");
    assert!(!closed, "wide={wide} sasl-response closed");
    assert!(ldap_contains(&out, &swapped), "wide={wide} sasl-response kept the decoy");
    assert!(
      !ldap_contains(&out, AMQP_FAKE.as_bytes()),
      "wide={wide} sasl-response leaked the decoy"
    );

    for (frame, name) in [
      (AmqpErrorFrame::Close, "amqp:close:list"),
      (AmqpErrorFrame::End, "amqp:end:list"),
      (AmqpErrorFrame::Detach, "amqp:detach:list"),
    ] {
      let data = symbolic_open(AMQP_HEADER_10, &amqp_error_10(frame, &format!("bad {AMQP_REAL}")), name, wide);
      let (out, closed) = amqp_splits_match(AmqpLeg::Up, &data, &[5, 13]).expect("close splits");
      assert!(!closed, "{name} wide={wide} closed");
      assert!(
        ldap_contains(&out, AMQP_FAKE.as_bytes()),
        "{name} wide={wide} left the real password"
      );
      assert!(
        !ldap_contains(&out, AMQP_REAL.as_bytes()),
        "{name} wide={wide} leaked the real password"
      );
    }

    let unknown = symbolic_open(
      AMQP_HEADER_SASL,
      &amqp_sasl_init("PLAIN", Some(amqp_plain(AMQP_FAKE))),
      "amqp:sasl-mechanisms:list",
      wide,
    );
    let (out, closed) = amqp_splits_match(AmqpLeg::DownSwap, &unknown, &[3, 9]).expect("unknown symbol splits");
    assert!(!closed, "wide={wide} unknown symbol closed");
    assert_eq!(out, unknown, "wide={wide} unknown symbol was rewritten");

    let overrun = amqp_symbol_overrun(wide);
    let (out, closed) = amqp_splits_match(AmqpLeg::DownSwap, &overrun, &[2, 8]).expect("overrun splits");
    assert!(!closed, "wide={wide} overrun closed");
    assert_eq!(out, overrun, "wide={wide} overrun was held");
  }
}

fn amqp_text() -> impl Strategy<Value = String> {
  proptest::string::string_regex("[b-z]{0,8}").expect("plain text")
}

fn amqp_mechanism() -> impl Strategy<Value = &'static str> {
  prop_oneof![Just("PLAIN"), Just("AMQPLAIN")]
}

fn amqp_password() -> impl Strategy<Value = &'static str> {
  prop_oneof![Just(AMQP_FAKE), Just("guest-pass")]
}

fn amqp_server_bound() -> impl Strategy<Value = Vec<u8>> {
  prop_oneof![
    (amqp_mechanism(), amqp_password(), amqp_text()).prop_map(|(mechanism, password, text)| {
      let mut out = AMQP_HEADER_091.to_vec();
      out.extend(amqp_start_ok(mechanism, &amqp_plain(password)));
      out.extend(amqp_091(&amq_protocol::frame::AMQPFrame::Body(1, text.into_bytes())));
      out
    }),
    (
      amqp_mechanism(),
      amqp_password(),
      any::<bool>(),
      proptest::collection::vec(any::<u8>(), 0..16)
    )
      .prop_map(|(mechanism, password, deferred, tail)| {
        let mut out = AMQP_HEADER_SASL.to_vec();
        if deferred {
          out.extend(amqp_sasl_init(mechanism, None));
          out.extend(amqp_sasl_response(amqp_plain(password)));
        } else {
          out.extend(amqp_sasl_init(mechanism, Some(amqp_plain(password))));
        }
        out.extend_from_slice(AMQP_HEADER_10);
        out.extend(tail);
        out
      }),
  ]
}

fn amqp_guest_frame_091() -> impl Strategy<Value = Vec<u8>> {
  prop_oneof![
    Just(amqp_091(&amq_protocol::frame::AMQPFrame::Heartbeat)),
    amqp_text().prop_map(|text| amqp_091(&amq_protocol::frame::AMQPFrame::Body(1, text.into_bytes()))),
    (any::<bool>(), amqp_text()).prop_map(|(on_channel, text)| amqp_close_091(on_channel, &text)),
    (any::<bool>(), amqp_text()).prop_map(|(on_channel, pad)| amqp_close_091(on_channel, &format!("{pad}{AMQP_REAL}"))),
    (1usize..AMQP_REAL.len()).prop_map(|k| amqp_close_091(false, AMQP_REAL.get(..k).unwrap_or(AMQP_REAL))),
  ]
}

fn amqp_error_frame() -> impl Strategy<Value = AmqpErrorFrame> {
  prop_oneof![Just(AmqpErrorFrame::Close), Just(AmqpErrorFrame::End), Just(AmqpErrorFrame::Detach)]
}

fn amqp_guest_frame_10() -> impl Strategy<Value = Vec<u8>> {
  prop_oneof![
    amqp_text().prop_map(|text| amqp_transfer_10(text.as_bytes())),
    (amqp_error_frame(), amqp_text()).prop_map(|(frame, text)| amqp_error_10(frame, &text)),
    (amqp_error_frame(), amqp_text()).prop_map(|(frame, pad)| amqp_error_10(frame, &format!("{pad}{AMQP_REAL}"))),
  ]
}

fn amqp_guest_bound() -> impl Strategy<Value = Vec<u8>> {
  prop_oneof![
    proptest::collection::vec(amqp_guest_frame_091(), 1..4).prop_map(|frames| frames.concat()),
    proptest::collection::vec(amqp_guest_frame_10(), 1..3).prop_map(|frames| {
      let mut out = AMQP_HEADER_SASL.to_vec();
      out.extend(amqp_sasl_outcome());
      out.extend_from_slice(AMQP_HEADER_10);
      out.extend(frames.concat());
      out
    }),
  ]
}

#[derive(Clone, Debug)]
enum AmqpSecret {
  Close091 { on_channel: bool, pad: String },
  Body091 { pre: Vec<u8>, post: Vec<u8> },
  Error10 { frame: AmqpErrorFrame, pad: String },
  Transfer10 { pre: Vec<u8>, post: Vec<u8> },
}

impl AmqpSecret {
  fn bytes(&self) -> Vec<u8> {
    let around = |pre: &[u8], post: &[u8]| [pre, AMQP_REAL.as_bytes(), post].concat();
    match self {
      Self::Close091 { on_channel, pad } => amqp_close_091(*on_channel, &format!("{pad}{AMQP_REAL}")),
      Self::Body091 { pre, post } => amqp_091(&amq_protocol::frame::AMQPFrame::Body(1, around(pre, post))),
      Self::Error10 { frame, pad } => [AMQP_HEADER_10, amqp_error_10(*frame, &format!("{pad}{AMQP_REAL}")).as_slice()].concat(),
      Self::Transfer10 { pre, post } => [AMQP_HEADER_10, amqp_transfer_10(&around(pre, post)).as_slice()].concat(),
    }
  }

  fn is_redacted(&self) -> bool {
    matches!(self, Self::Close091 { .. } | Self::Error10 { .. })
  }
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(256))]

  /// A prefix of an accepted frame closes on EOF, the same way for every cut.
  #[test]
  fn prop_ldap_truncated_prefix_closes_alike(
    leg in prop_oneof![Just(LdapLeg::DownSwap), Just(LdapLeg::DownClear), Just(LdapLeg::Up)],
    frame in ldap_safe_message(),
    keep in any::<usize>(),
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    prop_assume!(frame.len() > 1);
    let end = 1 + (keep % (frame.len() - 1));
    let prefix = &frame[..end];
    let scaled: Vec<usize> = cuts.into_iter().map(|cut| cut % prefix.len().max(1)).collect();
    ldap_truncated_closes_alike(|| ldap_leg(leg), prefix, &scaled)?;
  }

  /// Any cut of one accepted LDAP stream, including one byte at a time, matches one shot.
  #[test]
  fn prop_ldap_split_output_is_identical(
    leg in prop_oneof![Just(LdapLeg::DownSwap), Just(LdapLeg::DownClear), Just(LdapLeg::Up)],
    first in ldap_safe_message(),
    second in proptest::option::of(ldap_safe_message()),
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    let mut data = first;
    if let Some(extra) = second {
      data.extend(extra);
    }
    let scaled: Vec<usize> = cuts.into_iter().map(|cut| cut % data.len().max(1)).collect();
    ldap_splits_match(|| ldap_leg(leg), &data, &scaled)?;
    if matches!(leg, LdapLeg::Up) {
      let out = run_ldap(ldap_leg(LdapLeg::Up), &data, &[]);
      prop_assert!(!ldap_contains(&out.out, LDAP_REAL.as_bytes()));
    }
    if matches!(leg, LdapLeg::DownSwap) && ldap_contains(&data, LDAP_FAKE.as_bytes()) {
      let swapped = run_ldap(ldap_leg(LdapLeg::DownSwap), &data, &[]);
      prop_assert!(ldap_contains(&swapped.out, LDAP_REAL.as_bytes()));
      prop_assert!(!ldap_contains(&swapped.out, LDAP_FAKE.as_bytes()));
    }
  }

  /// The real password stays out of guest-bound LDAP output for every cut.
  #[test]
  fn prop_ldap_guest_output_hides_the_real_password(
    place in prop_oneof![
      (1u8..=127, ldap_plain()).prop_map(|(id, pad)| LdapSecret::Diagnostic { id, pad }),
      (1u8..=127, proptest::collection::vec(any::<u8>(), 0..8), proptest::collection::vec(any::<u8>(), 0..8))
        .prop_map(|(id, pre, post)| LdapSecret::Body { id, pre, post }),
      (
        proptest::collection::vec(any::<u8>(), 5..=8),
        proptest::collection::vec(any::<u8>(), 0..8),
        proptest::collection::vec(any::<u8>(), 0..8),
      ).prop_map(|(id, pre, post)| LdapSecret::Wide { id, pre, post }),
    ],
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    let data = ldap_secret_frame(&place);
    let scaled: Vec<usize> = cuts.into_iter().map(|cut| cut % data.len().max(1)).collect();
    ldap_hides_real(&data, &scaled)?;
    if matches!(place, LdapSecret::Diagnostic { .. }) {
      ldap_splits_match(|| ldap_leg(LdapLeg::Up), &data, &scaled)?;
      let out = run_ldap(ldap_leg(LdapLeg::Up), &data, &[]);
      prop_assert!(ldap_contains(&out.out, LDAP_FAKE.as_bytes()));
    }
  }

  /// Fragmented StartTLS reply, held password prefix, and wide message ids.
  #[test]
  fn prop_ldap_wide_id_starttls_and_password_prefix(
    shape in prop_oneof![Just(0u8), Just(1u8), Just(2u8)],
    id in 1u8..=127u8,
    id_len in 5usize..=8,
    k in 1usize..LDAP_REAL.len(),
    tail in proptest::collection::vec(any::<u8>(), 0..16),
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    match shape {
      0 => {
        let frame = ldap_wide(&vec![0x11; id_len], &tail);
        let scaled: Vec<usize> = cuts.into_iter().map(|cut| cut % frame.len().max(1)).collect();
        ldap_splits_match(|| ldap_leg(LdapLeg::DownSwap), &frame, &scaled)?;
        ldap_splits_match(|| ldap_leg(LdapLeg::Up), &frame, &scaled)?;
        let wide = run_ldap(ldap_leg(LdapLeg::Up), &frame, &[]);
        prop_assert_eq!(&wide.out, &frame);
      }
      1 => {
        let frame = ldap_starttls_response(u32::from(id));
        let scaled: Vec<usize> = cuts.into_iter().map(|cut| cut % frame.len().max(1)).collect();
        ldap_splits_match(|| ldap_expecting(u32::from(id)), &frame, &scaled)?;
        let full = run_ldap(ldap_expecting(u32::from(id)), &frame, &[]);
        prop_assert_eq!(full.starttls, Some(true));
        prop_assert_eq!(&full.out, &frame);
        for cut in 0..frame.len() {
          let partial = run_ldap(ldap_expecting(u32::from(id)), &frame[..cut], &[]);
          prop_assert_eq!(partial.starttls, None);
        }
      }
      _ => {
        let prefix = LDAP_REAL.get(..k).unwrap_or(LDAP_REAL);
        let frame = ldap_bind_response(u32::from(id), prefix);
        let scaled: Vec<usize> = cuts.into_iter().map(|cut| cut % frame.len().max(1)).collect();
        ldap_splits_match(|| ldap_leg(LdapLeg::Up), &frame, &scaled)?;
        let once = run_ldap(ldap_leg(LdapLeg::Up), &frame, &[]);
        prop_assert_eq!(&once.out, &frame);
        let byte_cuts: Vec<usize> = (1..frame.len()).collect();
        let byte = run_ldap(ldap_leg(LdapLeg::Up), &frame, &byte_cuts);
        prop_assert_eq!(&byte.out, &frame);
      }
    }
  }

  /// Crash resistance: arbitrary bytes, one cut, either leg, then EOF.
  #[test]
  fn prop_ldap_arbitrary_no_panic(
    data in proptest::collection::vec(any::<u8>(), 0..1024),
    cut in 0usize..1024,
    leg in prop_oneof![Just(LdapLeg::DownSwap), Just(LdapLeg::DownClear), Just(LdapLeg::Up)],
  ) {
    let _ = run_ldap(ldap_leg(leg), &data, &[cut.min(data.len())]);
  }

  #[test]
  fn prop_amqp_split_output_is_identical(
    server_bound in amqp_server_bound(),
    guest_bound in amqp_guest_bound(),
    leg in prop_oneof![Just(AmqpLeg::DownSwap), Just(AmqpLeg::DownClear), Just(AmqpLeg::Up)],
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    let data = if matches!(leg, AmqpLeg::Up) { guest_bound } else { server_bound };
    let scaled: Vec<usize> = cuts.into_iter().map(|cut| cut % data.len().max(1)).collect();
    let (out, closed) = amqp_splits_match(leg, &data, &scaled)?;
    prop_assert!(!closed);
    let plain_fake = amqp_plain(AMQP_FAKE);
    let plain_real = [b"\0svc\0".as_slice(), AMQP_REAL.as_bytes()].concat();
    match leg {
      AmqpLeg::Up => prop_assert!(!ldap_contains(&out, AMQP_REAL.as_bytes())),
      AmqpLeg::DownClear => prop_assert_eq!(&out, &data),
      AmqpLeg::DownSwap if ldap_contains(&data, &plain_fake) && ldap_contains(&data, b"\x05PLAIN") => {
        prop_assert!(ldap_contains(&out, &plain_real));
        prop_assert!(!ldap_contains(&out, AMQP_FAKE.as_bytes()));
      }
      AmqpLeg::DownSwap => prop_assert_eq!(&out, &data),
    }
  }

  #[test]
  fn prop_amqp_guest_output_hides_the_real_password(
    place in prop_oneof![
      (any::<bool>(), amqp_text()).prop_map(|(on_channel, pad)| AmqpSecret::Close091 { on_channel, pad }),
      (proptest::collection::vec(any::<u8>(), 0..8), proptest::collection::vec(any::<u8>(), 0..8))
        .prop_map(|(pre, post)| AmqpSecret::Body091 { pre, post }),
      (amqp_error_frame(), amqp_text()).prop_map(|(frame, pad)| AmqpSecret::Error10 { frame, pad }),
      (proptest::collection::vec(any::<u8>(), 0..8), proptest::collection::vec(any::<u8>(), 0..8))
        .prop_map(|(pre, post)| AmqpSecret::Transfer10 { pre, post }),
    ],
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    let data = place.bytes();
    let scaled: Vec<usize> = cuts.into_iter().map(|cut| cut % data.len().max(1)).collect();
    let byte_cuts: Vec<usize> = (1..data.len()).collect();
    for run in [&[][..], &scaled, &byte_cuts] {
      let (out, closed) = run_amqp(AmqpLeg::Up, &data, run);
      prop_assert!(!ldap_contains(&out, AMQP_REAL.as_bytes()));
      prop_assert_eq!(closed, !place.is_redacted());
    }
    if place.is_redacted() {
      let (out, _) = amqp_splits_match(AmqpLeg::Up, &data, &scaled)?;
      prop_assert!(ldap_contains(&out, AMQP_FAKE.as_bytes()));
    }
  }

  #[test]
  fn prop_amqp_truncated_close_reply_closes_alike(
    on_channel in any::<bool>(),
    pad in amqp_text(),
    keep in any::<usize>(),
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    let frame = amqp_close_091(on_channel, &format!("{pad}{AMQP_REAL}"));
    let prefix = &frame[..=(keep % (frame.len() - 1))];
    let scaled: Vec<usize> = cuts.into_iter().map(|cut| cut % prefix.len()).collect();
    let (out, closed) = amqp_splits_match(AmqpLeg::Up, prefix, &scaled)?;
    prop_assert!(closed);
    prop_assert!(!ldap_contains(&out, AMQP_REAL.as_bytes()));
  }

  #[test]
  fn prop_amqp_oversize_declared_frame_forwards(
    leg in prop_oneof![Just(AmqpLeg::DownSwap), Just(AmqpLeg::DownClear), Just(AmqpLeg::Up)],
    sasl in any::<bool>(),
    on_channel in any::<bool>(),
    cuts in proptest::collection::vec(any::<usize>(), 0..6),
  ) {
    let frame = amqp_oversize_clean(leg, sasl, on_channel);
    prop_assert!(frame.len() > MAX_CREDENTIAL_FRAME);
    let scaled: Vec<usize> = cuts.into_iter().map(|cut| cut % frame.len()).collect();
    let (out, closed) = amqp_splits_match(leg, &frame, &scaled)?;
    prop_assert!(!closed);
    prop_assert_eq!(&out, &frame);
  }

  #[test]
  fn prop_amqp_arbitrary_no_panic(
    header in prop_oneof![Just(&[][..]), Just(AMQP_HEADER_091), Just(AMQP_HEADER_SASL), Just(AMQP_HEADER_10)],
    data in proptest::collection::vec(any::<u8>(), 0..1024),
    cut in 0usize..1024,
    leg in prop_oneof![Just(AmqpLeg::DownSwap), Just(AmqpLeg::DownClear), Just(AmqpLeg::Up)],
  ) {
    let data = [header, data.as_slice()].concat();
    let _ = run_amqp(leg, &data, &[cut.min(data.len())]);
  }
}
