//! Property and fuzz tests: adversarial byte streams through the
//! substitution machines (HTTP), the SNI parser, and grant parsing.
//! SMTP properties live in `arkham-smtp`. LDAP properties live in `arkham-ldap`.
//! NATS properties live in `transports/nats/props.rs`.
//!
//! Two families:
//! - **Invariants** (valid framing, adversarial splits): a token split
//!   across any arrival boundary must recombine and substitute whole;
//!   fixed-length bodies must not drift; chunked output must re-parse.
//!   One shot, random cuts, and one byte at a time must match, and every
//!   run ends with the empty EOF flush.
//! - **Crash resistance** (arbitrary bytes): no input, arrival split, or
//!   pipelining combination may panic or hang.
//!
//! Tests are sync: async machine entry points run on a current-thread
//! tokio runtime via `block_on` (no timers, no IO — the machines are
//! deterministic over the byte input alone).
use proptest::prelude::*;

use arkham_config::grants::{Credential, Grant, Scheme};

use super::harness::{run_split, run_split_h2};
use super::{Direction, Http, raw_new};
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
    let mut m = raw_new(&grants, Scheme::Tcp, "h", 1, Direction::Downstream);
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
