//! NATS property tests. 256 cases. Every run ends with the empty EOF flush
//! `feed(&[])`.
//!
//! proptest 1.12.0 `TestRunner::run` (`runner.rs`) takes a synchronous `Fn`,
//! and `proptest!` expands to a sync `fn` (`sugar.rs`). These tests build
//! that runner, draw each case with `Strategy::new_tree`, and await the case
//! on the `#[tokio::test]` runtime.

use arkham_config::grants::{Grant, NatsSeed};
use base64::Engine as _;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use secrecy::SecretString;

use crate::transports::engine::harness::{CutPend, feed_parts};
use crate::transports::nats::fixtures::{mint_user, nats_grants};
use crate::transports::nats::machine::{self, MAX_COMMAND as NATS_MAX_COMMAND, Nats};
use crate::transports::nats::server_info;

fn count_bytes(hay: &[u8], needle: &[u8]) -> usize {
  if needle.is_empty() || hay.len() < needle.len() {
    return 0;
  }
  hay.windows(needle.len()).filter(|window| *window == needle).count()
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
  count_bytes(hay, needle) > 0
}

/// NATS decoy and real passwords. Lengths differ on purpose. Both hold an
/// `a`, which [`nats_word`] never produces.
const NATS_FAKE: &str = "arkham_fake_nats_pass"; // betterleaks:allow
const NATS_REAL: &str = "arkham_real_nats_pass_01"; // betterleaks:allow
const NATS_HOST: &str = "nats.internal";
const NATS_PORT: u16 = 4222;

/// One direction the NATS properties drive. Guest-bound output is [`NatsLeg::Up`].
#[derive(Clone, Copy, Debug)]
enum NatsLeg {
  Down,
  Up,
}

fn nats_leg(leg: NatsLeg) -> Nats {
  let grants = nats_grants(
    &format!("nats://agent:{NATS_FAKE}@{NATS_HOST}:{NATS_PORT}"),
    &format!("tls://agent:{NATS_REAL}@nats.upstream:{NATS_PORT}"),
  );
  match leg {
    NatsLeg::Down => Nats::downstream(&grants, NATS_HOST, NATS_PORT),
    NatsLeg::Up => Nats::upstream(&grants, NATS_HOST, NATS_PORT),
  }
}

struct NatsFed {
  out: Vec<u8>,
  hits: usize,
  closed: bool,
}

/// [`feed_parts`] over a fresh `leg`, ending with the empty EOF flush.
async fn run_nats(leg: NatsLeg, data: &[u8], cuts: &[usize]) -> NatsFed {
  let mut machine = nats_leg(leg);
  let (out, hits, closed) = feed_parts(&mut machine, data, cuts).await;
  NatsFed { out, hits, closed }
}

/// Random cuts scaled into `data` and sorted ascending.
fn nats_cuts(cuts: &[usize], data: &[u8]) -> Vec<usize> {
  let mut scaled: Vec<usize> = cuts.iter().map(|cut| cut % data.len().max(1)).collect();
  scaled.sort_unstable();
  scaled
}

/// One shot, `cuts`, and one byte at a time.
async fn nats_runs(leg: NatsLeg, data: &[u8], cuts: &[usize]) -> [NatsFed; 3] {
  let byte_cuts: Vec<usize> = (1..data.len()).collect();
  [
    run_nats(leg, data, &[]).await,
    run_nats(leg, data, cuts).await,
    run_nats(leg, data, &byte_cuts).await,
  ]
}

/// Every arrival agrees on the bytes and the hits, and the leg stays open.
async fn nats_splits_match(leg: NatsLeg, data: &[u8], cuts: &[usize]) -> Result<NatsFed, TestCaseError> {
  let [once, split, byte] = nats_runs(leg, data, cuts).await;
  prop_assert_eq!(&once.out, &split.out);
  prop_assert_eq!(&once.out, &byte.out);
  prop_assert_eq!(once.hits, split.hits);
  prop_assert_eq!(once.hits, byte.hits);
  prop_assert!(
    !once.closed && !split.closed && !byte.closed,
    "an accepted stream closed the {:?} leg",
    leg
  );
  Ok(once)
}

/// Subjects, names, and error text that cannot spell either password.
fn nats_word() -> impl Strategy<Value = String> {
  proptest::string::string_regex("[b-z]{1,8}").expect("nats word")
}

fn nats_payload() -> impl Strategy<Value = Vec<u8>> {
  proptest::collection::vec(any::<u8>(), 0..16)
}

fn nats_connect(pass: &str, name: &str, lower: bool) -> Vec<u8> {
  let verb = if lower { "connect" } else { "CONNECT" };
  format!("{verb} {{\"verbose\":false,\"user\":\"agent\",\"pass\":\"{pass}\",\"name\":\"{name}\"}}\r\n").into_bytes()
}

/// A counted command. `head` is everything before the counts; a header
/// block, when there is one, leads the payload.
fn nats_counted(head: &str, headers: bool, payload: &[u8]) -> Vec<u8> {
  let block: &[u8] = if headers { b"NATS/1.0\r\n\r\n" } else { b"" };
  let total = block.len().saturating_add(payload.len());
  let counts = if headers {
    format!("{} {total}", block.len())
  } else {
    total.to_string()
  };
  let mut out = format!("{head} {counts}\r\n").into_bytes();
  out.extend_from_slice(block);
  out.extend_from_slice(payload);
  out.extend_from_slice(b"\r\n");
  out
}

fn nats_client_message() -> impl Strategy<Value = Vec<u8>> {
  prop_oneof![
    (nats_word(), any::<bool>()).prop_map(|(name, lower)| nats_connect(NATS_FAKE, &name, lower)),
    (nats_word(), any::<bool>()).prop_map(|(name, lower)| nats_connect("guest-pass", &name, lower)),
    (nats_word(), any::<bool>(), nats_payload()).prop_map(|(subject, headers, payload)| {
      let verb = if headers { "HPUB" } else { "PUB" };
      nats_counted(&format!("{verb} {subject}"), headers, &payload)
    }),
    (nats_word(), 1u16..1000).prop_map(|(subject, sid)| format!("SUB {subject} {sid}\r\n").into_bytes()),
    (1u16..1000).prop_map(|sid| format!("UNSUB {sid}\r\n").into_bytes()),
    Just(b"PING\r\n".to_vec()),
    Just(b"PONG\r\n".to_vec()),
  ]
}

/// Server frames that keep the leg open. The real password appears only
/// where the leg redacts it, or as a proper prefix inside a payload.
fn nats_server_message() -> impl Strategy<Value = Vec<u8>> {
  prop_oneof![
    nats_word().prop_map(|id| format!("INFO {{\"server_id\":\"{id}\",\"tls_required\":true}}\r\n").into_bytes()),
    nats_word().prop_map(|text| format!("-ERR '{text}'\r\n").into_bytes()),
    nats_word().prop_map(|text| format!("-ERR '{text} {NATS_REAL}'\r\n").into_bytes()),
    (1usize..NATS_REAL.len()).prop_map(|k| format!("-ERR '{}'\r\n", NATS_REAL.get(..k).unwrap_or(NATS_REAL)).into_bytes()),
    Just(b"+OK\r\n".to_vec()),
    Just(b"PING\r\n".to_vec()),
    Just(b"PONG\r\n".to_vec()),
    (nats_word(), 1u16..1000, any::<bool>(), nats_payload()).prop_map(|(subject, sid, headers, payload)| {
      let verb = if headers { "HMSG" } else { "MSG" };
      nats_counted(&format!("{verb} {subject} {sid}"), headers, &payload)
    }),
    (nats_word(), 1u16..1000, 1usize..NATS_REAL.len()).prop_map(|(subject, sid, k)| {
      let prefix = NATS_REAL.get(..k).unwrap_or(NATS_REAL);
      nats_counted(&format!("MSG {subject} {sid}"), false, prefix.as_bytes())
    }),
    (nats_word(), 1u16..1000).prop_map(|(subject, sid)| nats_counted(&format!("MSG {subject} {sid}"), false, NATS_FAKE.as_bytes())),
  ]
}

/// Where the real password sits in a server frame.
#[derive(Clone, Debug)]
enum NatsSecret {
  /// Inside a delimited line: redacted to the decoy.
  Line { info: bool, pre: String, post: String },
  /// Inside a counted payload: the leg closes.
  Payload { headers: bool, pre: Vec<u8>, post: Vec<u8> },
  /// As a MSG subject: the leg closes.
  Subject { sid: u16 },
}

fn nats_secret_frame(place: &NatsSecret) -> Vec<u8> {
  match place {
    NatsSecret::Line { info: true, pre, post } => format!("INFO {{\"server_id\":\"{pre}{NATS_REAL}{post}\"}}\r\n").into_bytes(),
    NatsSecret::Line { info: false, pre, post } => format!("-ERR '{pre}{NATS_REAL}{post}'\r\n").into_bytes(),
    NatsSecret::Payload { headers, pre, post } => {
      let mut payload = pre.clone();
      payload.extend_from_slice(NATS_REAL.as_bytes());
      payload.extend_from_slice(post);
      let verb = if *headers { "HMSG" } else { "MSG" };
      nats_counted(&format!("{verb} orders 1"), *headers, &payload)
    }
    NatsSecret::Subject { sid } => nats_counted(&format!("MSG {NATS_REAL} {sid}"), false, b"hi"),
  }
}

fn nats_runner(name: &'static str) -> TestRunner {
  let mut config = proptest::test_runner::contextualize_config(ProptestConfig::with_cases(256));
  config.test_name = Some(name);
  config.source_file = Some(file!());
  TestRunner::new(config)
}

async fn drive<S, F, Fut>(name: &'static str, strategy: S, mut check: F)
where
  S: Strategy,
  S::Value: std::fmt::Debug,
  F: FnMut(S::Value) -> Fut,
  Fut: Future<Output = Result<(), TestCaseError>>,
{
  let mut runner = nats_runner(name);
  let cases = runner.config().cases;
  let max_rejects = runner.config().max_global_rejects;
  let max_shrink = runner.config().max_shrink_iters();
  let mut passed = 0u32;
  let mut rejected = 0u32;
  while passed < cases {
    let mut tree = strategy
      .new_tree(&mut runner)
      .unwrap_or_else(|err| panic!("{name} could not draw a case: {err}"));
    match check(tree.current()).await {
      Ok(()) => passed = passed.saturating_add(1),
      Err(TestCaseError::Reject(_)) => {
        rejected = rejected.saturating_add(1);
        assert!(rejected <= max_rejects, "{name} rejected {rejected} cases");
      }
      Err(TestCaseError::Fail(reason)) => {
        let mut why = reason;
        let mut shrinks = 0u32;
        if tree.simplify() {
          loop {
            shrinks = shrinks.saturating_add(1);
            if shrinks > max_shrink {
              break;
            }
            match check(tree.current()).await {
              Ok(()) | Err(TestCaseError::Reject(_)) => {
                if !tree.complicate() {
                  break;
                }
              }
              Err(TestCaseError::Fail(next)) => {
                why = next;
                if !tree.simplify() {
                  break;
                }
              }
            }
          }
        }
        panic!("{name} failed: {why}\n{:?}", tree.current());
      }
    }
  }
}

/// Any cut of an accepted NATS stream, including one byte at a time,
/// matches one shot. Guest-bound bytes never hold the real password.
#[tokio::test]
async fn prop_nats_split_output_is_identical() {
  drive(
    concat!(module_path!(), "::prop_nats_split_output_is_identical"),
    (
      proptest::collection::vec(nats_client_message(), 1..4),
      proptest::collection::vec(nats_server_message(), 1..4),
      proptest::collection::vec(any::<usize>(), 0..6),
    ),
    |(client, server, cuts)| async move {
      let client = client.concat();
      let server = server.concat();
      let client_cuts = nats_cuts(&cuts, &client);
      let swapped = nats_splits_match(NatsLeg::Down, &client, &client_cuts).await?;
      let decoys = count_bytes(&client, format!("\"pass\":\"{NATS_FAKE}\"").as_bytes());
      prop_assert_eq!(count_bytes(&swapped.out, format!("\"pass\":\"{NATS_REAL}\"").as_bytes()), decoys);
      prop_assert_eq!(swapped.hits, decoys);
      let up = nats_splits_match(NatsLeg::Up, &server, &nats_cuts(&cuts, &server)).await?;
      prop_assert!(
        !contains_bytes(&up.out, NATS_REAL.as_bytes()),
        "the real password reached the guest"
      );
      Ok(())
    },
  )
  .await;
}

/// The real password stays out of guest-bound NATS output for every cut.
/// A line carries the decoy instead; a payload or subject closes the leg.
#[tokio::test]
async fn prop_nats_guest_output_hides_the_real_password() {
  drive(
    concat!(module_path!(), "::prop_nats_guest_output_hides_the_real_password"),
    (
      prop_oneof![
        (any::<bool>(), nats_word(), nats_word()).prop_map(|(info, pre, post)| NatsSecret::Line { info, pre, post }),
        (any::<bool>(), nats_payload(), nats_payload()).prop_map(|(headers, pre, post)| NatsSecret::Payload { headers, pre, post }),
        (1u16..1000).prop_map(|sid| NatsSecret::Subject { sid }),
      ],
      proptest::collection::vec(nats_server_message(), 0..3),
      proptest::collection::vec(any::<usize>(), 0..6),
    ),
    |(place, lead, cuts)| async move {
      let mut data = lead.concat();
      data.extend(nats_secret_frame(&place));
      let scaled = nats_cuts(&cuts, &data);
      let runs = nats_runs(NatsLeg::Up, &data, &scaled).await;
      for run in &runs {
        prop_assert!(
          !contains_bytes(&run.out, NATS_REAL.as_bytes()),
          "the real password reached the guest"
        );
      }
      if matches!(place, NatsSecret::Line { .. }) {
        let once = nats_splits_match(NatsLeg::Up, &data, &scaled).await?;
        prop_assert!(contains_bytes(&once.out, NATS_FAKE.as_bytes()), "the line lost its decoy");
      } else {
        for run in &runs {
          prop_assert!(run.closed, "a frame holding the real password stayed open");
        }
      }
      Ok(())
    },
  )
  .await;
}

/// INFO cut at any offset is still one line to the guest. The read that
/// holds its LF may end there or run into the bytes after it, TLS records
/// or the next NATS line, which are left for the next reader.
#[tokio::test]
async fn prop_nats_info_cut_leaves_the_rest_unread() {
  drive(
    concat!(module_path!(), "::prop_nats_info_cut_leaves_the_rest_unread"),
    (
      nats_word(),
      any::<bool>(),
      proptest::option::of(proptest::collection::vec(any::<u8>(), 0..32)),
      0usize..4,
      proptest::collection::vec(any::<usize>(), 0..4),
    ),
    |(id, secret, handshake, past_newline, cuts)| async move {
      let real = if secret { NATS_REAL } else { "" };
      let info = format!("INFO {{\"server_id\":\"{id}{real}\",\"tls_required\":true}}\r\n").into_bytes();
      let tail = match &handshake {
        Some(record) => [&[0x16, 0x03, 0x01], record.as_slice()].concat(),
        None => b"PING\r\n".to_vec(),
      };
      let stream = [info.as_slice(), tail.as_slice()].concat();
      let mut cuts: Vec<usize> = cuts.iter().map(|cut| cut % stream.len()).collect();
      cuts.push(info.len().saturating_add(past_newline));
      let expected = run_nats(NatsLeg::Up, &info, &[]).await.out;
      let mut clear_reader = CutPend::new(stream.clone(), &cuts);
      let mut clear_up = nats_leg(NatsLeg::Up);
      let mut clear_down = nats_leg(NatsLeg::Down);
      let mut clear_guest = Vec::new();
      let err = server_info(&mut clear_reader, &mut clear_up, &mut clear_down, &mut clear_guest, true)
        .await
        .expect_err("cleartext INFO with tls_required must close");
      prop_assert!(
        matches!(
          err,
          crate::Error::NatsTlsRequired {
            tls_available: false,
            tls_verify: false
          }
        ),
        "cleartext close was {err}"
      );
      prop_assert!(
        !clear_guest.contains(&b'\n'),
        "the read that held LF was written on a cleartext close"
      );
      prop_assert!(
        !contains_bytes(&clear_guest, NATS_REAL.as_bytes()),
        "INFO carried the real password to the guest"
      );
      let mut reader = CutPend::new(stream, &cuts);
      let mut up = nats_leg(NatsLeg::Up);
      let mut down = nats_leg(NatsLeg::Down);
      let mut guest = Vec::new();
      let opened = server_info(&mut reader, &mut up, &mut down, &mut guest, false)
        .await
        .expect("info read");
      let Some(mut rest) = opened else {
        return Err(TestCaseError::fail("the INFO reader closed"));
      };
      prop_assert_eq!(&guest, &expected, "cut INFO reached the guest differently");
      prop_assert!(
        !contains_bytes(&guest, NATS_REAL.as_bytes()),
        "INFO carried the real password to the guest"
      );
      rest.extend_from_slice(reader.data.get(reader.at..).unwrap_or_default());
      prop_assert_eq!(&rest, &tail, "bytes past INFO were consumed or lost");
      if handshake.is_none() {
        let (next, _, closed) = feed_parts(&mut up, &rest, &[]).await;
        prop_assert!(!closed, "the line after INFO closed the leg");
        prop_assert_eq!(next, tail, "the leg lost its framing after INFO");
      }
      Ok(())
    },
  )
  .await;
}

/// A proper prefix at EOF: the guest leg flushes it unchanged, the server
/// leg closes, and every cut agrees.
#[tokio::test]
async fn prop_nats_truncated_prefix_at_eof() {
  drive(
    concat!(module_path!(), "::prop_nats_truncated_prefix_at_eof"),
    (
      nats_client_message(),
      nats_server_message(),
      any::<usize>(),
      proptest::collection::vec(any::<usize>(), 0..6),
    ),
    |(client, server, keep, cuts)| async move {
      let end = 1 + keep % (client.len() - 1);
      let prefix = &client[..end];
      for run in nats_runs(NatsLeg::Down, prefix, &nats_cuts(&cuts, prefix)).await {
        prop_assert_eq!(run.out.as_slice(), prefix, "a partial guest command changed at EOF");
        prop_assert!(!run.closed, "a partial guest command closed the leg");
      }
      let end = 1 + keep % (server.len() - 1);
      let prefix = &server[..end];
      let [once, split, byte] = nats_runs(NatsLeg::Up, prefix, &nats_cuts(&cuts, prefix)).await;
      prop_assert!(
        once.closed && split.closed && byte.closed,
        "a partial server frame stayed open at EOF"
      );
      prop_assert_eq!(&once.out, &split.out);
      prop_assert_eq!(&once.out, &byte.out);
      Ok(())
    },
  )
  .await;
}

/// One byte at a time stays in the unit tests: this line is longer than
/// the cap, and walking every byte for 256 cases would pass the slow-test
/// deadline.
#[tokio::test]
async fn prop_nats_oversize_connect_is_forwarded() {
  drive(
    concat!(module_path!(), "::prop_nats_oversize_connect_is_forwarded"),
    (0usize..64, any::<bool>(), proptest::collection::vec(any::<usize>(), 0..6)),
    |(extra, lower, cuts)| async move {
      let verb = if lower { "connect" } else { "CONNECT" };
      let name = "b".repeat(NATS_MAX_COMMAND.saturating_add(extra));
      let line = format!("{verb} {{\"verbose\":false,\"user\":\"agent\",\"pass\":\"{NATS_FAKE}\",\"name\":\"{name}\"}}\r\n");
      prop_assert!(line.len() > NATS_MAX_COMMAND);
      let mut data = line.into_bytes();
      data.extend_from_slice(b"PING\r\n");
      let scaled = nats_cuts(&cuts, &data);
      let once = run_nats(NatsLeg::Down, &data, &[]).await;
      let split = run_nats(NatsLeg::Down, &data, &scaled).await;
      prop_assert!(!once.closed && !split.closed, "an oversize CONNECT closed the leg");
      prop_assert_eq!(&once.out, &data);
      prop_assert_eq!(&split.out, &data);
      prop_assert_eq!(once.hits, 0);
      prop_assert_eq!(split.hits, 0);
      Ok(())
    },
  )
  .await;
}

/// Crash resistance: arbitrary bytes, one cut, any leg, then EOF; and the
/// same bytes through the INFO reader.
#[tokio::test]
async fn prop_nats_arbitrary_no_panic() {
  drive(
    concat!(module_path!(), "::prop_nats_arbitrary_no_panic"),
    (
      proptest::collection::vec(any::<u8>(), 0..1024),
      0usize..1024,
      prop_oneof![Just(NatsLeg::Down), Just(NatsLeg::Up)],
    ),
    |(data, cut, leg)| async move {
      let _ = run_nats(leg, &data, &[cut.min(data.len())]).await;
      let mut reader = CutPend::new(data, &[cut]);
      let mut up = nats_leg(NatsLeg::Up);
      let mut down = nats_leg(NatsLeg::Down);
      let mut guest = Vec::new();
      let _ = server_info(&mut reader, &mut up, &mut down, &mut guest, false).await;
      Ok(())
    },
  )
  .await;
}

fn prop_b64(bytes: &[u8]) -> String {
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn prop_user_jwt(public: &str) -> String {
  let header = prop_b64(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
  let payload = prop_b64(format!(r#"{{"sub":"{public}"}}"#).as_bytes());
  format!("{header}.{payload}.{}", prop_b64(b"sig"))
}

/// Printable ASCII, including quotes and backslashes. The INFO line is JSON,
/// so the parser has to return this exact nonce before anyone signs it.
fn nonce_text() -> impl Strategy<Value = String> {
  proptest::string::string_regex("[ -~]{1,24}").expect("nonce")
}

struct UserKey {
  raw: String,
  seed: NatsSeed,
  public: String,
}

fn user_key(bytes: [u8; 32]) -> Result<UserKey, TestCaseError> {
  let pair = nkeys::KeyPair::new_from_raw(nkeys::KeyPairType::User, bytes).map_err(|_source| TestCaseError::fail("user key"))?;
  let raw = pair.seed().map_err(|_source| TestCaseError::fail("user seed"))?;
  let public = pair.public_key();
  let seed = NatsSeed::from_seed(SecretString::from(raw.clone())).map_err(|_source| TestCaseError::fail("parsed seed"))?;
  Ok(UserKey { raw, seed, public })
}

fn json_quote(value: &str) -> String {
  serde_json::to_string(value).expect("json string")
}

/// `names` in the order `rank` sorts them. Equal ranks keep the input order.
fn order_names<'a>(names: &[&'a str], rank: &[u8]) -> Vec<&'a str> {
  let mut indexed: Vec<(u8, usize, &str)> = names
    .iter()
    .enumerate()
    .map(|(index, name)| (rank.get(index).copied().unwrap_or(0), index, *name))
    .collect();
  indexed.sort_by_key(|item| (item.0, item.1));
  indexed.into_iter().map(|item| item.2).collect()
}

fn spaced_connect(verb_spaces: usize, tab: bool, json_spaces: usize, fields: &[(&str, String)]) -> Vec<u8> {
  let gap = if tab { "\t" } else { " " }.repeat(json_spaces);
  let body = fields
    .iter()
    .map(|(name, value)| format!("{gap}\"{name}\"{gap}:{gap}{value}{gap}"))
    .collect::<Vec<_>>()
    .join(",");
  let verb_gap = if tab { "\t" } else { " " }.repeat(verb_spaces.max(1));
  format!("CONNECT{verb_gap}{{{body}}}\r\n").into_bytes()
}

fn info_line(nonce: &str) -> Vec<u8> {
  format!("INFO {{\"nonce\":{}}}\r\n", json_quote(nonce)).into_bytes()
}

async fn arm_nonce(grants: &[Grant], nonce: &str) -> Result<Nats, TestCaseError> {
  let mut up = Nats::upstream(grants, NATS_HOST, NATS_PORT);
  let mut down = Nats::downstream(grants, NATS_HOST, NATS_PORT);
  let info = info_line(nonce);
  let (out, _, closed) = feed_parts(&mut up, &info, &[]).await;
  prop_assert!(!closed && out == info, "opening INFO");
  machine::arm_opening(&mut up, &mut down);
  Ok(down)
}

async fn arm_absent(grants: &[Grant]) -> Nats {
  let mut up = Nats::upstream(grants, NATS_HOST, NATS_PORT);
  let mut down = Nats::downstream(grants, NATS_HOST, NATS_PORT);
  let info = b"INFO {\"server_id\":\"N1\"}\r\n";
  let (out, _, closed) = feed_parts(&mut up, info, &[]).await;
  assert!(!closed && out == info, "opening INFO without a nonce");
  machine::arm_opening(&mut up, &mut down);
  down
}

fn rewritten_sig(out: &[u8]) -> Result<Vec<u8>, TestCaseError> {
  let text = std::str::from_utf8(out).map_err(|_source| TestCaseError::fail("connect was not utf-8"))?;
  let start = text.find('{').ok_or_else(|| TestCaseError::fail("connect had no json"))?;
  let end = text.rfind('}').ok_or_else(|| TestCaseError::fail("connect had no json end"))?;
  let json = text.get(start..=end).ok_or_else(|| TestCaseError::fail("connect json span"))?;
  let value: serde_json::Value = serde_json::from_str(json).map_err(|_source| TestCaseError::fail("connect json"))?;
  let sig = value
    .get("sig")
    .and_then(serde_json::Value::as_str)
    .ok_or_else(|| TestCaseError::fail("sig missing"))?;
  base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(sig)
    .map_err(|_source| TestCaseError::fail("sig encoding"))
}

/// A verifying CONNECT, with a generated nonce, keys, field order, and
/// spacing. The upstream signature verifies under the real public key, and
/// the decoy public key, decoy JWT, and decoy signature are gone.
#[tokio::test]
async fn prop_nats_signed_connect_is_split_stable() {
  drive(
    concat!(module_path!(), "::prop_nats_signed_connect_is_split_stable"),
    (
      any::<[u8; 32]>(),
      any::<[u8; 32]>(),
      nonce_text(),
      any::<bool>(),
      any::<bool>(),
      any::<bool>(),
      1usize..5,
      any::<bool>(),
      0usize..4,
      proptest::collection::vec(any::<u8>(), 4),
      nats_word(),
      proptest::collection::vec(any::<usize>(), 0..6),
    ),
    |(fake_bytes, real_bytes, nonce, jwt_kind, with_nkey, lower, verb_spaces, tab, json_spaces, rank, name, cuts)| async move {
      prop_assume!(fake_bytes != real_bytes);
      let fake = user_key(fake_bytes)?;
      let real = user_key(real_bytes)?;
      let fake_jwt = prop_user_jwt(&fake.public);
      let real_jwt = prop_user_jwt(&real.public);
      let grants = if jwt_kind {
        nats_grants(
          &format!("nats://creds:{}:{fake_jwt}@{NATS_HOST}:{NATS_PORT}", fake.raw),
          &format!("tls://creds:{}:{real_jwt}@nats.upstream:{NATS_PORT}", real.raw),
        )
      } else {
        nats_grants(
          &format!("nats://nkey:{}@{NATS_HOST}:{NATS_PORT}", fake.raw),
          &format!("tls://nkey:{}@nats.upstream:{NATS_PORT}", real.raw),
        )
      };
      let sig = prop_b64(
        &fake
          .seed
          .pair
          .sign(nonce.as_bytes())
          .map_err(|_err| TestCaseError::fail("fake seed signs"))?,
      );
      let names: &[&str] = if jwt_kind && with_nkey {
        &["jwt", "nkey", "sig", "name"]
      } else if jwt_kind {
        &["jwt", "sig", "name"]
      } else {
        &["nkey", "sig", "name"]
      };
      let mut fields = Vec::new();
      for field in order_names(names, &rank) {
        let value = match field {
          "jwt" => json_quote(&fake_jwt),
          "nkey" => json_quote(&fake.public),
          "sig" => json_quote(&sig),
          "name" => json_quote(&name),
          _ => json_quote("false"),
        };
        fields.push((field, value));
      }
      let mut line = spaced_connect(verb_spaces, tab, json_spaces, &fields);
      if lower && let Some(head) = line.get_mut(.."CONNECT".len()) {
        head.make_ascii_lowercase();
      }
      let mut once_down = arm_nonce(&grants, &nonce).await?;
      let mut split_down = arm_nonce(&grants, &nonce).await?;
      let once = feed_parts(&mut once_down, &line, &[]).await;
      let split = feed_parts(&mut split_down, &line, &nats_cuts(&cuts, &line)).await;
      prop_assert_eq!(&once.0, &split.0);
      prop_assert_eq!(once.1, split.1);
      prop_assert_eq!(once.2, split.2);
      prop_assert!(!once.2, "a verifying CONNECT closed");
      let raw = rewritten_sig(&once.0)?;
      prop_assert!(
        NatsSeed::verify(&real.public, nonce.as_bytes(), &raw),
        "the upstream signature does not verify under the real public key"
      );
      prop_assert!(!contains_bytes(&once.0, sig.as_bytes()), "the decoy signature stayed");
      prop_assert!(!contains_bytes(&once.0, fake.public.as_bytes()), "the decoy public key stayed");
      if jwt_kind {
        prop_assert!(!contains_bytes(&once.0, fake_jwt.as_bytes()), "the decoy jwt stayed");
        prop_assert!(contains_bytes(&once.0, real_jwt.as_bytes()), "the real jwt was not written");
      }
      Ok(())
    },
  )
  .await;
}

/// A CONNECT that must not be rewritten stays byte-identical and gains no real material.
#[derive(Clone, Copy, Debug)]
enum SignedTamper {
  BadSig,
  ForeignNkey,
  JwtOnNkey,
  Pending,
  Absent,
  OverCap,
}

#[tokio::test]
async fn prop_nats_tampered_signed_connect_is_forwarded() {
  drive(
    concat!(module_path!(), "::prop_nats_tampered_signed_connect_is_forwarded"),
    (
      any::<[u8; 32]>(),
      any::<[u8; 32]>(),
      any::<[u8; 32]>(),
      nonce_text(),
      any::<bool>(),
      prop_oneof![
        Just(SignedTamper::BadSig),
        Just(SignedTamper::ForeignNkey),
        Just(SignedTamper::JwtOnNkey),
        Just(SignedTamper::Pending),
        Just(SignedTamper::Absent),
        Just(SignedTamper::OverCap),
      ],
      proptest::collection::vec(any::<usize>(), 0..6),
    ),
    |(fake_bytes, real_bytes, foreign_bytes, nonce, jwt_kind, tamper, cuts)| async move {
      prop_assume!(fake_bytes != real_bytes && fake_bytes != foreign_bytes && real_bytes != foreign_bytes);
      let fake = user_key(fake_bytes)?;
      let real = user_key(real_bytes)?;
      let foreign = user_key(foreign_bytes)?;
      let fake_jwt = prop_user_jwt(&fake.public);
      let real_jwt = prop_user_jwt(&real.public);
      let nkey_rule = matches!(tamper, SignedTamper::JwtOnNkey) || !jwt_kind;
      let grants = if nkey_rule {
        nats_grants(
          &format!("nats://nkey:{}@{NATS_HOST}:{NATS_PORT}", fake.raw),
          &format!("tls://nkey:{}@nats.upstream:{NATS_PORT}", real.raw),
        )
      } else {
        nats_grants(
          &format!("nats://creds:{}:{fake_jwt}@{NATS_HOST}:{NATS_PORT}", fake.raw),
          &format!("tls://creds:{}:{real_jwt}@nats.upstream:{NATS_PORT}", real.raw),
        )
      };
      let mut signed_nonce = nonce.clone();
      let mut nkey_public = fake.public.clone();
      let mut signer = &fake.seed;
      if matches!(tamper, SignedTamper::BadSig) {
        signed_nonce.push('x');
      }
      if matches!(tamper, SignedTamper::ForeignNkey) {
        nkey_public.clone_from(&foreign.public);
        signer = &foreign.seed;
      }
      let sig = prop_b64(
        &signer
          .pair
          .sign(signed_nonce.as_bytes())
          .map_err(|_err| TestCaseError::fail("seed signs"))?,
      );
      let mut fields = vec![
        ("nkey".to_string(), json_quote(&nkey_public)),
        ("sig".to_string(), json_quote(&sig)),
      ];
      if !nkey_rule {
        fields.insert(0, ("jwt".to_string(), json_quote(&fake_jwt)));
      }
      if matches!(tamper, SignedTamper::JwtOnNkey) {
        fields.insert(0, ("jwt".to_string(), json_quote(&fake_jwt)));
      }
      if matches!(tamper, SignedTamper::OverCap) {
        fields.push(("name".to_string(), json_quote(&"b".repeat(NATS_MAX_COMMAND))));
      }
      let owned: Vec<(&str, String)> = fields.iter().map(|(name, value)| (name.as_str(), value.clone())).collect();
      let line = spaced_connect(1, false, 0, &owned);
      if matches!(tamper, SignedTamper::OverCap) {
        prop_assert!(line.len() > NATS_MAX_COMMAND);
      }
      let mut down = match tamper {
        SignedTamper::Pending => Nats::downstream(&grants, NATS_HOST, NATS_PORT),
        SignedTamper::Absent => arm_absent(&grants).await,
        _ => arm_nonce(&grants, &nonce).await?,
      };
      let (out, hits, closed) = feed_parts(&mut down, &line, &nats_cuts(&cuts, &line)).await;
      let (once, once_hits, once_closed) = feed_parts(
        &mut match tamper {
          SignedTamper::Pending => Nats::downstream(&grants, NATS_HOST, NATS_PORT),
          SignedTamper::Absent => arm_absent(&grants).await,
          _ => arm_nonce(&grants, &nonce).await?,
        },
        &line,
        &[],
      )
      .await;
      prop_assert!(!closed && !once_closed, "a forwarded CONNECT closed");
      prop_assert_eq!(hits, 0);
      prop_assert_eq!(once_hits, 0);
      prop_assert_eq!(&out, &line, "a tampered CONNECT was rewritten");
      prop_assert_eq!(&once, &line, "a tampered CONNECT was rewritten");
      prop_assert!(!contains_bytes(&out, real.public.as_bytes()), "the real public key was written");
      prop_assert!(!contains_bytes(&out, real_jwt.as_bytes()), "the real jwt was written");
      Ok(())
    },
  )
  .await;
}

/// Server bytes, cut anywhere, agree. Guest-bound output never carries the real seed, JWT, or public key.
/// The user-JWT kind hides the real public key in a payload, not only the real JWT.
#[tokio::test]
async fn prop_nats_guest_output_hides_signed_material() {
  let (fake_raw, fake) = mint_user();
  let (real_raw, real) = mint_user();
  let fake_jwt = prop_user_jwt(&fake.public);
  let real_jwt = prop_user_jwt(&real.public);
  let fake_public = fake.public.clone();
  let real_public = real.public.clone();
  let nkey = nats_grants(
    &format!("nats://nkey:{fake_raw}@{NATS_HOST}:{NATS_PORT}"),
    &format!("tls://nkey:{real_raw}@nats.upstream:{NATS_PORT}"),
  );
  let jwt = nats_grants(
    &format!("nats://creds:{fake_raw}:{fake_jwt}@{NATS_HOST}:{NATS_PORT}"),
    &format!("tls://creds:{real_raw}:{real_jwt}@nats.upstream:{NATS_PORT}"),
  );
  drive(
    concat!(module_path!(), "::prop_nats_guest_output_hides_signed_material"),
    (
      any::<bool>(),
      any::<bool>(),
      any::<bool>(),
      nats_word(),
      nats_word(),
      proptest::collection::vec(any::<usize>(), 0..6),
    ),
    move |(jwt_kind, payload, hide_public, pre, post, cuts)| {
      let grants = if jwt_kind { jwt.clone() } else { nkey.clone() };
      let real_raw = real_raw.clone();
      let real_public = real_public.clone();
      let real_jwt = real_jwt.clone();
      let fake_public = fake_public.clone();
      let fake_jwt = fake_jwt.clone();
      async move {
        let (secret, decoy_value) = if jwt_kind && !hide_public {
          (real_jwt.as_str(), fake_jwt.as_str())
        } else {
          (real_public.as_str(), fake_public.as_str())
        };
        let frame = if payload {
          let mut body = pre.into_bytes();
          body.extend_from_slice(secret.as_bytes());
          body.extend_from_slice(post.as_bytes());
          nats_counted("MSG orders 1", false, &body)
        } else {
          format!("-ERR '{pre}{secret}{post}'\r\n").into_bytes()
        };
        let mut once_up = Nats::upstream(&grants, NATS_HOST, NATS_PORT);
        let mut split_up = Nats::upstream(&grants, NATS_HOST, NATS_PORT);
        let once = feed_parts(&mut once_up, &frame, &[]).await;
        let split = feed_parts(&mut split_up, &frame, &nats_cuts(&cuts, &frame)).await;
        for run in [&once, &split] {
          prop_assert!(!contains_bytes(&run.0, real_raw.as_bytes()), "guest output carried the real seed");
          prop_assert!(!contains_bytes(&run.0, real_jwt.as_bytes()), "guest output carried the real jwt");
          prop_assert!(
            !contains_bytes(&run.0, real_public.as_bytes()),
            "guest output carried the real public key"
          );
        }
        if payload {
          prop_assert!(once.2 && split.2, "a payload holding the real value stayed open");
        } else {
          prop_assert_eq!(&once.0, &split.0);
          prop_assert_eq!(once.1, split.1);
          prop_assert!(!once.2 && !split.2, "a redacted line closed");
          prop_assert!(contains_bytes(&once.0, decoy_value.as_bytes()), "the decoy was not written");
        }
        Ok(())
      }
    },
  )
  .await;
}
