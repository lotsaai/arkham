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
  DownSwap,
  DownClear,
  Up,
}

fn nats_leg(leg: NatsLeg) -> Nats {
  let grants = nats_grants(
    &format!("nats://agent:{NATS_FAKE}@{NATS_HOST}:{NATS_PORT}"),
    &format!("tls://agent:{NATS_REAL}@nats.upstream:{NATS_PORT}"),
  );
  match leg {
    NatsLeg::DownSwap => Nats::downstream(&grants, NATS_HOST, NATS_PORT, true),
    NatsLeg::DownClear => Nats::downstream(&grants, NATS_HOST, NATS_PORT, false),
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
/// matches one shot. A cleartext server leg changes nothing; a TLS one
/// swaps each decoy CONNECT; guest-bound bytes never hold the real password.
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
      let clear = nats_splits_match(NatsLeg::DownClear, &client, &client_cuts).await?;
      prop_assert_eq!(&clear.out, &client, "a cleartext server leg changed guest bytes");
      let swapped = nats_splits_match(NatsLeg::DownSwap, &client, &client_cuts).await?;
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
      let mut clear_down = nats_leg(NatsLeg::DownSwap);
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
      let mut down = nats_leg(NatsLeg::DownSwap);
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
      for leg in [NatsLeg::DownSwap, NatsLeg::DownClear] {
        for run in nats_runs(leg, prefix, &nats_cuts(&cuts, prefix)).await {
          prop_assert_eq!(run.out.as_slice(), prefix, "a partial guest command changed at EOF");
          prop_assert!(!run.closed, "a partial guest command closed the leg");
        }
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

/// A CONNECT past the cap is forwarded byte-identical. One shot and the
/// random cuts each end with the empty EOF flush. A TLS leg does not swap
/// it, and the command after it keeps the session open. One byte at a time
/// stays in the unit tests: this line is longer than the cap, and walking
/// every byte for 256 cases would pass the slow-test deadline.
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
      for leg in [NatsLeg::DownSwap, NatsLeg::DownClear] {
        let once = run_nats(leg, &data, &[]).await;
        let split = run_nats(leg, &data, &scaled).await;
        prop_assert!(!once.closed && !split.closed, "an oversize CONNECT closed the {leg:?} leg");
        prop_assert_eq!(&once.out, &data);
        prop_assert_eq!(&split.out, &data);
        prop_assert_eq!(once.hits, 0);
        prop_assert_eq!(split.hits, 0);
      }
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
      prop_oneof![Just(NatsLeg::DownSwap), Just(NatsLeg::DownClear), Just(NatsLeg::Up)],
    ),
    |(data, cut, leg)| async move {
      let _ = run_nats(leg, &data, &[cut.min(data.len())]).await;
      let mut reader = CutPend::new(data, &[cut]);
      let mut up = nats_leg(NatsLeg::Up);
      let mut down = nats_leg(NatsLeg::DownSwap);
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

fn prop_sig(seed: &NatsSeed, nonce: &[u8]) -> String {
  prop_b64(&seed.sign(nonce).expect("seed signs"))
}

async fn arm_down(grants: &[Grant]) -> Nats {
  let mut up = Nats::upstream(grants, NATS_HOST, NATS_PORT);
  let mut down = Nats::downstream(grants, NATS_HOST, NATS_PORT, true);
  let info = b"INFO {\"nonce\":\"N0NCE\"}\r\n";
  let (out, _, closed) = feed_parts(&mut up, info, &[]).await;
  assert!(!closed && out == info, "opening INFO");
  machine::arm_opening(&mut up, &mut down);
  down
}

/// A verifying CONNECT, cut anywhere, rewrites the same way and never emits the real seed.
#[tokio::test]
async fn prop_nats_signed_connect_is_split_stable() {
  let (fake_raw, fake) = mint_user();
  let (real_raw, real) = mint_user();
  let fake_jwt = prop_user_jwt(fake.public_key());
  let real_jwt = prop_user_jwt(real.public_key());
  let nkey = nats_grants(
    &format!("nats://nkey:{fake_raw}@{NATS_HOST}:{NATS_PORT}"),
    &format!("tls://nkey:{real_raw}@nats.upstream:{NATS_PORT}"),
  );
  let jwt = nats_grants(
    &format!("nats://creds:{fake_raw}:{fake_jwt}@{NATS_HOST}:{NATS_PORT}"),
    &format!("tls://creds:{real_raw}:{real_jwt}@nats.upstream:{NATS_PORT}"),
  );
  let nonce = b"N0NCE";
  let nkey_line = format!(
    "CONNECT {{\"nkey\":\"{}\",\"sig\":\"{}\",\"verbose\":false}}\r\n",
    fake.public_key(),
    prop_sig(&fake, nonce)
  )
  .into_bytes();
  let jwt_line = format!(
    "CONNECT {{\"jwt\":\"{fake_jwt}\",\"sig\":\"{}\",\"verbose\":false}}\r\n",
    prop_sig(&fake, nonce)
  )
  .into_bytes();
  let real_public = real.public_key().to_string();
  drive(
    concat!(module_path!(), "::prop_nats_signed_connect_is_split_stable"),
    (any::<bool>(), proptest::collection::vec(any::<usize>(), 0..6)),
    move |(jwt_kind, cuts)| {
      let grants = if jwt_kind { jwt.clone() } else { nkey.clone() };
      let line = if jwt_kind { jwt_line.clone() } else { nkey_line.clone() };
      let real_raw = real_raw.clone();
      let real_public = real_public.clone();
      let real_jwt = real_jwt.clone();
      async move {
        let mut once_down = arm_down(&grants).await;
        let mut split_down = arm_down(&grants).await;
        let once = feed_parts(&mut once_down, &line, &[]).await;
        let split = feed_parts(&mut split_down, &line, &nats_cuts(&cuts, &line)).await;
        prop_assert_eq!(&once.0, &split.0);
        prop_assert_eq!(once.1, split.1);
        prop_assert_eq!(once.2, split.2);
        prop_assert!(!once.2, "a verifying CONNECT closed");
        prop_assert!(!contains_bytes(&once.0, real_raw.as_bytes()), "the real seed reached upstream");
        if jwt_kind {
          prop_assert!(contains_bytes(&once.0, real_jwt.as_bytes()), "the real jwt was not written");
        } else {
          prop_assert!(
            contains_bytes(&once.0, real_public.as_bytes()),
            "the real public key was not written"
          );
        }
        Ok(())
      }
    },
  )
  .await;
}

/// Server bytes, cut anywhere, agree. Guest-bound output never carries the real seed, JWT, or public key.
#[tokio::test]
async fn prop_nats_guest_output_hides_signed_material() {
  let (fake_raw, fake) = mint_user();
  let (real_raw, real) = mint_user();
  let fake_jwt = prop_user_jwt(fake.public_key());
  let real_jwt = prop_user_jwt(real.public_key());
  let fake_public = fake.public_key().to_string();
  let real_public = real.public_key().to_string();
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
      nats_word(),
      nats_word(),
      proptest::collection::vec(any::<usize>(), 0..6),
    ),
    move |(jwt_kind, payload, pre, post, cuts)| {
      let grants = if jwt_kind { jwt.clone() } else { nkey.clone() };
      let real_raw = real_raw.clone();
      let real_public = real_public.clone();
      let real_jwt = real_jwt.clone();
      let fake_public = fake_public.clone();
      let fake_jwt = fake_jwt.clone();
      async move {
        let secret = if jwt_kind { real_jwt.as_str() } else { real_public.as_str() };
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
          let decoy = if jwt_kind { fake_jwt.as_str() } else { fake_public.as_str() };
          prop_assert!(contains_bytes(&once.0, decoy.as_bytes()), "the decoy was not written");
        }
        Ok(())
      }
    },
  )
  .await;
}
