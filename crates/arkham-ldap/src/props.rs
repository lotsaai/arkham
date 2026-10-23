//! LDAP byte properties. `block_on` stays in this test module.

use proptest::prelude::*;
use secrecy::ExposeSecret as _;

use arkham_wire::engine::{Direction, Rewritten, Wire};

use crate::{BindSwap, Ldap, LdapScope};

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

fn bind_swap() -> BindSwap {
  let user = LDAP_DN.replace('=', "%3D").replace(' ', "%20").replace(',', "%2C");
  let fake = format!("ldap://{user}:{LDAP_FAKE}@ldap:389");
  let real = format!("ldap://{user}:{LDAP_REAL}@ldap:389");
  let scope = LdapScope::from_strings(&fake, &real).expect("ldap scope");
  BindSwap {
    label: "ldap".into(),
    fake: scope.downstream.password.expose_secret().to_string(),
    real: scope.upstream.password.expose_secret().to_string(),
    downstream_dn: scope.downstream.dn,
    upstream_dn: scope.upstream.dn,
  }
}

fn ldap_leg(leg: LdapLeg) -> Ldap {
  let swap = bind_swap();
  match leg {
    LdapLeg::DownSwap | LdapLeg::DownClear => Ldap::new(Some(swap), Direction::Downstream),
    LdapLeg::Up => Ldap::new(Some(swap), Direction::Upstream),
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

  /// Fragmented `StartTLS` reply, held password prefix, and wide message ids.
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
        let once = run_ldap(ldap_leg(LdapLeg::DownSwap), &frame, &[]);
        let split = run_ldap(ldap_leg(LdapLeg::DownSwap), &frame, &scaled);
        let byte_cuts: Vec<usize> = (1..frame.len()).collect();
        let byte = run_ldap(ldap_leg(LdapLeg::DownSwap), &frame, &byte_cuts);
        prop_assert!(once.closed);
        prop_assert_eq!(once.closed, split.closed);
        prop_assert_eq!(once.closed, byte.closed);
        prop_assert_eq!(&once.out, &split.out);
        prop_assert_eq!(&once.out, &byte.out);
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

}
