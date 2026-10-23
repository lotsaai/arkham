//! SMTP byte properties. The harness drives the AUTH machine on a current-thread
//! runtime. `block_on` stays in this test module.

use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine as _;
use proptest::prelude::*;
use secrecy::SecretString;
use tokio::io::{AsyncRead, ReadBuf};

use arkham_wire::GuestTlsMode;
use arkham_wire::engine::{CredentialPair, Direction, Rewritten, Wire};

use crate::machine::{AuthMaterial, MAX_COMMAND, Smtp};
use crate::scope::{SmtpLeg, SmtpScope};
use crate::session::{GuestLeg, acceptance_reply, plain_guest};

fn emit_bytes(rewritten: Rewritten<'_>) -> Vec<u8> {
  match rewritten {
    Rewritten::Emit(bytes) => bytes.into_owned(),
    Rewritten::Hold | Rewritten::Close => Vec::new(),
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

fn run_split_parts<M: Wire>(machine: &mut M, data: &[u8], splits: &[usize]) -> (Vec<u8>, usize, bool) {
  block_on(async {
    let mut out = Vec::new();
    let mut hits = 0usize;
    let mut prev = 0usize;
    let mut closed = false;
    for &cut in splits.iter().chain(std::iter::once(&data.len())) {
      if cut > prev {
        let (rewritten, chunk_hits) = machine.feed(&data[prev..cut]).await;
        closed |= matches!(rewritten, Rewritten::Close);
        out.extend_from_slice(&emit_bytes(rewritten));
        hits = hits.saturating_add(chunk_hits.len());
        prev = cut;
      }
    }
    if prev < data.len() {
      let (rewritten, chunk_hits) = machine.feed(&data[prev..]).await;
      closed |= matches!(rewritten, Rewritten::Close);
      out.extend_from_slice(&emit_bytes(rewritten));
      hits = hits.saturating_add(chunk_hits.len());
    }
    let (rewritten, chunk_hits) = machine.feed(&[]).await;
    closed |= matches!(rewritten, Rewritten::Close);
    out.extend_from_slice(&emit_bytes(rewritten));
    hits = hits.saturating_add(chunk_hits.len());
    (out, hits, closed)
  })
}

/// One reply stream. Each poll yields bytes up to the next cut, then pends once.
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
    let Some(piece) = rest.get(..n) else {
      return Poll::Ready(Ok(()));
    };
    buf.put_slice(piece);
    self.at = self.at.saturating_add(n);
    self.reads = self.reads.saturating_add(1);
    self.arm_pend = self.at < self.data.len();
    Poll::Ready(Ok(()))
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

fn smtp_machines(fake_pass: &str, real_pass: &str) -> (Smtp, Smtp) {
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
  let material = AuthMaterial::from_scope(&scope, "smtp");
  let pairs = vec![CredentialPair {
    needle: real_pass.as_bytes().to_vec(),
    replacement: fake_pass.as_bytes().to_vec(),
    label: "smtp".into(),
  }];
  let down = Smtp::new(Direction::Downstream, material.clone(), Vec::new());
  let mut up = Smtp::new(Direction::Upstream, material, pairs);
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
  let (_down, mut up) = smtp_machines(fake, real);
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
