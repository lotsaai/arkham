//! Redis wire format: AUTH and HELLO credential rewrite, then raw relay.
//!
//! Downstream client commands parse as RESP arrays or inline lines. AUTH and
//! HELLO arguments reframe to the upstream spelling at any length; every
//! other command relays through [`Raw`]. Upstream is pure redaction: replies
//! authenticate nothing, but MONITOR and SLOWLOG output can carry the real
//! password back to the guest.

use std::borrow::Cow;

use arkham_config::grants::{Grant, RedisLeg, Scheme};
use secrecy::ExposeSecret as _;

use crate::transports::engine::{Direction, Hit, Location, Raw, Rewritten, Wire, raw_new};

/// Cap for one buffered command. Real AUTH and HELLO commands are tens of
/// bytes; anything past this is a drip or an attack, never an auth command.
const MAX_COMMAND: usize = 16_384;

/// One Redis direction leg.
pub(crate) struct Redis {
  /// Parse state. `None` on response legs: replies authenticate nothing.
  downstream: Option<Leg>,
  inner: Raw,
}

/// Downstream parse state.
struct Leg {
  /// Bytes waiting for a complete command.
  buf: Vec<u8>,
  /// Legs of the covering grant, when its users differ: the AUTH user
  /// argument reframes to the upstream spelling.
  legs: Option<(RedisLeg, RedisLeg)>,
  /// Fake password of the covering grant.
  fake: String,
  /// Real password of the covering grant.
  real: String,
  /// Grant label for hits.
  label: String,
  /// Fail-closed latch.
  closed: bool,
}

impl Redis {
  /// Fresh leg. Response legs never parse: replies authenticate nothing.
  pub(crate) fn new(grants: &[Grant], host: &str, port: u16, dir: Direction) -> Self {
    let downstream = (dir == Direction::Downstream)
      .then(|| {
        grants.iter().find(|grant| grant.redis(Some(host), port).is_some()).map(|grant| {
          let scope = grant.redis(Some(host), port).expect("find checked it");
          Leg {
            buf: Vec::new(),
            legs: (scope.upstream.user.is_some() && scope.upstream.user != scope.downstream.user)
              .then(|| (scope.downstream.clone(), scope.upstream.clone())),
            fake: scope.downstream.password.expose_secret().to_string(),
            real: scope.upstream.password.expose_secret().to_string(),
            label: grant.credential().map(|credential| credential.label.clone()).unwrap_or_default(),
            closed: false,
          }
        })
      })
      .flatten();
    Self {
      downstream,
      inner: raw_new(grants, Scheme::Redis, host, port, dir),
    }
  }

  /// Feed one downstream chunk through the command parser.
  async fn feed_downstream<'a>(&mut self, chunk: &'a [u8]) -> (Cow<'a, [u8]>, Vec<Hit>) {
    let Some(leg) = self.downstream.as_mut() else {
      return (Cow::Borrowed(&[]), Vec::new());
    };
    if chunk.is_empty() {
      // Stream end: flush whatever is buffered through the relay.
      let rest = std::mem::take(&mut leg.buf);
      let (out, hits) = self.inner_feed(&rest).await;
      return (Cow::Owned(out.into_owned()), hits);
    }
    leg.buf.extend_from_slice(chunk);
    let mut out = Vec::new();
    let mut hits = Vec::new();
    loop {
      if leg.buf.len() > MAX_COMMAND {
        leg.closed = true;
        return (Cow::Owned(out), hits);
      }
      let Some((frame, kind)) = take_command(&mut leg.buf) else {
        break;
      };
      if let Ok((bytes, found)) = rewrite_command(frame, &kind, &leg.fake, &leg.real, leg.legs.as_ref(), &leg.label) {
        out.extend_from_slice(&bytes);
        hits.extend(found);
      } else {
        leg.closed = true;
        return (Cow::Owned(Vec::new()), hits);
      }
    }
    (Cow::Owned(out), hits)
  }

  /// Steady-state relay through [`Raw`], mapped onto the shared Cow shape.
  async fn inner_feed<'a>(&mut self, chunk: &'a [u8]) -> (Cow<'a, [u8]>, Vec<Hit>) {
    match self.inner.feed(chunk).await {
      (Rewritten::Emit(bytes), hits) => (bytes, hits),
      (Rewritten::Hold | Rewritten::Close, hits) => (Cow::Borrowed(&[]), hits),
    }
  }
}

impl Wire for Redis {
  async fn feed<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    let (out, hits) = if self.downstream.is_some() {
      self.feed_downstream(chunk).await
    } else {
      self.inner_feed(chunk).await
    };
    let closed = self.downstream.as_ref().is_some_and(|leg| leg.closed);
    let rewritten = if closed {
      Rewritten::Close
    } else if out.is_empty() {
      Rewritten::Hold
    } else {
      Rewritten::Emit(out)
    };
    (rewritten, hits)
  }
}

/// One parsed client command. ARG positions are byte offsets in the frame.
struct Command {
  /// `AUTH` in any case.
  auth: bool,
  /// `HELLO` in any case.
  hello: bool,
  /// RESP arguments: `(start, len)` of each argument token's bytes, empty
  /// for inline commands.
  args: Vec<(usize, usize)>,
  /// Tokens after the verb, split on spaces.
  tokens: Vec<Vec<u8>>,
}

/// First `\n`, with its `\r` when present.
fn line_end(buf: &[u8]) -> Option<usize> {
  let nl = buf.iter().position(|&b| b == b'\n')?;
  buf.get(nl.wrapping_sub(1)).is_some_and(|&b| b == b'\r').then_some(nl + 1)
}

/// Take one complete command off the buffer. `None` while incomplete.
fn take_command(buf: &mut Vec<u8>) -> Option<(Vec<u8>, Command)> {
  if buf.first() == Some(&b'*') {
    take_array(buf)
  } else {
    take_inline(buf)
  }
}

/// Take one complete RESP array command.
fn take_array(buf: &mut Vec<u8>) -> Option<(Vec<u8>, Command)> {
  let header_end = line_end(buf)?;
  let count = parse_int(&buf[1..header_end])?;
  let mut args = Vec::with_capacity(count.min(64));
  let mut pos = header_end;
  for _ in 0..count {
    if buf.get(pos) != Some(&b'$') {
      return None;
    }
    let len_line = pos + line_end(&buf[pos..])?;
    let len = parse_int(&buf[pos + 1..len_line])?;
    let end = len_line.checked_add(len)?.checked_add(2)?;
    if buf.get(end.wrapping_sub(2)) != Some(&b'\r') || buf.get(end.wrapping_sub(1)) != Some(&b'\n') {
      return None;
    }
    args.push((len_line, len));
    pos = end;
  }
  if pos > buf.len() {
    return None;
  }
  let frame: Vec<u8> = buf.drain(..pos).collect();
  let tokens = args.iter().map(|&(start, len)| frame[start..start + len].to_vec()).collect();
  Some((frame, classify(tokens, args)))
}

/// Take one complete inline command.
fn take_inline(buf: &mut Vec<u8>) -> Option<(Vec<u8>, Command)> {
  let end = line_end(buf)?;
  let frame: Vec<u8> = buf.drain(..end).collect();
  let tokens = frame[..end - 2]
    .split(|&b| b == b' ')
    .filter(|token| !token.is_empty())
    .map(Vec::from)
    .collect();
  Some((frame, classify(tokens, Vec::new())))
}

/// Name the verb and carry the token offsets.
fn classify(tokens: Vec<Vec<u8>>, args: Vec<(usize, usize)>) -> Command {
  let verb = tokens.first().map(Vec::as_slice).unwrap_or_default();
  Command {
    auth: verb.eq_ignore_ascii_case(b"AUTH"),
    hello: verb.eq_ignore_ascii_case(b"HELLO"),
    args,
    tokens,
  }
}

/// Leading digits of a line (`$5\r\n`), no sign.
fn parse_int(line: &[u8]) -> Option<usize> {
  let digits: &[u8] = &line[..line.iter().position(|&b| !b.is_ascii_digit()).unwrap_or(line.len())];
  if digits.is_empty() {
    return None;
  }
  digits
    .iter()
    .try_fold(0usize, |acc, &b| acc.checked_mul(10)?.checked_add(usize::from(b - b'0')))
}

/// Rewrite AUTH and HELLO credentials in one complete command frame. `Err`
/// is a named command that breaks its own arity: fail closed.
fn rewrite_command(
  frame: Vec<u8>,
  kind: &Command,
  fake: &str,
  real: &str,
  legs: Option<&(RedisLeg, RedisLeg)>,
  label: &str,
) -> Result<(Vec<u8>, Vec<Hit>), ()> {
  if !kind.auth && !kind.hello {
    return Ok((frame, Vec::new()));
  }
  if kind.args.is_empty() {
    rewrite_inline(frame, kind, fake, real, legs, label)
  } else {
    rewrite_array(frame, kind, fake, real, legs, label)
  }
}
/// Index of the AUTH block's first argument. `None` when the command carries
/// no AUTH block. HELLO: `AUTH user password` needs two tokens after AUTH.
fn auth_block(kind: &Command) -> Option<usize> {
  if kind.auth {
    // Tokens carry the verb at 0; the AUTH block starts after it.
    return Some(1);
  }
  if !kind.hello {
    return None;
  }
  kind
    .tokens
    .iter()
    .skip(1)
    .position(|token| token.eq_ignore_ascii_case(b"AUTH"))
    .and_then(|at| {
      let first = at + 2;
      (first < kind.args.len()).then_some(first)
    })
}

/// Rewrite a RESP-framed AUTH or HELLO. Argument offsets stay valid while
/// reads happen before writes; every write is local to one token.
fn rewrite_array(
  mut frame: Vec<u8>,
  kind: &Command,
  fake: &str,
  real: &str,
  legs: Option<&(RedisLeg, RedisLeg)>,
  label: &str,
) -> Result<(Vec<u8>, Vec<Hit>), ()> {
  let count = kind.args.len();
  if kind.auth && count != 2 && count != 3 {
    return Err(());
  }
  let Some(auth_at) = auth_block(kind) else {
    return Ok((frame, Vec::new()));
  };
  // The AUTH block is `[user,] password`: the password index must exist, so
  // a HELLO naming AUTH without both user and password fails closed instead
  // of indexing past the argument list.
  let (user_at, pass_at) = if kind.hello || count - auth_at == 2 {
    if auth_at + 1 >= count {
      return Err(());
    }
    (Some(auth_at), auth_at + 1)
  } else {
    (None, auth_at)
  };
  let mut hits = Vec::new();
  // Password first, user after: a later token's swap never shifts an
  // earlier token's offsets.
  let (start, len) = kind.args[pass_at];
  if !fake.is_empty() && &frame[start..start + len] == fake.as_bytes() {
    swap_token(&mut frame, kind.args[pass_at], real.as_bytes());
    hits.push(Hit {
      label: label.to_string(),
      location: Location::Body,
    });
  }
  if let (Some(user_at), Some(legs)) = (user_at, legs)
    && let Some(user) = &legs.1.user
  {
    swap_token(&mut frame, kind.args[user_at], user.as_bytes());
  }
  Ok((frame, hits))
}

/// Rewrite an inline AUTH or HELLO line.
fn rewrite_inline(
  mut frame: Vec<u8>,
  kind: &Command,
  fake: &str,
  real: &str,
  legs: Option<&(RedisLeg, RedisLeg)>,
  label: &str,
) -> Result<(Vec<u8>, Vec<Hit>), ()> {
  let count = kind.tokens.len();
  let auth_at = if kind.auth {
    if count != 2 && count != 3 {
      return Err(());
    }
    1
  } else {
    let Some(at) = kind
      .tokens
      .iter()
      .skip(2)
      .position(|token| token.eq_ignore_ascii_case(b"AUTH"))
      .map(|at| at + 2)
    else {
      return Ok((frame, Vec::new()));
    };
    if at + 2 > count - 1 {
      return Ok((frame, Vec::new()));
    }
    at + 1
  };
  let user_at = (count >= auth_at + 2).then_some(auth_at);
  let pass_at = auth_at + usize::from(user_at.is_some());
  let mut hits = Vec::new();
  if let (Some(user_at), Some(legs)) = (user_at, legs)
    && let Some(user) = &legs.1.user
  {
    splice_inline(&mut frame, &kind.tokens[user_at], user.as_bytes());
  }
  if !fake.is_empty() && kind.tokens[pass_at] == fake.as_bytes() {
    splice_inline(&mut frame, &kind.tokens[pass_at], real.as_bytes());
    hits.push(Hit {
      label: label.to_string(),
      location: Location::Body,
    });
  }
  Ok((frame, hits))
}

/// Replace one RESP bulk-string token: body first, then its preceding
/// `$len` line's digits.
fn swap_token(frame: &mut Vec<u8>, (start, len): (usize, usize), body: &[u8]) {
  frame.splice(start..start + len, body.iter().copied());
  let Some(dollar) = frame[..start].iter().rposition(|&b| b == b'$') else {
    return;
  };
  let digits_end = start - 2;
  let digits = body.len().to_string();
  frame.splice(dollar + 1..digits_end, digits.bytes());
}

/// Replace one inline token in place.
fn splice_inline(frame: &mut Vec<u8>, token: &[u8], body: &[u8]) {
  let Some(start) = frame.windows(token.len().max(1)).position(|w| w == token) else {
    return;
  };
  frame.splice(start..start + token.len(), body.iter().copied());
}

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::grants::{Credential, GuestTlsMode, RedisScope};
  use secrecy::SecretString;

  const FAKE_PW: &str = "fakepw";
  const REAL_PW: &str = "real-password-value-99";

  fn grants(fake_user: Option<&str>, real_user: Option<&str>, fake_pw: &str, real_pw: &str) -> Vec<Grant> {
    vec![Grant::Redis {
      credential: Credential {
        label: "r".into(),
        fake: fake_pw.into(),
        value: SecretString::from(real_pw),
      },
      scope: Box::new(RedisScope {
        downstream: RedisLeg {
          host: "cache.internal".into(),
          port: 6379,
          user: fake_user.map(str::to_string),
          password: SecretString::from(fake_pw),
          database: Some("0".into()),
        },
        is_downstream_tls: false,
        upstream: RedisLeg {
          host: "cache.internal".into(),
          port: 6379,
          user: real_user.map(str::to_string),
          password: SecretString::from(real_pw),
          database: Some("0".into()),
        },
        is_upstream_tls: false,
        root_cert: None,
        client_cert: None,
        client_key: None,
        guest_tls: GuestTlsMode::default(),
      }),
    }]
  }

  fn downstream() -> Redis {
    Redis::new(
      &grants(Some("guest"), Some("svc"), FAKE_PW, REAL_PW),
      "cache.internal",
      6379,
      Direction::Downstream,
    )
  }

  /// Feed chunks through one leg, collecting emitted bytes, hits, and
  /// whether the leg failed closed.
  async fn feed_all(wire: &mut Redis, chunks: &[&[u8]]) -> (Vec<u8>, Vec<Hit>, bool) {
    let mut out = Vec::new();
    let mut hits = Vec::new();
    let mut closed = false;
    for chunk in chunks {
      match wire.feed(chunk).await {
        (Rewritten::Emit(bytes), found) => {
          out.extend_from_slice(&bytes);
          hits.extend(found);
        }
        (Rewritten::Hold, found) => hits.extend(found),
        (Rewritten::Close, found) => {
          hits.extend(found);
          closed = true;
          break;
        }
      }
    }
    (out, hits, closed)
  }

  #[tokio::test]
  async fn auth_password_reframes_to_any_length() {
    let mut wire = downstream();
    let (out, hits, closed) = feed_all(&mut wire, &[b"*2\r\n$4\r\nAUTH\r\n$6\r\nfakepw\r\n"]).await;
    assert!(!closed);
    assert_eq!(out, b"*2\r\n$4\r\nAUTH\r\n$22\r\nreal-password-value-99\r\n");
    assert_eq!(hits.len(), 1);
  }

  #[tokio::test]
  async fn auth_with_username_swaps_both() {
    let mut wire = downstream();
    let (out, _, closed) = feed_all(&mut wire, &[b"*3\r\n$4\r\nAUTH\r\n$5\r\nguest\r\n$6\r\nfakepw\r\n"]).await;
    assert!(!closed);
    assert_eq!(out, b"*3\r\n$4\r\nAUTH\r\n$3\r\nsvc\r\n$22\r\nreal-password-value-99\r\n");
  }

  #[tokio::test]
  async fn username_passes_through_when_legs_share_it() {
    let rules = grants(Some("app"), Some("app"), FAKE_PW, REAL_PW);
    let mut wire = Redis::new(&rules, "cache.internal", 6379, Direction::Downstream);
    let (out, _, closed) = feed_all(&mut wire, &[b"*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$6\r\nfakepw\r\n"]).await;
    assert!(!closed);
    assert_eq!(out, b"*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$22\r\nreal-password-value-99\r\n");
  }

  #[tokio::test]
  async fn hello_auth_reframes_around_setname() {
    let mut wire = downstream();
    let (out, _, closed) = feed_all(
      &mut wire,
      &[b"*6\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$5\r\nguest\r\n$6\r\nfakepw\r\n$7\r\nSETNAME\r\n$3\r\ncli\r\n"],
    )
    .await;
    assert!(!closed);
    assert_eq!(
      out,
      b"*6\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$3\r\nsvc\r\n$22\r\nreal-password-value-99\r\n$7\r\nSETNAME\r\n$3\r\ncli\r\n"
    );
  }

  #[tokio::test]
  async fn hello_auth_without_password_fails_closed() {
    let mut wire = downstream();
    let (_, _, closed) = feed_all(&mut wire, &[b"*3\r\n$5\r\nHELLO\r\n$4\r\nAUTH\r\n$5\r\nguest\r\n"]).await;
    assert!(closed);
  }

  #[tokio::test]
  async fn inline_auth_reframes() {
    let mut wire = downstream();
    let (out, _, closed) = feed_all(&mut wire, &[b"AUTH fakepw\r\n"]).await;
    assert!(!closed);
    assert_eq!(out, b"AUTH real-password-value-99\r\n");
  }

  #[tokio::test]
  async fn unknown_password_passes_through_untouched() {
    let mut wire = downstream();
    let (out, hits, closed) = feed_all(&mut wire, &[b"*2\r\n$4\r\nAUTH\r\n$5\r\nwrong\r\n"]).await;
    assert!(!closed);
    assert_eq!(out, b"*2\r\n$4\r\nAUTH\r\n$5\r\nwrong\r\n");
    assert_eq!(hits, [] as [Hit; 0]);
  }

  #[tokio::test]
  async fn other_commands_pass_through_byte_identical() {
    let mut wire = downstream();
    let (out, _, closed) = feed_all(&mut wire, &[b"*1\r\n$4\r\nPING\r\n*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"]).await;
    assert!(!closed);
    assert_eq!(out, b"*1\r\n$4\r\nPING\r\n*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n");
  }

  #[tokio::test]
  async fn pipelined_auth_then_select() {
    let mut wire = downstream();
    let (out, _, closed) = feed_all(
      &mut wire,
      &[b"*2\r\n$4\r\nAUTH\r\n$6\r\nfakepw\r\n*2\r\n$6\r\nSELECT\r\n$1\r\n0\r\n"],
    )
    .await;
    assert!(!closed);
    assert_eq!(
      out,
      b"*2\r\n$4\r\nAUTH\r\n$22\r\nreal-password-value-99\r\n*2\r\n$6\r\nSELECT\r\n$1\r\n0\r\n"
    );
  }

  #[tokio::test]
  async fn split_auth_holds_until_complete() {
    let mut wire = downstream();
    let full = b"*2\r\n$4\r\nAUTH\r\n$6\r\nfakepw\r\n";
    let (out, _, closed) = feed_all(&mut wire, &[&full[..10]]).await;
    assert!(!closed);
    assert_eq!(out, [] as [u8; 0]);
    let (out, _, closed) = feed_all(&mut wire, &[&full[10..]]).await;
    assert!(!closed);
    assert_eq!(out, b"*2\r\n$4\r\nAUTH\r\n$22\r\nreal-password-value-99\r\n");
  }

  #[tokio::test]
  async fn short_auth_arity_closes() {
    let mut wire = downstream();
    let (_, _, closed) = feed_all(&mut wire, &[b"*1\r\n$4\r\nAUTH\r\n"]).await;
    assert!(closed);
  }

  #[tokio::test]
  async fn oversized_command_closes() {
    let mut wire = downstream();
    let big = vec![b'x'; MAX_COMMAND + 1];
    let (_, _, closed) = feed_all(&mut wire, &[&big]).await;
    assert!(closed);
  }

  #[tokio::test]
  async fn upstream_redacts_real_password() {
    let rules = grants(Some("guest"), Some("svc"), "FAKEPASS1", "REALPASS1");
    let mut wire = Redis::new(&rules, "cache.internal", 6379, Direction::Upstream);
    let (out, hits, closed) = feed_all(&mut wire, &[b"+OK\r\n$8\r\nREALPASS1\r\n"]).await;
    assert!(!closed);
    assert_eq!(out, b"+OK\r\n$8\r\nFAKEPASS1\r\n");
    assert_eq!(hits.len(), 1);
  }
}
