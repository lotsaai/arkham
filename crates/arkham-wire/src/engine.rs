//! Byte substitution shared by every protocol machine.

use std::borrow::Cow;

/// One direction of the credential swap on one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
  /// Guest→upstream: substitute decoy fakes with real values.
  Downstream,
  /// Upstream→guest: redact real values back to decoy fakes.
  Upstream,
}

/// Where a substitution hit was found (log context only, never values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
  /// Raw header bytes.
  Header,
  /// Inside an `Authorization: Basic` credential.
  BasicAuth,
  /// Message body / DATA payload.
  Body,
}

/// One substitution hit: label and where it was found (never the value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
  /// Grant label identifying the secret (never the value itself).
  pub label: String,
  /// Where the match was found.
  pub location: Location,
}

/// Result of feeding one chunk to a wire.
#[derive(Debug)]
pub enum Rewritten<'a> {
  /// Emit these bytes toward the peer.
  Emit(Cow<'a, [u8]>),
  /// Nothing yet: frame incomplete, keep feeding.
  Hold,
  /// Fail closed: drop the connection, leak nothing.
  Close,
}

/// One direction's credential rewrite, framed by its protocol. Feeding an
/// empty chunk flushes held bytes at stream end. `take_peer_note` carries a
/// framing fact to the opposite direction. HTTP uses [`PeerFact::Heads`] so a
/// HEAD request suppresses the response body. LDAP uses [`PeerFact::Open`]
/// and [`PeerFact::Abandon`] so the upstream machine knows which client
/// operations still expect a response.
pub trait Wire {
  /// Process one chunk; empty input flushes held bytes at stream EOF.
  /// Async because the plugin hook awaits.
  fn feed<'a>(&mut self, chunk: &'a [u8]) -> impl Future<Output = (Rewritten<'a>, Vec<Hit>)> + Send;
  /// Guest-bound protocol reply, if the last chunk queued one.
  fn take_reply(&mut self) -> Option<Vec<u8>> {
    None
  }
  /// Framing fact for the opposite direction, if the last chunk queued one.
  fn take_peer_note(&mut self) -> Option<PeerFact> {
    None
  }
  /// Apply a framing fact from the opposite direction.
  fn apply_peer_note(&mut self, _fact: PeerFact) {}
  /// Upgrade noticed at a message boundary, if the last `feed` completed one.
  ///
  /// `prefix` is bytes already consumed that belong to the protocol after the
  /// upgrade. The relay stops and the caller replays them.
  fn take_upgrade(&mut self) -> Option<UpgradeNote> {
    None
  }
  /// The extended response with this id is the upgrade result.
  fn arm_upgrade(&mut self, _id: u64) {}
  /// Release `id`, or a parked one, when this direction is between messages.
  fn release_handoff(&mut self, id: Option<u64>) -> Option<u64> {
    id
  }
  /// Decide a withheld upgrade once the request pump has handed the id over.
  ///
  /// The default proceeds. A protocol that still has work in flight refuses.
  fn local_upgrade(&mut self, _id: u64) -> LocalUpgrade {
    LocalUpgrade::Proceed
  }
}

/// Framing fact on the request→response channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerFact {
  /// HEAD requests whose response bodies are suppressed.
  Heads(usize),
  /// A client operation waiting for a final response. `false` cannot be abandoned.
  Open(u32, bool),
  /// An abandon names that operation. It gets no response of its own.
  Abandon(u32),
}

/// What the response pump does with a withheld upgrade.
#[derive(Debug)]
pub enum LocalUpgrade {
  /// Stop the relay and hand both sockets to the handshake.
  Proceed,
  /// Write these bytes to the guest and keep relaying.
  Refuse(Vec<u8>),
  /// End the relay.
  Close,
}

/// One direction's upgrade, taken once from the feed that completed it.
#[derive(Debug)]
pub enum UpgradeNote {
  /// The upgrade request is complete. `local` means those bytes were not emitted.
  Request {
    /// Message id.
    id: u64,
    /// Bytes after the request. They belong to the next protocol.
    prefix: Vec<u8>,
    /// The request was withheld because the peer is already upgraded.
    local: bool,
  },
  /// The matching response is complete.
  Response {
    /// `true` when the peer accepted the upgrade.
    ok: bool,
    /// Bytes after the response. They belong to the next protocol.
    prefix: Vec<u8>,
  },
}

/// One needle→replacement pair for a connection direction.
#[derive(Clone)]
pub struct CredentialPair {
  /// Bytes to find. Logs never record these.
  pub needle: Vec<u8>,
  /// Bytes to write in place of `needle`.
  pub replacement: Vec<u8>,
  /// Grant label. Logs carry this, never the bytes.
  pub label: String,
}

impl std::fmt::Debug for CredentialPair {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("CredentialPair")
      .field("needle", &self.needle.len())
      .field("replacement", &self.replacement.len())
      .field("label", &self.label)
      .finish()
  }
}

/// Cross-chunk overlap window: longest needle minus one.
#[must_use]
pub fn max_tail_size(pairs: &[CredentialPair]) -> usize {
  pairs.iter().map(|pair| pair.needle.len()).max().unwrap_or(1).saturating_sub(1)
}

/// True for a match ending past `tail_len`: not wholly inside the tail the
/// previous chunk already reported.
#[must_use]
pub fn find_new_match(combined: &[u8], needle: &[u8], tail_len: usize) -> bool {
  if needle.is_empty() || combined.len() < needle.len() {
    return false;
  }
  combined
    .windows(needle.len())
    .enumerate()
    .any(|(i, w)| w == needle && i + needle.len() > tail_len)
}

/// True when needle matches in window starting before `old_tail_len`
/// (straddling the previous tail boundary).
#[must_use]
pub fn find_crossing(window: &[u8], needle: &[u8], old_tail_len: usize) -> bool {
  if needle.is_empty() || window.len() < needle.len() {
    return false;
  }
  window
    .windows(needle.len())
    .enumerate()
    .any(|(i, w)| i < old_tail_len && w == needle)
}

/// Scan-only hit detection with a rolling tail window. One hit per pair per
/// chunk: a chunk containing repeated needles reports one hit, not one per
/// occurrence.
#[must_use]
pub fn scan_with_tail(pairs: &[CredentialPair], tail: &mut Vec<u8>, tail_size: usize, data: &[u8], location: Location) -> Vec<Hit> {
  let mut hits = Vec::new();
  if tail.is_empty() {
    for pair in pairs {
      if find_new_match(data, &pair.needle, 0) {
        hits.push(Hit {
          label: pair.label.clone(),
          location,
        });
      }
    }
  } else {
    let old_tail_len = tail.len();
    let bound = tail_size.min(data.len());
    let mut window = std::mem::take(tail);
    window.extend_from_slice(&data[..bound]);
    for pair in pairs {
      let inside = find_new_match(data, &pair.needle, 0);
      let crossing = find_crossing(&window, &pair.needle, old_tail_len);
      if inside || crossing {
        hits.push(Hit {
          label: pair.label.clone(),
          location,
        });
      }
    }
  }
  let keep = tail_size.min(data.len());
  *tail = data[data.len() - keep..].to_vec();
  hits
}

/// Replace all non-overlapping occurrences; `None` when nothing matched.
/// Allocates only on first match; copies runs, never byte-at-a-time.
#[must_use]
pub fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Option<Vec<u8>> {
  if needle.is_empty() || haystack.len() < needle.len() {
    return None;
  }
  let mut out: Option<Vec<u8>> = None;
  let mut run_start = 0;
  let mut cursor = 0;
  while cursor + needle.len() <= haystack.len() {
    if haystack[cursor..].starts_with(needle) {
      let buf = out.get_or_insert_with(|| Vec::with_capacity(haystack.len()));
      buf.extend_from_slice(&haystack[run_start..cursor]);
      buf.extend_from_slice(replacement);
      cursor += needle.len();
      run_start = cursor;
    } else {
      cursor += 1;
    }
  }
  out.map(|mut buf| {
    buf.extend_from_slice(&haystack[run_start..]);
    buf
  })
}

/// Apply every pair. The borrow stands when nothing matched.
#[must_use]
pub fn replace_in<'a>(data: &'a [u8], pairs: &[CredentialPair], location: Location) -> (Cow<'a, [u8]>, Vec<Hit>) {
  let mut current = Cow::Borrowed(data);
  let mut hits = Vec::new();
  for pair in pairs {
    let hay: &[u8] = match &current {
      Cow::Borrowed(bytes) => bytes,
      Cow::Owned(buf) => buf,
    };
    if let Some(next) = replace_bytes(hay, &pair.needle, &pair.replacement) {
      current = Cow::Owned(next);
      hits.push(Hit {
        label: pair.label.clone(),
        location,
      });
    }
  }
  (current, hits)
}

/// True for response statuses that never carry a body (1xx, 204, 304).
#[must_use]
pub fn response_has_no_body(status: Option<u16>) -> bool {
  let Some(code) = status else {
    return false;
  };
  (100..200).contains(&code) || code == 204 || code == 205 || code == 304
}

/// Longest suffix of `data` (bounded by `bound`) that is a proper prefix of
/// some needle: exactly the bytes that might still grow into a match.
#[must_use]
pub fn needle_prefix_suffix_len(data: &[u8], pairs: &[CredentialPair], bound: usize) -> usize {
  let max = bound.min(data.len());
  for keep in (1..=max).rev() {
    let suffix = &data[data.len() - keep..];
    if pairs.iter().any(|pair| pair.needle.len() > keep && pair.needle.starts_with(suffix)) {
      return keep;
    }
  }
  0
}

/// How many bytes of `data` may be emitted (and substituted) now without
/// cutting a needle: past the end of every complete match, and short of any
/// trailing partial match that stays held until more bytes arrive.
#[must_use]
pub fn needle_safe_emit_len(data: &[u8], pairs: &[CredentialPair], tail_bound: usize) -> usize {
  let mut emit = data.len() - needle_prefix_suffix_len(data, pairs, tail_bound);
  for pair in pairs {
    let needle = &pair.needle;
    if needle.is_empty() || data.len() < needle.len() {
      continue;
    }
    let mut cursor = 0;
    while cursor + needle.len() <= data.len() {
      if data[cursor..].starts_with(needle) {
        emit = emit.max(cursor + needle.len());
        cursor += needle.len();
      } else {
        cursor += 1;
      }
    }
  }
  emit
}
