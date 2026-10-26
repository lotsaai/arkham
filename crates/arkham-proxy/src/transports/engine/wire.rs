use std::borrow::Cow;

/// One direction of the credential swap on one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
  /// Guest→upstream: substitute decoy fakes with real values.
  Downstream,
  /// Upstream→guest: redact real values back to decoy fakes.
  Upstream,
}

/// Where a substitution hit was found (log context only, never values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Location {
  /// Raw header bytes.
  Header,
  /// Inside an `Authorization: Basic` credential.
  BasicAuth,
  /// Message body / DATA payload.
  Body,
}

/// One substitution hit: label and where it was found (never the value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hit {
  /// Grant label identifying the secret (never the value itself).
  pub(crate) label: String,
  /// Where the match was found.
  pub(crate) location: Location,
}

/// Result of feeding one chunk to a wire.
pub(crate) enum Rewritten<'a> {
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
pub(crate) trait Wire {
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
pub(crate) enum PeerFact {
  /// HEAD requests whose response bodies are suppressed.
  Heads(usize),
  /// A client operation waiting for a final response. `false` cannot be abandoned.
  Open(u32, bool),
  /// An abandon names that operation. It gets no response of its own.
  Abandon(u32),
}

/// What the response pump does with a withheld upgrade.
#[derive(Debug)]
pub(crate) enum LocalUpgrade {
  /// Stop the relay and hand both sockets to the handshake.
  Proceed,
  /// Write these bytes to the guest and keep relaying.
  Refuse(Vec<u8>),
  /// End the relay.
  Close,
}

/// One direction's upgrade, taken once from the feed that completed it.
#[derive(Debug)]
pub(crate) enum UpgradeNote {
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
pub(crate) struct CredentialPair {
  pub(crate) needle: Vec<u8>,
  pub(crate) replacement: Vec<u8>,
  pub(crate) label: String,
}
