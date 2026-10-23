use crate::scope::AmqpUriError;

/// Every way AMQP grant parsing and the SASL machine can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// An AMQP connection string does not parse.
  #[error("rule `{label}`: {source}")]
  Scope {
    /// Rule label.
    label: String,
    /// Parse failure.
    #[source]
    source: AmqpUriError,
  },
  /// An AMQP rule states its upstream identity outside the connection string.
  #[error("rule `{label}`: amqp states the upstream identity in its connection string (`sslcert`/`sslkey`), never in the rule table")]
  Identity {
    /// Rule label.
    label: String,
  },
  /// An AMQP rule states its upstream trust outside the connection string.
  #[error("rule `{label}`: amqp states upstream trust in its connection string (`sslrootcert`), never in the rule table")]
  Trust {
    /// Rule label.
    label: String,
  },
  /// A secret does not fit the smallest frame either peer can negotiate.
  #[error("amqp secret of {len} bytes exceeds the minimum frame")]
  SecretTooLong {
    /// Secret length in bytes.
    len: usize,
  },
  /// A guest Open cannot reserve the withheld prefix and stay above the minimum frame size.
  #[error("amqp open max-frame-size {offered} cannot reserve {room} bytes")]
  FrameMax {
    /// Maximum the guest offered.
    offered: u32,
    /// Bytes withheld from a later frame.
    room: usize,
  },
  /// A grant is active and the guest Open could not be lowered.
  #[error("amqp open could not be lowered")]
  OpenUnlowered,
  /// Retained AMQP payload exceeded the connection carry budget.
  #[error("amqp carry holds {bytes} bytes across {entries} links")]
  CarryBudget {
    /// Total retained bytes.
    bytes: usize,
    /// Carry-map entries.
    entries: usize,
  },
}

/// AMQP result.
pub type Result<T> = std::result::Result<T, Error>;
