//! SMTP failures: connection-string law, rule-table placement, and the session.

use arkham_wire::Error as WireError;

use crate::scope::SmtpUriError;

/// Every way SMTP grant parsing and a live session can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// An SMTP connection string does not parse.
  #[error("rule `{label}`: {source}")]
  Scope {
    /// Rule label.
    label: String,
    /// Parse failure.
    #[source]
    source: SmtpUriError,
  },
  /// An SMTP rule states its upstream identity outside the connection string.
  #[error("rule `{label}`: smtp states the upstream identity in its connection string (`sslcert`/`sslkey`), never in the rule table")]
  Identity {
    /// Rule label.
    label: String,
  },
  /// An SMTP rule states its upstream trust outside the connection string.
  #[error("rule `{label}`: smtp states upstream trust in its connection string (`sslrootcert`), never in the rule table")]
  Trust {
    /// Rule label.
    label: String,
  },
  /// An SMTP leg was asked to start TLS when it was already in TLS.
  #[error("smtp leg is already TLS")]
  LegAlreadyTls,
  /// A shared TLS or relay failure.
  #[error(transparent)]
  Wire(WireError),
}

/// SMTP result.
pub type Result<T> = std::result::Result<T, Error>;
