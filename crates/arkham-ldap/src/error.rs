//! LDAP grant parsing and encode failures.

use crate::scope::LdapUriError;

/// Every way LDAP grant parsing and a live session can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// An LDAP connection string does not parse.
  #[error("rule `{label}`: {source}")]
  Scope {
    /// Rule label.
    label: String,
    /// Parse failure.
    #[source]
    source: LdapUriError,
  },
  /// An LDAP rule states its upstream identity outside the connection string.
  #[error("rule `{label}`: ldap states the upstream identity in its connection string (`sslcert`/`sslkey`), never in the rule table")]
  Identity {
    /// Rule label.
    label: String,
  },
  /// An LDAP rule states its upstream trust outside the connection string.
  #[error("rule `{label}`: ldap states upstream trust in its connection string (`sslrootcert`), never in the rule table")]
  Trust {
    /// Rule label.
    label: String,
  },
  /// A fixed LDAP message could not be encoded.
  #[error("ldap encode: {source}")]
  Encode {
    /// Encoder failure.
    #[source]
    source: rasn::error::EncodeError,
  },
}

/// LDAP result.
pub type Result<T> = std::result::Result<T, Error>;
