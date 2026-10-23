//! Crate error type: every fallible API returns `Result<T, Error>`.

use std::error::Error as StdError;
use std::io::Error as IoError;
use std::path::PathBuf;

use crate::connection::TrustAnchorsError;
use httparse::Error as HttparseError;
use russh::Error as RusshError;

/// Every way proxy setup and connection serving can fail.
///
/// Per-connection failures mostly close quietly with a debug log; these
/// surface startup failures and the pre-auth errors the driver reports.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A plugin error passes through.
  #[error(transparent)]
  Plugin(#[from] arkham_plugin::Error),
  /// A PKI error passes through.
  #[error(transparent)]
  Pki(#[from] arkham_pki::Error),
  /// A raw I/O failure with no extra context.
  #[error(transparent)]
  Io(#[from] IoError),
  /// An ssh leg protocol failure.
  #[error(transparent)]
  Ssh(#[from] RusshError),
  /// No ssh host key path is set or derivable for a granted ssh leg.
  #[error("ssh host key path is unset")]
  SshHostKeyUnset,
  /// An ssh leg blob does not load.
  #[error("ssh blob {path}: {source}")]
  SshRead {
    /// Blob path.
    path: PathBuf,
    /// Underlying read failure.
    #[source]
    source: IoError,
  },
  /// A CONNECT head that does not parse.
  #[error(transparent)]
  HeadParse(#[from] HttparseError),
  /// The egress trust anchors reject.
  #[error("egress trust anchors: {source}")]
  EgressTrustAnchors {
    /// Underlying anchor failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// A trust bundle does not load.
  #[error(transparent)]
  TrustAnchors(#[from] TrustAnchorsError),
  /// An entry `root_cert` relay does not build.
  #[error("trust bundle {path}: {source}", path = path.display())]
  EntryTrustBundle {
    /// Bundle path.
    path: PathBuf,
    /// Underlying relay failure.
    #[source]
    source: Box<Error>,
  },
  /// The mTLS trust store does not build.
  #[error("mtls trust store: {source}")]
  MtlsTrustStore {
    /// Underlying store failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// The mTLS trust anchor does not load.
  #[error("mtls trust anchor: {source}")]
  MtlsTrustAnchor {
    /// Underlying anchor failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// MITM issuance bursts past its guard.
  #[error("MITM issuance burst exceeded for {identity}")]
  BurstExceeded {
    /// Identity being minted.
    identity: String,
  },
  /// The MITM relay fails.
  #[error("MITM relay: {source}")]
  MitmRelay {
    /// Underlying relay failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// The explicit listen socket does not build.
  #[error("explicit listen socket: {source}")]
  ListenSocket {
    /// Underlying socket failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// The explicit listener does not listen.
  #[error("explicit listen: {source}")]
  Listen {
    /// Underlying listen failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// The explicit listener does not bind.
  #[error("explicit bind: {source}")]
  Bind {
    /// Underlying bind failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// The client head read times out.
  #[error("client head read timed out")]
  HeadTimeout,
  /// A MITM identity does not parse.
  #[error("bad MITM identity {identity}: {source}")]
  BadIdentity {
    /// Offending identity.
    identity: String,
    /// Underlying parse failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// Minting refuses an empty value.
  #[error("cannot mint a decoy for an empty value")]
  MintEmpty,
  /// The upstream never answers the TLS request.
  #[error("upstream never answered the TLS request")]
  TlsRequestUnanswered,
  /// A guest NATS TLS handshake fails.
  #[error("guest nats TLS: {source}")]
  GuestNatsTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// A server NATS TLS handshake fails.
  #[error("server nats TLS: {source}")]
  ServerNatsTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// A NATS upstream name cannot become a TLS server name.
  #[error("nats server name: {source}")]
  NatsServerName {
    /// Underlying name failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// A NATS TLS handshake exceeded the configured budget.
  #[error("nats handshake timed out")]
  NatsHandshakeTimeout,
  /// `guest_tls_mode` is `mtls` and the guest sent plaintext after INFO.
  #[error("nats mtls guest sent plaintext")]
  NatsGuestPlaintext,
  /// The server's INFO set `tls_required` and the upstream is cleartext.
  #[error("nats server requires tls on a cleartext upstream")]
  NatsTlsRequired {
    /// INFO `tls_available`.
    tls_available: bool,
    /// INFO `tls_verify`.
    tls_verify: bool,
  },
  /// A cleartext INFO line did not finish an object, and `tls_required` was not true.
  #[error("nats INFO did not yield tls flags on a cleartext upstream")]
  NatsInfoUnreadable,
  /// An SMTP leg was asked to start TLS when it was already in TLS.
  #[error("smtp leg is already TLS")]
  SmtpLegAlreadyTls,
  /// Postgres authentication did not finish inside the handshake budget.
  #[error("postgres authentication timed out")]
  PostgresAuthTimeout,
  /// Postgres SCRAM framing failed after the server offered SASL.
  #[error("postgres scram authentication: {source}")]
  PostgresScram {
    /// Underlying protocol failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// An egress client identity does not build.
  #[error("client identity: {source}")]
  ClientAuthPolicy {
    /// Underlying build failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// An entry names a trust bundle the state never built.
  #[error("unknown trust bundle `{path}`", path = path.display())]
  UnknownTrustBundle {
    /// Missing bundle path.
    path: PathBuf,
  },
  /// An SMTP grant-parse failure reached the proxy.
  #[error(transparent)]
  Smtp(arkham_smtp::Error),
  /// A shared TLS or relay failure.
  #[error(transparent)]
  Wire(#[from] arkham_wire::Error),
  /// An LDAP encode or grant-parse failure reached the proxy.
  #[error(transparent)]
  Ldap(#[from] arkham_ldap::Error),
  /// An AMQP frame or grant-parse failure reached the proxy.
  #[error(transparent)]
  Amqp(#[from] arkham_amqp::Error),
}

impl From<arkham_smtp::Error> for Error {
  fn from(err: arkham_smtp::Error) -> Self {
    match err {
      arkham_smtp::Error::Wire(source) => Self::from(source),
      arkham_smtp::Error::LegAlreadyTls => Self::SmtpLegAlreadyTls,
      other => Self::Smtp(other),
    }
  }
}
