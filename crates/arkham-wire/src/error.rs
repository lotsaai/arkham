//! Shared TLS and relay failures.

use std::error::Error as StdError;
use std::io::Error as IoError;
use std::path::PathBuf;

use rustls::Error as RustlsError;

/// Failures of the shared TLS legs, the client identity loader, and the relay.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A PKI failure passes through.
  #[error(transparent)]
  Pki(#[from] arkham_pki::Error),
  /// A file cannot be read.
  #[error("read {path}: {source}", path = path.display())]
  ReadFile {
    /// File that could not be read.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails writing the request head upstream.
  #[error("relay request head to upstream: {source}")]
  RequestHeadToUpstream {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails flushing the request head upstream.
  #[error("relay request head flush: {source}")]
  RequestHeadFlush {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails flushing the request to upstream.
  #[error("relay request flush to upstream: {source}")]
  RequestFlushToUpstream {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails writing a request chunk upstream.
  #[error("relay request chunk to upstream: {source}")]
  RequestChunkToUpstream {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails reading the guest.
  #[error("guest read: {source}")]
  GuestRead {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails reading upstream.
  #[error("upstream read: {source}")]
  UpstreamRead {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails flushing the response to the guest.
  #[error("relay response flush to guest: {source}")]
  ResponseFlushToGuest {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails writing a response chunk to the guest.
  #[error("relay response chunk to guest: {source}")]
  ResponseChunkToGuest {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails flushing the guest.
  #[error("relay guest flush: {source}")]
  GuestFlush {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails on the final guest flush.
  #[error("relay final guest flush: {source}")]
  FinalGuestFlush {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails writing a protocol reply to the guest.
  #[error("relay protocol reply to guest: {source}")]
  ProtocolReplyToGuest {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The relay fails flushing a protocol reply.
  #[error("relay protocol reply flush: {source}")]
  ProtocolReplyFlush {
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A guest certificate chain does not parse.
  #[error("certificate {path}: {source}", path = path.display())]
  GuestCertificate {
    /// Chain file that failed to parse.
    path: PathBuf,
    /// Underlying parse failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// A guest chain file holds no certificates.
  #[error("`{path}` holds no certificates", path = path.display())]
  EmptyChain {
    /// Chain file that holds nothing.
    path: PathBuf,
  },
  /// A client key does not parse.
  #[error("key {path}: {source}", path = path.display())]
  ClientKey {
    /// Key file that failed to parse.
    path: PathBuf,
    /// Underlying parse failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// A guest TLS handshake fails.
  #[error("guest TLS: {source}")]
  GuestTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// An upstream TLS handshake fails.
  #[error("server TLS: {source}")]
  ServerTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// An upstream name cannot become a TLS server name.
  #[error("TLS server name: {source}")]
  TlsServerName {
    /// Underlying name failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// A TLS handshake exceeded the configured budget.
  #[error("TLS handshake timed out")]
  HandshakeTimeout,
  /// The configured client identity is empty.
  #[error("client identity `{path}` is empty", path = path.display())]
  EmptyClientIdentity {
    /// Identity cert file that is empty.
    path: PathBuf,
  },
  /// The client identity does not build.
  #[error("client identity `{path}`: {source}", path = path.display())]
  ClientIdentity {
    /// Identity cert file that failed.
    path: PathBuf,
    /// Underlying build failure.
    #[source]
    source: RustlsError,
  },
  /// The mTLS guest roots do not build.
  #[error("mtls guest roots: {source}")]
  MtlsGuestRoots {
    /// Underlying build failure.
    #[source]
    source: RustlsError,
  },
  /// The mTLS guest verifier does not build.
  #[error("mtls guest verifier: {source}")]
  MtlsGuestVerifier {
    /// Underlying build failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// The mTLS leaf does not build.
  #[error("mtls leaf: {source}")]
  MtlsLeaf {
    /// Underlying build failure.
    #[source]
    source: RustlsError,
  },
  /// An `sslrootcert` file fails.
  #[error("sslrootcert {path}: {source}", path = path.display())]
  SslRootCert {
    /// Root file that failed.
    path: PathBuf,
    /// Underlying failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// An `sslrootcert` file holds no certificate.
  #[error("sslrootcert {path}: no certificate in file", path = path.display())]
  EmptyRootCert {
    /// Root file that holds nothing.
    path: PathBuf,
  },
  /// The system trust store reports an error.
  #[error("sslrootcert system store: {source}")]
  SystemStore {
    /// Underlying store failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// The system trust store holds no certificates.
  #[error("sslrootcert system store holds no certificates")]
  EmptySystemStore,
}

/// Shared result.
pub type Result<T> = std::result::Result<T, Error>;
