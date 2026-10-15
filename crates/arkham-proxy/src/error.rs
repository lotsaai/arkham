//! Crate error type: every fallible API returns `Result<T, Error>`.

use std::error::Error as StdError;
use std::io::Error as IoError;
use std::path::PathBuf;

use crate::connection::TrustAnchorsError;
use httparse::Error as HttparseError;
use russh::Error as RusshError;
use rustls::Error as RustlsError;

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
  /// A file cannot be read.
  #[error("read {path}: {source}", path = path.display())]
  ReadFile {
    /// File that could not be read.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
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
  /// A guest Postgres TLS handshake fails.
  #[error("guest postgres TLS: {source}")]
  GuestPostgresTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// A server Postgres TLS handshake fails.
  #[error("server postgres TLS: {source}")]
  ServerPostgresTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// A Postgres upstream name cannot become a TLS server name.
  #[error("postgres server name: {source}")]
  PostgresServerName {
    /// Underlying name failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// A guest Redis TLS handshake fails.
  #[error("guest redis TLS: {source}")]
  GuestRedisTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// A server Redis TLS handshake fails.
  #[error("server redis TLS: {source}")]
  ServerRedisTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// A Redis upstream name cannot become a TLS server name.
  #[error("redis server name: {source}")]
  RedisServerName {
    /// Underlying name failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// A guest SMTP TLS handshake fails.
  #[error("guest smtp TLS: {source}")]
  GuestSmtpTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// A guest LDAP TLS handshake fails.
  #[error("guest ldap TLS: {source}")]
  GuestLdapTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// A server SMTP TLS handshake fails.
  #[error("server smtp TLS: {source}")]
  ServerSmtpTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// A server LDAP TLS handshake fails.
  #[error("server ldap TLS: {source}")]
  ServerLdapTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// An SMTP upstream name cannot become a TLS server name.
  #[error("smtp server name: {source}")]
  SmtpServerName {
    /// Underlying name failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// An LDAP upstream name cannot become a TLS server name.
  #[error("ldap server name: {source}")]
  LdapServerName {
    /// Underlying name failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// A guest AMQP TLS handshake fails.
  #[error("guest amqp TLS: {source}")]
  GuestAmqpTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// A server AMQP TLS handshake fails.
  #[error("server amqp TLS: {source}")]
  ServerAmqpTls {
    /// Underlying handshake failure.
    #[source]
    source: IoError,
  },
  /// An AMQP upstream name cannot become a TLS server name.
  #[error("amqp server name: {source}")]
  AmqpServerName {
    /// Underlying name failure.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// An AMQP TLS handshake exceeded the configured budget.
  #[error("amqp handshake timed out")]
  AmqpHandshakeTimeout,
  /// An SMTP TLS handshake exceeded the configured budget.
  #[error("smtp handshake timed out")]
  SmtpHandshakeTimeout,
  /// An SMTP leg was asked to start TLS when it was already in TLS.
  #[error("smtp leg is already TLS")]
  SmtpLegAlreadyTls,
  /// An LDAP message this proxy built could not be encoded.
  #[error("ldap encode: {source}")]
  LdapEncode {
    /// Underlying encoder failure.
    #[source]
    source: rasn::error::EncodeError,
  },
  /// `guest_tls_mode` is `mtls` and the postgres guest opened in cleartext.
  #[error("postgres mtls guest sent plaintext")]
  PostgresGuestPlaintext,
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
}
