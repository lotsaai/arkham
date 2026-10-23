//! Guest TLS mode and the upstream trust anchor named by a connection string.

use std::path::PathBuf;

/// How the guest leg treats client certificates. The mode is arkham's own
/// configuration, carried by the rule's `tls` table, never by an entry URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestTlsMode {
  /// Terminate TLS and never ask the guest for a client certificate.
  #[default]
  Tls,
  /// Request a client certificate and admit only ones arkham's own CA signs.
  Mtls,
}

/// Upstream trust anchor an entry names with `sslrootcert`: a PEM path, or
/// the `system` spelling for the platform trust store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RootCert {
  /// PEM trust anchors read from this path.
  Path(PathBuf),
  /// The platform trust store.
  System,
}
