//! Upstream client identity loaded from PEM files.

use std::path::Path;

use rama::tls::client::{ClientAuth, ClientAuthData};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::Error;

/// Load an upstream client identity (mTLS) from the entry's PEM paths: the
/// certificate chain and its key, ready for the relay's egress. Only the
/// entry names this identity; nothing invents one.
///
/// # Errors
///
/// Returns an error when a file cannot be read, the chain is empty, or the
/// key does not parse.
pub fn client_identity(cert: &Path, key: &Path) -> Result<ClientAuth, Error> {
  let cert_bytes = std::fs::read(cert).map_err(|err| Error::ReadFile {
    path: cert.to_path_buf(),
    source: err,
  })?;
  let key_bytes = std::fs::read(key).map_err(|err| Error::ReadFile {
    path: key.to_path_buf(),
    source: err,
  })?;
  let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|err| Error::GuestCertificate {
      path: cert.to_path_buf(),
      source: err.into(),
    })?;
  if chain.is_empty() {
    return Err(Error::EmptyChain { path: cert.to_path_buf() });
  }
  let private = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|err| Error::ClientKey {
    path: key.to_path_buf(),
    source: err.into(),
  })?;
  Ok(ClientAuth::Single(ClientAuthData {
    cert_chain: chain,
    private_key: private,
  }))
}
