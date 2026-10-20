//! Grant files read once when the proxy starts.
//!
//! A connection looks these up. It does not open the files again.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use arkham_config::context::guest_cert_path;
use arkham_config::grants::{Grant, ResolvedConfig};
use rama::tls::boring::client::ConnectorConfigClientAuth;
use rama::tls::boring::core::ssl::SslCredential;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;

use crate::Error;
use crate::connection::{client_identity, trust_anchors};

/// Guest leaves, upstream trust anchors, and client pairs named by the config.
#[derive(Clone, Default)]
pub(crate) struct GrantMaterial {
  bundles: HashMap<PathBuf, Vec<CertificateDer<'static>>>,
  leaves: HashMap<PathBuf, Vec<u8>>,
  credentials: HashMap<(PathBuf, PathBuf), SslCredential>,
}

impl GrantMaterial {
  /// Read every bundle, guest leaf, and client pair the grants name.
  ///
  /// # Errors
  ///
  /// Returns an error when a named file cannot be read or holds no certificate.
  /// A missing guest leaf is not an error: that grant has no certificate to match.
  pub(crate) fn load(resolved: &ResolvedConfig) -> Result<Self, Error> {
    let mut material = Self::default();
    for path in &resolved.proxy.root_certs {
      material.insert_anchors(path)?;
    }
    for grant in &resolved.grants {
      let Grant::Token { allow, .. } = grant else { continue };
      for scope in allow {
        if let Some(path) = &scope.root_cert {
          material.insert_anchors(path)?;
        }
        if let Some(cert) = &scope.client_cert {
          material.insert_leaf(cert)?;
        }
        if let (Some(cert), Some(key)) = (&scope.client_cert, &scope.client_key) {
          material.insert_pair(cert, key)?;
        }
      }
    }
    Ok(material)
  }

  /// Parsed certificates for a bundle loaded by [`Self::load`].
  ///
  /// # Errors
  ///
  /// Returns an error when `path` was not part of the load.
  pub(crate) fn anchors(&self, path: &Path) -> Result<&[CertificateDer<'static>], Error> {
    self
      .bundles
      .get(path)
      .map(Vec::as_slice)
      .ok_or_else(|| Error::UnknownTrustBundle { path: path.to_path_buf() })
  }

  /// Certificate bytes for one loaded bundle, sorted so two files can be compared.
  ///
  /// # Errors
  ///
  /// Returns an error when `path` was not part of the load.
  pub(crate) fn anchor_bytes(&self, path: &Path) -> Result<Vec<Vec<u8>>, Error> {
    let mut anchors: Vec<Vec<u8>> = self.anchors(path)?.iter().map(|cert| cert.as_ref().to_vec()).collect();
    anchors.sort_unstable();
    Ok(anchors)
  }

  /// DER of the guest leaf beside `client_cert`, when that file was present at load.
  #[must_use]
  pub(crate) fn guest_leaf(&self, client_cert: &Path) -> Option<Vec<u8>> {
    self.leaves.get(client_cert).cloned()
  }

  /// Upstream credential for a client pair loaded by [`Self::load`].
  ///
  /// # Errors
  ///
  /// Returns an error when the pair was not part of the load.
  pub(crate) fn ssl_credential(&self, cert: &Path, key: &Path) -> Result<SslCredential, Error> {
    self
      .credentials
      .get(&(cert.to_path_buf(), key.to_path_buf()))
      .cloned()
      .ok_or_else(|| Error::ReadFile {
        path: cert.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "client pair was not loaded with the proxy"),
      })
  }

  fn insert_anchors(&mut self, path: &Path) -> Result<(), Error> {
    if self.bundles.contains_key(path) {
      return Ok(());
    }
    let anchors = trust_anchors(path)?;
    self.bundles.insert(path.to_path_buf(), anchors);
    Ok(())
  }

  fn insert_leaf(&mut self, client_cert: &Path) -> Result<(), Error> {
    if self.leaves.contains_key(client_cert) {
      return Ok(());
    }
    let Some(path) = guest_cert_path(client_cert) else {
      return Ok(());
    };
    if !path.is_file() {
      return Ok(());
    }
    let bytes = std::fs::read(&path).map_err(|source| Error::ReadFile {
      path: path.clone(),
      source,
    })?;
    let mut certs = CertificateDer::pem_slice_iter(&bytes);
    let Some(first) = certs.next() else {
      return Err(Error::EmptyChain { path });
    };
    let der = first.map_err(|err| Error::GuestCertificate {
      path,
      source: Box::new(err),
    })?;
    self.leaves.insert(client_cert.to_path_buf(), der.as_ref().to_vec());
    Ok(())
  }

  fn insert_pair(&mut self, cert: &Path, key: &Path) -> Result<(), Error> {
    let key_id = (cert.to_path_buf(), key.to_path_buf());
    if self.credentials.contains_key(&key_id) {
      return Ok(());
    }
    let auth = client_identity(cert, key)?;
    let configured = ConnectorConfigClientAuth::try_from(auth).map_err(|err| Error::ClientAuthPolicy { source: err })?;
    let credential = SslCredential::try_from(configured).map_err(|err| Error::ClientAuthPolicy { source: err })?;
    self.credentials.insert(key_id, credential);
    Ok(())
  }

  /// Bundles for tests that compare paths without a full config.
  #[cfg(test)]
  pub(crate) fn from_anchor_files(paths: &[PathBuf]) -> Result<Self, Error> {
    let mut material = Self::default();
    for path in paths {
      material.insert_anchors(path)?;
    }
    Ok(material)
  }
}
