//! Cached guest leaves and upstream trust anchors.
//!
//! Every TLS transport shares one [`super::TlsCache`]. The leaf key is the
//! server name, the ALPN offer, and whether the leaf demands a client
//! certificate, so a `postgresql` leaf and a leaf that offers nothing stay
//! distinct for the same name.

use std::sync::Arc;

use dashmap::DashMap;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use rustls::{RootCertStore, ServerConfig};

use arkham_config::grants::RootCert;
use arkham_pki::ca::CertAuthority;
use arkham_pki::ca::generate_domain_pair;

use crate::Error;

/// Leaf for one name and one ALPN offer.
///
/// # Errors
///
/// Returns an error when the leaf cannot be minted.
pub(crate) fn cached_leaf(
  ca: &CertAuthority,
  leaves: &DashMap<String, Arc<ServerConfig>>,
  sni: &str,
  alpn: Option<&[u8]>,
) -> Result<Arc<ServerConfig>, Error> {
  let offered = alpn.map(|bytes| bytes.escape_ascii().to_string()).unwrap_or_default();
  let key = format!("t\0{offered}\0{sni}");
  if let Some(config) = leaves.get(&key) {
    return Ok(config.clone());
  }
  let mut config = (*ca.generate_domain_cert(sni)?.server_config).clone();
  if let Some(alpn) = alpn {
    config.alpn_protocols = vec![alpn.to_vec()];
  }
  let config = Arc::new(config);
  leaves.insert(key, Arc::clone(&config));
  Ok(config)
}

/// `mtls` variant of [`cached_leaf`]: the same leaf shape, presented by a
/// config that demands a client certificate this arkham's CA can verify.
///
/// # Errors
///
/// Returns an error when the leaf cannot be minted or the verifier cannot
/// be built.
pub(crate) fn cached_leaf_mtls(
  ca: &CertAuthority,
  leaves: &DashMap<String, Arc<ServerConfig>>,
  sni: &str,
  alpn: Option<&[u8]>,
) -> Result<Arc<ServerConfig>, Error> {
  let offered = alpn.map(|bytes| bytes.escape_ascii().to_string()).unwrap_or_default();
  let key = format!("m\0{offered}\0{sni}");
  if let Some(config) = leaves.get(&key) {
    return Ok(config.clone());
  }
  let (chain, key_der) = generate_domain_pair(ca, sni)?;
  let mut roots = RootCertStore::empty();
  roots
    .add(ca.cert_der().clone())
    .map_err(|err| Error::MtlsGuestRoots { source: err })?;
  let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
    .build()
    .map_err(|err| Error::MtlsGuestVerifier { source: err.into() })?;
  let mut config = rustls::server::ServerConfig::builder()
    .with_client_cert_verifier(verifier)
    .with_single_cert(chain, key_der)
    .map_err(|err| Error::MtlsLeaf { source: err })?;
  if let Some(alpn) = alpn {
    config.alpn_protocols = vec![alpn.to_vec()];
  }
  let config = Arc::new(config);
  leaves.insert(key, Arc::clone(&config));
  Ok(config)
}

/// Trust anchors for one upstream leg, read once per [`RootCert`].
///
/// # Errors
///
/// Returns an error when the anchor cannot be read or holds no certificates.
pub(crate) fn cached_roots(roots: &DashMap<RootCert, Arc<RootCertStore>>, root: &RootCert) -> Result<Arc<RootCertStore>, Error> {
  if let Some(store) = roots.get(root) {
    return Ok(store.clone());
  }
  let store = match root {
    RootCert::Path(path) => {
      let pem = std::fs::read(path).map_err(|err| Error::SslRootCert {
        path: path.clone(),
        source: err.into(),
      })?;
      let mut store = RootCertStore::empty();
      let mut anchors = 0usize;
      for cert in CertificateDer::pem_slice_iter(&pem) {
        let cert = cert.map_err(|err| Error::SslRootCert {
          path: path.clone(),
          source: err.into(),
        })?;
        store.add(cert).map_err(|err| Error::SslRootCert {
          path: path.clone(),
          source: err.into(),
        })?;
        anchors += 1;
      }
      if anchors == 0 {
        return Err(Error::EmptyRootCert { path: path.clone() });
      }
      store
    }
    // The platform trust store. An unreadable or empty store fails closed
    // rather than silently verifying nothing.
    RootCert::System => {
      let mut native = rustls_native_certs::load_native_certs();
      if !native.errors.is_empty() {
        return Err(Error::SystemStore {
          source: native.errors.remove(0).into(),
        });
      }
      let mut store = RootCertStore::empty();
      for cert in native.certs {
        store.add(cert).map_err(|err| Error::SystemStore { source: err.into() })?;
      }
      if store.is_empty() {
        return Err(Error::EmptySystemStore);
      }
      store
    }
  };
  let store = Arc::new(store);
  roots.insert(root.clone(), Arc::clone(&store));
  Ok(store)
}
