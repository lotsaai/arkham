//! Cached guest leaves and upstream trust anchors shared by the TLS transports.
//!
//! Redis, Postgres, and LDAP each keep their own cache. The mint and the
//! PEM read are the same work, so they live here. A protocol that offers an
//! ALPN identifier passes it in; one that does not passes `None`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dashmap::DashMap;
use rama::tls::client::ClientAuth;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use rustls::{RootCertStore, ServerConfig};

use arkham_config::grants::RootCert;
use arkham_pki::ca::CertAuthority;
use arkham_pki::ca::generate_domain_pair;

use crate::Error;
use crate::connection::client_identity;

/// Leaf for one name, cached. Minted before insert so two guests naming the
/// same host keygen at most twice. `alpn` is offered when the protocol's
/// clients look for an identifier.
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
  if let Some(config) = leaves.get(sni) {
    return Ok(config.clone());
  }
  let mut config = (*ca.generate_domain_cert(sni)?.server_config).clone();
  if let Some(alpn) = alpn {
    config.alpn_protocols = vec![alpn.to_vec()];
  }
  let config = Arc::new(config);
  leaves.insert(sni.to_string(), Arc::clone(&config));
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
  let cache_key = format!("{sni}|mtls");
  if let Some(config) = leaves.get(&cache_key) {
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
  leaves.insert(cache_key, Arc::clone(&config));
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

/// Certificates at `path`, read once.
///
/// A missing file is [`None`]. An empty file is an empty chain.
///
/// # Errors
///
/// Returns an error when the file cannot be read or a PEM block is not a certificate.
pub(crate) fn cached_guest_certs(
  cache: &DashMap<PathBuf, Arc<Vec<CertificateDer<'static>>>>,
  path: &Path,
) -> Result<Option<Arc<Vec<CertificateDer<'static>>>>, Error> {
  if let Some(hit) = cache.get(path) {
    return Ok(Some(Arc::clone(hit.value())));
  }
  let pem = match std::fs::read(path) {
    Ok(pem) => pem,
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
    Err(source) => {
      return Err(Error::ReadFile {
        path: path.to_path_buf(),
        source,
      });
    }
  };
  let mut certs = Vec::new();
  for cert in CertificateDer::pem_slice_iter(&pem) {
    certs.push(cert.map_err(|err| Error::GuestCertificate {
      path: path.to_path_buf(),
      source: err.into(),
    })?);
  }
  let certs = Arc::new(certs);
  cache.insert(path.to_path_buf(), Arc::clone(&certs));
  Ok(Some(certs))
}

/// Upstream client identity for `cert` and `key`, read once.
///
/// # Errors
///
/// Returns an error when the pair cannot be read or parsed.
pub(crate) fn cached_client_identity(cache: &DashMap<PathBuf, ClientAuth>, cert: &Path, key: &Path) -> Result<ClientAuth, Error> {
  if let Some(hit) = cache.get(cert) {
    return Ok(hit.clone());
  }
  let auth = client_identity(cert, key)?;
  cache.insert(cert.to_path_buf(), auth.clone());
  Ok(auth)
}
