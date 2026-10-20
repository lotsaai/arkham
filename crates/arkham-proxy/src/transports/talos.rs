use std::path::{Path, PathBuf};
use std::sync::Arc;

use dashmap::DashMap;
use rustls::client::ClientConfig;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_config::context::{AmbientProtocol, guest_cert_file};
use arkham_config::grants::{EndpointScope, Grant, RootCert, Scheme};
use arkham_pki::ca::CertAuthority;
use rama::tls::client::ClientAuth;

use super::{ServeStream, Transport};
use crate::Error;
use crate::connection::{Prefixed, client_identity, dial_marked};
use crate::identity::{CandidateParams, Hello, read_client_hello};
use crate::relay::relay_guarded;
use crate::transports::engine::Raw;
use crate::transports::tls::cached_leaf_mtls;

/// HTTP/2 ALPN. The Talos API is gRPC.
const ALPN_H2: &[u8] = b"h2";

#[derive(Debug)]
pub(crate) struct TalosTransport {
  ca: CertAuthority,
  leaves: DashMap<String, Arc<ServerConfig>>,
  roots: DashMap<RootCert, Arc<RootCertStore>>,
  guest_certs: DashMap<PathBuf, Arc<Vec<CertificateDer<'static>>>>,
  identities: DashMap<PathBuf, ClientAuth>,
}

impl TalosTransport {
  pub(crate) fn new(ca: &CertAuthority) -> Result<Self, Error> {
    Ok(Self {
      ca: CertAuthority::load(&ca.cert_pem(), &ca.key_pem())?,
      leaves: DashMap::new(),
      roots: DashMap::new(),
      guest_certs: DashMap::new(),
      identities: DashMap::new(),
    })
  }
}

impl Transport for TalosTransport {
  type Scope = ();

  async fn serve<G>(&self, ServeStream { mut guest, params, .. }: ServeStream<'_, G, ()>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let CandidateParams {
      state,
      snapshot,
      dial_host,
      port,
      host,
      initial,
      ..
    } = params;
    let budget = std::time::Duration::from_secs(snapshot.proxy.handshake_timeout_secs);
    let Some(read) = read_client_hello(&mut guest, initial, budget).await? else {
      return Ok(());
    };
    let (hello, sni) = match read {
      Hello::Named { buf, sni, .. } => (buf, Some(sni)),
      Hello::Unnamed { buf, .. } => (buf, None),
    };
    if let (Some(authority), Some(named)) = (host, sni.as_deref())
      && !named.eq_ignore_ascii_case(authority)
    {
      tracing::debug!(authority, sni = named, "CONNECT authority differs from SNI; closing");
      return Ok(());
    }
    let identity = match (host, sni) {
      (Some(authority), _) => authority.to_string(),
      (None, Some(named)) => named,
      (None, None) => dial_host.to_string(),
    };
    if identity.is_empty() {
      return Ok(());
    }
    if !state.mint.allow() {
      return Err(Error::BurstExceeded { identity });
    }
    let config = cached_leaf_mtls(&self.ca, &self.leaves, &identity, Some(ALPN_H2))?;
    let accepted = TlsAcceptor::from(config).accept(Prefixed::new(hello, guest)).await;
    let guest_tls = match accepted {
      Ok(stream) => stream,
      Err(err) => {
        tracing::debug!(%err, "talos guest handshake closed");
        return Ok(());
      }
    };
    let Some(peer) = guest_tls.get_ref().1.peer_certificates().and_then(|certs| certs.first()).cloned() else {
      tracing::debug!(host = %identity, port, "talos guest presented no certificate");
      return Ok(());
    };
    let matched = matching_grants(&self.guest_certs, &snapshot.grants, &identity, port, peer.as_ref())?;
    let Some((label, scope)) = one_match(&identity, port, matched)? else {
      tracing::debug!(host = %identity, port, "talos client certificate matched no context");
      return Ok(());
    };
    let server = match self.connect_upstream(label, scope, dial_host, port, &identity, state.fwmark).await {
      Ok(server) => server,
      Err(err) => {
        tracing::warn!(%err, host = %identity, port, label, "talos upstream");
        return Err(err);
      }
    };
    let mut downstream = Raw::from_pairs(Vec::new());
    let mut upstream = Raw::from_pairs(Vec::new());
    relay_guarded(guest_tls, server, &mut downstream, &mut upstream, &[], &[]).await
  }
}

impl TalosTransport {
  async fn connect_upstream(
    &self,
    label: &str,
    scope: &EndpointScope,
    dial_host: &str,
    port: u16,
    identity: &str,
    fwmark: Option<u32>,
  ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, Error> {
    let Some(root_path) = &scope.root_cert else {
      return Err(Error::TalosRootUnset {
        label: label.to_string(),
        host: identity.to_string(),
        port,
      });
    };
    let roots = crate::transports::tls::cached_roots(&self.roots, &RootCert::Path(root_path.clone()))?;
    let (Some(cert), Some(key)) = (&scope.client_cert, &scope.client_key) else {
      return Err(Error::TalosIdentityUnset {
        label: label.to_string(),
        host: identity.to_string(),
        port,
      });
    };
    let ClientAuth::Single(data) = cached_client_identity(&self.identities, cert, key)? else {
      return Err(Error::EmptyClientIdentity { path: cert.clone() });
    };
    let mut config = ClientConfig::builder()
      .with_root_certificates(roots)
      .with_client_auth_cert(data.cert_chain.clone(), data.private_key.clone_key())
      .map_err(|err| Error::ClientIdentity {
        path: cert.clone(),
        source: err,
      })?;
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    let name = upstream_server_name(identity)?;
    let tcp = dial_marked(dial_host, port, fwmark).await?;
    TlsConnector::from(Arc::new(config))
      .connect(name, tcp)
      .await
      .map_err(|source| Error::TalosUpstreamTls { source })
  }
}

fn matching_grants<'a>(
  cache: &DashMap<PathBuf, Arc<Vec<CertificateDer<'static>>>>,
  grants: &'a [Grant],
  host: &str,
  port: u16,
  peer: &[u8],
) -> Result<Vec<(&'a str, &'a EndpointScope)>, Error> {
  let mut matched = Vec::new();
  for grant in grants {
    let Some(credential) = grant.credential() else {
      continue;
    };
    if !AmbientProtocol::Talos.owns_label(&credential.label) {
      continue;
    }
    let Some(scope) = grant.endpoint(Scheme::Https, Some(host), port) else {
      continue;
    };
    if guest_leaf_matches(cache, scope, &credential.label, peer)? {
      matched.push((credential.label.as_str(), scope));
    }
  }
  Ok(matched)
}

fn guest_leaf_matches(
  cache: &DashMap<PathBuf, Arc<Vec<CertificateDer<'static>>>>,
  scope: &EndpointScope,
  label: &str,
  peer: &[u8],
) -> Result<bool, Error> {
  let Some(client_cert) = &scope.client_cert else {
    return Ok(false);
  };
  let path = client_cert.with_file_name(guest_cert_file(label));
  let Some(certs) = cached_guest_certs(cache, &path)? else {
    return Ok(false);
  };
  Ok(certs.iter().any(|cert| cert.as_ref() == peer))
}

fn cached_guest_certs(
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

fn cached_client_identity(cache: &DashMap<PathBuf, ClientAuth>, cert: &Path, key: &Path) -> Result<ClientAuth, Error> {
  if let Some(hit) = cache.get(cert) {
    return Ok(hit.clone());
  }
  let auth = client_identity(cert, key)?;
  cache.insert(cert.to_path_buf(), auth.clone());
  Ok(auth)
}

fn upstream_server_name(identity: &str) -> Result<ServerName<'static>, Error> {
  ServerName::try_from(identity.to_string()).map_err(|err| Error::TalosServerName { source: err.into() })
}

fn one_match<'a>(host: &str, port: u16, matched: Vec<(&'a str, &'a EndpointScope)>) -> Result<Option<(&'a str, &'a EndpointScope)>, Error> {
  match matched.len() {
    0 => Ok(None),
    1 => Ok(matched.into_iter().next()),
    _ => {
      let labels = matched.iter().map(|(label, _)| format!("`{label}`")).collect::<Vec<_>>().join(", ");
      Err(Error::TalosAmbiguous {
        labels,
        host: host.to_string(),
        port,
      })
    }
  }
}

#[cfg(test)]
mod tests {
  use arkham_config::grants::{Credential, EndpointScope, Grant, GuestTlsMode, Scheme};
  use arkham_pki::ca::{CertAuthority, generate_client_pair};
  use rama::crypto::pem::PemEncode as _;
  use secrecy::SecretString;

  use super::{matching_grants, upstream_server_name};
  use rustls::pki_types::ServerName;

  #[test]
  fn ip_endpoint_is_an_ip_server_name() {
    let name = upstream_server_name("10.5.0.2").expect("ip endpoint");
    let ServerName::IpAddress(ip) = name else {
      panic!("expected an IP server name");
    };
    assert_eq!(ip, std::net::Ipv4Addr::new(10, 5, 0, 2).into());
  }

  #[test]
  fn hostname_endpoint_stays_a_dns_name() {
    let name = upstream_server_name("talos.example").expect("hostname");
    assert!(matches!(name, ServerName::DnsName(_)));
  }

  #[test]
  fn guest_certificate_match_survives_removal_of_the_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let ca = CertAuthority::generate().expect("ca");
    let (chain, _) = generate_client_pair(&ca, "guest").expect("guest");
    let label = "talos-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let guest = dir.path().join(arkham_config::context::guest_cert_file(label));
    let mut pem = String::new();
    for cert in &chain {
      pem.push_str(&cert.to_pem());
    }
    std::fs::write(&guest, pem).expect("guest cert");
    let grants = vec![talos_grant(label, dir.path())];
    let peer = chain[0].as_ref();
    let cache = dashmap::DashMap::new();
    let first = matching_grants(&cache, &grants, "localhost", 50000, peer).expect("match");
    assert_eq!(first.len(), 1);
    std::fs::remove_file(&guest).expect("remove guest cert");
    let second = matching_grants(&cache, &grants, "localhost", 50000, peer).expect("cached match");
    assert_eq!(second.len(), 1);
  }

  #[test]
  fn upstream_identity_stays_loaded_after_the_key_file_is_removed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let ca = CertAuthority::generate().expect("ca");
    let (cert, key) = arkham_pki::ca::load_or_generate_client_pair(&ca, dir.path(), "client").expect("pair");
    let cache = dashmap::DashMap::new();
    super::cached_client_identity(&cache, &cert, &key).expect("load");
    std::fs::remove_file(&key).expect("remove key");
    super::cached_client_identity(&cache, &cert, &key).expect("cached identity");
  }

  fn talos_grant(label: &str, dir: &std::path::Path) -> Grant {
    Grant::Token {
      credential: Credential {
        label: label.to_string(),
        fake: "fake".into(),
        value: SecretString::from("value"),
      },
      allow: vec![EndpointScope {
        scheme: Scheme::Https,
        host: "localhost".parse().expect("host"),
        port: 50000,
        client_cert: Some(dir.join(format!("{label}.client.crt"))),
        client_key: Some(dir.join(format!("{label}.client.key"))),
        root_cert: Some(dir.join(format!("{label}.ca.crt"))),
        guest_tls: GuestTlsMode::Mtls,
      }],
      pattern: None,
      oauth2: None,
    }
  }
}
