//! Talos vertical: terminate the guest with mutual TLS, select the context
//! from the client certificate, dial that context's upstream, then pump.

use std::sync::Arc;

use dashmap::DashMap;
use rustls::client::ClientConfig;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_config::context::AmbientProtocol;
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

/// Talos transport. The guest certificate selects one context. The upstream
/// leg trusts that context's CA and presents that context's client certificate.
#[derive(Debug)]
pub(crate) struct TalosTransport {
  ca: CertAuthority,
  leaves: DashMap<String, Arc<ServerConfig>>,
  roots: DashMap<RootCert, Arc<RootCertStore>>,
}

impl TalosTransport {
  /// Build the guest leaf cache over the CA that signs those leaves.
  ///
  /// # Errors
  ///
  /// Returns an error when the CA cannot be read back from its own PEM.
  pub(crate) fn new(ca: &CertAuthority) -> Result<Self, Error> {
    Ok(Self {
      ca: CertAuthority::load(&ca.cert_pem(), &ca.key_pem())?,
      leaves: DashMap::new(),
      roots: DashMap::new(),
    })
  }
}

impl Transport for TalosTransport {
  type Scope = ();

  /// Handshake the guest, select one Talos grant from its certificate, dial
  /// that grant, and pump both directions. No certificate, or a certificate
  /// that matches nothing, closes without dialing.
  ///
  /// # Errors
  ///
  /// Returns an error when two contexts match the certificate, when the
  /// selected grant cannot name an upstream identity, or when a leg fails
  /// after selection. A guest handshake that does not complete closes quietly.
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
    let matched = matching_grants(&snapshot.grants, &identity, port, peer.as_ref())?;
    let Some((label, scope)) = one_match(&identity, port, matched)? else {
      tracing::debug!(host = %identity, port, "talos client certificate matched no context");
      return Ok(());
    };
    let server = self
      .connect_upstream(label, scope, dial_host, port, &identity, state.fwmark)
      .await?;
    let mut downstream = Raw::from_pairs(Vec::new());
    let mut upstream = Raw::from_pairs(Vec::new());
    relay_guarded(guest_tls, server, &mut downstream, &mut upstream, &[], &[]).await
  }
}

impl TalosTransport {
  /// Dial `dial_host` and present this grant's client certificate. Trust is
  /// the grant's `root_cert` alone.
  ///
  /// # Errors
  ///
  /// Returns an error when the grant names no CA or client identity, when
  /// those files do not load, or when the handshake fails.
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
    let ClientAuth::Single(data) = client_identity(cert, key)? else {
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

/// Talos grants covering `host`:`port` whose guest certificate file holds `peer`.
///
/// # Errors
///
/// Returns an error when a guest certificate file exists but does not parse.
fn matching_grants<'a>(grants: &'a [Grant], host: &str, port: u16, peer: &[u8]) -> Result<Vec<(&'a str, &'a EndpointScope)>, Error> {
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
    if guest_leaf_matches(scope, &credential.label, peer)? {
      matched.push((credential.label.as_str(), scope));
    }
  }
  Ok(matched)
}

/// The guest leaf materialized beside `client_cert` as `{label}.guest.crt`.
/// A missing file is not a match.
///
/// # Errors
///
/// Returns an error when the file cannot be read or holds no PEM certificate.
fn guest_leaf_matches(scope: &EndpointScope, label: &str, peer: &[u8]) -> Result<bool, Error> {
  let Some(client_cert) = &scope.client_cert else {
    return Ok(false);
  };
  let path = client_cert.with_file_name(format!("{label}.guest.crt"));
  let pem = match std::fs::read(&path) {
    Ok(pem) => pem,
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
    Err(source) => return Err(Error::ReadFile { path, source }),
  };
  for cert in CertificateDer::pem_slice_iter(&pem) {
    let cert = cert.map_err(|err| Error::GuestCertificate {
      path: path.clone(),
      source: err.into(),
    })?;
    if cert.as_ref() == peer {
      return Ok(true);
    }
  }
  Ok(false)
}

/// The upstream TLS name. An IP endpoint parses as an IP server name, and a
/// hostname stays a DNS name.
fn upstream_server_name(identity: &str) -> Result<ServerName<'static>, Error> {
  ServerName::try_from(identity.to_string()).map_err(|err| Error::TalosServerName { source: err.into() })
}

/// Zero matches closes. Two or more is an error naming every label.
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
  use super::upstream_server_name;
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
}
