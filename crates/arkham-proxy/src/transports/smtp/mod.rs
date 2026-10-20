//! SMTP vertical: transport halves, then the shared relay.
//!
//! `smtp://` is cleartext until `STARTTLS`. The cleartext opening reads the
//! greeting and the upgrade, then both sockets go to `relay_guarded`.
//! `smtps://` is TLS from the first byte and relays immediately. The
//! upstream `smtps` leg, and a `starttls=required` leg after it upgrades,
//! verify the chain and the host name.

mod machine;
mod session;

#[cfg(test)]
pub(crate) use machine::{MAX_COMMAND, Smtp};
#[cfg(test)]
pub(crate) use session::{GuestLeg, acceptance_reply, plain_guest};

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_config::grants::{GuestTlsMode, RootCert, SmtpScope};
use arkham_pki::ca::CertAuthority;
use arkham_pki::ca::generate_domain_pair;

use super::{PairCtx, ServeStream, TlsHalves, Transport};
use crate::Error;
use crate::connection::{Prefixed, client_identity, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use rama::tls::client::ClientAuth;

/// First byte of a TLS record carrying a handshake. A cleartext `smtp`
/// scope never serves one; implicit TLS is `smtps`.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;

/// SMTP transport. Each connection string states its own leg.
#[derive(Debug)]
pub(crate) struct SmtpTransport {
  ca: CertAuthority,
  leaves: DashMap<String, Arc<ServerConfig>>,
  roots: DashMap<RootCert, Arc<RootCertStore>>,
}

impl SmtpTransport {
  /// Build both halves over the CA that signs guest-facing leaves.
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

  // TODO: `leaf`, `leaf_mtls`, and `roots_for` match the Redis transport.
  // A later TLS protocol should share them instead of copying them again.
  /// Leaf for one name, cached. Minted before insert so two guests naming
  /// the same host keygen at most twice.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted.
  fn leaf(&self, sni: &str) -> Result<Arc<ServerConfig>, Error> {
    if let Some(config) = self.leaves.get(sni) {
      return Ok(config.clone());
    }
    // SMTP has no ALPN identifier; a real server offers none either.
    let config = Arc::new((*self.ca.generate_domain_cert(sni)?.server_config).clone());
    self.leaves.insert(sni.to_string(), Arc::clone(&config));
    Ok(config)
  }

  /// `mtls` variant of [`Self::leaf`]: the same leaf, demanding a client
  /// certificate this arkham's CA can verify.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted or the verifier cannot
  /// be built.
  fn leaf_mtls(&self, sni: &str) -> Result<Arc<ServerConfig>, Error> {
    let cache_key = format!("{sni}|mtls");
    if let Some(config) = self.leaves.get(&cache_key) {
      return Ok(config.clone());
    }
    let (chain, key_der) = generate_domain_pair(&self.ca, sni)?;
    let mut roots = RootCertStore::empty();
    roots
      .add(self.ca.cert_der().clone())
      .map_err(|err| Error::MtlsGuestRoots { source: err })?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
      .build()
      .map_err(|err| Error::MtlsGuestVerifier { source: err.into() })?;
    let config = Arc::new(
      rustls::server::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key_der)
        .map_err(|err| Error::MtlsLeaf { source: err })?,
    );
    self.leaves.insert(cache_key, Arc::clone(&config));
    Ok(config)
  }

  /// Trust anchors for the upstream leg: the real string's `sslrootcert`,
  /// or the platform store when it names none.
  ///
  /// # Errors
  ///
  /// Returns an error when the anchor cannot be read or holds no certificates.
  fn roots_for(&self, root: &RootCert) -> Result<Arc<RootCertStore>, Error> {
    if let Some(store) = self.roots.get(root) {
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
    self.roots.insert(root.clone(), Arc::clone(&store));
    Ok(store)
  }
}

impl TlsHalves for SmtpTransport {
  type Scope = SmtpScope;

  /// Accept the guest's TLS, minting the leaf for `name` on first use.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted or the handshake fails.
  async fn accept_guest<G>(&self, name: &str, guest: G, guest_tls: GuestTlsMode) -> Result<ServerTlsStream<G>, Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    let config = match guest_tls {
      GuestTlsMode::Tls => self.leaf(name)?,
      GuestTlsMode::Mtls => self.leaf_mtls(name)?,
    };
    TlsAcceptor::from(config)
      .accept(guest)
      .await
      .map_err(|err| Error::GuestSmtpTls { source: err })
  }

  /// Handshake the server. The chain and the host name are verified
  /// against the real string's `sslrootcert`, or the platform store.
  ///
  /// # Errors
  ///
  /// Returns an error when the trust anchor cannot be read, when the server
  /// name is unusable, or when the handshake fails.
  async fn connect_server<S>(&self, scope: &SmtpScope, server_name: &str, server: S) -> Result<ClientTlsStream<S>, Error>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let root = scope.root_cert.clone().unwrap_or(RootCert::System);
    let roots = self.roots_for(&root)?;
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let config = match (&scope.client_cert, &scope.client_key) {
      (Some(cert), Some(key)) => {
        let ClientAuth::Single(data) = client_identity(cert, key)? else {
          return Err(Error::EmptyClientIdentity { path: cert.clone() });
        };
        builder
          .with_client_auth_cert(data.cert_chain.clone(), data.private_key.clone_key())
          .map_err(|err| Error::ClientIdentity {
            path: cert.clone(),
            source: err,
          })?
      }
      _ => builder.with_no_client_auth(),
    };
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| Error::SmtpServerName { source: err.into() })?;
    TlsConnector::from(Arc::new(config))
      .connect(name, server)
      .await
      .map_err(|err| Error::ServerSmtpTls { source: err })
  }
}

impl Transport for SmtpTransport {
  type Scope = SmtpScope;

  /// The `smtp://` / `smtps://` arm. Implicit TLS settles here and relays.
  /// `STARTTLS` upgrades in the cleartext opening, then both sockets relay.
  async fn serve<G>(&self, ServeStream { mut guest, params, scope }: ServeStream<'_, G, SmtpScope>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let CandidateParams {
      state,
      snapshot,
      host,
      port,
      initial,
      ..
    } = params;
    let budget = Duration::from_secs(snapshot.proxy.handshake_timeout_secs);
    let mut server_name = host.map(ToString::to_string);
    let guest_head = initial.to_vec();
    let mut guest_tls: Option<(Vec<u8>, String)> = None;
    if scope.is_downstream_tls {
      // Transparent capture has no CONNECT authority. A ClientHello with no
      // SNI still has a name: the scope was chosen by port, and its
      // downstream host is the name that client checks the leaf against.
      let authority = host.or(Some(scope.downstream.host.as_str()));
      let Some((hello_buf, identity, sni_name)) = guest_tls_opening(&mut guest, initial, budget, authority, &state.mint).await? else {
        return Ok(());
      };
      server_name = Some(sni_name);
      guest_tls = Some((hello_buf, identity));
    } else if initial.first() == Some(&TLS_RECORD_HANDSHAKE) {
      tracing::debug!("TLS opening on a cleartext smtp scope; closing");
      return Ok(());
    }

    let upstream = dial_marked(&scope.upstream.host, scope.upstream.port, state.fwmark).await?;
    // Key the swap on the scope host. The captured address is not the name
    // in the connection string, and keying on it would forward the decoy.
    let matched_name = server_name
      .as_deref()
      .filter(|name| scope.downstream.host.eq_ignore_ascii_case(name));
    let ctx = PairCtx {
      grants: &snapshot.grants,
      redact: &snapshot.grants,
      host: matched_name.unwrap_or(scope.downstream.host.as_str()),
      port,
      plugins: &state.plugins,
      mint: Some(state.mint_handle()),
    };
    let upstream_name = scope.upstream.host.as_str();
    let guest_leg = match guest_tls {
      Some((hello_buf, identity)) => {
        let tls = within(
          budget,
          self.accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls),
        )
        .await?;
        session::tls_guest(tls)
      }
      None => session::plain_guest(Prefixed::new(guest_head, guest)),
    };
    let server_leg = if scope.is_upstream_tls {
      let tls = within(budget, self.connect_server(scope, upstream_name, upstream)).await?;
      session::tls_server(tls)
    } else {
      session::plain_server(upstream)
    };
    session::run(session::Dialogue {
      transport: self,
      scope,
      guest: guest_leg,
      server: server_leg,
      grants: ctx.grants,
      host: ctx.host,
      port: ctx.port,
      budget,
    })
    .await
  }
}

async fn within<T>(budget: Duration, handshake: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
  match tokio::time::timeout(budget, handshake).await {
    Ok(result) => result,
    Err(_elapsed) => Err(Error::SmtpHandshakeTimeout),
  }
}
