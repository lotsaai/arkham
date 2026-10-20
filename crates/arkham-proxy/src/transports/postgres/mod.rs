//! Postgres vertical: transport halves, serve arm, and the pgwire framing
//! machine — everything postgres owns.

mod auth;
pub(crate) mod machine;

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, ServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_config::grants::{GuestTlsMode, PostgresScope, RootCert, SslMode, SslNegotiation};
use arkham_pki::ca::CertAuthority;

use super::PairCtx;
use super::{ServeStream, TlsHalves, Transport};
use crate::Error;
use crate::connection::{Prefixed, client_identity, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::relay::relay_guarded;
use crate::transports::engine::{Direction, Postgres};
use crate::transports::engine::{GuestOpening, read_guest_opening, request_upstream_tls};
use crate::transports::tls::{cached_leaf, cached_leaf_mtls, cached_roots};
use rama::tls::client::ClientAuth;

/// Postgres transport: guest leaves under the `postgresql` ALPN, upstream
/// handshakes under libpq's `sslmode` law.
#[derive(Debug)]
pub(crate) struct PostgresTransport {
  ca: CertAuthority,
  provider: Arc<CryptoProvider>,
  leaves: DashMap<String, Arc<ServerConfig>>,
  roots: DashMap<RootCert, Arc<RootCertStore>>,
}

impl PostgresTransport {
  /// Build both halves over the CA that signs guest-facing leaves.
  ///
  /// # Errors
  ///
  /// Returns an error when the CA cannot be read back from its own PEM.
  pub(crate) fn new(ca: &CertAuthority) -> Result<Self, Error> {
    Ok(Self {
      // An own handle on the same CA: minting needs its signing key, and the
      // caller's borrow ends with this call.
      ca: CertAuthority::load(&ca.cert_pem(), &ca.key_pem())?,
      provider: CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
      leaves: DashMap::new(),
      roots: DashMap::new(),
    })
  }
}

impl TlsHalves for PostgresTransport {
  type Scope = PostgresScope;

  /// Accept the guest's TLS, minting the leaf for `sni` on first use.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted or the handshake fails.
  async fn accept_guest<G>(&self, name: &str, guest: G, guest_tls: GuestTlsMode) -> Result<ServerTlsStream<G>, Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    // A real server offers this identifier, and a direct-TLS client looks for
    // it (PostgreSQL 17). Classic clients offer no ALPN and see none.
    let config = match guest_tls {
      GuestTlsMode::Tls => cached_leaf(&self.ca, &self.leaves, name, Some(POSTGRESQL_ALPN))?,
      // `mtls` asks the guest for a client certificate and admits only ones
      // this arkham's own CA signs — the same anchor that mints the leaves.
      GuestTlsMode::Mtls => cached_leaf_mtls(&self.ca, &self.leaves, name, Some(POSTGRESQL_ALPN))?,
    };
    TlsAcceptor::from(config)
      .accept(guest)
      .await
      .map_err(|err| Error::GuestPostgresTls { source: err })
  }

  /// Handshake the server, verifying only what the entry asked to verify.
  ///
  /// # Errors
  ///
  /// Returns an error when the named trust anchor cannot be read, when the
  /// server name is unusable, or when the handshake fails.
  async fn connect_server<S>(&self, scope: &PostgresScope, server_name: &str, server: S) -> Result<ClientTlsStream<S>, Error>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let roots = match &scope.root_cert {
      Some(root) => Some(cached_roots(&self.roots, root)?),
      None => None,
    };
    let verifier = EgressCertVerifier {
      roots,
      check_name: scope.ssl == SslMode::VerifyFull,
      provider: Arc::clone(&self.provider),
    };
    let builder = ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(verifier));
    let mut config = match (&scope.client_cert, &scope.client_key) {
      // The entry names the proxy's client identity, so the upstream leg
      // presents it; nothing else invents one.
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
    if scope.negotiation == SslNegotiation::Direct {
      // Direct TLS is defined by this identifier, on both ends (RFC 9113 does
      // the same for `h2`). A negotiated-shape client offers nothing.
      config.alpn_protocols = vec![POSTGRESQL_ALPN.to_vec()];
    }
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| Error::PostgresServerName { source: err.into() })?;
    TlsConnector::from(Arc::new(config))
      .connect(name, server)
      .await
      .map_err(|err| Error::ServerPostgresTls { source: err })
  }
}

impl Transport for PostgresTransport {
  type Scope = PostgresScope;

  /// The `postgres://` arm. The entry states the far side's transport and
  /// the guest states its own, so both legs are settled here and the wire
  /// machine then works on plaintext whichever way either arrived.
  async fn serve<G>(&self, ServeStream { mut guest, params, scope }: ServeStream<'_, G, PostgresScope>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let CandidateParams {
      state,
      snapshot,
      host,
      raw_host,
      port,
      initial,
      ..
    } = params;
    let budget = Duration::from_secs(snapshot.proxy.handshake_timeout_secs);
    let Some(opening) = read_guest_opening(&mut guest, initial, budget).await? else {
      return Ok(());
    };
    let mut server_name = host.map(ToString::to_string);
    // Guest leg: everything already read past the opening, plus the name to
    // mint for when the guest asked for TLS. Those bytes were consumed from
    // the guest stream, so they are replayed into whichever leg follows.
    let mut guest_tls: Option<(Vec<u8>, String)> = None;
    let mut guest_head = Vec::new();
    if let GuestOpening::Tls(buf) = opening {
      let Some((hello_buf, identity, sni_name)) = guest_tls_opening(&mut guest, &buf, budget, host, &state.mint).await? else {
        return Ok(());
      };
      server_name = Some(sni_name);
      guest_tls = Some((hello_buf, identity));
    } else if let GuestOpening::Cleartext(buf) = opening {
      guest_head = buf;
    }

    if guest_tls.is_none() && scope.guest_tls == GuestTlsMode::Mtls {
      return Err(Error::PostgresGuestPlaintext);
    }

    // The real string states the far end: the dial follows its host and
    // port, not the destination the guest aimed at.
    let mut upstream = dial_marked(&scope.upstream.host, scope.upstream.port, state.fwmark).await?;
    // `disable` never asks. `allow` mimics libpq statelessly: the guest's
    // own escalation decides the upstream leg. A cleartext guest gets
    // cleartext upstream — a hostssl-only refusal is relayed honestly, and
    // it is the guest's libpq that reconnects with an SSLRequest — while a
    // guest that asked for TLS escalates the upstream to TLS too.
    let asks_tls = match scope.ssl {
      SslMode::Disable => false,
      SslMode::Allow => guest_tls.is_some(),
      SslMode::Prefer | SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull => true,
    };
    let accepted = if asks_tls {
      request_upstream_tls(&mut upstream, scope.negotiation, budget).await?
    } else {
      false
    };
    let needed = matches!(scope.ssl, SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull);
    if needed && !accepted {
      tracing::debug!(host = %scope.upstream.host, "server refused TLS on an entry that requires it; closing");
      return Ok(());
    }

    let ctx = PairCtx {
      grants: &snapshot.grants,
      host: server_name.as_deref().unwrap_or(raw_host),
      port,
      plugins: &state.plugins,
      mint: Some(state.mint_handle()),
    };
    // The upstream leg verifies against the real string's host, which its
    // certificate must carry.
    let upstream_name = scope.upstream.host.as_str();
    let postgres = &state.postgres;
    match (guest_tls, accepted) {
      (None, false) => relay(Prefixed::new(guest_head, guest), upstream, &ctx, budget).await,
      (Some((hello_buf, identity)), false) => {
        let plain = postgres
          .accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls)
          .await?;
        relay(plain, upstream, &ctx, budget).await
      }
      (None, true) => {
        let plain = postgres.connect_server(scope, upstream_name, upstream).await?;
        relay(Prefixed::new(guest_head, guest), plain, &ctx, budget).await
      }
      (Some((hello_buf, identity)), true) => {
        let guest_plain = postgres
          .accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls)
          .await?;
        let server_plain = postgres.connect_server(scope, upstream_name, upstream).await?;
        relay(guest_plain, server_plain, &ctx, budget).await
      }
    }
  }
}

/// Pump one settled pair: both legs are plaintext by the time this runs,
/// whichever transports carried them there.
async fn relay<G, S>(mut guest: G, mut server: S, ctx: &PairCtx<'_>, budget: Duration) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let (mut downstream_machine, mut upstream_machine) = postgres_pair(ctx);
  let auth::Prelude::Relay(tail) = auth::settle(&mut guest, &mut server, &mut downstream_machine, ctx, budget).await? else {
    return Ok(());
  };
  relay_guarded(guest, server, &mut downstream_machine, &mut upstream_machine, &[], &tail).await
}

/// ALPN identifier for direct Postgres TLS.
const POSTGRESQL_ALPN: &[u8] = b"postgresql";

/// Egress server verification shaped by the entry rather than by this proxy.
///
/// libpq verifies nothing when no trust anchor is named, which is what makes
/// `require` usable against a private server; it verifies the chain once one
/// is; and it checks the host name only for `verify-full`. Inventing an anchor
/// here would fail the servers those modes exist to reach.
#[derive(Debug)]
struct EgressCertVerifier {
  roots: Option<Arc<RootCertStore>>,
  check_name: bool,
  provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for EgressCertVerifier {
  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    _ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, RustlsError> {
    let Some(roots) = self.roots.as_ref() else {
      return Ok(ServerCertVerified::assertion());
    };
    let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
    rustls::client::verify_server_cert_signed_by_trust_anchor(
      &cert,
      roots,
      intermediates,
      now,
      self.provider.signature_verification_algorithms.all,
    )?;
    if self.check_name {
      rustls::client::verify_server_name(&cert, server_name)?;
    }
    Ok(ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.provider.signature_verification_algorithms.supported_schemes()
  }
}

/// Cleartext Postgres: pgwire greeting, then raw relay on postgres grants.
pub(crate) fn postgres_pair(ctx: &PairCtx<'_>) -> (Postgres, Postgres) {
  (
    Postgres::new(ctx.grants, ctx.host, ctx.port, Direction::Downstream),
    Postgres::new(ctx.grants, ctx.host, ctx.port, Direction::Upstream),
  )
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::time::Duration;

  use arkham_config::config::ProxyCfg;
  use arkham_config::grants::{Credential, Grant, GuestTlsMode, PostgresScope, ResolvedConfig};
  use arkham_pki::ca::{CertAuthority, install_crypto_provider};
  use secrecy::SecretString;
  use tokio::io::AsyncReadExt as _;
  use tokio::net::TcpListener;

  use super::PostgresTransport;
  use crate::ProxyState;
  use crate::identity::CandidateParams;
  use crate::transports::{ServeStream, Transport as _};

  const FAKE: &str = "arkham_fake_pg_pass"; // betterleaks:allow
  const VALUE: &str = "arkham_real_pg_pass_01"; // betterleaks:allow

  fn startup() -> Vec<u8> {
    let mut body = 196_608u32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0app\0database\0stubdb\0\0");
    let mut msg = u32::try_from(body.len() + 4).unwrap().to_be_bytes().to_vec();
    msg.extend(body);
    msg
  }

  fn wire(message: &impl pgwire::messages::Message) -> Vec<u8> {
    let mut buf = bytes::BytesMut::new();
    message.encode(&mut buf).unwrap();
    buf.to_vec()
  }

  async fn assert_opening_sends_nothing(initial: Vec<u8>, close: OpeningClose) {
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let spy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = spy.local_addr().unwrap().port();
    let bytes = Arc::new(AtomicUsize::new(0));
    let recorded = Arc::clone(&bytes);
    let spy_task = tokio::spawn(async move {
      let Ok(Ok((mut conn, _))) = tokio::time::timeout(Duration::from_secs(2), spy.accept()).await else {
        return;
      };
      let mut buf = [0u8; 64];
      if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut buf)).await {
        recorded.store(n, Ordering::Relaxed);
      }
    });
    let mut scope = PostgresScope::from_strings(
      &format!("postgres://app:{FAKE}@localhost:{port}/stubdb"),
      &format!("postgres://app:{VALUE}@localhost:{port}/stubdb?sslmode=require"),
    )
    .unwrap();
    scope.guest_tls = GuestTlsMode::Mtls;
    let state = ProxyState::new(
      ResolvedConfig {
        proxy: ProxyCfg {
          listen: "127.0.0.1:0".parse().unwrap(),
          ca_file: None,
          ssh_host_key: None,
          ssh_known_hosts: None,
          root_certs: Vec::new(),
          handshake_timeout_secs: 1,
        },
        grants: vec![Grant::Postgres {
          credential: Credential {
            label: "pg".into(),
            fake: FAKE.into(),
            value: SecretString::from(VALUE),
          },
          scope: Box::new(scope.clone()),
        }],
        plugins: Vec::new(),
      },
      &ca,
    )
    .unwrap();
    let snapshot = state.snapshot();
    let (guest, _peer) = tokio::io::duplex(64);
    let transport = PostgresTransport::new(&ca).unwrap();
    let result = transport
      .serve(ServeStream {
        guest,
        params: CandidateParams {
          state: &state,
          snapshot: snapshot.as_ref(),
          dial_host: "127.0.0.1",
          port,
          host: Some("localhost"),
          raw_host: "localhost",
          initial: &initial,
        },
        scope: &scope,
      })
      .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let sent = bytes.load(Ordering::Relaxed);
    spy_task.abort();
    assert_eq!(sent, 0, "plaintext mtls guest sent bytes upstream");
    match close {
      OpeningClose::Plaintext => {
        let err = result.expect_err("plaintext mtls guest");
        assert!(matches!(err, crate::Error::PostgresGuestPlaintext), "{err}");
      }
      OpeningClose::Quiet => {
        result.expect("sslrequest then non-tls bytes closes before the dial");
      }
    }
  }

  enum OpeningClose {
    Plaintext,
    Quiet,
  }

  #[tokio::test]
  async fn postgres_mtls_plaintext_guest_sends_nothing_upstream() {
    assert_opening_sends_nothing(startup(), OpeningClose::Plaintext).await;
  }

  #[tokio::test]
  async fn postgres_mtls_gssenc_then_startup_sends_nothing_upstream() {
    let mut opening = wire(&pgwire::messages::startup::GssEncRequest::new());
    opening.extend(startup());
    assert_opening_sends_nothing(opening, OpeningClose::Plaintext).await;
  }

  #[tokio::test]
  async fn postgres_mtls_cancel_request_sends_nothing_upstream() {
    let cancel = pgwire::messages::cancel::CancelRequest::new(7, pgwire::messages::startup::SecretKey::I32(11));
    assert_opening_sends_nothing(wire(&cancel), OpeningClose::Plaintext).await;
  }

  #[tokio::test]
  async fn postgres_mtls_sslrequest_then_plaintext_sends_nothing_upstream() {
    let mut opening = wire(&pgwire::messages::startup::SslRequest::new());
    opening.extend(startup());
    assert_opening_sends_nothing(opening, OpeningClose::Quiet).await;
  }
}
