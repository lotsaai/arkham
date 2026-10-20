pub(crate) mod machine;

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_config::grants::{AmqpScope, GuestTlsMode, RootCert};
use arkham_pki::ca::CertAuthority;

use super::PairCtx;
use super::{ServeStream, TlsHalves, Transport};
use crate::Error;
use crate::connection::{Prefixed, client_identity, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::relay::relay_guarded;
use crate::transports::engine::{Amqp, Direction};
use crate::transports::tls::{cached_leaf, cached_leaf_mtls, cached_roots};
use rama::tls::client::ClientAuth;

const TLS_RECORD_HANDSHAKE: u8 = 0x16;

#[derive(Debug)]
pub(crate) struct AmqpTransport {
  ca: CertAuthority,
  leaves: DashMap<String, Arc<ServerConfig>>,
  roots: DashMap<RootCert, Arc<RootCertStore>>,
}

impl AmqpTransport {
  pub(crate) fn new(ca: &CertAuthority) -> Result<Self, Error> {
    Ok(Self {
      ca: CertAuthority::load(&ca.cert_pem(), &ca.key_pem())?,
      leaves: DashMap::new(),
      roots: DashMap::new(),
    })
  }
}

impl TlsHalves for AmqpTransport {
  type Scope = AmqpScope;

  async fn accept_guest<G>(&self, name: &str, guest: G, guest_tls: GuestTlsMode) -> Result<ServerTlsStream<G>, Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    let config = match guest_tls {
      GuestTlsMode::Tls => cached_leaf(&self.ca, &self.leaves, name, None)?,
      GuestTlsMode::Mtls => cached_leaf_mtls(&self.ca, &self.leaves, name, None)?,
    };
    TlsAcceptor::from(config)
      .accept(guest)
      .await
      .map_err(|err| Error::GuestAmqpTls { source: err })
  }

  async fn connect_server<S>(&self, scope: &AmqpScope, server_name: &str, server: S) -> Result<ClientTlsStream<S>, Error>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let root = scope.root_cert.clone().unwrap_or(RootCert::System);
    let roots = cached_roots(&self.roots, &root)?;
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
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| Error::AmqpServerName { source: err.into() })?;
    TlsConnector::from(Arc::new(config))
      .connect(name, server)
      .await
      .map_err(|err| Error::ServerAmqpTls { source: err })
  }
}

impl Transport for AmqpTransport {
  type Scope = AmqpScope;

  async fn serve<G>(&self, ServeStream { mut guest, params, scope }: ServeStream<'_, G, AmqpScope>) -> Result<(), Error>
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
      let authority = host.or(Some(scope.downstream.host.as_str()));
      let Some((hello_buf, identity, sni_name)) = guest_tls_opening(&mut guest, initial, budget, authority, &state.mint).await? else {
        return Ok(());
      };
      server_name = Some(sni_name);
      guest_tls = Some((hello_buf, identity));
    } else if initial.first() == Some(&TLS_RECORD_HANDSHAKE) {
      tracing::debug!("TLS opening on a cleartext amqp scope; closing");
      return Ok(());
    }

    let upstream = dial_marked(&scope.upstream.host, scope.upstream.port, state.fwmark).await?;
    let matched_name = server_name
      .as_deref()
      .filter(|name| scope.downstream.host.eq_ignore_ascii_case(name));
    let ctx = PairCtx {
      grants: &snapshot.grants,
      host: matched_name.unwrap_or(scope.downstream.host.as_str()),
      port,
      plugins: &state.plugins,
      mint: Some(state.mint_handle()),
    };
    self
      .relay_settled(
        OpenGuest {
          stream: guest,
          head: guest_head,
          tls: guest_tls,
        },
        upstream,
        scope,
        &ctx,
        budget,
      )
      .await
  }
}

struct OpenGuest<G> {
  stream: G,
  head: Vec<u8>,
  tls: Option<(Vec<u8>, String)>,
}

impl AmqpTransport {
  async fn relay_settled<G, S>(
    &self,
    guest: OpenGuest<G>,
    upstream: S,
    scope: &AmqpScope,
    ctx: &PairCtx<'_>,
    budget: Duration,
  ) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let OpenGuest { stream, head, tls } = guest;
    let swap = scope.is_upstream_tls;
    let upstream_name = scope.upstream.host.as_str();
    match (tls, scope.is_upstream_tls) {
      (None, false) => relay(Prefixed::new(head, stream), upstream, ctx, swap).await,
      (Some((hello_buf, identity)), false) => {
        let plain = within(
          budget,
          self.accept_guest(&identity, Prefixed::new(hello_buf, stream), scope.guest_tls),
        )
        .await?;
        relay(plain, upstream, ctx, swap).await
      }
      (None, true) => {
        let plain = within(budget, self.connect_server(scope, upstream_name, upstream)).await?;
        relay(Prefixed::new(head, stream), plain, ctx, swap).await
      }
      (Some((hello_buf, identity)), true) => {
        let guest_plain = within(
          budget,
          self.accept_guest(&identity, Prefixed::new(hello_buf, stream), scope.guest_tls),
        )
        .await?;
        let server_plain = within(budget, self.connect_server(scope, upstream_name, upstream)).await?;
        relay(guest_plain, server_plain, ctx, swap).await
      }
    }
  }
}

async fn within<T>(budget: Duration, handshake: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
  match tokio::time::timeout(budget, handshake).await {
    Ok(result) => result,
    Err(_elapsed) => Err(Error::AmqpHandshakeTimeout),
  }
}

async fn relay<G, S>(guest: G, server: S, ctx: &PairCtx<'_>, swap: bool) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let (mut downstream, mut upstream) = amqp_pair(ctx, swap)?;
  relay_guarded(guest, server, &mut downstream, &mut upstream, &[], &[]).await
}

pub(crate) fn amqp_pair(ctx: &PairCtx<'_>, swap: bool) -> Result<(Amqp, Amqp), Error> {
  Ok((
    Amqp::new(ctx.grants, ctx.host, ctx.port, Direction::Downstream, swap)?,
    Amqp::new(ctx.grants, ctx.host, ctx.port, Direction::Upstream, false)?,
  ))
}
