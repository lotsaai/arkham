use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::{GuestTlsMode, RootCert, SmtpScope};

use super::super::PairCtx;
use super::super::{ServeStream, Settled, TlsCache, TlsHalves, Transport, matched_host, open_flagged};
use crate::Error;

/// SMTP transport. Each connection string states its own leg.
#[derive(Debug, Clone)]
pub(crate) struct SmtpTransport {
  tls: TlsCache,
}

impl SmtpTransport {
  /// Share the proxy TLS cache.
  pub(crate) fn new(tls: TlsCache) -> Self {
    Self { tls }
  }
}

impl TlsHalves for SmtpTransport {
  type Scope = SmtpScope;

  fn tls(&self) -> &TlsCache {
    &self.tls
  }

  fn tls_label(&self) -> &'static str {
    "smtp"
  }

  fn root_cert<'a>(&self, scope: &'a SmtpScope) -> Option<&'a RootCert> {
    scope.root_cert.as_ref()
  }

  fn client_paths<'a>(&self, scope: &'a SmtpScope) -> Option<(&'a Path, &'a Path)> {
    Some((scope.client_cert.as_deref()?, scope.client_key.as_deref()?))
  }

  fn guest_tls(&self, scope: &SmtpScope) -> GuestTlsMode {
    scope.guest_tls
  }

  fn upstream_host<'a>(&self, scope: &'a SmtpScope) -> &'a str {
    scope.upstream.host.as_str()
  }
}

impl Transport for SmtpTransport {
  type Scope = SmtpScope;

  /// The `smtp://` / `smtps://` arm. Implicit TLS settles here and relays.
  /// `STARTTLS` upgrades in the cleartext opening, then both sockets relay.
  async fn serve<G>(&self, ServeStream { guest, params, scope }: ServeStream<'_, G, SmtpScope>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let budget = Duration::from_secs(params.snapshot.proxy.handshake_timeout_secs);
    let Some(mut opened) = open_flagged(guest, &params, scope).await? else {
      return Ok(());
    };
    let server_name = opened.server_name.take();
    let ctx = PairCtx::new(&params, matched_host(server_name.as_deref(), scope.downstream.host.as_str()));
    let settled = self.settle(scope, opened, Some(budget)).await?;
    let (guest_leg, server_leg) = match settled {
      Settled::Clear { guest, server } => (super::session::plain_guest(guest), super::session::plain_server(server)),
      Settled::GuestTls { guest, server } => (super::session::tls_guest(guest), super::session::plain_server(server)),
      Settled::ServerTls { guest, server } => (super::session::plain_guest(guest), super::session::tls_server(server)),
      Settled::Both { guest, server } => (super::session::tls_guest(guest), super::session::tls_server(server)),
    };
    super::session::run(super::session::Dialogue {
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
