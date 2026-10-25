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

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::{RootCert, SmtpScope};

use super::{ServeStream, Settled, TlsCache, TlsHalves, Transport, matched_host, open_flagged, pair_ctx, settle_legs};
use crate::Error;
use crate::identity::CandidateParams;

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
}

impl Transport for SmtpTransport {
  type Scope = SmtpScope;

  /// The `smtp://` / `smtps://` arm. Implicit TLS settles here and relays.
  /// `STARTTLS` upgrades in the cleartext opening, then both sockets relay.
  async fn serve<G>(&self, ServeStream { guest, params, scope }: ServeStream<'_, G, SmtpScope>) -> Result<(), Error>
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
    let Some(opened) = open_flagged(
      guest,
      initial,
      budget,
      host,
      (scope.downstream.host.as_str(), scope.is_downstream_tls),
      (scope.upstream.host.as_str(), scope.upstream.port, state.fwmark),
      &state.mint,
    )
    .await?
    else {
      return Ok(());
    };
    let ctx = pair_ctx(
      &snapshot.grants,
      matched_host(opened.server_name.as_deref(), scope.downstream.host.as_str()),
      port,
      &state.plugins,
      state.mint_store(),
    );
    let settled = settle_legs(
      self,
      opened.guest_tls,
      scope.is_upstream_tls,
      (opened.guest, opened.guest_head),
      opened.upstream,
      scope,
      (scope.guest_tls, scope.upstream.host.as_str(), Some(("smtp", budget))),
    )
    .await?;
    let (guest_leg, server_leg) = match settled {
      Settled::Clear { guest, server } => (session::plain_guest(guest), session::plain_server(server)),
      Settled::GuestTls { guest, server } => (session::tls_guest(guest), session::plain_server(server)),
      Settled::ServerTls { guest, server } => (session::plain_guest(guest), session::tls_server(server)),
      Settled::Both { guest, server } => (session::tls_guest(guest), session::tls_server(server)),
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
