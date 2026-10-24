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
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::{RootCert, SmtpScope};

use super::{PairCtx, ServeStream, TlsCache, TlsHalves, Transport, within};
use crate::Error;
use crate::connection::{Prefixed, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;

/// SMTP transport. Each connection string states its own leg.
#[derive(Debug)]
pub(crate) struct SmtpTransport {
  tls: Arc<TlsCache>,
}

impl SmtpTransport {
  /// Share the proxy TLS cache.
  pub(crate) fn new(tls: Arc<TlsCache>) -> Self {
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
    }

    let upstream = dial_marked(&scope.upstream.host, scope.upstream.port, state.fwmark).await?;
    // Key the swap on the scope host. The captured address is not the name
    // in the connection string, and keying on it would forward the decoy.
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
    let upstream_name = scope.upstream.host.as_str();
    let guest_leg = match guest_tls {
      Some((hello_buf, identity)) => {
        let tls = within(
          "smtp",
          budget,
          self.accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls),
        )
        .await?;
        session::tls_guest(tls)
      }
      None => session::plain_guest(Prefixed::new(guest_head, guest)),
    };
    let server_leg = if scope.is_upstream_tls {
      let tls = within("smtp", budget, self.connect_server(scope, upstream_name, upstream)).await?;
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
