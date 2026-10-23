//! SMTP vertical: the cleartext opening, then the shared relay.
//!
//! `smtp://` is cleartext until `STARTTLS`. The opening reads the greeting
//! and the upgrade, then both sockets go to `relay_guarded`. `smtps://` is
//! TLS from the first byte and relays immediately. AUTH swaps on either leg.
//! An upstream TLS leg verifies the chain and the host name.

mod machine;
mod session;

#[cfg(test)]
pub(crate) use machine::{MAX_COMMAND, Smtp};
#[cfg(test)]
pub(crate) use session::{GuestLeg, acceptance_reply, plain_guest};

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::SmtpScope;

use super::{ServeStream, Transport};
use crate::Error;
use crate::connection::{Prefixed, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::transports::tls::{UpstreamTls, Verify, finish};

/// SMTP transport. Each connection string states its own leg.
#[derive(Debug, Default)]
pub(crate) struct SmtpTransport;

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
    // in the connection string, and keying on it would miss the grant.
    let matched_name = server_name
      .as_deref()
      .filter(|name| scope.downstream.host.eq_ignore_ascii_case(name));
    let host_key = matched_name.unwrap_or(scope.downstream.host.as_str());
    let legs = &state.legs;
    let guest_leg = match guest_tls {
      Some((hello_buf, identity)) => {
        let mode = scope.guest_tls;
        let tls = finish(budget, legs.accept_guest(&identity, Prefixed::new(hello_buf, guest), mode, None)).await?;
        session::tls_guest(tls)
      }
      None => session::plain_guest(Prefixed::new(guest_head, guest)),
    };
    let server_leg = if scope.is_upstream_tls {
      let server_name = scope.upstream.host.as_str();
      let root = scope.root_cert.as_ref();
      let client_cert = scope.client_cert.as_deref();
      let client_key = scope.client_key.as_deref();
      let tls = finish(budget, async move {
        legs
          .connect_upstream(
            &UpstreamTls {
              server_name,
              root,
              verify: Verify::Full,
              client_cert,
              client_key,
              alpn: None,
            },
            upstream,
          )
          .await
      })
      .await?;
      session::tls_server(tls)
    } else {
      session::plain_server(upstream)
    };
    session::run(session::Dialogue {
      legs,
      scope,
      guest: guest_leg,
      server: server_leg,
      grants: &snapshot.grants,
      host: host_key,
      port,
      budget,
    })
    .await
  }
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use arkham_config::config::ProxyCfg;
  use arkham_config::grants::{Credential, Grant, ResolvedConfig, SmtpScope};
  use arkham_pki::ca::{CertAuthority, install_crypto_provider};
  use secrecy::SecretString;
  use tokio::net::TcpListener;

  use super::SmtpTransport;
  use crate::ProxyState;
  use crate::identity::CandidateParams;
  use crate::transports::{ServeStream, Transport as _};

  const FAKE: &str = "arkham_fake_smtp_pass"; // betterleaks:allow
  const VALUE: &str = "arkham_real_smtp_pass_01"; // betterleaks:allow

  #[tokio::test]
  async fn cleartext_smtp_dials_when_the_guest_starts_with_a_tls_record() {
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let spy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = spy.local_addr().unwrap().port();
    let scope = SmtpScope::from_strings(
      &format!("smtp://agent:{FAKE}@localhost:{port}"),
      &format!("smtp://agent:{VALUE}@localhost:{port}"),
    )
    .unwrap();
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
        grants: vec![Grant::Smtp {
          credential: Credential {
            label: "s".into(),
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
    let initial = [0x16u8, 0x03, 0x01];
    let transport = SmtpTransport;
    let accept = spy.accept();
    tokio::pin!(accept);
    let serve = transport.serve(ServeStream {
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
    });
    tokio::pin!(serve);
    let dialed = tokio::time::timeout(Duration::from_secs(2), async {
      tokio::select! {
        biased;
        accepted = &mut accept => accepted.is_ok(),
        result = &mut serve => {
          let _ = result;
          false
        }
      }
    })
    .await;
    assert!(
      matches!(dialed, Ok(true)),
      "cleartext smtp dials when the first guest byte is a TLS record"
    );
  }
}
