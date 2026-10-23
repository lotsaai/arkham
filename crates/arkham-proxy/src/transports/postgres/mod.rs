//! Postgres vertical: serve arm and the pgwire framing machine.

mod auth;
pub(crate) mod machine;

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::{PostgresScope, SslMode, SslNegotiation};

use super::PairCtx;
use super::{ServeStream, Transport};
use crate::Error;
use crate::connection::{Prefixed, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::relay::relay_guarded;
use crate::transports::engine::{Direction, GuestOpening, Postgres, read_guest_opening, request_upstream_tls};
use crate::transports::tls::{Leg, UpstreamTls, Verify, finish};

/// ALPN identifier for direct Postgres TLS.
const POSTGRESQL_ALPN: &[u8] = b"postgresql";

/// Postgres transport. Guest leaves and upstream handshakes go through the
/// shared TLS helper. `sslmode` still decides whether this arm asks the
/// server for TLS.
#[derive(Debug, Default)]
pub(crate) struct PostgresTransport;

impl Transport for PostgresTransport {
  type Scope = PostgresScope;

  /// The `postgres://` arm. The entry states the far side's transport and
  /// the guest states its own, so both legs settle here and the wire
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
    let legs = &state.legs;
    let guest_leg = match guest_tls {
      Some((hello_buf, identity)) => {
        let mode = scope.guest_tls;
        Leg::Tls(
          finish(
            budget,
            legs.accept_guest(&identity, Prefixed::new(hello_buf, guest), mode, Some(POSTGRESQL_ALPN)),
          )
          .await?,
        )
      }
      None => Leg::Plain(Prefixed::new(guest_head, guest)),
    };
    let server_name = scope.upstream.host.as_str();
    let root = scope.root_cert.as_ref();
    let verify = Verify::Libpq {
      name: scope.ssl == SslMode::VerifyFull,
    };
    let client_cert = scope.client_cert.as_deref();
    let client_key = scope.client_key.as_deref();
    let alpn = (scope.negotiation == SslNegotiation::Direct).then_some(POSTGRESQL_ALPN);
    let upstream_leg = if accepted {
      Leg::Tls(
        finish(
          budget,
          legs.connect_upstream(
            &UpstreamTls {
              server_name,
              root,
              verify,
              client_cert,
              client_key,
              alpn,
            },
            upstream,
          ),
        )
        .await?,
      )
    } else {
      Leg::Plain(upstream)
    };
    relay(guest_leg, upstream_leg, &ctx, scope, budget).await
  }
}

/// Pump one settled pair: both legs are plaintext by the time this runs,
/// whichever transports carried them there.
async fn relay<G, S>(mut guest: G, mut server: S, ctx: &PairCtx<'_>, scope: &PostgresScope, budget: Duration) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let (mut downstream_machine, mut upstream_machine) = postgres_pair(ctx);
  let auth::Prelude::Relay(tail) = auth::settle(&mut guest, &mut server, &mut downstream_machine, scope, budget).await? else {
    return Ok(());
  };
  relay_guarded(guest, server, &mut downstream_machine, &mut upstream_machine, &[], &tail).await
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

  async fn drive_opening(initial: Vec<u8>, close: OpeningClose) {
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
    let transport = PostgresTransport;
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
    match close {
      OpeningClose::Plaintext => {
        assert!(sent > 0, "cleartext guest bytes reach the upstream");
        let _ = result;
      }
      OpeningClose::Quiet => {
        assert_eq!(sent, 0, "a broken tls opening sends nothing upstream");
        result.expect("sslrequest then non-tls bytes closes before the dial");
      }
    }
  }

  enum OpeningClose {
    Plaintext,
    Quiet,
  }

  #[tokio::test]
  async fn postgres_mtls_plaintext_guest_reaches_upstream() {
    drive_opening(startup(), OpeningClose::Plaintext).await;
  }

  #[tokio::test]
  async fn postgres_mtls_gssenc_then_startup_reaches_upstream() {
    let mut opening = wire(&pgwire::messages::startup::GssEncRequest::new());
    opening.extend(startup());
    drive_opening(opening, OpeningClose::Plaintext).await;
  }

  #[tokio::test]
  async fn postgres_mtls_cancel_request_reaches_upstream() {
    let cancel = pgwire::messages::cancel::CancelRequest::new(7, pgwire::messages::startup::SecretKey::I32(11));
    drive_opening(wire(&cancel), OpeningClose::Plaintext).await;
  }

  #[tokio::test]
  async fn postgres_mtls_sslrequest_then_plaintext_sends_nothing_upstream() {
    let mut opening = wire(&pgwire::messages::startup::SslRequest::new());
    opening.extend(startup());
    drive_opening(opening, OpeningClose::Quiet).await;
  }
}
