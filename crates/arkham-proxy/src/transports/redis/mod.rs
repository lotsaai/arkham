//! Redis vertical: serve arm and the RESP framing machine.

pub(crate) mod machine;

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::RedisScope;

use super::PairCtx;
use super::{ServeStream, Transport};
use crate::Error;
use crate::connection::{Prefixed, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::relay::relay_guarded;
use crate::transports::engine::{Direction, Redis};
use crate::transports::tls::{Pending, UpstreamTls, Verify, settle};

/// Redis transport. Each connection string states its own leg, and the
/// upstream `rediss` leg verifies the chain and the host name.
#[derive(Debug, Default)]
pub(crate) struct RedisTransport;

impl Transport for RedisTransport {
  type Scope = RedisScope;

  /// The `redis://` / `rediss://` arm. Both legs settle through the shared
  /// TLS helper, then the wire machine works on plaintext.
  async fn serve<G>(&self, ServeStream { mut guest, params, scope }: ServeStream<'_, G, RedisScope>) -> Result<(), Error>
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
      // SNI — Bun's Redis client sends none — would otherwise close here.
      // The scope was already chosen by port, and its downstream host is the
      // name that client checks the leaf against.
      let authority = host.or(Some(scope.downstream.host.as_str()));
      let Some((hello_buf, identity, sni_name)) = guest_tls_opening(&mut guest, initial, budget, authority, &state.mint).await? else {
        return Ok(());
      };
      server_name = Some(sni_name);
      guest_tls = Some((hello_buf, identity));
    }

    // The real string states the far end: the dial follows its host and
    // port, not the destination the guest aimed at.
    let upstream = dial_marked(&scope.upstream.host, scope.upstream.port, state.fwmark).await?;
    // Transparent capture knows the destination address, not the name in
    // the connection string. The scope was already chosen by port; keying
    // the swap on that address would miss the grant and forward the fake
    // password unchanged.
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
    let legs = &state.legs;
    let guest_pending = match guest_tls {
      Some((hello_buf, identity)) => {
        let mode = scope.guest_tls;
        Pending::Tls(async move { legs.accept_guest(&identity, Prefixed::new(hello_buf, guest), mode, None).await })
      }
      None => Pending::Plain(Prefixed::new(guest_head, guest)),
    };
    let server_name = scope.upstream.host.as_str();
    let root = scope.root_cert.as_ref();
    let client_cert = scope.client_cert.as_deref();
    let client_key = scope.client_key.as_deref();
    let upstream_pending = if scope.is_upstream_tls {
      Pending::Tls(async move {
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
    } else {
      Pending::Plain(upstream)
    };
    let (guest_leg, upstream_leg) = settle(guest_pending, upstream_pending, budget).await?;
    relay(guest_leg, upstream_leg, &ctx).await
  }
}

/// Pump one settled pair: both legs are plaintext by the time this runs,
/// whichever transports carried them there.
async fn relay<G, S>(guest: G, server: S, ctx: &PairCtx<'_>) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let (mut downstream_machine, mut upstream_machine) = redis_pair(ctx);
  relay_guarded(guest, server, &mut downstream_machine, &mut upstream_machine, &[], &[]).await
}

/// Both directions for a redis scope: AUTH and HELLO reframe downstream,
/// redaction upstream, over whichever transports carried them there.
pub(crate) fn redis_pair(ctx: &PairCtx<'_>) -> (Redis, Redis) {
  (
    Redis::new(ctx.grants, ctx.host, ctx.port, Direction::Downstream),
    Redis::new(ctx.grants, ctx.host, ctx.port, Direction::Upstream),
  )
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use arkham_config::config::ProxyCfg;
  use arkham_config::grants::{Credential, Grant, RedisScope, ResolvedConfig};
  use arkham_pki::ca::{CertAuthority, install_crypto_provider};
  use secrecy::SecretString;
  use tokio::net::TcpListener;

  use super::RedisTransport;
  use crate::ProxyState;
  use crate::identity::CandidateParams;
  use crate::transports::{ServeStream, Transport as _};

  const FAKE: &str = "arkham_fake_redis_pass"; // betterleaks:allow
  const VALUE: &str = "arkham_real_redis_pass_01"; // betterleaks:allow

  #[tokio::test]
  async fn cleartext_redis_dials_when_the_guest_starts_with_a_tls_record() {
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let spy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = spy.local_addr().unwrap().port();
    let scope = RedisScope::from_strings(
      &format!("redis://app:{FAKE}@localhost:{port}/0"),
      &format!("redis://app:{VALUE}@localhost:{port}/0"),
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
        grants: vec![Grant::Redis {
          credential: Credential {
            label: "r".into(),
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
    let transport = RedisTransport;
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
      "cleartext redis dials when the first guest byte is a TLS record"
    );
  }
}
