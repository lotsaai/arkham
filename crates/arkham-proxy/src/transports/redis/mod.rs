//! Redis vertical: transport halves, serve arm, and the RESP framing
//! machine — everything redis owns.

pub(crate) mod machine;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::{RedisScope, RootCert};

use super::PairCtx;
use super::{ServeStream, TlsCache, TlsHalves, Transport};
use crate::Error;
use crate::connection::{Prefixed, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::relay::relay_guarded;
use crate::transports::engine::{Direction, Redis};

/// Redis transport: each connection string states its own leg, and the
/// upstream `rediss` leg verifies the chain and the host name — the https
/// precedent, not libpq's.
#[derive(Debug)]
pub(crate) struct RedisTransport {
  tls: Arc<TlsCache>,
}

impl RedisTransport {
  /// Share the proxy TLS cache.
  pub(crate) fn new(tls: Arc<TlsCache>) -> Self {
    Self { tls }
  }
}

impl TlsHalves for RedisTransport {
  type Scope = RedisScope;

  fn tls(&self) -> &TlsCache {
    &self.tls
  }

  fn tls_label(&self) -> &'static str {
    "redis"
  }

  fn root_cert<'a>(&self, scope: &'a RedisScope) -> Option<&'a RootCert> {
    scope.root_cert.as_ref()
  }

  fn client_paths<'a>(&self, scope: &'a RedisScope) -> Option<(&'a Path, &'a Path)> {
    Some((scope.client_cert.as_deref()?, scope.client_key.as_deref()?))
  }
}

impl Transport for RedisTransport {
  type Scope = RedisScope;

  /// The `redis://` / `rediss://` arm. Each connection string states its
  /// own leg's transport, so both legs are settled here and the wire
  /// machine then works on plaintext whichever way either arrived.
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
    let upstream_name = scope.upstream.host.as_str();
    let redis = &state.redis;
    match (guest_tls, scope.is_upstream_tls) {
      (None, false) => relay(Prefixed::new(guest_head, guest), upstream, &ctx).await,
      (Some((hello_buf, identity)), false) => {
        let plain = redis
          .accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls)
          .await?;
        relay(plain, upstream, &ctx).await
      }
      (None, true) => {
        let plain = redis.connect_server(scope, upstream_name, upstream).await?;
        relay(Prefixed::new(guest_head, guest), plain, &ctx).await
      }
      (Some((hello_buf, identity)), true) => {
        let guest_plain = redis
          .accept_guest(&identity, Prefixed::new(hello_buf, guest), scope.guest_tls)
          .await?;
        let server_plain = redis.connect_server(scope, upstream_name, upstream).await?;
        relay(guest_plain, server_plain, &ctx).await
      }
    }
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
  use std::sync::Arc;
  use std::sync::atomic::{AtomicBool, Ordering};
  use std::time::Duration;

  use arkham_config::config::ProxyCfg;
  use arkham_config::grants::{Credential, Grant, RedisScope, ResolvedConfig};
  use arkham_pki::ca::{CertAuthority, install_crypto_provider};
  use secrecy::SecretString;
  use tokio::net::TcpListener;

  use super::super::TlsCache;
  use super::RedisTransport;
  use crate::ProxyState;
  use crate::identity::CandidateParams;
  use crate::transports::{ServeStream, Transport as _};

  const FAKE: &str = "arkham_fake_redis_pass"; // betterleaks:allow
  const VALUE: &str = "arkham_real_redis_pass_01"; // betterleaks:allow

  #[tokio::test]
  async fn cleartext_redis_tls_record_still_dials() {
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let spy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = spy.local_addr().unwrap().port();
    let dialed = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&dialed);
    let spy_task = tokio::spawn(async move {
      if tokio::time::timeout(Duration::from_secs(2), spy.accept()).await.is_ok() {
        seen.store(true, Ordering::Relaxed);
      }
    });
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
            label: "redis".into(),
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
    let transport = RedisTransport::new(Arc::new(TlsCache::new(&ca).unwrap()));
    transport
      .serve(ServeStream {
        guest,
        params: CandidateParams {
          state: &state,
          snapshot: snapshot.as_ref(),
          dial_host: "127.0.0.1",
          port,
          host: Some("localhost"),
          raw_host: "localhost",
          initial: &[0x16, 0x03, 0x01],
        },
        scope: &scope,
      })
      .await
      .expect("cleartext redis with a tls record still serves");
    let _ = tokio::time::timeout(Duration::from_secs(2), spy_task).await;
    assert!(dialed.load(Ordering::Relaxed), "cleartext redis tls record did not dial");
  }
}
