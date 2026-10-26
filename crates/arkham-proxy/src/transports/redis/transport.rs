use std::path::Path;

use tokio::io::{AsyncRead, AsyncWrite};

use arkham_config::grants::{GuestTlsMode, RedisScope, RootCert};

use super::super::PairCtx;
use super::super::{ServeStream, TlsCache, TlsHalves, Transport, matched_host, open_flagged};
use crate::Error;
use crate::relay::relay_guarded;
use crate::transports::engine::{Direction, Redis};

/// Redis transport: each connection string states its own leg, and the
/// upstream `rediss` leg verifies the chain and the host name — the https
/// precedent, not libpq's.
#[derive(Debug, Clone)]
pub(crate) struct RedisTransport {
  tls: TlsCache,
}

impl RedisTransport {
  /// Share the proxy TLS cache.
  pub(crate) fn new(tls: TlsCache) -> Self {
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

  fn guest_tls(&self, scope: &RedisScope) -> GuestTlsMode {
    scope.guest_tls
  }

  fn upstream_host<'a>(&self, scope: &'a RedisScope) -> &'a str {
    scope.upstream.host.as_str()
  }
}

impl Transport for RedisTransport {
  type Scope = RedisScope;

  /// The `redis://` / `rediss://` arm. Each connection string states its
  /// own leg's transport, so both legs are settled here and the wire
  /// machine then works on plaintext whichever way either arrived.
  async fn serve<G>(&self, ServeStream { guest, params, scope }: ServeStream<'_, G, RedisScope>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    // The real string states the far end: the dial follows its host and port.
    let Some(mut opened) = open_flagged(guest, &params, scope).await? else {
      return Ok(());
    };
    let server_name = opened.server_name.take();
    let ctx = PairCtx::new(&params, matched_host(server_name.as_deref(), scope.downstream.host.as_str()));
    let settled = self.settle(scope, opened, None).await?;
    super::super::relay_settled!(settled, relay, &ctx)
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

  use super::super::super::TlsCache;
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
    let transport = RedisTransport::new(TlsCache::new(&ca).unwrap());
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
