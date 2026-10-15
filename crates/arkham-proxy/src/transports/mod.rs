//! Protocol transports. This root is protocol-blind: it holds the traits —
//! one per responsibility — the stream a transport is handed, and the
//! shared substitution engine. Each protocol vertical implements the
//! responsibilities it owns; the composition root (lib.rs) retains the
//! strategies, and the picker (identity.rs) routes one stream to one
//! strategy in one place.

pub(crate) mod amqp;
pub(crate) mod engine;
pub(crate) mod http;
pub(crate) mod ldap;
pub(crate) mod postgres;
pub(crate) mod redis;
pub(crate) mod smtp;
pub(crate) mod ssh;
pub(crate) mod tcp;
pub(crate) mod tls;

use arkham_config::grants::{Grant, GuestTlsMode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;

use crate::Error;
use crate::identity::CandidateParams;
use crate::mint::MintHandle;
/// One candidate stream handed to a transport: the guest stream, the
/// dispatch params, and the scope the grants stated for it.
pub(crate) struct ServeStream<'a, G, S> {
  /// The guest's stream, plus any bytes the ingress already read.
  pub(crate) guest: G,
  /// Targets, identity material, and the shared state.
  pub(crate) params: CandidateParams<'a>,
  /// The typed scope this protocol's grants carry.
  pub(crate) scope: &'a S,
}

/// Serving one stream for one protocol: the dispatchable strategy.
pub(crate) trait Transport: Send + Sync {
  /// The typed scope this protocol's grants carry.
  type Scope: Sync;

  /// Settle both legs of one candidate stream and pump it.
  ///
  /// # Errors
  ///
  /// Returns an error when a leg cannot be settled; malformed guest
  /// traffic closes quietly instead.
  fn serve<G>(&self, stream: ServeStream<'_, G, Self::Scope>) -> impl Future<Output = Result<(), Error>>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static;
}

/// Terminating the guest's TLS and handshaking the real server: the two
/// TLS halves a protocol with its own TLS law owns.
pub(crate) trait TlsHalves: Send + Sync {
  /// The typed scope this protocol's grants carry.
  type Scope: Sync;

  /// Terminate the guest's TLS with a leaf minted for `name` under this
  /// protocol's own ALPN law.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted or the handshake fails.
  fn accept_guest<G>(&self, name: &str, guest: G, guest_tls: GuestTlsMode) -> impl Future<Output = Result<ServerTlsStream<G>, Error>>
  where
    G: AsyncRead + AsyncWrite + Unpin;

  /// Handshake the real server under this protocol's own verification law.
  ///
  /// # Errors
  ///
  /// Returns an error when the named trust anchor cannot be read, when the
  /// server name is unusable, or when the handshake fails.
  fn connect_server<S>(&self, scope: &Self::Scope, server_name: &str, server: S) -> impl Future<Output = Result<ClientTlsStream<S>, Error>>
  where
    S: AsyncRead + AsyncWrite + Unpin;
}

/// Borrowed construction context for a framing pair: grants authorize,
/// plugins hook, and the connection identity scopes both.
pub(crate) struct PairCtx<'a> {
  /// Grant source for eligible pairs.
  pub(crate) grants: &'a [Grant],
  /// Connection endpoint host.
  pub(crate) host: &'a str,
  /// Connection endpoint port.
  pub(crate) port: u16,
  /// Per-connection plugin registry.
  pub(crate) plugins: &'a arkham_plugin::Registry,
  /// Runtime token-mint handle; `None` keeps value-swap-only behavior.
  pub(crate) mint: Option<MintHandle>,
}
