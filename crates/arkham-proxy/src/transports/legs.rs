use std::time::Duration;

use arkham_config::grants::Grant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::Error;
use crate::connection::{dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::mint::MintStore;

/// First byte of a TLS record carrying a handshake.
pub(crate) const TLS_RECORD_HANDSHAKE: u8 = 0x16;

/// Downstream opening when the scope says whether the guest leg is TLS.
pub(crate) struct FlaggedOpen<G> {
  /// Guest stream, after any hello bytes were read off it.
  pub(crate) guest: G,
  /// Cleartext bytes already read, replayed when the guest leg stays clear.
  pub(crate) guest_head: Vec<u8>,
  /// Guest TLS hello and the name the leaf was minted for.
  pub(crate) guest_tls: Option<(Vec<u8>, String)>,
  /// SNI or authority captured for the swap key.
  pub(crate) server_name: Option<String>,
  /// Dialed upstream.
  pub(crate) upstream: TcpStream,
}

/// Open the downstream leg and dial upstream. `Ok(None)` closes quietly.
///
/// # Errors
///
/// Returns an error when the hello cannot be read or the upstream dial fails.
pub(crate) async fn open_flagged<G>(
  mut guest: G,
  params: &CandidateParams<'_>,
  downstream: (&str, bool),
  upstream: (&str, u16),
) -> Result<Option<FlaggedOpen<G>>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let (downstream_host, downstream_tls) = downstream;
  let (upstream_host, upstream_port) = upstream;
  let budget = Duration::from_secs(params.snapshot.proxy.handshake_timeout_secs);
  let mut server_name = params.host.map(ToString::to_string);
  let guest_head = params.initial.to_vec();
  let mut guest_tls = None;
  if downstream_tls {
    let authority = params.host.or(Some(downstream_host));
    let Some((hello_buf, identity, sni_name)) =
      guest_tls_opening(&mut guest, params.initial, budget, authority, &params.state.mint).await?
    else {
      return Ok(None);
    };
    server_name = Some(sni_name);
    guest_tls = Some((hello_buf, identity));
  }
  let dialed = dial_marked(upstream_host, upstream_port, params.state.fwmark).await?;
  Ok(Some(FlaggedOpen {
    guest,
    guest_head,
    guest_tls,
    server_name,
    upstream: dialed,
  }))
}

/// Captured name when it matches the downstream host, otherwise that host.
#[must_use]
pub(crate) fn matched_host<'a>(server_name: Option<&'a str>, downstream_host: &'a str) -> &'a str {
  server_name
    .filter(|name| downstream_host.eq_ignore_ascii_case(name))
    .unwrap_or(downstream_host)
}

/// The four ways a guest leg and an upstream leg can settle.
pub(crate) enum Settled<ClearGuest, TlsGuest, ClearServer, TlsServer> {
  /// Both legs stay cleartext.
  Clear { guest: ClearGuest, server: ClearServer },
  /// Guest TLS, cleartext upstream.
  GuestTls { guest: TlsGuest, server: ClearServer },
  /// Cleartext guest, TLS upstream.
  ServerTls { guest: ClearGuest, server: TlsServer },
  /// TLS on both legs.
  Both { guest: TlsGuest, server: TlsServer },
}

/// Relay every settled leg pair through one function.
macro_rules! relay_settled {
  ($settled:expr, $relay:path, $($arg:expr),+ $(,)?) => {
    match $settled {
      $crate::transports::Settled::Clear { guest, server } => $relay(guest, server, $($arg),+).await,
      $crate::transports::Settled::GuestTls { guest, server } => $relay(guest, server, $($arg),+).await,
      $crate::transports::Settled::ServerTls { guest, server } => $relay(guest, server, $($arg),+).await,
      $crate::transports::Settled::Both { guest, server } => $relay(guest, server, $($arg),+).await,
    }
  };
}
pub(crate) use relay_settled;

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
  /// Runtime token-mint store; `None` keeps value-swap-only behavior.
  pub(crate) mint: Option<MintStore>,
}

impl<'a> PairCtx<'a> {
  /// Grants, plugins, port, and the mint store from `params`, keyed by `host`.
  #[must_use]
  pub(crate) fn new(params: &CandidateParams<'a>, host: &'a str) -> Self {
    Self {
      grants: &params.snapshot.grants,
      host,
      port: params.port,
      plugins: &params.state.plugins,
      mint: Some(params.state.mint_store()),
    }
  }
}
