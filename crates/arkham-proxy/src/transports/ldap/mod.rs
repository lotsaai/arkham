//! LDAP transport. The BER machine lives in `arkham-ldap`.
//! This module dials, settles TLS on the shared legs, and runs the `StartTLS` opening.

use std::io::{Error as IoError, ErrorKind};
use std::time::Duration;

use secrecy::ExposeSecret as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio_rustls::client::TlsStream as ClientTlsStream;

use arkham_config::grants::{Grant, LdapScope};
use arkham_ldap::{BindSwap, Ldap, starttls_success};
use arkham_wire::engine::{Direction, Rewritten, Wire};
use arkham_wire::tls::TlsLegs;

use super::PairCtx;
use super::{ServeStream, Transport};
use crate::Error;
use crate::connection::{Prefixed, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::mint::MintBucket;
use crate::relay::{RelayEnd, log_hits, relay_guarded, relay_stop};
use crate::transports::tls::{UpstreamTls, Verify, finish};

/// LDAP transport. `ldaps://` settles TLS before the machine runs.
/// `ldap://` stays cleartext until `StartTLS`.
#[derive(Debug, Default)]
pub(crate) struct LdapTransport;

impl Transport for LdapTransport {
  type Scope = LdapScope;

  /// `ldap://` and `ldaps://`. LDAPS settles both legs, then relays.
  /// Cleartext classifies the first message. `StartTLS` is lockstep.
  /// Anything else is [`relay_guarded`] from the bytes already read.
  async fn serve<G>(&self, ServeStream { mut guest, params, scope }: ServeStream<'_, G, LdapScope>) -> Result<(), Error>
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
      let authority = host.or(Some(scope.downstream.host.as_str()));
      let Some((hello_buf, identity, sni_name)) = guest_tls_opening(&mut guest, initial, budget, authority, &state.mint).await? else {
        return Ok(());
      };
      server_name = Some(sni_name);
      guest_tls = Some((hello_buf, identity));
    }

    let upstream = dial_marked(&scope.upstream.host, scope.upstream.port, state.fwmark).await?;
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
    let legs = &state.legs;
    let pump = Pump {
      scope,
      ctx: &ctx,
      budget,
      mint: &state.mint,
      legs,
      upgrade_upstream: !scope.is_upstream_tls,
    };
    if scope.is_downstream_tls {
      return self
        .relay_settled(
          OpenGuest {
            stream: guest,
            head: guest_head,
            tls: guest_tls,
          },
          upstream,
          &pump,
          upstream_name,
        )
        .await;
    }
    if scope.is_upstream_tls {
      let plain = connect_server(legs, scope, upstream_name, upstream, budget).await?;
      self.opening(Prefixed::new(guest_head, guest), plain, &pump).await
    } else {
      self.opening(Prefixed::new(guest_head, guest), upstream, &pump).await
    }
  }
}

async fn connect_server<S>(
  legs: &TlsLegs,
  scope: &LdapScope,
  server_name: &str,
  server: S,
  budget: Duration,
) -> Result<ClientTlsStream<S>, Error>
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  finish(
    budget,
    legs.connect_upstream(
      &UpstreamTls {
        server_name,
        root: scope.root_cert.as_ref(),
        verify: Verify::Full,
        client_cert: scope.client_cert.as_deref(),
        client_key: scope.client_key.as_deref(),
        alpn: None,
      },
      server,
    ),
  )
  .await
  .map_err(Error::from)
}

/// Guest bytes already read, plus whether that leg opened with TLS.
struct OpenGuest<G> {
  stream: G,
  head: Vec<u8>,
  tls: Option<(Vec<u8>, String)>,
}

/// Facts the cleartext opening and the `StartTLS` upgrade share.
struct Pump<'a> {
  scope: &'a LdapScope,
  ctx: &'a PairCtx<'a>,
  budget: Duration,
  mint: &'a MintBucket,
  legs: &'a TlsLegs,
  /// `false` when the upstream leg is already TLS, so `StartTLS` is answered here.
  upgrade_upstream: bool,
}

impl LdapTransport {
  /// Both legs already know their transport. Cleartext and TLS both swap.
  async fn relay_settled<G, S>(&self, guest: OpenGuest<G>, upstream: S, pump: &Pump<'_>, upstream_name: &str) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let OpenGuest { stream, head, tls } = guest;
    let scope = pump.scope;
    match (tls, scope.is_upstream_tls) {
      (None, false) => relay(Prefixed::new(head, stream), upstream, pump.ctx).await,
      (Some((hello_buf, identity)), false) => {
        let plain = finish(
          pump.budget,
          pump
            .legs
            .accept_guest(&identity, Prefixed::new(hello_buf, stream), scope.guest_tls, None),
        )
        .await?;
        relay(plain, upstream, pump.ctx).await
      }
      (None, true) => {
        let plain = connect_server(pump.legs, scope, upstream_name, upstream, pump.budget).await?;
        relay(Prefixed::new(head, stream), plain, pump.ctx).await
      }
      (Some((hello_buf, identity)), true) => {
        let guest_plain = finish(
          pump.budget,
          pump
            .legs
            .accept_guest(&identity, Prefixed::new(hello_buf, stream), scope.guest_tls, None),
        )
        .await?;
        let server_plain = connect_server(pump.legs, scope, upstream_name, upstream, pump.budget).await?;
        relay(guest_plain, server_plain, pump.ctx).await
      }
    }
  }

  /// Classify the first cleartext message. `StartTLS` stays here. Every other
  /// opening is the shared relay.
  async fn opening<G, S>(&self, mut guest: G, mut server: S, pump: &Pump<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    match read_first(
      &mut guest,
      &mut server,
      pump.upgrade_upstream,
      bind_swap(pump.ctx.grants, pump.ctx.host, pump.ctx.port),
    )
    .await?
    {
      First::Eof | First::Close => Ok(()),
      First::Relay(prefix) => {
        let (mut downstream, mut upstream) = ldap_pair(pump.ctx);
        if !pump.upgrade_upstream {
          downstream.hold_starttls();
        }
        match Box::pin(relay_stop(guest, server, &mut downstream, &mut upstream, &prefix, &[])).await? {
          RelayEnd::Done => Ok(()),
          RelayEnd::Upgrade(upgrade) => self.finish_starttls(upgrade, pump).await,
        }
      }
      First::StartTls(open) => self.starttls(&open, guest, server, pump).await,
    }
  }

  /// Forward one `StartTLS` exchange, or answer it locally when the upstream
  /// leg is already TLS, then hand both plaintext legs to [`relay`].
  async fn starttls<G, S>(&self, open: &StartTlsOpen, mut guest: G, mut server: S, pump: &Pump<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    tracing::debug!(id = open.id, prefix = open.request.len(), "ldap starttls");
    let (success, server_rest) = if pump.upgrade_upstream {
      let mut upstream = Ldap::new(bind_swap(pump.ctx.grants, pump.ctx.host, pump.ctx.port), Direction::Upstream);
      upstream.expect_starttls(open.id);
      read_starttls_result(&mut server, &mut guest, &mut upstream, pump.budget).await?
    } else {
      (true, Vec::new())
    };
    if !success {
      tracing::debug!("ldap starttls refused; closing");
      return Ok(());
    }
    Box::pin(self.protect(
      guest,
      server,
      Accept {
        guest_prefix: &open.handshake,
        server_prefix: server_rest,
        id: u64::from(open.id),
        local: !pump.upgrade_upstream,
      },
      pump,
    ))
    .await
  }

  /// The relay stopped on `StartTLS`. Finish that exchange and relay the
  /// plaintext legs. `pump.budget` bounds the `ClientHello` read.
  async fn finish_starttls<G, S>(&self, upgrade: crate::relay::RelayUpgrade<G, S>, pump: &Pump<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let crate::relay::RelayUpgrade {
      guest,
      server,
      guest_prefix,
      server_prefix,
      id,
      local,
    } = upgrade;
    Box::pin(self.protect(
      guest,
      server,
      Accept {
        guest_prefix: &guest_prefix,
        server_prefix,
        id,
        local,
      },
      pump,
    ))
    .await
  }

  /// Accept the guest TLS leg once, then relay. `local` writes the success
  /// here because the server socket is already TLS. Bytes still arriving on
  /// that socket are written to the guest until the `ClientHello` is read.
  /// `pump.budget` bounds that read.
  async fn protect<G, S>(&self, guest: G, server: S, accept: Accept<'_>, pump: &Pump<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let Accept {
      guest_prefix,
      server_prefix,
      id,
      local,
    } = accept;
    let (guest, server, opened) = if local {
      let Ok(id) = u32::try_from(id) else {
        return Ok(());
      };
      let bytes = starttls_success(id)?;
      forward_until_hello(guest, Prefixed::new(server_prefix, server), guest_prefix, pump, &bytes).await?
    } else {
      let mut guest = guest;
      let opened = guest_tls_opening(
        &mut guest,
        guest_prefix,
        pump.budget,
        Some(pump.scope.downstream.host.as_str()),
        pump.mint,
      )
      .await?;
      (guest, Prefixed::new(server_prefix, server), opened)
    };
    let Some((hello_buf, identity, _)) = opened else {
      return Ok(());
    };
    let guest_plain = finish(
      pump.budget,
      pump
        .legs
        .accept_guest(&identity, Prefixed::new(hello_buf, guest), pump.scope.guest_tls, None),
    )
    .await?;
    if local {
      relay(guest_plain, server, pump.ctx).await
    } else {
      let server_plain = connect_server(pump.legs, pump.scope, pump.scope.upstream.host.as_str(), server, pump.budget).await?;
      relay(guest_plain, server_plain, pump.ctx).await
    }
  }
}

/// Write `success`, then copy server bytes to the guest until the guest
/// presents a `ClientHello` or closes. In-flight LDAP results stay on the
/// cleartext leg.
async fn forward_until_hello<G, S>(
  guest: G,
  server: S,
  prefix: &[u8],
  pump: &Pump<'_>,
  success: &[u8],
) -> Result<(G, S, Option<(Vec<u8>, String, String)>), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let mut guest = guest;
  write_guest(&mut guest, success).await?;
  let (mut guest_read, mut guest_write) = tokio::io::split(guest);
  let (mut server_read, server_write) = tokio::io::split(server);
  let mut buf = vec![0u8; 8 * 1024];
  let opened = {
    let mut hello = Box::pin(guest_tls_opening(
      &mut guest_read,
      prefix,
      pump.budget,
      Some(pump.scope.downstream.host.as_str()),
      pump.mint,
    ));
    loop {
      tokio::select! {
        biased;
        result = &mut hello => break result?,
        result = server_read.read(&mut buf) => {
          let n = read_count(result).map_err(|source| Error::from(arkham_wire::Error::UpstreamRead { source }))?;
          if n == 0 {
            break hello.await?;
          }
          let Some(chunk) = buf.get(..n) else {
            return Err(
              arkham_wire::Error::UpstreamRead {
                source: IoError::new(ErrorKind::InvalidData, "ldap server read"),
              }
              .into(),
            );
          };
          write_guest(&mut guest_write, chunk).await?;
        }
      }
    }
  };
  Ok((guest_read.unsplit(guest_write), server_read.unsplit(server_write), opened))
}

/// Bytes already read around one `StartTLS`, plus whether this side answers it.
struct Accept<'a> {
  guest_prefix: &'a [u8],
  server_prefix: Vec<u8>,
  id: u64,
  local: bool,
}

/// What the first cleartext message was.
enum First {
  /// The guest closed before a message.
  Eof,
  /// The cursor closed on malformed BER.
  Close,
  /// Not `StartTLS`. `bytes` is the prefix already taken off the guest.
  Relay(Vec<u8>),
  /// One `StartTLS` request. `request` is only the OID prefix.
  StartTls(StartTlsOpen),
}

/// The `StartTLS` prefix. Control bytes are not kept here.
struct StartTlsOpen {
  /// LDAP message id.
  id: u32,
  /// Bytes through the `StartTLS` OID. Controls are not included.
  request: Vec<u8>,
  /// Bytes already taken that belong to the following handshake.
  handshake: Vec<u8>,
}

/// `UnexpectedEof` from rustls is a normal FIN.
fn read_count(result: Result<usize, IoError>) -> Result<usize, IoError> {
  match result {
    Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(0),
    other => other,
  }
}

/// Read the guest until the first message is `StartTLS` or the cursor emits.
/// Bytes after that stay unread. A swapping bind emits when the password is
/// decided, so the prefix can be the whole message. After a `StartTLS` OID,
/// the control tail is read in chunks of at most the unread count and is not
/// kept. `forward` writes that request upstream. Otherwise the tail is
/// discarded, which is the path when the upstream leg is already TLS.
async fn read_first<R, W>(guest: &mut R, upstream: &mut W, forward: bool, swap: Option<BindSwap>) -> Result<First, Error>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  let mut probe = Ldap::new(swap, Direction::Downstream);
  let mut got = Vec::new();
  let mut byte = [0u8; 1];
  loop {
    let n = read_count(guest.read(&mut byte).await).map_err(|source| Error::from(arkham_wire::Error::GuestRead { source }))?;
    if n == 0 {
      return Ok(if got.is_empty() { First::Eof } else { First::Relay(got) });
    }
    let Some(next) = byte.first().copied() else {
      return Ok(First::Close);
    };
    got.push(next);
    let (rewritten, hits) = probe.feed(std::slice::from_ref(&next)).await;
    log_hits(&hits);
    if let Some(id) = probe.take_starttls() {
      let handshake = probe.take_prefix();
      let Some(start) = got.len().checked_sub(handshake.len()) else {
        return Ok(First::Close);
      };
      if got.get(start..) != Some(handshake.as_slice()) {
        return Ok(First::Close);
      }
      got.truncate(start);
      if forward {
        write_server(upstream, &got).await?;
      }
      return Ok(First::StartTls(StartTlsOpen {
        id,
        request: got,
        handshake,
      }));
    }
    if probe.starttls_tail().is_some() {
      if !forward_controls(guest, upstream, &mut probe, forward, &got).await? {
        return Ok(First::Close);
      }
      let Some(id) = probe.take_starttls() else {
        return Ok(First::Close);
      };
      return Ok(First::StartTls(StartTlsOpen {
        id,
        request: got,
        handshake: probe.take_prefix(),
      }));
    }
    match rewritten {
      Rewritten::Close => return Ok(First::Close),
      Rewritten::Hold => {}
      Rewritten::Emit(_) => return Ok(First::Relay(got)),
    }
  }
}

/// Read window for a `StartTLS` control tail. Each read is also capped by the
/// unread count, so the following handshake stays in the socket. The window
/// is reused. It is not a limit on the tail.
const CONTROL_READ: usize = 8 * 1024;

/// Stream the control bytes that follow a recognized `StartTLS` OID.
/// `probe` counts those bytes down. They are not appended to the prefix.
/// `false` when the guest closes first.
async fn forward_controls<R, W>(guest: &mut R, upstream: &mut W, probe: &mut Ldap, forward: bool, prefix: &[u8]) -> Result<bool, Error>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  if forward {
    upstream
      .write_all(prefix)
      .await
      .map_err(|source| Error::from(arkham_wire::Error::RequestChunkToUpstream { source }))?;
  }
  let mut buf = vec![0u8; CONTROL_READ];
  while let Some((_, left)) = probe.starttls_tail() {
    let want = left.min(buf.len());
    let Some(window) = buf.get_mut(..want) else {
      return Ok(false);
    };
    let n = read_count(guest.read(window).await).map_err(|source| Error::from(arkham_wire::Error::GuestRead { source }))?;
    if n == 0 {
      return Ok(false);
    }
    let Some(chunk) = window.get(..n) else {
      return Ok(false);
    };
    let (rewritten, hits) = probe.feed(chunk).await;
    log_hits(&hits);
    if matches!(rewritten, Rewritten::Close) || probe.starttls_tail().is_some_and(|(_, next)| next >= left) {
      return Ok(false);
    }
    if forward {
      upstream
        .write_all(chunk)
        .await
        .map_err(|source| Error::from(arkham_wire::Error::RequestChunkToUpstream { source }))?;
    }
    if probe.starttls_tail().is_none() {
      break;
    }
  }
  if forward {
    upstream
      .flush()
      .await
      .map_err(|source| Error::from(arkham_wire::Error::RequestHeadFlush { source }))?;
  }
  Ok(true)
}

/// Read the server until its `StartTLS` extended response has been forwarded.
/// Lockstep: the guest is not read, so the following handshake stays put.
async fn read_starttls_result<R, W>(server: &mut R, guest: &mut W, up: &mut Ldap, budget: Duration) -> Result<(bool, Vec<u8>), Error>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  let deadline = tokio::time::Instant::now() + budget;
  let mut buf = [0u8; 256];
  loop {
    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
    if left.is_zero() {
      return Err(
        arkham_wire::Error::UpstreamRead {
          source: IoError::new(ErrorKind::TimedOut, "ldap starttls response"),
        }
        .into(),
      );
    }
    let read = tokio::time::timeout(left, server.read(&mut buf)).await.map_err(|_elapsed| {
      Error::from(arkham_wire::Error::UpstreamRead {
        source: IoError::new(ErrorKind::TimedOut, "ldap starttls response"),
      })
    })?;
    let n = read_count(read).map_err(|source| Error::from(arkham_wire::Error::UpstreamRead { source }))?;
    if n == 0 {
      return Ok((false, Vec::new()));
    }
    let Some(chunk) = buf.get(..n) else {
      return Ok((false, Vec::new()));
    };
    if !forward_up(up, chunk, guest).await? {
      return Ok((false, Vec::new()));
    }
    if let Some(ok) = up.take_starttls_result() {
      let prefix = up.take_prefix();
      let (flushed, hits) = up.feed(&[]).await;
      log_hits(&hits);
      if let Rewritten::Emit(bytes) = flushed {
        write_guest(guest, &bytes).await?;
      }
      return Ok((ok, prefix));
    }
  }
}

/// Feed one upstream chunk and write what the cursor emits.
async fn forward_up<W>(up: &mut Ldap, chunk: &[u8], guest: &mut W) -> Result<bool, Error>
where
  W: AsyncWrite + Unpin,
{
  let (rewritten, hits) = up.feed(chunk).await;
  log_hits(&hits);
  match rewritten {
    Rewritten::Close => Ok(false),
    Rewritten::Hold => Ok(true),
    Rewritten::Emit(bytes) => {
      write_guest(guest, &bytes).await?;
      Ok(true)
    }
  }
}

async fn write_guest<W>(guest: &mut W, bytes: &[u8]) -> Result<(), Error>
where
  W: AsyncWrite + Unpin,
{
  guest
    .write_all(bytes)
    .await
    .map_err(|source| Error::from(arkham_wire::Error::ResponseChunkToGuest { source }))?;
  guest
    .flush()
    .await
    .map_err(|source| Error::from(arkham_wire::Error::GuestFlush { source }))?;
  Ok(())
}

async fn write_server<W>(server: &mut W, bytes: &[u8]) -> Result<(), Error>
where
  W: AsyncWrite + Unpin,
{
  server
    .write_all(bytes)
    .await
    .map_err(|source| Error::from(arkham_wire::Error::RequestChunkToUpstream { source }))?;
  server
    .flush()
    .await
    .map_err(|source| Error::from(arkham_wire::Error::RequestHeadFlush { source }))?;
  Ok(())
}

/// Pump one settled pair. A later `StartTLS` is forwarded to the server.
async fn relay<G, S>(guest: G, server: S, ctx: &PairCtx<'_>) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let (mut downstream, mut upstream) = ldap_pair(ctx);
  downstream.forward_starttls();
  relay_guarded(guest, server, &mut downstream, &mut upstream, &[], &[]).await
}

/// The simple-bind swap for the grant that covers this destination.
fn bind_swap(grants: &[Grant], host: &str, port: u16) -> Option<BindSwap> {
  grants.iter().find_map(|grant| {
    let scope = grant.ldap(Some(host), port)?;
    let label = grant.credential().map(|credential| credential.label.clone()).unwrap_or_default();
    Some(BindSwap {
      label,
      fake: scope.downstream.password.expose_secret().to_string(),
      real: scope.upstream.password.expose_secret().to_string(),
      downstream_dn: scope.downstream.dn.clone(),
      upstream_dn: scope.upstream.dn.clone(),
    })
  })
}

/// Both directions for one LDAP scope. Cleartext and TLS both swap.
pub(crate) fn ldap_pair(ctx: &PairCtx<'_>) -> (Ldap, Ldap) {
  let swap = bind_swap(ctx.grants, ctx.host, ctx.port);
  (Ldap::new(swap.clone(), Direction::Downstream), Ldap::new(swap, Direction::Upstream))
}

#[cfg(test)]
mod tests {
  use std::io::Cursor;

  use arkham_config::grants::Credential;
  use rasn::prelude::OctetString;
  use rasn_ldap::{AuthenticationChoice, BindRequest, Control, ExtendedRequest, LdapMessage, LdapString, ProtocolOp};
  use secrecy::SecretString;

  use super::*;

  const FAKE_PW: &str = "arkham_fake_ldap_pass"; // betterleaks:allow
  const REAL_PW: &str = "arkham_real_ldap_pass_01"; // betterleaks:allow
  const DN: &str = "cn=Directory Manager";
  const STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

  fn grants() -> Vec<Grant> {
    let scope = LdapScope::from_strings(
      &format!("ldap://{}:{FAKE_PW}@ldap:389", encode_dn(DN)),
      &format!("ldap://{}:{REAL_PW}@ldap:389", encode_dn(DN)),
    )
    .unwrap();
    vec![Grant::Ldap {
      credential: Credential {
        label: "ldap".into(),
        fake: FAKE_PW.into(),
        value: SecretString::from(REAL_PW),
      },
      scope: Box::new(scope),
    }]
  }

  fn encode_dn(dn: &str) -> String {
    dn.replace('=', "%3D").replace(' ', "%20").replace(',', "%2C")
  }

  fn bind_frame() -> Vec<u8> {
    let message = LdapMessage::new(
      1,
      ProtocolOp::BindRequest(BindRequest::new(
        3,
        LdapString::from(DN),
        AuthenticationChoice::Simple(OctetString::from(FAKE_PW.as_bytes())),
      )),
    );
    rasn::ber::encode(&message).unwrap()
  }

  fn starttls_frame(controls: bool) -> Vec<u8> {
    let mut message = LdapMessage::new(
      4,
      ProtocolOp::ExtendedReq(ExtendedRequest {
        request_name: OctetString::from_static(STARTTLS_OID),
        request_value: None,
      }),
    );
    if controls {
      message.controls = Some(vec![Control::new(OctetString::from_static(b"1.2.840.113556.1.4.319"), true, None)]);
    }
    rasn::ber::encode(&message).unwrap()
  }

  /// Keep the encoded content and announce `extra` more outer bytes.
  fn announce_extra(frame: &[u8], extra: usize) -> Vec<u8> {
    let lead = frame.get(1).copied().unwrap();
    let (header, content_len) = if lead < 0x80 {
      (2, usize::from(lead))
    } else {
      let octets = usize::from(lead & 0x7f);
      let mut len = 0usize;
      for byte in frame.get(2..2 + octets).unwrap() {
        len = (len << 8) | usize::from(*byte);
      }
      (2 + octets, len)
    };
    let content = frame.get(header..header + content_len).unwrap();
    let new_len = u32::try_from(content_len + extra).unwrap();
    let mut out = Vec::with_capacity(6 + content.len());
    out.push(0x30);
    out.push(0x84);
    out.extend_from_slice(&new_len.to_be_bytes());
    out.extend_from_slice(content);
    out
  }

  #[tokio::test]
  async fn starttls_with_controls_keeps_the_handshake_unread() {
    let frame = starttls_frame(true);
    let extra = b"\x16handshake";
    let mut bytes = frame.clone();
    bytes.extend_from_slice(extra);
    let mut guest = Cursor::new(bytes);
    let mut upstream = Cursor::new(Vec::new());
    let First::StartTls(StartTlsOpen { id, request, handshake }) =
      read_first(&mut guest, &mut upstream, true, bind_swap(&grants(), "ldap", 389))
        .await
        .unwrap()
    else {
      panic!("starttls");
    };
    assert_eq!(id, 4);
    assert_eq!(handshake, [] as [u8; 0]);
    assert!(request.len() < frame.len());
    assert!(frame.starts_with(&request));
    assert_eq!(upstream.into_inner(), frame);
    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut guest, &mut rest).unwrap();
    assert_eq!(rest, extra);
  }

  #[tokio::test]
  async fn starttls_large_control_tail_is_forwarded_byte_for_byte() {
    let tail_len = 64 * 1024;
    let head = announce_extra(&starttls_frame(false), tail_len);
    let controls = vec![0x5a; tail_len];
    let extra = b"\x16handshake";
    let mut bytes = head.clone();
    bytes.extend_from_slice(&controls);
    bytes.extend_from_slice(extra);
    let mut guest = Cursor::new(bytes);
    let mut upstream = Cursor::new(Vec::new());
    let First::StartTls(StartTlsOpen { request, handshake, .. }) =
      read_first(&mut guest, &mut upstream, true, bind_swap(&grants(), "ldap", 389))
        .await
        .unwrap()
    else {
      panic!("starttls");
    };
    assert_eq!(request, head);
    assert_eq!(handshake, [] as [u8; 0]);
    assert!(request.len() < tail_len);
    let mut expect = head;
    expect.extend_from_slice(&controls);
    assert_eq!(upstream.into_inner(), expect);
    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut guest, &mut rest).unwrap();
    assert_eq!(rest, extra);
  }

  #[tokio::test]
  async fn starttls_control_tail_is_dropped_when_upstream_is_tls() {
    let frame = starttls_frame(true);
    let extra = b"\x16handshake";
    let mut bytes = frame.clone();
    bytes.extend_from_slice(extra);
    let mut guest = Cursor::new(bytes);
    let mut upstream = Cursor::new(Vec::new());
    let First::StartTls(StartTlsOpen { request, handshake, .. }) =
      read_first(&mut guest, &mut upstream, false, bind_swap(&grants(), "ldap", 389))
        .await
        .unwrap()
    else {
      panic!("starttls");
    };
    assert!(request.len() < frame.len());
    assert_eq!(handshake, [] as [u8; 0]);
    assert_eq!(upstream.into_inner(), [] as [u8; 0]);
    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut guest, &mut rest).unwrap();
    assert_eq!(rest, extra);
  }

  #[tokio::test]
  async fn bind_opener_relays_from_the_prefix() {
    let frame = bind_frame();
    let mut guest = Cursor::new(frame.clone());
    let mut upstream = Cursor::new(Vec::new());
    let First::Relay(prefix) = read_first(&mut guest, &mut upstream, true, bind_swap(&grants(), "ldap", 389))
      .await
      .unwrap()
    else {
      panic!("relay");
    };
    assert_eq!(upstream.into_inner(), [] as [u8; 0]);
    assert_ne!(prefix, [] as [u8; 0]);
    assert!(frame.starts_with(&prefix));
    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut guest, &mut rest).unwrap();
    let mut whole = prefix;
    whole.extend(rest);
    assert_eq!(whole, frame);
  }
}
