//! Bidirectional pump through two wire directions.
//!
//! Each direction runs as its own pump future: a blocked guest-bound write
//! never stalls the reading of upstream bytes, and the other way around. The
//! request pump talks to the response pump over one FIFO channel (protocol
//! replies, framing facts, and the request direction's terminal intent —
//! ordering inside the channel replaces any select priority). The response
//! pump ends the request pump through a oneshot. An upgrade decision is a
//! separate signal, so a refusal can leave the relay running.

use std::io::{Error as IoError, ErrorKind};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadHalf, WriteHalf, split};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::Error;
use crate::transports::engine::{Hit, LocalUpgrade, PeerFact, Rewritten, UpgradeNote, Wire};

/// Guest-bound work and terminal intent, request pump → response pump.
/// FIFO order is the contract: replies and framing facts queued before a
/// terminal message are applied before it is honored.
enum ToResponse {
  /// Guest-bound protocol reply (Postgres negotiation refusals).
  Reply(Vec<u8>),
  /// Framing fact from the request machine.
  PeerNote(PeerFact),
  /// The request direction failed or failed closed: end the relay now.
  RequestsEnded,
  /// The next extended response with this id is the upgrade result.
  /// Sent before the upgrade request is written.
  ArmUpgrade(u64),
  /// The upgrade request was withheld. The response pump decides with this id.
  Handoff(u64),
}

/// What one relay stopped on. `Upgrade` still owns both sockets.
#[derive(Debug)]
#[must_use]
pub(crate) enum RelayEnd<G, S> {
  /// The peers finished or the relay failed closed.
  Done,
  /// An upgrade was accepted. `prefix` bytes were already read.
  Upgrade(RelayUpgrade<G, S>),
}

/// Both sockets, the unread bytes past the upgrade messages, and the message id.
#[derive(Debug)]
pub(crate) struct RelayUpgrade<G, S> {
  /// Guest socket, reunited.
  pub(crate) guest: G,
  /// Server socket, reunited.
  pub(crate) server: S,
  /// Bytes after the upgrade request.
  pub(crate) guest_prefix: Vec<u8>,
  /// Bytes after the upgrade response.
  pub(crate) server_prefix: Vec<u8>,
  /// Message id of the upgrade request.
  pub(crate) id: u64,
  /// The request was answered here. The server socket is already upgraded.
  pub(crate) local: bool,
}

/// How the request pump stopped.
enum RequestEnd<G, S> {
  Done,
  Upgrade {
    read: ReadHalf<G>,
    write: WriteHalf<S>,
    prefix: Vec<u8>,
    id: u64,
    local: bool,
  },
}

/// How the response pump stopped.
enum ResponseEnd<G, S> {
  Done,
  Upgrade {
    read: ReadHalf<S>,
    write: WriteHalf<G>,
    prefix: Vec<u8>,
  },
}

/// Bidirectional relay through the two directions' wire formats. Guest FIN
/// flushes the downstream direction, then upstream shutdown while still
/// draining upstream→guest; upstream close flushes the upstream direction
/// and ends the relay.
pub(crate) async fn relay_guarded<G, S, M>(
  guest: G,
  server: S,
  downstream: &mut M,
  upstream: &mut M,
  first: &[u8],
  upstream_first: &[u8],
) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  // The upgrade state stays on the heap. Inlining it here would sit in
  // every protocol's relay future.
  match Box::pin(relay_stop(guest, server, downstream, upstream, first, upstream_first)).await? {
    RelayEnd::Done | RelayEnd::Upgrade(_) => Ok(()),
  }
}

/// [`relay_guarded`], plus an upgrade handoff that returns both sockets.
///
/// A protocol that does not report an upgrade gets [`RelayEnd::Done`]. The
/// read buffer and the deadlines stay the ones this relay already has.
pub(crate) async fn relay_stop<G, S, M>(
  guest: G,
  server: S,
  downstream: &mut M,
  upstream: &mut M,
  first: &[u8],
  upstream_first: &[u8],
) -> Result<RelayEnd<G, S>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  let (guest_read, guest_write) = split(guest);
  let (server_read, server_write) = split(server);
  let (to_responses_tx, to_responses_rx) = mpsc::unbounded_channel();
  let (responses_done_tx, responses_done_rx) = oneshot::channel();
  // One slot. The request pump waits before the next decision, so a refusal
  // cannot sit in front of a later approval.
  let (upgrade_tx, upgrade_rx) = mpsc::channel(1);
  let (requests, responses) = tokio::join!(
    pump_requests(
      guest_read,
      server_write,
      downstream,
      to_responses_tx,
      responses_done_rx,
      upgrade_rx,
      first,
    ),
    pump_responses(
      server_read,
      guest_write,
      upstream,
      to_responses_rx,
      responses_done_tx,
      upgrade_tx,
      upstream_first,
    ),
  );
  match (requests?, responses?) {
    (
      RequestEnd::Upgrade {
        read,
        write,
        prefix,
        id,
        local,
      },
      ResponseEnd::Upgrade {
        read: server_read,
        write: guest_write,
        prefix: server_prefix,
      },
    ) => Ok(RelayEnd::Upgrade(RelayUpgrade {
      guest: read.unsplit(guest_write),
      server: server_read.unsplit(write),
      guest_prefix: prefix,
      server_prefix,
      id,
      local,
    })),
    // Both directions finished, or only one of them stopped on the upgrade.
    // The halves come from one `split`, so a single side cannot put them
    // back together. The sockets close with the relay.
    _ => Ok(RelayEnd::Done),
  }
}

/// Tell the response pump the request direction ended the relay. A closed
/// channel means it already ended itself; the relay is closing either way.
fn end_requests(responses: &mpsc::UnboundedSender<ToResponse>) {
  let _ = responses.send(ToResponse::RequestsEnded);
}

/// Guest→upstream direction: read the guest, feed the downstream machine,
/// carry rewritten bytes upstream, hand replies and framing facts to the
/// response pump.
async fn pump_requests<G, S, M>(
  mut guest: ReadHalf<G>,
  mut server: WriteHalf<S>,
  downstream: &mut M,
  responses: mpsc::UnboundedSender<ToResponse>,
  mut responses_done: oneshot::Receiver<()>,
  mut upgrade_rx: mpsc::Receiver<bool>,
  first: &[u8],
) -> Result<RequestEnd<G, S>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  if !first.is_empty() && !pump_first(&mut server, downstream, &responses, &mut responses_done, first).await? {
    return Ok(RequestEnd::Done);
  }
  let mut buf = vec![0u8; 32 * 1024];
  let mut replay = Vec::new();
  loop {
    if !replay.is_empty() {
      let bytes = std::mem::take(&mut replay);
      match feed_guest(&mut server, downstream, &responses, &mut responses_done, &mut upgrade_rx, &bytes).await? {
        UpgradeWait::Stay => {}
        UpgradeWait::Replay(next) => replay = next,
        UpgradeWait::Done => return Ok(RequestEnd::Done),
        UpgradeWait::Proceed { prefix, id, local } => {
          return Ok(RequestEnd::Upgrade {
            read: guest,
            write: server,
            prefix,
            id,
            local,
          });
        }
      }
      continue;
    }
    tokio::select! {
      _ = &mut responses_done => return Ok(RequestEnd::Done),
      result = guest.read(&mut buf) => {
        // rustls surfaces a peer FIN without close_notify as UnexpectedEof;
        // for a relay that is a normal end-of-stream, not an error.
        let result = match result {
          Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(0),
          other => other,
        };
        match result {
          Ok(0) => {
            let (rewritten, hits) = downstream.feed(&[]).await;
            hand_over(&responses, downstream);
            log_hits(&hits);
            if let Rewritten::Emit(flushed) = rewritten {
              write_or_stopped(
                &mut server,
                &flushed,
                &mut responses_done,
                |source| request_flush_error(&responses, source),
              )
              .await?;
            }
            // Upstream may already have closed its write side; a failed
            // shutdown must not abort the relay — keep draining the
            // response direction.
            let _ = server.shutdown().await;
            return Ok(RequestEnd::Done);
          }
          Ok(n) => {
            match feed_guest(&mut server, downstream, &responses, &mut responses_done, &mut upgrade_rx, &buf[..n]).await? {
              UpgradeWait::Stay => {}
              UpgradeWait::Replay(next) => replay = next,
              UpgradeWait::Done => return Ok(RequestEnd::Done),
              UpgradeWait::Proceed { prefix, id, local } => {
                return Ok(RequestEnd::Upgrade {
                  read: guest,
                  write: server,
                  prefix,
                  id,
                  local,
                });
              }
            }
          }
          Err(err) => {
            end_requests(&responses);
            return Err(Error::GuestRead { source: err });
          }
        }
      }
    }
  }
}

/// What the request pump does after one guest chunk.
enum UpgradeWait {
  Stay,
  /// Bytes after a refused upgrade. They are still LDAP.
  Replay(Vec<u8>),
  Done,
  Proceed {
    prefix: Vec<u8>,
    id: u64,
    local: bool,
  },
}

async fn feed_guest<S, M>(
  server: &mut WriteHalf<S>,
  downstream: &mut M,
  responses: &mpsc::UnboundedSender<ToResponse>,
  responses_done: &mut oneshot::Receiver<()>,
  upgrade_rx: &mut mpsc::Receiver<bool>,
  chunk: &[u8],
) -> Result<UpgradeWait, Error>
where
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  let (rewritten, hits) = downstream.feed(chunk).await;
  hand_over(responses, downstream);
  log_hits(&hits);
  if let Some(note) = downstream.take_upgrade() {
    return request_upgrade(server, responses, responses_done, upgrade_rx, &rewritten, note).await;
  }
  match rewritten {
    Rewritten::Close => {
      end_requests(responses);
      Ok(UpgradeWait::Done)
    }
    Rewritten::Hold => Ok(UpgradeWait::Stay),
    Rewritten::Emit(out) => {
      if write_or_stopped(server, &out, responses_done, |source| request_chunk_error(responses, source))
        .await?
        .is_none()
      {
        return Ok(UpgradeWait::Done);
      }
      Ok(UpgradeWait::Stay)
    }
  }
}

/// Feed the replayed first bytes downstream and carry the first chunk
/// upstream. Returns `false` when the downstream direction already ended the
/// relay.
async fn pump_first<W, M>(
  server: &mut W,
  downstream: &mut M,
  responses: &mpsc::UnboundedSender<ToResponse>,
  responses_done: &mut oneshot::Receiver<()>,
  first: &[u8],
) -> Result<bool, Error>
where
  W: AsyncWrite + Unpin,
  M: Wire,
{
  let (rewritten, hits) = downstream.feed(first).await;
  hand_over(responses, downstream);
  log_hits(&hits);
  match rewritten {
    Rewritten::Close => {
      end_requests(responses);
      Ok(false)
    }
    Rewritten::Hold => Ok(true),
    Rewritten::Emit(out) => {
      write_or_stopped(server, &out, responses_done, |source| request_head_error(responses, source)).await?;
      server.flush().await.map_err(|source| Error::RequestHeadFlush { source })?;
      Ok(true)
    }
  }
}

/// Stop reading the guest until the response pump decides. A dropped sender ends the relay.
async fn request_upgrade<S>(
  server: &mut WriteHalf<S>,
  responses: &mpsc::UnboundedSender<ToResponse>,
  responses_done: &mut oneshot::Receiver<()>,
  upgrade_rx: &mut mpsc::Receiver<bool>,
  rewritten: &Rewritten<'_>,
  note: UpgradeNote,
) -> Result<UpgradeWait, Error>
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let UpgradeNote::Request { id, prefix, local } = note else {
    end_requests(responses);
    return Ok(UpgradeWait::Done);
  };
  let _ = responses.send(if local {
    ToResponse::Handoff(id)
  } else {
    ToResponse::ArmUpgrade(id)
  });
  if let Rewritten::Emit(out) = rewritten {
    if write_or_stopped(server, out, responses_done, |source| request_chunk_error(responses, source))
      .await?
      .is_none()
    {
      return Ok(UpgradeWait::Done);
    }
    server.flush().await.map_err(|source| request_flush_error(responses, source))?;
  }
  // Reading the guest stops here. That lockstep is what the upgrade needs.
  // A later StartTLS in this relay can still be approved, so the signal is
  // not a oneshot.
  match upgrade_rx.recv().await {
    Some(true) => Ok(UpgradeWait::Proceed { prefix, id, local }),
    Some(false) if local => Ok(if prefix.is_empty() {
      UpgradeWait::Stay
    } else {
      UpgradeWait::Replay(prefix)
    }),
    _ => {
      if !local {
        let _ = server.shutdown().await;
      }
      Ok(UpgradeWait::Done)
    }
  }
}

/// Upstream→guest direction: read the upstream, feed the upstream machine,
/// carry rewritten bytes to the guest, apply what the request pump queued.
async fn pump_responses<G, S, M>(
  mut server: ReadHalf<S>,
  mut guest: WriteHalf<G>,
  upstream: &mut M,
  mut requests: mpsc::UnboundedReceiver<ToResponse>,
  responses_done: oneshot::Sender<()>,
  upgrade_tx: mpsc::Sender<bool>,
  upstream_first: &[u8],
) -> Result<ResponseEnd<G, S>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  let mut armed = false;
  if !upstream_first.is_empty() {
    let open = write_upstream_chunk(&mut guest, upstream, upstream_first).await?;
    if !open {
      let _ = responses_done.send(());
      guest.flush().await.map_err(|source| Error::FinalGuestFlush { source })?;
      let _ = guest.shutdown().await;
      return Ok(ResponseEnd::Done);
    }
  }
  let mut buf = vec![0u8; 32 * 1024];
  let mut requests_open = true;
  let upgrade = loop {
    tokio::select! {
      msg = requests.recv(), if requests_open => match msg {
        Some(ToResponse::RequestsEnded) => break Ok(None),
        Some(ToResponse::Handoff(id)) => match answer_handoff(&mut guest, upstream, &upgrade_tx, id).await? {
          ChunkStep::Stay => {}
          ChunkStep::Stop => break Ok(None),
          ChunkStep::Upgrade(prefix) => break Ok(Some(prefix)),
        },
        Some(ToResponse::ArmUpgrade(id)) => {
          armed = true;
          upstream.arm_upgrade(id);
        }
        Some(msg) => apply_message(&mut guest, upstream, msg).await?,
        None => requests_open = false,
      },
      result = server.read(&mut buf) => {
        // rustls surfaces a peer FIN without close_notify as UnexpectedEof;
        // for a relay that is a normal end-of-stream, not an error.
        let result = match result {
          Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(0),
          other => other,
        };
        match result {
          Ok(0) => break upstream_end(&mut guest, upstream, &mut requests, &mut armed, &upgrade_tx).await,
          Ok(n) => match on_upstream_chunk(&mut guest, upstream, &mut requests, &mut armed, &upgrade_tx, &buf[..n]).await? {
            ChunkStep::Stay => {}
            ChunkStep::Stop => break Ok(None),
            ChunkStep::Upgrade(prefix) => break Ok(Some(prefix)),
          },
          Err(err) => break Err(Error::UpstreamRead { source: err }),
        }
      }
    }
  };
  if let Ok(Some(prefix)) = upgrade {
    return Ok(ResponseEnd::Upgrade {
      read: server,
      write: guest,
      prefix,
    });
  }
  if armed {
    let _ = upgrade_tx.try_send(false);
  }
  let _ = responses_done.send(());
  match upgrade {
    Ok(_) => {
      guest.flush().await.map_err(|source| Error::FinalGuestFlush { source })?;
      let _ = guest.shutdown().await;
      Ok(ResponseEnd::Done)
    }
    Err(err) => Err(err),
  }
}

enum ChunkStep {
  Stay,
  Stop,
  Upgrade(Vec<u8>),
}

async fn upstream_end<G, M>(
  guest: &mut WriteHalf<G>,
  upstream: &mut M,
  requests: &mut mpsc::UnboundedReceiver<ToResponse>,
  armed: &mut bool,
  upgrade_tx: &mpsc::Sender<bool>,
) -> Result<Option<Vec<u8>>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  match drain_requests(guest, upstream, requests, armed, upgrade_tx).await? {
    ChunkStep::Stop => return Ok(None),
    ChunkStep::Upgrade(prefix) => return Ok(Some(prefix)),
    ChunkStep::Stay => {}
  }
  let (rewritten, hits) = upstream.feed(&[]).await;
  log_hits(&hits);
  if let Rewritten::Emit(flushed) = rewritten {
    guest
      .write_all(&flushed)
      .await
      .map_err(|source| Error::ResponseFlushToGuest { source })?;
  }
  Ok(None)
}

/// Drain queued notes, then feed one upstream chunk. A handoff still writes bytes this read took.
async fn on_upstream_chunk<G, M>(
  guest: &mut WriteHalf<G>,
  upstream: &mut M,
  requests: &mut mpsc::UnboundedReceiver<ToResponse>,
  armed: &mut bool,
  upgrade_tx: &mpsc::Sender<bool>,
  chunk: &[u8],
) -> Result<ChunkStep, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  let drained = drain_requests(guest, upstream, requests, armed, upgrade_tx).await?;
  if matches!(drained, ChunkStep::Stop) {
    return Ok(ChunkStep::Stop);
  }
  let (rewritten, hits) = upstream.feed(chunk).await;
  log_hits(&hits);
  if let ChunkStep::Upgrade(prefix) = drained {
    if let Rewritten::Emit(out) = &rewritten {
      write_guest_chunk(guest, out).await?;
    }
    return Ok(ChunkStep::Upgrade(prefix));
  }
  if let Some(note) = upstream.take_upgrade() {
    return match response_upgrade(guest, &rewritten, upgrade_tx, note).await? {
      Some(prefix) => Ok(ChunkStep::Upgrade(prefix)),
      None => Ok(ChunkStep::Stop),
    };
  }
  match rewritten {
    // A scan that cannot rewrite the chunk closes rather than forward it.
    Rewritten::Close => Ok(ChunkStep::Stop),
    Rewritten::Hold => Ok(ChunkStep::Stay),
    Rewritten::Emit(out) => {
      write_guest_chunk(guest, &out).await?;
      Ok(ChunkStep::Stay)
    }
  }
}

async fn write_guest_chunk(guest: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Result<(), Error> {
  guest
    .write_all(bytes)
    .await
    .map_err(|source| Error::ResponseChunkToGuest { source })?;
  guest.flush().await.map_err(|source| Error::GuestFlush { source })?;
  Ok(())
}

/// Write an upgrade result and wake the request pump. `Some` is the unread tail.
async fn response_upgrade<W>(
  guest: &mut W,
  rewritten: &Rewritten<'_>,
  upgrade_tx: &mpsc::Sender<bool>,
  note: UpgradeNote,
) -> Result<Option<Vec<u8>>, Error>
where
  W: AsyncWrite + Unpin,
{
  let UpgradeNote::Response { ok, prefix } = note else {
    let _ = upgrade_tx.try_send(false);
    return Ok(None);
  };
  if let Rewritten::Emit(out) = rewritten {
    write_guest_chunk(guest, out).await?;
  }
  let _ = upgrade_tx.try_send(ok);
  Ok(ok.then_some(prefix))
}

/// A withheld upgrade. Outstanding work is `operationsError` now; an empty set upgrades.
async fn answer_handoff<W, M>(guest: &mut W, upstream: &mut M, upgrade_tx: &mpsc::Sender<bool>, id: u64) -> Result<ChunkStep, Error>
where
  W: AsyncWrite + Unpin,
  M: Wire,
{
  match upstream.local_upgrade(id) {
    LocalUpgrade::Proceed => {
      let _ = upgrade_tx.try_send(true);
      Ok(ChunkStep::Upgrade(Vec::new()))
    }
    LocalUpgrade::Refuse(bytes) => {
      write_guest_chunk(guest, &bytes).await?;
      let _ = upgrade_tx.try_send(false);
      Ok(ChunkStep::Stay)
    }
    LocalUpgrade::Close => Ok(ChunkStep::Stop),
  }
}

/// Feed bytes already taken from the server and write what the upstream
/// machine emits. `false` means that machine closed the relay.
async fn write_upstream_chunk<W, M>(guest: &mut W, upstream: &mut M, bytes: &[u8]) -> Result<bool, Error>
where
  W: AsyncWrite + Unpin,
  M: Wire,
{
  let (rewritten, hits) = upstream.feed(bytes).await;
  log_hits(&hits);
  match rewritten {
    Rewritten::Close => Ok(false),
    Rewritten::Hold => Ok(true),
    Rewritten::Emit(out) => {
      if !out.is_empty() {
        write_guest_chunk(guest, &out).await?;
      }
      Ok(true)
    }
  }
}

/// Apply one queued message from the request pump: a guest-bound protocol
/// reply or a framing fact into the response machine.
async fn apply_message<W, M>(guest: &mut W, upstream: &mut M, msg: ToResponse) -> Result<(), Error>
where
  W: AsyncWrite + Unpin,
  M: Wire,
{
  match msg {
    ToResponse::Reply(reply) => {
      guest
        .write_all(&reply)
        .await
        .map_err(|source| Error::ProtocolReplyToGuest { source })?;
      guest.flush().await.map_err(|source| Error::ProtocolReplyFlush { source })?;
    }
    ToResponse::PeerNote(fact) => upstream.apply_peer_note(fact),
    ToResponse::ArmUpgrade(id) => upstream.arm_upgrade(id),
    ToResponse::RequestsEnded | ToResponse::Handoff(_) => {}
  }
  Ok(())
}

/// Apply queued request-pump notes. `Upgrade` is a handoff the caller still writes through.
async fn drain_requests<W, M>(
  guest: &mut W,
  upstream: &mut M,
  requests: &mut mpsc::UnboundedReceiver<ToResponse>,
  armed: &mut bool,
  upgrade_tx: &mpsc::Sender<bool>,
) -> Result<ChunkStep, Error>
where
  W: AsyncWrite + Unpin,
  M: Wire,
{
  while let Ok(msg) = requests.try_recv() {
    match msg {
      ToResponse::RequestsEnded => return Ok(ChunkStep::Stop),
      ToResponse::Handoff(id) => return answer_handoff(guest, upstream, upgrade_tx, id).await,
      ToResponse::ArmUpgrade(id) => {
        *armed = true;
        upstream.arm_upgrade(id);
      }
      other => apply_message(guest, upstream, other).await?,
    }
  }
  Ok(ChunkStep::Stay)
}

/// Hand the response pump a queued protocol reply and any framing fact. A
/// closed channel means the response direction already ended; the relay is
/// closing, so dropping the reply is correct.
fn hand_over<M: Wire>(responses: &mpsc::UnboundedSender<ToResponse>, downstream: &mut M) {
  if let Some(reply) = downstream.take_reply() {
    let _ = responses.send(ToResponse::Reply(reply));
  }
  while let Some(fact) = downstream.take_peer_note() {
    let _ = responses.send(ToResponse::PeerNote(fact));
  }
}

/// Write that abandons the direction when the response direction ended: a
/// half-finished write is fine, the connection is closing anyway. `None`
/// means stopped before completion.
async fn write_or_stopped<W, F>(
  sink: &mut W,
  bytes: &[u8],
  responses_done: &mut oneshot::Receiver<()>,
  into_error: F,
) -> Result<Option<()>, Error>
where
  W: AsyncWrite + Unpin,
  F: FnOnce(IoError) -> Error,
{
  tokio::select! {
    result = sink.write_all(bytes) => match result {
      Ok(()) => Ok(Some(())),
      Err(source) => Err(into_error(source)),
    },
    _ = &mut *responses_done => Ok(None),
  }
}

/// Terminal intent rides with the error: the response pump must learn the
/// relay ended even when the request pump unwinds early.
fn request_flush_error(responses: &mpsc::UnboundedSender<ToResponse>, source: IoError) -> Error {
  end_requests(responses);
  Error::RequestFlushToUpstream { source }
}

/// Terminal intent rides with the error: the response pump must learn the
/// relay ended even when the request pump unwinds early.
fn request_chunk_error(responses: &mpsc::UnboundedSender<ToResponse>, source: IoError) -> Error {
  end_requests(responses);
  Error::RequestChunkToUpstream { source }
}

/// Terminal intent rides with the error: the response pump must learn the
/// relay ended even when the request pump unwinds early.
fn request_head_error(responses: &mpsc::UnboundedSender<ToResponse>, source: IoError) -> Error {
  end_requests(responses);
  Error::RequestHeadToUpstream { source }
}

pub(crate) fn log_hits(hits: &[Hit]) {
  for hit in hits {
    tracing::debug!(label = %hit.label, location = ?hit.location, "substituted");
  }
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use crate::transports::engine::{Direction, Ldap};
  use arkham_config::grants::{Credential, Grant, LdapScope};
  use rasn_ldap::{ExtendedRequest, LdapMessage, ProtocolOp, ResultCode};
  use secrecy::SecretString;

  use super::*;

  const FAKE_PW: &str = "arkham_fake_ldap_pass"; // betterleaks:allow
  const REAL_PW: &str = "arkham_real_ldap_pass_01"; // betterleaks:allow

  fn grants() -> Vec<Grant> {
    let scope = LdapScope::from_strings(
      &format!("ldap://cn%3Ddir:{FAKE_PW}@ldap:389"),
      &format!("ldap://cn%3Ddir:{REAL_PW}@ldap:389"),
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

  fn pair() -> (Ldap, Ldap) {
    let grants = grants();
    (
      Ldap::new(&grants, "ldap", 389, Direction::Downstream, true),
      Ldap::new(&grants, "ldap", 389, Direction::Upstream, false),
    )
  }

  fn bind_and_starttls() -> Vec<u8> {
    let bind = LdapMessage::new(
      1,
      ProtocolOp::BindRequest(rasn_ldap::BindRequest::new(
        3,
        rasn_ldap::LdapString::from("cn=dir"),
        rasn_ldap::AuthenticationChoice::Simple(rasn::prelude::OctetString::from(FAKE_PW.as_bytes())),
      )),
    );
    let start = LdapMessage::new(
      2,
      ProtocolOp::ExtendedReq(ExtendedRequest {
        request_name: rasn::prelude::OctetString::from_static(b"1.3.6.1.4.1.1466.20037"),
        request_value: None,
      }),
    );
    let mut bytes = rasn::ber::encode(&bind).unwrap();
    bytes.extend(rasn::ber::encode(&start).unwrap());
    bytes
  }

  #[tokio::test]
  async fn open_bind_refuses_starttls_before_any_bind_result() {
    let (mut down, mut up) = pair();
    down.hold_starttls();
    let (guest_relay, mut guest) = tokio::io::duplex(4096);
    let (server_relay, _server) = tokio::io::duplex(4096);
    let relay = tokio::spawn(async move { relay_stop(guest_relay, server_relay, &mut down, &mut up, &[], &[]).await });
    guest.write_all(&bind_and_starttls()).await.unwrap();
    let mut buf = [0u8; 512];
    let read = tokio::time::timeout(Duration::from_millis(500), guest.read(&mut buf)).await;
    relay.abort();
    let n = read.expect("operationsError before the bind result").unwrap();
    let message: LdapMessage = rasn::ber::decode(&buf[..n]).unwrap();
    let ProtocolOp::ExtendedResp(body) = message.protocol_op else {
      panic!("starttls response");
    };
    assert_eq!(message.message_id, 2);
    assert_eq!(body.result_code, ResultCode::OperationsError);
  }

  fn starttls(id: u32) -> Vec<u8> {
    let start = LdapMessage::new(
      id,
      ProtocolOp::ExtendedReq(ExtendedRequest {
        request_name: rasn::prelude::OctetString::from_static(b"1.3.6.1.4.1.1466.20037"),
        request_value: None,
      }),
    );
    rasn::ber::encode(&start).unwrap()
  }

  #[tokio::test]
  async fn held_starttls_hands_off_when_nothing_is_outstanding() {
    let (mut down, mut up) = pair();
    down.hold_starttls();
    let (guest_relay, mut guest) = tokio::io::duplex(4096);
    let (server_relay, _server) = tokio::io::duplex(4096);
    let relay = tokio::spawn(async move { relay_stop(guest_relay, server_relay, &mut down, &mut up, &[], &[]).await });
    guest.write_all(&starttls(7)).await.unwrap();
    let end = tokio::time::timeout(Duration::from_secs(1), relay)
      .await
      .expect("handoff")
      .unwrap()
      .unwrap();
    let RelayEnd::Upgrade(upgrade) = end else {
      panic!("upgrade");
    };
    assert!(upgrade.local);
    assert_eq!(upgrade.id, 7);
  }

  #[tokio::test]
  async fn split_entry_gets_operations_error_after_the_whole_entry() {
    let (entry, split) = big_entry();
    let (mut down, mut up) = pair();
    down.hold_starttls();
    let (guest_relay, mut guest) = tokio::io::duplex(64 * 1024);
    let (server_relay, mut server) = tokio::io::duplex(64 * 1024);
    let relay = tokio::spawn(async move { relay_stop(guest_relay, server_relay, &mut down, &mut up, &[], &[]).await });
    guest.write_all(&search_bytes(1)).await.unwrap();
    server.write_all(&entry[..split]).await.unwrap();
    let mut first = vec![0u8; split];
    tokio::time::timeout(Duration::from_secs(1), guest.read_exact(&mut first))
      .await
      .expect("entry prefix")
      .unwrap();
    assert_eq!(first, entry[..split]);
    guest.write_all(&starttls(2)).await.unwrap();
    let mut early = [0u8; 64];
    let early = tokio::time::timeout(Duration::from_millis(200), guest.read(&mut early)).await;
    assert!(early.is_err(), "operationsError landed inside the entry");
    server.write_all(&entry[split..]).await.unwrap();
    let mut rest = vec![0u8; entry.len() - split + 256];
    let n = tokio::time::timeout(Duration::from_secs(1), guest.read(&mut rest))
      .await
      .expect("entry tail")
      .unwrap();
    relay.abort();
    let mut stream = entry[..split].to_vec();
    stream.extend_from_slice(&rest[..n]);
    let (decoded, after) = decode_one(&stream);
    assert_eq!(decoded, rasn::ber::decode(&entry).unwrap());
    let (refusal, leftover) = decode_one(after);
    assert!(leftover.is_empty());
    let ProtocolOp::ExtendedResp(body) = refusal.protocol_op else {
      panic!("starttls response");
    };
    assert_eq!(refusal.message_id, 2);
    assert_eq!(body.result_code, ResultCode::OperationsError);
  }

  #[tokio::test]
  async fn split_entry_delays_the_upgrade_until_its_last_byte() {
    let (entry, split) = big_entry();
    let (mut down, mut up) = pair();
    down.hold_starttls();
    let (guest_relay, mut guest) = tokio::io::duplex(64 * 1024);
    let (server_relay, mut server) = tokio::io::duplex(64 * 1024);
    let mut relay = tokio::spawn(async move { relay_stop(guest_relay, server_relay, &mut down, &mut up, &[], &[]).await });
    guest.write_all(&search_bytes(1)).await.unwrap();
    server.write_all(&entry[..split]).await.unwrap();
    let mut first = vec![0u8; split];
    tokio::time::timeout(Duration::from_secs(1), guest.read_exact(&mut first))
      .await
      .expect("entry prefix")
      .unwrap();
    let mut abandon = rasn::ber::encode(&LdapMessage::new(2, ProtocolOp::AbandonRequest(rasn_ldap::AbandonRequest(1)))).unwrap();
    abandon.extend(starttls(3));
    guest.write_all(&abandon).await.unwrap();
    let early = tokio::time::timeout(Duration::from_millis(200), &mut relay).await;
    assert!(early.is_err(), "upgraded inside the entry");
    server.write_all(&entry[split..]).await.unwrap();
    let end = tokio::time::timeout(Duration::from_secs(1), relay)
      .await
      .expect("upgrade after the entry")
      .unwrap()
      .unwrap();
    let RelayEnd::Upgrade(upgrade) = end else {
      panic!("upgrade");
    };
    assert!(upgrade.local);
    assert_eq!(upgrade.id, 3);
    let mut got = vec![0u8; entry.len()];
    tokio::time::timeout(Duration::from_secs(1), guest.read_exact(&mut got))
      .await
      .expect("full entry")
      .unwrap();
    assert_eq!(got, entry);
  }

  #[tokio::test]
  async fn backpressured_prefix_still_upgrades() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    let (mut down, mut up) = pair();
    down.hold_starttls();
    let (guest_relay, mut guest) = tokio::io::duplex(4096);
    let (server_relay, mut server) = tokio::io::duplex(4096);
    let released = Arc::new(AtomicBool::new(false));
    let stalled = Arc::new(AtomicBool::new(false));
    let slot = Arc::new(Mutex::new(None));
    let stalled_server = StallWrite {
      inner: server_relay,
      released: Arc::clone(&released),
      stalled: Arc::clone(&stalled),
      slot: Arc::clone(&slot),
    };
    let relay = tokio::spawn(async move { relay_stop(guest_relay, stalled_server, &mut down, &mut up, &[], &[]).await });
    let release = tokio::spawn(async move {
      while !stalled.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
      }
      for _ in 0..8 {
        tokio::task::yield_now().await;
      }
      released.store(true, Ordering::SeqCst);
      if let Some(waker) = slot.lock().unwrap().take() {
        waker.wake();
      }
    });
    let mut bytes = search_bytes(1);
    bytes.extend(rasn::ber::encode(&LdapMessage::new(2, ProtocolOp::AbandonRequest(rasn_ldap::AbandonRequest(1)))).unwrap());
    bytes.extend(starttls(3));
    guest.write_all(&bytes).await.unwrap();
    let end = tokio::time::timeout(Duration::from_secs(2), relay)
      .await
      .expect("upgrade")
      .unwrap()
      .unwrap();
    release.abort();
    let RelayEnd::Upgrade(upgrade) = end else {
      panic!("upgrade");
    };
    assert!(upgrade.local);
    assert_eq!(upgrade.id, 3);
    let mut got = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(1), server.read(&mut got))
      .await
      .expect("prefix written")
      .unwrap();
    assert!(n > 0);
  }

  fn search_bytes(id: u32) -> Vec<u8> {
    rasn::ber::encode(&LdapMessage::new(
      id,
      ProtocolOp::SearchRequest(rasn_ldap::SearchRequest::new(
        rasn_ldap::LdapString::from(""),
        rasn_ldap::SearchRequestScope::BaseObject,
        rasn_ldap::SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        rasn_ldap::Filter::Present(rasn_ldap::LdapString::from("objectClass")),
        Vec::new(),
      )),
    ))
    .unwrap()
  }

  fn big_entry() -> (Vec<u8>, usize) {
    let entry = rasn_ldap::SearchResultEntry::new(
      rasn_ldap::LdapString::from("cn=a"),
      vec![rasn_ldap::PartialAttribute::new(
        rasn_ldap::LdapString::from("cn"),
        vec![rasn::prelude::OctetString::from(vec![b'x'; 2048])].into(),
      )],
    );
    let bytes = rasn::ber::encode(&LdapMessage::new(1, ProtocolOp::SearchResEntry(entry))).unwrap();
    (bytes, 64)
  }

  fn decode_one(bytes: &[u8]) -> (LdapMessage, &[u8]) {
    let message: LdapMessage = rasn::ber::decode(bytes).unwrap();
    let encoded = rasn::ber::encode(&message).unwrap();
    (message, bytes.get(encoded.len()..).unwrap_or_default())
  }

  struct StallWrite<T> {
    inner: T,
    released: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stalled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    slot: std::sync::Arc<std::sync::Mutex<Option<std::task::Waker>>>,
  }

  impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for StallWrite<T> {
    fn poll_read(
      self: std::pin::Pin<&mut Self>,
      cx: &mut std::task::Context<'_>,
      buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
      std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
  }

  impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for StallWrite<T> {
    fn poll_write(
      self: std::pin::Pin<&mut Self>,
      cx: &mut std::task::Context<'_>,
      buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
      let this = self.get_mut();
      if !this.released.load(std::sync::atomic::Ordering::SeqCst) {
        this.stalled.store(true, std::sync::atomic::Ordering::SeqCst);
        *this.slot.lock().unwrap() = Some(cx.waker().clone());
        return std::task::Poll::Pending;
      }
      std::pin::Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
      std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
      std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
  }

  #[tokio::test]
  async fn abandon_lets_the_following_starttls_hand_off() {
    let (mut down, mut up) = pair();
    down.hold_starttls();
    let (guest_relay, mut guest) = tokio::io::duplex(4096);
    let (server_relay, _server) = tokio::io::duplex(4096);
    let relay = tokio::spawn(async move { relay_stop(guest_relay, server_relay, &mut down, &mut up, &[], &[]).await });
    let bind = LdapMessage::new(
      1,
      ProtocolOp::BindRequest(rasn_ldap::BindRequest::new(
        3,
        rasn_ldap::LdapString::from("cn=dir"),
        rasn_ldap::AuthenticationChoice::Simple(rasn::prelude::OctetString::from(FAKE_PW.as_bytes())),
      )),
    );
    let abandon = LdapMessage::new(2, ProtocolOp::AbandonRequest(rasn_ldap::AbandonRequest(1)));
    let mut bytes = rasn::ber::encode(&bind).unwrap();
    bytes.extend(rasn::ber::encode(&abandon).unwrap());
    bytes.extend(starttls(3));
    guest.write_all(&bytes).await.unwrap();
    let end = tokio::time::timeout(Duration::from_secs(1), relay)
      .await
      .expect("handoff after abandon")
      .unwrap()
      .unwrap();
    let RelayEnd::Upgrade(upgrade) = end else {
      panic!("upgrade");
    };
    assert!(upgrade.local);
    assert_eq!(upgrade.id, 3);
  }
}
