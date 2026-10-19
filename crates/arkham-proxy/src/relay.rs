//! Bidirectional pump through two wire directions.
//!
//! Each direction runs as its own pump future: a blocked guest-bound write
//! never stalls the reading of upstream bytes, and the other way around. The
//! request pump talks to the response pump over one FIFO channel (protocol
//! replies, framing facts, and the request direction's terminal intent —
//! ordering inside the channel replaces any select priority). Finished
//! response ids travel back on a second FIFO into [`Wire::apply_peer_note`].
//! The response pump ends the request pump through a oneshot.

use std::io::{Error as IoError, ErrorKind};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadHalf, WriteHalf, split};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::Error;
use crate::transports::engine::{Hit, Rewritten, UpgradeNote, Wire};

/// Guest-bound work and terminal intent, request pump → response pump.
/// FIFO order is the contract: replies and framing facts queued before a
/// terminal message are applied before it is honored.
enum ToResponse {
  /// Guest-bound protocol reply (Postgres negotiation refusals).
  Reply(Vec<u8>),
  /// Framing fact from the request machine (HEAD requests suppress bodies).
  PeerNote(usize),
  /// The request direction failed or failed closed: end the relay now.
  RequestsEnded,
  /// The next extended response with this id is the upgrade result.
  /// Sent before the upgrade request is written.
  ArmUpgrade(u64),
  /// The upgrade request was not forwarded. Stop without reading further.
  Handoff,
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

/// Request pump's ends of the two FIFOs.
struct RequestLinks {
  responses: mpsc::UnboundedSender<ToResponse>,
  settled: mpsc::UnboundedReceiver<usize>,
}

/// Response pump's ends of the two FIFOs.
struct ResponseLinks {
  requests: mpsc::UnboundedReceiver<ToResponse>,
  settled: mpsc::UnboundedSender<usize>,
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
  let (upgrade_tx, upgrade_rx) = oneshot::channel();
  let (settled_tx, settled_rx) = mpsc::unbounded_channel();
  let (requests, responses) = tokio::join!(
    pump_requests(
      guest_read,
      server_write,
      downstream,
      RequestLinks {
        responses: to_responses_tx,
        settled: settled_rx
      },
      responses_done_rx,
      upgrade_rx,
      first,
    ),
    pump_responses(
      server_read,
      guest_write,
      upstream,
      ResponseLinks {
        requests: to_responses_rx,
        settled: settled_tx
      },
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

fn end_requests(responses: &mpsc::UnboundedSender<ToResponse>) {
  let _ = responses.send(ToResponse::RequestsEnded);
}

async fn pump_requests<G, S, M>(
  mut guest: ReadHalf<G>,
  mut server: WriteHalf<S>,
  downstream: &mut M,
  mut links: RequestLinks,
  mut responses_done: oneshot::Receiver<()>,
  upgrade_rx: oneshot::Receiver<bool>,
  first: &[u8],
) -> Result<RequestEnd<G, S>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  if !first.is_empty() && !pump_first(&mut server, downstream, &links.responses, &mut responses_done, first).await? {
    return Ok(RequestEnd::Done);
  }
  let mut buf = vec![0u8; 32 * 1024];
  let mut settled_open = true;
  loop {
    tokio::select! {
      _ = &mut responses_done => return Ok(RequestEnd::Done),
      note = links.settled.recv(), if settled_open => match note {
        Some(id) => {
          downstream.apply_peer_note(id);
          hand_over(&links.responses, downstream);
        }
        None => settled_open = false,
      },
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
            hand_over(&links.responses, downstream);
            log_hits(&hits);
            if let Rewritten::Emit(flushed) = rewritten {
              write_or_stopped(
                &mut server,
                &flushed,
                &mut responses_done,
                |source| request_flush_error(&links.responses, source),
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
            let (rewritten, hits) = downstream.feed(&buf[..n]).await;
            hand_over(&links.responses, downstream);
            log_hits(&hits);
            if let Some(note) = downstream.take_upgrade() {
              return request_upgrade(guest, server, &links.responses, &mut responses_done, upgrade_rx, &rewritten, note).await;
            }
            match rewritten {
              Rewritten::Close => {
                end_requests(&links.responses);
                return Ok(RequestEnd::Done);
              }
              Rewritten::Hold => {}
              Rewritten::Emit(out) => {
                write_or_stopped(&mut server, &out, &mut responses_done, |source| {
                  request_chunk_error(&links.responses, source)
                })
                .await?;
              }
            }
          }
          Err(err) => {
            end_requests(&links.responses);
            return Err(Error::GuestRead { source: err });
          }
        }
      }
    }
  }
}

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

/// Stop reading the guest. A dropped `upgrade_rx` (close, read error, refusal) ends the relay.
async fn request_upgrade<G, S>(
  guest: ReadHalf<G>,
  mut server: WriteHalf<S>,
  responses: &mpsc::UnboundedSender<ToResponse>,
  responses_done: &mut oneshot::Receiver<()>,
  upgrade_rx: oneshot::Receiver<bool>,
  rewritten: &Rewritten<'_>,
  note: UpgradeNote,
) -> Result<RequestEnd<G, S>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let UpgradeNote::Request { id, prefix, local } = note else {
    end_requests(responses);
    return Ok(RequestEnd::Done);
  };
  let _ = responses.send(if local { ToResponse::Handoff } else { ToResponse::ArmUpgrade(id) });
  if let Rewritten::Emit(out) = rewritten {
    if write_or_stopped(&mut server, out, responses_done, |source| request_chunk_error(responses, source))
      .await?
      .is_none()
    {
      return Ok(RequestEnd::Done);
    }
    server.flush().await.map_err(|source| request_flush_error(responses, source))?;
  }
  // Reading the guest stops here. That lockstep is what the upgrade needs.
  if !local && !upgrade_rx.await.unwrap_or(false) {
    let _ = server.shutdown().await;
    return Ok(RequestEnd::Done);
  }
  Ok(RequestEnd::Upgrade {
    read: guest,
    write: server,
    prefix,
    id,
    local,
  })
}

async fn pump_responses<G, S, M>(
  mut server: ReadHalf<S>,
  mut guest: WriteHalf<G>,
  upstream: &mut M,
  mut links: ResponseLinks,
  responses_done: oneshot::Sender<()>,
  upgrade_tx: oneshot::Sender<bool>,
  upstream_first: &[u8],
) -> Result<ResponseEnd<G, S>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  let mut upgrade_tx = Some(upgrade_tx);
  let mut armed = false;
  if !upstream_first.is_empty() {
    let open = write_upstream_chunk(&mut guest, upstream, upstream_first).await?;
    publish_settled(upstream, &links.settled);
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
      msg = links.requests.recv(), if requests_open => match msg {
        Some(ToResponse::RequestsEnded) => break Ok(None),
        Some(ToResponse::Handoff) => break Ok(Some(Vec::new())),
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
          Ok(0) => break upstream_end(&mut guest, upstream, &mut links.requests, &mut armed, &links.settled).await,
          Ok(n) => match on_upstream_chunk(
            &mut guest,
            upstream,
            &mut links.requests,
            &mut armed,
            &mut upgrade_tx,
            &links.settled,
            &buf[..n],
          )
          .await?
          {
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
  if armed && let Some(tx) = upgrade_tx.take() {
    let _ = tx.send(false);
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
  settled: &mpsc::UnboundedSender<usize>,
) -> Result<Option<Vec<u8>>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  match drain_requests(guest, upstream, requests, armed).await? {
    ChunkStep::Stop => return Ok(None),
    ChunkStep::Upgrade(prefix) => return Ok(Some(prefix)),
    ChunkStep::Stay => {}
  }
  let (rewritten, hits) = upstream.feed(&[]).await;
  log_hits(&hits);
  publish_settled(upstream, settled);
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
  upgrade_tx: &mut Option<oneshot::Sender<bool>>,
  settled: &mpsc::UnboundedSender<usize>,
  chunk: &[u8],
) -> Result<ChunkStep, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  let drained = drain_requests(guest, upstream, requests, armed).await?;
  if matches!(drained, ChunkStep::Stop) {
    return Ok(ChunkStep::Stop);
  }
  let (rewritten, hits) = upstream.feed(chunk).await;
  log_hits(&hits);
  let step = if let ChunkStep::Upgrade(prefix) = drained {
    if let Rewritten::Emit(out) = &rewritten {
      write_guest_chunk(guest, out).await?;
    }
    ChunkStep::Upgrade(prefix)
  } else if let Some(note) = upstream.take_upgrade() {
    match response_upgrade(guest, &rewritten, upgrade_tx, note).await? {
      Some(prefix) => ChunkStep::Upgrade(prefix),
      None => ChunkStep::Stop,
    }
  } else {
    match rewritten {
      // A scan that cannot rewrite the chunk closes rather than forward it.
      Rewritten::Close => ChunkStep::Stop,
      Rewritten::Hold => ChunkStep::Stay,
      Rewritten::Emit(out) => {
        write_guest_chunk(guest, &out).await?;
        ChunkStep::Stay
      }
    }
  };
  // Response bytes are on the guest before the id drops out of the outstanding set.
  publish_settled(upstream, settled);
  Ok(step)
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
  upgrade_tx: &mut Option<oneshot::Sender<bool>>,
  note: UpgradeNote,
) -> Result<Option<Vec<u8>>, Error>
where
  W: AsyncWrite + Unpin,
{
  let UpgradeNote::Response { ok, prefix } = note else {
    if let Some(tx) = upgrade_tx.take() {
      let _ = tx.send(false);
    }
    return Ok(None);
  };
  if let Rewritten::Emit(out) = rewritten {
    write_guest_chunk(guest, out).await?;
  }
  if let Some(tx) = upgrade_tx.take() {
    let _ = tx.send(ok);
  }
  Ok(ok.then_some(prefix))
}

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
    ToResponse::PeerNote(n) => upstream.apply_peer_note(n),
    ToResponse::ArmUpgrade(id) => upstream.arm_upgrade(id),
    ToResponse::RequestsEnded | ToResponse::Handoff => {}
  }
  Ok(())
}

/// Apply queued request-pump notes. `Upgrade` is a handoff the caller still writes through.
async fn drain_requests<W, M>(
  guest: &mut W,
  upstream: &mut M,
  requests: &mut mpsc::UnboundedReceiver<ToResponse>,
  armed: &mut bool,
) -> Result<ChunkStep, Error>
where
  W: AsyncWrite + Unpin,
  M: Wire,
{
  while let Ok(msg) = requests.try_recv() {
    match msg {
      ToResponse::RequestsEnded => return Ok(ChunkStep::Stop),
      ToResponse::Handoff => return Ok(ChunkStep::Upgrade(Vec::new())),
      ToResponse::ArmUpgrade(id) => {
        *armed = true;
        upstream.arm_upgrade(id);
      }
      other => apply_message(guest, upstream, other).await?,
    }
  }
  Ok(ChunkStep::Stay)
}

fn publish_settled<M: Wire>(upstream: &mut M, settled: &mpsc::UnboundedSender<usize>) {
  let mut note = upstream.take_peer_note();
  while note != 0 {
    let _ = settled.send(note);
    note = upstream.take_peer_note();
  }
}

fn hand_over<M: Wire>(responses: &mpsc::UnboundedSender<ToResponse>, downstream: &mut M) {
  if let Some(reply) = downstream.take_reply() {
    let _ = responses.send(ToResponse::Reply(reply));
  }
  let pending = downstream.take_peer_note();
  if pending > 0 {
    let _ = responses.send(ToResponse::PeerNote(pending));
  }
}

/// `None` when the response direction ended mid-write. The connection is closing.
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

fn request_flush_error(responses: &mpsc::UnboundedSender<ToResponse>, source: IoError) -> Error {
  end_requests(responses);
  Error::RequestFlushToUpstream { source }
}

fn request_chunk_error(responses: &mpsc::UnboundedSender<ToResponse>, source: IoError) -> Error {
  end_requests(responses);
  Error::RequestChunkToUpstream { source }
}

fn request_head_error(responses: &mpsc::UnboundedSender<ToResponse>, source: IoError) -> Error {
  end_requests(responses);
  Error::RequestHeadToUpstream { source }
}

pub(crate) fn log_hits(hits: &[Hit]) {
  for hit in hits {
    tracing::debug!(label = %hit.label, location = ?hit.location, "substituted");
  }
}
