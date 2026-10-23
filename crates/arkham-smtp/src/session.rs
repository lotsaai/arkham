//! Cleartext SMTP opening, then the shared relay.

use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;

use arkham_wire::engine::{CredentialPair, Direction, Rewritten, Wire};
use arkham_wire::relay::{log_hits, relay_guarded};
use arkham_wire::tls::{TlsLegs, UpstreamTls, Verify, finish};

use crate::error::Error;
use crate::machine::{AuthMaterial, MAX_COMMAND, Smtp, is_opening_command, is_starttls};
use crate::scope::SmtpScope;

/// Guest socket, cleartext or terminated TLS.
pub enum GuestLeg<G> {
  /// Bytes still in the clear.
  Plain(G),
  /// TLS terminated with a leaf minted for the grant host.
  Tls(Box<ServerTlsStream<G>>),
}

/// Upstream socket, cleartext or TLS.
pub enum ServerLeg {
  /// Bytes still in the clear.
  Plain(TcpStream),
  /// TLS to the real server from the first byte.
  Tls(Box<ClientTlsStream<TcpStream>>),
  /// TLS after `STARTTLS`. Bytes past the acceptance line are read first.
  Upgraded(Box<ClientTlsStream<HeadThen<TcpStream>>>),
}

/// Socket reads that start with bytes already taken from that socket.
pub struct HeadThen<S> {
  head: Vec<u8>,
  at: usize,
  inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for HeadThen<S> {
  fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    if self.at < self.head.len() {
      let Some(remaining) = self.head.get(self.at..) else {
        return Poll::Ready(Err(std::io::Error::other("acceptance head")));
      };
      let n = remaining.len().min(buf.remaining());
      let Some(chunk) = remaining.get(..n) else {
        return Poll::Ready(Err(std::io::Error::other("acceptance head")));
      };
      buf.put_slice(chunk);
      self.at = self.at.saturating_add(n);
      if self.at >= self.head.len() {
        self.head.clear();
        self.head.shrink_to(0);
        self.at = 0;
      }
      return Poll::Ready(Ok(()));
    }
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HeadThen<S> {
  fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

impl<G> GuestLeg<G>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  fn is_plain(&self) -> bool {
    matches!(self, Self::Plain(_))
  }
}

impl<G> AsyncRead for GuestLeg<G>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
    }
  }
}

impl<G> AsyncWrite for GuestLeg<G>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
    }
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
    }
  }
}

impl ServerLeg {
  fn is_plain(&self) -> bool {
    matches!(self, Self::Plain(_))
  }
}

impl AsyncRead for ServerLeg {
  fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
      Self::Upgraded(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
    }
  }
}

impl AsyncWrite for ServerLeg {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
      Self::Upgraded(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
      Self::Upgraded(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
    }
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
      Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
      Self::Upgraded(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
    }
  }
}

/// One SMTP dialogue: both sockets, the grant that keys the swap, and
/// the handshake budget.
#[derive(Debug)]
pub struct Dialogue<'a, G> {
  /// Shared TLS legs. A mid-session `STARTTLS` handshake uses them.
  pub legs: &'a TlsLegs,
  /// Both legs of the matched rule.
  pub scope: &'a SmtpScope,
  /// Guest socket, cleartext or already terminated.
  pub guest: GuestLeg<G>,
  /// Upstream socket, cleartext or already encrypted.
  pub server: ServerLeg,
  /// AUTH bytes the downstream machine swaps.
  pub material: AuthMaterial,
  /// Upstream needles. The real password is the needle and the decoy is the replacement.
  pub pairs: Vec<CredentialPair>,
  /// Host the leaf is minted for.
  pub leaf: &'a str,
  /// Budget for a mid-stream TLS handshake.
  pub budget: Duration,
}

impl<G> std::fmt::Debug for GuestLeg<G> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Plain(_) => f.write_str("Plain"),
      Self::Tls(_) => f.write_str("Tls"),
    }
  }
}

impl std::fmt::Debug for ServerLeg {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Plain(_) => f.write_str("Plain"),
      Self::Tls(_) => f.write_str("Tls"),
      Self::Upgraded(_) => f.write_str("Upgraded"),
    }
  }
}

impl<S> std::fmt::Debug for HeadThen<S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("HeadThen")
      .field("head", &self.head.len())
      .field("at", &self.at)
      .field("inner", &std::any::type_name::<S>())
      .finish()
  }
}

/// Run the dialogue.
///
/// # Errors
///
/// Returns an error when a leg cannot be read, written, or upgraded.
/// A framing machine that closes, or a peer that hangs up, ends quietly.
pub async fn run<G>(dialogue: Dialogue<'_, G>) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let Dialogue {
    legs,
    scope,
    guest,
    server,
    material,
    pairs,
    leaf,
    budget,
  } = dialogue;
  let mut down = Smtp::new(Direction::Downstream, material.clone(), Vec::new());
  let mut up = Smtp::new(Direction::Upstream, material, pairs);
  Smtp::share_data_gate(&down, &mut up);
  if !guest.is_plain() {
    return relay_guarded(guest, server, &mut down, &mut up, &[], &[])
      .await
      .map_err(Error::Wire);
  }
  Opening {
    legs,
    scope,
    guest,
    server,
    down: &mut down,
    up: &mut up,
    leaf,
    budget,
  }
  .run()
  .await
}

/// Cleartext sockets plus the machines they hand to the relay.
struct Opening<'a, G> {
  legs: &'a TlsLegs,
  scope: &'a SmtpScope,
  guest: GuestLeg<G>,
  server: ServerLeg,
  down: &'a mut Smtp,
  up: &'a mut Smtp,
  leaf: &'a str,
  budget: Duration,
}

impl<G> Opening<'_, G>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  /// Greeting, then pre-transaction commands, until `STARTTLS` or a command
  /// the relay should own. `AUTH` stays here so a refusal before the upgrade
  /// can still be followed by `STARTTLS` on the same sockets.
  async fn run(mut self) -> Result<(), Error> {
    let mut lead = Vec::new();
    let greeting = acceptance_reply(&mut self.server, self.up, &mut self.guest, &lead).await?;
    if greeting.code.is_none() {
      return Ok(());
    }
    lead = greeting.rest;
    loop {
      let Some(line) = guest_line(&mut self.guest)
        .await
        .map_err(|source| Error::Wire(arkham_wire::Error::GuestRead { source }))?
      else {
        return Ok(());
      };
      if is_starttls(&line) {
        match self.forward_starttls(&line, &lead).await? {
          StarttlsStep::Continue(rest) => {
            lead = rest;
            continue;
          }
          StarttlsStep::Closed => return Ok(()),
          StarttlsStep::Upgrade(rest) => {
            let guest = upgrade_guest(self.legs, self.scope, self.guest, self.leaf, self.budget).await?;
            let server = upgrade_server(self.legs, self.scope, self.server, self.budget, rest).await?;
            return relay_guarded(guest, server, self.down, self.up, &[], &[])
              .await
              .map_err(Error::Wire);
          }
          StarttlsStep::Local => {
            self.down.queue_starttls_ready();
            if let Some(reply) = self.down.take_reply() {
              write_guest(&mut self.guest, &reply).await?;
            }
            let guest = upgrade_guest(self.legs, self.scope, self.guest, self.leaf, self.budget).await?;
            return relay_guarded(guest, self.server, self.down, self.up, &[], &lead)
              .await
              .map_err(Error::Wire);
          }
          StarttlsStep::Relay(rest) => {
            return relay_guarded(self.guest, self.server, self.down, self.up, &[], &rest)
              .await
              .map_err(Error::Wire);
          }
        }
      }
      if self.down.awaiting_auth_payload() || is_opening_command(&line) {
        match forward_down(self.down, &mut self.server, &line).await? {
          Forwarded::Stop => return Ok(()),
          Forwarded::Held => {
            return relay_guarded(self.guest, self.server, self.down, self.up, &[], &lead)
              .await
              .map_err(Error::Wire);
          }
          Forwarded::Sent => {}
        }
        let reply = acceptance_reply(&mut self.server, self.up, &mut self.guest, &lead).await?;
        if reply.code.is_none() {
          return Ok(());
        }
        lead = reply.rest;
        continue;
      }
      return relay_guarded(self.guest, self.server, self.down, self.up, &line, &lead)
        .await
        .map_err(Error::Wire);
    }
  }

  /// Forward `STARTTLS` when the upstream leg is still clear. A non-`220`
  /// reply leaves the opening loop in place so a later `STARTTLS` can
  /// upgrade. A `220`, or an upstream leg that is already TLS, ends the
  /// opening.
  async fn forward_starttls(&mut self, line: &[u8], lead: &[u8]) -> Result<StarttlsStep, Error> {
    if self.server.is_plain() {
      match forward_down(self.down, &mut self.server, line).await? {
        Forwarded::Stop => return Ok(StarttlsStep::Closed),
        Forwarded::Held => return Ok(StarttlsStep::Relay(lead.to_vec())),
        Forwarded::Sent => {}
      }
      let reply = acceptance_reply(&mut self.server, self.up, &mut self.guest, lead).await?;
      let Some(code) = reply.code else {
        return Ok(StarttlsStep::Closed);
      };
      if is_220(code) {
        Ok(StarttlsStep::Upgrade(reply.rest))
      } else {
        Ok(StarttlsStep::Continue(reply.rest))
      }
    } else if self.guest.is_plain() {
      Ok(StarttlsStep::Local)
    } else {
      Ok(StarttlsStep::Relay(lead.to_vec()))
    }
  }
}

/// What `STARTTLS` did to the opening loop. A carried suffix is the bytes
/// past the final newline, handed to the next server reader.
enum StarttlsStep {
  /// The server refused. The next guest command is still an opening command.
  Continue(Vec<u8>),
  /// The peer closed before the upgrade.
  Closed,
  /// Cleartext upstream accepted. Upgrade both legs, then relay.
  Upgrade(Vec<u8>),
  /// Upstream is already TLS. Answer locally and upgrade the guest.
  Local,
  /// Hand the sockets to the relay without an upgrade.
  Relay(Vec<u8>),
}

/// What one downstream feed did with a complete opening line.
enum Forwarded {
  /// The line was written upstream.
  Sent,
  /// The machine kept the line. The relay continues from there.
  Held,
  /// The machine closed the connection.
  Stop,
}

async fn forward_down(down: &mut Smtp, server: &mut ServerLeg, line: &[u8]) -> Result<Forwarded, Error> {
  let (rewritten, hits) = down.feed(line).await;
  log_hits(&hits);
  match rewritten {
    Rewritten::Close => Ok(Forwarded::Stop),
    Rewritten::Hold => Ok(Forwarded::Held),
    Rewritten::Emit(bytes) => {
      if !bytes.is_empty() {
        write_server(server, &bytes).await?;
      }
      Ok(Forwarded::Sent)
    }
  }
}

async fn upgrade_guest<G>(legs: &TlsLegs, scope: &SmtpScope, guest: GuestLeg<G>, leaf: &str, budget: Duration) -> Result<GuestLeg<G>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let plain = match guest {
    GuestLeg::Plain(stream) => stream,
    GuestLeg::Tls(_) => return Err(Error::LegAlreadyTls),
  };
  let mode = scope.guest_tls;
  let tls = finish(budget, legs.accept_guest(leaf, plain, mode, None))
    .await
    .map_err(Error::Wire)?;
  Ok(GuestLeg::Tls(Box::new(tls)))
}

async fn upgrade_server(legs: &TlsLegs, scope: &SmtpScope, server: ServerLeg, budget: Duration, rest: Vec<u8>) -> Result<ServerLeg, Error> {
  let plain = match server {
    ServerLeg::Plain(stream) => stream,
    ServerLeg::Tls(_) | ServerLeg::Upgraded(_) => return Err(Error::LegAlreadyTls),
  };
  let server_name = scope.upstream.host.as_str();
  let root = scope.root_cert.as_ref();
  let client_cert = scope.client_cert.as_deref();
  let client_key = scope.client_key.as_deref();
  let io = HeadThen {
    head: rest,
    at: 0,
    inner: plain,
  };
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
        io,
      )
      .await
  })
  .await
  .map_err(Error::Wire)?;
  Ok(ServerLeg::Upgraded(Box::new(tls)))
}

async fn write_guest<G>(guest: &mut GuestLeg<G>, bytes: &[u8]) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  guest
    .write_all(bytes)
    .await
    .map_err(|source| Error::Wire(arkham_wire::Error::ResponseChunkToGuest { source }))?;
  guest
    .flush()
    .await
    .map_err(|source| Error::Wire(arkham_wire::Error::ResponseChunkToGuest { source }))?;
  Ok(())
}

async fn write_server(server: &mut ServerLeg, bytes: &[u8]) -> Result<(), Error> {
  server
    .write_all(bytes)
    .await
    .map_err(|source| Error::Wire(arkham_wire::Error::RequestChunkToUpstream { source }))?;
  server
    .flush()
    .await
    .map_err(|source| Error::Wire(arkham_wire::Error::RequestChunkToUpstream { source }))?;
  Ok(())
}

/// One guest command, stopping at the newline so the following payload or
/// handshake stays unread. A line that reaches the AUTH cap is returned
/// as-is; the machine closes if it is still incomplete.
async fn guest_line<R>(reader: &mut R) -> Result<Option<Vec<u8>>, std::io::Error>
where
  R: AsyncRead + Unpin,
{
  let mut line = Vec::new();
  let mut byte = [0u8; 1];
  loop {
    match reader.read(&mut byte).await {
      Ok(0) => {
        if line.is_empty() {
          return Ok(None);
        }
        return Ok(Some(line));
      }
      Ok(_) => {
        let Some(next) = byte.first().copied() else {
          return Err(std::io::Error::other("empty read"));
        };
        line.push(next);
        if next == b'\n' || line.len() >= MAX_COMMAND {
          return Ok(Some(line));
        }
      }
      Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
        if line.is_empty() {
          return Ok(None);
        }
        return Ok(Some(line));
      }
      Err(err) => return Err(err),
    }
  }
}

/// Stack buffer for one reply read. A longer line continues in the next
/// read. Nothing from a previous read is kept here.
const REPLY_READ: usize = 8192;

/// One opening reply. `rest` is the bytes of this read that follow the
/// final newline. The caller gives them to the next server reader.
pub(crate) struct Acceptance {
  /// Final line status. `None` when the peer closed before a final line.
  pub(crate) code: Option<[u8; 3]>,
  /// Suffix after the final newline. Empty when the read ended on it.
  pub(crate) rest: Vec<u8>,
}

/// One SMTP reply, including a multiline (`250-` … `250 `) continuation.
/// Each read is fed to the upstream machine. What it emits is collected
/// into one buffer for that read and written before the next read.
/// `feed(&[])` runs on newline or EOF, so a password split across reads
/// stays inside the needle hold-back, and the guest is flushed there too.
/// The first four bytes decide whether the line is final. The line itself
/// is not kept. Bytes after the final newline are `Acceptance::rest`.
///
/// `lead` is a suffix returned by the previous call. It is scanned before
/// the next read and is not appended to later reads.
///
/// # Errors
///
/// Returns an error when the guest write fails or a read fails.
pub(crate) async fn acceptance_reply<R, G>(reader: &mut R, up: &mut Smtp, guest: &mut GuestLeg<G>, lead: &[u8]) -> Result<Acceptance, Error>
where
  R: AsyncRead + Unpin,
  G: AsyncRead + AsyncWrite + Unpin,
{
  let mut head = ReplyHead::default();
  let mut saw = !lead.is_empty();
  let mut buf = [0u8; REPLY_READ];
  // One chunk's emit. Cleared after the write, so the next read starts empty.
  // `Raw` is what keeps a needle prefix across reads.
  let mut emit = Vec::with_capacity(REPLY_READ);
  if !lead.is_empty()
    && let Some(rest) = finish_chunk(up, guest, &mut head, &mut emit, lead).await?
  {
    return Ok(Acceptance {
      code: Some(head.code),
      rest,
    });
  }
  loop {
    let n = match reader.read(&mut buf).await {
      Ok(n) => n,
      Err(err) if err.kind() == ErrorKind::UnexpectedEof => 0,
      Err(source) => return Err(Error::Wire(arkham_wire::Error::UpstreamRead { source })),
    };
    if n == 0 {
      if !saw {
        return Ok(Acceptance {
          code: None,
          rest: Vec::new(),
        });
      }
      append_fed(up, &mut emit, &[]).await?;
      write_emit(guest, &mut emit).await?;
      flush_guest(guest).await?;
      let code = head.is_final().then_some(head.code);
      return Ok(Acceptance { code, rest: Vec::new() });
    }
    saw = true;
    let bytes = chunk_bytes(&buf, n)?;
    if let Some(rest) = finish_chunk(up, guest, &mut head, &mut emit, bytes).await? {
      return Ok(Acceptance {
        code: Some(head.code),
        rest,
      });
    }
  }
}

fn chunk_bytes(buf: &[u8], n: usize) -> Result<&[u8], Error> {
  buf.get(..n).ok_or_else(|| {
    Error::Wire(arkham_wire::Error::UpstreamRead {
      source: std::io::Error::other("reply read past the chunk"),
    })
  })
}

/// Feed `bytes` through the final newline, write what that produced, and
/// return the suffix after that newline. `None` means the chunk has no
/// final newline yet.
async fn finish_chunk<G>(
  up: &mut Smtp,
  guest: &mut GuestLeg<G>,
  head: &mut ReplyHead,
  emit: &mut Vec<u8>,
  bytes: &[u8],
) -> Result<Option<Vec<u8>>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let mut start = 0usize;
  let mut i = 0usize;
  let mut saw_newline = false;
  while i < bytes.len() {
    let Some(&byte) = bytes.get(i) else {
      return Err(Error::Wire(arkham_wire::Error::UpstreamRead {
        source: std::io::Error::other("reply read past the chunk"),
      }));
    };
    i = i.saturating_add(1);
    if byte != b'\n' {
      head.observe(byte);
      continue;
    }
    saw_newline = true;
    let Some(line) = bytes.get(start..i) else {
      return Err(Error::Wire(arkham_wire::Error::UpstreamRead {
        source: std::io::Error::other("reply read past the chunk"),
      }));
    };
    append_fed(up, emit, line).await?;
    append_fed(up, emit, &[]).await?;
    // A bare `\n` leaves `at` at 0. That line is still final.
    let final_line = head.at == 0 || head.is_final();
    if final_line {
      write_emit(guest, emit).await?;
      flush_guest(guest).await?;
      return Ok(Some(bytes.get(i..).unwrap_or(&[]).to_vec()));
    }
    *head = ReplyHead::default();
    start = i;
  }
  if let Some(tail) = bytes.get(start..)
    && !tail.is_empty()
  {
    append_fed(up, emit, tail).await?;
  }
  write_emit(guest, emit).await?;
  if saw_newline {
    flush_guest(guest).await?;
  }
  Ok(None)
}

/// Status and separator of the reply line being read. Four bytes decide
/// the line. Nothing here retains the text.
#[derive(Default)]
struct ReplyHead {
  /// `0..3` collect the status code. `3` is the separator. `4` is the rest.
  at: u8,
  code: [u8; 3],
  /// The separator was `-`, so another line follows.
  continues: bool,
}

impl ReplyHead {
  fn observe(&mut self, byte: u8) {
    if self.at >= 4 {
      return;
    }
    if self.at < 3 {
      if let Some(slot) = self.code.get_mut(usize::from(self.at)) {
        *slot = byte;
      }
    } else {
      self.continues = byte == b'-';
    }
    self.at = self.at.saturating_add(1);
  }

  /// Newline or EOF ended a line that is not a continuation.
  fn is_final(&self) -> bool {
    self.at > 0 && !self.continues
  }
}

/// Append what one feed emits. An empty chunk flushes the hold-back. The
/// caller does that on newline or EOF, then writes `emit` once.
async fn append_fed(up: &mut Smtp, emit: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
  let (rewritten, hits) = up.feed(bytes).await;
  log_hits(&hits);
  match rewritten {
    Rewritten::Emit(part) if !part.is_empty() => {
      emit.extend_from_slice(&part);
      Ok(())
    }
    Rewritten::Emit(_) | Rewritten::Hold | Rewritten::Close => Ok(()),
  }
}

/// One guest write for the chunk just fed. `emit` is empty afterwards.
async fn write_emit<G>(guest: &mut GuestLeg<G>, emit: &mut Vec<u8>) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  if emit.is_empty() {
    return Ok(());
  }
  write_guest_bytes(guest, emit).await?;
  emit.clear();
  emit.shrink_to(REPLY_READ);
  Ok(())
}

/// Write without flushing. The caller flushes on newline or EOF.
async fn write_guest_bytes<G>(guest: &mut GuestLeg<G>, bytes: &[u8]) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  guest
    .write_all(bytes)
    .await
    .map_err(|source| Error::Wire(arkham_wire::Error::ResponseChunkToGuest { source }))
}

async fn flush_guest<G>(guest: &mut GuestLeg<G>) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  guest
    .flush()
    .await
    .map_err(|source| Error::Wire(arkham_wire::Error::ResponseChunkToGuest { source }))
}

fn is_220(code: [u8; 3]) -> bool {
  code == *b"220"
}

/// Cleartext guest leg.
#[must_use]
pub fn plain_guest<G>(stream: G) -> GuestLeg<G> {
  GuestLeg::Plain(stream)
}

/// Guest leg whose TLS is already terminated.
#[must_use]
pub fn tls_guest<G>(stream: ServerTlsStream<G>) -> GuestLeg<G> {
  GuestLeg::Tls(Box::new(stream))
}

/// Cleartext upstream leg.
#[must_use]
pub fn plain_server(stream: TcpStream) -> ServerLeg {
  ServerLeg::Plain(stream)
}

/// Upstream leg whose TLS handshake already finished.
#[must_use]
pub fn tls_server(stream: ClientTlsStream<TcpStream>) -> ServerLeg {
  ServerLeg::Tls(Box::new(stream))
}

#[cfg(test)]
mod tests {
  use std::pin::Pin;
  use std::sync::{Arc, Mutex, PoisonError};
  use std::task::{Context, Poll};

  use secrecy::SecretString;
  use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

  use arkham_wire::GuestTlsMode;
  use arkham_wire::engine::CredentialPair;

  use super::{Direction, Smtp, Wire};
  use crate::AuthMaterial;
  use crate::scope::{SmtpLeg, SmtpScope};

  #[derive(Default)]
  struct WriteLog {
    buf: Vec<u8>,
    writes: Vec<usize>,
  }

  impl AsyncRead for WriteLog {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
      Poll::Ready(Ok(()))
    }
  }

  impl AsyncWrite for WriteLog {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
      self.writes.push(buf.len());
      self.buf.extend_from_slice(buf);
      Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
      Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
      Poll::Ready(Ok(()))
    }
  }

  #[derive(Clone, Default)]
  struct SharedLog {
    buf: Arc<Mutex<Vec<u8>>>,
    writes: Arc<Mutex<Vec<usize>>>,
    flushes: Arc<Mutex<u32>>,
  }

  impl AsyncRead for SharedLog {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
      Poll::Ready(Ok(()))
    }
  }

  impl AsyncWrite for SharedLog {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
      self.buf.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(buf);
      self.writes.lock().unwrap_or_else(PoisonError::into_inner).push(buf.len());
      Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
      *self.flushes.lock().unwrap_or_else(PoisonError::into_inner) += 1;
      Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
      Poll::Ready(Ok(()))
    }
  }

  /// Yields `data`, then stays pending. It never reports EOF.
  struct PendAfter {
    data: Vec<u8>,
    at: usize,
  }

  impl AsyncRead for PendAfter {
    fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
      let Some(rest) = self.data.get(self.at..) else {
        return Poll::Pending;
      };
      let n = rest.len().min(buf.remaining());
      if n == 0 {
        return Poll::Pending;
      }
      let Some(chunk) = rest.get(..n) else {
        return Poll::Pending;
      };
      buf.put_slice(chunk);
      self.at = self.at.saturating_add(n);
      Poll::Ready(Ok(()))
    }
  }

  /// Yields `first`, parks once, then yields `second` and EOF.
  struct PauseReader {
    first: Vec<u8>,
    second: Vec<u8>,
    at: usize,
    stage: u8,
  }

  impl AsyncRead for PauseReader {
    fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
      if self.stage == 0 {
        let Some(rest) = self.first.get(self.at..) else {
          self.stage = 1;
          self.at = 0;
          return Poll::Pending;
        };
        let n = rest.len().min(buf.remaining());
        if n == 0 {
          self.stage = 1;
          self.at = 0;
          return Poll::Pending;
        }
        let Some(chunk) = rest.get(..n) else {
          return Poll::Pending;
        };
        buf.put_slice(chunk);
        self.at = self.at.saturating_add(n);
        return Poll::Ready(Ok(()));
      }
      let Some(rest) = self.second.get(self.at..) else {
        return Poll::Ready(Ok(()));
      };
      let n = rest.len().min(buf.remaining());
      if n == 0 {
        return Poll::Ready(Ok(()));
      }
      let Some(chunk) = rest.get(..n) else {
        return Poll::Ready(Ok(()));
      };
      buf.put_slice(chunk);
      self.at = self.at.saturating_add(n);
      Poll::Ready(Ok(()))
    }
  }

  fn drive<F>(fut: F) -> F::Output
  where
    F: Future,
  {
    let mut fut = std::pin::pin!(fut);
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    for _ in 0..8 {
      match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => return out,
        Poll::Pending => {}
      }
    }
    panic!("acceptance_reply stayed pending");
  }

  const FAKE_PASS: &str = "fake-smtp-pass"; // betterleaks:allow
  const REAL_PASS: &str = "real-smtp-pass"; // betterleaks:allow

  /// Feed one complete reply and flush the hold-back, the way a newline does.
  async fn redact_reply(up: &mut Smtp, reply: &[u8]) -> Vec<u8> {
    let (rewritten, _) = up.feed(reply).await;
    let mut out = match rewritten {
      super::Rewritten::Emit(bytes) => bytes.into_owned(),
      super::Rewritten::Hold | super::Rewritten::Close => Vec::new(),
    };
    let (flushed, _) = up.feed(&[]).await;
    if let super::Rewritten::Emit(bytes) = flushed {
      out.extend(bytes.into_owned());
    }
    out
  }

  fn upstream_with(real: &str) -> Smtp {
    let scope = SmtpScope {
      downstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: "agent@demo.test".into(),
        password: SecretString::from(FAKE_PASS),
      },
      is_downstream_tls: false,
      upstream: SmtpLeg {
        host: "mail".into(),
        port: 587,
        user: "agent@demo.test".into(),
        password: SecretString::from(real),
      },
      is_upstream_tls: true,
      starttls_required: false,
      root_cert: None,
      client_cert: None,
      client_key: None,
      guest_tls: GuestTlsMode::default(),
    };
    let material = AuthMaterial::from_scope(&scope, "smtp");
    let pairs = vec![CredentialPair {
      needle: real.as_bytes().to_vec(),
      replacement: FAKE_PASS.as_bytes().to_vec(),
      label: "smtp".into(),
    }];
    Smtp::new(Direction::Upstream, material, pairs)
  }

  fn upstream() -> Smtp {
    upstream_with(REAL_PASS)
  }

  /// The opening writes the machine's output, so a reply that echoes the
  /// real password reaches the guest as the decoy.
  #[tokio::test]
  async fn opening_reply_redacts_the_real_password() {
    let mut up = upstream();
    let reply = format!("535 5.7.8 authentication failed for {REAL_PASS}\r\n");
    let out = redact_reply(&mut up, reply.as_bytes()).await;
    assert_eq!(out, format!("535 5.7.8 authentication failed for {FAKE_PASS}\r\n").into_bytes());
    assert!(!out.windows(REAL_PASS.len()).any(|window| window == REAL_PASS.as_bytes()));
  }

  /// The handshake record is the suffix after the final line.
  #[tokio::test]
  async fn acceptance_line_leaves_the_handshake_bytes() {
    let banner = b"220-wait\r\n220 2.0.0 Ready to start TLS\r\n";
    let mut payload = banner.to_vec();
    payload.extend_from_slice(&[0x16, 0x03, 0x01]);
    let payload_len = payload.len();
    let mut cursor = std::io::Cursor::new(payload);
    let mut guest = super::plain_guest(std::io::Cursor::new(Vec::new()));
    let mut up = upstream();
    let done = super::acceptance_reply(&mut cursor, &mut up, &mut guest, &[]).await.unwrap();
    let reply = done.code.unwrap();
    assert_eq!(reply, *b"220");
    assert!(super::is_220(reply));
    assert_eq!(done.rest, [0x16, 0x03, 0x01]);
    let super::GuestLeg::Plain(writer) = guest else {
      unreachable!("the guest leg is the cursor");
    };
    assert_eq!(writer.into_inner(), banner);
    let at = usize::try_from(cursor.position()).unwrap();
    assert_eq!(at, payload_len, "the chunk includes the bytes after the final line");
  }

  /// A bare newline is a final line. The handshake that follows it is the suffix.
  #[tokio::test]
  async fn bare_newline_is_final_and_leaves_the_handshake() {
    let mut payload = vec![b'\n'];
    payload.extend_from_slice(&[0x16, 0x03, 0x01]);
    let mut cursor = std::io::Cursor::new(payload);
    let mut guest = super::plain_guest(WriteLog::default());
    let mut up = upstream();
    let done = super::acceptance_reply(&mut cursor, &mut up, &mut guest, &[]).await.unwrap();
    let reply = done.code.unwrap();
    assert!(!super::is_220(reply));
    assert_eq!(done.rest, [0x16, 0x03, 0x01]);
    let super::GuestLeg::Plain(log) = guest else {
      unreachable!("the guest leg is the write log");
    };
    assert_eq!(log.buf, b"\n");
  }

  /// Bytes already read reach the guest while the line is still open.
  /// The reader then pends and never sends EOF, so a per-line buffer
  /// would still be holding them.
  #[tokio::test]
  async fn long_line_reaches_the_guest_before_it_ends() {
    let data = vec![b'q'; 20_000];
    let mut reader = PendAfter { data: data.clone(), at: 0 };
    let log = SharedLog::default();
    let buf = Arc::clone(&log.buf);
    let writes = Arc::clone(&log.writes);
    let flushes = Arc::clone(&log.flushes);
    let mut guest = super::plain_guest(log);
    let mut up = upstream();
    let mut task = std::pin::pin!(super::acceptance_reply(&mut reader, &mut up, &mut guest, &[]));
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(
      matches!(task.as_mut().poll(&mut cx), Poll::Pending),
      "the line has no newline and the reader has not closed"
    );
    let got = buf.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert_eq!(got, data, "guest holds {} bytes while the line is still open", got.len());
    let writes = writes.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert!(writes.len() > 1, "one write would be the whole line: {writes:?}");
    assert!(
      writes.iter().all(|len| *len <= super::REPLY_READ),
      "a write grew past one read: {writes:?}"
    );
    assert_eq!(writes.iter().sum::<usize>(), data.len());
    assert_eq!(*flushes.lock().unwrap_or_else(PoisonError::into_inner), 0);
  }

  /// The data and the following EOF are two reads, so the hold-back flush
  /// is the EOF read's write. The guest still receives every byte.
  #[tokio::test]
  async fn eof_holdback_is_the_eof_reads_write() {
    let line = format!("535 {REAL_PASS}");
    let cut = line.len() - 4;
    let bytes = line.as_bytes().get(..cut).unwrap().to_vec();
    let mut cursor = std::io::Cursor::new(bytes.clone());
    let mut guest = super::plain_guest(WriteLog::default());
    let mut up = upstream();
    let reply = super::acceptance_reply(&mut cursor, &mut up, &mut guest, &[])
      .await
      .unwrap()
      .code
      .unwrap();
    assert_eq!(reply, *b"535");
    let super::GuestLeg::Plain(log) = guest else {
      unreachable!("the guest leg is the write log");
    };
    assert_eq!(log.writes.len(), 2, "{:?}", log.writes);
    assert_eq!(log.writes.iter().sum::<usize>(), bytes.len());
    assert_eq!(log.buf, bytes);
  }

  /// A needle prefix still in the hold-back is written when the peer
  /// closes. Dropping it would shorten the reply.
  #[tokio::test]
  async fn held_prefix_is_flushed_at_eof() {
    let line = format!("535 {REAL_PASS}");
    let cut = line.len() - 4;
    let first = line.as_bytes().get(..cut).unwrap().to_vec();
    let mut reader = PauseReader {
      first: first.clone(),
      second: Vec::new(),
      at: 0,
      stage: 0,
    };
    let mut guest = super::plain_guest(WriteLog::default());
    let mut up = upstream();
    let reply = drive(super::acceptance_reply(&mut reader, &mut up, &mut guest, &[]))
      .unwrap()
      .code
      .unwrap();
    assert_eq!(reply, *b"535");
    let super::GuestLeg::Plain(log) = guest else {
      unreachable!("the guest leg is the write log");
    };
    assert_eq!(log.buf, first);
    assert!(!log.buf.windows(REAL_PASS.len()).any(|window| window == REAL_PASS.as_bytes()));
  }

  /// A password split across two reads, then `\r\n`, is still the decoy.
  #[tokio::test]
  async fn held_prefix_then_crlf_redacts_the_password() {
    let line = format!("535 {REAL_PASS}\r\n");
    let pass_at = line.find(REAL_PASS).unwrap();
    let cut = pass_at + 4;
    let mut reader = PauseReader {
      first: line.as_bytes().get(..cut).unwrap().to_vec(),
      second: line.as_bytes().get(cut..).unwrap().to_vec(),
      at: 0,
      stage: 0,
    };
    let mut guest = super::plain_guest(WriteLog::default());
    let mut up = upstream();
    let reply = drive(super::acceptance_reply(&mut reader, &mut up, &mut guest, &[]))
      .unwrap()
      .code
      .unwrap();
    assert_eq!(reply, *b"535");
    let super::GuestLeg::Plain(log) = guest else {
      unreachable!("the guest leg is the write log");
    };
    let text = String::from_utf8(log.buf).unwrap();
    assert!(text.contains(FAKE_PASS), "{text}");
    assert!(!text.contains(REAL_PASS), "{text}");
    assert!(text.ends_with("\r\n"), "{text}");
  }

  /// A password split across two reads, with no newline, is still the decoy.
  /// EOF flushes the hold-back.
  #[tokio::test]
  async fn password_split_across_reads_redacts_without_a_newline() {
    let line = format!("535 {REAL_PASS}");
    let pass_at = line.find(REAL_PASS).unwrap();
    let cut = pass_at + 4;
    let mut reader = PauseReader {
      first: line.as_bytes().get(..cut).unwrap().to_vec(),
      second: line.as_bytes().get(cut..).unwrap().to_vec(),
      at: 0,
      stage: 0,
    };
    let mut guest = super::plain_guest(WriteLog::default());
    let mut up = upstream();
    let reply = drive(super::acceptance_reply(&mut reader, &mut up, &mut guest, &[]))
      .unwrap()
      .code
      .unwrap();
    assert_eq!(reply, *b"535");
    let super::GuestLeg::Plain(log) = guest else {
      unreachable!("the guest leg is the write log");
    };
    let text = String::from_utf8(log.buf).unwrap();
    assert!(text.contains(FAKE_PASS), "{text}");
    assert!(!text.contains(REAL_PASS), "{text}");
    assert_eq!(log.writes.len(), 2, "{:?}", log.writes);
  }

  /// Each read chunk is one guest write. A line longer than the read is
  /// several writes. A write per byte fills the capture path's outbound
  /// queue before `STARTTLS` can handshake.
  #[tokio::test]
  async fn reply_lines_are_one_guest_write() {
    let banner = b"220-wait\r\n220 2.0.0 Ready to start TLS\r\n";
    let mut cursor = std::io::Cursor::new(banner.to_vec());
    let mut guest = super::plain_guest(WriteLog::default());
    let mut up = upstream();
    let reply = super::acceptance_reply(&mut cursor, &mut up, &mut guest, &[])
      .await
      .unwrap()
      .code
      .unwrap();
    assert_eq!(reply, *b"220");
    let super::GuestLeg::Plain(log) = guest else {
      unreachable!("the guest leg is the write log");
    };
    // One `read` returns both lines. One guest write covers that chunk.
    assert_eq!(log.writes, vec![banner.len()]);
    assert_eq!(log.buf, banner);

    let mut line = vec![b'q'; super::REPLY_READ + 50];
    line.extend_from_slice(b"\r\n");
    let reply_len = line.len();
    let mut payload = line;
    payload.extend_from_slice(&[0x16, 0x03, 0x01]);
    let mut cursor = std::io::Cursor::new(payload);
    let mut guest = super::plain_guest(WriteLog::default());
    let mut up = upstream();
    let done = super::acceptance_reply(&mut cursor, &mut up, &mut guest, &[]).await.unwrap();
    let code = done.code.unwrap();
    assert_eq!(code, *b"qqq");
    assert_eq!(done.rest, [0x16, 0x03, 0x01]);
    let super::GuestLeg::Plain(log) = guest else {
      unreachable!("the guest leg is the write log");
    };
    assert_eq!(log.writes, vec![super::REPLY_READ, 50 + 2]);
    assert!(log.writes.iter().all(|len| *len <= super::REPLY_READ));
    let at = usize::try_from(cursor.position()).unwrap();
    assert_eq!(at, reply_len.saturating_add(3));
  }

  /// A reply that echoes a real password longer than the decoy is written
  /// with the decoy. The status code stays the server's.
  #[tokio::test]
  async fn opening_reply_redacts_a_longer_real_password() {
    const LONG_REAL: &str = "real-smtp-pass-extended"; // betterleaks:allow
    let mut up = upstream_with(LONG_REAL);
    let reply = format!("535 5.7.8 authentication failed for {LONG_REAL}\r\n");
    let out = redact_reply(&mut up, reply.as_bytes()).await;
    let text = String::from_utf8(out).unwrap();
    assert!(text.starts_with("535 "), "{text}");
    assert!(text.contains(FAKE_PASS), "{text}");
    assert!(!text.contains(LONG_REAL), "{text}");
  }

  /// A reply longer than one command redacts the password. The handshake
  /// is the suffix after the newline.
  #[tokio::test]
  async fn long_reply_redacts_the_password() {
    const LONG_REAL: &str = "real-smtp-pass-extended"; // betterleaks:allow
    let pass = LONG_REAL.as_bytes();
    let start = super::MAX_COMMAND.saturating_sub(4);
    let lead = b"535 ";
    assert!(start > lead.len());
    let mut line = Vec::new();
    line.extend_from_slice(lead);
    line.resize(start, b'x');
    line.extend_from_slice(pass);
    line.extend_from_slice(b"\r\n");
    let reply_len = line.len();
    let mut payload = line;
    payload.extend_from_slice(&[0x16, 0x03, 0x01]);
    let mut cursor = std::io::Cursor::new(payload);
    let mut guest = super::plain_guest(std::io::Cursor::new(Vec::new()));
    let mut up = upstream_with(LONG_REAL);
    let done = super::acceptance_reply(&mut cursor, &mut up, &mut guest, &[]).await.unwrap();
    let code = done.code.unwrap();
    assert_eq!(code, *b"535");
    assert_eq!(done.rest, [0x16, 0x03, 0x01]);
    let super::GuestLeg::Plain(writer) = guest else {
      unreachable!("the guest leg is the cursor");
    };
    let text = String::from_utf8(writer.into_inner()).unwrap();
    assert!(text.starts_with("535 "), "{text}");
    assert!(text.contains(FAKE_PASS), "{text}");
    assert!(!text.contains(LONG_REAL), "{text}");
    let at = usize::try_from(cursor.position()).unwrap();
    assert_eq!(at, reply_len.saturating_add(3));
  }
}
