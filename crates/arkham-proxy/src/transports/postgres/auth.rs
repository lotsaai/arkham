use std::time::Duration;

use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use pgwire::api::auth::Password;
use pgwire::api::auth::sasl::SCRAM_SHA_256_METHOD;
use pgwire::api::auth::sasl::scram::{SCRAM_ITERATIONS, ScramClientAuth, ScramServerAuth, gen_salted_password, random_nonce};
use pgwire::messages::response::ErrorResponse;
use pgwire::messages::startup::{Authentication, PasswordMessageFamily, SASLInitialResponse, SASLResponse};
use pgwire::messages::{DecodeContext, PgWireBackendMessage, PgWireFrontendMessage};
use secrecy::ExposeSecret as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::machine::{MAX_GREETING, Postgres};
use crate::Error;
use crate::transports::PairCtx;
use crate::transports::engine::{Rewritten, Wire as _};

/// Outcome of the authentication prelude.
pub(super) enum Prelude {
  /// The guest was refused, or the peer closed.
  Close,
  /// Server bytes still owed to the guest.
  Relay(Vec<u8>),
}

/// Finish authentication before the byte relay.
///
/// # Errors
///
/// Returns an error when a frame exceeds the greeting cap, a read times out,
/// or a SCRAM message cannot be built or checked.
pub(super) async fn settle<G, S>(
  guest: &mut G,
  server: &mut S,
  downstream: &mut Postgres,
  ctx: &PairCtx<'_>,
  budget: Duration,
) -> Result<Prelude, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let Some(startup) = forward_startup(guest, server, downstream, budget).await? else {
    return Ok(Prelude::Close);
  };
  let mut server_frames = Frames::new(server, budget, DecodeContext::default());
  loop {
    if server_frames.buf.len() > MAX_GREETING {
      return Err(scram_err(short("postgres authentication message exceeds the greeting cap")));
    }
    let snapshot = server_frames.buf.to_vec();
    match PgWireBackendMessage::decode(&mut server_frames.buf, &server_frames.ctx).map_err(scram_err)? {
      Some(PgWireBackendMessage::Authentication(Authentication::SASL(mechanisms))) => {
        if !mechanisms.iter().any(|mechanism| mechanism == SCRAM_SHA_256_METHOD) {
          return Ok(Prelude::Relay(snapshot));
        }
        let Some((fake, real)) = leg_passwords(ctx) else {
          return Ok(Prelude::Relay(snapshot));
        };
        let Some(user) = scram_user(&startup, ctx) else {
          return Ok(Prelude::Relay(snapshot));
        };
        return run_scram(guest, &mut server_frames, budget, &user, &fake, &real).await;
      }
      Some(_) => return Ok(Prelude::Relay(snapshot)),
      None => {
        if !server_frames.pull().await? {
          return Ok(Prelude::Close);
        }
      }
    }
  }
}

async fn forward_startup<G, S>(guest: &mut G, server: &mut S, downstream: &mut Postgres, budget: Duration) -> Result<Option<Vec<u8>>, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let mut buf = BytesMut::new();
  loop {
    if buf.len() > MAX_GREETING {
      return Ok(None);
    }
    if !pull(guest, &mut buf, budget).await? {
      return Ok(None);
    }
    let (rewritten, _) = downstream.feed(&buf).await;
    let emitted = match rewritten {
      Rewritten::Emit(bytes) => Some(bytes.into_owned()),
      Rewritten::Close => return Ok(None),
      Rewritten::Hold => None,
    };
    if let Some(reply) = downstream.take_reply() {
      guest.write_all(&reply).await?;
      guest.flush().await?;
    }
    buf.clear();
    if let Some(bytes) = emitted {
      server.write_all(&bytes).await?;
      server.flush().await?;
      return Ok(Some(bytes));
    }
  }
}

async fn run_scram<G, S>(
  guest: &mut G,
  server: &mut Frames<&mut S>,
  budget: Duration,
  user: &str,
  fake: &str,
  real: &str,
) -> Result<Prelude, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  let decoy_verifier = match prove_guest(guest, budget, fake).await? {
    GuestProof::Refused => return Ok(Prelude::Close),
    GuestProof::Proved(verifier) => verifier,
  };
  let Some(tail) = prove_upstream(server, user, real).await? else {
    write_backend(guest, &auth_failed()).await?;
    return Ok(Prelude::Close);
  };
  write_backend(
    guest,
    &PgWireBackendMessage::Authentication(Authentication::SASLFinal(Bytes::from(decoy_verifier))),
  )
  .await?;
  write_backend(guest, &PgWireBackendMessage::Authentication(Authentication::Ok)).await?;
  Ok(Prelude::Relay(tail))
}

enum GuestProof {
  Proved(String),
  Refused,
}

async fn prove_guest<G>(guest: &mut G, budget: Duration, fake: &str) -> Result<GuestProof, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let mut guest_frames = Frames::new(guest, budget, password_ctx());
  guest_frames
    .send_backend(&PgWireBackendMessage::Authentication(Authentication::SASL(vec![
      SCRAM_SHA_256_METHOD.to_owned(),
    ])))
    .await?;
  let Some(message) = guest_frames.next_frontend().await? else {
    return Ok(GuestProof::Refused);
  };
  let PgWireFrontendMessage::PasswordMessageFamily(family) = message else {
    guest_frames.send_backend(&auth_failed()).await?;
    return Ok(GuestProof::Refused);
  };
  let Ok(initial) = family.into_sasl_initial_response() else {
    guest_frames.send_backend(&auth_failed()).await?;
    return Ok(GuestProof::Refused);
  };
  if initial.auth_method != SCRAM_SHA_256_METHOD {
    guest_frames.send_backend(&auth_failed()).await?;
    return Ok(GuestProof::Refused);
  }
  let Some(client_first) = initial.data else {
    guest_frames.send_backend(&auth_failed()).await?;
    return Ok(GuestProof::Refused);
  };
  let salt = base64::engine::general_purpose::STANDARD
    .decode(random_nonce())
    .map_err(scram_err)?;
  let salted = gen_salted_password(fake, &salt, SCRAM_ITERATIONS);
  let (server_first, waiting) = ScramServerAuth::new()
    .on_client_first_message(&client_first, Password::new(Some(salt), salted))
    .map_err(scram_err)?;
  guest_frames
    .send_backend(&PgWireBackendMessage::Authentication(Authentication::SASLContinue(Bytes::from(
      server_first,
    ))))
    .await?;
  let Some(message) = guest_frames.next_frontend().await? else {
    return Ok(GuestProof::Refused);
  };
  let PgWireFrontendMessage::PasswordMessageFamily(family) = message else {
    guest_frames.send_backend(&auth_failed()).await?;
    return Ok(GuestProof::Refused);
  };
  let Ok(response) = family.into_sasl_response() else {
    guest_frames.send_backend(&auth_failed()).await?;
    return Ok(GuestProof::Refused);
  };
  if let Ok(server_final) = waiting.on_client_final_message(&response.data) {
    Ok(GuestProof::Proved(server_final))
  } else {
    guest_frames.send_backend(&auth_failed()).await?;
    Ok(GuestProof::Refused)
  }
}

async fn prove_upstream<S>(server: &mut Frames<&mut S>, user: &str, real: &str) -> Result<Option<Vec<u8>>, Error>
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let client = ScramClientAuth::new(user.to_owned(), real.to_owned());
  let (client_first, waiting_server) = client.build_client_first().map_err(scram_err)?;
  server
    .send_frontend(&PgWireFrontendMessage::PasswordMessageFamily(
      PasswordMessageFamily::SASLInitialResponse(SASLInitialResponse::new(
        SCRAM_SHA_256_METHOD.to_owned(),
        Some(Bytes::from(client_first)),
      )),
    ))
    .await?;
  let Some(PgWireBackendMessage::Authentication(Authentication::SASLContinue(continue_data))) = server.next_backend().await? else {
    return Ok(None);
  };
  let (client_final, waiting_final) = waiting_server.build_client_final(&continue_data).map_err(scram_err)?;
  server
    .send_frontend(&PgWireFrontendMessage::PasswordMessageFamily(PasswordMessageFamily::SASLResponse(
      SASLResponse::new(Bytes::from(client_final)),
    )))
    .await?;
  let mut saw_final = false;
  let mut tail = Vec::new();
  loop {
    match server.next_backend().await? {
      Some(PgWireBackendMessage::Authentication(Authentication::SASLFinal(data))) => {
        waiting_final.verify_server_final(&data).map_err(scram_err)?;
        saw_final = true;
      }
      Some(PgWireBackendMessage::Authentication(
        Authentication::Ok
        | Authentication::CleartextPassword
        | Authentication::KerberosV5
        | Authentication::MD5Password(_)
        | Authentication::SASL(_)
        | Authentication::SASLContinue(_),
      )) => {}
      Some(PgWireBackendMessage::Authentication(_)) => {
        return Err(scram_err(short("postgres authentication message is not scram")));
      }
      Some(PgWireBackendMessage::ErrorResponse(_)) | None => return Ok(None),
      Some(PgWireBackendMessage::ReadyForQuery(message)) => {
        tail.extend(encode_backend(&PgWireBackendMessage::ReadyForQuery(message))?);
        tail.extend_from_slice(&server.buf);
        break;
      }
      Some(message) => tail.extend(encode_backend(&message)?),
    }
  }
  Ok(saw_final.then_some(tail))
}

fn scram_user(startup: &[u8], ctx: &PairCtx<'_>) -> Option<String> {
  let parsed = startup_user(startup).filter(|user| !user.is_empty());
  if parsed.is_some() {
    return parsed;
  }
  let scope = ctx.grants.iter().find_map(|grant| grant.postgres(Some(ctx.host), ctx.port))?;
  scope
    .upstream
    .user
    .clone()
    .filter(|user| !user.is_empty())
    .or_else(|| scope.downstream.user.clone().filter(|user| !user.is_empty()))
}

fn startup_user(startup: &[u8]) -> Option<String> {
  let len = usize::try_from(u32::from_be_bytes(startup.get(..4)?.try_into().ok()?)).ok()?;
  let startup = startup.get(..len)?;
  let mut pos = 8usize;
  while pos < startup.len() {
    let key_end = pos + startup.get(pos..)?.iter().position(|&byte| byte == 0)?;
    let value_start = key_end.checked_add(1)?;
    let value_end = value_start + startup.get(value_start..)?.iter().position(|&byte| byte == 0)?;
    if startup.get(pos..key_end) == Some(b"user".as_slice()) {
      return std::str::from_utf8(startup.get(value_start..value_end)?).ok().map(str::to_owned);
    }
    pos = value_end.checked_add(1)?;
  }
  None
}

fn leg_passwords(ctx: &PairCtx<'_>) -> Option<(String, String)> {
  let scope = ctx.grants.iter().find_map(|grant| grant.postgres(Some(ctx.host), ctx.port))?;
  Some((
    scope.downstream.password.expose_secret().to_owned(),
    scope.upstream.password.expose_secret().to_owned(),
  ))
}

fn auth_failed() -> PgWireBackendMessage {
  PgWireBackendMessage::ErrorResponse(ErrorResponse::new(vec![
    (b'S', "FATAL".to_owned()),
    (b'C', "28P01".to_owned()),
    (b'M', "password authentication failed".to_owned()),
  ]))
}

fn password_ctx() -> DecodeContext {
  let mut ctx = DecodeContext::default();
  ctx.awaiting_frontend_ssl = false;
  ctx.awaiting_frontend_startup = false;
  ctx
}

struct Frames<R> {
  reader: R,
  buf: BytesMut,
  budget: Duration,
  ctx: DecodeContext,
}

impl<R> Frames<R> {
  fn new(reader: R, budget: Duration, ctx: DecodeContext) -> Self {
    Self {
      reader,
      buf: BytesMut::new(),
      budget,
      ctx,
    }
  }
}

impl<R: AsyncRead + Unpin> Frames<R> {
  async fn pull(&mut self) -> Result<bool, Error> {
    pull(&mut self.reader, &mut self.buf, self.budget).await
  }

  async fn send_backend(&mut self, message: &PgWireBackendMessage) -> Result<(), Error>
  where
    R: AsyncWrite,
  {
    write_backend(&mut self.reader, message).await
  }

  async fn send_frontend(&mut self, message: &PgWireFrontendMessage) -> Result<(), Error>
  where
    R: AsyncWrite,
  {
    write_frontend(&mut self.reader, message).await
  }

  async fn next_backend(&mut self) -> Result<Option<PgWireBackendMessage>, Error> {
    loop {
      if self.buf.len() > MAX_GREETING {
        return Err(scram_err(short("postgres authentication message exceeds the greeting cap")));
      }
      match PgWireBackendMessage::decode(&mut self.buf, &self.ctx).map_err(scram_err)? {
        Some(message) => return Ok(Some(message)),
        None => {
          if !self.pull().await? {
            return Ok(None);
          }
        }
      }
    }
  }

  async fn next_frontend(&mut self) -> Result<Option<PgWireFrontendMessage>, Error> {
    loop {
      if self.buf.len() > MAX_GREETING {
        return Err(scram_err(short("postgres authentication message exceeds the greeting cap")));
      }
      match PgWireFrontendMessage::decode(&mut self.buf, &self.ctx).map_err(scram_err)? {
        Some(message) => return Ok(Some(message)),
        None => {
          if !self.pull().await? {
            return Ok(None);
          }
        }
      }
    }
  }
}

async fn pull<R>(reader: &mut R, buf: &mut BytesMut, budget: Duration) -> Result<bool, Error>
where
  R: AsyncRead + Unpin,
{
  let mut tmp = [0u8; 4096];
  let read = match tokio::time::timeout(budget, reader.read(&mut tmp)).await {
    Ok(Ok(0)) => return Ok(false),
    Ok(Ok(read)) => read,
    Ok(Err(err)) => return Err(err.into()),
    Err(_elapsed) => return Err(Error::PostgresAuthTimeout),
  };
  let Some(chunk) = tmp.get(..read) else {
    return Err(scram_err(short("postgres authentication read exceeded its buffer")));
  };
  buf.extend_from_slice(chunk);
  Ok(true)
}

async fn write_backend<W>(writer: &mut W, message: &PgWireBackendMessage) -> Result<(), Error>
where
  W: AsyncWrite + Unpin,
{
  writer.write_all(&encode_backend(message)?).await?;
  writer.flush().await?;
  Ok(())
}

async fn write_frontend<W>(writer: &mut W, message: &PgWireFrontendMessage) -> Result<(), Error>
where
  W: AsyncWrite + Unpin,
{
  let mut buf = BytesMut::new();
  message.encode(&mut buf).map_err(scram_err)?;
  writer.write_all(&buf).await?;
  writer.flush().await?;
  Ok(())
}

fn encode_backend(message: &PgWireBackendMessage) -> Result<Vec<u8>, Error> {
  let mut buf = BytesMut::new();
  message.encode(&mut buf).map_err(scram_err)?;
  Ok(buf.to_vec())
}

fn scram_err(err: impl std::error::Error + Send + Sync + 'static) -> Error {
  Error::PostgresScram { source: Box::new(err) }
}

fn short(message: &str) -> std::io::Error {
  std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}
