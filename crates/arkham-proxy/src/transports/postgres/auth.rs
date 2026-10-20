use std::time::Duration;

use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use pgwire::api::auth::Password;
use pgwire::api::auth::sasl::SCRAM_SHA_256_METHOD;
use pgwire::api::auth::sasl::scram::{SCRAM_ITERATIONS, ScramClientAuth, ScramServerAuth, gen_salted_password, random_nonce};
use pgwire::messages::response::ErrorResponse;
use pgwire::messages::startup::{Authentication, PasswordMessageFamily, SASLInitialResponse, SASLResponse, Startup};
use pgwire::messages::{DecodeContext, Message as _, PgWireBackendMessage, PgWireFrontendMessage};
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
      Some(PgWireBackendMessage::Authentication(Authentication::Ok | Authentication::KerberosV5)) => {}
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
  let body = startup.get(4..)?;
  let mut buf = BytesMut::from(body);
  let decoded = Startup::decode_body(&mut buf, body.len(), &DecodeContext::default()).ok()?;
  decoded.parameters.get("user").filter(|user| !user.is_empty()).cloned()
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

#[cfg(test)]
mod tests {
  use std::sync::OnceLock;
  use std::time::Instant;

  use arkham_config::grants::{Credential, Grant, PostgresScope};
  use arkham_plugin::Registry;
  use pgwire::api::auth::sasl::SCRAM_SHA_256_PLUS_METHOD;
  use secrecy::SecretString;
  use tokio::io::duplex;

  use super::*;
  use crate::transports::engine::Direction;

  const FAKE: &str = "arkham_fake_pg_pass"; // betterleaks:allow
  const REAL: &str = "arkham_real_pg_pass"; // betterleaks:allow
  const LEAK: &str = "upstream-leak-marker";

  fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry::load(&[]).expect("empty plugin registry"))
  }

  fn grant() -> Grant {
    Grant::Postgres {
      credential: Credential {
        label: "pg".into(),
        fake: FAKE.into(),
        value: SecretString::from(REAL),
      },
      scope: Box::new(
        PostgresScope::from_strings(
          &format!("postgres://app:{FAKE}@db.internal:5432/main"), // betterleaks:allow
          &format!("postgres://app:{REAL}@db.internal:5432/main?sslmode=disable"), // betterleaks:allow
        )
        .expect("grant"),
      ),
    }
  }

  fn userless_grant() -> Grant {
    Grant::Postgres {
      credential: Credential {
        label: "pg".into(),
        fake: FAKE.into(),
        value: SecretString::from(REAL),
      },
      scope: Box::new(
        PostgresScope::from_strings(
          &format!("postgres://:{FAKE}@db.internal:5432/main"), // betterleaks:allow
          &format!("postgres://:{REAL}@db.internal:5432/main?sslmode=disable"), // betterleaks:allow
        )
        .expect("userless grant"),
      ),
    }
  }

  fn startup_message(user: Option<&str>) -> Vec<u8> {
    let mut startup = Startup::new();
    if let Some(user) = user {
      startup.parameters.insert("user".into(), user.into());
    }
    startup.parameters.insert("database".into(), "main".into());
    let mut buf = BytesMut::new();
    startup.encode(&mut buf).expect("startup encodes");
    buf.to_vec()
  }

  fn backend(message: &PgWireBackendMessage) -> Vec<u8> {
    encode_backend(message).expect("backend message encodes")
  }

  async fn read_backend<R>(reader: &mut R) -> PgWireBackendMessage
  where
    R: AsyncRead + Unpin,
  {
    read_decoded(reader, DecodeContext::default(), PgWireBackendMessage::decode)
      .await
      .expect("backend message")
  }

  async fn read_frontend<R>(reader: &mut R) -> PgWireFrontendMessage
  where
    R: AsyncRead + Unpin,
  {
    read_decoded(reader, password_ctx(), PgWireFrontendMessage::decode)
      .await
      .expect("frontend message")
  }

  async fn read_decoded<R, T, E>(
    reader: &mut R,
    ctx: DecodeContext,
    decode: impl Fn(&mut BytesMut, &DecodeContext) -> Result<Option<T>, E>,
  ) -> Option<T>
  where
    R: AsyncRead + Unpin,
    E: std::fmt::Debug,
  {
    let mut buf = BytesMut::new();
    let mut tmp = [0u8; 1024];
    loop {
      if let Some(message) = decode(&mut buf, &ctx).expect("frame decodes") {
        return Some(message);
      }
      let read = reader.read(&mut tmp).await.expect("read");
      if read == 0 {
        return None;
      }
      buf.extend_from_slice(tmp.get(..read).expect("read fits the buffer"));
    }
  }

  async fn prove_decoy<G>(guest: &mut G, startup: &[u8])
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    guest.write_all(startup).await.expect("startup");
    guest.flush().await.expect("startup flush");
    let PgWireBackendMessage::Authentication(Authentication::SASL(mechanisms)) = read_backend(guest).await else {
      panic!("guest offer");
    };
    assert!(mechanisms.iter().any(|mechanism| mechanism == SCRAM_SHA_256_METHOD));
    let (client_first, waiting) = ScramClientAuth::new("app".into(), FAKE.into())
      .build_client_first()
      .expect("client first");
    let initial = PgWireFrontendMessage::PasswordMessageFamily(PasswordMessageFamily::SASLInitialResponse(SASLInitialResponse::new(
      SCRAM_SHA_256_METHOD.into(),
      Some(bytes::Bytes::from(client_first)),
    )));
    guest.write_all(&encode_message(&initial)).await.expect("client first write");
    guest.flush().await.expect("client first flush");
    let PgWireBackendMessage::Authentication(Authentication::SASLContinue(data)) = read_backend(guest).await else {
      panic!("guest continue");
    };
    let (client_final, _) = waiting.build_client_final(&data).expect("client final");
    let response = PgWireFrontendMessage::PasswordMessageFamily(PasswordMessageFamily::SASLResponse(SASLResponse::new(
      bytes::Bytes::from(client_final),
    )));
    guest.write_all(&encode_message(&response)).await.expect("client final write");
    guest.flush().await.expect("client final flush");
  }

  fn encode_message(message: &PgWireFrontendMessage) -> Vec<u8> {
    let mut buf = BytesMut::new();
    message.encode(&mut buf).expect("frontend message encodes");
    buf.to_vec()
  }

  #[test]
  fn startup_user_reads_the_decoded_parameter() {
    let startup = startup_message(Some("app"));
    assert_eq!(startup_user(&startup).as_deref(), Some("app"));
  }

  #[tokio::test]
  async fn upstream_rejection_reaches_the_guest_as_our_28p01() {
    let (guest_peer, mut guest) = duplex(64 * 1024);
    let (server_peer, mut server) = duplex(64 * 1024);
    let startup = startup_message(Some("app"));
    let guest_task = tokio::spawn(async move {
      prove_decoy(&mut guest, &startup).await;
      read_backend(&mut guest).await
    });
    let server_task = tokio::spawn(async move {
      let () = read_startup(&mut server).await;
      let offer = backend(&PgWireBackendMessage::Authentication(Authentication::SASL(vec![
        SCRAM_SHA_256_METHOD.to_owned(),
      ])));
      server.write_all(&offer).await.expect("offer");
      server.flush().await.expect("offer flush");
      let _ = read_frontend(&mut server).await;
      let refusal = backend(&PgWireBackendMessage::ErrorResponse(ErrorResponse::new(vec![
        (b'S', "FATAL".into()),
        (b'C', "28P01".into()),
        (b'M', LEAK.into()),
      ])));
      server.write_all(&refusal).await.expect("refusal");
      server.flush().await.expect("refusal flush");
    });
    let grants = [grant()];
    let plugins = registry();
    let ctx = PairCtx {
      grants: &grants,
      host: "db.internal",
      port: 5432,
      plugins,
      mint: None,
    };
    let mut downstream = Postgres::new(&grants, ctx.host, ctx.port, Direction::Downstream);
    let mut guest_peer = guest_peer;
    let mut server_peer = server_peer;
    let outcome = settle(&mut guest_peer, &mut server_peer, &mut downstream, &ctx, Duration::from_secs(2))
      .await
      .expect("upstream refusal closes");
    assert!(matches!(outcome, Prelude::Close));
    let seen = guest_task.await.expect("guest");
    let PgWireBackendMessage::ErrorResponse(error) = seen else {
      panic!("guest error");
    };
    let text = format!("{error:?}");
    assert!(text.contains("28P01"), "{text}");
    assert!(text.contains("password authentication failed"), "{text}");
    assert!(!text.contains(LEAK), "{text}");
    server_task.abort();
  }

  async fn read_startup<R>(reader: &mut R)
  where
    R: AsyncRead + Unpin,
  {
    let mut buf = BytesMut::new();
    let mut tmp = [0u8; 1024];
    loop {
      if Startup::decode(&mut buf, &DecodeContext::default())
        .expect("startup decodes")
        .is_some()
      {
        return;
      }
      let read = reader.read(&mut tmp).await.expect("startup read");
      assert_ne!(read, 0, "startup closed");
      buf.extend_from_slice(tmp.get(..read).expect("read fits"));
    }
  }

  #[tokio::test]
  async fn sasl_without_scram_sha_256_is_forwarded_unchanged() {
    let mechanisms = vec![SCRAM_SHA_256_PLUS_METHOD.to_owned()];
    let offer = backend(&PgWireBackendMessage::Authentication(Authentication::SASL(mechanisms)));
    let seen = forwarded_offer(&offer, &[grant()], Some("app")).await;
    assert_eq!(seen, offer);
  }

  #[tokio::test]
  async fn scram_without_a_grant_is_forwarded_unchanged() {
    let offer = backend(&PgWireBackendMessage::Authentication(Authentication::SASL(vec![
      SCRAM_SHA_256_METHOD.to_owned(),
    ])));
    let seen = forwarded_offer(&offer, &[], Some("app")).await;
    assert_eq!(seen, offer);
  }

  #[tokio::test]
  async fn scram_without_a_user_is_forwarded_unchanged() {
    let offer = backend(&PgWireBackendMessage::Authentication(Authentication::SASL(vec![
      SCRAM_SHA_256_METHOD.to_owned(),
    ])));
    let grants = [userless_grant()];
    let seen = forwarded_offer(&offer, &grants, None).await;
    assert_eq!(seen, offer);
  }

  async fn forwarded_offer(offer: &[u8], grants: &[Grant], user: Option<&str>) -> Vec<u8> {
    let (guest_peer, mut guest) = duplex(64 * 1024);
    let (server_peer, mut server) = duplex(64 * 1024);
    let startup = startup_message(user);
    let guest_task = tokio::spawn(async move {
      guest.write_all(&startup).await.expect("startup");
      guest.flush().await.expect("flush");
      let mut tmp = [0u8; 8];
      let read = tokio::time::timeout(Duration::from_millis(50), guest.read(&mut tmp)).await;
      assert!(read.is_err(), "fallback must not write the server message to the guest");
    });
    let offer_bytes = offer.to_vec();
    let server_task = tokio::spawn(async move {
      read_startup(&mut server).await;
      server.write_all(&offer_bytes).await.expect("offer");
      server.flush().await.expect("flush");
      std::future::pending::<()>().await;
    });
    let plugins = registry();
    let ctx = PairCtx {
      grants,
      host: "db.internal",
      port: 5432,
      plugins,
      mint: None,
    };
    let mut downstream = Postgres::new(grants, ctx.host, ctx.port, Direction::Downstream);
    let mut guest_peer = guest_peer;
    let mut server_peer = server_peer;
    let outcome = settle(&mut guest_peer, &mut server_peer, &mut downstream, &ctx, Duration::from_secs(2))
      .await
      .expect("fallback relays");
    guest_task.await.expect("guest");
    server_task.abort();
    match outcome {
      Prelude::Relay(bytes) => bytes,
      Prelude::Close => panic!("fallback closed"),
    }
  }

  #[tokio::test]
  async fn late_cleartext_md5_or_sasl_fails_without_waiting() {
    let cases = [
      Authentication::CleartextPassword,
      Authentication::MD5Password(vec![1, 2, 3, 4]),
      Authentication::SASL(vec![SCRAM_SHA_256_METHOD.to_owned()]),
      Authentication::SASLContinue(bytes::Bytes::from_static(b"v=late")),
    ];
    for authentication in cases {
      let started = Instant::now();
      let Err(err) = late_authentication(authentication).await else {
        panic!("late authentication fails the session");
      };
      assert!(
        started.elapsed() < Duration::from_millis(500),
        "late authentication waited {elapsed:?}",
        elapsed = started.elapsed()
      );
      assert!(matches!(err, Error::PostgresScram { .. }), "{err}");
    }
  }

  async fn late_authentication(authentication: Authentication) -> Result<Prelude, Error> {
    let (guest_peer, mut guest) = duplex(64 * 1024);
    let (server_peer, mut server) = duplex(64 * 1024);
    let startup = startup_message(Some("app"));
    let guest_task = tokio::spawn(async move {
      prove_decoy(&mut guest, &startup).await;
      std::future::pending::<()>().await;
    });
    let server_task = tokio::spawn(async move {
      read_startup(&mut server).await;
      let offer = backend(&PgWireBackendMessage::Authentication(Authentication::SASL(vec![
        SCRAM_SHA_256_METHOD.to_owned(),
      ])));
      server.write_all(&offer).await.expect("offer");
      server.flush().await.expect("offer flush");
      let PgWireFrontendMessage::PasswordMessageFamily(family) = read_frontend(&mut server).await else {
        panic!("upstream client first");
      };
      let initial = family.into_sasl_initial_response().expect("sasl initial");
      let salt = base64::engine::general_purpose::STANDARD.decode(random_nonce()).expect("salt");
      let salted = gen_salted_password(REAL, &salt, SCRAM_ITERATIONS);
      let (server_first, _) = ScramServerAuth::new()
        .on_client_first_message(initial.data.as_deref().expect("client first"), Password::new(Some(salt), salted))
        .expect("server first");
      let continue_message = backend(&PgWireBackendMessage::Authentication(Authentication::SASLContinue(
        bytes::Bytes::from(server_first),
      )));
      server.write_all(&continue_message).await.expect("continue");
      server.flush().await.expect("continue flush");
      let _ = read_frontend(&mut server).await;
      let late = backend(&PgWireBackendMessage::Authentication(authentication));
      server.write_all(&late).await.expect("late");
      server.flush().await.expect("late flush");
      std::future::pending::<()>().await;
    });
    let grants = [grant()];
    let plugins = registry();
    let ctx = PairCtx {
      grants: &grants,
      host: "db.internal",
      port: 5432,
      plugins,
      mint: None,
    };
    let mut downstream = Postgres::new(&grants, ctx.host, ctx.port, Direction::Downstream);
    let mut guest_peer = guest_peer;
    let mut server_peer = server_peer;
    let outcome = settle(&mut guest_peer, &mut server_peer, &mut downstream, &ctx, Duration::from_secs(2)).await;
    guest_task.abort();
    server_task.abort();
    outcome
  }
}
