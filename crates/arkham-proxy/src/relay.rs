//! Bidirectional pump. The implementation lives in `arkham-wire`.

pub(crate) use arkham_wire::relay::{RelayEnd, RelayUpgrade, log_hits};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::Error;
use arkham_wire::engine::Wire;

/// Bidirectional relay through the two directions' wire formats.
///
/// # Errors
///
/// Returns an error when a direction cannot be read or written.
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
  arkham_wire::relay::relay_guarded(guest, server, downstream, upstream, first, upstream_first)
    .await
    .map_err(Into::into)
}

/// [`relay_guarded`], plus an upgrade handoff that returns both sockets.
///
/// # Errors
///
/// Returns an error when a direction cannot be read or written.
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
  arkham_wire::relay::relay_stop(guest, server, downstream, upstream, first, upstream_first)
    .await
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use crate::transports::engine::{Direction, Ldap};
  use arkham_config::grants::{Credential, Grant, LdapScope};
  use rasn_ldap::{ExtendedRequest, LdapMessage, ProtocolOp, ResultCode};
  use secrecy::SecretString;

  use arkham_wire::relay::{ChunkStep, ToResponse, on_upstream_chunk};
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
    assert_eq!(leftover, &b""[..]);
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
    let mut got = vec![0u8; entry.len() - split];
    tokio::time::timeout(Duration::from_secs(1), guest.read_exact(&mut got))
      .await
      .expect("entry tail")
      .unwrap();
    assert_eq!(got, entry[split..]);
  }

  #[tokio::test]
  async fn queued_handoff_writes_the_split_entry_before_upgrade() {
    let (entry, split) = big_entry();
    let (_down, mut up) = pair();
    let (guest_relay, mut guest) = tokio::io::duplex(64 * 1024);
    let (_guest_read, mut guest_write) = tokio::io::split(guest_relay);
    let (requests_tx, mut requests) = tokio::sync::mpsc::unbounded_channel();
    requests_tx.send(ToResponse::Handoff(3)).unwrap();
    let (upgrade_tx, mut upgrade_rx) = tokio::sync::mpsc::channel(1);
    let mut armed = false;
    let step = on_upstream_chunk(&mut guest_write, &mut up, &mut requests, &mut armed, &upgrade_tx, &entry[..split])
      .await
      .unwrap();
    match step {
      ChunkStep::Stay => {}
      ChunkStep::Upgrade(_) => panic!("handoff upgraded before the entry finished"),
      ChunkStep::Stop => panic!("relay stopped before the entry finished"),
    }
    assert!(upgrade_rx.try_recv().is_err(), "upgrade signal fired before the entry finished");
    let mut got = vec![0u8; split];
    tokio::time::timeout(Duration::from_secs(1), guest.read_exact(&mut got))
      .await
      .expect("entry prefix")
      .unwrap();
    assert_eq!(got, entry[..split]);
    let step = on_upstream_chunk(&mut guest_write, &mut up, &mut requests, &mut armed, &upgrade_tx, &entry[split..])
      .await
      .unwrap();
    match step {
      ChunkStep::Upgrade(prefix) => assert!(prefix.is_empty(), "local handoff carries no unread tail"),
      ChunkStep::Stay => panic!("upgrade never followed the entry"),
      ChunkStep::Stop => panic!("relay stopped on the entry tail"),
    }
    assert!(upgrade_rx.try_recv().unwrap());
    let mut tail = vec![0u8; entry.len() - split];
    tokio::time::timeout(Duration::from_secs(1), guest.read_exact(&mut tail))
      .await
      .expect("entry tail")
      .unwrap();
    assert_eq!(tail, entry[split..]);
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
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
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
    let abandon = LdapMessage::new(2, ProtocolOp::AbandonRequest(rasn_ldap::AbandonRequest(1)));
    let mut bytes = search_bytes(1);
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
