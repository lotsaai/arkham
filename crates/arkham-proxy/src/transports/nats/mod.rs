//! NATS vertical: transport halves, the INFO-first opening, and the framer.
//!
//! The server speaks first. On `nats://` and `tls://` the proxy forwards one
//! cleartext INFO line. A `tls://` server leg then upgrades before CONNECT,
//! with the bytes read past INFO replayed into its handshake. A guest whose
//! next byte opens a TLS record is terminated here. With `handshake_first`
//! both legs settle TLS before any protocol byte. CONNECT carries the real
//! values on a cleartext server leg the same way it does on TLS.

pub mod machine;

#[cfg(test)]
pub(crate) mod fixtures;

#[cfg(test)]
mod props;

use std::io::{Error as IoError, ErrorKind};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use arkham_config::grants::{Grant, NatsScope, NatsTlsOrder, NatsTrust, NatsUpstream, RootCert};
use arkham_pki::ca::CertAuthority;

use super::{ServeStream, TlsHalves, Transport};
use crate::Error;
use crate::connection::{Prefixed, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::mint::MintBucket;
use crate::relay::{log_hits, relay_guarded};
use crate::transports::engine::{Rewritten, Wire};
use machine::Nats;

/// First byte of a TLS record carrying a handshake.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;

/// Read window for INFO and for the guest's first bytes.
const OPENING_READ: usize = 4096;

/// NATS transport.
#[derive(Debug)]
pub(crate) struct NatsTransport {
  ca: CertAuthority,
  leaves: DashMap<String, Arc<ServerConfig>>,
  roots: DashMap<RootCert, Arc<RootCertStore>>,
}

impl NatsTransport {
  /// Build both halves over the CA that signs guest-facing leaves.
  ///
  /// # Errors
  ///
  /// Returns an error when the CA cannot be read back from its own PEM.
  pub(crate) fn new(ca: &CertAuthority) -> Result<Self, Error> {
    Ok(Self {
      ca: CertAuthority::load(&ca.cert_pem(), &ca.key_pem())?,
      leaves: DashMap::new(),
      roots: DashMap::new(),
    })
  }
}

impl TlsHalves for NatsTransport {
  type Scope = NatsTrust;

  fn ca(&self) -> &CertAuthority {
    &self.ca
  }

  fn leaves(&self) -> &DashMap<String, Arc<ServerConfig>> {
    &self.leaves
  }

  fn roots(&self) -> &DashMap<RootCert, Arc<RootCertStore>> {
    &self.roots
  }

  fn tls_label(&self) -> &'static str {
    "nats"
  }

  fn root_cert<'a>(&self, scope: &'a NatsTrust) -> Option<&'a RootCert> {
    Some(&scope.root_cert)
  }

  fn client_paths<'a>(&self, scope: &'a NatsTrust) -> Option<(&'a Path, &'a Path)> {
    let identity = scope.identity.as_ref()?;
    Some((identity.cert.as_path(), identity.key.as_path()))
  }
}

impl Transport for NatsTransport {
  type Scope = NatsScope;

  /// The `nats://` / `tls://` arm. The real string alone decides the server
  /// leg; the guest picks its own TLS.
  async fn serve<G>(&self, ServeStream { guest, params, scope }: ServeStream<'_, G, NatsScope>) -> Result<(), Error>
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
    let open = Open {
      scope,
      grants: &snapshot.grants,
      port,
      budget: Duration::from_secs(snapshot.proxy.handshake_timeout_secs),
      mint: &state.mint,
      authority: host.unwrap_or(scope.downstream.host.as_str()),
      fwmark: state.fwmark,
    };
    match &scope.upstream_tls {
      NatsUpstream::Tls {
        order: NatsTlsOrder::HandshakeFirst,
        trust,
      } => self.handshake_first(guest, initial, trust, &open).await,
      NatsUpstream::Tls {
        order: NatsTlsOrder::AfterInfo,
        trust,
      } => self.after_info(guest, initial, Some(trust), &open).await,
      NatsUpstream::Cleartext => self.after_info(guest, initial, None, &open).await,
    }
  }
}

/// Facts every NATS opening shares.
struct Open<'a> {
  scope: &'a NatsScope,
  grants: &'a [Grant],
  port: u16,
  budget: Duration,
  mint: &'a MintBucket,
  /// The name a guest leaf is minted for when its hello has no SNI.
  authority: &'a str,
  fwmark: Option<u32>,
}

impl Open<'_> {
  /// Both directions. Machines key on the grant host, which every
  /// identity this arm serves already matched.
  fn pair(&self, swap: bool) -> (Nats, Nats) {
    nats_pair(self.grants, &self.scope.downstream.host, self.port, swap)
  }
}

/// The server leg once its transport is settled.
struct ServerLeg<S> {
  stream: S,
  /// Server bytes read past INFO, replayed ahead of the stream.
  first: Vec<u8>,
  down: Nats,
  up: Nats,
}

impl NatsTransport {
  /// INFO travels cleartext on both legs. A `tls://` server leg upgrades
  /// right after it; `trust` is `None` on `nats://`, which never upgrades.
  async fn after_info<G>(&self, mut guest: G, initial: &[u8], trust: Option<&NatsTrust>, open: &Open<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    let upstream = &open.scope.upstream;
    let mut tcp = dial_marked(&upstream.host, upstream.port, open.fwmark).await?;
    let (mut down, mut up) = open.pair(true);
    let Some(rest) = server_info(&mut tcp, &mut up, &mut down, &mut guest).await? else {
      return Ok(());
    };
    if let Some(trust) = trust {
      let stream = within(open.budget, self.connect_server(trust, &upstream.host, Prefixed::new(rest, tcp))).await?;
      let server = ServerLeg {
        stream,
        first: Vec::new(),
        down,
        up,
      };
      self.relay_guest(guest, initial, server, open).await
    } else {
      let server = ServerLeg {
        stream: tcp,
        first: rest,
        down,
        up,
      };
      self.relay_guest(guest, initial, server, open).await
    }
  }

  /// `handshake_first`: the guest's hello comes before any NATS byte, and
  /// the server leg settles TLS before INFO.
  async fn handshake_first<G>(&self, mut guest: G, initial: &[u8], trust: &NatsTrust, open: &Open<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    let Some((hello_buf, identity, _)) = guest_tls_opening(&mut guest, initial, open.budget, Some(open.authority), open.mint).await? else {
      return Ok(());
    };
    let upstream = &open.scope.upstream;
    let tcp = dial_marked(&upstream.host, upstream.port, open.fwmark).await?;
    let mut server = within(open.budget, self.connect_server(trust, &upstream.host, tcp)).await?;
    let mut guest = within(
      open.budget,
      self.accept_guest(&identity, Prefixed::new(hello_buf, guest), open.scope.guest_tls),
    )
    .await?;
    let (mut down, mut up) = open.pair(true);
    let Some(rest) = server_info(&mut server, &mut up, &mut down, &mut guest).await? else {
      return Ok(());
    };
    relay_guarded(guest, server, &mut down, &mut up, &[], &rest).await
  }

  /// After INFO, a guest whose first byte opens a TLS record is terminated
  /// here. Either way the guest leg joins the settled server leg.
  async fn relay_guest<G, S>(&self, mut guest: G, initial: &[u8], server: ServerLeg<S>, open: &Open<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let ServerLeg {
      stream,
      first,
      mut down,
      mut up,
    } = server;
    let Some(head) = guest_head(&mut guest, initial).await? else {
      return Ok(());
    };
    if head.first() != Some(&TLS_RECORD_HANDSHAKE) {
      return relay_guarded(guest, stream, &mut down, &mut up, &head, &first).await;
    }
    let Some((hello_buf, identity, _)) = guest_tls_opening(&mut guest, &head, open.budget, Some(open.authority), open.mint).await? else {
      return Ok(());
    };
    let guest = within(
      open.budget,
      self.accept_guest(&identity, Prefixed::new(hello_buf, guest), open.scope.guest_tls),
    )
    .await?;
    relay_guarded(guest, stream, &mut down, &mut up, &[], &first).await
  }
}

/// Both directions for a NATS scope. `swap` rewrites CONNECT. Production
/// passes `true` on every server leg.
pub(crate) fn nats_pair(grants: &[Grant], host: &str, port: u16, swap: bool) -> (Nats, Nats) {
  (Nats::downstream(grants, host, port, swap), Nats::upstream(grants, host, port))
}

async fn within<T>(budget: Duration, step: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
  tokio::time::timeout(budget, step).await.unwrap_or(Err(Error::NatsHandshakeTimeout))
}

/// Forward the server's first line, INFO, through `up` to the guest, and
/// return the bytes read past its LF. On a `tls://` server leg they belong
/// to the server's TLS, not to NATS. `None` when the server closes first or
/// `up` closes the leg. The line may cross reads. `up` reads the object with
/// actson as those reads stream. The success path that has seen LF moves
/// that line's nonce onto `down` before returning the bytes past it.
/// `tls_required` does not close the session.
///
/// # Errors
///
/// Returns an error when the server read or the guest write fails.
pub(crate) async fn server_info<S, G>(server: &mut S, up: &mut Nats, down: &mut Nats, guest: &mut G) -> Result<Option<Vec<u8>>, Error>
where
  S: AsyncRead + Unpin,
  G: AsyncWrite + Unpin,
{
  let mut buf = vec![0u8; OPENING_READ];
  loop {
    let n = read_count(server.read(&mut buf).await).map_err(|source| Error::UpstreamRead { source })?;
    let Some(chunk) = buf.get(..n).filter(|chunk| !chunk.is_empty()) else {
      return Ok(None);
    };
    let newline = memchr::memchr(b'\n', chunk);
    let cut = newline.map_or(chunk.len(), |at| at.saturating_add(1));
    let Some((line, rest)) = chunk.split_at_checked(cut) else {
      return Ok(None);
    };
    let (rewritten, hits) = up.feed(line).await;
    log_hits(&hits);
    match rewritten {
      Rewritten::Close => return Ok(None),
      Rewritten::Hold => {}
      Rewritten::Emit(bytes) => write_guest(guest, &bytes).await?,
    }
    if newline.is_some() {
      machine::arm_opening(up, down);
      return Ok(Some(rest.to_vec()));
    }
  }
}

/// The guest's first bytes after INFO: the ingress replay, or one read.
/// `None` when the guest closes.
async fn guest_head<G>(guest: &mut G, initial: &[u8]) -> Result<Option<Vec<u8>>, Error>
where
  G: AsyncRead + Unpin,
{
  if !initial.is_empty() {
    return Ok(Some(initial.to_vec()));
  }
  let mut buf = vec![0u8; OPENING_READ];
  let n = read_count(guest.read(&mut buf).await).map_err(|source| Error::GuestRead { source })?;
  if n == 0 {
    return Ok(None);
  }
  buf.truncate(n);
  Ok(Some(buf))
}

fn read_count(result: Result<usize, IoError>) -> Result<usize, IoError> {
  match result {
    Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(0),
    other => other,
  }
}

async fn write_guest<W>(guest: &mut W, bytes: &[u8]) -> Result<(), Error>
where
  W: AsyncWrite + Unpin,
{
  guest
    .write_all(bytes)
    .await
    .map_err(|source| Error::ResponseChunkToGuest { source })?;
  guest.flush().await.map_err(|source| Error::GuestFlush { source })
}

#[cfg(test)]
mod tests {
  use std::io::Cursor;
  use std::pin::Pin;
  use std::task::{Context, Poll};
  use std::time::Duration;

  use arkham_config::grants::{GuestTlsMode, NatsSeed};
  use arkham_pki::ca::CertAuthority;
  use base64::Engine as _;
  use pretty_assertions::assert_eq;
  use tokio::io::{AsyncRead, AsyncReadExt as _, ReadBuf};

  use super::{NatsTransport, Open, ServerLeg, nats_pair};

  use super::fixtures::{mint_user, nats_grants};
  use super::machine::Nats;
  use super::server_info;
  use crate::transports::engine::{Rewritten, Wire};

  #[tokio::test]
  async fn mtls_plaintext_guest_forwards_the_real_password() {
    let ca = CertAuthority::generate().expect("ca");
    let transport = NatsTransport::new(&ca).expect("transport");
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",   // betterleaks:allow
      "tls://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let mut scope = grants.first().and_then(|grant| grant.nats(None, 4222)).cloned().expect("scope");
    scope.guest_tls = GuestTlsMode::Mtls;
    let (down, up) = nats_pair(&grants, "nats.internal", 4222, true);
    let (mut upstream, server) = tokio::io::duplex(256);
    let (guest_peer, guest) = tokio::io::duplex(64);
    drop(guest_peer);
    let mint = crate::mint::MintBucket::new();
    let connect = b"CONNECT {\"user\":\"agent\",\"pass\":\"arkham_fake_nats_pass\"}\r\n"; // betterleaks:allow
    let relay = tokio::spawn(async move {
      let open = Open {
        scope: &scope,
        grants: &grants,
        port: 4222,
        budget: Duration::from_secs(10),
        mint: &mint,
        authority: "nats.internal",
        fwmark: None,
      };
      transport
        .relay_guest(
          guest,
          connect,
          ServerLeg {
            stream: server,
            first: Vec::new(),
            down,
            up,
          },
          &open,
        )
        .await
    });
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), upstream.read(&mut buf))
      .await
      .expect("upstream receives CONNECT")
      .expect("upstream read");
    assert!(n > 0, "upstream received nothing");
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.contains("real-nats-pass-is-longer"), "{text}");
    assert!(!text.contains("arkham_fake_nats_pass"), "{text}");
    drop(upstream);
    let finished = tokio::time::timeout(Duration::from_secs(2), relay)
      .await
      .expect("relay ends")
      .expect("relay task");
    finished.expect("plaintext mtls guest relay");
  }

  #[tokio::test]
  async fn info_reader_leaves_the_bytes_after_the_newline() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",   // betterleaks:allow
      "tls://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let info = b"INFO {\"server_id\":\"N1\",\"tls_required\":true}\r\n";
    let mut wire = info.to_vec();
    wire.extend_from_slice(&[0x16, 0x03, 0x01]);
    let mut server = Cursor::new(wire);
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222, true);
    let rest = server_info(&mut server, &mut up, &mut down, &mut guest).await.unwrap();
    assert_eq!(rest, Some(vec![0x16, 0x03, 0x01]));
    assert_eq!(guest, info);
    let Rewritten::Emit(next) = up.feed(b"+OK\r\n").await.0 else {
      panic!("a line after INFO is emitted");
    };
    assert_eq!(next.as_ref(), b"+OK\r\n");
  }

  #[tokio::test]
  async fn cleartext_upstream_forwards_info_when_tls_is_required() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",    // betterleaks:allow
      "nats://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let info = b"INFO {\"server_id\":\"N1\",\"tls_required\":true,\"tls_available\":true,\"tls_verify\":false}\r\nCONNECT {\"x\":1}\r\n";
    let mut server = Cursor::new(info.to_vec());
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222, true);
    let line = &info[..info.len() - b"CONNECT {\"x\":1}\r\n".len()];
    let rest = server_info(&mut server, &mut up, &mut down, &mut guest)
      .await
      .expect("cleartext INFO is forwarded");
    assert_eq!(guest, line);
    assert_eq!(rest.as_deref(), Some(&b"CONNECT {\"x\":1}\r\n"[..]));
  }

  #[tokio::test]
  async fn cleartext_upstream_forwards_info_when_tls_is_not_required() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",    // betterleaks:allow
      "nats://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let info = b"INFO {\"server_id\":\"N1\",\"tls_required\":false,\"tls_available\":true,\"tls_verify\":true}\r\n";
    let mut server = Cursor::new(info.to_vec());
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222, true);
    let rest = server_info(&mut server, &mut up, &mut down, &mut guest).await.unwrap();
    assert_eq!(rest, Some(Vec::new()));
    assert_eq!(guest, info);
  }

  /// `\u005f` is `_`. That spelling of `tls_required` is still forwarded.
  #[tokio::test]
  async fn escaped_tls_required_key_is_forwarded() {
    let info = b"INFO {\"tls\\u005frequired\":true,\"tls_available\":true,\"tls_verify\":false}\r\n";
    let (guest, rest) = forward_info(&[info]).await;
    assert_eq!(guest, info);
    assert_eq!(rest, Some(Vec::new()));
  }

  /// An INFO line that never finishes an object is forwarded.
  #[tokio::test]
  async fn malformed_info_is_forwarded() {
    let info = b"INFO {\"server_id\":\r\n";
    let (guest, rest) = forward_info(&[info]).await;
    assert_eq!(guest, info);
    assert_eq!(rest, Some(Vec::new()));
  }

  /// A broken object after `tls_required` is forwarded.
  #[tokio::test]
  async fn broken_info_after_tls_required_is_forwarded() {
    let info = b"INFO {\"tls_required\":true,\r\n";
    let (guest, rest) = forward_info(&[info]).await;
    assert_eq!(guest, info);
    assert_eq!(rest, Some(Vec::new()));
  }

  /// INFO whose newline is not in the same read as `INFO`. Bytes past LF stay unread.
  #[tokio::test]
  async fn info_split_across_reads_leaves_the_tail_unread() {
    let first: &[u8] = b"INFO {\"server_id\":\"split\",\"tls_req";
    let second: &[u8] = b"uired\":true,\"tls_available\":true,\"tls_verify\":false}\r\nEXTRA";
    let (guest, rest) = forward_info(&[first, second]).await;
    assert_eq!(guest, [first, &second[..second.len() - b"EXTRA".len()]].concat());
    assert_eq!(rest.as_deref(), Some(&b"EXTRA"[..]));
  }

  /// The JSON bool itself crosses the read. The line is still one INFO.
  #[tokio::test]
  async fn info_bool_split_across_reads_is_one_line() {
    let first: &[u8] = b"INFO {\"tls_required\":tru";
    let second: &[u8] = b"e,\"tls_available\":true,\"tls_verify\":false}\r\n";
    let (guest, rest) = forward_info(&[first, second]).await;
    assert_eq!(guest, [first, second].concat());
    assert_eq!(rest, Some(Vec::new()));
  }

  /// The verb itself crosses the read. The framer holds those bytes until the delimiter.
  #[tokio::test]
  async fn info_verb_split_across_reads_leaves_the_tail_unread() {
    let first: &[u8] = b"INF";
    let second: &[u8] = b"O {\"tls_required\":true,\"tls_available\":false,\"tls_verify\":true}\r\nTAIL";
    let (guest, rest) = forward_info(&[first, second]).await;
    assert_eq!(guest, [first, &second[..second.len() - b"TAIL".len()]].concat());
    assert_eq!(rest.as_deref(), Some(&b"TAIL"[..]));
  }

  async fn forward_info(parts: &[&[u8]]) -> (Vec<u8>, Option<Vec<u8>>) {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",    // betterleaks:allow
      "nats://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let mut server = SliceReads { parts, index: 0 };
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222, true);
    let rest = server_info(&mut server, &mut up, &mut down, &mut guest)
      .await
      .expect("info forwarded");
    (guest, rest)
  }

  /// A split INFO whose top-level `tls_required` is false is forwarded. Text
  /// and a nested object that contain the key do not close the session.
  #[tokio::test]
  async fn cleartext_info_split_without_tls_required_is_forwarded() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",    // betterleaks:allow
      "nats://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let line: &[u8] = b"INFO {\"note\":\"see \\\"tls_required\\\":true\",\"tls\":{\"tls_required\":true},\"connect_urls\":[\"nats://example\"],\"tls_required\":false,\"tls_available\":true,\"tls_verify\":true}\r\nEXTRA";
    let (first, second) = line.split_at(24);
    let parts = [first, second];
    let mut server = SliceReads { parts: &parts, index: 0 };
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222, true);
    let rest = server_info(&mut server, &mut up, &mut down, &mut guest).await.unwrap();
    assert_eq!(rest, Some(b"EXTRA".to_vec()));
    assert_eq!(guest, &line[..line.len() - b"EXTRA".len()]);
  }

  fn sig_b64(seed: &NatsSeed, nonce: &[u8]) -> String {
    let raw = seed.pair.sign(nonce).expect("seed signs");
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &raw)
  }

  fn nkey_connect(public: &str, sig: &str) -> String {
    format!("CONNECT {{\"nkey\":\"{public}\",\"sig\":\"{sig}\",\"verbose\":false}}\r\n")
  }

  /// The opening INFO's nonce is on the guest leg before CONNECT, including a second arm.
  #[tokio::test]
  async fn server_info_arms_a_ready_nonce_before_connect() {
    let (fake_raw, fake) = mint_user();
    let (real_raw, real) = mint_user();
    let grants = nats_grants(
      &format!("nats://nkey:{fake_raw}@nats.internal:4222"),
      &format!("tls://nkey:{real_raw}@nats.upstream:4222"),
    );
    let info = b"INFO {\"nonce\":\"N0NCE\",\"server_id\":\"N1\"}\r\n";
    let mut server = Cursor::new(info.to_vec());
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222, true);
    let rest = server_info(&mut server, &mut up, &mut down, &mut guest).await.unwrap();
    assert_eq!(rest, Some(Vec::new()));
    assert_eq!(guest, info);
    let line = nkey_connect(fake.public.as_str(), &sig_b64(&fake, b"N0NCE"));
    let (rewritten, hits) = down.feed(line.as_bytes()).await;
    assert_eq!(hits.len(), 1);
    let Rewritten::Emit(bytes) = rewritten else {
      panic!("swapped connect");
    };
    let text = String::from_utf8_lossy(&bytes);
    let value: serde_json::Value = serde_json::from_str(text.trim().strip_prefix("CONNECT").expect("verb")).expect("json");
    assert_eq!(value.get("nkey").and_then(serde_json::Value::as_str), Some(real.public.as_str()));
    let sig = value.get("sig").and_then(serde_json::Value::as_str).expect("sig");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig).expect("sig bytes");
    assert!(NatsSeed::verify(real.public.as_str(), b"N0NCE", &raw));
    assert!(!text.contains(fake.public.as_str()));
  }

  /// The first INFO had no nonce. A later INFO's nonce does not replace that.
  #[tokio::test]
  async fn a_second_info_does_not_replace_an_absent_nonce() {
    let (fake_raw, fake) = mint_user();
    let (real_raw, real) = mint_user();
    let grants = nats_grants(
      &format!("nats://nkey:{fake_raw}@nats.internal:4222"),
      &format!("tls://nkey:{real_raw}@nats.upstream:4222"),
    );
    let first: &[u8] = b"INFO {\"server_id\":\"N1\"}\r\n";
    let second: &[u8] = b"INFO {\"nonce\":\"N0NCE\"}\r\n";
    let parts = [first, second];
    let mut server = SliceReads { parts: &parts, index: 0 };
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222, true);
    let rest = server_info(&mut server, &mut up, &mut down, &mut guest).await.unwrap();
    assert_eq!(rest, Some(Vec::new()));
    let rest = server_info(&mut server, &mut up, &mut down, &mut guest).await.unwrap();
    assert_eq!(rest, Some(Vec::new()));
    let line = nkey_connect(fake.public.as_str(), &sig_b64(&fake, b"N0NCE"));
    let (rewritten, hits) = down.feed(line.as_bytes()).await;
    assert_eq!(hits.len(), 0);
    let Rewritten::Emit(bytes) = rewritten else {
      panic!("forwarded connect");
    };
    assert_eq!(bytes.as_ref(), line.as_bytes());
    assert!(!line.contains(real.public.as_str()));
  }

  /// An empty read arms nothing. A finished INFO arms its nonce even when
  /// `tls_required` is set. A line that does not finish an object does not.
  #[tokio::test]
  async fn info_arms_a_nonce_when_the_object_finishes() {
    let (fake_raw, fake) = mint_user();
    let (real_raw, real) = mint_user();
    let grants = nats_grants(
      &format!("nats://nkey:{fake_raw}@nats.internal:4222"),
      &format!("tls://nkey:{real_raw}@nats.upstream:4222"),
    );
    let line = nkey_connect(fake.public.as_str(), &sig_b64(&fake, b"N0NCE"));
    let cases: [(&[u8], bool); 3] = [
      (b"", false),
      (b"INFO {\"nonce\":\"N0NCE\",\"tls_required\":true}\r\n", true),
      (b"INFO {\"nonce\":\"N0NCE\"\r\n", false),
    ];
    for (wire, armed) in cases {
      let mut server = Cursor::new(wire.to_vec());
      let mut guest = Vec::new();
      let mut up = Nats::upstream(&grants, "nats.internal", 4222);
      let mut down = Nats::downstream(&grants, "nats.internal", 4222, true);
      let opened = server_info(&mut server, &mut up, &mut down, &mut guest).await.expect("info read");
      if wire.is_empty() {
        assert_eq!(opened, None);
      } else {
        assert_eq!(opened.as_deref(), Some(&[][..]));
        assert_eq!(guest, wire);
      }
      let (rewritten, hits) = down.feed(line.as_bytes()).await;
      let Rewritten::Emit(bytes) = rewritten else {
        panic!("connect emitted");
      };
      if armed {
        assert_eq!(hits.len(), 1);
        assert!(
          bytes
            .windows(real.public.as_str().len())
            .any(|window| window == real.public.as_bytes())
        );
      } else {
        assert_eq!(hits.len(), 0);
        assert_eq!(bytes.as_ref(), line.as_bytes());
      }
    }
  }

  /// Yields one slice per read so a command line can cross the read boundary.
  struct SliceReads<'a> {
    parts: &'a [&'a [u8]],
    index: usize,
  }

  impl AsyncRead for SliceReads<'_> {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
      let this = self.get_mut();
      let Some(part) = this.parts.get(this.index).copied() else {
        return Poll::Ready(Ok(()));
      };
      let Some(dst) = buf.initialize_unfilled().get_mut(..part.len()) else {
        return Poll::Ready(Err(std::io::Error::new(
          std::io::ErrorKind::InvalidInput,
          "read buffer shorter than the slice",
        )));
      };
      dst.copy_from_slice(part);
      buf.advance(part.len());
      this.index = this.index.saturating_add(1);
      Poll::Ready(Ok(()))
    }
  }
}
