//! NATS vertical: transport halves, the INFO-first opening, and the framer.
//!
//! The server speaks first. On `nats://` and `tls://` the proxy forwards one
//! cleartext INFO line. A `tls://` server leg then upgrades before CONNECT,
//! with the bytes read past INFO replayed into its handshake. A `nats://`
//! leg does the same when that INFO sets `tls_required`, using the platform
//! trust store. A guest whose next byte opens a TLS record is terminated
//! here. With `handshake_first` both legs settle TLS before any protocol
//! byte. CONNECT is swapped when a grant covers the endpoint.

pub mod machine;

#[cfg(test)]
pub(crate) mod fixtures;

#[cfg(test)]
mod props;

use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rama::tls::client::ClientAuth;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use arkham_config::grants::{Grant, GuestTlsMode, NatsScope, NatsTlsOrder, NatsTrust, NatsUpstream, RootCert};
use arkham_pki::ca::CertAuthority;

use super::{ServeStream, TlsHalves, Transport};
use crate::Error;
use crate::connection::{Prefixed, client_identity, dial_marked, guest_tls_opening};
use crate::identity::CandidateParams;
use crate::mint::MintBucket;
use crate::relay::{log_hits, relay_guarded};
use crate::transports::engine::{Rewritten, Wire};
use crate::transports::tls::{cached_leaf, cached_leaf_mtls, cached_roots};
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

  /// Accept the guest's TLS, minting the leaf for `name` on first use.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted or the handshake fails.
  async fn accept_guest<G>(&self, name: &str, guest: G, guest_tls: GuestTlsMode) -> Result<ServerTlsStream<G>, Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    let config = match guest_tls {
      GuestTlsMode::Tls => cached_leaf(&self.ca, &self.leaves, name, None)?,
      GuestTlsMode::Mtls => cached_leaf_mtls(&self.ca, &self.leaves, name, None)?,
    };
    TlsAcceptor::from(config)
      .accept(guest)
      .await
      .map_err(|source| Error::GuestNatsTls { source })
  }

  /// Handshake the server under the trust a `tls://` string states. Chain
  /// and host name are always verified.
  ///
  /// # Errors
  ///
  /// Returns an error when the trust anchor or client identity cannot be
  /// read, when the server name is unusable, or when the handshake fails.
  async fn connect_server<S>(&self, scope: &NatsTrust, server_name: &str, server: S) -> Result<ClientTlsStream<S>, Error>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let roots = cached_roots(&self.roots, &scope.root_cert)?;
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let config = match &scope.identity {
      Some(identity) => {
        let ClientAuth::Single(data) = client_identity(&identity.cert, &identity.key)? else {
          return Err(Error::EmptyClientIdentity {
            path: identity.cert.clone(),
          });
        };
        builder
          .with_client_auth_cert(data.cert_chain.clone(), data.private_key.clone_key())
          .map_err(|source| Error::ClientIdentity {
            path: identity.cert.clone(),
            source,
          })?
      }
      None => builder.with_no_client_auth(),
    };
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| Error::NatsServerName { source: err.into() })?;
    TlsConnector::from(Arc::new(config))
      .connect(name, server)
      .await
      .map_err(|source| Error::ServerNatsTls { source })
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
  fn pair(&self) -> (Nats, Nats) {
    nats_pair(self.grants, &self.scope.downstream.host, self.port)
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
  async fn after_info<G>(&self, mut guest: G, initial: &[u8], trust: Option<&NatsTrust>, open: &Open<'_>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    if initial.first() == Some(&TLS_RECORD_HANDSHAKE) {
      tracing::debug!("TLS before INFO on a nats scope without handshake_first; closing");
      return Ok(());
    }
    let upstream = &open.scope.upstream;
    let mut tcp = dial_marked(&upstream.host, upstream.port, open.fwmark).await?;
    let (mut down, mut up) = open.pair();
    let Some(opened) = server_info(&mut tcp, &mut up, &mut down, &mut guest, trust.is_none()).await? else {
      return Ok(());
    };
    let system = NatsTrust {
      root_cert: RootCert::System,
      identity: None,
    };
    let trust = match trust {
      Some(trust) => Some(trust),
      None if opened.upgrade => Some(&system),
      None => None,
    };
    if let Some(trust) = trust {
      let stream = within(
        open.budget,
        self.connect_server(trust, &upstream.host, Prefixed::new(opened.rest, tcp)),
      )
      .await?;
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
        first: opened.rest,
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
    let (mut down, mut up) = open.pair();
    let Some(opened) = server_info(&mut server, &mut up, &mut down, &mut guest, false).await? else {
      return Ok(());
    };
    relay_guarded(guest, server, &mut down, &mut up, &[], &opened.rest).await
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
      if open.scope.guest_tls == GuestTlsMode::Mtls {
        return Err(Error::NatsGuestPlaintext);
      }
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

/// Both directions for a NATS scope.
pub(crate) fn nats_pair(grants: &[Grant], host: &str, port: u16) -> (Nats, Nats) {
  (Nats::downstream(grants, host, port), Nats::upstream(grants, host, port))
}

async fn within<T>(budget: Duration, step: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
  tokio::time::timeout(budget, step).await.unwrap_or(Err(Error::NatsHandshakeTimeout))
}

#[derive(Debug)]
pub(crate) struct ServerOpening {
  pub(crate) rest: Vec<u8>,
  /// INFO set `tls_required` on a `nats://` leg.
  pub(crate) upgrade: bool,
}

/// On a `tls://` server leg, bytes read past INFO belong to the server's TLS, not to NATS.
/// `cleartext` is a `nats://` leg: INFO `tls_required` sets [`ServerOpening::upgrade`] after the line is written.
///
/// # Errors
///
/// Returns [`Error::NatsInfoUnreadable`] when `cleartext` is set and the
/// object does not finish without `tls_required`.
pub(crate) async fn server_info<S, G>(
  server: &mut S,
  up: &mut Nats,
  down: &mut Nats,
  guest: &mut G,
  cleartext: bool,
) -> Result<Option<ServerOpening>, Error>
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
    let mut upgrade = false;
    if cleartext && let Some(verdict) = up.take_info_tls() {
      match verdict {
        machine::InfoVerdict::Flags(info) if info.tls_required => upgrade = true,
        machine::InfoVerdict::Unreadable => return Err(Error::NatsInfoUnreadable),
        machine::InfoVerdict::Flags(_) => {}
      }
    }
    match rewritten {
      Rewritten::Close => return Ok(None),
      Rewritten::Hold => {}
      Rewritten::Emit(bytes) => write_guest(guest, &bytes).await?,
    }
    if newline.is_some() {
      machine::arm_opening(up, down);
      return Ok(Some(ServerOpening {
        rest: rest.to_vec(),
        upgrade,
      }));
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

  type OpeningFailure<'a> = (&'a [u8], fn(&crate::Error) -> bool);

  #[tokio::test]
  async fn mtls_plaintext_guest_closes_without_forwarding() {
    let ca = CertAuthority::generate().expect("ca");
    let transport = NatsTransport::new(&ca).expect("transport");
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",   // betterleaks:allow
      "tls://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let mut scope = grants.first().and_then(|grant| grant.nats(None, 4222)).cloned().expect("scope");
    scope.guest_tls = GuestTlsMode::Mtls;
    let (down, up) = nats_pair(&grants, "nats.internal", 4222);
    let (mut upstream, server) = tokio::io::duplex(256);
    let (guest_peer, guest) = tokio::io::duplex(64);
    drop(guest_peer);
    let mint = crate::mint::MintBucket::new();
    let open = Open {
      scope: &scope,
      grants: &grants,
      port: 4222,
      budget: Duration::from_secs(10),
      mint: &mint,
      authority: "nats.internal",
      fwmark: None,
    };
    let connect = b"CONNECT {\"user\":\"agent\",\"pass\":\"arkham_fake_nats_pass\"}\r\n"; // betterleaks:allow
    let finished = tokio::time::timeout(
      Duration::from_millis(200),
      transport.relay_guest(
        guest,
        connect,
        ServerLeg {
          stream: server,
          first: Vec::new(),
          down,
          up,
        },
        &open,
      ),
    )
    .await
    .expect("plaintext mtls guest must not enter the relay");
    let err = finished.expect_err("plaintext mtls guest");
    assert!(matches!(err, crate::Error::NatsGuestPlaintext), "{err}");
    let mut forwarded = Vec::new();
    upstream.read_to_end(&mut forwarded).await.expect("upstream read");
    assert_eq!(forwarded, b"");
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
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, false)
      .await
      .unwrap()
      .expect("info");
    assert_eq!(opened.rest, vec![0x16, 0x03, 0x01]);
    assert!(!opened.upgrade);
    assert_eq!(guest, info);
    let Rewritten::Emit(next) = up.feed(b"+OK\r\n").await.0 else {
      panic!("a line after INFO is emitted");
    };
    assert_eq!(next.as_ref(), b"+OK\r\n");
  }

  #[tokio::test]
  async fn cleartext_upstream_upgrades_when_info_requires_tls() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",    // betterleaks:allow
      "nats://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let line = b"INFO {\"server_id\":\"N1\",\"tls_required\":true,\"tls_available\":true,\"tls_verify\":false}\r\n";
    let mut wire = line.to_vec();
    wire.extend_from_slice(b"CONNECT {\"x\":1}\r\n");
    let mut server = Cursor::new(wire);
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, true)
      .await
      .unwrap()
      .expect("info");
    assert!(opened.upgrade);
    assert_eq!(opened.rest, b"CONNECT {\"x\":1}\r\n");
    assert_eq!(guest, line);
    assert!(
      !guest
        .windows(b"real-nats-pass-is-longer".len())
        .any(|window| window == b"real-nats-pass-is-longer")
    );
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
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, true)
      .await
      .unwrap()
      .expect("info");
    assert!(!opened.upgrade);
    assert_eq!(opened.rest, Vec::<u8>::new());
    assert_eq!(guest, info);
  }

  /// `\u005f` is `_`.
  #[tokio::test]
  async fn cleartext_info_escaped_tls_required_key_upgrades() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",    // betterleaks:allow
      "nats://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let info = b"INFO {\"tls\\u005frequired\":true,\"tls_available\":true,\"tls_verify\":false}\r\n";
    let mut server = Cursor::new(info.to_vec());
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, true)
      .await
      .unwrap()
      .expect("info");
    assert!(opened.upgrade);
    assert_eq!(opened.rest, Vec::<u8>::new());
    assert_eq!(guest, info);
    assert!(
      !guest
        .windows(b"real-nats-pass-is-longer".len())
        .any(|window| window == b"real-nats-pass-is-longer")
    );
  }

  /// A cleartext INFO that never finishes an object, and never sets the flag, closes.
  #[tokio::test]
  async fn cleartext_malformed_info_closes() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",    // betterleaks:allow
      "nats://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let info = b"INFO {\"server_id\":\r\n";
    let mut server = Cursor::new(info.to_vec());
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let err = server_info(&mut server, &mut up, &mut down, &mut guest, true).await.unwrap_err();
    assert!(matches!(err, crate::Error::NatsInfoUnreadable), "{err}");
  }

  /// `tls_required` was already true when the object broke, so the leg upgrades.
  #[tokio::test]
  async fn cleartext_broken_info_after_tls_required_upgrades() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",    // betterleaks:allow
      "nats://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let info = b"INFO {\"tls_required\":true,\r\n";
    let mut server = Cursor::new(info.to_vec());
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, true)
      .await
      .unwrap()
      .expect("info");
    assert!(opened.upgrade);
    assert_eq!(opened.rest, Vec::<u8>::new());
    assert_eq!(guest, info);
  }

  /// INFO whose newline is not in the same read as `INFO`. The verb and the
  /// start of `tls_required` arrive first; the value and the LF arrive next.
  #[tokio::test]
  async fn cleartext_info_split_across_reads_upgrades() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",    // betterleaks:allow
      "nats://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let first: &[u8] = b"INFO {\"server_id\":\"split\",\"tls_req";
    let second: &[u8] = b"uired\":true,\"tls_available\":true,\"tls_verify\":false}\r\nEXTRA";
    let parts = [first, second];
    let mut server = SliceReads { parts: &parts, index: 0 };
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, true)
      .await
      .unwrap()
      .expect("info");
    assert!(opened.upgrade);
    assert_eq!(opened.rest, b"EXTRA");
    let mut line = first.to_vec();
    line.extend_from_slice(&second[..second.len() - b"EXTRA".len()]);
    assert_eq!(guest, line);
  }

  #[tokio::test]
  async fn cleartext_info_bool_split_across_reads_upgrades() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",    // betterleaks:allow
      "nats://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let first: &[u8] = b"INFO {\"tls_required\":tru";
    let second: &[u8] = b"e,\"tls_available\":true,\"tls_verify\":false}\r\n";
    let parts = [first, second];
    let mut server = SliceReads { parts: &parts, index: 0 };
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, true)
      .await
      .unwrap()
      .expect("info");
    assert!(opened.upgrade);
    assert_eq!(opened.rest, Vec::<u8>::new());
    let mut line = first.to_vec();
    line.extend_from_slice(second);
    assert_eq!(guest, line);
  }

  #[tokio::test]
  async fn cleartext_info_verb_split_across_reads_upgrades() {
    let grants = nats_grants(
      "nats://agent:arkham_fake_nats_pass@nats.internal:4222",    // betterleaks:allow
      "nats://agent:real-nats-pass-is-longer@nats.upstream:4222", // betterleaks:allow
    );
    let first: &[u8] = b"INF";
    let second: &[u8] = b"O {\"tls_required\":true,\"tls_available\":false,\"tls_verify\":true}\r\nTAIL";
    let parts = [first, second];
    let mut server = SliceReads { parts: &parts, index: 0 };
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, true)
      .await
      .unwrap()
      .expect("info");
    assert!(opened.upgrade);
    assert_eq!(opened.rest, b"TAIL");
    let mut line = first.to_vec();
    line.extend_from_slice(&second[..second.len() - b"TAIL".len()]);
    assert_eq!(guest, line);
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
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, true)
      .await
      .unwrap()
      .expect("info");
    assert!(!opened.upgrade);
    assert_eq!(opened.rest, b"EXTRA");
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
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, false)
      .await
      .unwrap()
      .expect("info");
    assert_eq!(opened.rest, Vec::<u8>::new());
    assert!(!opened.upgrade);
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
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, false)
      .await
      .unwrap()
      .expect("info");
    assert_eq!(opened.rest, Vec::<u8>::new());
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, false)
      .await
      .unwrap()
      .expect("info");
    assert_eq!(opened.rest, Vec::<u8>::new());
    let line = nkey_connect(fake.public.as_str(), &sig_b64(&fake, b"N0NCE"));
    let (rewritten, hits) = down.feed(line.as_bytes()).await;
    assert_eq!(hits.len(), 0);
    let Rewritten::Emit(bytes) = rewritten else {
      panic!("forwarded connect");
    };
    assert_eq!(bytes.as_ref(), line.as_bytes());
    assert!(!line.contains(real.public.as_str()));
  }

  /// A close or an unreadable INFO does not arm a nonce. `tls_required` does.
  #[tokio::test]
  async fn closing_info_does_not_arm_a_nonce() {
    let (fake_raw, fake) = mint_user();
    let (real_raw, real) = mint_user();
    let grants = nats_grants(
      &format!("nats://nkey:{fake_raw}@nats.internal:4222"),
      &format!("nats://nkey:{real_raw}@nats.upstream:4222"),
    );
    let line = nkey_connect(fake.public.as_str(), &sig_b64(&fake, b"N0NCE"));
    let cases: Vec<OpeningFailure<'_>> = vec![
      (b"", |_| false),
      (b"INFO {\"nonce\":\"N0NCE\"\r\n", |err| {
        matches!(err, crate::Error::NatsInfoUnreadable)
      }),
    ];
    for (wire, expect_err) in cases {
      let mut server = Cursor::new(wire.to_vec());
      let mut guest = Vec::new();
      let mut up = Nats::upstream(&grants, "nats.internal", 4222);
      let mut down = Nats::downstream(&grants, "nats.internal", 4222);
      let opened = server_info(&mut server, &mut up, &mut down, &mut guest, true).await;
      if wire.is_empty() {
        assert_eq!(opened.unwrap().map(|opening| opening.rest), None);
      } else {
        let err = opened.unwrap_err();
        assert!(expect_err(&err), "{err}");
      }
      let (rewritten, hits) = down.feed(line.as_bytes()).await;
      assert!(hits.is_empty(), "{err_case}", err_case = String::from_utf8_lossy(wire));
      let Rewritten::Emit(bytes) = rewritten else {
        panic!("forwarded connect");
      };
      assert_eq!(bytes.as_ref(), line.as_bytes());
      assert!(
        !bytes
          .windows(real.public.as_str().len())
          .any(|window| window == real.public.as_bytes())
      );
    }

    let info = b"INFO {\"nonce\":\"N0NCE\",\"tls_required\":true}\r\n";
    let mut server = Cursor::new(info.to_vec());
    let mut guest = Vec::new();
    let mut up = Nats::upstream(&grants, "nats.internal", 4222);
    let mut down = Nats::downstream(&grants, "nats.internal", 4222);
    let opened = server_info(&mut server, &mut up, &mut down, &mut guest, true)
      .await
      .unwrap()
      .expect("info");
    assert!(opened.upgrade);
    assert_eq!(guest, info);
    let (rewritten, hits) = down.feed(line.as_bytes()).await;
    assert_eq!(hits.len(), 1);
    let Rewritten::Emit(bytes) = rewritten else {
      panic!("swapped connect");
    };
    assert_ne!(bytes.as_ref(), line.as_bytes());
    assert!(
      !bytes
        .windows(fake.public.as_str().len())
        .any(|window| window == fake.public.as_bytes())
    );
    assert!(
      bytes
        .windows(real.public.as_str().len())
        .any(|window| window == real.public.as_bytes())
    );
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
