//! SSH legs: the guest's session terminates here against a decoy key, and
//! arkham opens its own upstream session presenting the real identity and
//! verifying the upstream host key OpenSSH-style: `accept-new` into arkham's
//! own `known_hosts`, changed keys rejected. Session channels bridge
//! request-for-request; exec, shell/pty, env, signals, and subsystems
//! forward, port and agent forwarding never opens, and only the decoy
//! public key ever authenticates.

use arkham_pki::ssh::append_known_host;
use arkham_pki::ssh::pinned_host_keys;
use russh::Channel;
use russh::ChannelMsg;
use russh::ChannelWriteHalf;
use russh::Error as RusshError;
use russh::client::Config as ClientConfig;
use russh::client::Handle;
use russh::client::Msg as ClientMsg;
use russh::client::connect_stream;
use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::decode_secret_key;
use russh::keys::parse_public_key_base64;
use russh::keys::ssh_key::PrivateKey;
use russh::keys::ssh_key::PublicKey;
use russh::server::Auth;
use russh::server::Config as ServerConfig;
use russh::server::Msg as ServerMsg;
use russh::server::Session;
use russh::server::run_stream;
use std::future::ready;
use std::io::Error as IoError;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

use crate::Error;
use crate::connection::dial_marked;

/// Inactivity timeout for both legs, as a multiple of the handshake budget:
/// an agent session idles far longer than a handshake takes, so the window
/// has to outlive the budget or long-lived sessions die mid-thought.
const INACTIVITY_BUDGET_MULTIPLE: u32 = 60;

/// One decoy the guest may offer, and the real identity that offer selects.
#[derive(Clone)]
struct SshCandidate {
  decoy: PublicKey,
  identity: Arc<PrivateKey>,
}

/// Everything one guest connection bridges between: the guest leg's trust,
/// the upstream identities the offered key selects, and where the session dials.
#[derive(Clone)]
pub(crate) struct SshLegs {
  /// Host key the guest verifies: arkham's own, presented by the guest leg.
  host_key: Arc<PrivateKey>,
  /// Decoy keys the guest may offer, in grant order. The signed offer picks one.
  candidates: Vec<SshCandidate>,
  /// Arkham's own upstream `known_hosts`, OpenSSH `accept-new` semantics:
  /// first-seen keys are recorded, a changed key on a known host fails.
  known_hosts: PathBuf,
  /// Where and how the upstream leg dials.
  upstream: Upstream,
}

/// The upstream dial target.
#[derive(Clone)]
pub(crate) struct Upstream {
  /// Dial host.
  pub(crate) host: String,
  /// Dial port.
  pub(crate) port: u16,
  /// Hostname the pinned keys are recorded for.
  pub(crate) name: String,
  /// fwmark excluding the dial from capture.
  pub(crate) fwmark: Option<u32>,
}

/// One identity file and the decoy public key that selects it.
#[derive(Clone, Copy)]
pub(crate) struct SshKeyPair<'a> {
  /// Identity arkham presents upstream when this decoy is offered.
  pub(crate) identity: &'a Path,
  /// Decoy public key the guest leg admits.
  pub(crate) guest_key: &'a Path,
}

/// The files one guest connection's legs need: the guest host key, one or
/// more identity pairs, and arkham's own `known_hosts`.
#[derive(Clone, Copy)]
pub(crate) struct SshLegsFiles<'a> {
  /// Host key the guest verifies, generated on first run.
  pub(crate) host_key: &'a Path,
  /// Identity arkham presents upstream for [`Self::guest_key`].
  pub(crate) identity: &'a Path,
  /// Decoy public key paired with [`Self::identity`].
  pub(crate) guest_key: &'a Path,
  /// Further identity pairs, after the first.
  pub(crate) extra: &'a [SshKeyPair<'a>],
  /// Arkham's own upstream `known_hosts`.
  pub(crate) known_hosts: &'a Path,
}

/// Disk-loaded keys shared across connections on the same key files: the
/// guest host key, the decoy admission key, and the real upstream identity.
/// Key files are config-immutable at runtime, so one load per file triple.
#[derive(Clone)]
pub(crate) struct LegKeys {
  host_key: Arc<PrivateKey>,
  candidates: Vec<SshCandidate>,
}

fn load_candidate(pair: SshKeyPair<'_>) -> Result<SshCandidate, Error> {
  let identity_text = std::fs::read_to_string(pair.identity).map_err(|source| Error::SshRead {
    path: pair.identity.to_path_buf(),
    source,
  })?;
  let identity = Arc::new(decode_secret_key(&identity_text, None).map_err(RusshError::from)?);
  let guest_line = std::fs::read_to_string(pair.guest_key).map_err(|source| Error::SshRead {
    path: pair.guest_key.to_path_buf(),
    source,
  })?;
  let blob = guest_line.split(' ').nth(1).unwrap_or_default();
  let decoy = parse_public_key_base64(blob).map_err(RusshError::from)?;
  Ok(SshCandidate { decoy, identity })
}

impl LegKeys {
  /// Load every key the two legs need: the guest host key (generated on
  /// first run, the CA's load-or-generate contract), the real identity, and
  /// the decoy admission key from the grant's blobs.
  ///
  /// # Errors
  ///
  /// Returns an error when the host key cannot be generated or loaded, or
  /// when either key file cannot be read or parsed.
  pub(crate) fn load(files: SshLegsFiles<'_>) -> Result<Self, Error> {
    let host_key = Arc::new(arkham_pki::load_or_generate_host_key(files.host_key)?.into_private());
    let mut pairs = Vec::with_capacity(files.extra.len().saturating_add(1));
    pairs.push(SshKeyPair {
      identity: files.identity,
      guest_key: files.guest_key,
    });
    pairs.extend_from_slice(files.extra);
    let mut candidates = Vec::with_capacity(pairs.len());
    for pair in pairs {
      candidates.push(load_candidate(pair)?);
    }
    Ok(Self { host_key, candidates })
  }

  /// Legs for one connection's dial target over these shared keys.
  fn assemble(&self, known_hosts: &Path, upstream: Upstream) -> SshLegs {
    SshLegs {
      host_key: Arc::clone(&self.host_key),
      candidates: self.candidates.clone(),
      known_hosts: known_hosts.to_path_buf(),
      upstream,
    }
  }
}

impl SshLegs {
  /// Load every key the two legs need: the guest host key (generated on
  /// first run, the CA's load-or-generate contract), the real identity, and
  /// the decoy admission key from the grant's blobs.
  ///
  /// # Errors
  ///
  /// Returns an error when the host key cannot be generated or loaded, or
  /// when either key file cannot be read or parsed.
  pub(crate) fn load(files: SshLegsFiles<'_>, upstream: Upstream) -> Result<Self, Error> {
    Ok(LegKeys::load(files)?.assemble(files.known_hosts, upstream))
  }

  /// Legs over already-loaded keys: the transport's per-file cache path.
  pub(crate) fn from_keys(keys: &LegKeys, known_hosts: &Path, upstream: Upstream) -> Self {
    keys.assemble(known_hosts, upstream)
  }

  /// The disk-loaded keys behind these legs, for the transport cache.
  pub(crate) fn keys(&self) -> LegKeys {
    LegKeys {
      host_key: Arc::clone(&self.host_key),
      candidates: self.candidates.clone(),
    }
  }

  /// Terminate the guest's session and bridge its channels upstream.
  ///
  /// # Errors
  ///
  /// Returns an error when either leg's protocol fails.
  pub(crate) async fn serve<G>(self, guest: G, budget: Duration) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let config = Arc::new(ServerConfig {
      keys: vec![(*self.host_key).clone()],
      inactivity_timeout: Some(budget * INACTIVITY_BUDGET_MULTIPLE),
      ..ServerConfig::default()
    });
    let handler = Guest {
      legs: self,
      user: String::new(),
      selected: None,
      upstream: None,
      budget,
    };
    let session = run_stream(config, guest, handler).await?;
    session.await?;
    Ok(())
  }
}

/// The guest leg: admit only the decoy key, bridge every session channel.
struct Guest {
  legs: SshLegs,
  user: String,
  /// Real identity selected by the signed public key offer.
  selected: Option<Arc<PrivateKey>>,
  upstream: Option<Handle<UpstreamLeg>>,
  budget: Duration,
}
impl russh::server::Handler for Guest {
  type Error = RusshError;
  fn auth_publickey_offered(&mut self, _user: &str, public_key: &PublicKey) -> impl Future<Output = Result<Auth, Self::Error>> {
    tracing::debug!(key = ?public_key.to_openssh(), "ssh guest leg: key offered");
    let auth = if self.legs.candidates.iter().any(|candidate| candidate.decoy == *public_key) {
      Auth::Accept
    } else {
      Auth::reject()
    };
    ready(Ok(auth))
  }

  fn auth_publickey(&mut self, user: &str, public_key: &PublicKey) -> impl Future<Output = Result<Auth, Self::Error>> {
    tracing::debug!(key = ?public_key.to_openssh(), "ssh guest leg: signed auth");
    let auth = if let Some(candidate) = self.legs.candidates.iter().find(|candidate| candidate.decoy == *public_key) {
      self.user = user.to_string();
      self.selected = Some(Arc::clone(&candidate.identity));
      Auth::Accept
    } else {
      Auth::reject()
    };
    ready(Ok(auth))
  }

  fn auth_password(&mut self, _user: &str, _password: &str) -> impl Future<Output = Result<Auth, Self::Error>> {
    ready(Ok(Auth::reject()))
  }
  async fn channel_open_session(&mut self, mut channel: Channel<ServerMsg>, session: &mut Session) -> Result<bool, Self::Error> {
    if self.upstream.is_none() {
      let handle = self.dial_upstream().await?;
      self.upstream = Some(handle);
    }
    // The slot was filled just above; an empty read still closes the
    // channel quietly instead of panicking.
    let Some(upstream) = self.upstream.as_ref() else {
      return Ok(false);
    };
    let remote = upstream.channel_open_session().await?;
    let (mut read, write) = remote.split();
    let guest_id = channel.id();
    let guest_writer = session.handle();

    let pump_writer = Arc::new(write);
    let bridge_writer = Arc::clone(&pump_writer);
    tokio::spawn(async move {
      while let Some(message) = channel.wait().await {
        if !forward_guest_message(&bridge_writer, message).await {
          break;
        }
      }
    });
    tokio::spawn(async move {
      loop {
        let Some(message) = read.wait().await else {
          break;
        };

        match message {
          ChannelMsg::Data { data } => {
            if guest_writer.data(guest_id, data).await.is_err() {
              break;
            }
          }
          ChannelMsg::ExtendedData { data, ext } => {
            if guest_writer.extended_data(guest_id, ext, data).await.is_err() {
              break;
            }
          }
          ChannelMsg::ExitStatus { exit_status } => {
            let _ = guest_writer.exit_status_request(guest_id, exit_status).await;
          }
          // Replies to want_reply requests (exec, pty, subsystem): OpenSSH
          // clients wait for these before treating the request as served.
          ChannelMsg::Success => {
            let _ = guest_writer.channel_success(guest_id).await;
          }
          ChannelMsg::Failure => {
            let _ = guest_writer.channel_failure(guest_id).await;
          }
          ChannelMsg::Eof => {
            let _ = guest_writer.eof(guest_id).await;
          }
          ChannelMsg::Close | ChannelMsg::OpenFailure(_) => {
            let _ = guest_writer.close(guest_id).await;
            break;
          }
          _ => {}
        }
      }
      // However the upstream channel ended, the guest channel ends too.
      let _ = guest_writer.close(guest_id).await;
      let _ = pump_writer.close().await;
    });
    Ok(true)
  }
}

impl Guest {
  /// Dial and authenticate the upstream session once per guest connection:
  /// the real identity presented, the server verified against the pinned
  /// host keys, the whole dial under the handshake budget.
  async fn dial_upstream(&self) -> Result<Handle<UpstreamLeg>, RusshError> {
    let legs = self.legs.clone();
    let budget = self.budget;
    let user = self.user.clone();
    let Some(identity) = self.selected.clone() else {
      return Err(RusshError::UnknownKey);
    };
    let dial = async move {
      let stream = dial_marked(&legs.upstream.host, legs.upstream.port, legs.upstream.fwmark)
        .await
        .map_err(russh_io)?;
      let config = Arc::new(ClientConfig {
        inactivity_timeout: Some(budget * INACTIVITY_BUDGET_MULTIPLE),
        ..ClientConfig::default()
      });
      let handler = UpstreamLeg {
        known_hosts: legs.known_hosts.clone(),
        name: legs.upstream.name.clone(),
        port: legs.upstream.port,
      };
      let mut handle = connect_stream(config, stream, handler).await?;
      let auth = PrivateKeyWithHashAlg::new(identity, None);
      if !handle.authenticate_publickey(user, auth).await?.success() {
        return Err(RusshError::UnknownKey);
      }
      Ok(handle)
    };
    tokio::time::timeout(budget, dial).await.map_err(RusshError::Elapsed)?
  }
}

async fn forward_guest_message(upstream: &ChannelWriteHalf<ClientMsg>, message: ChannelMsg) -> bool {
  let (closed, failed) = match message {
    ChannelMsg::Exec { want_reply, command } => (false, upstream.exec(want_reply, command).await.is_err()),
    ChannelMsg::RequestShell { want_reply } => (false, upstream.request_shell(want_reply).await.is_err()),
    ChannelMsg::RequestPty {
      want_reply,
      term,
      col_width,
      row_height,
      pix_width,
      pix_height,
      terminal_modes,
    } => (
      false,
      upstream
        .request_pty(want_reply, &term, col_width, row_height, pix_width, pix_height, &terminal_modes)
        .await
        .is_err(),
    ),
    ChannelMsg::RequestSubsystem { want_reply, name } => (false, upstream.request_subsystem(want_reply, name).await.is_err()),
    ChannelMsg::SetEnv {
      want_reply,
      variable_name,
      variable_value,
    } => (false, upstream.set_env(want_reply, variable_name, variable_value).await.is_err()),
    ChannelMsg::WindowChange {
      col_width,
      row_height,
      pix_width,
      pix_height,
    } => (
      false,
      upstream.window_change(col_width, row_height, pix_width, pix_height).await.is_err(),
    ),
    ChannelMsg::Signal { signal } => (false, upstream.signal(signal).await.is_err()),
    ChannelMsg::Data { data } => (false, upstream.data(&*data).await.is_err()),
    ChannelMsg::ExtendedData { data, ext } => (false, upstream.extended_data(ext, &*data).await.is_err()),
    ChannelMsg::Eof => (false, upstream.eof().await.is_err()),
    ChannelMsg::Close => (true, upstream.close().await.is_err()),
    // Port and agent forwarding, X11: never forwarded.
    _ => (false, false),
  };
  !closed && !failed
}
/// Russh's handler traits fix their error type; `IO` is the only carrier
/// that reaches the caller with a message. One wrapper keeps the erasure
/// deliberate instead of scattering it.
fn russh_io(source: impl std::fmt::Display) -> RusshError {
  RusshError::IO(IoError::other(source.to_string()))
}

/// The upstream leg: OpenSSH `accept-new`. A first-seen host key is
/// recorded in arkham's own `known_hosts` — ssh's mechanism is the allowlist —
/// a matching pin verifies, and a changed key on a known host fails.
struct UpstreamLeg {
  known_hosts: PathBuf,
  name: String,
  port: u16,
}

impl russh::client::Handler for UpstreamLeg {
  type Error = RusshError;

  fn check_server_key(&mut self, server_public_key: &PublicKey) -> impl Future<Output = Result<bool, Self::Error>> {
    ready(self.verify_server_key(server_public_key))
  }
}

impl UpstreamLeg {
  /// Verify the upstream host key OpenSSH `accept-new`: a first-seen key
  /// is recorded, a matching pin verifies, a changed key on a known host
  /// fails.
  fn verify_server_key(&self, server_public_key: &PublicKey) -> Result<bool, RusshError> {
    let pinned = pinned_host_keys(&self.name, self.port, &self.known_hosts).map_err(russh_io)?;
    if pinned.is_empty() {
      append_known_host(&self.name, self.port, server_public_key, &self.known_hosts).map_err(russh_io)?;
      return Ok(true);
    }
    Ok(pinned.iter().any(|(_, known)| known == server_public_key))
  }
}

#[cfg(test)]
mod tests {
  use russh::CryptoVec;

  use super::*;
  use arkham_pki::ssh::SshKey;
  use arkham_pki::ssh::known_hosts_line_for_public;
  use std::process::ExitStatus;
  use tokio::net::TcpStream;

  /// An upstream stub that admits only the real key and echoes exec output.
  struct Stub {
    /// The only key the stub admits.
    admit: PublicKey,
    /// The key the stub last saw, shared with the test.
    saw_key: Arc<std::sync::Mutex<Option<PublicKey>>>,
  }

  impl russh::server::Handler for Stub {
    type Error = RusshError;

    fn auth_publickey(&mut self, _user: &str, public_key: &PublicKey) -> impl Future<Output = Result<Auth, Self::Error>> {
      *self.saw_key.lock().expect("stub mutex") = Some(public_key.clone());
      ready(Ok(if *public_key == self.admit { Auth::Accept } else { Auth::reject() }))
    }

    fn channel_open_session(
      &mut self,
      mut channel: Channel<ServerMsg>,
      session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> {
      let writer = session.handle();
      let id = channel.id();
      tokio::spawn(async move {
        while let Some(message) = channel.wait().await {
          if let ChannelMsg::Exec { command, .. } = message {
            // A real sshd answers the request before any output; OpenSSH
            // clients wait for that reply.
            let _ = writer.channel_success(id).await;
            let reply = format!("ok:{}", String::from_utf8_lossy(&command));
            let _ = writer.data(id, CryptoVec::from(reply)).await;
            let _ = writer.exit_status_request(id, 0).await;
            let _ = writer.eof(id).await;
            let _ = writer.close(id).await;
            break;
          }
        }
      });
      ready(Ok(true))
    }
  }

  /// A guest client that accepts any server key: the guest side of the test.
  struct Client;

  impl russh::client::Handler for Client {
    type Error = RusshError;

    fn check_server_key(&mut self, _server_public_key: &PublicKey) -> impl Future<Output = Result<bool, Self::Error>> {
      ready(Ok(true))
    }
  }

  #[tokio::test]
  async fn decoy_key_reaches_upstream_as_the_real_key() {
    let real = SshKey::generate().unwrap();
    let decoy = SshKey::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let stub_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = stub_listener.local_addr().unwrap();
    let saw_key = Arc::new(std::sync::Mutex::new(None));
    let stub_saw = Arc::clone(&saw_key);
    let admit = real.public().clone();
    let stub_key = SshKey::generate().unwrap();
    let stub_public = stub_key.public().clone();
    tokio::spawn(async move {
      let (socket, _) = stub_listener.accept().await.unwrap();
      let config = Arc::new(ServerConfig {
        keys: vec![stub_key.into_private()],
        ..ServerConfig::default()
      });
      let handler = Stub {
        admit: admit.clone(),
        saw_key: stub_saw,
      };
      // Arkham's own known_hosts starts absent: the first upstream connection
      let _ = run_stream(config, socket, handler).await.unwrap().await;
    });

    // Arkham's own known_hosts starts absent: the first upstream connection
    // must trust-on-first-use record the stub's key, ssh's accept-new.
    let known_hosts = dir.path().join("known_hosts");
    let guest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let guest_addr = guest_listener.local_addr().unwrap();
    let legs = SshLegs::load(
      SshLegsFiles {
        host_key: &dir.path().join("ssh_host"),
        identity: &write_key(&dir, "identity", &real),
        guest_key: &write_key(&dir, "guest", &decoy),
        extra: &[],
        known_hosts: &known_hosts,
      },
      Upstream {
        host: stub_addr.ip().to_string(),
        port: stub_addr.port(),
        name: "stub.local".to_string(),
        fwmark: None,
      },
    )
    .unwrap();
    tokio::spawn(async move {
      loop {
        let Ok((socket, _)) = guest_listener.accept().await else {
          break;
        };
        let legs = legs.clone();
        tokio::spawn(async move {
          let _ = legs.serve(socket, Duration::from_secs(10)).await;
        });
      }
    });

    let socket = TcpStream::connect(guest_addr).await.unwrap();
    let config = Arc::new(ClientConfig::default());
    let mut session = connect_stream(config, socket, Client).await.unwrap();
    assert!(
      session
        .authenticate_publickey("deploy", PrivateKeyWithHashAlg::new(Arc::new(decoy.into_private()), None))
        .await
        .unwrap()
        .success()
    );
    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(true, "marker").await.unwrap();
    let mut output = Vec::new();
    while let Some(message) = channel.wait().await {
      match message {
        ChannelMsg::Data { data } => output.extend_from_slice(&data),
        ChannelMsg::ExitStatus { exit_status } => {
          assert_eq!(exit_status, 0);
          break;
        }
        ChannelMsg::Close | ChannelMsg::OpenFailure(_) => break,
        _ => {}
      }
    }
    assert_eq!(output, b"ok:marker");
    // The stub's key was unknown; accept-new must have recorded it.
    let learned = std::fs::read_to_string(&known_hosts).unwrap();
    assert!(
      learned.contains(&stub_public.to_openssh().unwrap()),
      "accept-new recorded the stub key: {learned}"
    );
    let seen = saw_key.lock().expect("stub mutex").clone();
    assert_eq!(seen, Some(real.public().clone()), "the stub saw the real key");
  }

  #[tokio::test]
  async fn changed_host_key_fails_closed() {
    let real = SshKey::generate().unwrap();
    let decoy = SshKey::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let stub_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = stub_listener.local_addr().unwrap();
    let admit = real.public().clone();
    let stub_key = SshKey::generate().unwrap();
    let saw_key = Arc::new(std::sync::Mutex::new(None));
    let stub_saw = Arc::clone(&saw_key);
    tokio::spawn(async move {
      let (socket, _) = stub_listener.accept().await.unwrap();
      let config = Arc::new(ServerConfig {
        keys: vec![stub_key.into_private()],
        ..ServerConfig::default()
      });
      let handler = Stub {
        admit: admit.clone(),
        saw_key: stub_saw,
      };
      let _ = run_stream(config, socket, handler).await.unwrap().await;
    });

    // The guest authenticates with the right decoy, but arkham's
    // known_hosts already pins a different key for the stub: accept-new
    // must not swallow a changed key, the session dies.
    let known_hosts = dir.path().join("known_hosts");
    let other = SshKey::generate().unwrap();
    let stale_line = known_hosts_line_for_public("stub.local", stub_addr.port(), other.public()).unwrap();
    std::fs::write(&known_hosts, format!("{stale_line}\n")).unwrap();

    let guest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let guest_addr = guest_listener.local_addr().unwrap();
    let legs = SshLegs::load(
      SshLegsFiles {
        host_key: &dir.path().join("ssh_host"),
        identity: &write_key(&dir, "identity", &real),
        guest_key: &write_key(&dir, "guest", &decoy),
        extra: &[],
        known_hosts: &known_hosts,
      },
      Upstream {
        host: stub_addr.ip().to_string(),
        port: stub_addr.port(),
        name: "stub.local".to_string(),
        fwmark: None,
      },
    )
    .unwrap();
    tokio::spawn(async move {
      let (socket, _) = guest_listener.accept().await.unwrap();
      let _ = legs.serve(socket, Duration::from_secs(10)).await;
    });

    let socket = TcpStream::connect(guest_addr).await.unwrap();
    let config = Arc::new(ClientConfig::default());
    let mut session = connect_stream(config, socket, Client).await.unwrap();
    assert!(
      session
        .authenticate_publickey("deploy", PrivateKeyWithHashAlg::new(Arc::new(decoy.into_private()), None))
        .await
        .unwrap()
        .success()
    );
    // The upstream leg rejects the changed key, so the channel never opens.
    session.channel_open_session().await.unwrap_err();
    // And the stale pin was not overwritten.
    let recorded = std::fs::read_to_string(&known_hosts).unwrap();
    assert_eq!(recorded, format!("{stale_line}\n"), "a changed key never rewrites the pin");
  }

  fn write_key(dir: &tempfile::TempDir, name: &str, key: &SshKey) -> PathBuf {
    // `guest` is the guest-leg admission blob (authorized_keys line);
    // every other name is a private key file a client or arkham presents.
    let text = if name == "guest" {
      key.public_line().unwrap()
    } else {
      key.to_openssh().unwrap()
    };
    let path = dir.path().join(name);
    std::fs::write(&path, text).unwrap();
    if name != "guest" {
      use std::os::unix::fs::PermissionsExt;
      std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
  }

  /// A real openssh client, not a russh mirror: it probes with an unsigned
  /// key offer before signing, negotiates current KEX, and verifies host
  /// keys exactly like a production agent. The russh-in-process tests above
  /// cannot catch offer-phase incompatibilities.
  #[test]
  fn openssh_client_exec_reaches_upstream_as_the_real_key() {
    let ssh = std::env::var_os("ARKHAM_TEST_SSH_BIN")
      .map(PathBuf::from)
      .or_else(which_ssh)
      .expect("an openssh client binary is required (install openssh-client); ARKHAM_TEST_SSH_BIN overrides");
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async move {
      let real = SshKey::generate().unwrap();
      let decoy = SshKey::generate().unwrap();
      let dir = tempfile::tempdir().unwrap();

      let stub_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
      let stub_addr = stub_listener.local_addr().unwrap();
      let saw_key = Arc::new(std::sync::Mutex::new(None));
      let stub_saw = Arc::clone(&saw_key);
      let admit = real.public().clone();
      let stub_key = SshKey::generate().unwrap();
      tokio::spawn(async move {
        let (socket, _) = stub_listener.accept().await.unwrap();
        let config = Arc::new(ServerConfig {
          keys: vec![stub_key.into_private()],
          ..ServerConfig::default()
        });
        let handler = Stub {
          admit: admit.clone(),
          saw_key: stub_saw,
        };
        let _ = run_stream(config, socket, handler).await.unwrap().await;
      });

      let known_hosts = dir.path().join("known_hosts");
      let guest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
      let guest_addr = guest_listener.local_addr().unwrap();
      let legs = SshLegs::load(
        SshLegsFiles {
          host_key: &dir.path().join("ssh_host"),
          identity: &write_key(&dir, "identity", &real),
          guest_key: &write_key(&dir, "guest", &decoy),
          extra: &[],
          known_hosts: &known_hosts,
        },
        Upstream {
          host: stub_addr.ip().to_string(),
          port: stub_addr.port(),
          name: "stub.local".to_string(),
          fwmark: None,
        },
      )
      .unwrap();
      let serve_legs = legs.clone();
      tokio::spawn(async move {
        while let Ok((socket, _)) = guest_listener.accept().await {
          let legs = serve_legs.clone();
          tokio::spawn(async move {
            let _ = legs.serve(socket, Duration::from_secs(10)).await;
          });
        }
      });

      let ssh_log = dir.path().join("ssh.log");
      let args = vec![
        "-vvv".to_string(),
        "-E".to_string(),
        ssh_log.to_string_lossy().into_owned(),
        "-F".to_string(),
        "/dev/null".to_string(),
        "-i".to_string(),
        write_key(&dir, "client_decoy", &decoy).to_string_lossy().into_owned(),
        "-o".to_string(),
        "IdentitiesOnly=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        format!("UserKnownHostsFile={}", dir.path().join("client_known_hosts").display()),
        "-o".to_string(),
        "GlobalKnownHostsFile=/dev/null".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-p".to_string(),
        guest_addr.port().to_string(),
        "deploy@127.0.0.1".to_string(),
        "echo".to_string(),
        "marker".to_string(),
      ];
      let ssh_client = tokio::task::spawn_blocking(move || run_ssh_client(&ssh, &args));
      let log = std::fs::read_to_string(&ssh_log).unwrap_or_default();
      let Some((status, stdout, stderr)) = ssh_client.await.expect("the client thread joins") else {
        panic!("ssh client hung; protocol log:\n{log}");
      };
      assert!(status.success(), "ssh failed: {stderr}\nprotocol log:\n{log}");
      assert_eq!(stdout, "ok:echo marker", "protocol log:\n{log}");
      // The upstream stub observed the real key: decoy in, real out.
      let seen = saw_key.lock().expect("stub mutex").clone();
      assert_eq!(seen, Some(real.public().clone()), "the stub saw the real key; log:\n{log}");
      // And arkham's upstream TOFU file recorded the stub's host key.
      let learned = std::fs::read_to_string(&known_hosts).unwrap();
      assert!(learned.contains("stub.local"), "accept-new recorded the upstream: {learned}");
    });
  }

  /// Run the openssh client to completion, bounded to ~20s. A stuck bridge
  /// shows up as a hang, not an error, and the caller reports the client's
  /// own protocol log either way.
  fn run_ssh_client(ssh: &Path, args: &[String]) -> Option<(ExitStatus, String, String)> {
    use std::io::Read;
    let mut child = std::process::Command::new(ssh)
      .args(args)
      .env_remove("SSH_AUTH_SOCK")
      .stdout(std::process::Stdio::piped())
      .stderr(std::process::Stdio::piped())
      .spawn()
      .expect("the ssh client runs");
    for _ in 0..200 {
      if let Some(status) = child.try_wait().expect("the client is pollable") {
        let mut stdout = String::new();
        let mut stderr = String::new();
        child
          .stdout
          .take()
          .expect("stdout piped")
          .read_to_string(&mut stdout)
          .expect("stdout read");
        child
          .stderr
          .take()
          .expect("stderr piped")
          .read_to_string(&mut stderr)
          .expect("stderr read");
        return Some((status, stdout, stderr));
      }
      std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    None
  }

  fn which_ssh() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
      .map(|dir| dir.join("ssh"))
      .find(|candidate| candidate.is_file())
  }
}
