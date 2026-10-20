//! SSH vertical: the serve arm and the russh bridge — everything ssh owns.

pub(crate) mod legs;

use std::path::PathBuf;
use std::time::Duration;

use dashmap::DashMap;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};
use tokio::time::{Instant, timeout};

use arkham_config::grants::SshScope;
use arkham_config::grants::ssh_candidates;

use super::{ServeStream, Transport};
use crate::Error;
use crate::connection::Prefixed;
use crate::identity::CandidateParams;
use crate::transports::engine::{LegKeys, SshKeyPair, SshLegs, SshLegsFiles, Upstream};
use crate::transports::tcp;
/// The `ssh://` transport: the guest leg terminates here against a decoy
/// key, the upstream leg presents the real key. Disk keys are cached per
/// file triple; only the dial target assembles per connection.
#[derive(Default)]
pub(crate) struct SshTransport {
  keys: DashMap<(PathBuf, Vec<(PathBuf, PathBuf)>), LegKeys>,
}

impl SshTransport {
  /// Legs for one connection: cached disk keys over fresh dial state.
  fn legs(&self, files: SshLegsFiles<'_>, upstream: Upstream) -> Result<SshLegs, Error> {
    let mut pairs = Vec::with_capacity(files.extra.len().saturating_add(1));
    pairs.push((files.identity.to_path_buf(), files.guest_key.to_path_buf()));
    for extra in files.extra {
      pairs.push((extra.identity.to_path_buf(), extra.guest_key.to_path_buf()));
    }
    let key = (files.host_key.to_path_buf(), pairs);
    if let Some(cached) = self.keys.get(&key) {
      return Ok(SshLegs::from_keys(&cached, files.known_hosts, upstream));
    }
    let legs = SshLegs::load(files, upstream)?;
    self.keys.insert(key, legs.keys());
    Ok(legs)
  }
}
impl Transport for SshTransport {
  type Scope = SshScope;

  /// The `ssh://` arm. Only a banner announcing SSH-2.0 enters the leg;
  /// anything else on the port splices verbatim, because the scope does
  /// not own those bytes.
  async fn serve<G>(&self, ServeStream { mut guest, params, scope }: ServeStream<'_, G, SshScope>) -> Result<(), Error>
  where
    G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  {
    let CandidateParams {
      state,
      snapshot,
      dial_host,
      port,
      host,
      initial,
      ..
    } = params;
    let budget = Duration::from_secs(snapshot.proxy.handshake_timeout_secs);
    // The transparent capture arrives with nothing read yet; the banner
    // is the first bytes every ssh client sends, so the prefix decides leg
    // versus splice — an empty initial must not splice.
    let mut banner = initial.to_vec();
    let deadline = Instant::now() + budget;
    // The banner arrives in one segment in practice, but TCP does not
    // promise that: loop until the prefix is decided, not for one read.
    // Eight bytes settle it either way — a longer wait is a drip, not ssh.
    while banner.len() < 8 && b"SSH-2.0-".starts_with(&banner) {
      let remaining = deadline.saturating_duration_since(Instant::now());
      if remaining.is_zero() {
        return Ok(());
      }
      let mut buf = [0u8; 256];
      match timeout(remaining, guest.read(&mut buf)).await {
        Ok(Ok(0)) | Err(_) => return Ok(()),
        Ok(Err(source)) => return Err(source.into()),
        Ok(Ok(read)) => banner.extend_from_slice(&buf[..read]),
      }
    }
    if !banner.starts_with(b"SSH-2.0-") {
      return tcp::splice(guest, dial_host, port, state.fwmark, &banner).await;
    }
    let name = host.unwrap_or(dial_host).to_string();
    let config_dir = arkham_config::config::config_dir();
    let host_key_path = snapshot
      .proxy
      .ssh_host_key
      .clone()
      .or_else(|| config_dir.as_ref().map(|dir| dir.join("ssh_host_ed25519")))
      .ok_or(Error::SshHostKeyUnset)?;
    let known_hosts = snapshot
      .proxy
      .ssh_known_hosts
      .clone()
      .or_else(|| config_dir.map(|dir| dir.join("ssh_known_hosts")))
      .ok_or(Error::SshHostKeyUnset)?;
    let scopes = ssh_candidates(&snapshot.grants, host, port);
    let Some(first) = scopes.first() else {
      return Err(Error::SshNoIdentity { port: scope.port });
    };
    let extra: Vec<SshKeyPair<'_>> = scopes
      .iter()
      .skip(1)
      .map(|entry| SshKeyPair {
        identity: entry.identity.as_path(),
        guest_key: entry.guest_key.as_path(),
      })
      .collect();
    let legs = self.legs(
      SshLegsFiles {
        host_key: &host_key_path,
        identity: first.identity.as_path(),
        guest_key: first.guest_key.as_path(),
        extra: &extra,
        known_hosts: &known_hosts,
      },
      Upstream {
        host: dial_host.to_string(),
        port,
        name,
        fwmark: state.fwmark,
      },
    )?;
    legs.serve(Prefixed::new(banner, guest), budget).await
  }
}
