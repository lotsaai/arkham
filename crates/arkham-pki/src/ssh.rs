//! SSH key material: the proxy's guest-leg host key and the decoy pairs the
//! agent mounts. Parsing, decoding, and host-key verification stay russh's;
//! this module owns generation and the exact file formats arkham writes.

use std::io::ErrorKind;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use rand::rngs::OsRng;
use russh::keys::decode_secret_key;
use russh::keys::known_hosts::known_host_keys_path;
use russh::keys::ssh_encoding::LineEnding;
use russh::keys::ssh_key::Algorithm;
use russh::keys::ssh_key::PrivateKey;
use russh::keys::ssh_key::PublicKey;

use crate::error::Error;

/// One ed25519 SSH key pair in the formats arkham writes: an openssh private
/// key file for storage and mounts, an `authorized_keys` line for admission.
#[derive(Debug, Clone)]
pub struct SshKey {
  key: PrivateKey,
}

impl SshKey {
  /// Generate a fresh ed25519 pair.
  ///
  /// # Errors
  ///
  /// Returns [`Error::SshKeygen`] when the backend refuses to generate.
  pub fn generate() -> Result<Self, Error> {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|source| Error::SshKeygen { source })?;
    Ok(Self { key })
  }

  /// Decode an unencrypted openssh private key from its file text.
  ///
  /// # Errors
  ///
  /// Returns [`Error::SshKeys`] when the text is not a readable key.
  pub fn from_openssh(text: &str) -> Result<Self, Error> {
    let key = decode_secret_key(text, None).map_err(|source| Error::SshKeys { source })?;
    Ok(Self { key })
  }

  /// The russh private key, for protocol legs that sign with it.
  #[must_use]
  pub fn into_private(self) -> PrivateKey {
    self.key
  }

  /// The pair as an openssh private key file.
  ///
  /// # Errors
  ///
  /// Returns [`Error::SshKeygen`] when encoding fails.
  pub fn to_openssh(&self) -> Result<String, Error> {
    let encoded = self
      .key
      .to_openssh(LineEnding::default())
      .map_err(|source| Error::SshKeygen { source })?;
    Ok(encoded.to_string())
  }

  /// The public half, for admission checks and rendering.
  #[must_use]
  pub fn public(&self) -> &PublicKey {
    self.key.public_key()
  }

  /// The public half as an `authorized_keys` line.
  ///
  /// # Errors
  ///
  /// Returns [`Error::SshKeygen`] when encoding fails.
  pub fn public_line(&self) -> Result<String, Error> {
    self.key.public_key().to_openssh().map_err(|source| Error::SshKeygen { source })
  }
}

/// The proxy's guest-leg host key at `path`, generated 0600 on first run.
/// The same load-or-generate contract as the CA, so serve and the decoy
/// `known_hosts` agree on one key.
///
/// # Errors
///
/// Returns an error when the file cannot be read or written, or when its
/// contents are not a readable key.
pub fn load_or_generate_host_key(path: &Path) -> Result<SshKey, Error> {
  match std::fs::read_to_string(path) {
    Ok(text) => SshKey::from_openssh(&text),
    Err(err) if err.kind() == ErrorKind::NotFound => generate_host_key(path),
    Err(source) => Err(Error::Io(source)),
  }
}

/// Generate the host key and persist it 0600; a concurrent writer's file
/// wins, so this reloads instead of overwriting it.
fn generate_host_key(path: &Path) -> Result<SshKey, Error> {
  let key = SshKey::generate()?;
  let encoded = key.to_openssh()?;
  if let Some(dir) = path.parent() {
    std::fs::create_dir_all(dir)?;
  }
  let written = std::fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .open(path)
    .and_then(|mut file| {
      file.write_all(encoded.as_bytes())?;
      file.sync_all()
    });
  match written {
    Ok(()) => Ok(key),
    Err(err) if err.kind() == ErrorKind::AlreadyExists => load_or_generate_host_key(path),
    Err(source) => Err(Error::Io(source)),
  }
}

/// One `known_hosts` line pinning `key` for `host:port`, OpenSSH's own shape:
/// `[host]:port` for non-default ports, the bare host for 22.
///
/// # Errors
///
/// Returns [`Error::SshKeygen`] when encoding the public key fails.
pub fn known_hosts_line_for_public(host: &str, port: u16, key: &PublicKey) -> Result<String, Error> {
  let name = if port == 22 { host.to_string() } else { format!("[{host}]:{port}") };
  Ok(format!(
    "{name} {}",
    key.to_openssh().map_err(|source| Error::SshKeygen { source })?
  ))
}

/// The public keys a `known_hosts` file pins for `host:port`, hashed entries
/// included. Empty when nothing pins the host: trust-on-first-use is the
/// caller's policy, never this lookup's.
///
/// # Errors
///
/// Returns [`Error::SshKeys`] when the file cannot be read or parsed.
pub fn pinned_host_keys(host: &str, port: u16, path: &Path) -> Result<Vec<(usize, PublicKey)>, Error> {
  known_host_keys_path(host, port, path).map_err(|source| Error::SshKeys { source })
}

/// Append a first-seen host key line, OpenSSH's `accept-new` recording half.
/// The caller owns the policy: this only writes, never verifies.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file cannot be written.
pub fn append_known_host(host: &str, port: u16, key: &PublicKey, path: &Path) -> Result<(), Error> {
  let line = known_hosts_line_for_public(host, port, key)?;
  if let Some(dir) = path.parent() {
    std::fs::create_dir_all(dir)?;
  }
  let mut text = std::fs::read_to_string(path).unwrap_or_default();
  if !text.is_empty() && !text.ends_with('\n') {
    text.push('\n');
  }
  text.push_str(&line);
  text.push('\n');
  std::fs::write(path, text)?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::fs;
  use std::os::unix::fs::PermissionsExt;

  use russh::keys::parse_public_key_base64;

  use super::*;

  #[test]
  fn generated_key_round_trips_through_openssh() {
    let key = SshKey::generate().unwrap();
    let text = key.to_openssh().unwrap();
    assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"), "{text}");
    let reloaded = SshKey::from_openssh(&text).unwrap();
    assert_eq!(reloaded.public(), key.public());
  }

  #[test]
  fn two_generations_differ() {
    let first = SshKey::generate().unwrap();
    let second = SshKey::generate().unwrap();
    assert_ne!(first.public(), second.public());
  }

  #[test]
  fn public_line_is_an_authorized_keys_line() {
    let key = SshKey::generate().unwrap();
    let line = key.public_line().unwrap();
    assert!(line.starts_with("ssh-ed25519 "), "{line}");
    let blob = line.split(' ').nth(1).unwrap();
    assert_eq!(&parse_public_key_base64(blob).unwrap(), key.public());
  }

  #[test]
  fn host_key_load_or_generate_is_stable_and_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh_host_ed25519");
    let first = load_or_generate_host_key(&path).unwrap();
    let second = load_or_generate_host_key(&path).unwrap();
    assert_eq!(first.public(), second.public(), "the second call reloads");
    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "key mode was {mode:o}");
  }

  #[test]
  fn known_hosts_line_renders_what_russh_reads_back() {
    let key = SshKey::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    fs::write(
      &path,
      format!("{}\n", known_hosts_line_for_public("git.example", 2222, key.public()).unwrap()),
    )
    .unwrap();
    let matched = known_host_keys_path("git.example", 2222, &path).unwrap();
    assert_eq!(matched.len(), 1);
    assert_eq!(&matched[0].1, key.public());

    let line = known_hosts_line_for_public("git.example", 22, key.public()).unwrap();
    assert!(line.starts_with("git.example ssh-ed25519 "), "{line}");
  }
}
