//! Per-context grant identity.
//!
//! [`identities`] names a subject. [`require_distinct`] rejects two subjects that share a destination and a decoy. [`crate::grants::Grant::matches`] stays the host matcher.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use strum::{Display, IntoStaticStr};

use crate::config::fake_for;
use crate::error::Error;

/// Protocol tag stored in a context label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, IntoStaticStr)]
pub enum AmbientProtocol {
  /// Bearer and client certificate for one kube user. Tag `kube-user`.
  #[strum(serialize = "kube-user")]
  KubernetesUser,
  /// CA blob for one kube cluster. Tag `kube-cluster`.
  #[strum(serialize = "kube-cluster")]
  KubernetesCluster,
  /// One Talos context. Tag `talos`.
  #[strum(serialize = "talos")]
  Talos,
  /// One NATS context. Tag `nats`.
  #[strum(serialize = "nats")]
  Nats,
  /// One SSH host block. Tag `ssh`.
  #[strum(serialize = "ssh")]
  Ssh,
}

impl AmbientProtocol {
  /// Stable tag stored in the label and in the canonical bytes.
  #[must_use]
  pub fn tag(self) -> &'static str {
    <&'static str>::from(self)
  }
}

/// Guest leaf file written beside a context's client certificate.
#[must_use]
pub fn guest_cert_file(label: &str) -> String {
  format!("{label}.guest.crt")
}

/// `{label}.guest.crt` beside a `{label}.client.crt` path.
#[must_use]
pub fn guest_cert_path(client_cert: &Path) -> Option<PathBuf> {
  let name = client_cert.file_name()?.to_str()?;
  let label = name.strip_suffix(".client.crt")?;
  Some(client_cert.with_file_name(guest_cert_file(label)))
}

/// Why a source path cannot identify a context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathFault {
  /// The path is empty.
  #[error("is empty")]
  Empty,
  /// The path is not Unicode.
  #[error("is not unicode")]
  NotUnicode,
  /// The path contains U+001F.
  #[error("contains a unit separator")]
  UnitSeparator,
}

/// Why a context name cannot become a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NameFault {
  /// The name is empty.
  #[error("is empty")]
  Empty,
  /// The name contains U+001F.
  #[error("contains a unit separator")]
  UnitSeparator,
}

/// One source record passed to [`identities`]. The path is stored as given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextRef<'a> {
  /// File the adapter read.
  pub source: &'a Path,
  /// Protocol this name belongs to.
  pub protocol: AmbientProtocol,
  /// Name as it appears in the source file.
  pub name: &'a str,
}

/// Label, env, and decoy for one subject.
#[derive(Clone)]
pub struct ContextIdentity {
  /// Protocol this identity was built with.
  pub protocol: AmbientProtocol,
  /// Path passed to [`identities`].
  pub source: PathBuf,
  /// Original name, including case and punctuation.
  pub name: String,
  /// Grant label and client-pair stem.
  pub label: String,
  key_seed: [u8; 32],
}

impl fmt::Debug for ContextIdentity {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ContextIdentity")
      .field("protocol", &self.protocol)
      .field("source", &self.source)
      .field("name", &self.name)
      .field("label", &self.label)
      .field("key_seed", &"<redacted>")
      .finish()
  }
}

impl ContextIdentity {
  /// Env name. [`crate::config::fake_for`] seed for this subject.
  #[must_use]
  pub fn env(&self) -> String {
    self.label.replace('-', "_").to_ascii_uppercase()
  }

  /// Bearer, password, or token. [`crate::config::fake_for`] of [`Self::env`] with no pattern.
  #[must_use]
  pub fn secret(&self) -> String {
    fake_for(&self.env(), None)
  }

  /// 32-byte ed25519 seed. SHA-256 of the canonical bytes.
  #[must_use]
  pub fn key_seed(&self) -> &[u8; 32] {
    &self.key_seed
  }
}

/// One identity presented at one destination.
#[derive(Debug, Clone, Copy)]
pub struct Presented<'a> {
  /// Identity under test.
  pub identity: &'a ContextIdentity,
  /// Destination host. [`require_distinct`] trims it and lowercases ASCII.
  pub host: &'a str,
  /// Destination port.
  pub port: u16,
  /// Decoy bytes the guest presents. An empty slice still compares.
  pub decoy: &'a [u8],
}

/// One context named by a collision or an ambiguity error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousParty {
  /// Protocol of that context.
  pub protocol: AmbientProtocol,
  /// Original name.
  pub name: String,
  /// Source path.
  pub source: PathBuf,
}

impl fmt::Display for AmbiguousParty {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "`{}` ({}, {})", self.name, self.source.display(), self.protocol)
  }
}

/// Two or more contexts that share a label. `parties` is sorted by path, name, and tag.
#[derive(Debug, thiserror::Error)]
#[error("contexts {} share `{shared}`", join_parties(&self.parties))]
pub struct ContextCollision {
  /// Contexts that share the label. At least two.
  pub parties: Vec<AmbiguousParty>,
  /// Shared label.
  pub shared: String,
}

/// Contexts that present the same host, port, and decoy bytes. `parties` is sorted by path, name, and tag.
#[derive(Debug, thiserror::Error)]
#[error("contexts {} at {host}:{port} are indistinguishable", join_parties(&self.parties))]
pub struct AmbiguousContexts {
  /// Contexts in the group. At least two.
  pub parties: Vec<AmbiguousParty>,
  /// Lowercased destination host.
  pub host: String,
  /// Destination port the caller supplied.
  pub port: u16,
}

/// Labels and decoy seeds for `refs`, in input order. A repeated path, protocol, and name keeps the first record.
///
/// # Errors
///
/// Returns [`Error::ContextPathInvalid`], [`Error::ContextNameInvalid`], or [`Error::ContextCollision`].
pub fn identities(refs: &[ContextRef<'_>]) -> Result<Vec<ContextIdentity>, Error> {
  let mut built = Vec::with_capacity(refs.len());
  for reference in refs {
    if built
      .iter()
      .any(|existing| same_subject(existing, reference.protocol, reference.source, reference.name))
    {
      continue;
    }
    built.push(build_identity(reference.source, reference.protocol, reference.name)?);
  }
  ensure_distinct(&built)?;
  Ok(built)
}

/// Fail when two different identities share a trimmed, lowercased host, a port, and the same decoy bytes.
///
/// # Errors
///
/// Returns [`Error::WireHostEmpty`] or [`Error::AmbiguousContexts`]. The same identity repeated is success. Ports are not defaulted.
pub fn require_distinct(presented: &[Presented<'_>]) -> Result<(), Error> {
  let mut groups: BTreeMap<(String, u16, &[u8]), Vec<&ContextIdentity>> = BTreeMap::new();
  for item in presented {
    let host = item.host.trim().to_ascii_lowercase();
    if host.is_empty() {
      return Err(Error::WireHostEmpty);
    }
    let group = groups.entry((host, item.port, item.decoy)).or_default();
    if group
      .iter()
      .any(|existing| same_subject(existing, item.identity.protocol, &item.identity.source, &item.identity.name))
    {
      continue;
    }
    group.push(item.identity);
  }
  for ((host, port, _), group) in groups {
    if group.len() < 2 {
      continue;
    }
    let parties = parties_from(group);
    return Err(Error::AmbiguousContexts(Box::new(AmbiguousContexts { parties, host, port })));
  }
  Ok(())
}

fn ensure_distinct(built: &[ContextIdentity]) -> Result<(), Error> {
  for (index, identity) in built.iter().enumerate() {
    for previous in built.iter().take(index) {
      if same_subject(previous, identity.protocol, &identity.source, &identity.name) || previous.label != identity.label {
        continue;
      }
      let parties = parties_from([previous, identity]);
      return Err(Error::ContextCollision(Box::new(ContextCollision {
        parties,
        shared: identity.label.clone(),
      })));
    }
  }
  Ok(())
}

fn same_subject(existing: &ContextIdentity, protocol: AmbientProtocol, source: &Path, name: &str) -> bool {
  existing.protocol == protocol && existing.source.as_path() == source && existing.name == name
}

fn build_identity(source: &Path, protocol: AmbientProtocol, name: &str) -> Result<ContextIdentity, Error> {
  let path = path_text(source)?;
  if name.is_empty() {
    return Err(name_error(source, protocol, name, NameFault::Empty));
  }
  if name.contains('\u{001f}') {
    return Err(name_error(source, protocol, name, NameFault::UnitSeparator));
  }
  let canonical = canonical_bytes(protocol.tag(), path, name);
  let key_seed: [u8; 32] = Sha256::digest(&canonical).into();
  let label = format!("{}-{}", protocol.tag(), hex::encode(&key_seed[..16]));
  Ok(ContextIdentity {
    protocol,
    source: source.to_path_buf(),
    name: name.to_string(),
    label,
    key_seed,
  })
}

fn path_text(source: &Path) -> Result<&str, Error> {
  if source.as_os_str().is_empty() {
    return Err(Error::ContextPathInvalid {
      path: source.to_path_buf(),
      fault: PathFault::Empty,
    });
  }
  let Some(path) = source.to_str() else {
    return Err(Error::ContextPathInvalid {
      path: source.to_path_buf(),
      fault: PathFault::NotUnicode,
    });
  };
  if path.contains('\u{001f}') {
    return Err(Error::ContextPathInvalid {
      path: source.to_path_buf(),
      fault: PathFault::UnitSeparator,
    });
  }
  Ok(path)
}

fn name_error(source: &Path, protocol: AmbientProtocol, name: &str, fault: NameFault) -> Error {
  Error::ContextNameInvalid {
    path: source.to_path_buf(),
    protocol,
    name: name.to_string(),
    fault,
  }
}

fn canonical_bytes(tag: &str, path: &str, name: &str) -> Vec<u8> {
  let mut bytes = Vec::with_capacity(tag.len() + path.len() + name.len() + 2);
  bytes.extend_from_slice(tag.as_bytes());
  bytes.push(0x1f);
  bytes.extend_from_slice(path.as_bytes());
  bytes.push(0x1f);
  bytes.extend_from_slice(name.as_bytes());
  bytes
}

fn parties_from<'a>(identities: impl IntoIterator<Item = &'a ContextIdentity>) -> Vec<AmbiguousParty> {
  let mut parties: Vec<AmbiguousParty> = identities.into_iter().map(party_from).collect();
  parties.sort_by(|left, right| {
    left
      .source
      .cmp(&right.source)
      .then_with(|| left.name.cmp(&right.name))
      .then_with(|| left.protocol.tag().cmp(right.protocol.tag()))
  });
  parties
}

fn party_from(identity: &ContextIdentity) -> AmbiguousParty {
  AmbiguousParty {
    protocol: identity.protocol,
    name: identity.name.clone(),
    source: identity.source.clone(),
  }
}

fn join_parties(parties: &[AmbiguousParty]) -> String {
  parties.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
  use std::ffi::OsStr;
  use std::os::unix::ffi::OsStrExt;
  use std::path::{Path, PathBuf};

  use pretty_assertions::assert_eq;

  use super::{
    AmbientProtocol, ContextIdentity, ContextRef, NameFault, PathFault, Presented, ensure_distinct, identities, require_distinct,
  };
  use crate::Error;
  use crate::config::fake_for;

  const SSH_SOURCE: &str = "/home/ivan/.ssh/config";
  const SSH_LABEL: &str = "ssh-13786934f8941a5f07bb7b5b084cc9e8";
  const SSH_ENV: &str = "SSH_13786934F8941A5F07BB7B5B084CC9E8";
  const SSH_SEED: &str = "13786934f8941a5f07bb7b5b084cc9e80fb9db120fd9f3cb873d4be2a9c005ee";

  fn one(source: &str, protocol: AmbientProtocol, name: &str) -> ContextIdentity {
    let path = PathBuf::from(source);
    let ids = identities(&[ContextRef {
      source: &path,
      protocol,
      name,
    }])
    .unwrap();
    ids.into_iter().next().unwrap()
  }

  fn forged(source: &str, protocol: AmbientProtocol, name: &str, label: &str) -> ContextIdentity {
    ContextIdentity {
      protocol,
      source: PathBuf::from(source),
      name: name.to_string(),
      label: label.to_string(),
      key_seed: [7; 32],
    }
  }

  #[test]
  fn ssh_git_label_is_the_digest() {
    let identity = one(SSH_SOURCE, AmbientProtocol::Ssh, "git");
    assert_eq!(identity.label, SSH_LABEL);
    assert_eq!(identity.env(), SSH_ENV);
    assert_eq!(hex::encode(identity.key_seed()), SSH_SEED);
    assert!(!identity.label.contains("ivan"), "{}", identity.label);
    assert!(!identity.env().contains("IVAN"), "{}", identity.env());
    assert_eq!(identity.secret(), fake_for(&identity.env(), None));
  }

  #[test]
  fn identities_are_stable() {
    let first = one("/home/ivan/.kube/config", AmbientProtocol::KubernetesUser, "ivan");
    let second = one("/home/ivan/.kube/config", AmbientProtocol::KubernetesUser, "ivan");
    assert_eq!(first.label, second.label);
    assert_eq!(first.env(), second.env());
    assert_eq!(first.secret(), second.secret());
    assert_eq!(first.key_seed(), second.key_seed());
  }

  #[test]
  fn case_and_punctuation_stay_distinct() {
    let path = "/home/ivan/.kube/config";
    let lower = one(path, AmbientProtocol::KubernetesUser, "prod");
    let upper = one(path, AmbientProtocol::KubernetesUser, "Prod");
    let punct = one(path, AmbientProtocol::KubernetesUser, "prod!");
    assert_ne!(lower.label, upper.label);
    assert_ne!(lower.label, punct.label);
    assert_eq!(lower.name, "prod");
    assert_eq!(upper.name, "Prod");
  }

  #[test]
  fn path_is_part_of_the_digest() {
    let left = one("/home/a/.kube/config", AmbientProtocol::KubernetesUser, "prod");
    let right = one("/home/b/.kube/config", AmbientProtocol::KubernetesUser, "prod");
    assert_ne!(left.label, right.label);
  }

  #[test]
  fn protocol_is_part_of_the_digest() {
    let path = "/home/ivan/.kube/config";
    let user = one(path, AmbientProtocol::KubernetesUser, "prod");
    let cluster = one(path, AmbientProtocol::KubernetesCluster, "prod");
    assert_ne!(user.label, cluster.label);
    assert!(user.label.starts_with("kube-user-"), "{}", user.label);
    assert!(cluster.label.starts_with("kube-cluster-"), "{}", cluster.label);
  }

  #[test]
  fn repeated_subject_keeps_the_first() {
    let path = PathBuf::from("/home/ivan/.kube/config");
    let ids = identities(&[
      ContextRef {
        source: path.as_path(),
        protocol: AmbientProtocol::KubernetesUser,
        name: "prod",
      },
      ContextRef {
        source: path.as_path(),
        protocol: AmbientProtocol::KubernetesUser,
        name: "prod",
      },
    ])
    .unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].name, "prod");
  }

  #[test]
  fn eks_arn_name_gets_a_fixed_label() {
    let name = "arn:aws:eks:us-east-1:123456789012:cluster/prod";
    let identity = one("/home/ivan/.kube/config", AmbientProtocol::KubernetesUser, name);
    assert_eq!(identity.name, name);
    assert_eq!(identity.label.len(), 42);
    assert!(identity.label.starts_with("kube-user-"), "{}", identity.label);
    assert!(!identity.label.contains("arn"), "{}", identity.label);
    assert!(!identity.label.contains('/'), "{}", identity.label);
    assert_eq!(identity.env().len(), 42);
  }

  #[test]
  fn empty_name_fails() {
    let path = Path::new("/home/ivan/.talos/config");
    let err = identities(&[ContextRef {
      source: path,
      protocol: AmbientProtocol::Talos,
      name: "",
    }])
    .unwrap_err();
    match err {
      Error::ContextNameInvalid {
        path: got,
        protocol,
        name,
        fault,
      } => {
        assert_eq!(got.as_path(), path);
        assert_eq!(protocol, AmbientProtocol::Talos);
        assert_eq!(name, "");
        assert_eq!(fault, NameFault::Empty);
      }
      other => panic!("expected an empty name, got {other}"),
    }
  }

  #[test]
  fn unit_separator_in_name_fails() {
    let path = Path::new("/home/ivan/.talos/config");
    let name = "pro\u{001f}d";
    let err = identities(&[ContextRef {
      source: path,
      protocol: AmbientProtocol::Talos,
      name,
    }])
    .unwrap_err();
    match err {
      Error::ContextNameInvalid {
        path: got_path,
        name: got,
        fault,
        ..
      } => {
        assert_eq!(got_path.as_path(), path);
        assert_eq!(got, name);
        assert_eq!(fault, NameFault::UnitSeparator);
      }
      other => panic!("expected a unit separator in the name, got {other}"),
    }
  }

  #[test]
  fn empty_path_fails() {
    let path = Path::new("");
    let err = identities(&[ContextRef {
      source: path,
      protocol: AmbientProtocol::Ssh,
      name: "git",
    }])
    .unwrap_err();
    match err {
      Error::ContextPathInvalid { path: got, fault } => {
        assert_eq!(got.as_path(), path);
        assert_eq!(fault, PathFault::Empty);
      }
      other => panic!("expected an empty path, got {other}"),
    }
  }

  #[test]
  fn unit_separator_in_path_fails() {
    let path = Path::new("/tmp/\u{001f}/config");
    let err = identities(&[ContextRef {
      source: path,
      protocol: AmbientProtocol::Nats,
      name: "demo",
    }])
    .unwrap_err();
    match err {
      Error::ContextPathInvalid { path: got, fault } => {
        assert_eq!(got.as_path(), path);
        assert_eq!(fault, PathFault::UnitSeparator);
      }
      other => panic!("expected a unit separator in the path, got {other}"),
    }
  }

  #[test]
  fn non_utf8_path_fails() {
    let path = Path::new(OsStr::from_bytes(b"/tmp/\xff"));
    let err = identities(&[ContextRef {
      source: path,
      protocol: AmbientProtocol::Talos,
      name: "prod",
    }])
    .unwrap_err();
    match err {
      Error::ContextPathInvalid { path: got, fault } => {
        assert_eq!(got.as_path(), path);
        assert_eq!(fault, PathFault::NotUnicode);
      }
      other => panic!("expected a non-unicode path, got {other}"),
    }
  }

  #[test]
  fn shared_label_names_both_contexts() {
    let source = "/home/ivan/.kube/config";
    let prod = forged(source, AmbientProtocol::KubernetesUser, "prod", "kube-user-shared");
    let staging = forged(source, AmbientProtocol::KubernetesUser, "staging", "kube-user-shared");
    let forward = ensure_distinct(&[prod.clone(), staging.clone()]).unwrap_err();
    let reverse = ensure_distinct(&[staging, prod]).unwrap_err();
    let expected =
      "contexts `prod` (/home/ivan/.kube/config, kube-user), `staging` (/home/ivan/.kube/config, kube-user) share `kube-user-shared`";
    assert_eq!(forward.to_string(), expected);
    assert_eq!(reverse.to_string(), expected);
  }

  #[test]
  fn different_decoy_bytes_on_one_destination_are_ok() {
    let git = one(SSH_SOURCE, AmbientProtocol::Ssh, "git");
    let other = one(SSH_SOURCE, AmbientProtocol::Ssh, "git.example");
    require_distinct(&[
      Presented {
        identity: &git,
        host: "github.com",
        port: 22,
        decoy: b"key-a",
      },
      Presented {
        identity: &other,
        host: "github.com",
        port: 22,
        decoy: b"key-b",
      },
    ])
    .unwrap();
  }

  #[test]
  fn same_decoy_on_one_destination_names_both() {
    let git = one(SSH_SOURCE, AmbientProtocol::Ssh, "git");
    let other = one(SSH_SOURCE, AmbientProtocol::Ssh, "git.example");
    let err = require_distinct(&[
      Presented {
        identity: &other,
        host: "GitHub.com",
        port: 22,
        decoy: b"key",
      },
      Presented {
        identity: &git,
        host: " github.com ",
        port: 22,
        decoy: b"key",
      },
    ])
    .unwrap_err();
    assert_eq!(
      err.to_string(),
      "contexts `git` (/home/ivan/.ssh/config, ssh), `git.example` (/home/ivan/.ssh/config, ssh) at github.com:22 are indistinguishable"
    );
  }

  #[test]
  fn three_contexts_join_with_commas() {
    let lab = one("/home/ivan/.talos/config", AmbientProtocol::Talos, "lab");
    let prod = one("/home/ivan/.talos/config", AmbientProtocol::Talos, "prod");
    let staging = one("/home/ivan/.talos/config", AmbientProtocol::Talos, "staging");
    let err = require_distinct(&[
      Presented {
        identity: &staging,
        host: "talos.example",
        port: 50000,
        decoy: b"same",
      },
      Presented {
        identity: &lab,
        host: "talos.example",
        port: 50000,
        decoy: b"same",
      },
      Presented {
        identity: &prod,
        host: "talos.example",
        port: 50000,
        decoy: b"same",
      },
    ])
    .unwrap_err();
    assert_eq!(
      err.to_string(),
      "contexts `lab` (/home/ivan/.talos/config, talos), `prod` (/home/ivan/.talos/config, talos), `staging` (/home/ivan/.talos/config, talos) at talos.example:50000 are indistinguishable"
    );
  }

  #[test]
  fn same_identity_repeated_is_ok() {
    let git = one(SSH_SOURCE, AmbientProtocol::Ssh, "git");
    require_distinct(&[
      Presented {
        identity: &git,
        host: "github.com",
        port: 22,
        decoy: b"key",
      },
      Presented {
        identity: &git,
        host: " GitHub.com ",
        port: 22,
        decoy: b"key",
      },
    ])
    .unwrap();
  }

  #[test]
  fn same_identity_on_two_destinations_is_ok() {
    let git = one(SSH_SOURCE, AmbientProtocol::Ssh, "git");
    require_distinct(&[
      Presented {
        identity: &git,
        host: "github.com",
        port: 22,
        decoy: b"key",
      },
      Presented {
        identity: &git,
        host: "gitlab.com",
        port: 22,
        decoy: b"key",
      },
    ])
    .unwrap();
  }

  #[test]
  fn brackets_stay_on_the_host() {
    let git = one(SSH_SOURCE, AmbientProtocol::Ssh, "git");
    let other = one(SSH_SOURCE, AmbientProtocol::Ssh, "git.example");
    let err = require_distinct(&[
      Presented {
        identity: &git,
        host: "[2001:db8::1]",
        port: 22,
        decoy: b"key",
      },
      Presented {
        identity: &other,
        host: "[2001:db8::1]",
        port: 22,
        decoy: b"key",
      },
    ])
    .unwrap_err();
    assert!(err.to_string().contains("at [2001:db8::1]:22"), "{err}");
  }

  #[test]
  fn empty_host_fails() {
    let git = one(SSH_SOURCE, AmbientProtocol::Ssh, "git");
    let err = require_distinct(&[Presented {
      identity: &git,
      host: " \t ",
      port: 22,
      decoy: b"key",
    }])
    .unwrap_err();
    match err {
      Error::WireHostEmpty => {}
      other => panic!("expected an empty host, got {other}"),
    }
  }

  #[test]
  fn guest_cert_file_is_the_label_and_guest_crt() {
    assert_eq!(
      super::guest_cert_file("talos-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
      "talos-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.guest.crt"
    );
    let client = Path::new("/arkham/grants/rules.d/kube-user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.client.crt");
    assert_eq!(
      super::guest_cert_path(client),
      Some(PathBuf::from(
        "/arkham/grants/rules.d/kube-user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.guest.crt"
      ))
    );
  }
}
