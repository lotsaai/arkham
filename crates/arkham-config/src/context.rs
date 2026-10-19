//! Per-context grant identity.
//!
//! Adapters call [`identities`] while they write grants. They call
//! [`require_distinct`] before they write a grant that shares a destination
//! with another. [`crate::grants::Grant::matches`] stays the host matcher.
//! No config key names a current context.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::config::{fake_for, valid_env_name};
use crate::error::Error;

const MAX_LABEL_LEN: usize = 240;

/// Protocol tag stored in a context label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmbientProtocol {
  /// Bearer and client certificate for one kube user. Tag `kube-user`.
  KubernetesUser,
  /// CA blob for one kube cluster. Tag `kube-cluster`.
  KubernetesCluster,
  /// One Talos context. Tag `talos`.
  Talos,
  /// One NATS context. Tag `nats`.
  Nats,
  /// One SSH host block. Tag `ssh`.
  Ssh,
}

impl AmbientProtocol {
  /// Stable tag stored in the label and in the canonical bytes.
  #[must_use]
  pub const fn tag(self) -> &'static str {
    match self {
      Self::KubernetesUser => "kube-user",
      Self::KubernetesCluster => "kube-cluster",
      Self::Talos => "talos",
      Self::Nats => "nats",
      Self::Ssh => "ssh",
    }
  }

  fn from_tag(tag: &str) -> Option<Self> {
    match tag {
      "kube-user" => Some(Self::KubernetesUser),
      "kube-cluster" => Some(Self::KubernetesCluster),
      "talos" => Some(Self::Talos),
      "nats" => Some(Self::Nats),
      "ssh" => Some(Self::Ssh),
      _ => None,
    }
  }
}

impl fmt::Display for AmbientProtocol {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.tag())
  }
}

/// Why a source path cannot identify a context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFault {
  /// The path is empty.
  Empty,
  /// The path is not Unicode.
  NotUnicode,
  /// The path contains U+001F.
  UnitSeparator,
}

impl fmt::Display for PathFault {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let phrase = match self {
      Self::Empty => "is empty",
      Self::NotUnicode => "is not unicode",
      Self::UnitSeparator => "contains a unit separator",
    };
    f.write_str(phrase)
  }
}

impl std::error::Error for PathFault {}

/// Why a context name cannot become a label and an env name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameFault {
  /// The name is empty.
  Empty,
  /// The name contains U+001F.
  UnitSeparator,
  /// The label is longer than 240 bytes.
  LabelTooLong {
    /// Label length in bytes.
    length: usize,
  },
  /// The env form fails [`crate::config::valid_env_name`].
  EnvInvalid,
}

impl fmt::Display for NameFault {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Empty => f.write_str("is empty"),
      Self::UnitSeparator => f.write_str("contains a unit separator"),
      Self::LabelTooLong { length } => write!(f, "has label length {length}"),
      Self::EnvInvalid => f.write_str("is not an env name"),
    }
  }
}

impl std::error::Error for NameFault {}

/// One source record passed to [`identities`].
///
/// The path is stored as given. This helper does not canonicalize it.
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
///
/// Equality is label equality.
#[derive(Clone)]
pub struct ContextIdentity {
  protocol: AmbientProtocol,
  source: PathBuf,
  name: String,
  label: String,
  env: String,
  pair_stem: String,
  key_seed: [u8; 32],
}

impl PartialEq for ContextIdentity {
  fn eq(&self, other: &Self) -> bool {
    self.label == other.label
  }
}

impl Eq for ContextIdentity {}

impl fmt::Debug for ContextIdentity {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ContextIdentity")
      .field("protocol", &self.protocol)
      .field("source", &self.source)
      .field("name", &self.name)
      .field("label", &self.label)
      .field("env", &self.env)
      .field("pair_stem", &self.pair_stem)
      .field("key_seed", &"<redacted>")
      .finish()
  }
}

impl ContextIdentity {
  /// Protocol this identity was built with.
  #[must_use]
  pub fn protocol(&self) -> AmbientProtocol {
    self.protocol
  }

  /// Path passed to [`identities`].
  #[must_use]
  pub fn source(&self) -> &Path {
    &self.source
  }

  /// Original name, including case and punctuation.
  #[must_use]
  pub fn name(&self) -> &str {
    &self.name
  }

  /// Grant label. `{tag}--` plus the lowercase hex of the canonical bytes.
  #[must_use]
  pub fn label(&self) -> &str {
    &self.label
  }

  /// Env name. [`crate::config::fake_for`] seed for this subject.
  #[must_use]
  pub fn env(&self) -> &str {
    &self.env
  }

  /// Stable decoy material for this subject.
  #[must_use]
  pub fn decoy(&self) -> DecoyIdentity<'_> {
    DecoyIdentity {
      secret: fake_for(&self.env, None),
      pair_stem: self.pair_stem.as_str(),
      key_seed: &self.key_seed,
    }
  }

  /// Inverse of [`Self::label`].
  ///
  /// # Errors
  ///
  /// Returns [`Error::ContextPathInvalid`] or [`Error::ContextNameInvalid`]
  /// when the label decodes to a path or name that [`identities`] rejects.
  /// Returns [`Error::ContextLabelInvalid`] when the text is not the
  /// lowercase label [`identities`] would issue.
  pub fn from_label(label: &str) -> Result<Self, Error> {
    let Some((tag, hex_body)) = label.split_once("--") else {
      return Err(rejected_label(label));
    };
    let Some(protocol) = AmbientProtocol::from_tag(tag) else {
      return Err(rejected_label(label));
    };
    let Ok(bytes) = hex::decode(hex_body) else {
      return Err(rejected_label(label));
    };
    let Ok(text) = str::from_utf8(&bytes) else {
      return Err(rejected_label(label));
    };
    let mut fields = text.split('\u{001f}');
    let embedded = fields.next();
    let path = fields.next();
    let name = fields.next();
    if fields.next().is_some() {
      return Err(rejected_label(label));
    }
    let (Some(embedded), Some(path), Some(name)) = (embedded, path, name) else {
      return Err(rejected_label(label));
    };
    if embedded != tag {
      return Err(rejected_label(label));
    }
    let mut built = identities(&[ContextRef {
      source: Path::new(path),
      protocol,
      name,
    }])?;
    if built.len() == 1
      && let Some(identity) = built.pop()
      && identity.label() == label
    {
      return Ok(identity);
    }
    Err(rejected_label(label))
  }
}

/// Decoy material derived from one identity.
///
/// [`Debug`] redacts `secret` and `key_seed`.
pub struct DecoyIdentity<'a> {
  secret: String,
  pair_stem: &'a str,
  key_seed: &'a [u8; 32],
}

impl fmt::Debug for DecoyIdentity<'_> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("DecoyIdentity")
      .field("secret", &"<redacted>")
      .field("pair_stem", &self.pair_stem)
      .field("key_seed", &"<redacted>")
      .finish()
  }
}

impl DecoyIdentity<'_> {
  /// Bearer, password, or token written into the guest file.
  ///
  /// Equals [`crate::config::fake_for`] of the env with no pattern.
  #[must_use]
  pub fn secret(&self) -> &str {
    &self.secret
  }

  /// Argument to `load_or_generate_client_pair`.
  ///
  /// `{tag}-` plus the first 32 hex characters of [`Self::key_seed`].
  #[must_use]
  pub fn pair_stem(&self) -> &str {
    self.pair_stem
  }

  /// 32-byte ed25519 seed. SHA-256 of the canonical bytes.
  #[must_use]
  pub fn key_seed(&self) -> &[u8; 32] {
    self.key_seed
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
  /// Decoy bytes the guest presents. An empty slice still hashes.
  pub decoy: &'a [u8],
}

/// A third or later context named by [`Error::AmbiguousContexts`](crate::Error::AmbiguousContexts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousParty {
  /// Protocol of that context.
  pub protocol: AmbientProtocol,
  /// Original name.
  pub name: String,
  /// Source path.
  pub source: PathBuf,
}

/// Both contexts that share a label or a pair stem.
#[derive(Debug)]
pub struct ContextCollision {
  /// Protocol of the earlier context.
  pub left_protocol: AmbientProtocol,
  /// Original name of the earlier context.
  pub left_name: String,
  /// Source path of the earlier context.
  pub left_source: PathBuf,
  /// Protocol of the later context.
  pub right_protocol: AmbientProtocol,
  /// Original name of the later context.
  pub right_name: String,
  /// Source path of the later context.
  pub right_source: PathBuf,
  /// Shared label or pair stem.
  pub shared: String,
}

impl fmt::Display for ContextCollision {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "contexts `{left}` ({left_path}) and `{right}` ({right_path}) on {protocol} share `{shared}`",
      left = self.left_name,
      left_path = self.left_source.display(),
      right = self.right_name,
      right_path = self.right_source.display(),
      protocol = self.left_protocol,
      shared = self.shared,
    )
  }
}

/// Contexts that present the same host, port, and decoy bytes.
///
/// `left` is the first context after sorting by source display, name, and tag.
/// `also` holds the third and later contexts.
#[derive(Debug)]
pub struct AmbiguousContexts {
  /// Protocol of the first context after sorting.
  pub left_protocol: AmbientProtocol,
  /// Original name of the first context after sorting.
  pub left_name: String,
  /// Source path of the first context after sorting.
  pub left_source: PathBuf,
  /// Protocol of the second context after sorting.
  pub right_protocol: AmbientProtocol,
  /// Original name of the second context after sorting.
  pub right_name: String,
  /// Source path of the second context after sorting.
  pub right_source: PathBuf,
  /// Third and later contexts, already sorted.
  pub also: Vec<AmbiguousParty>,
  /// Lowercased destination host.
  pub host: String,
  /// Destination port the caller supplied.
  pub port: u16,
}

impl fmt::Display for AmbiguousContexts {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut parts = Vec::with_capacity(2 + self.also.len());
    parts.push(context_party(&self.left_name, &self.left_source, self.left_protocol));
    parts.push(context_party(&self.right_name, &self.right_source, self.right_protocol));
    for extra in &self.also {
      parts.push(context_party(&extra.name, &extra.source, extra.protocol));
    }
    write!(
      f,
      "contexts {} at {}:{} are indistinguishable",
      join_context_list(&parts),
      self.host,
      self.port,
    )
  }
}

fn context_party(name: &str, source: &Path, protocol: AmbientProtocol) -> String {
  format!("`{name}` ({}, {protocol})", source.display())
}

fn join_context_list(parts: &[String]) -> String {
  let Some((first, rest)) = parts.split_first() else {
    return String::new();
  };
  let Some((second, tail)) = rest.split_first() else {
    return first.clone();
  };
  if tail.is_empty() {
    return format!("{first} and {second}");
  }
  let Some((last, middle)) = tail.split_last() else {
    return format!("{first} and {second}");
  };
  let mut out = format!("{first}, {second}");
  for part in middle {
    out.push_str(", ");
    out.push_str(part);
  }
  out.push_str(", and ");
  out.push_str(last);
  out
}

/// Labels, envs, and decoy seeds for `refs`.
///
/// A repeated path, protocol, and name is one identity. The first one is kept.
/// The result follows input order. Two different refs that share a label or a
/// pair stem return [`Error::ContextCollision`].
///
/// # Errors
///
/// * [`Error::ContextPathInvalid`] when a path is empty, not Unicode, or contains U+001F.
/// * [`Error::ContextNameInvalid`] when a name is empty, contains U+001F, the label is longer than 240 bytes, or the env form fails [`valid_env_name`](crate::config::valid_env_name).
/// * [`Error::ContextCollision`] when two different refs share a label or a pair stem.
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

/// Fail when two different identities share a host, a port, and the same decoy bytes.
///
/// The same identity repeated is success. The same identity on two destinations
/// is success. Hosts are trimmed and stored in ASCII lowercase. Ports are not
/// defaulted. Brackets stay on the host.
///
/// # Errors
///
/// * [`Error::WireHostEmpty`] when a host is empty after trimming.
/// * [`Error::AmbiguousContexts`] when two different identities share a host, a port, and a decoy hash.
pub fn require_distinct(presented: &[Presented<'_>]) -> Result<(), Error> {
  let mut groups: BTreeMap<(String, u16, [u8; 32]), Vec<&ContextIdentity>> = BTreeMap::new();
  for item in presented {
    let host = item.host.trim().to_ascii_lowercase();
    if host.is_empty() {
      return Err(Error::WireHostEmpty);
    }
    let mark: [u8; 32] = Sha256::digest(item.decoy).into();
    let group = groups.entry((host, item.port, mark)).or_default();
    if group.contains(&item.identity) {
      continue;
    }
    group.push(item.identity);
  }
  for ((host, port, _), mut group) in groups {
    if group.len() < 2 {
      continue;
    }
    group.sort_by(|left, right| compare_presented(left, right));
    let Some(left) = group.first() else {
      continue;
    };
    let Some(right) = group.get(1) else {
      continue;
    };
    let also = group.iter().skip(2).copied().map(party_from).collect();
    return Err(Error::AmbiguousContexts(Box::new(AmbiguousContexts {
      left_protocol: left.protocol,
      left_name: left.name.clone(),
      left_source: left.source.clone(),
      right_protocol: right.protocol,
      right_name: right.name.clone(),
      right_source: right.source.clone(),
      also,
      host,
      port,
    })));
  }
  Ok(())
}

fn ensure_distinct(built: &[ContextIdentity]) -> Result<(), Error> {
  for (index, identity) in built.iter().enumerate() {
    for previous in built.iter().take(index) {
      if same_subject(previous, identity.protocol, &identity.source, &identity.name) {
        continue;
      }
      let shared = if previous.label == identity.label {
        previous.label.clone()
      } else if previous.pair_stem == identity.pair_stem {
        previous.pair_stem.clone()
      } else {
        continue;
      };
      return Err(Error::ContextCollision(Box::new(ContextCollision {
        left_protocol: previous.protocol,
        left_name: previous.name.clone(),
        left_source: previous.source.clone(),
        right_protocol: identity.protocol,
        right_name: identity.name.clone(),
        right_source: identity.source.clone(),
        shared,
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
  let label = labeled(protocol, &canonical);
  if label.len() > MAX_LABEL_LEN {
    return Err(name_error(source, protocol, name, NameFault::LabelTooLong { length: label.len() }));
  }
  let env = env_from_label(&label);
  if !valid_env_name(&env) {
    return Err(name_error(source, protocol, name, NameFault::EnvInvalid));
  }
  let key_seed = sha256(&canonical);
  Ok(ContextIdentity {
    protocol,
    source: source.to_path_buf(),
    name: name.to_string(),
    label,
    env,
    pair_stem: pair_stem_from(protocol, &key_seed),
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

fn labeled(protocol: AmbientProtocol, canonical: &[u8]) -> String {
  let mut label = String::with_capacity(protocol.tag().len() + 2 + canonical.len() * 2);
  label.push_str(protocol.tag());
  label.push_str("--");
  label.push_str(&hex::encode(canonical));
  label
}

fn env_from_label(label: &str) -> String {
  let mut env = String::with_capacity(label.len());
  for character in label.chars() {
    if character == '-' {
      env.push('_');
    } else {
      env.push(character.to_ascii_uppercase());
    }
  }
  env
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
  Sha256::digest(bytes).into()
}

fn pair_stem_from(protocol: AmbientProtocol, key_seed: &[u8; 32]) -> String {
  let mut head = [0u8; 16];
  for (slot, byte) in head.iter_mut().zip(key_seed.iter()) {
    *slot = *byte;
  }
  let mut stem = String::with_capacity(protocol.tag().len() + 1 + head.len() * 2);
  stem.push_str(protocol.tag());
  stem.push('-');
  stem.push_str(&hex::encode(head));
  stem
}

fn party_from(identity: &ContextIdentity) -> AmbiguousParty {
  AmbiguousParty {
    protocol: identity.protocol,
    name: identity.name.clone(),
    source: identity.source.clone(),
  }
}

fn compare_presented(left: &ContextIdentity, right: &ContextIdentity) -> Ordering {
  let by_source = left.source.display().to_string().cmp(&right.source.display().to_string());
  if by_source != Ordering::Equal {
    return by_source;
  }
  let by_name = left.name.cmp(&right.name);
  if by_name != Ordering::Equal {
    return by_name;
  }
  left.protocol.tag().cmp(right.protocol.tag())
}

fn rejected_label(label: &str) -> Error {
  Error::ContextLabelInvalid { label: label.to_string() }
}

#[cfg(test)]
mod tests {
  use std::collections::HashSet;
  use std::ffi::OsStr;
  use std::os::unix::ffi::OsStrExt;
  use std::path::{Path, PathBuf};

  use pretty_assertions::assert_eq;

  use super::{
    AmbientProtocol, ContextIdentity, ContextRef, NameFault, PathFault, Presented, ensure_distinct, identities, require_distinct,
  };
  use crate::Error;
  use crate::config::{fake_for, valid_env_name};

  const SSH_SOURCE: &str = "/home/ivan/.ssh/config";
  const SSH_LABEL: &str = "ssh--7373681f2f686f6d652f6976616e2f2e7373682f636f6e6669671f676974";
  const SSH_ENV: &str = "SSH__7373681F2F686F6D652F6976616E2F2E7373682F636F6E6669671F676974";
  const SSH_PAIR_STEM: &str = "ssh-13786934f8941a5f07bb7b5b084cc9e8";

  fn identity_for_test(protocol: AmbientProtocol, source: &str, name: &str, label: &str, pair_stem: &str) -> ContextIdentity {
    ContextIdentity {
      protocol,
      source: PathBuf::from(source),
      name: name.to_string(),
      label: label.to_string(),
      env: label.to_string(),
      pair_stem: pair_stem.to_string(),
      key_seed: [7; 32],
    }
  }

  fn one(source: &str, protocol: AmbientProtocol, name: &str) -> ContextIdentity {
    let path = PathBuf::from(source);
    let ids = identities(&[ContextRef {
      source: &path,
      protocol,
      name,
    }])
    .unwrap();
    assert_eq!(ids.len(), 1);
    ids.into_iter().next().unwrap()
  }

  fn is_dns_label(stem: &str) -> bool {
    let bytes = stem.as_bytes();
    if stem.len() > 63 {
      return false;
    }
    let Some((first, rest)) = bytes.split_first() else {
      return false;
    };
    let Some((last, middle)) = rest.split_last() else {
      return false;
    };
    if !first.is_ascii_lowercase() {
      return false;
    }
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
      return false;
    }
    middle
      .iter()
      .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
  }

  #[test]
  fn ssh_git_round_trip() {
    let identity = one(SSH_SOURCE, AmbientProtocol::Ssh, "git");
    assert_eq!(identity.label(), SSH_LABEL);
    assert_eq!(identity.env(), SSH_ENV);
    assert_eq!(identity.decoy().pair_stem(), SSH_PAIR_STEM);
    let restored = ContextIdentity::from_label(SSH_LABEL).unwrap();
    assert_eq!(restored.source(), Path::new(SSH_SOURCE));
    assert_eq!(restored.name(), "git");
    assert_eq!(restored.protocol(), AmbientProtocol::Ssh);
    assert_eq!(restored.label(), SSH_LABEL);
    assert_eq!(restored.env(), SSH_ENV);
    assert_eq!(restored.decoy().pair_stem(), SSH_PAIR_STEM);
    assert_eq!(restored.decoy().key_seed(), identity.decoy().key_seed());
    assert_eq!(restored.decoy().secret(), identity.decoy().secret());
  }

  #[test]
  fn identities_is_stable() {
    let first = one("/home/ivan/.kube/config", AmbientProtocol::KubernetesUser, "ivan");
    let second = one("/home/ivan/.kube/config", AmbientProtocol::KubernetesUser, "ivan");
    assert_eq!(first.label(), second.label());
    assert_eq!(first.env(), second.env());
    assert_eq!(first.decoy().secret(), second.decoy().secret());
    assert_eq!(first.decoy().key_seed(), second.decoy().key_seed());
    assert_eq!(first.decoy().pair_stem(), second.decoy().pair_stem());
  }

  #[test]
  fn secret_matches_fake_for_env() {
    let identity = one(SSH_SOURCE, AmbientProtocol::Ssh, "git");
    assert_eq!(identity.decoy().secret(), fake_for(identity.env(), None));
  }

  #[test]
  fn case_and_punctuation_stay_distinct() {
    let names = ["prod", "Prod", "prod!", "foo.bar", "foo-bar", "foo_bar", "Foo-Bar"];
    let path = PathBuf::from("/home/ivan/.talos/config");
    let refs: Vec<ContextRef<'_>> = names
      .iter()
      .map(|name| ContextRef {
        source: path.as_path(),
        protocol: AmbientProtocol::Talos,
        name,
      })
      .collect();
    let ids = identities(&refs).unwrap();
    assert_eq!(ids.len(), names.len());
    let mut labels = HashSet::new();
    for (identity, name) in ids.iter().zip(names) {
      assert_eq!(identity.name(), name);
      assert!(labels.insert(identity.label().to_string()), "duplicate label");
      let restored = ContextIdentity::from_label(identity.label()).unwrap();
      assert_eq!(restored.name(), name);
      assert_eq!(restored.source(), path.as_path());
    }
  }

  #[test]
  fn source_path_distinguishes_the_same_name() {
    let left = one("/home/a/.kube/config", AmbientProtocol::KubernetesUser, "prod");
    let right = one("/home/b/.kube/config", AmbientProtocol::KubernetesUser, "prod");
    assert_eq!(left.name(), "prod");
    assert_eq!(right.name(), "prod");
    assert_ne!(left.label(), right.label());
    assert_ne!(left.env(), right.env());
  }

  #[test]
  fn kube_user_and_cluster_with_the_same_name_differ() {
    let user = one("/home/ivan/.kube/config", AmbientProtocol::KubernetesUser, "prod");
    let cluster = one("/home/ivan/.kube/config", AmbientProtocol::KubernetesCluster, "prod");
    assert_eq!(user.name(), "prod");
    assert_eq!(cluster.name(), "prod");
    assert_eq!(user.protocol(), AmbientProtocol::KubernetesUser);
    assert_eq!(cluster.protocol(), AmbientProtocol::KubernetesCluster);
    assert_ne!(user.label(), cluster.label());
    assert_ne!(user.decoy().pair_stem(), cluster.decoy().pair_stem());
  }

  #[test]
  fn protocol_distinguishes_the_same_path_and_name() {
    let talos = one("/home/ivan/.config", AmbientProtocol::Talos, "prod");
    let nats = one("/home/ivan/.config", AmbientProtocol::Nats, "prod");
    assert_eq!(talos.name(), "prod");
    assert_eq!(nats.name(), "prod");
    assert_ne!(talos.label(), nats.label());
    assert_ne!(talos.env(), nats.env());
  }

  #[test]
  fn repeated_ref_is_one_identity() {
    let path = PathBuf::from("/home/ivan/.kube/config");
    let refs = [
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
    ];
    let ids = identities(&refs).unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.first().unwrap().name(), "prod");
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
  fn label_over_240_bytes_fails() {
    let name = "a".repeat(400);
    let path = Path::new("/home/ivan/.kube/config");
    let err = identities(&[ContextRef {
      source: path,
      protocol: AmbientProtocol::KubernetesUser,
      name: &name,
    }])
    .unwrap_err();
    match err {
      Error::ContextNameInvalid {
        fault: NameFault::LabelTooLong { length },
        name: got,
        ..
      } => {
        assert_eq!(got, name);
        assert!(length > 240, "length {length}");
      }
      other => panic!("expected a label that is too long, got {other}"),
    }
  }

  #[test]
  fn digit_leading_path_is_a_valid_env() {
    let identity = one("/9/kube/config", AmbientProtocol::KubernetesUser, "1prod");
    assert_eq!(identity.name(), "1prod");
    let env = identity.env();
    assert!(env.starts_with("KUBE_USER__"), "{env}");
    assert!(valid_env_name(env), "{env}");
    assert!(env.chars().all(|character| !character.is_ascii_lowercase() && character != '-'));
  }

  #[test]
  fn pair_stem_is_a_dns_label() {
    let identity = one(SSH_SOURCE, AmbientProtocol::Ssh, "git");
    let decoy = identity.decoy();
    let stem = decoy.pair_stem();
    assert_eq!(stem, SSH_PAIR_STEM);
    assert!(stem.len() <= 63);
    assert_ne!(stem, identity.label());
    assert!(is_dns_label(stem), "{stem}");
  }

  #[test]
  fn collision_names_both_contexts() {
    let left = identity_for_test(
      AmbientProtocol::KubernetesUser,
      "/home/ivan/.kube/config",
      "prod",
      "kube-user--shared",
      "kube-user-aaaa",
    );
    let right = identity_for_test(
      AmbientProtocol::KubernetesUser,
      "/home/ivan/.kube/config",
      "staging",
      "kube-user--shared",
      "kube-user-bbbb",
    );
    let err = ensure_distinct(&[left, right]).unwrap_err();
    let text = err.to_string();
    match &err {
      Error::ContextCollision(hit) => {
        assert_eq!(hit.left_protocol, AmbientProtocol::KubernetesUser);
        assert_eq!(hit.left_name, "prod");
        assert_eq!(hit.left_source.as_path(), Path::new("/home/ivan/.kube/config"));
        assert_eq!(hit.right_protocol, AmbientProtocol::KubernetesUser);
        assert_eq!(hit.right_name, "staging");
        assert_eq!(hit.right_source.as_path(), Path::new("/home/ivan/.kube/config"));
        assert_eq!(hit.shared, "kube-user--shared");
      }
      other => panic!("expected a collision, got {other}"),
    }
    assert_eq!(
      text,
      "contexts `prod` (/home/ivan/.kube/config) and `staging` (/home/ivan/.kube/config) on kube-user share `kube-user--shared`"
    );

    let stem_left = identity_for_test(
      AmbientProtocol::Talos,
      "/home/ivan/.talos/config",
      "prod",
      "talos--aaa",
      "talos-sharedstem",
    );
    let stem_right = identity_for_test(
      AmbientProtocol::Talos,
      "/home/ivan/.talos/config",
      "prod!",
      "talos--bbb",
      "talos-sharedstem",
    );
    let stem_err = ensure_distinct(&[stem_left, stem_right]).unwrap_err();
    match stem_err {
      Error::ContextCollision(hit) => {
        assert_eq!(hit.left_name, "prod");
        assert_eq!(hit.right_name, "prod!");
        assert_eq!(hit.shared, "talos-sharedstem");
      }
      other => panic!("expected a pair stem collision, got {other}"),
    }
  }

  #[test]
  fn require_distinct_same_identity_twice_is_ok() {
    let git = identity_for_test(AmbientProtocol::Ssh, SSH_SOURCE, "git", "label-git", "stem-git");
    require_distinct(&[
      Presented {
        identity: &git,
        host: "github.com",
        port: 22,
        decoy: b"key",
      },
      Presented {
        identity: &git,
        host: "github.com",
        port: 22,
        decoy: b"key",
      },
    ])
    .unwrap();
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
        decoy: b"other",
      },
    ])
    .unwrap();
  }

  #[test]
  fn require_distinct_different_decoys_is_ok() {
    let git = identity_for_test(AmbientProtocol::Ssh, SSH_SOURCE, "git", "label-git", "stem-git");
    let other = identity_for_test(
      AmbientProtocol::Ssh,
      SSH_SOURCE,
      "git.example",
      "label-git-example",
      "stem-git-example",
    );
    require_distinct(&[
      Presented {
        identity: &git,
        host: "github.com",
        port: 22,
        decoy: b"alpha",
      },
      Presented {
        identity: &other,
        host: "github.com",
        port: 22,
        decoy: b"beta",
      },
    ])
    .unwrap();
  }

  #[test]
  fn require_distinct_different_ports_is_ok() {
    let git = identity_for_test(AmbientProtocol::Ssh, SSH_SOURCE, "git", "label-git", "stem-git");
    let other = identity_for_test(
      AmbientProtocol::Ssh,
      SSH_SOURCE,
      "git.example",
      "label-git-example",
      "stem-git-example",
    );
    require_distinct(&[
      Presented {
        identity: &git,
        host: "github.com",
        port: 22,
        decoy: b"key",
      },
      Presented {
        identity: &other,
        host: "github.com",
        port: 2222,
        decoy: b"key",
      },
    ])
    .unwrap();
  }

  #[test]
  fn require_distinct_names_both_contexts() {
    let path = "/home/ivan/.talos/config";
    let prod = identity_for_test(AmbientProtocol::Talos, path, "prod", "label-prod", "stem-prod");
    let bang = identity_for_test(AmbientProtocol::Talos, path, "prod!", "label-bang", "stem-bang");
    let decoy = b"DECOYMARK";
    let forward = [
      Presented {
        identity: &bang,
        host: "Talos.Example",
        port: 50000,
        decoy,
      },
      Presented {
        identity: &prod,
        host: "talos.example",
        port: 50000,
        decoy,
      },
    ];
    let reversed = [forward[1], forward[0]];
    let forward_err = require_distinct(&forward).unwrap_err();
    let reverse_err = require_distinct(&reversed).unwrap_err();
    assert_eq!(forward_err.to_string(), reverse_err.to_string());
    let text = forward_err.to_string();
    assert!(!text.contains("DECOYMARK"));
    match forward_err {
      Error::AmbiguousContexts(hit) => {
        assert_eq!(hit.left_name, "prod");
        assert_eq!(hit.right_name, "prod!");
        assert_eq!(hit.host, "talos.example");
        assert_eq!(hit.port, 50000);
        assert_eq!(hit.also.len(), 0);
      }
      other => panic!("expected ambiguous contexts, got {other}"),
    }
    assert_eq!(
      text,
      "contexts `prod` (/home/ivan/.talos/config, talos) and `prod!` (/home/ivan/.talos/config, talos) at talos.example:50000 are indistinguishable"
    );
  }

  #[test]
  fn require_distinct_three_lists_every_name() {
    let path = "/home/ivan/.talos/config";
    let lab = identity_for_test(AmbientProtocol::Talos, path, "lab", "label-lab", "stem-lab");
    let prod = identity_for_test(AmbientProtocol::Talos, path, "prod", "label-prod", "stem-prod");
    let staging = identity_for_test(AmbientProtocol::Talos, path, "staging", "label-staging", "stem-staging");
    let decoy = b"same";
    let err = require_distinct(&[
      Presented {
        identity: &staging,
        host: "Talos.Example",
        port: 50000,
        decoy,
      },
      Presented {
        identity: &prod,
        host: "talos.example",
        port: 50000,
        decoy,
      },
      Presented {
        identity: &lab,
        host: "TALOS.EXAMPLE",
        port: 50000,
        decoy,
      },
    ])
    .unwrap_err();
    let text = err.to_string();
    match err {
      Error::AmbiguousContexts(hit) => {
        assert_eq!(hit.left_name, "lab");
        assert_eq!(hit.right_name, "prod");
        assert_eq!(hit.also.len(), 1);
        assert_eq!(hit.also.first().unwrap().name, "staging");
        assert_eq!(hit.host, "talos.example");
        assert_eq!(hit.port, 50000);
      }
      other => panic!("expected three ambiguous contexts, got {other}"),
    }
    assert_eq!(
      text,
      "contexts `lab` (/home/ivan/.talos/config, talos), `prod` (/home/ivan/.talos/config, talos), and `staging` (/home/ivan/.talos/config, talos) at talos.example:50000 are indistinguishable"
    );
  }

  #[test]
  fn empty_host_fails() {
    let git = identity_for_test(AmbientProtocol::Ssh, SSH_SOURCE, "git", "label-git", "stem-git");
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
  fn from_label_rejects_uppercase_hex() {
    let hex_body = SSH_LABEL.trim_start_matches("ssh--");
    let label = format!("ssh--{}", hex_body.to_ascii_uppercase());
    let err = ContextIdentity::from_label(&label).unwrap_err();
    match err {
      Error::ContextLabelInvalid { label: got } => {
        assert_eq!(got, label);
      }
      other => panic!("expected a rejected label, got {other}"),
    }
  }

  #[test]
  fn from_label_rejects_a_truncated_hex() {
    let label = "ssh--7373681f2f686f";
    let err = ContextIdentity::from_label(label).unwrap_err();
    match err {
      Error::ContextLabelInvalid { label: got } => {
        assert_eq!(got, label);
      }
      other => panic!("expected a rejected label, got {other}"),
    }
  }
}
