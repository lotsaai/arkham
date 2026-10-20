//! Ssh config adapter for `file_rewrite`. `ssh2-config` parses the file:
//! first-obtained parameters, `Host` negation, and `Include` globs. One
//! config becomes one grant whose `allow` list is in file order. Wildcard
//! and multi-name blocks are granted. `Match`, `ProxyJump`, `IdentityAgent`,
//! and `CertificateFile` are a typed error. An `Include` nested under a
//! `Host` block is a typed error because the parser does not expose the
//! parent pattern. Include cycles and nesting past [`INCLUDE_LIMIT`] are
//! typed errors. The decoy config keeps the source verbatim and prepends
//! `StrictHostKeyChecking accept-new` plus one `Host` block per pattern,
//! ordered by specificity, each naming that block's decoy identity files
//! and `IdentitiesOnly yes`. OpenSSH offers the first of those files, which
//! is the more specific block even when the source listed a wildcard first.
//! Real keys stay in the grant blobs.
//!
//! A known destination prefers the more specific pattern (exact, then a
//! glob, then `*.suffix`, then `*`). The same rank keeps file order. That
//! is how `Host *.corp` then `Host db.corp` then `Host *` selects the exact
//! block for `db.corp`. OpenSSH's own first-obtained value would keep the
//! earlier wildcard.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use arkham_config::config::{HostSshCfg, IfMissing};
use arkham_config::context::{AmbientProtocol, ContextIdentity, ContextRef, Presented, identities, require_distinct};
use arkham_config::grants::host_pat;
use arkham_pki::ssh::SshKey;
use sha2::{Digest as _, Sha256};
use ssh2_config::{ParseRule, SshConfig};

use crate::adapt::{BLOB_PREFIX_SSH, DecoyFile, GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, render_fragment};
use crate::error::Error;

/// How deep an `Include` chain may nest. OpenSSH has no fixed cap. Sixteen
/// is the adapter's.
const INCLUDE_LIMIT: u8 = 16;

static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
  fn drop(&mut self) {
    if let Err(err) = fs::remove_dir_all(&self.0)
      && err.kind() != std::io::ErrorKind::NotFound
    {
      tracing::warn!(path = %self.0.display(), %err, "ssh include stage cleanup failed");
    }
  }
}

/// One parsed `Host` block that carries at least one readable identity.
struct ParsedBlock {
  name: String,
  port: u16,
  hostname: Option<String>,
  positives: Vec<String>,
  negated: Vec<String>,
  files: Vec<PathBuf>,
}

struct Claimed {
  stem: String,
  seed_used: [u8; 32],
  real: Vec<u8>,
  guest: Vec<u8>,
  decoy: Vec<u8>,
  container: String,
}

/// Map an ssh config onto one grant. Every host block's decoy private key
/// is on that single entry, because the collector mounts `decoy_files` from
/// the first entry only.
///
/// # Errors
///
/// Returns an error when the config cannot be parsed, when `Include` cycles
/// or nests too deep, when a refused keyword is present, or when two
/// contexts share a destination and a decoy.
pub(crate) fn adapt(source: &Path, content: &[u8], home: &str, host_home: &Path) -> Result<Vec<RewriteAdapted>, Error> {
  let text = String::from_utf8_lossy(content);
  let stage = std::env::temp_dir().join(format!(
    "arkham-ssh-{}-{}",
    std::process::id(),
    STAGE_SEQ.fetch_add(1, Ordering::Relaxed)
  ));
  fs::create_dir_all(&stage).map_err(|err| Error::CreateDir {
    path: stage.clone(),
    source: err,
  })?;
  let _cleanup = RemoveOnDrop(stage.clone());
  let mut stack = Vec::new();
  let rewritten = stage_text(source, &text, host_home, &stage, &mut stack, 0)?;
  let mut reader = Cursor::new(rewritten);
  let parsed = SshConfig::default()
    .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS)
    .map_err(|err| Error::SshParse {
      path: source.to_path_buf(),
      source: err,
    })?;
  reject_unsupported(parsed.get_hosts())?;
  let blocks = blocks_from(parsed.get_hosts(), source, home, host_home);
  if blocks.is_empty() {
    return Ok(Vec::new());
  }
  let refs: Vec<ContextRef<'_>> = blocks
    .iter()
    .map(|block| ContextRef {
      source,
      protocol: AmbientProtocol::Ssh,
      name: block.name.as_str(),
    })
    .collect();
  let ids = identities(&refs)?;
  let claimed = claim_files(&blocks, &ids, source, home, host_home)?;
  render_adapted(source, home, &text, &blocks, &ids, &claimed)
}

fn render_adapted(
  source: &Path,
  home: &str,
  text: &str,
  blocks: &[ParsedBlock],
  ids: &[ContextIdentity],
  claimed: &BTreeMap<PathBuf, Claimed>,
) -> Result<Vec<RewriteAdapted>, Error> {
  let mut presentations: Vec<(String, u16, PathBuf, String)> = Vec::new();
  for block in blocks {
    let mut hosts = Vec::new();
    for pattern in &block.positives {
      if is_concrete(pattern) {
        hosts.push(pattern.clone());
      }
    }
    if let Some(hostname) = &block.hostname {
      hosts.push(hostname.clone());
    }
    for host in hosts {
      for file in &block.files {
        if claimed.contains_key(file) {
          presentations.push((host.clone(), block.port, file.clone(), block.name.clone()));
        }
      }
    }
  }
  let mut presented: Vec<Presented<'_>> = Vec::new();
  for (host, port, file, name) in &presentations {
    let identity = block_identity(ids, name)?;
    let Some(claim) = claimed.get(file) else {
      continue;
    };
    presented.push(Presented {
      identity,
      host: host.as_str(),
      port: *port,
      decoy: claim.guest.as_slice(),
    });
  }
  require_distinct(&presented)?;
  let Some(first) = blocks.first() else {
    return Ok(Vec::new());
  };
  let rule = block_identity(ids, &first.name)?;
  let mut allow = Vec::new();
  let mut ssh = BTreeMap::new();
  let mut ordinals: BTreeMap<String, u32> = BTreeMap::new();
  for block in blocks {
    let mut out = EntryOut {
      allow: &mut allow,
      ssh: &mut ssh,
      ordinals: &mut ordinals,
      claimed,
    };
    for pattern in &block.positives {
      push_entries(&mut out, pattern, &block.negated, block.port, &block.files);
    }
    if let Some(hostname) = &block.hostname {
      push_entries(&mut out, hostname, &[], block.port, &block.files);
    }
  }
  if allow.is_empty() {
    return Ok(Vec::new());
  }
  let fragment = render_fragment(
    source,
    &rule.label,
    &GrantFragment {
      env: rule.env(),
      registry: false,
      allow,
      value: None,
      real: None,
      generated: false,
      if_missing: Some(IfMissing::Ignore),
      tls: BTreeMap::new(),
      ssh,
    },
  )?;
  let mut materialized = Vec::new();
  let mut decoy_files = Vec::new();
  for claim in claimed.values() {
    materialized.push((format!("{}.identity", claim.stem), claim.real.clone()));
    materialized.push((format!("{}.guest_key", claim.stem), claim.guest.clone()));
    decoy_files.push(DecoyFile {
      name: format!("{}.decoy-key", claim.stem),
      bytes: claim.decoy.clone(),
      container: claim.container.clone(),
    });
  }
  decoy_files.push(DecoyFile {
    name: format!("{BLOB_PREFIX_SSH}known-hosts"),
    bytes: Vec::new(),
    container: format!("{home}/.ssh/known_hosts"),
  });
  Ok(vec![RewriteAdapted {
    fragment,
    decoy: decoy_config(text, blocks, claimed),
    materialized,
    decoy_files,
  }])
}

/// Guest ssh config. Specificity order is in front of the source so the
/// first identity OpenSSH obtains is the more specific block's decoy.
fn decoy_config(text: &str, blocks: &[ParsedBlock], claimed: &BTreeMap<PathBuf, Claimed>) -> String {
  let mut ranked: Vec<(u8, usize)> = blocks
    .iter()
    .enumerate()
    .map(|(index, block)| {
      let rank = block
        .positives
        .iter()
        .map(|pattern| host_pat(pattern).specificity())
        .min()
        .unwrap_or(u8::MAX);
      (rank, index)
    })
    .collect();
  ranked.sort_by_key(|item| *item);
  let mut out = String::from("StrictHostKeyChecking accept-new\n");
  for (_, index) in ranked {
    let Some(block) = blocks.get(index) else {
      continue;
    };
    let files: Vec<&str> = block
      .files
      .iter()
      .filter_map(|file| claimed.get(file).map(|claim| claim.container.as_str()))
      .collect();
    if files.is_empty() {
      continue;
    }
    for pattern in &block.positives {
      out.push_str("\nHost");
      for token in &block.negated {
        let _ = write!(out, " !{token}");
      }
      let _ = write!(out, " {pattern}\n  IdentitiesOnly yes\n");
      for container in &files {
        let _ = writeln!(out, "  IdentityFile {container}");
      }
    }
  }
  out.push('\n');
  out.push_str(text);
  out
}

struct EntryOut<'a> {
  allow: &'a mut Vec<String>,
  ssh: &'a mut BTreeMap<String, HostSshCfg>,
  ordinals: &'a mut BTreeMap<String, u32>,
  claimed: &'a BTreeMap<PathBuf, Claimed>,
}

fn claim_files(
  blocks: &[ParsedBlock],
  ids: &[ContextIdentity],
  source: &Path,
  home: &str,
  host_home: &Path,
) -> Result<BTreeMap<PathBuf, Claimed>, Error> {
  let mut claimed = BTreeMap::new();
  for block in blocks {
    let identity = block_identity(ids, &block.name)?;
    for file in &block.files {
      if claimed.contains_key(file) {
        continue;
      }
      let seed = claim_seed(identity.key_seed(), file, &claimed);
      let key = SshKey::from_seed(&seed);
      let real = fs::read(file).map_err(|err| Error::ReadFile {
        path: file.clone(),
        source: err,
      })?;
      let Some(container) = mirror_container_path(&file.to_string_lossy(), host_home, home) else {
        tracing::warn!(config = %source.display(), identity = %file.display(), "ssh identity skipped: it does not mirror under the container home");
        continue;
      };
      let stem = fresh_stem(&identity.label, &claimed);
      claimed.insert(
        file.clone(),
        Claimed {
          stem,
          seed_used: seed,
          real,
          guest: key.public_line()?.into_bytes(),
          decoy: key.to_openssh()?.into_bytes(),
          container,
        },
      );
    }
  }
  Ok(claimed)
}

fn push_entries(out: &mut EntryOut<'_>, pattern: &str, negated: &[String], port: u16, files: &[PathBuf]) {
  let base = allow_base(pattern, negated, port);
  for file in files {
    let Some(claim) = out.claimed.get(file) else {
      continue;
    };
    let ordinal = out.ordinals.entry(base.clone()).or_insert(0);
    let entry = if *ordinal == 0 {
      base.clone()
    } else {
      let mut tokens: Vec<String> = negated.iter().map(|item| format!("!{item}")).collect();
      tokens.push(format!("~{ordinal}"));
      format!("{}#{}", allow_base(pattern, &[], port), tokens.join(","))
    };
    *ordinal = ordinal.saturating_add(1);
    out.allow.push(entry.clone());
    out.ssh.insert(
      entry,
      HostSshCfg {
        identity: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{}.identity", claim.stem))),
        guest_key: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{}.guest_key", claim.stem))),
      },
    );
  }
}

fn allow_base(pattern: &str, negated: &[String], port: u16) -> String {
  let host = encode_ssh_host(pattern);
  let mut entry = if port == 22 {
    format!("ssh://{host}")
  } else {
    format!("ssh://{host}:{port}")
  };
  if !negated.is_empty() {
    let tokens: Vec<String> = negated.iter().map(|item| format!("!{item}")).collect();
    entry.push('#');
    entry.push_str(&tokens.join(","));
  }
  entry
}

fn encode_ssh_host(pattern: &str) -> String {
  if pattern == "*" || pattern.strip_prefix("*.").is_some_and(|rest| !rest.contains(['*', '?'])) {
    return pattern.to_string();
  }
  let mut out = String::with_capacity(pattern.len());
  for ch in pattern.chars() {
    if ch == '*' || ch == '?' || ch == '#' {
      let _ = write!(out, "%{code:02X}", code = u32::from(ch));
    } else {
      out.push(ch);
    }
  }
  out
}

fn blocks_from(hosts: &[ssh2_config::Host], source: &Path, home: &str, host_home: &Path) -> Vec<ParsedBlock> {
  let mut blocks = Vec::new();
  for host in hosts {
    let positives: Vec<String> = host
      .pattern
      .iter()
      .filter(|clause| !clause.negated)
      .map(|clause| clause.pattern.clone())
      .collect();
    let negated: Vec<String> = host
      .pattern
      .iter()
      .filter(|clause| clause.negated)
      .map(|clause| clause.pattern.clone())
      .collect();
    let Some(name) = positives.first().cloned() else {
      continue;
    };
    let Some(files) = host.params.identity_file.as_ref() else {
      continue;
    };
    if files.is_empty() {
      continue;
    }
    let mut readable = Vec::new();
    for file in files {
      match fs::read_to_string(file) {
        Ok(_) => {
          if mirror_container_path(&file.to_string_lossy(), host_home, home).is_none() {
            tracing::warn!(config = %source.display(), identity = %file.display(), "ssh identity skipped: it does not mirror under the container home");
            continue;
          }
          readable.push(file.clone());
        }
        Err(err) => {
          tracing::warn!(config = %source.display(), identity = %file.display(), %err, "ssh identity skipped: the identity is unreadable");
        }
      }
    }
    if readable.is_empty() {
      continue;
    }
    blocks.push(ParsedBlock {
      name,
      port: host.params.port.unwrap_or(22),
      hostname: host.params.host_name.clone(),
      positives,
      negated,
      files: readable,
    });
  }
  blocks
}

fn reject_unsupported(hosts: &[ssh2_config::Host]) -> Result<(), Error> {
  for host in hosts {
    for key in host.params.ignored_fields.keys() {
      if key.eq_ignore_ascii_case("match") {
        return Err(Error::SshUnsupported {
          keyword: "match".to_string(),
        });
      }
    }
    for key in host.params.unsupported_fields.keys() {
      if key.eq_ignore_ascii_case("identityagent") {
        return Err(Error::SshUnsupported {
          keyword: "identityagent".to_string(),
        });
      }
    }
    if host.params.proxy_jump.as_ref().is_some_and(|jump| !jump.is_empty()) {
      return Err(Error::SshUnsupported {
        keyword: "proxyjump".to_string(),
      });
    }
    if host.params.certificate_file.is_some() {
      return Err(Error::SshUnsupported {
        keyword: "certificatefile".to_string(),
      });
    }
  }
  Ok(())
}

fn block_identity<'a>(ids: &'a [ContextIdentity], name: &str) -> Result<&'a ContextIdentity, Error> {
  for identity in ids {
    if identity.name == name {
      return Ok(identity);
    }
  }
  Err(Error::SshContext { name: name.to_string() })
}

fn is_concrete(pattern: &str) -> bool {
  !pattern.contains(['*', '?'])
}

fn claim_seed(block_seed: &[u8; 32], path: &Path, claimed: &BTreeMap<PathBuf, Claimed>) -> [u8; 32] {
  if let Some(existing) = claimed.get(path) {
    return existing.seed_used;
  }
  if claimed.values().any(|item| item.seed_used == *block_seed) {
    return mix_seed(block_seed, path);
  }
  *block_seed
}

fn mix_seed(seed: &[u8; 32], path: &Path) -> [u8; 32] {
  let mut hasher = Sha256::new();
  hasher.update(seed);
  hasher.update([0xff]);
  hasher.update(path.to_string_lossy().as_bytes());
  hasher.finalize().into()
}

fn fresh_stem(label: &str, claimed: &BTreeMap<PathBuf, Claimed>) -> String {
  if claimed.values().all(|item| item.stem != label) {
    return label.to_string();
  }
  let mut n = 2u32;
  while n < u32::MAX {
    let stem = format!("{label}-{n}");
    if claimed.values().all(|item| item.stem != stem) {
      return stem;
    }
    n = n.saturating_add(1);
  }
  format!("{label}-last")
}

fn stage_text(origin: &Path, content: &str, host_home: &Path, stage: &Path, stack: &mut Vec<PathBuf>, depth: u8) -> Result<String, Error> {
  if depth > INCLUDE_LIMIT {
    return Err(Error::SshIncludeDepth {
      path: origin.to_path_buf(),
      limit: INCLUDE_LIMIT,
    });
  }
  if stack.iter().any(|seen| seen == origin) {
    return Err(Error::SshIncludeCycle {
      path: origin.to_path_buf(),
    });
  }
  stack.push(origin.to_path_buf());
  let mut out = String::new();
  let mut saw_host = false;
  for line in content.lines() {
    if let Some((keyword, value)) = directive(line) {
      let keyword_l = keyword.to_ascii_lowercase();
      if keyword_l == "host" {
        saw_host = true;
      }
      if keyword_l == "include" {
        if saw_host {
          return Err(Error::SshNestedInclude);
        }
        let pattern = expand_ssh_path(value, host_home);
        stage_includes(&pattern, host_home, stage, stack, depth)?;
        out.push_str("Include ");
        out.push_str(&staged_pattern(&pattern, host_home, stage));
        out.push('\n');
        continue;
      }
      if keyword_l == "identityfile" {
        out.push_str("IdentityFile ");
        out.push_str(&expand_ssh_path(value, host_home));
        out.push('\n');
        continue;
      }
    }
    out.push_str(line);
    out.push('\n');
  }
  stack.pop();
  Ok(out)
}

fn stage_includes(pattern: &str, host_home: &Path, stage: &Path, stack: &mut Vec<PathBuf>, depth: u8) -> Result<(), Error> {
  let files = glob::glob(pattern).map_err(|err| Error::SshIncludePattern {
    pattern: pattern.to_string(),
    source: err,
  })?;
  for file in files {
    let file = file.map_err(|err| Error::SshIncludeGlob {
      path: PathBuf::from(pattern),
      source: err,
    })?;
    let text = fs::read_to_string(&file).map_err(|err| Error::ReadFile {
      path: file.clone(),
      source: err,
    })?;
    let rewritten = stage_text(&file, &text, host_home, stage, stack, depth.saturating_add(1))?;
    let dest = staged_file(&file, host_home, stage);
    if let Some(parent) = dest.parent() {
      fs::create_dir_all(parent).map_err(|err| Error::CreateDir {
        path: parent.to_path_buf(),
        source: err,
      })?;
    }
    fs::write(&dest, rewritten).map_err(|err| Error::WriteFile { path: dest, source: err })?;
  }
  Ok(())
}

fn staged_file(file: &Path, host_home: &Path, stage: &Path) -> PathBuf {
  match file.strip_prefix(host_home) {
    Ok(rel) => stage.join(rel),
    Err(_) => stage.join("outside").join(file.strip_prefix("/").unwrap_or(file)),
  }
}

fn staged_pattern(pattern: &str, host_home: &Path, stage: &Path) -> String {
  let home = host_home.to_string_lossy();
  let staged = stage.to_string_lossy();
  if let Some(rest) = pattern.strip_prefix(home.as_ref()) {
    return format!("{staged}{rest}");
  }
  let rest = pattern.strip_prefix('/').unwrap_or(pattern);
  format!("{staged}/outside/{rest}")
}

fn directive(line: &str) -> Option<(&str, &str)> {
  let line = line.trim();
  if line.is_empty() || line.starts_with('#') {
    return None;
  }
  let (keyword, rest) = line.split_once(char::is_whitespace).or_else(|| line.split_once('='))?;
  let rest = rest.trim().trim_matches('"');
  let rest = rest.split_once(" #").map_or(rest, |(value, _)| value.trim());
  Some((keyword, rest))
}

fn expand_ssh_path(raw: &str, host_home: &Path) -> String {
  if let Some(rest) = raw.strip_prefix("~/") {
    host_home.join(rest).to_string_lossy().into_owned()
  } else if raw == "~" {
    host_home.to_string_lossy().into_owned()
  } else if Path::new(raw).is_absolute() {
    raw.to_string()
  } else {
    host_home.join(".ssh").join(raw).to_string_lossy().into_owned()
  }
}

/// Where the real identity lives on the host: `~` expands, relative paths
/// resolve against `~/.ssh` the way ssh itself resolves them.
pub(crate) fn host_identity_path(identity: &str, host_home: &Path) -> PathBuf {
  if let Some(rest) = identity.strip_prefix("~/") {
    host_home.join(rest)
  } else if Path::new(identity).is_absolute() {
    PathBuf::from(identity)
  } else {
    host_home.join(".ssh").join(identity)
  }
}

/// The container path the decoy identity mounts at, mirroring the source
/// layout under the container home. `~`-relative and home-relative paths
/// mirror; anything else off the host home does not.
pub(crate) fn mirror_container_path(identity: &str, host_home: &Path, home: &str) -> Option<String> {
  let host_path = if let Some(rest) = identity.strip_prefix("~/") {
    host_home.join(rest)
  } else if Path::new(identity).is_absolute() {
    PathBuf::from(identity)
  } else {
    host_home.join(".ssh").join(identity)
  };
  let host_path = crate::paths::normalize(&host_path);
  let rel = crate::paths::path_under_home(&host_path, host_home)?;
  Some(format!("{home}/{rel}"))
}

#[cfg(test)]
mod tests {
  use super::*;

  const CONFIG: &str =
    "Host git.example\n  User deploy\n  IdentityFile ~/.ssh/id_ed25519\nHost *.wild.example\n  IdentityFile ~/.ssh/id_ed25519\nHost bare\n";
  /// A host home carrying a real key.
  fn host_home_with_key() -> (tempfile::TempDir, SshKey) {
    let dir = tempfile::tempdir().unwrap();
    let real = SshKey::generate().unwrap();
    let ssh_dir = dir.path().join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    fs::write(ssh_dir.join("id_ed25519"), real.to_openssh().unwrap()).unwrap();
    (dir, real)
  }

  fn adapt_in(dir: &tempfile::TempDir, config: &str) -> Vec<RewriteAdapted> {
    adapt(Path::new("/home/ivan/.ssh/config"), config.as_bytes(), "/home/agent", dir.path()).unwrap()
  }

  #[test]
  fn exact_host_block_maps_to_one_grant_and_decoy_files() {
    let (dir, real) = host_home_with_key();
    let adapted = adapt_in(&dir, CONFIG);
    assert_eq!(adapted.len(), 1, "one config is one grant, wildcards included");
    let entry = &adapted[0];
    assert!(
      entry.fragment.contains("ssh://*.wild.example"),
      "wildcard hosts are granted: {}",
      entry.fragment
    );
    assert!(
      !entry.fragment.contains("ssh://bare"),
      "a block with no identity is not a grant: {}",
      entry.fragment
    );
    assert!(
      entry.decoy.starts_with("StrictHostKeyChecking accept-new\n\n") && entry.decoy.ends_with(CONFIG),
      "the decoy config is the source under the accept-new option: {}",
      entry.decoy
    );
    assert_eq!(entry.materialized.len(), 2);
    let names: Vec<&String> = entry.materialized.iter().map(|(name, _)| name).collect();
    assert!(names.iter().all(|name| name.starts_with("ssh-")), "{names:?}");

    let source = Path::new("/home/ivan/.ssh/config");
    let label = arkham_config::context::identities(&[arkham_config::context::ContextRef {
      source,
      protocol: arkham_config::context::AmbientProtocol::Ssh,
      name: "git.example",
    }])
    .unwrap()
    .into_iter()
    .next()
    .unwrap()
    .label;
    let mut out = String::new();
    let _ = writeln!(out, "{}", entry.fragment);
    let doc: toml::Value = toml::from_str(&out).unwrap();
    let rule = doc.get("rules").unwrap().get(&label).unwrap();
    assert_eq!(
      rule.get("allow").unwrap().as_array().unwrap()[0].as_str().unwrap(),
      "ssh://git.example"
    );
    assert_eq!(rule.get("if_missing").unwrap().as_str().unwrap(), "ignore");
    let ssh = rule.get("ssh").unwrap().get("ssh://git.example").unwrap();
    assert!(
      ssh
        .get("identity")
        .unwrap()
        .as_str()
        .unwrap()
        .ends_with(&format!("/rules.d/{label}.identity"))
    );

    let identity = entry
      .materialized
      .iter()
      .find(|(name, _)| name.ends_with(".identity"))
      .map(|(_, bytes)| String::from_utf8(bytes.clone()).unwrap())
      .unwrap();
    assert_eq!(identity, real.to_openssh().unwrap(), "the state blob is the real key");
    let decoy_key = entry.decoy_files.iter().find(|file| file.name.ends_with(".decoy-key")).unwrap();
    assert_eq!(decoy_key.container, "/home/agent/.ssh/id_ed25519");
    let decoy = SshKey::from_openssh(&String::from_utf8(decoy_key.bytes.clone()).unwrap()).unwrap();
    assert_ne!(decoy.public(), real.public(), "the mounted key is a decoy");
    let known = entry.decoy_files.iter().find(|file| file.name == "ssh-known-hosts").unwrap();
    assert_eq!(known.container, "/home/agent/.ssh/known_hosts");
    assert!(
      known.bytes.is_empty(),
      "accept-new records arkham's key in the agent's own known_hosts"
    );
  }

  #[test]
  fn nonstandard_port_and_hostname_enter_the_grant() {
    let (dir, _) = host_home_with_key();
    let config = "Host alias\n  HostName bastion.internal\n  Port 2222\n  IdentityFile ~/.ssh/id_ed25519\n";
    let adapted = adapt_in(&dir, config);
    assert_eq!(adapted.len(), 1);
    let text = &adapted[0].fragment;
    assert!(text.contains("ssh://bastion.internal:2222"), "{text}");
  }

  #[test]
  fn an_unreadable_identity_skips_the_block_not_the_source() {
    let (dir, _) = host_home_with_key();
    let config = "Host broken.example\n IdentityFile ~/.ssh/vanished\nHost git.example\n IdentityFile ~/.ssh/id_ed25519\n";
    let adapted = adapt_in(&dir, config);
    assert_eq!(adapted.len(), 1, "the readable block still derives: {adapted:?}");
    assert!(adapted[0].fragment.contains("ssh://git.example"), "{}", adapted[0].fragment);
  }

  #[test]
  fn a_second_identity_is_offered_with_the_block() {
    let (dir, _) = host_home_with_key();
    let other = SshKey::generate().unwrap();
    fs::write(dir.path().join(".ssh").join("other"), other.to_openssh().unwrap()).unwrap();
    let config = "Host git.example\n IdentityFile ~/.ssh/id_ed25519\n IdentityFile ~/.ssh/other\n";
    let adapted = adapt_in(&dir, config);
    assert_eq!(adapted.len(), 1, "one file is one grant: {adapted:?}");
    let containers: Vec<&str> = adapted[0]
      .decoy_files
      .iter()
      .filter(|file| file.name.ends_with(".decoy-key"))
      .map(|file| file.container.as_str())
      .collect();
    assert!(containers.contains(&"/home/agent/.ssh/id_ed25519"), "{containers:?}");
    assert!(containers.contains(&"/home/agent/.ssh/other"), "{containers:?}");
  }

  #[test]
  fn tilde_parent_does_not_escape_the_container_home() {
    let home = Path::new("/host/home/eng");
    let mirrored = mirror_container_path("~/../.ssh/id_ed25519", home, "/home/eng");
    assert!(
      mirrored
        .as_deref()
        .is_none_or(|path| !path.contains("..") && path.starts_with("/home/eng/")),
      "{mirrored:?}"
    );
  }

  #[test]
  fn relative_parent_identity_does_not_keep_the_parent_segment() {
    let home = Path::new("/host/home/eng");
    let mirrored = mirror_container_path("../id_ed25519", home, "/home/eng");
    assert!(mirrored.as_deref().is_some_and(|path| !path.contains("..")), "{mirrored:?}");
  }

  #[test]
  fn relative_identity_mirrors_under_ssh() {
    let home = Path::new("/host/home/eng");
    assert_eq!(
      mirror_container_path("id_ed25519", home, "/home/eng").as_deref(),
      Some("/home/eng/.ssh/id_ed25519")
    );
  }

  #[test]
  fn symlink_identity_mounts_at_the_link_path() {
    let (dir, real) = host_home_with_key();
    std::os::unix::fs::symlink(dir.path().join(".ssh").join("id_ed25519"), dir.path().join(".ssh").join("link")).unwrap();
    let config = "Host git.example\n IdentityFile ~/.ssh/link\n";
    let adapted = adapt_in(&dir, config);
    assert_eq!(adapted.len(), 1);
    let decoy = adapted[0]
      .decoy_files
      .iter()
      .find(|file| file.name.ends_with(".decoy-key"))
      .unwrap();
    assert_eq!(decoy.container, "/home/agent/.ssh/link");
    let identity = adapted[0]
      .materialized
      .iter()
      .find(|(name, _)| name.ends_with(".identity"))
      .map(|(_, bytes)| String::from_utf8(bytes.clone()).unwrap())
      .unwrap();
    assert_eq!(identity, real.to_openssh().unwrap());
  }

  #[test]
  fn specificity_orders_exact_over_suffix_over_any() {
    let (dir, _) = host_home_with_key();
    write_identity(&dir, "id_a");
    write_identity(&dir, "id_b");
    write_identity(&dir, "id_c");
    let config = "Host *.corp\n IdentityFile ~/.ssh/id_a\nHost db.corp\n IdentityFile ~/.ssh/id_b\nHost *\n IdentityFile ~/.ssh/id_c\n";
    let adapted = adapt_in(&dir, config);
    assert_eq!(adapted.len(), 1, "every decoy key sits on the first entry: {adapted:?}");
    let fragment = &adapted[0].fragment;
    assert!(fragment.contains("ssh://*.corp"), "{fragment}");
    assert!(fragment.contains("ssh://db.corp"), "{fragment}");
    assert!(fragment.contains("ssh://*"), "{fragment}");
    let containers: Vec<&str> = adapted[0]
      .decoy_files
      .iter()
      .filter(|file| file.name.ends_with(".decoy-key"))
      .map(|file| file.container.as_str())
      .collect();
    assert_eq!(containers.len(), 3, "{containers:?}");
    let decoy = &adapted[0].decoy;
    let exact = decoy.find("IdentityFile /home/agent/.ssh/id_b").expect("exact decoy");
    let wildcard = decoy.find("IdentityFile /home/agent/.ssh/id_a").expect("wildcard decoy");
    assert!(exact < wildcard, "the more specific identity is offered first: {decoy}");
    assert!(decoy.contains("IdentitiesOnly yes"), "{decoy}");
    assert!(decoy.ends_with(config), "the source is preserved: {decoy}");
  }

  #[test]
  fn multi_name_host_grants_every_name() {
    let (dir, _) = host_home_with_key();
    let config = "Host a b\n IdentityFile ~/.ssh/id_ed25519\n";
    let adapted = adapt_in(&dir, config);
    assert_eq!(adapted.len(), 1);
    let fragment = &adapted[0].fragment;
    assert!(fragment.contains("ssh://a"), "{fragment}");
    assert!(fragment.contains("ssh://b"), "{fragment}");
  }

  #[test]
  fn negation_is_recorded_on_the_allow_entry() {
    let (dir, _) = host_home_with_key();
    let config = "Host !bastion *.corp\n IdentityFile ~/.ssh/id_ed25519\n";
    let adapted = adapt_in(&dir, config);
    assert_eq!(adapted.len(), 1, "{adapted:?}");
    assert!(adapted[0].fragment.contains("ssh://*.corp#!bastion"), "{}", adapted[0].fragment);
  }

  #[test]
  fn include_expands_hosts_from_the_host_home() {
    let (dir, _) = host_home_with_key();
    let extra = dir.path().join(".ssh").join("config.d");
    fs::create_dir_all(&extra).unwrap();
    fs::write(extra.join("extra"), "Host extra.example\n IdentityFile ~/.ssh/id_ed25519\n").unwrap();
    let config = "Include ~/.ssh/config.d/*\n";
    let adapted = adapt_in(&dir, config);
    assert_eq!(adapted.len(), 1, "{adapted:?}");
    assert!(adapted[0].fragment.contains("ssh://extra.example"), "{}", adapted[0].fragment);
  }

  #[test]
  fn match_is_a_typed_error() {
    let (dir, _) = host_home_with_key();
    let config = "Match host exec\nHost git.example\n IdentityFile ~/.ssh/id_ed25519\n";
    let err = adapt(Path::new("/home/ivan/.ssh/config"), config.as_bytes(), "/home/agent", dir.path()).expect_err("Match is a typed error");
    assert!(err.to_string().to_ascii_lowercase().contains("match"), "{err}");
  }

  #[test]
  fn proxyjump_identityagent_and_certificatefile_are_typed_errors() {
    let (dir, _) = host_home_with_key();
    for (keyword, config) in [
      ("proxyjump", "Host git.example\n ProxyJump jump\n IdentityFile ~/.ssh/id_ed25519\n"),
      (
        "identityagent",
        "Host git.example\n IdentityAgent SSH_AUTH_SOCK\n IdentityFile ~/.ssh/id_ed25519\n",
      ),
      (
        "certificatefile",
        "Host git.example\n CertificateFile ~/.ssh/id_ed25519-cert.pub\n IdentityFile ~/.ssh/id_ed25519\n",
      ),
    ] {
      let err = adapt(Path::new("/home/ivan/.ssh/config"), config.as_bytes(), "/home/agent", dir.path()).expect_err(keyword);
      assert!(err.to_string().to_ascii_lowercase().contains(keyword), "{keyword}: {err}");
    }
  }

  #[test]
  fn shared_identity_file_mounts_one_decoy() {
    let (dir, real) = host_home_with_key();
    let config = "Host a\n IdentityFile ~/.ssh/id_ed25519\nHost b\n IdentityFile ~/.ssh/id_ed25519\n";
    let adapted = adapt_in(&dir, config);
    assert_eq!(adapted.len(), 1, "{adapted:?}");
    let keys: Vec<_> = adapted[0]
      .decoy_files
      .iter()
      .filter(|file| file.container == "/home/agent/.ssh/id_ed25519")
      .collect();
    assert_eq!(keys.len(), 1, "one container path: {keys:?}");
    let decoy = SshKey::from_openssh(&String::from_utf8(keys[0].bytes.clone()).unwrap()).unwrap();
    assert_ne!(decoy.public(), real.public());
    assert!(
      adapted[0].fragment.contains("ssh://a") && adapted[0].fragment.contains("ssh://b"),
      "{}",
      adapted[0].fragment
    );
  }

  #[test]
  fn same_host_and_decoy_is_ambiguous() {
    let (dir, _) = host_home_with_key();
    let config = "Host git\n HostName github.com\n IdentityFile ~/.ssh/id_ed25519\nHost other\n HostName github.com\n IdentityFile ~/.ssh/id_ed25519\n";
    let err = adapt(Path::new("/home/ivan/.ssh/config"), config.as_bytes(), "/home/agent", dir.path())
      .expect_err("two blocks, one host, one decoy");
    let text = err.to_string();
    assert!(
      text.contains("git") && text.contains("other") && text.contains("github.com"),
      "{text}"
    );
  }

  fn write_identity(dir: &tempfile::TempDir, name: &str) {
    let key = SshKey::generate().unwrap();
    fs::write(dir.path().join(".ssh").join(name), key.to_openssh().unwrap()).unwrap();
  }
}
