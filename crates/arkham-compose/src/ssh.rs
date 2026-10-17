//! Ssh config adapter for `file_rewrite`: an ssh config's `Host` blocks are
//! the same information a rule holds — host, port, identity — so the adapter
//! derives one ssh grant per exact-host block that carries an `IdentityFile`,
//! replacing the real key with a decoy and pinning the upstream host key.
//! The decoy config is the source verbatim: the destination stays the
//! identity, and the decoy key and `known_hosts` mount at the mirrored paths
//! under the container home. Blocks with wildcards, or without an
//! `IdentityFile`, are skipped; `Include` and `Match` cannot be derived and
//! error; the format is never sniffed, only stated.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::config::{HostSshCfg, IfMissing};
use arkham_pki::ssh::SshKey;

use crate::adapt::{DecoyFile, GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, render_fragment, rewrite_label};
use crate::error::Error;

/// One `Host` block as the config states it.
#[derive(Debug, Default)]
struct HostBlock {
  /// `Host` tokens.
  patterns: Vec<String>,
  /// `HostName` override, when stated.
  hostname: Option<String>,
  /// `Port`, when stated.
  port: Option<u16>,
  /// `IdentityFile`, when stated.
  identity: Option<String>,
  /// Why this block cannot be derived, when it cannot. Real-world ssh
  /// configs carry `Include`, `Match`, and second identities; the adapter
  /// warns and skips the block instead of failing the source.
  skip: Option<String>,
}

impl HostBlock {
  /// The block maps when every `Host` token is an exact name and the block
  /// carries exactly one identity. Pattern blocks are skipped, not guessed.
  fn mappable(&self) -> bool {
    self.identity.is_some()
      && !self.patterns.is_empty()
      && self.patterns.iter().all(|pattern| !pattern.contains(['*', '?', '!']))
      && !self.patterns.iter().any(|pattern| pattern.starts_with('.'))
  }
}

/// Map an ssh config onto one grant fragment per mappable `Host` block, plus
/// the agent's decoy twin files. The first entry carries the decoy document
/// (the config verbatim) and every decoy file; each entry carries its own
/// fragment and key blobs.
///
/// Real-world ssh configs are often not fully valid: a block an
/// `Include`/`Match` directive, a second `IdentityFile`, `ProxyJump`,
/// `IdentityAgent`, or an unreadable identity makes underivable is skipped
/// with a warning, and the mappable blocks still derive. Only key minting
/// failures are errors.
///
/// # Errors
///
/// Returns an error when a decoy key cannot be minted.
pub(crate) fn adapt(source: &Path, content: &[u8], home: &str, host_home: &Path) -> Result<Vec<RewriteAdapted>, Error> {
  let blocks = parse(content);
  let mut adapted: Vec<RewriteAdapted> = Vec::new();
  for block in &blocks {
    if !block.mappable() {
      continue;
    }
    let host = block.hostname.clone().unwrap_or_else(|| block.patterns[0].clone());
    if let Some(reason) = &block.skip {
      tracing::warn!(config = %source.display(), host = %host, reason, "ssh block skipped: it cannot be derived");
      continue;
    }
    let port = block.port.unwrap_or(22);
    let identity = block.identity.as_ref().expect("mappable checked an identity");
    let label = rewrite_label(source, &host)?;
    let entry = if port == 22 {
      format!("ssh://{host}")
    } else {
      format!("ssh://{host}:{port}")
    };
    let real_path = host_identity_path(identity, host_home);
    let real = match fs::read_to_string(&real_path) {
      Ok(real) => real,
      Err(err) => {
        tracing::warn!(config = %source.display(), host = %host, identity = %real_path.display(), %err, "ssh block skipped: the identity is unreadable");
        continue;
      }
    };
    let decoy = SshKey::generate()?;
    let decoy_line = decoy.public_line()?;
    let fragment = render_fragment(
      source,
      &label,
      &GrantFragment {
        env: label.to_uppercase().replace('-', "_"),
        registry: false,
        allow: vec![entry.clone()],
        value: None,
        real: None,
        if_missing: Some(IfMissing::Ignore),
        tls: BTreeMap::new(),
        ssh: BTreeMap::from([(
          entry,
          HostSshCfg {
            identity: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/ssh-{label}.identity"))),
            guest_key: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/ssh-{label}.guest_key"))),
          },
        )]),
      },
    )?;
    let decoy_key = decoy.to_openssh()?;
    let Some(container) = mirror_container_path(identity, host_home, home) else {
      tracing::warn!(config = %source.display(), host = %host, identity = %identity, "ssh block skipped: the identity does not mirror under the container home");
      continue;
    };
    let decoy_files = vec![DecoyFile {
      name: format!("ssh-{label}.decoy-key"),
      bytes: decoy_key.into_bytes(),
      container,
    }];
    let entry = RewriteAdapted {
      fragment,
      decoy: String::new(),
      materialized: vec![
        (format!("ssh-{label}.identity"), real.into_bytes()),
        (format!("ssh-{label}.guest_key"), decoy_line.into_bytes()),
      ],
      decoy_files,
    };
    adapted.push(entry);
  }
  if let Some(first) = adapted.first_mut() {
    // The decoy config is the source verbatim under one global option:
    // accept-new lets the agent's own ssh record arkham's host key on
    // first use — ssh's mechanism is the allowlist, arkham adds no pins.
    first.decoy = format!("StrictHostKeyChecking accept-new\n\n{}", String::from_utf8_lossy(content));
    first.decoy_files.push(DecoyFile {
      name: "ssh-known-hosts".to_string(),
      bytes: Vec::new(),
      container: format!("{home}/.ssh/known_hosts"),
    });
  }
  Ok(adapted)
}

/// Parse the config into blocks, marking what cannot be derived. Nothing
/// fails: an underivable line marks its block with the reason, and the
/// caller warns and skips that block.
fn parse(content: &[u8]) -> Vec<HostBlock> {
  let mut blocks: Vec<HostBlock> = vec![HostBlock::default()];
  for line in String::from_utf8_lossy(content).lines() {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
      continue;
    }
    let Some((keyword, value)) = line.split_once(char::is_whitespace).or_else(|| line.split_once('=')) else {
      blocks.last_mut().expect("blocks starts with one").skip = Some(format!("line `{line}` is not a directive"));
      continue;
    };
    let keyword = keyword.to_ascii_lowercase();
    let value = value.trim();
    if keyword == "host" {
      blocks.push(HostBlock {
        patterns: value.split_whitespace().map(str::to_string).collect(),
        ..HostBlock::default()
      });
      continue;
    }
    let block = blocks.last_mut().expect("blocks starts with one");
    match keyword.as_str() {
      "include" | "match" => block.skip = Some(format!("`{keyword}` cannot be derived")),
      "hostname" => block.hostname = Some(value.to_string()),
      "port" => match value.parse() {
        Ok(port) => block.port = Some(port),
        Err(_) => block.skip = Some(format!("port `{value}` is not a number")),
      },
      "proxyjump" => block.skip = Some("ProxyJump cannot be derived".to_string()),
      "identityagent" => block.skip = Some("IdentityAgent cannot be derived".to_string()),
      "identityfile" if block.identity.replace(value.to_string()).is_some() => {
        block.skip = Some(format!("identityfile `{value}`: a derived host states exactly one identity"));
      }
      _ => {}
    }
  }
  blocks
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
  if let Some(rest) = identity.strip_prefix("~/") {
    return Some(format!("{home}/{rest}"));
  }
  let path = Path::new(identity);
  if path.is_absolute() {
    let rest = path.strip_prefix(host_home).ok()?;
    return Some(format!("{home}/{}", rest.display()));
  }
  Some(format!("{home}/.ssh/{identity}"))
}

#[cfg(test)]
mod tests {
  use std::fmt::Write as _;

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
    assert_eq!(adapted.len(), 1, "the wildcard block is skipped");
    let entry = &adapted[0];
    assert!(
      entry.decoy.starts_with("StrictHostKeyChecking accept-new\n\n") && entry.decoy.ends_with(CONFIG),
      "the decoy config is the source under the accept-new option: {}",
      entry.decoy
    );
    assert_eq!(entry.materialized.len(), 2);
    let names: Vec<&String> = entry.materialized.iter().map(|(name, _)| name).collect();
    assert!(names.iter().all(|name| name.starts_with("ssh-")), "{names:?}");

    let mut out = String::new();
    let _ = writeln!(out, "{}", entry.fragment);
    let doc: toml::Value = toml::from_str(&out).unwrap();
    let rule = doc.get("rules").unwrap().get("home-ivan-ssh-config-git-example").unwrap();
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
        .ends_with("/rules.d/ssh-home-ivan-ssh-config-git-example.identity")
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
  fn a_second_identity_skips_the_block() {
    let (dir, _) = host_home_with_key();
    let config = "Host git.example\n IdentityFile ~/.ssh/id_ed25519\n IdentityFile ~/.ssh/other\n";
    let adapted = adapt_in(&dir, config);
    assert!(adapted.is_empty(), "{adapted:?}");
  }

  #[test]
  fn tilde_parent_does_not_escape_the_container_home() {
    let home = Path::new("/host/home/eng");
    let mirrored = mirror_container_path("~/../.ssh/id_ed25519", home, "/home/eng");
    assert!(
      mirrored.as_deref().is_none_or(|path| !path.contains("..") && path.starts_with("/home/eng/")),
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
    let decoy = adapted[0].decoy_files.iter().find(|file| file.name.ends_with(".decoy-key")).unwrap();
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
  fn include_and_match_skip_their_block_not_the_source() {
    let (dir, _) = host_home_with_key();
    let config = "Include other\nMatch final\nHost git.example\n IdentityFile ~/.ssh/id_ed25519\n";
    let adapted = adapt_in(&dir, config);
    assert_eq!(adapted.len(), 1, "the mappable block survives the directives: {adapted:?}");
  }
}
