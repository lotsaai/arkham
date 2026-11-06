//! Build the in-memory session and the launch plan.
//!
//! Grant fragments are parsed into the config the proxy keeps. They are not
//! written where the agent can open them.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use arkham_config::WriteProfile;
use arkham_config::grants::ResolvedConfig;
use serde::Deserialize;

use crate::Error;
use crate::adapt::RewriteAdapted;
use crate::host::forge::{forged_bytes, indexed_aliases, inode_index, projection_files};
use crate::host::plan::{Bind, CA_DEST, LaunchPlan, is_proxy_env};
use crate::paths::Mount;
use crate::stack::host_material;

/// A session ready to register. `resolved` holds real secrets and stays in
/// the daemon. `plan` is what the wrapper is allowed to see.
#[derive(Debug)]
pub struct PreparedSession {
  /// Proxy config for this project.
  pub resolved: ResolvedConfig,
  /// Decoy plan for the wrapper.
  pub plan: LaunchPlan,
  /// Rule env names captured while the config files were read.
  pub rule_envs: BTreeSet<String>,
}

#[derive(Deserialize)]
struct RulesDoc {
  #[serde(default)]
  rules: std::collections::BTreeMap<String, arkham_config::config::RuleCfg>,
}

/// Prepare `root` into `scratch`.
///
/// `ca_cert` is the certificate PEM only. The CA key stays with the daemon.
/// `caller_env` is the agent process environment from the register request.
///
/// # Errors
///
/// Returns an error when the workspace cannot be prepared, a grant fragment
/// does not parse, or a projected file cannot be written.
pub async fn prepare_session(
  root: &Path,
  scratch: &Path,
  profile: WriteProfile,
  ca_cert: &Path,
  version: &str,
  caller_env: &BTreeMap<String, String>,
) -> Result<PreparedSession, Error> {
  let material = host_material(root, scratch, version).await?;
  let mut config = material.config;
  for grant in &material.grants {
    merge_fragment(&mut config, grant)?;
  }
  arkham_fnox::resolve(&mut config, &material.registry, material.fnox.clone()).await?;
  let rule_envs = config.rules.values().map(|rule| rule.env.clone()).collect();
  let resolved = arkham_config::resolve(&config)?;
  let mut binds = Vec::new();
  push_mounts(&mut binds, &material.mounts, &material.workspace, false);
  push_mounts(&mut binds, &material.file_mounts, &material.workspace, true);
  push_mounts(&mut binds, &material.tool_mounts, &material.workspace, false);
  push_mounts(&mut binds, &material.guest, &material.workspace, true);
  let forged_dir = scratch.join("forged");
  std::fs::create_dir_all(&forged_dir)?;
  let projected = projection_files(root)?;
  let mut devices = std::collections::HashSet::new();
  for path in projected.iter().chain(binds.iter().map(|bind| &bind.dest)) {
    if let Ok(meta) = std::fs::metadata(path) {
      devices.insert(meta.dev());
    }
  }
  let roots = crate::host::forge::scan_roots(root, &projected);
  let inodes = inode_index(&devices, &roots);
  let mut index = 0u32;
  for path in projected {
    let source = forged_dir.join(index.to_string());
    index = index.saturating_add(1);
    std::fs::write(&source, forged_bytes(&path))?;
    push_with_aliases(&mut binds, &inodes, source, path);
  }
  let existing = binds.clone();
  for bind in existing {
    for alias in indexed_aliases(&inodes, &bind.dest) {
      if binds.iter().any(|existing| existing.dest == alias) {
        continue;
      }
      binds.push(Bind {
        source: bind.source.clone(),
        dest: alias,
        read_only: true,
      });
    }
  }
  let mut env = Vec::new();
  for name in ["PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LC_ALL", "LC_CTYPE"] {
    if let Some(value) = caller_env.get(name) {
      set_env(&mut env, name, value.clone());
    }
  }
  for name in &material.passthrough {
    if let Some(value) = caller_env.get(name) {
      set_env(&mut env, name, value.clone());
    }
  }
  for decoy in &material.decoys {
    set_env(&mut env, &decoy.env, decoy.value.clone());
  }
  if profile == WriteProfile::WorkspaceWrite {
    set_env(&mut env, "TMPDIR", "/tmp".to_string());
  }
  for name in ["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"] {
    set_env(&mut env, name, CA_DEST.to_string());
  }
  let plan = LaunchPlan {
    profile,
    workspace: material.workspace.clone(),
    binds,
    ca_host: ca_cert.to_path_buf(),
    ca_dest: PathBuf::from(CA_DEST),
    env,
    workdir: material.workspace,
    shell: material.shell.unwrap_or_else(|| "sh".to_string()),
  };
  Ok(PreparedSession { resolved, plan, rule_envs })
}

fn push_with_aliases(binds: &mut Vec<Bind>, inodes: &std::collections::HashMap<(u64, u64), Vec<PathBuf>>, source: PathBuf, dest: PathBuf) {
  for alias in indexed_aliases(inodes, &dest) {
    push_file_bind(binds, source.clone(), alias);
  }
  push_file_bind(binds, source, dest);
}

fn push_file_bind(binds: &mut Vec<Bind>, source: PathBuf, dest: PathBuf) {
  if std::fs::symlink_metadata(&dest).is_ok_and(|meta| meta.file_type().is_symlink()) {
    return;
  }
  if binds.iter().any(|existing| existing.dest == dest) {
    return;
  }
  binds.push(Bind {
    source,
    dest,
    read_only: true,
  });
}

fn merge_fragment(config: &mut arkham_config::config::AppConfig, grant: &RewriteAdapted) -> Result<(), Error> {
  if grant.fragment.trim().is_empty() {
    return Ok(());
  }
  let doc: RulesDoc = toml::from_str(&grant.fragment).map_err(|source| Error::FragmentParse { source })?;
  for (label, rule) in doc.rules {
    config.rules.insert(label, rule);
  }
  Ok(())
}

fn push_mounts(binds: &mut Vec<Bind>, mounts: &[Mount], workspace: &Path, force_read_only: bool) {
  for mount in mounts {
    if mount.container == workspace || mount.host == workspace {
      continue;
    }
    if !mount.container.is_absolute() || !mount.host.is_absolute() {
      continue;
    }
    binds.push(Bind {
      source: mount.host.clone(),
      dest: mount.container.clone(),
      read_only: force_read_only || mount.ro,
    });
  }
}

fn set_env(env: &mut Vec<(String, String)>, key: &str, value: String) {
  if is_proxy_env(key) {
    return;
  }
  if let Some(slot) = env.iter_mut().find(|(name, _)| name == key) {
    slot.1 = value;
  } else {
    env.push((key.to_string(), value));
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn the_rule_set_stays_at_the_snapshot_after_the_file_changes() {
    let root = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let config_dir = root.path().join(".config").join("arkham");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    std::fs::write(
      &config_path,
      "[rules.snapshot]\nenv = \"SNAPSHOT_PROBE\"\nvalue = \"real-snapshot-value\"\nallow = [\"https://example.com\"]\n",
    )
    .unwrap();
    std::fs::write(scratch.path().join("ca.pem"), "-----BEGIN CERTIFICATE-----\n").unwrap();
    let prepared = prepare_session(
      root.path(),
      scratch.path(),
      WriteProfile::WorkspaceWrite,
      &scratch.path().join("ca.pem"),
      "test",
      &BTreeMap::new(),
    )
    .await
    .unwrap();
    assert!(prepared.rule_envs.contains("SNAPSHOT_PROBE"));
    std::fs::write(
      &config_path,
      "[rules.other]\nenv = \"OTHER\"\nvalue = \"x\"\nallow = [\"https://example.com\"]\n",
    )
    .unwrap();
    assert!(prepared.rule_envs.contains("SNAPSHOT_PROBE"));
    assert!(!prepared.rule_envs.contains("OTHER"));
    let rendered = format!("{:?}", prepared.plan);
    assert!(!rendered.contains("real-snapshot-value"));
  }

  #[tokio::test]
  async fn the_plan_env_comes_from_the_caller_not_the_process() {
    let root = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let config_dir = root.path().join(".config").join("arkham");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("config.toml"), "[workspace]\npassthrough = [\"FROM_AGENT\"]\n").unwrap();
    std::fs::write(root.path().join("fnox.toml"), "# workspace\n").unwrap();
    std::fs::write(scratch.path().join("ca.pem"), "-----BEGIN CERTIFICATE-----\n").unwrap();
    let mut caller = BTreeMap::new();
    caller.insert("PATH".to_string(), "/from-agent/bin".to_string());
    caller.insert("HOME".to_string(), "/from-agent/home".to_string());
    caller.insert("TERM".to_string(), "agent-term".to_string());
    caller.insert("FROM_AGENT".to_string(), "agent-value".to_string());
    let prepared = prepare_session(
      root.path(),
      scratch.path(),
      WriteProfile::WorkspaceWrite,
      &scratch.path().join("ca.pem"),
      "test",
      &caller,
    )
    .await
    .unwrap();
    let env: BTreeMap<_, _> = prepared.plan.env.iter().cloned().collect();
    let process_path = std::env::var("PATH").unwrap();
    assert_ne!(process_path, "/from-agent/bin");
    assert_eq!(env.get("PATH").map(String::as_str), Some("/from-agent/bin"));
    assert_eq!(env.get("HOME").map(String::as_str), Some("/from-agent/home"));
    assert_eq!(env.get("TERM").map(String::as_str), Some("agent-term"));
    assert_eq!(env.get("FROM_AGENT").map(String::as_str), Some("agent-value"));
    assert_ne!(env.get("PATH").map(String::as_str), Some(process_path.as_str()));
  }
}
