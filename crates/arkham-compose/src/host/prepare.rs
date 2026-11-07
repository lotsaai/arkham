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
  // A home directory is not a project. Prepare an empty tree so the host
  // directory at the session path is not read, then use the private tmpfs.
  let private = crate::host::discover::is_private_session(root);
  let empty_root = scratch.join("empty");
  let material_root = if private {
    std::fs::create_dir_all(&empty_root)?;
    empty_root.as_path()
  } else {
    root
  };
  let material = host_material(material_root, scratch, version).await?;
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
  let projected = projected_files(material_root, &material.mounts)?;
  let mut devices = std::collections::HashSet::new();
  for path in projected.iter().chain(binds.iter().map(|bind| &bind.dest)) {
    if let Ok(meta) = std::fs::metadata(path) {
      devices.insert(meta.dev());
    }
  }
  let roots = crate::host::forge::scan_roots(material_root, &projected);
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
  let protected = protected_config_paths(material_root, &binds)?;
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
  let workspace = if private {
    PathBuf::from(crate::host::discover::PRIVATE_SESSION_ROOT)
  } else {
    material.workspace
  };
  let plan = LaunchPlan {
    profile,
    workspace: workspace.clone(),
    binds,
    protected,
    ca_host: ca_cert.to_path_buf(),
    ca_dest: PathBuf::from(CA_DEST),
    env,
    workdir: workspace,
    shell: material.shell.unwrap_or_else(|| "sh".to_string()),
  };
  Ok(PreparedSession { resolved, plan, rule_envs })
}

fn protected_config_paths(workspace: &Path, binds: &[Bind]) -> Result<Vec<PathBuf>, Error> {
  let mut candidates = vec![workspace.join(".config/arkham"), workspace.join(".config/arkham.toml")];
  if let Some(home) = dirs::home_dir() {
    candidates.push(home.join(".config/arkham"));
  }
  candidates.extend(arkham_config::config::user_config_dirs().into_iter().map(|dir| dir.join("arkham")));
  if let Some(path) = std::env::var_os("ARKHAM_CONFIG") {
    candidates.push(PathBuf::from(path));
  }
  if let Some(path) = arkham_config::config::rules_dir() {
    candidates.push(path);
  }

  let mut targets = BTreeSet::new();
  let mut files = BTreeSet::new();
  for candidate in candidates {
    match std::fs::symlink_metadata(&candidate) {
      Ok(_) => collect_protected(&candidate, &mut targets, &mut files)?,
      Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
      Err(source) => return Err(source.into()),
    }
  }

  let devices: std::collections::HashSet<u64> = files
    .iter()
    .map(std::fs::metadata)
    .collect::<std::io::Result<Vec<_>>>()?
    .into_iter()
    .map(|meta| meta.dev())
    .collect();
  let mut roots = crate::host::forge::scan_roots(workspace, &files.iter().cloned().collect::<Vec<_>>());
  for bind in binds {
    roots.push(std::fs::canonicalize(&bind.source).unwrap_or_else(|_| bind.source.clone()));
  }
  #[cfg(target_os = "linux")]
  for name in super::plan::SYSTEM_ROOTS {
    if let Ok(path) = std::fs::canonicalize(Path::new("/").join(name)) {
      roots.push(path);
    }
  }
  #[cfg(target_os = "linux")]
  if !devices.is_empty() {
    let mounts = mounted_roots(&roots)?;
    roots.extend(mounts);
  }
  let inodes = inode_index(&devices, &roots);
  for file in &files {
    targets.extend(indexed_aliases(&inodes, file));
  }
  let source_paths: Vec<_> = targets.iter().cloned().collect();
  for bind in binds {
    let source = std::fs::canonicalize(&bind.source).unwrap_or_else(|_| bind.source.clone());
    for path in &source_paths {
      if let Ok(relative) = path.strip_prefix(&source) {
        targets.insert(bind.dest.join(relative));
      }
    }
  }
  Ok(targets.into_iter().collect())
}

#[cfg(target_os = "linux")]
fn mounted_roots(roots: &[PathBuf]) -> Result<Vec<PathBuf>, Error> {
  use std::os::unix::ffi::OsStringExt as _;

  let mountinfo = std::fs::read("/proc/self/mountinfo")?;
  let mut mounted = Vec::new();
  for line in mountinfo.split(|byte| *byte == b'\n') {
    let Some(encoded) = line.split(|byte| *byte == b' ').nth(4) else {
      continue;
    };
    let mut path = Vec::with_capacity(encoded.len());
    let mut bytes = encoded.iter().copied();
    while let Some(byte) = bytes.next() {
      if byte == b'\\' {
        match (bytes.next(), bytes.next(), bytes.next()) {
          (Some(b'0'), Some(b'4'), Some(b'0')) => path.push(b' '),
          (Some(b'0'), Some(b'1'), Some(b'1')) => path.push(b'\t'),
          (Some(b'0'), Some(b'1'), Some(b'2')) => path.push(b'\n'),
          (Some(b'1'), Some(b'3'), Some(b'4')) => path.push(b'\\'),
          _ => continue,
        }
      } else {
        path.push(byte);
      }
    }
    let path = PathBuf::from(std::ffi::OsString::from_vec(path));
    if roots.iter().any(|root| path.starts_with(root)) {
      mounted.push(path);
    }
  }
  Ok(mounted)
}

fn collect_protected(path: &Path, targets: &mut BTreeSet<PathBuf>, files: &mut BTreeSet<PathBuf>) -> Result<(), Error> {
  let path = match std::fs::canonicalize(path) {
    Ok(path) => path,
    Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
    Err(source) => return Err(source.into()),
  };
  if !targets.insert(path.clone()) {
    return Ok(());
  }
  let metadata = std::fs::metadata(&path)?;
  if metadata.is_dir() {
    for entry in std::fs::read_dir(path)? {
      collect_protected(&entry?.path(), targets, files)?;
    }
  } else if metadata.is_file() {
    files.insert(path);
  }
  Ok(())
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

/// Secret files in the enlisted root and in every include tree.
///
/// The include walk uses the same projection as the root. A mount of the
/// root itself is already covered. `/` is not a candidate.
///
/// # Errors
///
/// Returns an error when a discovered fnox file is not valid TOML.
fn projected_files(root: &Path, mounts: &[Mount]) -> Result<Vec<PathBuf>, Error> {
  let mut projected = projection_files(root)?;
  let workspace = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
  for mount in mounts {
    if mount.host == root || mount.host == workspace || mount.host == Path::new("/") {
      continue;
    }
    let tree = std::fs::canonicalize(&mount.host)?;
    if tree == workspace || tree == Path::new("/") || !tree.is_dir() {
      continue;
    }
    for path in projection_files(&tree)? {
      let dest = match path.strip_prefix(&tree) {
        Ok(relative) if !relative.as_os_str().is_empty() => mount.container.join(relative),
        _ => path,
      };
      if !projected.iter().any(|existing| existing == &dest) {
        projected.push(dest);
      }
    }
  }
  Ok(projected)
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

  #[test]
  fn a_dangling_config_link_does_not_hide_existing_config_files() {
    let root = tempfile::tempdir().unwrap();
    let existing = root.path().join("config.toml");
    std::fs::write(&existing, "# PRIVATE_CONTENT\n").unwrap();
    std::os::unix::fs::symlink("missing.toml", root.path().join("dangling.toml")).unwrap();
    let mut targets = BTreeSet::new();
    let mut files = BTreeSet::new();
    collect_protected(root.path(), &mut targets, &mut files).unwrap();
    assert_eq!(files, BTreeSet::from([existing.canonicalize().unwrap()]));
    assert!(!root.path().join("missing.toml").exists());
  }

  #[test]
  fn symlink_targets_and_translated_hardlinks_are_protected() {
    let base = tempfile::tempdir().unwrap();
    let workspace = base.path().join("workspace");
    let source = base.path().join("source");
    let dest = base.path().join("destination");
    std::fs::create_dir_all(workspace.join(".config")).unwrap();
    std::fs::create_dir_all(workspace.join("real-config")).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    let config = workspace.join("real-config/config.toml");
    std::fs::write(&config, "# PRIVATE_CONTENT\n").unwrap();
    std::os::unix::fs::symlink("../real-config", workspace.join(".config/arkham")).unwrap();
    std::fs::hard_link(&config, source.join("alias")).unwrap();
    let binds = vec![Bind {
      source,
      dest: dest.clone(),
      read_only: false,
    }];
    let protected = protected_config_paths(&workspace, &binds).unwrap();
    assert!(protected.contains(&workspace.join("real-config")));
    assert!(protected.contains(&config));
    assert!(protected.contains(&dest.join("alias")));
  }

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
  async fn an_include_tree_projects_its_fnox_file() {
    let base = tempfile::tempdir().unwrap();
    let base = base.path().canonicalize().unwrap();
    let root = base.join("proj");
    let sibling = base.join("sibling");
    std::fs::create_dir_all(root.join(".config/arkham")).unwrap();
    std::fs::create_dir_all(&sibling).unwrap();
    let marker = "REAL_INCLUDE_SECRET_9f3a";
    let fnox = sibling.join("fnox.toml");
    std::fs::write(&fnox, format!("# {marker}\n")).unwrap();
    std::fs::write(root.join("fnox.toml"), "# workspace\n").unwrap();
    std::fs::write(root.join(".config/arkham/config.toml"), "[workspace]\ninclude = [\"../sibling\"]\n").unwrap();
    let scratch = tempfile::tempdir().unwrap();
    std::fs::write(scratch.path().join("ca.pem"), "-----BEGIN CERTIFICATE-----\n").unwrap();
    let prepared = prepare_session(
      &root,
      scratch.path(),
      WriteProfile::WorkspaceWrite,
      &scratch.path().join("ca.pem"),
      "test",
      &BTreeMap::new(),
    )
    .await
    .unwrap();
    let bind = prepared.plan.binds.iter().find(|bind| bind.dest == fnox).unwrap();
    assert_ne!(bind.source, fnox);
    let forged = std::fs::read_to_string(&bind.source).unwrap();
    assert!(!forged.contains(marker), "{forged}");
    assert!(std::fs::read_to_string(&fnox).unwrap().contains(marker));
  }

  #[tokio::test]
  async fn a_private_tmp_session_does_not_project_home_or_the_host_tmp() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path().canonicalize().unwrap();
    let marker = "HOME_PROJECT_SECRET_9f3a";
    std::fs::write(home.join("fnox.toml"), format!("# {marker}\n")).unwrap();
    std::fs::create_dir(home.join(".git")).unwrap();
    let probe = PathBuf::from(format!("/tmp/arkham-probe-{}", std::process::id()));
    std::fs::create_dir_all(&probe).unwrap();
    let host_fnox = probe.join("fnox.toml");
    std::fs::write(&host_fnox, "# HOST_TMP_FNOX\n").unwrap();
    let saved = std::env::var_os("HOME");
    let saved_xdg = std::env::var_os("XDG_CONFIG_HOME");
    let saved_jj = std::env::var_os("JJ_CONFIG");
    // SAFETY: test-only mutation of HOME. The previous value is restored before return.
    unsafe {
      std::env::set_var("HOME", &home);
      std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
      std::env::set_var("JJ_CONFIG", home.join(".jjconfig.toml"));
    };
    let scratch = tempfile::tempdir().unwrap();
    std::fs::write(scratch.path().join("ca.pem"), "-----BEGIN CERTIFICATE-----\n").unwrap();
    let prepared = prepare_session(
      Path::new("/tmp"),
      scratch.path(),
      WriteProfile::WorkspaceWrite,
      &scratch.path().join("ca.pem"),
      "test",
      &BTreeMap::new(),
    )
    .await;
    // SAFETY: test-only restore of the HOME value captured above.
    unsafe {
      match saved {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
      }
      match saved_xdg {
        Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
        None => std::env::remove_var("XDG_CONFIG_HOME"),
      }
      match saved_jj {
        Some(value) => std::env::set_var("JJ_CONFIG", value),
        None => std::env::remove_var("JJ_CONFIG"),
      }
    }
    let _ = std::fs::remove_dir_all(&probe);
    let prepared = prepared.unwrap();
    assert_eq!(prepared.plan.workspace, Path::new("/tmp"));
    assert_eq!(prepared.plan.workdir, Path::new("/tmp"));
    #[cfg(target_os = "linux")]
    assert_private_session_argv(&prepared.plan, &home);
    assert!(
      prepared
        .plan
        .binds
        .iter()
        .all(|bind| { bind.source != home && !bind.source.starts_with(&home) && bind.dest != home && !bind.dest.starts_with(&home) }),
      "home was bound\n{:?}",
      prepared.plan.binds
    );
    assert!(
      prepared.plan.binds.iter().all(|bind| {
        bind.source != Path::new("/tmp")
          && bind.dest != Path::new("/tmp")
          && !bind.source.starts_with(&probe)
          && !bind.dest.starts_with(&probe)
      }),
      "host tmp was projected\n{:?}",
      prepared.plan.binds
    );
    let rendered = format!("{:?}", prepared.plan);
    assert!(!rendered.contains(marker), "{rendered}");
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

  #[cfg(target_os = "linux")]
  fn assert_private_session_argv(plan: &crate::host::plan::LaunchPlan, home: &Path) {
    let args = crate::host::plan::bwrap_argv(plan, &[]).unwrap();
    assert!(
      args.windows(2).any(|window| window[0] == "--chdir" && window[1] == "/tmp"),
      "argv missing --chdir /tmp"
    );
    assert!(
      !args.windows(3).any(|window| {
        (window[0] == "--bind" || window[0] == "--ro-bind")
          && (window[1] == "/tmp" || window[1] == home.as_os_str() || window[2] == home.as_os_str())
      }),
      "argv mounted home or host tmp"
    );
  }
}
