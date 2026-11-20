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
use crate::material::host_material;
use arkham_launch_plan::{Bind, CA_DEST, LaunchPlan, PRIVATE_SESSION_ROOT, is_private_session};
use arkham_paths::Mount;
use arkham_projection::{
  forged_bytes, indexed_aliases, inode_index, projected_files, protected_config_paths, push_with_aliases, scan_roots,
};
use arkham_tool_config::RewriteAdapted;

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

/// Public trust anchor and the daemon's private source bundle.
#[derive(Debug, Clone, Copy)]
pub struct CaPaths<'a> {
  /// Certificate-only PEM passed into the sandbox.
  pub cert: &'a Path,
  /// Daemon CA bundle whose contents must stay hidden.
  pub source: &'a Path,
}

#[derive(Deserialize)]
struct RulesDoc {
  #[serde(default)]
  rules: std::collections::BTreeMap<String, arkham_config::config::RuleCfg>,
}

/// Prepare `root` into `scratch`.
///
/// `ca` separates the public certificate from the sensitive daemon source.
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
  ca: CaPaths<'_>,
  version: &str,
  caller_env: &BTreeMap<String, String>,
) -> Result<PreparedSession, Error> {
  // A home directory is not a project. Prepare an empty tree so the host
  // directory at the session path is not read, then use the private tmpfs.
  let private = is_private_session(root);
  let empty_root = scratch.join("empty");
  let material_root = if private {
    std::fs::create_dir_all(&empty_root)?;
    empty_root.as_path()
  } else {
    root
  };
  let material = host_material(material_root, scratch, version).await?;
  let grants_dir = scratch.join("grants");
  crate::grant_state::write_state(&grants_dir, &material.grants)?;
  let mut config = material.config;
  for grant in &material.grants {
    merge_fragment(&mut config, grant, &grants_dir)?;
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
  let roots = scan_roots(material_root, &projected);
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
  let mut config_masks = protected_config_paths(material_root, &binds, ca.source)?;
  if grants_dir.exists() {
    config_masks.push(grants_dir);
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
  let workspace = if private {
    PathBuf::from(PRIVATE_SESSION_ROOT)
  } else {
    material.workspace
  };
  let plan = LaunchPlan {
    profile,
    workspace: workspace.clone(),
    binds,
    protected: config_masks,
    ca_host: ca.cert.to_path_buf(),
    ca_dest: PathBuf::from(CA_DEST),
    env,
    workdir: workspace,
    shell: material.shell.unwrap_or_else(|| "sh".to_string()),
  };
  Ok(PreparedSession { resolved, plan, rule_envs })
}

fn merge_fragment(config: &mut arkham_config::config::AppConfig, grant: &RewriteAdapted, grants_dir: &Path) -> Result<(), Error> {
  if grant.fragment.trim().is_empty() {
    return Ok(());
  }
  let old = format!("{}/rules.d/", arkham_tool_config::GRANTS_STATE_DIR);
  let new = format!("{}/rules.d/", grants_dir.display());
  let escaped = toml::Value::String(new.clone()).to_string();
  let escaped = escaped
    .get(1..escaped.len().saturating_sub(1))
    .ok_or_else(|| Error::FragmentPathEncoding {
      path: grants_dir.to_path_buf(),
    })?;
  let encoded_old: String = url::form_urlencoded::byte_serialize(old.as_bytes()).collect();
  let encoded_new: String = url::form_urlencoded::byte_serialize(new.as_bytes()).collect();
  let fragment = grant.fragment.replace(&old, escaped).replace(&encoded_old, &encoded_new);
  let doc: RulesDoc = toml::from_str(&fragment).map_err(|source| Error::FragmentParse { source })?;
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

fn is_proxy_env(name: &str) -> bool {
  matches!(name.to_ascii_lowercase().as_str(), "http_proxy" | "https_proxy" | "all_proxy")
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
  use arkham_test_support::IsolatedHome;
  use test_context::test_context;

  use super::*;

  #[test]
  fn proxy_environment_names_are_filtered_case_insensitively() {
    let mut env = Vec::new();
    for name in ["HTTP_PROXY", "Https_Proxy", "all_proxy"] {
      set_env(&mut env, name, "secret".to_string());
    }
    set_env(&mut env, "NO_PROXY", "localhost".to_string());
    assert_eq!(env, vec![("NO_PROXY".to_string(), "localhost".to_string())]);
  }

  #[test]
  fn materialized_client_certificate_is_available_to_the_proxy() {
    let scratch = tempfile::tempdir().unwrap();
    let config_file = scratch.path().join("config.toml");
    std::fs::write(&config_file, "").unwrap();
    let cli = arkham_config::cli::Cli { config: Some(config_file) };
    let (mut config, _) = arkham_config::config::load(&cli, None).unwrap();
    let grants_dir = scratch.path().join("grants");
    let grant = RewriteAdapted {
      fragment: "[rules.test]\nenv = \"TEST_TOKEN\"\nallow = [\"https://example.com\"]\n[rules.test.tls.\"https://example.com\"]\nroot_cert = \"/arkham/grants/rules.d/kube-test.ca\"\n".to_string(),
      decoy: String::new(),
      materialized: vec![("kube-test.ca".to_string(), b"PRIVATE CA".to_vec())],
      decoy_files: Vec::new(),
    };
    crate::grant_state::write_state(&grants_dir, std::slice::from_ref(&grant)).unwrap();
    merge_fragment(&mut config, &grant, &grants_dir).unwrap();
    let path = config.rules["test"].tls["https://example.com"].root_cert.as_ref().unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"PRIVATE CA");
    assert!(path.starts_with(&grants_dir));
  }

  #[test_context(IsolatedHome)]
  #[tokio::test]
  async fn the_rule_set_stays_at_the_snapshot_after_the_file_changes(_ctx: &mut IsolatedHome) {
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
      CaPaths {
        cert: &scratch.path().join("ca.pem"),
        source: &root.path().join("missing-ca"),
      },
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

  #[test_context(IsolatedHome)]
  #[tokio::test]
  async fn an_include_tree_projects_its_fnox_file(_ctx: &mut IsolatedHome) {
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
      CaPaths {
        cert: &scratch.path().join("ca.pem"),
        source: &root.join("missing-ca"),
      },
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

  #[test_context(IsolatedHome)]
  #[tokio::test]
  async fn a_private_tmp_session_does_not_project_home_or_the_host_tmp(ctx: &mut IsolatedHome) {
    let home = ctx.path().canonicalize().unwrap();
    let marker = "HOME_PROJECT_SECRET_9f3a";
    std::fs::write(home.join("fnox.toml"), format!("# {marker}\n")).unwrap();
    std::fs::create_dir(home.join(".git")).unwrap();
    let probe = PathBuf::from(format!("/tmp/arkham-probe-{}", std::process::id()));
    std::fs::create_dir_all(&probe).unwrap();
    let host_fnox = probe.join("fnox.toml");
    std::fs::write(&host_fnox, "# HOST_TMP_FNOX\n").unwrap();
    let scratch = tempfile::tempdir().unwrap();
    std::fs::write(scratch.path().join("ca.pem"), "-----BEGIN CERTIFICATE-----\n").unwrap();
    let prepared = prepare_session(
      Path::new("/tmp"),
      scratch.path(),
      WriteProfile::WorkspaceWrite,
      CaPaths {
        cert: &scratch.path().join("ca.pem"),
        source: &scratch.path().join("missing-ca"),
      },
      "test",
      &BTreeMap::new(),
    )
    .await;
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

  #[test_context(IsolatedHome)]
  #[tokio::test]
  async fn the_plan_env_comes_from_the_caller_not_the_process(_ctx: &mut IsolatedHome) {
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
      CaPaths {
        cert: &scratch.path().join("ca.pem"),
        source: &root.path().join("missing-ca"),
      },
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
  fn assert_private_session_argv(plan: &LaunchPlan, home: &Path) {
    let args = arkham_sandbox::bwrap_argv(plan, &[]).unwrap();
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
