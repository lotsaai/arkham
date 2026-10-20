//! Discovery chain copied from fnox-core 1.35.2 src/config.rs and extended
//! with one extra level.
//!
//! Copied verbatim: load, `load_with_recursion`, `load_recursive`,
//! `find_project_dir`, `load_global`, and `merge_configs`. The only change inside the
//! copied bodies is the level added in `load_recursive`, which reads
//! <config-dir>/arkham/fnox.toml and its profile stand-in after fnox own global
//! config and stacks them above it.
//!
//! Associated functions became free functions because Rust does not allow
//! inherent impls on a foreign type. Merge order, parent recursion, root = true,
//! and import handling are unchanged. fnox's `load_explicit` is not copied: it
//! serves explicit `--config` paths, which arkham has none of.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fnox_core::FnoxError;
use fnox_core::Result;
use fnox_core::config::Config;
use fnox_core::config::DaemonConfig;
use fnox_core::config::McpConfig;
use fnox_core::config::all_config_filenames;
use fnox_core::env;
use fnox_core::settings::Settings;
use fnox_core::source_registry;
/// Parse one fnox config file into a layered [`Config`].
///
/// # Errors
///
/// Returns a diagnostic carrying the file name and span when the TOML is
/// malformed or a layer has an unexpected type.
pub fn load<P: AsRef<Path>>(path: P) -> Result<Config> {
  use miette::{NamedSource, SourceSpan};

  let path = path.as_ref();
  let content = fs::read_to_string(path).map_err(|source| FnoxError::ConfigReadFailed {
    path: path.to_path_buf(),
    source,
  })?;

  // Register the source for error reporting
  source_registry::register(path, content.clone());

  let mut config: Config = toml_edit::de::from_str(&content).map_err(|e| {
    // Try to create a source-aware error with span highlighting
    if let Some(span) = e.span() {
      FnoxError::ConfigParseErrorWithSource {
        message: e.message().to_string(),
        src: Arc::new(NamedSource::new(path.display().to_string(), Arc::new(content))),
        span: SourceSpan::new(span.start.into(), span.end - span.start),
      }
    } else {
      // Fall back to the basic error if no span available
      FnoxError::ConfigParseError { source: e }
    }
  })?;

  if let Some(profile) = profile_name_from_file(path) {
    scope_to_profile(&mut config, profile);
  }

  // Set source paths for all secrets and providers
  set_source_paths(&mut config, path);

  Ok(config)
}

fn load_with_recursion<P: AsRef<Path>>(_start_path: P, include_local_sync: bool) -> Result<Config> {
  // Start from current working directory and search upwards
  let current_dir = env::current_dir().map_err(|e| FnoxError::Config(format!("Failed to get current directory: {e}")))?;

  let requested_profiles = Config::get_profiles(&[]);
  let mut profiles = requested_profiles.clone();
  let (mut config, mut found) = load_recursive(&current_dir, false, &profiles, include_local_sync)?;

  // Profile inheritance can select additional profile-specific files. Keep
  // loading until discovering those files no longer expands the stack.
  loop {
    let expanded = resolve_profiles_for_discovery(&config, &profiles)?;
    if expanded == profiles {
      break;
    }
    profiles = expanded;
    (config, found) = load_recursive(&current_dir, false, &profiles, include_local_sync)?;
  }

  if !found {
    return Err(FnoxError::ConfigNotFound {
      message: format!("No configuration file found in {} or any parent directory", current_dir.display()),
      help: "Run 'fnox init' to create a configuration file".to_string(),
    });
  }

  // Discovery must be permissive long enough to look for an inherited
  // profile file. Once the fixed point is reached, reject inherited
  // profiles that were neither declared nor discovered.
  config.resolve_profiles(&requested_profiles)?;

  // Find the nearest directory to cwd that contains a config file.
  // This is the project root used for scoping the lease ledger.
  config.project_dir = find_project_dir(&current_dir, &profiles);
  Ok(config)
}

fn load_recursive(dir: &Path, found_any: bool, profiles: &[String], include_local_sync: bool) -> Result<(Config, bool)> {
  let filenames = all_config_filenames(profiles);

  // Load all existing config files in order (later files override earlier ones)
  let mut config = Config::new();
  let mut found = found_any;

  for filename in &filenames {
    let path = dir.join(filename);
    if path.exists() {
      let mut file_config = Config::load(&path)?;
      let is_local = matches!(filename.as_str(), "fnox.local.toml" | ".fnox.local.toml");
      if is_local && !include_local_sync {
        file_config.secrets.retain(|_, secret| secret.sync.is_none());
        file_config.secret_sources.retain(|key, _| file_config.secrets.contains_key(key));
        for profile in file_config.profiles.values_mut() {
          profile.secrets.retain(|_, secret| secret.sync.is_none());
          profile.secret_sources.retain(|key, _| profile.secrets.contains_key(key));
        }
      }
      if is_local {
        let write_profile = Config::write_profile(profiles);
        if write_profile != "default" {
          scope_root_entries_to_profile_as_base(&mut file_config, write_profile, !Settings::get().no_defaults);
          set_source_paths(&mut file_config, &path);
        }
      }
      config = merge_configs(config, file_config);
      found = true;
    }
  }

  // If this config marks root, stop recursion but still load global config
  if config.root {
    // Load imports if any
    for import_path in &config.import.clone() {
      let import_config = Config::load_import(import_path, dir)?;
      config = merge_configs(import_config, config);
    }
    // Load global config as the base even for root configs
    let (global_config, global_found) = load_global()?;
    // arkham level, read after fnox's global config so it stacks above it.
    let (arkham_config, arkham_found) = load_arkham_level(profiles)?;
    if global_found || arkham_found {
      let base = merge_configs(global_config, arkham_config);
      config = merge_configs(base, config);
      found = true;
    }
    return Ok((config, found));
  }

  // Load imports first (they get overridden by local config)
  for import_path in &config.import.clone() {
    let import_config = Config::load_import(import_path, dir)?;
    config = merge_configs(import_config, config);
  }

  // If we have a parent directory, recurse up and merge
  if let Some(parent_dir) = dir.parent() {
    let (parent_config, parent_found) = load_recursive(parent_dir, found, profiles, include_local_sync)?;
    config = merge_configs(parent_config, config);
    found = found || parent_found;
  } else {
    // At the filesystem root, try to load global config as base
    let (global_config, global_found) = load_global()?;
    // arkham level, read after fnox's global config so it stacks above it.
    let (arkham_config, arkham_found) = load_arkham_level(profiles)?;
    if global_found || arkham_found {
      let base = merge_configs(global_config, arkham_config);
      config = merge_configs(base, config);
      found = true;
    }
  }

  Ok((config, found))
}

/// Copy of fnox's private `resolve_profiles_for_discovery`. Discovery runs it
/// while it is still looking for inherited profile files, so an inherited
/// profile that neither a table nor a loaded file backs yet is expanded in
/// rather than rejected. `Config::resolve_profiles` is the strict variant, and
/// using it here fails a chain fnox itself loads.
fn resolve_profiles_for_discovery(config: &Config, profiles: &[String]) -> Result<Vec<String>> {
  fn visit(
    config: &Config,
    profile: &str,
    resolved: &mut Vec<String>,
    visiting: &mut Vec<String>,
    visited: &mut HashSet<String>,
    force: bool,
  ) -> Result<()> {
    if !env::is_valid_profile_name(profile) {
      return Err(FnoxError::Config(format!("Invalid inherited profile name: '{profile}'")));
    }
    if visited.contains(profile) && !force {
      return Ok(());
    }
    // `default` is the top-level config; a [profiles.default] table is not an
    // alternate inheritance entry point.
    if profile == "default" {
      visited.insert(profile.to_string());
      resolved.push(profile.to_string());
      return Ok(());
    }
    if let Some(start) = visiting.iter().position(|name| name == profile) {
      let mut cycle = visiting[start..].to_vec();
      cycle.push(profile.to_string());
      return Err(FnoxError::ProfileInheritanceCycle { cycle: cycle.join(" -> ") });
    }
    visiting.push(profile.to_string());
    if let Some(profile_config) = config.profiles.get(profile) {
      for inherited in profile_config.inherits() {
        visit(config, inherited, resolved, visiting, visited, false)?;
      }
    }
    visiting.pop();
    visited.insert(profile.to_string());
    resolved.push(profile.to_string());
    Ok(())
  }

  let mut resolved = Vec::new();
  let mut visiting = Vec::new();
  let mut visited = HashSet::new();
  for profile in profiles {
    visit(config, profile, &mut resolved, &mut visiting, &mut visited, true)?;
  }
  Ok(resolved)
}
fn find_project_dir(start: &Path, profiles: &[String]) -> Option<PathBuf> {
  let filenames = all_config_filenames(profiles);
  let mut dir = Some(start);
  while let Some(d) = dir {
    for filename in &filenames {
      if d.join(filename).exists() {
        return Some(d.to_path_buf());
      }
    }
    dir = d.parent();
  }
  None
}

fn load_global() -> Result<(Config, bool)> {
  let global_config_path = Config::global_config_path();

  if global_config_path.exists() {
    tracing::debug!("Loading global config from {}", global_config_path.display());
    let mut config = Config::load(&global_config_path)?;

    let dir = global_config_path.parent().unwrap_or_else(|| Path::new(""));
    for import_path in &config.import.clone() {
      let import_config = Config::load_import(import_path, dir)?;
      config = merge_configs(import_config, config);
    }

    Ok((config, true))
  } else {
    Ok((Config::new(), false))
  }
}

/// Load the chain fnox discovers, plus arkham's own level.
pub(crate) fn discover() -> Result<Config> {
  load_with_recursion("fnox.toml", true)
}

/// Arkham's level filenames in read order. The plain file first, then the
/// profile stand-in: `fnox.local.toml` when the active stack is only the
/// default profile, otherwise one `fnox.<profile>.toml` per active profile,
/// mirroring `all_config_filenames`.
fn arkham_filenames(profiles: &[String]) -> Vec<String> {
  let named: Vec<&str> = profiles
    .iter()
    .map(String::as_str)
    .filter(|profile| *profile != "default")
    .collect();
  let mut files = vec!["fnox.toml".to_string()];
  if named.is_empty() {
    files.push("fnox.local.toml".to_string());
  } else {
    files.extend(named.into_iter().map(|profile| format!("fnox.{profile}.toml")));
  }
  files
}

/// Arkham's level: `<config-dir>/arkham/fnox.toml` and its profile stand-in,
/// read after fnox's global config so it stacks above it and below every
/// project level.
fn load_arkham_level(profiles: &[String]) -> Result<(Config, bool)> {
  let Some(dir) = arkham_config::config::config_dir() else {
    return Ok((Config::new(), false));
  };
  let mut config = Config::new();
  let mut found = false;
  for filename in arkham_filenames(profiles) {
    let path = dir.join(filename);
    if !path.exists() {
      continue;
    }
    let mut file_config = load(&path)?;
    // Imports resolve against the importing file's directory, as in load_global.
    let file_dir = path.parent().unwrap_or_else(|| Path::new(""));
    for import_path in &file_config.import.clone() {
      let import_config = Config::load_import(import_path, file_dir)?;
      file_config = merge_configs(import_config, file_config);
    }
    config = merge_configs(config, file_config);
    found = true;
  }
  Ok((config, found))
}

/// Merge `base` with `overlay`, overlay taking precedence field by field.
/// Copied from fnox-core as fallible; here it is infallible, because the
/// merge is pure field combination and every fallible step (imports,
/// loading) happens in the callers.
fn merge_configs(base: Config, overlay: Config) -> Config {
  let mut merged = base;

  // Merge imports (overlay takes precedence, but keep unique paths)
  for import_path in overlay.import {
    if !merged.import.contains(&import_path) {
      merged.import.push(import_path);
    }
  }

  // root flag: if either is true, result is true
  merged.root = merged.root || overlay.root;

  // Merge age_key_file (overlay takes precedence)
  if overlay.age_key_file.is_some() {
    merged.age_key_file = overlay.age_key_file;
  }

  // Merge if_missing (overlay takes precedence)
  if overlay.if_missing.is_some() {
    merged.if_missing = overlay.if_missing;
  }

  // Merge env default (overlay takes precedence)
  if overlay.env.is_some() {
    merged.env = overlay.env;
  }

  // Merge prompt_auth (overlay takes precedence)
  if overlay.prompt_auth.is_some() {
    merged.prompt_auth = overlay.prompt_auth;
  }

  // Merge mcp (overlay takes precedence, field-by-field to avoid
  // silently re-enabling tools when overlay only sets exec_timeout_secs)
  if let Some(overlay_mcp) = overlay.mcp {
    let base_mcp = merged.mcp.get_or_insert_with(McpConfig::default);
    if overlay_mcp.tools_explicitly_set() {
      base_mcp.set_tools(overlay_mcp.tools());
    }
    if overlay_mcp.exec_timeout_secs.is_some() {
      base_mcp.exec_timeout_secs = overlay_mcp.exec_timeout_secs;
    }
    if overlay_mcp.redact_output.is_some() {
      base_mcp.redact_output = overlay_mcp.redact_output;
    }
    // Replace entirely — a partial overlay should not silently
    // re-expose secrets that the base config restricted.
    if overlay_mcp.secrets.is_some() {
      base_mcp.secrets = overlay_mcp.secrets;
    }
  }

  // Merge daemon (overlay takes precedence, field-by-field)
  if let Some(overlay_daemon) = overlay.daemon {
    let base_daemon = merged.daemon.get_or_insert_with(DaemonConfig::default);
    if overlay_daemon.enabled.is_some() {
      base_daemon.enabled = overlay_daemon.enabled;
    }
    if overlay_daemon.idle_timeout.is_some() {
      base_daemon.idle_timeout = overlay_daemon.idle_timeout;
    }
  }

  // Replace proxy policy as a unit. Combining rules across config layers
  // can silently broaden an agent's authority.
  if overlay.proxy.is_some() {
    merged.proxy = overlay.proxy;
  }

  // Merge the default_provider source only (overlay takes precedence). The
  // provider name is a private fnox field, unreadable and unwritable from
  // outside the crate, so it cannot be carried across this merge.
  if overlay.default_provider_source.is_some() {
    merged.default_provider_source = overlay.default_provider_source;
  }

  // Merge lease backends (overlay takes precedence)
  for (name, lease) in overlay.leases {
    merged.leases.insert(name, lease);
  }

  // Merge providers (overlay takes precedence)
  for (name, provider) in overlay.providers {
    merged.providers.insert(name, provider);
  }

  // Merge provider sources (overlay takes precedence)
  for (name, source) in overlay.provider_sources {
    merged.provider_sources.insert(name, source);
  }

  // Merge secrets (overlay takes precedence)
  for (name, secret) in overlay.secrets {
    merged.secrets.insert(name, secret);
  }

  // Merge secret sources (overlay takes precedence)
  for (name, source) in overlay.secret_sources {
    merged.secret_sources.insert(name, source);
  }

  // arkham: loaded_file_profiles is a private fnox field with no getter, so
  // this bookkeeping cannot be merged. Profile inheritance expansion inside
  // fnox therefore sees none of the files loaded here.

  // Merge profiles (overlay takes precedence)
  for (name, profile) in overlay.profiles {
    if let Some(existing_profile) = merged.profiles.get_mut(&name) {
      // Merge existing profile
      if profile.inherits.is_some() {
        existing_profile.inherits = profile.inherits;
      }
      for (lease_name, lease) in profile.leases {
        existing_profile.leases.insert(lease_name, lease);
      }
      for (provider_name, provider) in profile.providers {
        existing_profile.providers.insert(provider_name, provider);
      }
      for (provider_name, source) in &profile.provider_sources {
        existing_profile.provider_sources.insert(provider_name.clone(), source.clone());
      }
      for (secret_name, secret) in profile.secrets {
        existing_profile.secrets.insert(secret_name, secret);
      }
      for (secret_name, source) in &profile.secret_sources {
        existing_profile.secret_sources.insert(secret_name.clone(), source.clone());
      }
      // Merge the profile default_provider source only, same private-field
      // limit as the top-level merge above.
      if profile.default_provider_source.is_some() {
        existing_profile.default_provider_source = profile.default_provider_source;
      }
    } else {
      merged.profiles.insert(name, profile);
    }
  }

  merged
}

// ---- copied private helpers, freed from the impl block ----

fn profile_name_from_file(path: &Path) -> Option<String> {
  let name = path.file_name()?.to_str()?;
  let name = name.strip_prefix('.').unwrap_or(name);
  let profile = name.strip_prefix("fnox.")?.strip_suffix(".toml")?;
  (profile != "default" && profile != "local" && env::is_valid_profile_name(profile)).then(|| profile.to_string())
}

/// Copy of fnox's private `scope_to_profile`. The `loaded_file_profiles`
/// insert is skipped because that field is private in fnox, so profile
/// inheritance expansion is left to fnox's own `resolve_profiles`.
fn scope_to_profile(config: &mut Config, profile_name: String) {
  scope_root_entries_to_profile(config, profile_name);
}

fn scope_root_entries_to_profile(config: &mut Config, profile_name: String) {
  let profile = config.profiles.entry(profile_name).or_default();
  profile.leases.extend(std::mem::take(&mut config.leases));
  profile.providers.extend(std::mem::take(&mut config.providers));
  profile.provider_sources.extend(std::mem::take(&mut config.provider_sources));
  profile.secrets.extend(std::mem::take(&mut config.secrets));
  profile.secret_sources.extend(std::mem::take(&mut config.secret_sources));
  // arkham: default_provider is a private fnox field, so moving it into the
  // profile cannot be reproduced here. Its source path still moves.
  if config.default_provider_source.is_some() {
    profile.default_provider_source = config.default_provider_source.take();
  }
}

fn scope_root_entries_to_profile_as_base(config: &mut Config, profile_name: &str, include_secrets: bool) {
  let overlay = config.profiles.shift_remove(profile_name);
  let root_secrets = (!include_secrets).then(|| std::mem::take(&mut config.secrets));
  let root_secret_sources = (!include_secrets).then(|| std::mem::take(&mut config.secret_sources));
  scope_root_entries_to_profile(config, profile_name.to_string());
  if let Some(root_secrets) = root_secrets {
    config.secrets = root_secrets;
  }
  if let Some(root_secret_sources) = root_secret_sources {
    config.secret_sources = root_secret_sources;
  }

  if let Some(mut overlay) = overlay {
    // arkham: ProfileConfig default_provider is a private fnox field, so its name
    // cannot be re-assigned from here. Only its source path is carried, read
    // before the fields below are moved out of `overlay`.
    let has_default_provider = overlay.default_provider().is_some();
    let default_provider_source = overlay.default_provider_source.take();
    let profile = config.profiles.get_mut(profile_name).unwrap();
    if overlay.inherits.is_some() {
      profile.inherits = overlay.inherits;
    }
    profile.leases.extend(overlay.leases);
    profile.providers.extend(overlay.providers);
    profile.provider_sources.extend(overlay.provider_sources);
    profile.secrets.extend(overlay.secrets);
    profile.secret_sources.extend(overlay.secret_sources);
    if has_default_provider {
      profile.default_provider_source = default_provider_source;
    }
  }
}

fn set_source_paths(config: &mut Config, path: &Path) {
  // Set source paths for default profile secrets
  for (key, secret) in &mut config.secrets {
    secret.source_path = Some(path.to_path_buf());
    secret.source_is_profile = false;
    secret.source_profile = None;
    config.secret_sources.insert(key.clone(), path.to_path_buf());
  }

  // Set source paths for default profile providers
  for (provider_name, _) in &config.providers {
    config.provider_sources.insert(provider_name.clone(), path.to_path_buf());
  }

  // Set source path for default_provider if set
  if config.default_provider().is_some() {
    config.default_provider_source = Some(path.to_path_buf());
  }

  // Set source paths for named profiles
  for (profile_name, profile) in &mut config.profiles {
    for (key, secret) in &mut profile.secrets {
      secret.source_path = Some(path.to_path_buf());
      secret.source_is_profile = true;
      secret.source_profile = Some(profile_name.clone());
      profile.secret_sources.insert(key.clone(), path.to_path_buf());
    }

    for (provider_name, _) in &profile.providers {
      profile.provider_sources.insert(provider_name.clone(), path.to_path_buf());
    }

    // Set source path for profile's default_provider if set
    if profile.default_provider().is_some() {
      profile.default_provider_source = Some(path.to_path_buf());
    }
  }
}

#[cfg(test)]
mod tests {
  // These tests need process-per-test isolation, which `mise run test` gives:
  // fnox caches FNOX_CONFIG_DIR, FNOX_PROFILE and HOME_DIR in process-wide
  // LazyLock statics, so they cannot share a process.
  use std::io::Write as _;

  use super::*;

  /// Enter `dir` as the process cwd, restoring the previous one on drop.
  struct CwdGuard(PathBuf);

  impl CwdGuard {
    fn enter(dir: &Path) -> Self {
      let previous = env::current_dir().unwrap();
      env::set_current_dir(dir).unwrap();
      Self(previous)
    }
  }

  impl Drop for CwdGuard {
    fn drop(&mut self) {
      env::set_current_dir(&self.0).unwrap();
    }
  }

  /// Scratch host: fnox's config directory, arkham's config directory, and the
  /// project tree the walk starts in.
  struct Host {
    dir: tempfile::TempDir,
  }

  impl Host {
    fn new() -> Self {
      let dir = tempfile::tempdir().unwrap();
      let root = dir.path();
      std::fs::create_dir_all(root.join("work")).unwrap();
      env::set_var("FNOX_CONFIG_DIR", root.join("fnox"));
      env::set_var("ARKHAM_CONFIG", root.join("arkham").join("config.toml"));
      env::remove_var("FNOX_PROFILE");
      Self { dir }
    }

    fn write(&self, rel: &str, body: &str) -> PathBuf {
      let path = self.dir.path().join(rel);
      std::fs::create_dir_all(path.parent().unwrap()).unwrap();
      std::fs::File::create(&path).unwrap().write_all(body.as_bytes()).unwrap();
      path
    }

    /// Start the walk inside the project tree; keep the guard alive.
    fn enter(&self, rel: &str) -> CwdGuard {
      CwdGuard::enter(&self.dir.path().join(rel))
    }
  }

  /// Set the active profile, before the first fnox call in this process.
  fn set_profile(name: &str) {
    env::set_var("FNOX_PROFILE", name);
  }

  /// One secret with a plain default, in fnox's file shape.
  fn secret(key: &str, value: &str) -> String {
    format!("[secrets.{key}]\ndefault = \"{value}\"\n")
  }

  /// Value of `key` under the active profile stack.
  fn value(config: &Config, key: &str) -> Option<String> {
    config
      .get_secret(&Config::get_profiles(&[]), key)
      .unwrap()
      .and_then(|secret| secret.default.clone())
  }

  #[test]
  fn arkham_layer_beats_fnox_global() {
    let host = Host::new();
    host.write("fnox/config.toml", &secret("GITHUB_TOKEN", "global"));
    let arkham = host.write("arkham/fnox.toml", &secret("GITHUB_TOKEN", "arkham"));
    let _cwd = host.enter("work");

    let config = discover().unwrap();
    let secret = config.get_secret(&Config::get_profiles(&[]), "GITHUB_TOKEN").unwrap().unwrap();
    assert_eq!(secret.default.as_deref(), Some("arkham"));
    assert_eq!(secret.source_path.as_deref(), Some(arkham.as_path()));
  }

  #[test]
  fn arkham_layer_alone_is_discovered() {
    let host = Host::new();
    host.write("arkham/fnox.toml", &secret("GITHUB_TOKEN", "arkham"));
    let _cwd = host.enter("work");

    let config = discover().unwrap();
    assert_eq!(value(&config, "GITHUB_TOKEN").as_deref(), Some("arkham"));
  }

  #[test]
  fn project_file_beats_arkham_layer() {
    let host = Host::new();
    host.write("fnox/config.toml", &secret("GITHUB_TOKEN", "global"));
    host.write("arkham/fnox.toml", &secret("GITHUB_TOKEN", "arkham"));
    host.write("work/fnox.toml", &secret("GITHUB_TOKEN", "project"));
    let _cwd = host.enter("work");

    let config = discover().unwrap();
    assert_eq!(value(&config, "GITHUB_TOKEN").as_deref(), Some("project"));
  }

  #[test]
  fn arkham_local_stands_in_for_the_local_slot() {
    let host = Host::new();
    host.write("arkham/fnox.toml", &secret("GITHUB_TOKEN", "plain"));
    host.write("arkham/fnox.local.toml", &secret("GITHUB_TOKEN", "local"));
    let _cwd = host.enter("work");

    let config = discover().unwrap();
    assert_eq!(value(&config, "GITHUB_TOKEN").as_deref(), Some("local"));
  }

  #[test]
  fn fnox_profile_replaces_the_local_slot() {
    let host = Host::new();
    host.write("arkham/fnox.toml", &secret("GITHUB_TOKEN", "plain"));
    host.write("arkham/fnox.local.toml", &secret("GITHUB_TOKEN", "local"));
    host.write("arkham/fnox.staging.toml", &secret("GITHUB_TOKEN", "staging"));
    set_profile("staging");
    let _cwd = host.enter("work");

    let config = discover().unwrap();
    assert_eq!(value(&config, "GITHUB_TOKEN").as_deref(), Some("staging"));
  }

  #[test]
  fn project_local_overrides_the_project_file() {
    let host = Host::new();
    host.write(
      "work/fnox.toml",
      &(secret("GITHUB_TOKEN", "plain") + &secret("ONLY_PLAIN", "plain")),
    );
    host.write("work/fnox.local.toml", &secret("GITHUB_TOKEN", "local"));
    let _cwd = host.enter("work");

    let config = discover().unwrap();
    assert_eq!(value(&config, "GITHUB_TOKEN").as_deref(), Some("local"));
    assert_eq!(value(&config, "ONLY_PLAIN").as_deref(), Some("plain"));
  }

  #[test]
  fn project_local_under_a_profile_keeps_root_keys_and_prefers_the_profile_table() {
    let host = Host::new();
    host.write(
      "work/fnox.local.toml",
      &(secret("TOKEN", "from-root") + &secret("ONLY_ROOT", "root") + "[profiles.staging.secrets.TOKEN]\ndefault = \"from-profile\"\n"),
    );
    set_profile("staging");
    let _cwd = host.enter("work");

    let config = discover().unwrap();
    assert_eq!(value(&config, "TOKEN").as_deref(), Some("from-profile"));
    assert_eq!(value(&config, "ONLY_ROOT").as_deref(), Some("root"));
  }

  #[test]
  fn root_true_stops_the_walk_above_it() {
    let host = Host::new();
    host.write("arkham/fnox.toml", &secret("GITHUB_TOKEN", "arkham"));
    host.write("work/fnox.toml", &secret("ONLY_OUTER", "outer"));
    host.write("work/inner/fnox.toml", &format!("root = true\n{}", secret("GITHUB_TOKEN", "inner")));
    let _cwd = host.enter("work/inner");

    let config = discover().unwrap();
    assert_eq!(value(&config, "GITHUB_TOKEN").as_deref(), Some("inner"));
    assert_eq!(value(&config, "ONLY_OUTER"), None);
  }

  #[test]
  fn imports_merge_under_the_file_that_imports_them() {
    let host = Host::new();
    host.write(
      "work/extra.toml",
      &(secret("GITHUB_TOKEN", "imported") + &secret("ONLY_IMPORTED", "yes")),
    );
    host.write(
      "work/fnox.toml",
      &(String::from("import = [\"extra.toml\"]\n") + &secret("GITHUB_TOKEN", "file")),
    );
    let _cwd = host.enter("work");

    let config = discover().unwrap();
    assert_eq!(value(&config, "GITHUB_TOKEN").as_deref(), Some("file"));
    assert_eq!(value(&config, "ONLY_IMPORTED").as_deref(), Some("yes"));
  }

  #[test]
  fn nothing_anywhere_is_still_config_not_found() {
    let host = Host::new();
    let _cwd = host.enter("work");

    let err = discover().unwrap_err();
    assert!(matches!(err, FnoxError::ConfigNotFound { .. }), "{err:?}");
  }

  #[test]
  fn an_inherited_profile_file_is_discovered() {
    let host = Host::new();
    host.write("work/fnox.staging.toml", "[profiles.staging]\ninherits = [\"prod\"]\n");
    host.write("work/fnox.prod.toml", &secret("GITHUB_TOKEN", "from-prod"));
    set_profile("staging");
    let _cwd = host.enter("work");

    let config = discover().unwrap();
    assert_eq!(value(&config, "GITHUB_TOKEN").as_deref(), Some("from-prod"));
  }

  #[test]
  fn an_inherited_profile_without_a_file_still_errors() {
    let host = Host::new();
    host.write("work/fnox.staging.toml", "[profiles.staging]\ninherits = [\"prod\"]\n");
    set_profile("staging");
    let _cwd = host.enter("work");

    let err = discover().unwrap_err();
    assert!(matches!(err, FnoxError::ProfileNotFound { .. }), "{err:?}");
  }

  #[test]
  fn the_arkham_level_resolves_its_imports() {
    let host = Host::new();
    host.write("arkham/extra.toml", &secret("GITHUB_TOKEN", "imported"));
    host.write("arkham/fnox.toml", "import = [\"extra.toml\"]\n");
    let _cwd = host.enter("work");

    let config = discover().unwrap();
    assert_eq!(value(&config, "GITHUB_TOKEN").as_deref(), Some("imported"));
  }

  /// Without the arkham level on disk, the copy must land on fnox's own loader's
  /// result, so the only behaviour that differs is the level that was added.
  #[test]
  fn the_copied_chain_matches_fnox_own_loader() {
    let host = Host::new();
    host.write("fnox/config.toml", &secret("GLOBAL_ONLY", "global"));
    host.write("work/fnox.toml", &(secret("PROJECT", "project") + &secret("SHARED", "project")));
    host.write("work/fnox.local.toml", &secret("SHARED", "local"));
    let _cwd = host.enter("work");

    let ours = discover().unwrap();
    let theirs = fnox_core::Fnox::discover().unwrap();
    let profiles = Config::get_profiles(&[]);
    for key in ["GLOBAL_ONLY", "PROJECT", "SHARED"] {
      let mine = ours.get_secret(&profiles, key).unwrap().and_then(|s| s.default.clone());
      let upstream = theirs.config().get_secret(&profiles, key).unwrap().and_then(|s| s.default.clone());
      assert_eq!(mine, upstream, "{key}");
    }
    assert_eq!(ours.import, theirs.config().import);
    assert_eq!(ours.project_dir, theirs.config().project_dir);
  }
}
