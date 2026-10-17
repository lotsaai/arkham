//! fnox integration: value lookup plus arkham's extra discovery level.
//!
//! Registry and host knowledge live in `arkham-config`; everything that talks
//! to fnox lives here.

mod error;
mod layers;

pub use error::Error;

#[cfg(test)]
use std::path::Path;

use std::collections::{BTreeMap, BTreeSet};
use std::env;

use arkham_config::config::{AppConfig, IfMissing, RuleCfg};
use arkham_config::registry::{Registry, authority_of};
use fnox_core::env as fnox_env;
use secrecy::SecretString;

/// Merged fnox config plus the profiles and names it declares.
#[derive(Clone, Debug)]
pub struct FnoxSource {
  config: fnox_core::config::Config,
  profiles: Vec<String>,
  declared: BTreeSet<String>,
}

/// Map a discovery failure with no config found to `None`; other errors stay.
fn discovered_or_none(found: fnox_core::Result<fnox_core::config::Config>) -> Result<Option<fnox_core::config::Config>, Error> {
  match found {
    Ok(config) => Ok(Some(config)),
    Err(fnox_core::FnoxError::ConfigNotFound { .. }) => Ok(None),
    Err(err) => Err(Error::Discovery { source: Box::new(err) }),
  }
}

/// The profile stack the chain loaded with, expanded through inheritance the
/// way `load_with_recursion` does, so lookup sees the same stack.
fn active_profiles(config: &fnox_core::config::Config) -> Result<Vec<String>, Error> {
  config
    .resolve_profiles(&fnox_core::config::Config::get_profiles(&[]))
    .map_err(|source| Error::Profiles { source: Box::new(source) })
}

/// Names a config declares under the active profiles.
fn declared_names(config: &fnox_core::config::Config, profiles: &[String]) -> Result<BTreeSet<String>, Error> {
  // Same setting value() reads through get_secret, so the declared set and the
  // resolved value cannot disagree about whether top-level secrets count.
  let no_defaults = fnox_core::settings::Settings::get().no_defaults;
  Ok(
    config
      .get_secrets_with_no_defaults(profiles, no_defaults)
      .map_err(|source| Error::ListSecrets { source: Box::new(source) })?
      .into_keys()
      .collect(),
  )
}

impl FnoxSource {
  /// Open the discovered chain, or `None` when no config exists.
  ///
  /// # Errors
  ///
  /// Returns an error when a discovered config file is malformed, when its
  /// profiles are unresolvable, or when fnox cannot list its declared secrets.
  pub fn open() -> Result<Option<Self>, Error> {
    let Some(config) = discovered_or_none(crate::layers::discover())? else {
      return Ok(None);
    };
    let profiles = active_profiles(&config)?;
    let declared = declared_names(&config, &profiles)?;
    Ok(Some(Self {
      config,
      profiles,
      declared,
    }))
  }

  /// Open one explicit config file; test injection point.
  #[cfg(test)]
  fn open_at(path: &Path) -> Result<Self, Error> {
    let config = crate::layers::load(path).map_err(|source| Error::ConfigFile {
      path: path.to_path_buf(),
      source: Box::new(source),
    })?;
    let profiles = active_profiles(&config)?;
    let declared = declared_names(&config, &profiles)?;
    Ok(Self {
      config,
      profiles,
      declared,
    })
  }

  /// Names fnox declares, sorted.
  #[must_use]
  pub fn declared(&self) -> &BTreeSet<String> {
    &self.declared
  }

  /// Value for one key: `None` when fnox does not declare it, error when a
  /// declared key resolves to nothing usable (no value or an empty one).
  async fn value(&self, key: &str) -> Result<Option<String>, Error> {
    if !self.declared.contains(key) {
      return Ok(None);
    }
    let Some(secret) = self.config.get_secret(&self.profiles, key).map_err(|source| Error::Secret {
      key: key.to_string(),
      source: Box::new(source),
    })?
    else {
      return Err(Error::DeclaredNoValue { key: key.to_string() });
    };
    let resolved = fnox_core::secret_resolver::resolve_secret(&self.config, &self.profiles, key, secret)
      .await
      .map_err(|source| Error::Secret {
        key: key.to_string(),
        source: Box::new(source),
      })?;
    let Some(value) = resolved else {
      return Err(Error::DeclaredNoValue { key: key.to_string() });
    };
    if value.is_empty() {
      return Err(Error::DeclaredEmpty { key: key.to_string() });
    }
    Ok(Some(value))
  }
}

/// Environment variables fnox itself reads: its own configuration, and the
/// credentials every provider it can talk to looks for. Arkham forwards the ones
/// the shell already has into the proxy container, and resolves the ones fnox
/// declares but the environment lacks, which is what makes a provider token
/// stored in fnox usable — the same job `fnox exec` does.
///
/// source: fnox-core 1.35 `src/env.rs`, `src/providers/*`, `src/lease_backends/*`
pub const FNOX_ENV: &[&str] = &[
  // fnox itself
  "FNOX_CONFIG_DIR",
  "FNOX_STATE_DIR",
  "FNOX_PROFILE",
  "FNOX_AGE_KEY",
  // Bitwarden Secrets Manager, Bitwarden CLI
  "BWS_ACCESS_TOKEN",
  "FNOX_BWS_ACCESS_TOKEN",
  "BWS_PROJECT_ID",
  "BW_SESSION",
  "FNOX_BW_SESSION",
  // 1Password
  "OP_SERVICE_ACCOUNT_TOKEN",
  "FNOX_OP_SERVICE_ACCOUNT_TOKEN",
  // HashiCorp Vault
  "VAULT_TOKEN",
  "VAULT_ADDR",
  "VAULT_NAMESPACE",
  "FNOX_VAULT_TOKEN",
  "FNOX_VAULT_ADDR",
  "FNOX_VAULT_NAMESPACE",
  // AWS Secrets Manager and SSO leases
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_PROFILE",
  "AWS_SSO_SESSION",
  // Azure Key Vault
  "AZURE_TENANT_ID",
  "AZURE_CLIENT_ID",
  "AZURE_CLIENT_SECRET",
  // Google Cloud
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GCP_SERVICE_ACCOUNT_KEY",
  // Infisical, Doppler, Cloudflare, GitHub App leases
  "INFISICAL_TOKEN",
  "INFISICAL_CLIENT_ID",
  "INFISICAL_CLIENT_SECRET",
  "INFISICAL_API_URL",
  "FNOX_INFISICAL_TOKEN",
  "FNOX_INFISICAL_CLIENT_ID",
  "FNOX_INFISICAL_CLIENT_SECRET",
  "FNOX_INFISICAL_API_URL",
  "DOPPLER_TOKEN",
  "FNOX_DOPPLER_TOKEN",
  "CLOUDFLARE_API_TOKEN",
  "CF_API_TOKEN",
  "FNOX_GITHUB_APP_PRIVATE_KEY",
  // Keeper, KeePass, Passwordstate, Proton Pass, pass, KMS
  "KSM_TOKEN",
  "KSM_CONFIG",
  "KEEPASS_PASSWORD",
  "FNOX_KEEPASS_PASSWORD",
  "FNOX_KEEPER_TOKEN",
  "FNOX_KEEPER_CONFIG",
  "PASSWORDSTATE_API_KEY",
  "FNOX_PASSWORDSTATE_API_KEY",
  "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
  "FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN",
  "PASSWORD_STORE_DIR",
  "FNOX_PASSWORD_STORE_DIR",
  "PASSWORD_STORE_GPG_OPTS",
  "FNOX_PASSWORD_STORE_GPG_OPTS",
];

/// Export provider credentials fnox declares but the environment lacks, so a
/// provider whose own token lives in fnox can still resolve the secrets that
/// need it. Only missing names are touched, so the shell always wins; a name
/// that resolves to nothing warns instead of failing startup, because the rule
/// needing that provider reports the real error a moment later.
///
/// A declared name that does not resolve is warned about and skipped, so this
/// never fails.
pub async fn export_provider_env(fnox: &FnoxSource) -> Vec<String> {
  let mut exported = Vec::new();
  for name in FNOX_ENV {
    if env::var_os(name).is_some() || !fnox.declared().contains(*name) {
      continue;
    }
    match fnox.value(name).await {
      Ok(Some(value)) => {
        // fnox-core's own write path, which serializes with the rest of fnox's
        // environment access; this runs once at startup, before any task reads
        // the environment.
        fnox_env::set_var(name, value);
        exported.push((*name).to_string());
      }
      Ok(None) => {}
      Err(err) => tracing::warn!(name, "provider credential declared in fnox did not resolve: {err}"),
    }
  }
  exported
}

/// Env names fnox declares that the registry knows, sorted; `None` yields none.
#[must_use]
pub fn selected_envs(fnox: Option<&FnoxSource>, registry: &Registry) -> Vec<String> {
  let Some(fnox) = fnox else { return Vec::new() };
  fnox
    .declared()
    .iter()
    .filter(|name| registry.lookup(name).is_some())
    .cloned()
    .collect()
}

/// One resolution pass over the rule table. It derives the catalog the
/// secret source and the registry agree on, fetches every rule's value,
/// then rewrites each rule in place — its kind's host union, decoy
/// pattern, and skip policy — reporting which rules to drop.
struct RulePass<'a> {
  /// Host registry for host unions, oauth flows, and decoy templates.
  registry: &'a Registry,
  /// The secret source, when one is configured.
  fnox: Option<&'a FnoxSource>,
  /// Fetched values by rule label, consumed as rules claim them.
  values: BTreeMap<String, Option<String>>,
}

impl RulePass<'_> {
  /// fnox secret name for one rule: `fnox_key`, else `env`.
  fn fnox_key(rule: &RuleCfg) -> String {
    rule.fnox_key.clone().unwrap_or_else(|| rule.env.clone())
  }

  /// Derive catalog rules: the catalog comes from what fnox declares and
  /// the registry hosts; config states overrides, not every name. An
  /// explicit rule wins per env, and a name the registry gives no hosts
  /// derives nothing.
  fn derive_catalog(&self, config: &mut AppConfig) {
    let Some(source) = self.fnox else {
      return;
    };
    let covered = config.rules.values().map(|rule| rule.env.clone()).collect::<BTreeSet<_>>();
    for name in source.declared() {
      if covered.contains(name) || self.registry.lookup(name).is_none_or(|known| known.hosts.is_empty()) {
        continue;
      }
      config.rules.entry(name.to_lowercase()).or_insert_with(|| RuleCfg {
        env: name.clone(),
        value: None,
        real: None,
        fnox_key: None,
        allow: Vec::new(),
        pattern: None,
        oauth2: None,
        registry: None,
        if_missing: IfMissing::Warn,
        tls: BTreeMap::new(),
        ssh: BTreeMap::new(),
      });
    }
  }

  /// Fetch every rule's value before the map is mutated, so rules stay
  /// borrowed immutably while fnox is awaited.
  ///
  /// # Errors
  ///
  /// Returns an error when the secret source fails to answer.
  async fn fetch_values(&mut self, config: &AppConfig) -> Result<(), Error> {
    let keys = config
      .rules
      .iter()
      .filter(|(_, rule)| rule.value.is_none() || rule.value_scheme().is_some())
      .map(|(label, rule)| (label.clone(), Self::fnox_key(rule)))
      .collect::<Vec<_>>();
    for (label, key) in keys {
      let value = match self.fnox {
        Some(source) => source.value(&key).await?,
        None => None,
      };
      self.values.insert(label, value);
    }
    Ok(())
  }

  /// Rewrite one rule per its kind. Returns `true` when the rule must be
  /// dropped from the table.
  fn apply(&mut self, label: &str, rule: &mut RuleCfg) -> Result<bool, Error> {
    if rule.is_ssh() {
      // SSH rule: the secret is key material in the `ssh` table, stated in
      // the config. Nothing resolves from fnox and no registry union may
      // widen the entries — an ssh rule's allow list is all ssh.
      tracing::info!(label, env = %rule.env, "ssh rule resolved: key material from the config");
      return Ok(false);
    }
    if rule.value_scheme().is_some() {
      return self.connection_string(label, rule);
    }
    self.token(label, rule)
  }

  /// Connection-string rule: `value` holds the stated fake string; the real
  /// connection string comes from fnox and never overwrites it. No
  /// registry hosts, no pattern — the connection string is the grant.
  fn connection_string(&mut self, label: &str, rule: &mut RuleCfg) -> Result<bool, Error> {
    if let Some(value) = self.values.remove(label).flatten() {
      rule.real = Some(SecretString::from(value));
      tracing::info!(label, env = %rule.env, "connection-string rule resolved: stated fake string, real connection string from fnox");
      return Ok(false);
    }
    // A generated grant states the real string beside the fake one. Fnox
    // wins when it has the key. When it does not, the stated real stays.
    if rule.real.is_some() {
      tracing::info!(label, env = %rule.env, "connection-string rule resolved: stated fake string, stated real connection string");
      return Ok(false);
    }
    let what = if self.fnox.is_some() {
      "no resolved real connection string and fnox does not declare its key"
    } else {
      "no resolved real connection string and fnox has no configuration"
    };
    Self::skip(label, rule, what)?;
    Ok(true)
  }

  /// Token rule: resolve the value when none is inline, union the registry
  /// hosts and flow authorities into `allow`, and fill the decoy pattern.
  fn token(&mut self, label: &str, rule: &mut RuleCfg) -> Result<bool, Error> {
    let inline = rule.value.is_some();
    if !inline {
      if let Some(value) = self.values.remove(label).flatten() {
        rule.value = Some(SecretString::from(value));
      } else {
        let what = if self.fnox.is_some() {
          "no inline value and fnox does not declare its key"
        } else {
          "no inline value and fnox has no configuration"
        };
        Self::skip(label, rule, what)?;
        return Ok(true);
      }
    }
    let mut hosts = self.registry.hosts_for(rule).to_vec();
    for entry in &rule.allow {
      if !hosts.contains(entry) {
        hosts.push(entry.clone());
      }
    }
    if hosts.is_empty() {
      Self::skip(label, rule, "no hosts: registry has no entry and `allow` is empty")?;
      return Ok(true);
    }
    // Unioned once here so `grants::resolve` sees the final list.
    rule.allow = hosts;
    if rule.oauth2.is_none() {
      rule.oauth2 = self.registry.flow_for(rule);
    }
    if let Some(flow) = &rule.oauth2 {
      for url in [&Some(flow.token_url.clone()), &flow.authorize_url, &flow.refresh_url]
        .into_iter()
        .flatten()
      {
        let authority = authority_of(url)?;
        if !rule.allow.contains(&authority) {
          rule.allow.push(authority);
        }
      }
    }
    rule.pattern = rule.pattern.take().filter(|pattern| !pattern.is_empty());
    if rule.pattern.is_none() {
      rule.pattern = Some(self.registry.template(&rule.env, None).into_owned());
    }
    let source = if inline { "inline" } else { "fnox" };
    let key = Self::fnox_key(rule);
    let key = (key != rule.env).then_some(key);
    tracing::info!(label, env = %rule.env, fnox_key = key.as_deref(), hosts = rule.allow.len(), value = source, "rule resolved");
    Ok(false)
  }

  /// Apply one rule's `if_missing` policy. `Ok(())` means drop the rule;
  /// `Error` bails instead.
  fn skip(label: &str, rule: &RuleCfg, detail: &str) -> Result<(), Error> {
    match rule.if_missing {
      IfMissing::Error => Err(Error::UnresolvedRule {
        label: label.to_string(),
        env: rule.env.clone(),
        detail: detail.to_string(),
      }),
      IfMissing::Warn => {
        tracing::warn!(label, env = %rule.env, reason = detail, "dropping rule");
        Ok(())
      }
      IfMissing::Ignore => Ok(()),
    }
  }
}

/// Resolve every rule in place: fetch values from fnox when no inline value
/// is present, union registry hosts into `allow`, fill the decoy pattern, and
/// drop rules that `if_missing` lets go.
///
/// # Errors
///
/// Returns an error when a rule's `fnox_key` is declared yet resolves to no
/// usable value, or when a rule's `allow` entry fails to parse.
pub async fn resolve(config: &mut AppConfig, registry: &Registry, fnox: Option<FnoxSource>) -> Result<(), Error> {
  let mut pass = RulePass {
    registry,
    fnox: fnox.as_ref(),
    values: BTreeMap::new(),
  };
  pass.derive_catalog(config);
  pass.fetch_values(config).await?;
  let mut dropped = Vec::new();
  for (label, rule) in &mut config.rules {
    if pass.apply(label, rule)? {
      dropped.push(label.clone());
    }
  }
  for label in dropped {
    config.rules.remove(&label);
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::config::{ProxyCfg, WorkspaceCfg};
  use arkham_config::registry::{FlowKind, OAuthFlow};
  use pretty_assertions::assert_eq;
  use secrecy::ExposeSecret as _;
  use std::error::Error as _;
  use std::fs;
  use std::path::PathBuf;
  use tempfile::tempdir;

  #[tokio::test]
  async fn resolve_unions_registry_hosts_with_explicit_allow() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("GITHUB_TOKEN");
    rule.allow = vec!["https://ghe.corp.example".to_string()];
    let mut config = config_with("gh", rule);
    resolve(&mut config, &registry, None).await.unwrap();
    let allow = &config.rules["gh"].allow;
    assert!(allow.contains(&"https://api.github.com".to_string()));
    assert!(allow.contains(&"https://ghe.corp.example".to_string()));
    assert_eq!(allow.len(), 4);
  }

  #[tokio::test]
  async fn resolve_unions_flow_authorities_into_allow() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("GITHUB_TOKEN");
    rule.oauth2 = Some(OAuthFlow {
      flow: FlowKind::ClientCredentials,
      token_url: "https://auth.example.com/oauth/token".into(),
      authorize_url: None,
      refresh_url: None,
      rotates_refresh: false,
      token_fields: Vec::new(),
    });
    let mut config = config_with("gh", rule);
    resolve(&mut config, &registry, None).await.unwrap();
    let allow = &config.rules["gh"].allow;
    assert!(
      allow.contains(&"https://auth.example.com".to_string()),
      "token_url authority must be unioned, got {allow:?}"
    );
    assert!(
      !allow.iter().any(|entry| entry.contains("/oauth/token")),
      "full URLs must be reduced to authority-only, got {allow:?}"
    );
  }
  #[tokio::test]
  async fn resolve_registry_false_keeps_only_explicit_hosts() {
    let registry = arkham_config::registry::Registry::load(None).unwrap();
    let mut rule = rule("GITHUB_TOKEN");
    rule.registry = Some(false);
    rule.allow = vec!["https://ghe.corp.example".to_string()];
    let mut config = config_with("gh", rule);
    resolve(&mut config, &registry, None).await.unwrap();
    assert_eq!(config.rules["gh"].allow, vec!["https://ghe.corp.example".to_string()]);
  }
  #[tokio::test]
  async fn resolve_fills_the_pattern_from_the_registry() {
    let registry = Registry::load(None).unwrap();
    let mut config = config_with("gh", rule("GITHUB_TOKEN"));
    resolve(&mut config, &registry, None).await.unwrap();
    assert_eq!(config.rules["gh"].pattern.as_deref(), Some("ghp_{hex:40}"));
  }
  #[tokio::test]
  async fn resolve_keeps_an_explicit_pattern() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("GITHUB_TOKEN");
    rule.pattern = Some("ghp_custom_{hex:8}".to_string());
    let mut config = config_with("gh", rule);
    resolve(&mut config, &registry, None).await.unwrap();
    assert_eq!(config.rules["gh"].pattern.as_deref(), Some("ghp_custom_{hex:8}"));
  }
  #[tokio::test]
  async fn empty_explicit_pattern_falls_back_to_the_registry() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("GITHUB_TOKEN");
    rule.pattern = Some(String::new());
    let mut config = config_with("gh", rule);
    resolve(&mut config, &registry, None).await.unwrap();
    assert_eq!(config.rules["gh"].pattern.as_deref(), Some("ghp_{hex:40}"));
  }
  #[tokio::test]
  async fn missing_hosts_error_by_default() {
    let registry = Registry::load(None).unwrap();
    let mut config = config_with("unknown", rule("NO_SUCH_SERVICE_TOKEN"));
    let err = resolve(&mut config, &registry, None).await.unwrap_err();
    assert!(err.to_string().contains("no hosts"), "{err:?}");
  }
  #[tokio::test]
  async fn missing_hosts_warn_drops_the_rule() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("NO_SUCH_SERVICE_TOKEN");
    rule.if_missing = IfMissing::Warn;
    let mut config = config_with("unknown", rule);
    resolve(&mut config, &registry, None).await.unwrap();
    assert!(config.rules.is_empty());
  }
  #[tokio::test]
  async fn missing_hosts_ignore_drops_the_rule_silently() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("NO_SUCH_SERVICE_TOKEN");
    rule.if_missing = IfMissing::Ignore;
    let mut config = config_with("unknown", rule);
    resolve(&mut config, &registry, None).await.unwrap();
    assert!(config.rules.is_empty());
  }

  fn rule(env: &str) -> RuleCfg {
    RuleCfg {
      env: env.to_string(),
      value: Some(SecretString::from("inline")),
      real: None,
      fnox_key: None,
      allow: Vec::new(),
      pattern: None,
      oauth2: None,
      registry: None,
      if_missing: IfMissing::Error,
      tls: BTreeMap::new(),
      ssh: BTreeMap::new(),
    }
  }

  fn empty_config() -> AppConfig {
    AppConfig {
      proxy: ProxyCfg {
        listen: "127.0.0.1:8080".parse().unwrap(),
        ca_file: None,
        root_certs: Vec::new(),
        ssh_host_key: None,
        ssh_known_hosts: None,
        handshake_timeout_secs: 10,
      },
      workspace: WorkspaceCfg::default(),
      rules: BTreeMap::new(),
      plugins: BTreeMap::new(),
      tools: BTreeMap::new(),
    }
  }

  fn config_with(label: &str, rule: RuleCfg) -> AppConfig {
    let mut config = empty_config();
    config.rules.insert(label.to_string(), rule);
    config
  }

  const FNOX_PLAIN: &str = r#"
[providers.plain]
type = "plain"

[secrets.GITHUB_TOKEN]
provider = "plain"
value = "real-github-token"

[secrets.OTHER_TOKEN]
provider = "plain"
value = "other-real-token"
"#;

  #[tokio::test]
  async fn selected_envs_intersects_fnox_with_the_registry() {
    let registry = Registry::load(None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = write_fnox(dir.path(), FNOX_PLAIN);
    let fnox = FnoxSource::open_at(&path).unwrap();
    assert_eq!(selected_envs(Some(&fnox), &registry), vec!["GITHUB_TOKEN".to_string()]);
    assert_eq!(selected_envs(None, &registry), [] as [std::string::String; 0]);
  }

  #[tokio::test]
  async fn resolve_derives_a_rule_for_every_fnox_secret_the_registry_hosts() {
    let registry = Registry::load(None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = write_fnox(dir.path(), FNOX_PLAIN);
    let fnox = FnoxSource::open_at(&path).unwrap();
    let mut config = empty_config();
    resolve(&mut config, &registry, Some(fnox)).await.unwrap();
    let rule = &config.rules["github_token"];
    assert_eq!(rule.env, "GITHUB_TOKEN");
    assert_eq!(rule.value.as_ref().unwrap().expose_secret(), "real-github-token");
    assert!(rule.allow.contains(&"https://api.github.com".to_string()));
    assert_eq!(rule.pattern.as_deref(), Some("ghp_{hex:40}"));
    assert_eq!(config.rules.len(), 1, "OTHER_TOKEN has no registry entry and must not derive");
  }

  #[tokio::test]
  async fn an_explicit_rule_for_the_env_beats_derivation() {
    let registry = Registry::load(None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = write_fnox(dir.path(), FNOX_PLAIN);
    let fnox = FnoxSource::open_at(&path).unwrap();
    let mut rule = rule("GITHUB_TOKEN");
    rule.allow = vec!["https://ghe.corp.example".to_string()];
    let mut config = config_with("mine", rule);
    resolve(&mut config, &registry, Some(fnox)).await.unwrap();
    assert_eq!(config.rules.len(), 1, "the explicit rule must win, no derived twin");
    assert!(config.rules.contains_key("mine"));
  }

  /// Config whose only rule pulls its value from the temp fnox file.
  fn config_with_fnox(label: &str, env: &str) -> AppConfig {
    let mut rule = rule(env);
    rule.value = None;
    config_with(label, rule)
  }

  /// Test-only env removal, so the unsafe call lives in one place.
  fn unset_env(key: &str) {
    // SAFETY: test-only mutation, and nextest runs one test per process.
    unsafe { env::remove_var(key) };
  }

  fn write_fnox(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("fnox.toml");
    fs::write(&path, body).unwrap();
    path
  }

  #[tokio::test]
  async fn provider_credentials_declared_in_fnox_reach_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_fnox(
      dir.path(),
      r#"
[providers.plain]
type = "plain"

[secrets.BWS_ACCESS_TOKEN]
provider = "plain"
value = "bws-from-fnox"
"#,
    );
    let key = "BWS_ACCESS_TOKEN";
    unset_env(key);

    let fnox = FnoxSource::open_at(&path).unwrap();
    assert_eq!(export_provider_env(&fnox).await, vec![key.to_string()]);
    assert_eq!(env::var(key).unwrap(), "bws-from-fnox");

    // The shell wins, and nothing is exported twice.
    assert_eq!(export_provider_env(&fnox).await, [] as [std::string::String; 0]);
    // A name fnox does not declare is never touched.
    assert!(env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_none());

    unset_env(key);
  }

  #[tokio::test]
  async fn fnox_supplies_the_value() {
    let registry = Registry::load(None).unwrap();
    let dir = tempdir().unwrap();
    let fnox_path = write_fnox(dir.path(), FNOX_PLAIN);
    let mut config = config_with_fnox("gh", "GITHUB_TOKEN");
    let fnox = FnoxSource::open_at(&fnox_path).unwrap();
    resolve(&mut config, &registry, Some(fnox)).await.unwrap();
    let value = config.rules["gh"].value.as_ref().unwrap();
    assert_eq!(value.expose_secret(), "real-github-token");
  }

  #[tokio::test]
  async fn inline_value_wins_over_fnox() {
    let registry = Registry::load(None).unwrap();
    let dir = tempdir().unwrap();
    let fnox_path = write_fnox(dir.path(), FNOX_PLAIN);
    let mut config = config_with_fnox("gh", "GITHUB_TOKEN");
    config.rules.get_mut("gh").unwrap().value = Some(SecretString::from("inline-wins"));
    let fnox = FnoxSource::open_at(&fnox_path).unwrap();
    resolve(&mut config, &registry, Some(fnox)).await.unwrap();
    let value = config.rules["gh"].value.as_ref().unwrap();
    assert_eq!(value.expose_secret(), "inline-wins");
  }

  #[tokio::test]
  async fn fnox_key_overrides_the_env_name() {
    let registry = Registry::load(None).unwrap();
    let dir = tempdir().unwrap();
    let fnox_path = write_fnox(dir.path(), FNOX_PLAIN);
    let mut config = config_with_fnox("gh", "GITHUB_TOKEN");
    config.rules.get_mut("gh").unwrap().fnox_key = Some("OTHER_TOKEN".to_string());
    let fnox = FnoxSource::open_at(&fnox_path).unwrap();
    resolve(&mut config, &registry, Some(fnox)).await.unwrap();
    let value = config.rules["gh"].value.as_ref().unwrap();
    assert_eq!(value.expose_secret(), "other-real-token");
  }

  #[tokio::test]
  async fn undeclared_fnox_key_follows_if_missing() {
    let registry = Registry::load(None).unwrap();
    let dir = tempdir().unwrap();
    let fnox_path = write_fnox(dir.path(), FNOX_PLAIN);
    let mut config = config_with_fnox("gh", "GITHUB_TOKEN");
    config.rules.get_mut("gh").unwrap().fnox_key = Some("NOT_DECLARED".to_string());
    let fnox = FnoxSource::open_at(&fnox_path).unwrap();

    let mut strict = config.clone();
    let err = resolve(&mut strict, &registry, Some(fnox.clone())).await.unwrap_err();
    assert!(err.to_string().contains("fnox does not declare"), "{err:?}");

    let mut lenient = config;
    lenient.rules.get_mut("gh").unwrap().if_missing = IfMissing::Warn;
    resolve(&mut lenient, &registry, Some(fnox)).await.unwrap();
    assert!(lenient.rules.is_empty());
  }

  #[tokio::test]
  async fn missing_fnox_config_file_is_an_error() {
    let err = match FnoxSource::open_at(Path::new("/nonexistent/arkham-absent-fnox.toml")) {
      Err(err) => err,
      Ok(source) => panic!("expected an error, got {source:?}"),
    };
    assert!(err.to_string().contains("fnox config"), "{err:?}");
    // The io error stays attached as the error source.
    assert!(err.source().is_some(), "{err:?}");
  }

  const FNOX_AGE_WITHOUT_KEY_FILE: &str = r#"
[providers.age]
type = "age"
recipients = ["age1arkhamreviewplaceholder"]
key_file = "/nonexistent/arkham-final-review-age-key.txt"

[secrets.DECLARED_BUT_UNRESOLVABLE]
provider = "age"
value = "not-an-age-ciphertext"
"#;

  const FNOX_EMPTY_VALUE: &str = r#"
[providers.plain]
type = "plain"

[secrets.DECLARED_BUT_EMPTY]
provider = "plain"
value = ""
"#;

  #[tokio::test]
  async fn declared_key_that_cannot_be_fetched_errors_under_every_if_missing() {
    let registry = Registry::load(None).unwrap();
    let dir = tempdir().unwrap();
    let fnox_path = write_fnox(dir.path(), FNOX_AGE_WITHOUT_KEY_FILE);
    for if_missing in [IfMissing::Error, IfMissing::Warn, IfMissing::Ignore] {
      let mut rule = rule("GITHUB_TOKEN");
      rule.value = None;
      rule.fnox_key = Some("DECLARED_BUT_UNRESOLVABLE".to_string());
      rule.if_missing = if_missing;
      let mut config = config_with("gh", rule);
      let fnox = FnoxSource::open_at(&fnox_path).unwrap();
      let err = resolve(&mut config, &registry, Some(fnox)).await.unwrap_err();
      assert!(err.to_string().contains("DECLARED_BUT_UNRESOLVABLE"), "{if_missing:?}: {err:?}");
    }
  }

  #[tokio::test]
  async fn declared_key_that_resolves_empty_errors_under_every_if_missing() {
    let registry = Registry::load(None).unwrap();
    let dir = tempdir().unwrap();
    let fnox_path = write_fnox(dir.path(), FNOX_EMPTY_VALUE);
    for if_missing in [IfMissing::Error, IfMissing::Warn, IfMissing::Ignore] {
      let mut rule = rule("GITHUB_TOKEN");
      rule.value = None;
      rule.fnox_key = Some("DECLARED_BUT_EMPTY".to_string());
      rule.if_missing = if_missing;
      let mut config = config_with("gh", rule);
      let fnox = FnoxSource::open_at(&fnox_path).unwrap();
      let err = resolve(&mut config, &registry, Some(fnox)).await.unwrap_err();
      assert!(err.to_string().contains("DECLARED_BUT_EMPTY"), "{if_missing:?}: {err:?}");
      assert!(err.to_string().contains("empty"), "{if_missing:?}: {err:?}");
    }
  }

  #[tokio::test]
  async fn stated_real_without_generated_marker_is_dropped() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("NATS_CONTEXT");
    rule.value = Some(SecretString::from("nats://decoy-token@nats.internal:4222"));
    rule.real = Some(SecretString::from("nats://real-token@nats.internal:4222"));
    rule.if_missing = IfMissing::Error;
    let mut config = config_with("nats", rule);
    let err = resolve(&mut config, &registry, None).await.expect_err("a hand-written real is ignored");
    assert!(err.to_string().contains("NATS_CONTEXT"), "{err}");
  }

  #[tokio::test]
  async fn all_inline_values_never_open_fnox() {
    let registry = Registry::load(None).unwrap();
    let mut config = config_with("gh", rule("GITHUB_TOKEN"));
    resolve(&mut config, &registry, None).await.unwrap();
    assert!(config.rules["gh"].value.is_some());
  }

  #[test]
  fn config_not_found_during_discovery_is_not_an_error() {
    let err = fnox_core::FnoxError::ConfigNotFound {
      message: "no config".to_string(),
      help: "run fnox init".to_string(),
    };
    assert!(discovered_or_none(Err(err)).unwrap().is_none());
  }
}
