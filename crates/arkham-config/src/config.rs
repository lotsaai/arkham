//! Config overlay: global + project files, env, CLI via confique.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use confique::{Config, Layer as _};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use validator::{Validate, ValidationError};

use crate::cli::Cli;
use crate::error::Error;
use crate::grants::{EndpointScope, GuestTlsMode, HostPat, NatsUriScheme, Scheme};
use crate::plugins::{PluginCfg, PluginDirection};
use crate::registry::{FlowKind, OAuthFlow, validate_flow};
use code_workspace::{Workspace, resolve_root};

/// Pattern used when neither the rule nor the registry supplies one.
pub const DEFAULT_PATTERN: &str = "{hex:32}";

/// Runtime config: listener settings, workspace mounts, plus rules by label.
#[derive(confique::Config, Debug, Clone, Serialize)]
pub struct AppConfig {
  /// Proxy listener settings.
  #[config(nested)]
  pub proxy: ProxyCfg,
  /// Workspace settings for generated compose output.
  #[config(nested)]
  pub workspace: WorkspaceCfg,
  /// Rules by label; merged per label across global + project files.
  #[config(default = {})]
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub rules: BTreeMap<String, RuleCfg>,
  /// WASM rewrite plugins by name; loaded at startup, fail closed.
  #[config(default = {})]
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub plugins: BTreeMap<String, PluginCfg>,
  /// Tool config mounts by tool name; extends or overrides the built-in table.
  #[config(default = {})]
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub tools: BTreeMap<String, ToolCfg>,
}

/// The profile every other profile inherits off: the shared base namespace.
/// Selected when `[workspace] profile` is unset.
pub const SHARED_PROFILE: &str = "__shared__";

/// `$HOME` inside the agent container when `[workspace] home` is unset: the
/// home every shipped example uses.
pub const DEFAULT_CONTAINER_HOME: &str = "/home/eng";

/// One tool config mount: the directory of this name under
/// `profiles/<profile>/` mounts at `config_dir` inside the agent container,
/// so the tool finds its own configuration where it looks by default.
#[derive(confique::Config, Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCfg {
  /// Container path the directory mounts at; `{home}` expands to
  /// `[workspace] home`.
  pub config_dir: String,
}

/// Extra host paths the generated agent service mounts, translated into the
/// container home; overlapping paths reuse the covering mount.
#[derive(confique::Config, Debug, Clone, Default, Serialize)]
pub struct WorkspaceCfg {
  /// Compose project name for the generated stack; defaults to the
  /// workspace slug.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub name: Option<String>,
  /// Shell `arkham agent` runs in the container when no command is given;
  /// defaults to sh.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub shell: Option<String>,
  /// Init script inside the agent image that the generated entrypoint chains
  /// to after installing the CA (`ARKHAM_INIT`); the common entrypoint script
  /// names are tried when unset, and the command runs directly otherwise.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub init: Option<String>,
  /// Paths included in the generated compose; `~` expands, relative paths
  /// resolve against the workspace root.
  #[config(default = [])]
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub include: Vec<PathBuf>,
  /// `$HOME` inside the agent container; host paths under the host home
  /// translate into this prefix, others mount at their own path. Unset
  /// means `/home/eng` (see `DEFAULT_CONTAINER_HOME`).
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub home: Option<String>,
  /// Profile selecting the isolated tool-config namespace the generated
  /// stack mounts; unset selects the shared base profile.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub profile: Option<String>,
  /// Ports the generated stack publishes on the host as stable `127.0.0.1`
  /// bindings, forwarded to the same port inside the agent's shared network
  /// namespace: the `fwd` sidecar exposes every agent-owned loopback
  /// listener there, and a published port names one from the host reliably
  /// instead of by a changing container IP. Applying a change needs a stack
  /// restart — publishings are fixed at container create.
  #[config(default = [])]
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub ports: Vec<u16>,
  /// On-demand host publishings with a distinct host port: each entry
  /// publishes `127.0.0.1:<host>` on the host, forwarded to `<port>` inside
  /// the agent's shared network namespace (same `fwd` mechanism as `ports`).
  /// The `arkham expose` command manages these entries so workspaces sharing
  /// one host never claim the same host port twice. Same load rules as
  /// `ports`: no zero, no capture listener ports, no host port twice.
  #[config(default = [])]
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub expose: Vec<ExposeMap>,
  /// Env names forwarded into the agent environment as `${NAME}` compose
  /// interpolation: compose substitutes the host value when the stack starts,
  /// so the generated file holds no secret and values stay fresh without
  /// regenerating. A name that is also a `[rules.*]` env or a selected decoy
  /// is a generation-time error — boundary discipline, one name one path.
  #[config(default = [])]
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub passthrough: Vec<String>,
  /// Host files rewritten with decoys and mounted read-only into the agent:
  /// each listed env name's real value is byte-replaced by its decoy and the
  /// result lands under the workspace state directory, mounted at `dest`
  /// (`{home}` expands to `home` above). A name with no known real value or
  /// no decoy fails generation, naming the name. Kubeconfig sources take a
  /// structural adapter instead of the byte-swap (detected, not declared)
  /// and state no `envs`: the file is the secret source.
  #[config(default = [])]
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub file_rewrite: Vec<FileRewrite>,
  /// Devices the generated stack hands the agent container on top of the
  /// built-in set (`/dev/net/tun`): host device paths passed verbatim to
  /// compose, e.g. `/dev/kvm`. Applying a change needs a stack restart —
  /// devices are fixed at container create.
  #[config(default = [])]
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub devices: Vec<String>,
  /// Extra Linux capabilities the agent container gains on top of the
  /// built-in set (`SYS_CHROOT`, `AUDIT_WRITE`, `NET_ADMIN`, `SETUID`,
  /// `SETGID`, `SYS_ADMIN`): capability names passed verbatim to compose,
  /// e.g. `SYS_PTRACE`.
  #[config(default = [])]
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub cap_add: Vec<String>,
  /// Existing compose networks the arkham service joins, each declared
  /// `external` at the top level: the agent inherits them through the shared
  /// network namespace (`network_mode: service:arkham`), so a sidecar like
  /// `headroom` on one of these networks is reachable by name from the
  /// agent. Joining any network moves arkham off the default project network.
  /// Applying a change needs a stack restart.
  #[config(default = [])]
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub networks: Vec<String>,
  /// Extra host entries rendered as `extra_hosts` on the arkham and agent
  /// services (`host:ip` or `host=ip`), beside the always-rendered
  /// `host.docker.internal:host-gateway`: `/etc/hosts` is per container, so
  /// both need each entry — the agent resolves the name, arkham dials the
  /// upstream. The gateway lets the agent reach host-bound services through
  /// the (spliced, not blocked) capture. Applying a change needs a stack
  /// restart.
  #[config(default = [])]
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub extra_hosts: Vec<String>,
  /// Agent image for the generated stack; defaults to the arkham dev image
  /// when unset.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub image: Option<String>,
  /// Dockerfile build for the agent image; when set, the agent service
  /// builds it instead of pulling, tagged with `image` above or a derived
  /// local tag.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub build: Option<WorkspaceBuild>,
}
impl WorkspaceCfg {
  /// Selected profile name, or the shared base when unset.
  #[must_use]
  pub fn profile_name(&self) -> &str {
    self.profile.as_deref().unwrap_or(SHARED_PROFILE)
  }

  /// `$HOME` inside the agent container: the stated `home`, or the default
  /// when unset or empty.
  #[must_use]
  pub fn container_home(&self) -> &str {
    self
      .home
      .as_deref()
      .filter(|home| !home.is_empty())
      .unwrap_or(DEFAULT_CONTAINER_HOME)
  }

  /// Every `$VAR` this workspace's settings reference: `include` entries,
  /// rewrite sources and dests with their envs, plus any extra strings the
  /// caller layers on top (the home).
  #[must_use]
  pub fn referenced_variables(&self, extra: &[&str]) -> BTreeSet<String> {
    let mut referenced = BTreeSet::new();
    for entry in &self.include {
      collect_referenced_variables(&entry.to_string_lossy(), &mut referenced);
    }
    for rewrite in &self.file_rewrite {
      collect_referenced_variables(&rewrite.source.to_string_lossy(), &mut referenced);
      collect_referenced_variables(&rewrite.dest, &mut referenced);
      referenced.extend(rewrite.envs.iter().cloned());
    }
    for value in extra {
      collect_referenced_variables(value, &mut referenced);
    }
    referenced
  }
}

/// Collect every `$VAR` reference in one interpolated string.
fn collect_referenced_variables(value: &str, names: &mut BTreeSet<String>) {
  for candidate in value.split('$').skip(1) {
    let name = match candidate.strip_prefix('{') {
      Some(braced) => match braced.split_once('}') {
        Some((inside, _)) => inside.split_once(":-").map_or(inside, |(name, _)| name),
        None => continue,
      },
      None => candidate
        .split(|character: char| !matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_'))
        .next()
        .unwrap_or_default(),
    };
    if valid_env_name(name) {
      names.insert(name.to_string());
    }
  }
}

/// Env names are `[_A-Za-z][_0-9A-Za-z]*`; anything else after a `$` is not a
/// reference.
fn valid_env_name(name: &str) -> bool {
  let mut chars = name.chars();
  let Some(first) = chars.next() else {
    return false;
  };
  matches!(first, 'A'..='Z' | 'a'..='z' | '_') && chars.all(|character| matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_'))
}

/// One host file to rewrite with decoys before the agent sees it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileRewrite {
  /// Host file to read: `~` and `$VAR` expand, relative paths resolve
  /// against the workspace root.
  pub source: PathBuf,
  /// Container path the rewritten file mounts at, read-only; `{home}`
  /// expands to `[workspace] home` and `$VAR` expands first.
  pub dest: String,
  /// Env names whose real values are replaced by their decoys in the file.
  /// Empty for the known config formats (`kubeconfig`, `talos`): the
  /// adapter knows where the secrets live.
  #[serde(default)]
  pub envs: Vec<String>,
  /// Declared format, skipping detection. Known formats: `kubeconfig`
  /// (kubectl), `talos` (talosctl). The git, jj, ssh, and nats configs are
  /// not declared: arkham reads them as ambient sources from their default
  /// locations. Unknown files keep the raw byte-swap when this is absent.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub format: Option<RewriteFormat>,
}

/// Declared `file_rewrite` format: the named adapter handles the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RewriteFormat {
  /// Kubectl config: structural grant derivation plus decoy twin.
  Kubeconfig,
  /// Talos client config: structural grant derivation plus decoy twin.
  Talos,
}

impl fmt::Display for RewriteFormat {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Kubeconfig => "kubeconfig",
      Self::Talos => "talos",
    })
  }
}

/// One on-demand host publishing with a distinct host port:
/// `[[workspace.expose]]` with `port = 3000, host = 3001` publishes
/// `127.0.0.1:3001` on the host, forwarded to port 3000 inside the agent's
/// shared network namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExposeMap {
  /// Port inside the agent's shared network namespace.
  pub port: u16,
  /// Port bound on the host (`127.0.0.1`).
  pub host: u16,
}

/// Dockerfile build for the agent image: paths resolve against the workspace
/// root, `~` expands. Both keys are required when `[workspace.build]` is
/// present; an absent section pulls `image` (or the default) instead.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceBuild {
  /// Dockerfile to build, relative to the workspace root.
  pub dockerfile: PathBuf,
  /// Build context directory, relative to the workspace root.
  pub context: PathBuf,
}

/// Proxy listener settings (CLI/env/file overlay).
#[derive(confique::Config, Clone, Debug, Serialize)]
#[config(layer_attr(derive(clap::Args, Clone, Debug, Default)))]
pub struct ProxyCfg {
  /// Explicit-proxy listen address.
  #[config(default = "127.0.0.1:8080", env = "ARKHAM_LISTEN")]
  #[config(layer_attr(arg(long = "listen", help = "explicit-proxy listen address")))]
  pub listen: SocketAddr,
  /// CA PEM path (default `/certs/ca.pem` when the generated stack mounted
  /// it there, else `<config-dir>/arkham/ca.pem`).
  #[config(env = "ARKHAM_CA_FILE")]
  #[config(layer_attr(arg(
    long = "ca-file",
    help = "CA PEM path (default /certs/ca.pem when mounted there, else <config-dir>/arkham/ca.pem)"
  )))]
  #[serde(skip_serializing_if = "Option::is_none")]
  pub ca_file: Option<PathBuf>,
  /// SSH host key path (default `<config-dir>/arkham/ssh_host_ed25519`):
  /// the key the guest leg presents, generated on first run.
  #[config(env = "ARKHAM_SSH_HOST_KEY")]
  #[config(layer_attr(arg(long = "ssh-host-key", help = "SSH host key path (default <config-dir>/arkham/ssh_host_ed25519)")))]
  #[serde(skip_serializing_if = "Option::is_none")]
  pub ssh_host_key: Option<PathBuf>,
  /// Arkham's own upstream `known_hosts`, OpenSSH `accept-new` semantics:
  /// first-seen keys are recorded, a changed key on a known host fails.
  #[config(env = "ARKHAM_SSH_KNOWN_HOSTS")]
  #[serde(skip_serializing_if = "Option::is_none")]
  pub ssh_known_hosts: Option<PathBuf>,
  /// Extra upstream CA bundles trusted on egress, additive to webpki roots.
  /// Entries extend this further with their own `root_cert`. Config file
  /// only: one path per bundle.
  #[config(default = [])]
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub root_certs: Vec<PathBuf>,
  /// Seconds the pre-auth or handshake reads may wait on a peer before the
  /// connection closes: the TLS `ClientHello`, the HTTP head, the Postgres
  /// greeting, and the upstream `SSLRequest` answer all share this budget.
  #[config(default = 10, env = "ARKHAM_HANDSHAKE_TIMEOUT_SECS")]
  #[config(layer_attr(arg(long = "handshake-timeout", help = "seconds a handshake read may wait before closing")))]
  pub handshake_timeout_secs: u64,
}

/// One rule: env name, allowed hosts, decoy shape, and value source.
#[derive(confique::Config, Debug, Clone, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct RuleCfg {
  /// Env var name: decoy seed, registry key, and default fnox key.
  #[validate(length(min = 1, message = "env must not be empty"))]
  pub env: String,
  /// Endpoint rules: the inline real secret (never serialized), winning over
  /// fnox. Database rules: the FAKE connection string the rule states — a
  /// proper `postgres://` URL, so the env var holds a URL — while the real
  /// connection string resolves from the secret source into `real`.
  #[serde(default, skip_serializing)]
  pub value: Option<SecretString>,
  /// Database and NATS connection-string rules: the real connection string.
  /// Fnox fills it when the key is present. A generated grant fragment may
  /// also state it. That stated value is used only when [`Self::generated`]
  /// is true and fnox has no value. A hand-written rule's stated real is ignored.
  #[serde(default, skip_serializing)]
  pub real: Option<SecretString>,
  /// Set by a generated grant fragment. A stated [`Self::real`] is kept only
  /// when this is true and fnox has no value for the rule. A hand-written
  /// rule leaves it false, and a stated real is ignored.
  #[config(default = false)]
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub generated: bool,
  /// fnox secret name; defaults to `env`.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub fnox_key: Option<String>,
  /// Raw `scheme://host[:port]` allow entries; unioned with registry hosts.
  #[serde(default)]
  #[validate(custom(function = "validate_allow"))]
  pub allow: Vec<String>,
  /// Explicit fake pattern overriding the registry.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[validate(custom(function = "validate_opt_pattern"))]
  pub pattern: Option<String>,
  /// `OAuth2` token-issuer flow overriding the registry.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub oauth2: Option<OAuthFlow>,
  /// Consult the host registry for this rule (default true).
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub registry: Option<bool>,
  /// What to do when the value or the hosts are missing.
  #[serde(default)]
  pub if_missing: IfMissing,
  /// Per-entry TLS configuration keyed by the exact `allow` entry string.
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub tls: BTreeMap<String, HostTlsCfg>,
  /// Per-entry SSH key material, keyed by the exact `allow` entry string.
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub ssh: BTreeMap<String, HostSshCfg>,
}

impl RuleCfg {
  /// The protocol a connection-string rule's `value` states, from its URL
  /// scheme; endpoint rules carry bare tokens and state none.
  #[must_use]
  pub fn value_scheme(&self) -> Option<Scheme> {
    let value = self.value.as_ref()?.expose_secret();
    if value.starts_with("postgres://") {
      Some(Scheme::Postgres)
    } else if value.starts_with("redis://") {
      Some(Scheme::Redis)
    } else if value.starts_with("rediss://") {
      Some(Scheme::Rediss)
    } else if value.starts_with("smtps://") {
      Some(Scheme::Smtps)
    } else if value.starts_with("smtp://") {
      Some(Scheme::Smtp)
    } else if value.starts_with("ldaps://") {
      Some(Scheme::Ldaps)
    } else if value.starts_with("ldap://") {
      Some(Scheme::Ldap)
    } else if NatsUriScheme::of(value).is_some() {
      Some(Scheme::Nats)
    } else if value.starts_with("amqps://") {
      Some(Scheme::Amqps)
    } else if value.starts_with("amqp://") {
      Some(Scheme::Amqp)
    } else {
      None
    }
  }

  /// An ssh rule's allow entries are all `ssh://` and its secret is key
  /// material in the `ssh` table: nothing resolves from fnox, and no
  /// registry union may touch the entry list.
  #[must_use]
  pub fn is_ssh(&self) -> bool {
    !self.ssh.is_empty()
  }
}

/// Per-entry TLS configuration, keyed by the rule's own `allow` entry string.
/// The proxy reads `client_cert`, `client_key`, `root_cert` and `guest_tls_mode`;
/// `guest_cert` and `guest_key` are compose-only mount targets inside the
/// guest container and no proxy behavior reads them.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostTlsCfg {
  /// Upstream client certificate (arkham → host), for endpoint entries.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub client_cert: Option<PathBuf>,
  /// Upstream client key, paired with `client_cert`.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub client_key: Option<PathBuf>,
  /// Upstream CA bundle trusting this entry's host, additive to the global
  /// egress trust (webpki roots plus the arkham CA).
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub root_cert: Option<PathBuf>,
  /// How the guest leg treats client certificates.
  #[serde(default)]
  pub guest_tls_mode: GuestTlsMode,
  /// Container-internal path the guest's minted certificate mounts at.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub guest_cert: Option<PathBuf>,
  /// Container-internal path the guest's minted key mounts at.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub guest_key: Option<PathBuf>,
}

/// Per-entry SSH key material, keyed by the rule's own `allow` entry string.
/// All three paths are required for an `ssh://` entry: the resolve step
/// fails closed when any is missing. Compose writes the blobs; the proxy
/// reads them at startup.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostSshCfg {
  /// Real private key (openssh format) the upstream leg presents.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub identity: Option<PathBuf>,
  /// Decoy public key (`authorized_keys` format) the guest leg admits.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub guest_key: Option<PathBuf>,
}

/// `allow` entries must all parse as URI grants.
fn validate_allow(entries: &Vec<String>) -> Result<(), ValidationError> {
  for entry in entries {
    entry.parse::<EndpointScope>().map_err(|err| {
      let mut error = ValidationError::new("allow");
      error.message = Some(format!("bad allow entry `{entry}`: {err}").into());
      error
    })?;
  }
  Ok(())
}

/// Present fake patterns must compile as templates. The validator derive
/// unwraps `Option` fields: `None` skips the check, `Some` lands here.
fn validate_opt_pattern(pattern: &String) -> Result<(), ValidationError> {
  if !pattern.is_empty() {
    validate_pattern(pattern).map_err(|err| {
      let mut error = ValidationError::new("pattern");
      error.message = Some(format!("bad pattern `{pattern}`: {err}").into());
      error
    })?;
  }
  Ok(())
}

/// What to do when a rule cannot be fully resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IfMissing {
  /// Fail startup.
  #[default]
  Error,
  /// Log a warning and drop the rule's grant.
  Warn,
  /// Drop the rule's grant silently.
  Ignore,
}

/// Load config with precedence CLI > env > project > global.
/// Returns the config plus the discovered workspace (`None` when no
/// workspace marker was found and no explicit root was given).
///
/// # Errors
///
/// Returns an error when the working directory is unreadable, when a config
/// layer is malformed, or when an `allow` entry fails to resolve.
pub fn load(cli: &Cli, proxy: Option<&<ProxyCfg as Config>::Layer>) -> Result<(AppConfig, Option<Workspace>), Error> {
  let cwd = env::current_dir().map_err(Error::CurrentDir)?;
  let mut cli_layer = <AppConfig as confique::Config>::Layer::empty();
  if let Some(proxy) = proxy {
    cli_layer.proxy = proxy.clone();
  }

  let mut builder = AppConfig::builder().preloaded(cli_layer).env();
  let project = match &cli.config {
    Some(path) => Some(path.clone()),
    None => discover_project_config(&cwd),
  };
  if let Some(path) = &project
    && path.exists()
  {
    builder = builder.file(path);
  }
  let global = global_config_path().filter(|path| path.exists());
  if let Some(path) = &global {
    builder = builder.file(path);
  }

  let mut config: AppConfig = builder.load()?;
  // confique merges the `rules` map wholesale per winning file, so re-merge
  // by label here: global entries first, project entries replace by label.
  // This second read of the same files is deliberate. confique's builder
  // produces the scalars and this pass produces the rule labels, so a file
  // edited between the two reads yields scalars from one parse and labels
  // from the other. Do not collapse it into a single read without accounting
  // for that.
  config.rules = load_merged_rules(project.as_deref(), global.as_deref())?;
  config.tools = load_merged_tools(project.as_deref(), global.as_deref())?;
  config.validate()?;

  let workspace = resolve_root(None, &cwd).ok().and_then(|root| Workspace::from_root(&root).ok());
  Ok((config, workspace))
}

/// Locate the project-layer file: resolve the workspace root upward from
/// `start`, then check the unified project config path with a legacy
/// fallback.
#[must_use]
pub fn discover_project_config(start: &Path) -> Option<PathBuf> {
  let root = resolve_root(None, start).ok()?;
  project_config_file(&root)
}

/// Merge `[rules]` tables by label: global first, project wins wholesale
/// per label. Errors name the file + label. A file that does not exist is
/// no layer at all: generation names the project path even when the
/// workspace has no config yet.
fn load_merged_rules(project: Option<&Path>, global: Option<&Path>) -> Result<BTreeMap<String, RuleCfg>, Error> {
  let mut merged = BTreeMap::new();
  for path in [global, project].into_iter().flatten() {
    let text = match fs::read_to_string(path) {
      Ok(text) => text,
      Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
      Err(source) => {
        return Err(Error::ReadFile {
          path: path.to_path_buf(),
          source,
        });
      }
    };
    let doc: toml::Table = toml::from_str(&text).map_err(|source| Error::ParseFile {
      path: path.to_path_buf(),
      source: Box::new(source),
    })?;
    let Some(rules) = doc.get("rules") else {
      continue;
    };
    let table = rules.as_table().ok_or_else(|| Error::RulesNotTable { path: path.to_path_buf() })?;
    for (label, entry) in table {
      let cfg = RuleCfg::deserialize(entry.clone()).map_err(|source| Error::BadRule {
        path: path.to_path_buf(),
        label: label.clone(),
        source: Box::new(source),
      })?;
      merged.insert(label.clone(), cfg);
    }
  }
  Ok(merged)
}

/// Merge `[tools]` tables by name: global first, project wins per name.
/// A file that does not exist is no layer at all, as in
/// [`load_merged_rules`].
fn load_merged_tools(project: Option<&Path>, global: Option<&Path>) -> Result<BTreeMap<String, ToolCfg>, Error> {
  let mut merged = BTreeMap::new();
  for path in [global, project].into_iter().flatten() {
    let text = match std::fs::read_to_string(path) {
      Ok(text) => text,
      Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
      Err(source) => {
        return Err(Error::ReadFile {
          path: path.to_path_buf(),
          source,
        });
      }
    };
    let doc: toml::Table = toml::from_str(&text).map_err(|source| Error::ParseFile {
      path: path.to_path_buf(),
      source: Box::new(source),
    })?;
    if let Some(tools) = doc.get("tools") {
      let table = tools.as_table().ok_or_else(|| Error::ToolsNotTable { path: path.to_path_buf() })?;
      for (name, entry) in table {
        let cfg = ToolCfg::deserialize(entry.clone()).map_err(|source| Error::BadTool {
          path: path.to_path_buf(),
          name: name.clone(),
          source: Box::new(source),
        })?;
        merged.insert(name.clone(), cfg);
      }
    }
  }
  Ok(merged)
}

/// Project config directory: `<root>/.config/arkham/`, mirroring the global
/// config directory layout.
#[must_use]
pub fn project_config_dir(root: &Path) -> PathBuf {
  root.join(".config").join("arkham")
}

/// Project-layer file: the unified path first, the legacy flat file when the
/// unified one is absent.
#[must_use]
pub fn project_config_file(root: &Path) -> Option<PathBuf> {
  let unified = project_config_dir(root).join("config.toml");
  if unified.is_file() {
    return Some(unified);
  }
  let legacy = root.join(".config").join("arkham.toml");
  if legacy.is_file() {
    tracing::warn!(path = %legacy.display(), "legacy project config path; move it to .config/arkham/config.toml");
    return Some(legacy);
  }
  None
}

/// Path `arkham init` writes the workspace config to: always the unified one.
#[must_use]
pub fn project_config_write_path(root: &Path) -> PathBuf {
  project_config_dir(root).join("config.toml")
}

/// Project registry overrides: `<root>/.config/arkham/rules.d/`.
#[must_use]
pub fn project_rules_dir(root: &Path) -> PathBuf {
  project_config_dir(root).join("rules.d")
}

/// Project profile roots: `<root>/.config/arkham/profiles/`.
#[must_use]
pub fn project_profiles_dir(root: &Path) -> PathBuf {
  project_config_dir(root).join("profiles")
}

/// Project registry overrides for the workspace enclosing the working
/// directory, when one encloses it.
#[must_use]
pub fn cwd_project_rules_dir() -> Option<PathBuf> {
  let cwd = env::current_dir().ok()?;
  let root = resolve_root(None, &cwd).ok()?;
  Some(project_rules_dir(&root))
}

/// One profile dir name: a single path segment, never `.` or `..`.
#[must_use]
pub fn valid_profile(name: &str) -> bool {
  !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\')
}

/// The parent a profile inherits off, from its `profile.toml` cookie. The
/// first layer holding a cookie wins outright, project before global: a
/// cookie without a `parent` key inherits the shared base directly, it does
/// not fall through to the other layer's cookie. No cookie at all means the
/// shared base. The shared base itself takes no parent.
fn profile_parent(project: Option<&Path>, global: Option<&Path>, profile: &str) -> Result<Option<String>, Error> {
  for layer in [project, global].into_iter().flatten() {
    let cookie = layer.join(profile).join("profile.toml");
    if !cookie.is_file() {
      continue;
    }
    let text = std::fs::read_to_string(&cookie).map_err(|source| Error::ReadFile {
      path: cookie.clone(),
      source,
    })?;
    let doc: toml::Table = toml::from_str(&text).map_err(|source| Error::ParseFile {
      path: cookie.clone(),
      source: Box::new(source),
    })?;
    let Some(parent) = doc.get("profile").and_then(|table| table.get("parent")) else {
      return Ok(None);
    };
    let Some(parent) = parent.as_str() else {
      return Err(Error::ProfileParentNotString { path: cookie.clone() });
    };
    if profile == SHARED_PROFILE {
      return Err(Error::SharedProfileParent { path: cookie.clone() });
    }
    if !valid_profile(parent) {
      return Err(Error::BadProfileParent {
        path: cookie.clone(),
        parent: parent.to_string(),
      });
    }
    return Ok(Some(parent.to_string()));
  }
  Ok(None)
}

/// Inheritance chain for `selected`, nearest first, ending at the shared
/// base. A profile missing from every layer resolves to the shared base
/// alone only when nothing names it; the selected profile missing everywhere
/// warns, since that is usually a misspelled `[workspace] profile`.
///
/// # Errors
///
/// Returns an error on an inheritance cycle, an invalid parent name, a
/// parent no layer holds, or a parent on the shared base.
pub fn profile_chain(project: Option<&Path>, global: Option<&Path>, selected: &str) -> Result<Vec<String>, Error> {
  if !valid_profile(selected) {
    return Err(Error::BadProfileName {
      name: selected.to_string(),
    });
  }
  let mut chain = vec![selected.to_string()];
  let mut name = selected.to_string();
  loop {
    if name == SHARED_PROFILE {
      profile_parent(project, global, &name)?;
      break;
    }
    let parent = profile_parent(project, global, &name)?.unwrap_or_else(|| SHARED_PROFILE.to_string());
    if chain.contains(&parent) {
      return Err(Error::ProfileCycle { parent: parent.clone() });
    }
    let held = parent == SHARED_PROFILE || [project, global].into_iter().flatten().any(|layer| layer.join(&parent).is_dir());
    if !held {
      return Err(Error::ProfileParentMissing {
        name: name.clone(),
        parent: parent.clone(),
      });
    }
    chain.push(parent.clone());
    name = parent;
  }
  let held = [project, global].into_iter().flatten().any(|layer| layer.join(selected).is_dir());
  if !held && selected != SHARED_PROFILE {
    tracing::warn!(
      profile = selected,
      "selected profile holds no directory in any layer; only shared tools mount"
    );
  }
  Ok(chain)
}

fn global_config_path() -> Option<PathBuf> {
  if let Ok(path) = env::var("ARKHAM_CONFIG") {
    return Some(PathBuf::from(path));
  }
  let standard = dirs::config_dir().map(|dir| dir.join("arkham").join("config.toml"));
  if let Some(path) = &standard
    && path.exists()
  {
    return Some(path.clone());
  }
  #[cfg(target_os = "macos")]
  {
    if let Some(home) = dirs::home_dir() {
      let path = home.join(".config").join("arkham").join("config.toml");
      if path.exists() {
        return Some(path);
      }
    }
  }
  standard
}

/// Directory holding the global config file, and `rules.d` beside it.
#[must_use]
pub fn config_dir() -> Option<PathBuf> {
  global_config_path().and_then(|path| path.parent().map(Path::to_path_buf))
}

/// Registry override directory: `rules.d` beside the global config file.
#[must_use]
pub fn rules_dir() -> Option<PathBuf> {
  config_dir().map(|dir| dir.join("rules.d"))
}

impl AppConfig {
  fn validate(&self) -> Result<(), Error> {
    let mut env_names: BTreeMap<&str, &str> = BTreeMap::new();
    for (label, rule) in &self.rules {
      if let Some(previous) = env_names.insert(rule.env.as_str(), label.as_str()) {
        return Err(Error::DuplicateEnv {
          previous: previous.to_string(),
          label: label.clone(),
          env: rule.env.clone(),
        });
      }
      if rule.env.is_empty() {
        return Err(Error::EmptyEnv { label: label.clone() });
      }
      if let Some(value) = &rule.value
        && value.expose_secret().is_empty()
      {
        return Err(Error::EmptyValue { label: label.clone() });
      }
      for entry in &rule.allow {
        let scope: EndpointScope = entry.parse().map_err(|err| Error::BadAllow {
          label: label.clone(),
          entry: entry.clone(),
          detail: err,
        })?;
        if matches!(scope.host, HostPat::Any) {
          tracing::warn!(label, entry, "grant matches any host; secret is exfil-risky");
        }
      }
      if let Some(pattern) = rule.pattern.as_deref().filter(|p| !p.is_empty()) {
        validate_pattern(pattern).map_err(|err| Error::BadPattern {
          label: label.clone(),
          pattern: pattern.to_string(),
          detail: err,
        })?;
      }
      if let Some(flow) = &rule.oauth2 {
        validate_flow(flow, "config", label)?;
      }
    }
    for port in &self.workspace.ports {
      if *port == 0 {
        return Err(Error::PortZero);
      }
      // The capture listeners hold these ports inside the shared netns, and
      // the `fwd` sidecar only forwards agent-owned listeners, so a published
      // capture port would shadow a host port with a dead binding. The
      // literals must stay in step with arkham-ebpf's `TCP_LISTEN_PORT` and
      // `UDP_LISTEN_PORT` (and with `arkham expose`'s pre-check).
      if *port == 15_000 || *port == 15_001 {
        return Err(Error::CapturePort { port: *port });
      }
    }
    // Host-side publishings must name distinct host ports: two bindings on
    // one host port is a compose create error, caught here with the setting
    // named instead.
    let mut hosts: BTreeSet<u16> = self.workspace.ports.iter().copied().collect();
    for map in &self.workspace.expose {
      for port in [map.port, map.host] {
        if port == 0 {
          return Err(Error::PortZero);
        }
        if port == 15_000 || port == 15_001 {
          return Err(Error::CapturePort { port });
        }
      }
      if !hosts.insert(map.host) {
        return Err(Error::ExposeHostConflict { port: map.host });
      }
    }
    for name in &self.workspace.networks {
      let plain = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
      if !plain {
        return Err(Error::NetworkInvalid { name: name.clone() });
      }
    }
    for entry in &self.workspace.extra_hosts {
      let shaped = entry
        .split_once([':', '='])
        .is_some_and(|(host, addr)| !host.trim().is_empty() && !addr.trim().is_empty());
      if !shaped {
        return Err(Error::ExtraHostsInvalid { entry: entry.clone() });
      }
    }
    Ok(())
  }
}

/// Deterministic format-valid fake seeded on `seed`. Static decoys seed on
/// the env name (stable across restarts, distinct per name); runtime token
/// minting seeds on the real token value (one decoy per issued token). A
/// raw TCP grant renders the seed at the real value's length by passing
/// `{hex:<len>}` as the pattern. `pattern` wins; the registry supplies one
/// through `Registry::decoy`, and `DEFAULT_PATTERN` is the floor.
#[must_use]
pub fn fake_for(seed: &str, pattern: Option<&str>) -> String {
  let template = pattern.filter(|pattern| !pattern.is_empty()).unwrap_or(DEFAULT_PATTERN);
  let seed = hex::encode(Sha256::digest(seed.as_bytes()));
  render_template(template, &seed)
}

/// Validate an explicit `pattern` template: every `{...}` must be a known
/// encoding (`hex`, `d`, `base62`) with a nonzero count. Rejects typos that
/// would otherwise render silently wrong (`{bogus:10}` → base62) or empty
/// (`{hex:0}` → skipped grant).
///
/// # Errors
///
/// Returns an error naming the offending encoding or count when a `{...}` segment
/// names no known encoding or carries a zero count.
pub fn validate_pattern(pattern: &str) -> Result<(), String> {
  let mut rest = pattern;
  while let Some(open) = rest.find('{') {
    let after = &rest[open + 1..];
    let Some(close) = after.find('}') else {
      return Err("unclosed `{`".to_string());
    };
    let body = &after[..close];
    let valid = match body.split_once(':') {
      Some((kind, count)) if matches!(kind, "hex" | "d" | "base62") && !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit()) => {
        count.parse::<usize>().is_ok_and(|n| n > 0)
      }
      _ => false,
    };
    if !valid {
      return Err(format!(
        "bad encoding `{{{body}}}`: expected {{hex:N}}, {{d:N}}, or {{base62:N}} with N > 0"
      ));
    }
    rest = &after[close + 1..];
  }
  Ok(())
}

/// A validated fake-template encoding: only these three render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
  Hex,
  Decimal,
  Base62,
}

impl Encoding {
  /// Parse an encoding name; `None` for anything `validate_pattern` rejects.
  fn parse(kind: &str) -> Option<Self> {
    match kind {
      "hex" => Some(Self::Hex),
      "d" => Some(Self::Decimal),
      "base62" => Some(Self::Base62),
      _ => None,
    }
  }

  /// Stable seed tag so each encoding streams independently per index.
  fn tag(self) -> &'static str {
    match self {
      Self::Hex => "hex",
      Self::Decimal => "d",
      Self::Base62 => "base62",
    }
  }
}

/// Upper bound on one pattern segment's count. Patterns come from config
/// and the bundled registry; real decoys are token-sized.
const MAX_PATTERN_COUNT: usize = 4096;

fn render_template(template: &str, seed: &str) -> String {
  let mut out = String::new();
  let mut rest = template;
  while let Some(open) = rest.find('{') {
    out.push_str(&rest[..open]);
    let after = &rest[open + 1..];
    let Some(close) = after.find('}') else {
      out.push_str(&rest[open..]);
      return out;
    };
    let body = &after[..close];
    // Unknown encodings and unparseable counts render literally: silently
    // emitting base62 (or nothing) would mint the wrong decoy shape.
    let literal = |out: &mut String| {
      out.push('{');
      out.push_str(body);
      out.push('}');
    };
    let validated = match body.split_once(':') {
      Some((kind, count_raw)) if !count_raw.is_empty() && count_raw.bytes().all(|b| b.is_ascii_digit()) => {
        match (Encoding::parse(kind), count_raw.parse::<usize>()) {
          // A count past the cap renders literally: an absurd pattern is a
          // config mistake, not a multi-gigabyte decoy to grind out.
          (Some(encoding), Ok(count)) if count <= MAX_PATTERN_COUNT => Some((encoding, count)),
          _ => None,
        }
      }
      _ => None,
    };
    match validated {
      Some((encoding, count)) => out.push_str(&fill_encoding(seed, encoding, count)),
      None => literal(&mut out),
    }
    rest = &after[close + 1..];
  }
  out.push_str(rest);
  out
}

/// Render `count` chars of `verb` from `seed`. Every encoding is a library
/// call: `hex::encode`, `base62::encode`, or std `Display` for decimal.
fn fill_encoding(seed: &str, encoding: Encoding, count: usize) -> String {
  let mut out = String::with_capacity(count);
  let mut index = 0;
  while out.len() < count {
    let digest = Sha256::digest(format!("{}:{}:{index}", seed, encoding.tag()).as_bytes());
    match encoding {
      Encoding::Hex => out.push_str(&hex::encode(digest)),
      Encoding::Decimal => {
        let head: [u8; 4] = digest.get(..4).and_then(|bytes| bytes.try_into().ok()).unwrap_or([0; 4]);
        out.push_str(&u32::from_be_bytes(head).to_string());
      }
      Encoding::Base62 => {
        let mut word = [0u8; 16];
        if let (Some(bytes), Some(slot)) = (digest.get(..16), word.get_mut(..16)) {
          slot.copy_from_slice(bytes);
        }
        out.push_str(&base62::encode(u128::from_be_bytes(word)));
      }
    }
    index += 1;
  }
  out.truncate(count);
  out
}

/// One sample entry per map-valued table, serialized for the reference
/// `arkham config` appends to the schema template. Drift is compile-checked:
/// every literal below names all fields of its struct, so a new field fails
/// the build until the sample states it, and
/// `reference_samples_name_every_setting` fails when the serializer then
/// hides one. No production type carries reference-only baggage.
///
/// # Errors
///
/// Returns an error when the in-repo sample literals fail to serialize.
pub fn reference_samples() -> Result<String, Error> {
  #[derive(Serialize)]
  struct Samples<'a> {
    rules: BTreeMap<&'a str, RuleCfg>,
    plugins: BTreeMap<&'a str, PluginCfg>,
    tools: BTreeMap<&'a str, ToolCfg>,
    workspace: WorkspaceSamples,
  }
  #[derive(Serialize)]
  struct WorkspaceSamples {
    file_rewrite: Vec<FileRewrite>,
  }
  let mut rule_tls = BTreeMap::new();
  rule_tls.insert(
    "https://api.example".to_string(),
    HostTlsCfg {
      client_cert: Some("/certs/client.pem".into()),
      client_key: Some("/certs/client.key".into()),
      root_cert: Some("/certs/bundle.pem".into()),
      guest_tls_mode: GuestTlsMode::Mtls,
      guest_cert: Some("{home}/.certs/client.pem".into()),
      guest_key: Some("{home}/.certs/client.key".into()),
    },
  );
  let rule = RuleCfg {
    env: "EXAMPLE_TOKEN".to_string(),
    value: None,
    real: None,
    generated: false,
    fnox_key: Some("EXAMPLE_FNOX_KEY".to_string()),
    allow: vec![
      "https://api.example".to_string(),
      "postgres://db.example:5432/app?sslmode=verify-full&sslrootcert=/certs/bundle.pem".to_string(),
      "ssh://git.example".to_string(),
    ],
    pattern: Some("example_{hex:32}".to_string()),
    oauth2: Some(OAuthFlow {
      flow: FlowKind::ClientCredentials,
      token_url: "https://auth.example/token".to_string(),
      authorize_url: Some("https://auth.example/authorize".to_string()),
      refresh_url: Some("https://auth.example/refresh".to_string()),
      rotates_refresh: true,
      token_fields: vec!["access_token".to_string()],
    }),
    registry: Some(true),
    if_missing: IfMissing::Warn,
    tls: rule_tls,
    ssh: BTreeMap::from([(
      "ssh://git.example".to_string(),
      HostSshCfg {
        identity: Some("/arkham/grants/rules.d/example.identity".into()),
        guest_key: Some("/arkham/grants/rules.d/example.guest_key".into()),
      },
    )]),
  };
  let samples = Samples {
    rules: [("example", rule)].into_iter().collect(),
    plugins: [(
      "example",
      PluginCfg {
        path: "target/plugins/example.wasm".into(),
        allow: vec!["https://api.example".to_string()],
        direction: PluginDirection::Both,
      },
    )]
    .into_iter()
    .collect(),
    tools: [(
      "example",
      ToolCfg {
        config_dir: "{home}/.example".to_string(),
      },
    )]
    .into_iter()
    .collect(),
    workspace: WorkspaceSamples {
      file_rewrite: vec![FileRewrite {
        source: "~/.example/settings".into(),
        dest: "{home}/.example/settings".to_string(),
        envs: vec!["EXAMPLE_TOKEN".to_string()],
        format: Some(RewriteFormat::Kubeconfig),
      }],
    },
  };
  let mut out = String::from("\n# ── Map-valued tables: one sample entry each; copy and rename the key ──\n\n");
  out.push_str("# `value` and `real` never serialize (secrets): `value` is the inline\n# real secret (or the database rule's FAKE postgres:// URL), `real` is the\n# database rule's REAL string, resolved from the secret source.\n\n");
  out.push_str(&toml::to_string_pretty(&samples).map_err(|source| Error::SerializeSamples { source })?);
  Ok(out)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::ffi::OsStr;
  use std::io::Write as _;
  use std::sync::{Mutex, MutexGuard, PoisonError};

  use clap::Parser as _;

  static ENV_LOCK: Mutex<()> = Mutex::new(());

  fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
  }

  fn scrub_env() {
    for key in ["ARKHAM_CONFIG", "ARKHAM_LISTEN", "ARKHAM_CA_FILE"] {
      // SAFETY: test-only mutation, serialized by ENV_LOCK.
      unsafe { env::remove_var(key) };
    }
  }

  /// Test-only env write; callers hold `ENV_LOCK`.
  fn set_env(key: &str, value: impl AsRef<OsStr>) {
    // SAFETY: test-only mutation, serialized by ENV_LOCK.
    unsafe { env::set_var(key, value) };
  }

  fn write_file(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
      fs::create_dir_all(parent).unwrap();
    }
    let mut file = fs::File::create(path).unwrap();
    file.write_all(body.as_bytes()).unwrap();
  }

  #[derive(clap::Parser)]
  struct TestCli {
    #[command(flatten)]
    cli: Cli,
  }

  fn cli_for(argv: &[&str]) -> Cli {
    TestCli::try_parse_from(argv).unwrap().cli
  }

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

  #[test]
  fn overlay_merges_proxy_scalar_and_rules_by_label() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    let project_root = dir.path().join("proj");
    let project = project_root.join(".config").join("arkham.toml");
    write_file(
      &global,
      r#"
[proxy]
listen = "127.0.0.1:1111"
[rules.a]
env = "A_TOKEN"
value = "global-a"
allow = ["https://a.example"]
[rules.b]
env = "B_TOKEN"
value = "global-b"
allow = ["https://b.example"]
"#,
    );
    write_file(
      &project,
      r#"
[proxy]
listen = "127.0.0.1:2222"
[rules.b]
env = "B_TOKEN"
value = "project-b"
allow = ["https://b.example"]
[rules.c]
env = "C_TOKEN"
value = "project-c"
allow = ["https://c.example"]
"#,
    );
    set_env("ARKHAM_CONFIG", &global);
    let nested = project_root.join("crates").join("inner");
    write_file(&project_root.join("Cargo.toml"), "[workspace]\n");
    fs::create_dir_all(&nested).unwrap();
    let _cwd = CwdGuard::enter(&nested);
    let cli = cli_for(&["arkham"]);
    let (config, _ws) = load(&cli, None).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:2222");
    assert_eq!(config.rules["a"].value.as_ref().unwrap().expose_secret(), "global-a");
    assert_eq!(config.rules["b"].value.as_ref().unwrap().expose_secret(), "project-b");
    assert_eq!(config.rules["c"].value.as_ref().unwrap().expose_secret(), "project-c");
    scrub_env();
  }

  #[test]
  fn a_config_flag_pointing_at_nothing_yields_the_global_layer_alone() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(
      &global,
      r#"
[rules.a]
env = "A_TOKEN"
value = "global-a"
allow = ["https://a.example"]
"#,
    );
    set_env("ARKHAM_CONFIG", &global);
    let missing = dir.path().join("fresh").join(".config").join("arkham").join("config.toml");
    let cli = cli_for(&["arkham", "--config", missing.to_str().unwrap()]);
    let (config, _) = load(&cli, None).unwrap();
    assert_eq!(config.rules["a"].value.as_ref().unwrap().expose_secret(), "global-a");
    assert_eq!(
      config.rules.len(),
      1,
      "a project file that does not exist is no project layer at all"
    );
    scrub_env();
  }

  #[test]
  fn unified_project_path_wins_over_the_legacy_flat_file() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let project_root = dir.path().join("proj");
    write_file(&project_root.join("Cargo.toml"), "[workspace]\n");
    write_file(
      &project_root.join(".config").join("arkham.toml"),
      "[proxy]\nlisten = \"127.0.0.1:2222\"\n",
    );
    write_file(
      &project_root.join(".config").join("arkham").join("config.toml"),
      "[proxy]\nlisten = \"127.0.0.1:3333\"\n",
    );
    let nested = project_root.join("inner");
    std::fs::create_dir_all(&nested).unwrap();
    let _cwd = CwdGuard::enter(&nested);
    assert_eq!(
      discover_project_config(&nested),
      Some(project_root.join(".config").join("arkham").join("config.toml"))
    );
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:3333");
    assert_eq!(WorkspaceCfg::default().profile_name(), SHARED_PROFILE);
    scrub_env();
  }

  #[test]
  fn tools_merge_by_name_with_project_winning() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    let project_root = dir.path().join("proj");
    write_file(
      &global,
      "[tools.pi]\nconfig_dir = \"{home}/.pi\"\n[tools.gh]\nconfig_dir = \"{home}/.config/gh\"\n",
    );
    write_file(
      &project_root.join(".config").join("arkham.toml"),
      "[workspace]\nprofile = \"work\"\n[tools.pi]\nconfig_dir = \"{home}/.pi-proj\"\n",
    );
    write_file(&project_root.join("Cargo.toml"), "[workspace]\n");
    set_env("ARKHAM_CONFIG", &global);
    let _cwd = CwdGuard::enter(&project_root);
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    assert_eq!(config.tools["pi"].config_dir, "{home}/.pi-proj");
    assert_eq!(config.tools["gh"].config_dir, "{home}/.config/gh");
    assert_eq!(config.workspace.profile_name(), "work");
    scrub_env();
  }

  #[test]
  fn profile_chain_follows_cookies_project_first() {
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("g").join("profiles");
    let project = dir.path().join("p").join("profiles");
    for d in [
      global.join("__shared__"),
      global.join("mid"),
      project.join("leaf"),
      project.join("mid"),
    ] {
      std::fs::create_dir_all(&d).unwrap();
    }
    write_file(&global.join("mid").join("profile.toml"), "[profile]\nparent = \"__shared__\"\n");
    write_file(&project.join("leaf").join("profile.toml"), "[profile]\nparent = \"mid\"\n");
    let chain = profile_chain(Some(project.as_path()), Some(global.as_path()), "leaf").unwrap();
    assert_eq!(chain, vec!["leaf", "mid", "__shared__"]);
    write_file(&project.join("leaf").join("profile.toml"), "[profile]\nparent = \"ghost\"\n");
    let err = profile_chain(Some(project.as_path()), Some(global.as_path()), "leaf").unwrap_err();
    assert!(err.to_string().contains("ghost"), "{err:?}");
  }

  #[test]
  fn precedence_cli_beats_env_beats_project_beats_global() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    let project_root = dir.path().join("proj");
    write_file(&global, "[proxy]\nlisten = \"127.0.0.1:1111\"\n");
    write_file(
      &project_root.join(".config").join("arkham.toml"),
      "[proxy]\nlisten = \"127.0.0.1:2222\"\n",
    );
    set_env("ARKHAM_CONFIG", &global);
    let nested = project_root.join("crates").join("inner");
    write_file(&project_root.join("Cargo.toml"), "[workspace]\n");
    fs::create_dir_all(&nested).unwrap();
    let _cwd = CwdGuard::enter(&nested);
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:2222");
    set_env("ARKHAM_LISTEN", "127.0.0.1:3333");
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:3333");
    let mut proxy = <ProxyCfg as Config>::Layer::empty();
    proxy.listen = Some("127.0.0.1:4444".parse().unwrap());
    let (config, _) = load(&cli_for(&["arkham"]), Some(&proxy)).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:4444");
    // the handshake budget defaults to 10 and layers like everything else
    assert_eq!(config.proxy.handshake_timeout_secs, 10);
    set_env("ARKHAM_HANDSHAKE_TIMEOUT_SECS", "3");
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    assert_eq!(config.proxy.handshake_timeout_secs, 3);
    let mut proxy = <ProxyCfg as Config>::Layer::empty();
    proxy.handshake_timeout_secs = Some(5);
    let (config, _) = load(&cli_for(&["arkham"]), Some(&proxy)).unwrap();
    assert_eq!(config.proxy.handshake_timeout_secs, 5);
    scrub_env();
  }

  #[test]
  fn config_flag_replaces_project_layer() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    let override_file = dir.path().join("override.toml");
    write_file(&global, "[proxy]\nlisten = \"127.0.0.1:1111\"\n");
    write_file(&override_file, "[proxy]\nlisten = \"127.0.0.1:5555\"\n");
    set_env("ARKHAM_CONFIG", &global);
    let markerless = dir.path().join("markerless");
    fs::create_dir_all(&markerless).unwrap();
    let _cwd = CwdGuard::enter(&markerless);
    let cli = cli_for(&["arkham", "--config", override_file.to_str().unwrap()]);
    let (config, _) = load(&cli, None).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:5555");
    scrub_env();
  }

  #[test]
  fn discovery_finds_workspace_root_from_nested_subdir() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("ws");
    let nested = root.join("crates").join("inner");
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir_all(root.join(".git")).unwrap();
    write_file(&root.join("Cargo.toml"), "[workspace]\n");
    let project = root.join(".config").join("arkham.toml");
    write_file(&project, "[proxy]\n");
    assert_eq!(discover_project_config(&nested), Some(project));
    fs::remove_file(root.join(".config").join("arkham.toml")).unwrap();
    assert_eq!(discover_project_config(&nested), None);
  }

  #[test]
  fn discovery_bare_dir_yields_no_project_layer() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(discover_project_config(dir.path()), None);
  }

  #[test]
  fn rule_value_is_optional_and_defaults_absent() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(
      &global,
      r#"
[rules.gh]
env = "GITHUB_TOKEN"
"#,
    );
    set_env("ARKHAM_CONFIG", &global);
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    let rule = &config.rules["gh"];
    assert!(rule.value.is_none());
    assert_eq!(rule.allow, [] as [String; 0]);
    assert_eq!(rule.if_missing, IfMissing::Error);
    assert_eq!(rule.registry, None);
    assert!(rule.fnox_key.is_none());
    scrub_env();
  }

  #[test]
  fn rule_parses_every_new_field() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(
      &global,
      r#"
[rules.gh]
env = "GITHUB_TOKEN"
value = "inline"
fnox_key = "GH_PAT"
allow = ["https://ghe.corp.example"]
pattern = "ghp_{hex:40}"
registry = false
if_missing = "warn"
"#,
    );
    set_env("ARKHAM_CONFIG", &global);
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    let rule = &config.rules["gh"];
    assert_eq!(rule.fnox_key.as_deref(), Some("GH_PAT"));
    assert_eq!(rule.registry, Some(false));
    assert_eq!(rule.if_missing, IfMissing::Warn);
    scrub_env();
  }

  #[test]
  fn an_ssh_rule_loads_its_key_material_from_the_file() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(
      &global,
      r#"
[rules.ssh]
env = "SSH_KEY"
registry = false
if_missing = "ignore"
allow = ["ssh://git.example"]

[rules.ssh.ssh."ssh://git.example"]
identity = "/arkham/grants/rules.d/t.identity"
guest_key = "/arkham/grants/rules.d/t.guest_key"
"#,
    );
    set_env("ARKHAM_CONFIG", &global);
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    let rule = &config.rules["ssh"];
    assert_eq!(rule.allow, ["ssh://git.example"]);
    let entry = &rule.ssh["ssh://git.example"];
    assert_eq!(entry.identity, Some(PathBuf::from("/arkham/grants/rules.d/t.identity")));
    assert_eq!(entry.guest_key, Some(PathBuf::from("/arkham/grants/rules.d/t.guest_key")));
    scrub_env();
  }

  #[test]
  fn rules_dir_sits_beside_the_config_file() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    set_env("ARKHAM_CONFIG", &global);
    assert_eq!(rules_dir(), Some(dir.path().join("rules.d")));
    scrub_env();
  }

  #[test]
  fn fakes_are_format_valid_and_deterministic() {
    let first = fake_for("GH_TOKEN", Some("ghp_{hex:40}"));
    assert_eq!(first, fake_for("GH_TOKEN", Some("ghp_{hex:40}")));
    assert!(first.starts_with("ghp_"), "{first}");
    assert_eq!(first.len(), 44);

    let fallback = fake_for("SOME_RANDOM_THING", None);
    assert_eq!(fallback.len(), 32);
    assert!(fallback.bytes().all(|b| b.is_ascii_hexdigit()));

    let explicit = fake_for("GH_TOKEN", Some("sk_live_{base62:24}"));
    assert_eq!(explicit, fake_for("GH_TOKEN", Some("sk_live_{base62:24}")));
    assert!(explicit.starts_with("sk_live_"), "{explicit}");

    assert_ne!(fake_for("GH_TOKEN", None), fake_for("GH_OTHER", None));
  }

  #[test]
  fn absurd_pattern_counts_render_literally() {
    assert_eq!(fake_for("X", Some("{hex:99999999}")), "{hex:99999999}");
    assert_eq!(render_template("{hex:4097}", "seed"), "{hex:4097}");
    assert_eq!(render_template("{hex:4096}", "seed").len(), 4096);
  }

  #[test]
  fn validate_rejects_bad_entries() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(&global, "[rules.bad]\nenv = \"B\"\nvalue = \"v\"\nallow = [\"gopher://h\"]\n");
    set_env("ARKHAM_CONFIG", &global);
    let err = load(&cli_for(&["arkham"]), None).unwrap_err();
    assert!(err.to_string().contains("gopher://h"), "{err:?}");
    scrub_env();
  }

  #[test]
  fn validate_rejects_bad_patterns() {
    validate_pattern("sk_live_{base62:24}").unwrap();
    validate_pattern("prefix_{hex:8}").unwrap();
    validate_pattern("{hex:0}").unwrap_err();
    validate_pattern("{bogus:10}").unwrap_err();
    validate_pattern("unclosed_{hex:8").unwrap_err();
  }

  #[test]
  fn duplicate_env_names_rejected() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(
      &global,
      r#"
[rules.a]
env = "A_TOKEN"
value = "a"
allow = ["https://a.example"]
[rules.b]
env = "A_TOKEN"
value = "b"
allow = ["https://b.example"]
"#,
    );
    set_env("ARKHAM_CONFIG", &global);
    let err = load(&cli_for(&["arkham"]), None).unwrap_err();
    assert!(err.to_string().contains("share env name"), "{err:?}");
    scrub_env();
  }

  #[test]
  fn unknown_encoding_renders_literally() {
    assert_eq!(render_template("{bogus:10}", "seed"), "{bogus:10}");
    assert_eq!(render_template("a{bogus:10}b", "seed"), "a{bogus:10}b");
    assert_eq!(fake_for("SOME_TOKEN", Some("{bogus:10}")), "{bogus:10}");
  }

  /// Workspace ports are load-refused when they cannot name an exposed
  /// agent listener: port 0 is no port, and the capture listeners are never
  /// agent-owned, so publishing one shadows a host port with a dead binding.
  #[test]
  fn workspace_ports_refuse_zero_and_the_capture_listener_ports() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    set_env("ARKHAM_CONFIG", &global);
    for (ports, expected) in [
      ("[0]", "port 0"),
      ("[15000]", "capture listener port"),
      ("[15001]", "capture listener port"),
      ("[3000, 0]", "port 0"),
    ] {
      write_file(&global, format!("[workspace]\nports = {ports}\n").as_str());
      let err = load(&cli_for(&["arkham"]), None).unwrap_err();
      assert!(err.to_string().contains(expected), "ports {ports}: {err:?}");
    }
    write_file(&global, "[workspace]\nports = [3000, 8080, 5432]\n");
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    assert_eq!(config.workspace.ports, vec![3000, 8080, 5432]);
    write_file(&global, "[proxy]\n");
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    assert!(config.workspace.ports.is_empty(), "absent ports stay empty");
    scrub_env();
  }

  /// Workspace networking keys load, default empty, and refuse malformed
  /// values: blank network names, host entries without a target, zero or
  /// capture ports in expose maps, and a host port published twice.
  #[test]
  fn workspace_networking_keys_validate() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    set_env("ARKHAM_CONFIG", &global);
    for (body, expected) in [
      ("networks = [\"\"]", "not a plain network name"),
      ("networks = [\"has space\"]", "not a plain network name"),
      ("extra_hosts = [\"bare-host\"]", "must be `host:ip`"),
      ("extra_hosts = [\":1.2.3.4\"]", "must be `host:ip`"),
      ("expose = [{ port = 0, host = 3000 }]", "port 0"),
      ("expose = [{ port = 3000, host = 15000 }]", "capture listener port"),
      ("ports = [3000]\nexpose = [{ port = 3000, host = 3000 }]", "published twice"),
    ] {
      write_file(&global, format!("[workspace]\n{body}\n").as_str());
      let err = load(&cli_for(&["arkham"]), None).unwrap_err();
      assert!(err.to_string().contains(expected), "{body}: {err:?}");
    }
    write_file(
      &global,
      "[workspace]\nports = [3000]\nnetworks = [\"headroom_default\"]\nextra_hosts = [\"host.docker.internal:host-gateway\"]\n[[workspace.expose]]\nport = 5173\nhost = 5174\n",
    );
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    assert_eq!(config.workspace.networks, vec!["headroom_default".to_string()]);
    assert_eq!(config.workspace.extra_hosts, vec!["host.docker.internal:host-gateway".to_string()]);
    assert_eq!(config.workspace.expose, vec![ExposeMap { port: 5173, host: 5174 }]);
    write_file(&global, "[proxy]\n");
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    assert!(config.workspace.networks.is_empty(), "absent networks stay empty");
    assert!(config.workspace.extra_hosts.is_empty(), "absent extra_hosts stay empty");
    assert!(config.workspace.expose.is_empty(), "absent expose stays empty");
    scrub_env();
  }

  #[test]
  fn workspace_image_and_build_parse() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    set_env("ARKHAM_CONFIG", &global);
    write_file(
      &global,
      "[workspace]\nimage = \"ghcr.io/example/devenv:1.0\"\n[workspace.build]\ndockerfile = \"docker/Dockerfile.agent\"\ncontext = \"docker\"\n",
    );
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    assert_eq!(config.workspace.image.as_deref(), Some("ghcr.io/example/devenv:1.0"));
    let build = config.workspace.build.as_ref().unwrap();
    assert_eq!(build.dockerfile, PathBuf::from("docker/Dockerfile.agent"));
    assert_eq!(build.context, PathBuf::from("docker"));
    write_file(&global, "[proxy]\n");
    let (config, _) = load(&cli_for(&["arkham"]), None).unwrap();
    assert!(config.workspace.image.is_none(), "absent image stays none");
    assert!(config.workspace.build.is_none(), "absent build stays none");
    scrub_env();
  }

  /// `$VAR`, `${VAR}` and `${VAR:-default}` all collect from every setting
  /// that interpolates, plus the extras; `$` alone and non-names do not.
  #[test]
  fn referenced_variables_collect_dollar_references_and_skip_noise() {
    let workspace = WorkspaceCfg {
      include: vec![PathBuf::from("$HOME/.cargo/${TOOL_BIN:-tool}/x")],
      file_rewrite: vec![FileRewrite {
        source: PathBuf::from("${UNBRACED}.npmrc"),
        dest: "{home}/.npmrc".to_string(),
        envs: vec!["NPM_TOKEN".to_string()],
        format: None,
      }],
      ..WorkspaceCfg::default()
    };
    let names = workspace.referenced_variables(&["$HOME"]);
    assert!(names.contains("HOME"));
    assert!(names.contains("TOOL_BIN"));
    assert!(names.contains("UNBRACED"));
    assert!(names.contains("NPM_TOKEN"));
    assert!(!names.contains("1"));
    assert!(!names.contains(""));
  }

  /// Braced references collect the name before `:-`, and a missing closing
  /// brace collects nothing.
  #[test]
  fn referenced_variables_collect_inside_composed_values() {
    let workspace = WorkspaceCfg {
      include: vec![PathBuf::from("https://${REGISTRY_HOST}/v2/${MISSING")],
      ..WorkspaceCfg::default()
    };
    assert_eq!(workspace.referenced_variables(&[]), BTreeSet::from(["REGISTRY_HOST".to_string()]));
  }

  /// Unset or empty `home` means the default container home; a stated home
  /// wins.
  #[test]
  fn container_home_defaults_when_unset_or_empty() {
    assert_eq!(WorkspaceCfg::default().container_home(), "/home/eng");
    let explicit = WorkspaceCfg {
      home: Some("/home/agent".to_string()),
      ..WorkspaceCfg::default()
    };
    assert_eq!(explicit.container_home(), "/home/agent");
    let empty = WorkspaceCfg {
      home: Some(String::new()),
      ..WorkspaceCfg::default()
    };
    assert_eq!(empty.container_home(), "/home/eng");
  }

  /// `arkham config` prints this: every setting, its default, and the doc
  /// comment explaining it, so undiscovered settings surface here first.
  #[test]
  fn config_template_lists_every_setting_with_its_default() {
    let template = confique::toml::template::<AppConfig>(confique::toml::FormatOptions::default());
    // Defaults render even though no config file names them.
    assert!(template.contains("handshake_timeout_secs = 10"), "{template}");
    assert!(template.contains("listen = \"127.0.0.1:8080\""), "{template}");
    // Every configurable table appears, including the maps.
    for section in ["[proxy]", "[workspace]", "#rules", "#plugins", "#tools", "#file_rewrite"] {
      assert!(template.contains(section), "missing `{section}` in:\n{template}");
    }
    // Doc comments travel with the settings they explain.
    assert!(template.contains("Default value"), "{template}");
    // Derived from the schema, never from values, and every line is
    // commented out: the template is a reference, never live config.
    assert!(!template.contains("\nvalue ="), "{template}");
  }

  /// Every field the sample literals name must survive serialization into
  /// the reference. The literals in [`reference_samples`] are exhaustive
  /// over their structs, so a new field fails to compile until sampled
  /// there; this test then fails if a skip attribute hides it anyway.
  #[test]
  fn reference_samples_name_every_setting() {
    let samples = reference_samples().expect("in-repo literals serialize");
    for name in [
      "[rules.example]",
      "env",
      "fnox_key",
      "allow",
      "pattern",
      "oauth2",
      "flow",
      "token_url",
      "authorize_url",
      "refresh_url",
      "rotates_refresh",
      "token_fields",
      "registry",
      "if_missing",
      "[rules.example.tls.\"https://api.example\"]",
      "client_cert",
      "client_key",
      "root_cert",
      "guest_tls_mode",
      "guest_cert",
      "guest_key",
      "[plugins.example]",
      "path",
      "direction",
      "[tools.example]",
      "config_dir",
      "[[workspace.file_rewrite]]",
      "source",
      "dest",
      "envs",
      "format",
    ] {
      assert!(samples.contains(name), "samples miss `{name}`:\n{samples}");
    }
    // The two secret fields never serialize; the sample explains them in
    // its own comment instead.
    assert!(samples.contains("`value` and `real` never serialize"), "{samples}");
    assert!(!samples.contains("\nvalue ="), "{samples}");
    assert!(!samples.contains("\nreal ="), "{samples}");
  }
}
