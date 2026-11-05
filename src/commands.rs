//! Binary-owned subcommands: each args struct implements [`CliCommand`] and
//! owns its `run`.
//!
//! Workspace commands (`init`, `agent`, `up`, `down`, `logs`) live in
//! `arkham-compose` instead; [`serve`](crate::serve) keeps its backend
//! machinery in the crate root and [`ServeArgs::run`] delegates to it.

#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use crate::fwd;
use crate::{ca_path, generation_registry, serve};
use arkham_compose::rules_command;
use arkham_config::ExposeSecret;
use arkham_config::cli::{Cli, CliCommand, ProxyBackend};
use arkham_config::config::{AppConfig, ProxyCfg, cwd_project_rules_dir, load, reference_samples, validate_pattern};
use arkham_config::grants::{EndpointScope, Scheme, decoy_for_rule};
use arkham_config::import::{flow_from_oidc, flows_from_openapi, to_toml_fragment};
use arkham_fnox::{FnoxSource, resolve};
use arkham_pki::ca::load_or_generate;
use clap::{Args, Subcommand};
use confique::Config;
use confique::toml::FormatOptions;
#[cfg(not(target_os = "linux"))]
use eyre::bail;
use eyre::{Report, eyre};
use tracing::warn;
/// Arguments for the serve command.
#[derive(Args, Debug, Clone, Default)]
pub struct ServeArgs {
  /// Proxy settings (CLI layer of the config overlay).
  #[command(flatten)]
  pub proxy: <ProxyCfg as Config>::Layer,
  // Deployment-mode switch: CLI + env only, deliberately not a file key —
  // both backends mutate host routes/nft rules and must be an explicit
  // intention, not ambient configuration.
  /// Capture traffic transparently with this backend, instead of only
  /// serving the explicit proxy alone.
  #[arg(long, env = "ARKHAM_PROXY_BACKEND", value_enum, default_value_t = ProxyBackend::None)]
  pub proxy_backend: ProxyBackend,
  /// Allow unscoped TPROXY rules in the current (host) network namespace.
  /// Without this, unscoped capture outside an isolated netns is refused:
  /// the rules reroute every outbound TCP packet, and an unclean exit
  /// leaves the machine without TCP egress until manually cleaned.
  #[arg(
    long,
    env = "ARKHAM_TPROXY_ALLOW_ROOT_NETNS",
    help = "allow unscoped TPROXY rules in the host network namespace (disposable machines only)"
  )]
  pub tproxy_allow_root_netns: bool,
  /// cgroup v2 directory whose member processes get captured by
  /// `--proxy-backend ebpf`. Required for that backend: there is deliberately
  /// no default, because defaulting to the root cgroup would capture every
  /// process on the machine. Without `enclosing`, arkham must live *outside* the
  /// named cgroup. The literal `enclosing` attaches to the cgroup this
  /// process's own cgroup lives under — what a stack that gives both services
  /// one `cgroup_parent` needs, since the daemon resolves that parent relative
  /// to its own cgroup root. arkham is a member of the attached subtree then,
  /// and the recorded proxy PID is what keeps its own sockets out of the loop.
  #[arg(long, env = "ARKHAM_EBPF_CGROUP")]
  pub ebpf_cgroup: Option<PathBuf>,
  /// File with runtime bypass CIDRs for the eBPF backend, one per line,
  /// re-read while capture runs. Podman networks are created inside the
  /// agent long after arkham starts, so the generated stack has the agent
  /// rewrite this file from `podman network inspect` and arkham applies it
  /// live. CLI/env only, like the other backend switches.
  #[arg(long, env = "ARKHAM_EBPF_BYPASS_FILE")]
  pub ebpf_bypass_file: Option<PathBuf>,
  /// Extra CIDRs the eBPF backend never captures (`10.89.0.0/16`), from the
  /// operator: podman ranges inside the agent, usually. Repeat or
  /// comma-separate; the loader always adds its own non-loopback addresses on
  /// top. CLI/env only, like the other backend switches — never a file key.
  #[cfg(target_os = "linux")]
  #[arg(long = "ebpf-bypass", env = "ARKHAM_EBPF_BYPASS", value_delimiter = ',', value_parser = arkham_ebpf::parse_bypass_cidr)]
  pub ebpf_bypass: Vec<(Ipv4Addr, u8)>,
}

impl CliCommand for ServeArgs {
  type Error = Report;
  /// Serves the proxy through the crate-root backend wiring.
  ///
  /// # Errors
  ///
  /// Returns whatever [`serve`](crate::serve) returns: bad backend flags, an
  /// unloadable config, an unbindable listener, a failed capture backend.
  async fn run(self, cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    serve(cli, self).await
  }
}

/// Arguments for [`Command::Fake`](crate::Command::Fake).
#[derive(Args, Debug, Clone)]
pub struct FakeArgs {
  /// Env var name the fake is derived from.
  pub env: String,
  /// Explicit fake pattern overriding the prefix default.
  #[arg(long)]
  pub pattern: Option<String>,
}

impl CliCommand for FakeArgs {
  type Error = Report;
  /// Prints the deterministic fake for the env var.
  ///
  /// # Errors
  ///
  /// Returns an error when the pattern is invalid, the registry or config
  /// does not load, or an allow entry does not parse.
  async fn run(self, cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    if let Some(pattern) = self.pattern.as_deref() {
      validate_pattern(pattern).map_err(|err| eyre!("bad --pattern: {err}"))?;
    }
    let registry = generation_registry()?;
    let (mut config, _) = load(cli, None)?;
    // Resolve the way `serve` does, so a `tcp://` rule previews the
    // length-matched decoy the proxy will actually use; fnox also supplies
    // the names derivation turns into rules, so it opens unconditionally.
    let fnox = FnoxSource::open()?;
    resolve(&mut config, &registry, fnox).await?;
    let rule = config.rules.values().find(|rule| rule.env == self.env);
    let Some(rule) = rule else {
      println!("{}", registry.decoy(&self.env, self.pattern.as_deref()));
      return Ok(());
    };
    let Some(value) = rule.value.as_ref() else {
      println!("{}", registry.decoy(&self.env, self.pattern.as_deref()));
      return Ok(());
    };
    let allow: Vec<EndpointScope> = rule
      .allow
      .iter()
      .map(|entry| entry.parse())
      .collect::<Result<_, _>>()
      .map_err(|err| eyre!("bad allow entry: {err}"))?;
    let (decoy, length_matched) = decoy_for_rule(
      &rule.env,
      rule.pattern.as_deref().or(self.pattern.as_deref()),
      &allow,
      ExposeSecret::expose_secret(value).len(),
    );
    if length_matched {
      eprintln!("# length-matched for a tcp:// allow entry; the registry shape rendered another length");
    }
    println!("{decoy}");
    Ok(())
  }
}

/// Arguments for [`Command::Schemes`](crate::Command::Schemes).
#[derive(Args, Debug, Clone, Copy)]
pub struct SchemesArgs;

impl CliCommand for SchemesArgs {
  type Error = Report;
  /// Prints each supported URL scheme, one per line.
  ///
  /// # Errors
  ///
  /// This command does not fail.
  fn run(self, _cli: &Cli, _arkham_version: &str) -> impl Future<Output = Result<(), Self::Error>> + Send {
    for scheme in Scheme::all() {
      println!("{}", scheme.as_str());
    }
    std::future::ready(Ok(()))
  }
}

/// Arguments for [`Command::Ca`](crate::Command::Ca).
#[derive(Args, Debug, Clone, Copy)]
pub struct CaArgs;

impl CliCommand for CaArgs {
  type Error = Report;
  /// Loads or generates the CA and prints its certificate PEM.
  ///
  /// # Errors
  ///
  /// Returns an error when the config or CA does not load.
  async fn run(self, cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    let cli = cli.clone();
    let (config, _) = tokio::task::spawn_blocking(move || load(&cli, None).map_err(Box::new))
      .await
      .map_err(|err| eyre!("config load task failed: {err}"))?
      .map_err(|err| eyre!("config load: {err}"))?;
    let ca = load_or_generate(&ca_path(&config.proxy)?)?;
    print!("{}", String::from_utf8_lossy(&ca.cert_pem()));
    Ok(())
  }
}

/// Arguments for [`Command::Rules`](crate::Command::Rules).
#[derive(Args, Debug, Clone, Copy)]
pub struct RulesArgs;

impl CliCommand for RulesArgs {
  type Error = Report;
  /// Prints what this workspace's proxy substitutes: derived rules, names
  /// still needing a host, and uncovered fnox declarations.
  ///
  /// # Errors
  ///
  /// Returns an error when the registry or fnox source does not open.
  async fn run(self, _cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    let rendered = tokio::task::spawn_blocking(|| rules_command(cwd_project_rules_dir().as_deref()))
      .await
      .map_err(|err| eyre!("rules task failed: {err}"))??;
    print!("{rendered}");
    Ok(())
  }
}

/// Arguments for the registry import commands.
#[derive(Args, Debug, Clone)]
pub struct ImportArgs {
  /// Path to the saved discovery or `OpenAPI` JSON document.
  pub file: PathBuf,
  /// Provider slug for the generated `[providers.<slug>]` entry.
  pub slug: String,
  /// Environment name the generated entry claims.
  pub env: String,
}

/// [`Command::Registry`](crate::Command::Registry) subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum RegistryCommand {
  /// Map an OIDC discovery document (`<issuer>/.well-known/openid-configuration`)
  /// onto one `[providers.<slug>.oauth2]` fragment. The flow comes from
  /// `grant_types_supported`.
  FromOidc(ImportArgs),
  /// Map an `OpenAPI` document's `components.securitySchemes` (`type: oauth2`)
  /// onto fragments, one per scheme. `openIdConnect` schemes are reported
  /// and skipped.
  FromOpenapi(ImportArgs),
}

#[derive(Args, Debug, Clone)]
pub struct RegistryArgs {
  /// Which document kind to import.
  #[command(subcommand)]
  pub command: RegistryCommand,
}

impl CliCommand for RegistryArgs {
  type Error = Report;
  /// Prints registry fragments curated from the document.
  ///
  /// # Errors
  ///
  /// Returns an error when the document cannot be read or parsed.
  async fn run(self, _cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    let import = match &self.command {
      RegistryCommand::FromOidc(import) | RegistryCommand::FromOpenapi(import) => import,
    };
    let doc = tokio::fs::read_to_string(&import.file)
      .await
      .map_err(|err| eyre!("read {}: {err}", import.file.display()))?;
    let flows = match &self.command {
      RegistryCommand::FromOidc(_) => {
        vec![(import.slug.clone(), flow_from_oidc(&doc).map_err(|err| err.to_string()))]
      }
      RegistryCommand::FromOpenapi(_) => flows_from_openapi(&doc)?,
    };
    for (slug, flow) in flows {
      match flow {
        Ok(flow) => print!("{}", to_toml_fragment(&slug, &import.env, &flow)?),
        Err(reason) => warn!(scheme = %slug, reason, "skipped security scheme"),
      }
    }
    Ok(())
  }
}

/// Arguments for the `arkham config` reference dump.
#[derive(Args, Debug, Clone, Copy)]
pub struct ConfigArgs;

impl CliCommand for ConfigArgs {
  type Error = Report;
  /// Prints a reference config: every setting, its default, and the doc
  /// comment explaining it, so undiscovered settings surface here first.
  ///
  /// # Errors
  ///
  /// Returns an error when the config does not load.
  async fn run(self, cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    let cli = cli.clone();
    tokio::task::spawn_blocking(move || load(&cli, None).map_err(Box::new))
      .await
      .map_err(|err| eyre!("config load task failed: {err}"))?
      .map_err(|err| eyre!("config load: {err}"))?;
    print!(
      "{}{}",
      confique::toml::template::<AppConfig>(FormatOptions::default()),
      reference_samples().map_err(Report::from)?
    );
    Ok(())
  }
}

#[derive(Args, Debug, Clone, Copy)]
pub struct FwdArgs;

impl CliCommand for FwdArgs {
  type Error = Report;
  /// Runs the loopback exposure sidecar.
  ///
  /// # Errors
  ///
  /// Returns an error on non-Linux hosts, or whatever the sidecar returns.
  async fn run(self, _cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    #[cfg(not(target_os = "linux"))]
    bail!("arkham fwd reads /proc/net/tcp and exists on Linux only");
    #[cfg(target_os = "linux")]
    fwd::run().await
  }
}

/// Arguments for the host daemon.
#[derive(Args, Debug, Clone, Default)]
pub struct DaemonArgs;

impl CliCommand for DaemonArgs {
  type Error = Report;
  /// Serves the shared host proxy and the control socket.
  ///
  /// # Errors
  ///
  /// Returns an error on non-Linux hosts, when the listen address is not
  /// loopback, or when the daemon cannot bind its socket.
  async fn run(self, _cli: &Cli, arkham_version: &str) -> Result<(), Self::Error> {
    #[cfg(not(target_os = "linux"))]
    {
      let _ = (self, arkham_version);
      bail!("the host daemon runs on Linux");
    }
    #[cfg(target_os = "linux")]
    crate::host::run(arkham_version).await
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::ffi::OsString;

  use clap::Parser as _;

  use crate::{ArkhamCli, Command};

  #[test]
  fn agent_takes_a_command_after_the_separator_and_no_workspace() {
    let cli = ArkhamCli::try_parse_from(["arkham", "agent", "--", "claude", "--resume"]).unwrap();
    match cli.command {
      Some(Command::Agent(args)) => {
        assert_eq!(args.workspace, None);
        assert_eq!(args.command, vec![OsString::from("claude"), OsString::from("--resume")]);
      }
      other => panic!("expected agent, got {other:?}"),
    }
  }

  #[test]
  fn agent_defaults_to_the_configured_shell_without_a_command() {
    let cli = ArkhamCli::try_parse_from(["arkham", "agent", "/srv/project"]).unwrap();
    match cli.command {
      Some(Command::Agent(args)) => {
        assert_eq!(args.workspace, Some(PathBuf::from("/srv/project")));
        assert_eq!(args.command, [] as [std::ffi::OsString; 0]);
      }
      other => panic!("expected agent, got {other:?}"),
    }
  }

  #[test]
  fn init_takes_the_backend_flag_and_the_workspace() {
    let cli = ArkhamCli::try_parse_from(["arkham", "init", "--backend", "tproxy", "/srv/project"]).unwrap();
    match cli.command {
      Some(Command::Init(args)) => {
        assert_eq!(args.backend, Some(ProxyBackend::Tproxy));
        assert_eq!(args.workspace, Some(PathBuf::from("/srv/project")));
      }
      other => panic!("expected init, got {other:?}"),
    }
    let cli = ArkhamCli::try_parse_from(["arkham", "init"]).unwrap();
    match cli.command {
      Some(Command::Init(args)) => assert_eq!(args.backend, None, "the OS default resolves later"),
      other => panic!("expected init, got {other:?}"),
    }
    ArkhamCli::try_parse_from(["arkham", "init", "--backend", "sideways"]).unwrap_err();
  }

  #[test]
  fn agent_rm_is_off_until_asked_for() {
    let cli = ArkhamCli::try_parse_from(["arkham", "agent", "--rm", "--", "claude"]).unwrap();
    match cli.command {
      Some(Command::Agent(args)) => {
        assert!(args.rm, "--rm stops the stack on exit");
        assert_eq!(args.command, vec![OsString::from("claude")]);
      }
      other => panic!("expected agent, got {other:?}"),
    }

    let cli = ArkhamCli::try_parse_from(["arkham", "agent"]).unwrap();
    match cli.command {
      Some(Command::Agent(args)) => assert!(!args.rm, "the stack outlives the agent by default"),
      other => panic!("expected agent, got {other:?}"),
    }
  }

  #[test]
  fn the_stack_commands_take_the_workspace_positional() {
    for argv in [vec!["arkham", "up"], vec!["arkham", "down"]] {
      let cli = ArkhamCli::try_parse_from(&argv).unwrap();
      let workspace = match cli.command {
        Some(Command::Up(args)) => args.workspace,
        Some(Command::Down(args)) => args.workspace,
        other => panic!("expected a stack command for {argv:?}, got {other:?}"),
      };
      assert_eq!(workspace, None, "absent means the current directory");
    }

    let cli = ArkhamCli::try_parse_from(["arkham", "up", "/srv/project"]).unwrap();
    match cli.command {
      Some(Command::Up(args)) => assert_eq!(args.workspace, Some(PathBuf::from("/srv/project"))),
      other => panic!("expected up, got {other:?}"),
    }
  }

  #[test]
  fn logs_takes_its_flags_service_names_and_workspace() {
    let cli = ArkhamCli::try_parse_from([
      "arkham",
      "logs",
      "--follow",
      "--no-log-prefix",
      "--tail",
      "50",
      "--workspace",
      "/srv/project",
      "arkham",
      "agent",
    ])
    .unwrap();
    match cli.command {
      Some(Command::Logs(logs)) => {
        assert!(logs.follow && logs.no_log_prefix);
        assert_eq!(logs.tail, "50");
        assert_eq!(logs.workspace, Some(PathBuf::from("/srv/project")));
        assert_eq!(logs.services, vec!["arkham", "agent"], "one or more services, all by default");
      }
      other => panic!("expected logs, got {other:?}"),
    }

    let cli = ArkhamCli::try_parse_from(["arkham", "logs"]).unwrap();
    match cli.command {
      Some(Command::Logs(logs)) => {
        assert!(!logs.follow && !logs.no_log_prefix);
        assert_eq!(logs.tail, "all", "the tail default is everything");
        assert_eq!(logs.workspace, None, "absent means the current directory");
        assert!(logs.services.is_empty(), "no services means all of them");
      }
      other => panic!("expected logs, got {other:?}"),
    }
  }
}
