//! Compose stack generation: mount resolution, rewrites, and YAML.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use arkham_config::cli::ProxyBackend;
use arkham_config::config::{AppConfig, ExposeMap, config_dir, project_profiles_dir};
use arkham_config::grants::GuestTlsMode;
use dirs::home_dir;
use libc::getuid;
use xpanda::Xpanda;

use crate::adapt::{self, GRANTS_STATE_DIR, RewriteAdapted, load_guest_ca};
use crate::ambient::{DeriveInputs, derive_sources};
use crate::decoys::{Decoy, Selection, validate_passthrough};
use crate::error::Error;
use crate::expand::{build_expander, expand_path, expand_value, resolution_env};
use crate::mounts::{BYPASS_CONTAINER_PATH, FnoxBinds, Layout};
use crate::paths::{Mount, translate};
use crate::profiles::{ProfileRoots, profile_mounts};
use crate::rewrites::{RewriteInputs, write_rewrites};
use crate::workspace::Workspace;

/// Fixed port the generated stack renders as `ARKHAM_LISTEN` instead of the
/// `127.0.0.1:8080` default: the explicit proxy is loopback-bound in the
/// shared netns, and 8080 is the port dev servers default to — squatted on.
pub(crate) const EXPLICIT_LISTEN: &str = "127.0.0.1:8099";

/// Builder of the generated [`Stack`]: owns the resolved workspace context
/// and every intermediate the steps produce, and each method resolves one
/// concern, in the order the story reads — resolve the context, select the
/// secrets, rewrite the declared files, derive the ambient sources, write
/// the grants, mount the tool profiles, mint the guest identities, then
/// assemble the agent and the stack. [`generate_stack`] is that chain.
struct StackBuilder<'a> {
  /// Mount layout: root, container home, and host home every mount resolves
  /// against.
  layout: Layout,
  /// Secret selection: fnox discovery joined against the registry.
  selection: Selection,
  /// Capture backend the serve command runs.
  backend: ProxyBackend,
  /// Arkham image tag: the binary's version, threaded from the face.
  version: &'a str,
  /// The workspace's merged config.
  config: AppConfig,
  /// Expansion environment: the process env plus fnox-resolved names.
  env: HashMap<String, String>,
  /// Xpanda expander built over `env`.
  expander: Xpanda,
  /// Compose project name: the configured name or the workspace slug.
  project: String,
  /// Include-derived mounts, deepest path first.
  mounts: Vec<Mount>,
  /// Decoys for the agent environment, from [`StackBuilder::secrets`].
  decoys: Vec<Decoy>,
  /// Adapter grants from [`StackBuilder::rewrites`] and
  /// [`StackBuilder::ambient`], written by [`StackBuilder::grants`].
  grants: Vec<RewriteAdapted>,
  /// Rewritten-file mounts, from [`StackBuilder::rewrites`] and
  /// [`StackBuilder::ambient`].
  file_mounts: Vec<Mount>,
  /// Grant-layer mounts, from [`StackBuilder::grants`].
  grants_mounts: Vec<Mount>,
  /// Tool-profile mounts, from [`StackBuilder::profiles`].
  tool_mounts: Vec<Mount>,
  /// Guest-identity mounts, from [`StackBuilder::guest_identities`].
  guest: Vec<Mount>,
}

impl<'a> StackBuilder<'a> {
  /// Resolve the workspace context every step shares: the merged config, the
  /// registry, fnox, the expansion environment, the include mounts, and the
  /// project name.
  ///
  /// # Errors
  ///
  /// Returns an error when the registry or config fails to load, when value
  /// resolution fails, or when a path fails to expand.
  async fn resolve(root: &'a Path, backend: ProxyBackend, version: &'a str) -> Result<Self, Error> {
    let workspace = Workspace::new(root);
    let config = workspace.config()?;
    let selection = workspace.selection()?;
    let raw_home = config.workspace.container_home().to_string();
    let referenced = config.workspace.referenced_variables(&[raw_home.as_str()]);
    let env = resolution_env(&selection.registry, selection.fnox.as_ref(), &referenced).await?;
    let expander = build_expander(env.clone());
    let home = expand_value(&expander, &raw_home)?;
    let layout = Layout::new(root, home, home_dir());
    let includes: Vec<PathBuf> = config
      .workspace
      .include
      .iter()
      .map(|entry| expand_path(&expander, &entry.to_string_lossy()).map(PathBuf::from))
      .collect::<Result<_, Error>>()?;
    let mounts = layout.include_mounts(&includes)?;
    let project = config.workspace.name.clone().unwrap_or_else(|| workspace.slug());
    Ok(Self {
      layout,
      selection,
      backend,
      version,
      config,
      env,
      expander,
      project,
      mounts,
      decoys: Vec::new(),
      grants: Vec::new(),
      file_mounts: Vec::new(),
      grants_mounts: Vec::new(),
      tool_mounts: Vec::new(),
      guest: Vec::new(),
    })
  }

  /// Select the decoys the agent environment holds, reshaped by each rule's
  /// own pattern — serve-time substitution derives its fake from
  /// `rule.pattern`, so a registry default would never match — and check the
  /// passthrough names against them.
  ///
  /// # Errors
  ///
  /// Returns an error when a passthrough name overlaps a rule env or a
  /// selected decoy.
  fn secrets(mut self) -> Result<Self, Error> {
    self.decoys = self.selection.apply_rule_patterns(self.selection.select(), &self.config.rules);
    validate_passthrough(&self.config.rules, &self.decoys, &self.config.workspace.passthrough)?;
    Ok(self)
  }

  /// The declared `[workspace] file_rewrite` entries: decoy twins written
  /// under the state directory and mounted read-only into the agent, plus
  /// the grants their adapters derive.
  ///
  /// # Errors
  ///
  /// Returns an error when a rewrite names an env with no known value or no
  /// decoy, or its dest does not expand to an absolute container path.
  fn rewrites(mut self) -> Result<Self, Error> {
    let files_dir = self.layout.files_dir();
    let guests_dir = self.layout.guests_dir();
    let rewritten = write_rewrites(&RewriteInputs {
      files_dir: &files_dir,
      root: self.layout.root(),
      rewrites: &self.config.workspace.file_rewrite,
      decoys: &self.decoys,
      env: &self.env,
      expander: &self.expander,
      home: self.layout.home(),
      host_home: self.layout.host_home(),
      guests_dir: &guests_dir,
    })?;
    self.grants = rewritten.grants;
    self.file_mounts = rewritten.mounts;
    Ok(self)
  }

  /// The ambient sources — gitconfig, jj, ssh, nats, kube, talos from their
  /// default locations: decoy twins mounted read-only plus the grants they
  /// derive, joined onto the declared rewrites.
  ///
  /// # Errors
  ///
  /// Returns an error when a source does not map onto grants or a decoy
  /// twin.
  fn ambient(mut self) -> Result<Self, Error> {
    let files_dir = self.layout.files_dir();
    let guests_dir = self.layout.guests_dir();
    let derived = derive_sources(&DeriveInputs {
      files_dir: &files_dir,
      root: self.layout.root(),
      registry: &self.selection.registry,
      decoys: &self.decoys,
      expander: &self.expander,
      home: self.layout.home(),
      host_home: self.layout.host_home(),
      guests_dir: &guests_dir,
      rewrites: &self.config.workspace.file_rewrite,
    })?;
    self.grants.extend(derived.grants);
    self.file_mounts.extend(derived.mounts);
    Ok(self)
  }

  /// Write the grant-adapter state the arkham service mounts read-only: no
  /// grants, no state, no mount.
  ///
  /// # Errors
  ///
  /// Returns an error when the state cannot be written.
  fn grants(mut self) -> Result<Self, Error> {
    if !self.grants.is_empty() {
      let grants_state = self.layout.state_dir().join("grants");
      adapt::write_state(&grants_state, &self.grants)?;
      self.grants_mounts = vec![Mount {
        host: grants_state,
        container: PathBuf::from(GRANTS_STATE_DIR),
        ro: true,
      }];
    }
    Ok(self)
  }

  /// The tool-config mounts for the selected profile.
  ///
  /// # Errors
  ///
  /// Returns an error when a `[tools.*]` name or `config_dir` is invalid, or
  /// a profile directory cannot be created.
  fn profiles(mut self) -> Result<Self, Error> {
    let global_profiles = config_dir().map(|dir| dir.join("profiles"));
    let project_profiles = project_profiles_dir(self.layout.root());
    let roots = ProfileRoots {
      project: Some(project_profiles.as_path()),
      global: global_profiles.as_deref(),
    };
    self.tool_mounts = profile_mounts(&roots, self.config.workspace.profile_name(), &self.config.tools, self.layout.home())?;
    Ok(self)
  }

  /// Guest identity pairs for rules that request mTLS, minted from the CA
  /// and mounted read-only at their declared container paths; none when no
  /// rule requests one.
  ///
  /// # Errors
  ///
  /// Returns an error when the config directory does not resolve, the CA
  /// cannot load, or a pair cannot be written.
  fn guest_identities(mut self) -> Result<Self, Error> {
    let mtls = self
      .config
      .rules
      .values()
      .any(|rule| rule.tls.values().any(|tls| tls.guest_tls_mode == GuestTlsMode::Mtls));
    if mtls {
      let ca = load_guest_ca("a guest identity needs the arkham config directory to load the CA from")?;
      let guests_dir = self.layout.guests_dir();
      self.guest = self.layout.guest_identity_mounts(&self.config.rules, &ca, &guests_dir)?;
    }
    Ok(self)
  }

  /// The agent service and the finished stack: the translated root, the
  /// resolved image or build, the fnox mounts, and the backend's bypass
  /// mount.
  ///
  /// # Errors
  ///
  /// Returns an error when the configured build does not resolve or names an
  /// empty image tag.
  fn stack(self) -> Result<Stack, Error> {
    let build_paths: Option<(PathBuf, PathBuf)> = self
      .config
      .workspace
      .build
      .as_ref()
      .map(|build| self.layout.resolve_build(build))
      .transpose()?;
    let agent = AgentSpec {
      root: translate(self.layout.root(), self.layout.host_home(), self.layout.home()),
      home: self.layout.home().to_string(),
      storage: self.layout.state_dir().join("containers"),
      uid: current_uid(),
      devices: self.config.workspace.devices.clone(),
      cap_add: self.config.workspace.cap_add.clone(),
      image: AgentSpec::image(&self.project, self.config.workspace.image.as_deref(), build_paths.is_some())?,
      build: build_paths.map(|(context, dockerfile)| AgentBuild { context, dockerfile }),
    };
    // The runtime bypass file both services share: the agent entrypoint
    // rewrites it from `podman network inspect`, arkham reloads it live into
    // the programs' bypass list. Ebpf only — other backends have no bypass
    // list to feed.
    let mut mounts = self.mounts;
    if self.backend == ProxyBackend::Ebpf {
      mounts.push(self.layout.bypass_mount());
    }
    Ok(Stack {
      backend: self.backend,
      project: self.project,
      decoys: self.decoys,
      agent,
      mounts,
      tool_mounts: self.tool_mounts,
      fnox: FnoxBinds::resolve(self.layout.fnox_config_dir().as_deref(), config_dir().as_deref()),
      guest: self.guest,
      init: self.config.workspace.init.clone(),
      ports: self.config.workspace.ports.clone(),
      expose: self.config.workspace.expose.clone(),
      networks: self.config.workspace.networks.clone(),
      extra_hosts: self.config.workspace.extra_hosts.clone(),
      passthrough: self.config.workspace.passthrough.clone(),
      file_mounts: self.file_mounts,
      grants_mounts: self.grants_mounts,
      arkham_version: self.version.to_string(),
    })
  }
}

/// The compose file for a workspace: resolve the context, run the build
/// steps, render.
///
/// # Errors
///
/// Returns whatever step fails: config or registry loading, value
/// resolution, rewrites, ambient derivation, grant state, profiles, guest
/// identities, or the agent build.
pub(crate) async fn generate_stack(root: &Path, backend: ProxyBackend, arkham_version: &str) -> Result<String, Error> {
  let stack = StackBuilder::resolve(root, backend, arkham_version)
    .await?
    .secrets()?
    .rewrites()?
    .ambient()?
    .grants()?
    .profiles()?
    .guest_identities()?
    .stack()?;
  Ok(stack.render())
}

/// The process's user id, from the kernel: the same value `id -u` prints,
/// without the subprocess.
pub(crate) fn current_uid() -> u32 {
  // Safety: `getuid` takes no arguments, cannot fail, and touches no memory.
  unsafe { getuid() }
}

/// What the generated agent service is built from: container-side paths and
/// the host directory mounted as the inner runtime's storage.
pub(crate) struct AgentSpec {
  /// Workspace root, translated into the agent container.
  pub(crate) root: PathBuf,
  /// The agent user's home directory in the container.
  pub(crate) home: String,
  /// Host directory mounted at `{home}/.local/share/containers`.
  pub(crate) storage: PathBuf,
  /// Host uid baked as the agent user: mounts the agent writes must be its own.
  pub(crate) uid: u32,
  /// Extra devices from `[workspace] devices`, appended to `/dev/net/tun`.
  pub(crate) devices: Vec<String>,
  /// Extra capabilities from `[workspace] cap_add`, appended to the built-in
  /// set.
  pub(crate) cap_add: Vec<String>,
  /// Image tag the agent service runs: configured, derived, or default.
  pub(crate) image: String,
  /// Dockerfile build from `[workspace.build]`, when one builds the image.
  pub(crate) build: Option<AgentBuild>,
}

/// Default agent image, when `[workspace] image` is unset and no
/// `[workspace.build]` builds one.
pub(crate) const DEFAULT_AGENT_IMAGE: &str = "ghcr.io/casualjim/devagent:26.04";

/// Resolved Dockerfile build for the agent service: absolute host paths for
/// compose, which sends the context to the daemon itself.
pub(crate) struct AgentBuild {
  /// Build context directory.
  pub(crate) context: PathBuf,
  /// Dockerfile to build.
  pub(crate) dockerfile: PathBuf,
}

impl AgentSpec {
  /// Image tag the agent service runs: the configured `image`, a local tag
  /// derived from the project when `[workspace.build]` builds one unnamed, or
  /// the default pull. An empty `image` is a config error, not a silent
  /// default: compose would fail on the empty tag without naming the setting.
  pub(crate) fn image(project: &str, image: Option<&str>, has_build: bool) -> Result<String, Error> {
    match image {
      Some(name) if !name.is_empty() => Ok(name.to_string()),
      Some(_) => Err(Error::EmptyImage),
      None if has_build => Ok(format!("arkham-agent-{}:local", project.to_lowercase())),
      None => Ok(DEFAULT_AGENT_IMAGE.to_string()),
    }
  }
}

/// A stack to generate: every input compose rendering reads, as one value.
/// [`StackBuilder`] fills it from a workspace; tests build it literally.
pub(crate) struct Stack {
  pub(crate) backend: ProxyBackend,
  pub(crate) project: String,
  pub(crate) decoys: Vec<Decoy>,
  pub(crate) agent: AgentSpec,
  pub(crate) mounts: Vec<Mount>,
  pub(crate) tool_mounts: Vec<Mount>,
  pub(crate) fnox: FnoxBinds,
  pub(crate) guest: Vec<Mount>,
  pub(crate) init: Option<String>,
  /// Ports the arkham service publishes as stable host `127.0.0.1` bindings,
  /// from `[workspace] ports`.
  pub(crate) ports: Vec<u16>,
  /// Host-to-container publishings from `[[workspace.expose]]`: each maps a
  /// distinct host port onto a container port.
  pub(crate) expose: Vec<ExposeMap>,
  /// Existing compose networks the arkham service joins (declared `external`
  /// at the top level), from `[workspace] networks`. The agent inherits them
  /// through the shared network namespace.
  pub(crate) networks: Vec<String>,
  /// Extra host entries for the arkham and agent services, from
  /// `[workspace] extra_hosts`.
  pub(crate) extra_hosts: Vec<String>,
  /// Env names forwarded as `${NAME}` interpolation in the agent
  /// environment, from `[workspace] passthrough`.
  pub(crate) passthrough: Vec<String>,
  /// Rewritten files mounted read-only at their dests, from
  /// `[workspace] file_rewrite`; after workspace mounts so they win.
  pub(crate) file_mounts: Vec<Mount>,
  /// Upstream identity files adapter grants materialize: mounted into the
  /// arkham service at their absolute paths, so host and container serve
  /// resolve the same fragment entries. Never into the agent: real secrets
  /// stay out.
  pub(crate) grants_mounts: Vec<Mount>,
  /// Arkham image tag: the binary's version, threaded from the binary crate.
  /// Library crates version independently, so `env!` here would lie.
  pub(crate) arkham_version: String,
}

impl Stack {
  /// What the arkham service runs for a capture backend, the extra
  /// capabilities that needs, and the service keys that go with it.
  fn backend_service(backend: ProxyBackend, project: &str) -> (String, &'static [&'static str], String) {
    match backend {
      ProxyBackend::Ebpf => (
        "[\"serve\", \"--proxy-backend\", \"ebpf\", \"--ebpf-cgroup\", \"enclosing\"]".to_string(),
        &["BPF", "PERFMON"],
        // Both services carry the same `cgroup_parent`, so docker creates that
        // cgroup as part of arkham's own start and arkham attaches to it by
        // resolving its parent from `/proc/self/cgroup`: the daemon resolves the
        // parent relative to its own cgroup root, which is why no host path is
        // written down here.
        format!("    cgroup: host\n    cgroup_parent: arkham-{project}.slice\n"),
      ),
      ProxyBackend::Tun => (
        "[\"serve\", \"--proxy-backend\", \"tun\"]".to_string(),
        &[],
        "    devices: [/dev/net/tun]\n".to_string(),
      ),
      ProxyBackend::Tproxy => ("[\"serve\", \"--proxy-backend\", \"tproxy\"]".to_string(), &[], String::new()),
      // `arkham init` rejects `none`; rendered anyway so this match is exhaustive.
      ProxyBackend::None => ("[\"serve\"]".to_string(), &[], String::new()),
    }
  }

  /// The compose file this stack renders to.
  pub(crate) fn render(&self) -> String {
    let (serve, extra_caps, service_extra) = Self::backend_service(self.backend, &self.project);
    let mut out = String::new();
    let _ = write!(
      out,
      "# generated by `arkham init`. This file is generated state.\n\
       # Overrides: ~/.config/arkham/compose.yaml or <workspace>/.config/arkham/compose.yaml.\n\
       # arkham merges config like always\n\
       # (global layer plus this workspace's .config/arkham/config.toml, discovered\n\
       # from its working directory, plus the generated tool-config grant layer\n\
       # when a rewrite adapts one); the agent holds decoys only.\n\
       name: {project}\n\
       services:\n\
       \x20 arkham:\n\
       \x20   image: ghcr.io/lotsaai/arkham:{version}\n\
       \x20   working_dir: \"{root}\"\n\
      \x20   command: {serve}\n\
       {service_extra}\
      \x20   # Capture dies with this process: the eBPF attachments are fd-held\n\
      \x20   # and the listeners live in it, so a crash would silently end all\n\
      \x20   # capture until the next `up`. Restart instead, loudly — the\n\
      \x20   # restart count in `compose ps` is what makes flapping visible.\n\
      \x20   restart: unless-stopped\n\
      \x20   environment:\n\
      \x20     RUST_LOG: info\n\
       \x20     # 8080 must stay free on loopback: agent dev servers default\n\
       \x20     # to it, and the explicit proxy's default bind would squat on\n\
       \x20     # 127.0.0.1:8080, leaving the fwd sidecar nothing to expose.\n\
       \x20     ARKHAM_LISTEN: {listen}\n",
      root = self.agent.root.display(),
      project = self.project,
      listen = EXPLICIT_LISTEN,
      version = self.arkham_version,
    );
    if self.backend == ProxyBackend::Ebpf {
      // The runtime bypass file, rewritten by the agent entrypoint from
      // `podman network inspect` and reloaded live by the loader: podman
      // networks are created inside the agent after arkham starts, so no
      // startup flag can name them.
      let _ = writeln!(out, "      ARKHAM_EBPF_BYPASS_FILE: {BYPASS_CONTAINER_PATH}");
    }
    out.push_str(
      "    cap_add:\n\
       \x20     - NET_ADMIN\n",
    );
    for cap in extra_caps {
      let _ = writeln!(out, "      - {cap}");
    }
    if !self.ports.is_empty() || !self.expose.is_empty() {
      out.push_str("    ports:\n");
      for port in &self.ports {
        // Same port both sides: the fwd sidecar holds the netns's own bridge
        // address for each exposed agent listener, and a stable host binding
        // names it instead of the changing bridge IP. Fixed at create:
        // applying a change takes a restart.
        let _ = writeln!(out, "      - \"127.0.0.1:{port}:{port}\"");
      }
      for map in &self.expose {
        // Distinct host port onto a container port: the `arkham expose`
        // allocation so workspaces sharing one host never bind the same host
        // port twice. Same restart rule as `ports`.
        let _ = writeln!(out, "      - \"127.0.0.1:{}:{}\"", map.host, map.port);
      }
    }
    // `/etc/hosts` is per container, so the agent service renders the same
    // block: the agent resolves the name, arkham dials the upstream.
    // `host.docker.internal` always points at the host gateway — generation
    // is Linux-only, so no platform branch; an explicitly stated gateway is
    // not repeated.
    out.push_str("    extra_hosts:\n");
    for entry in self.effective_extra_hosts() {
      let _ = writeln!(out, "      - \"{entry}\"");
    }
    if !self.networks.is_empty() {
      // The agent rides this service's network namespace, so it inherits
      // every network joined here — including DNS for their containers.
      out.push_str("    networks:\n");
      for network in &self.networks {
        let _ = writeln!(out, "      - \"{network}\"");
      }
    }
    out.push_str(
      "    stop_grace_period: 1s\n\
       \x20   volumes:\n",
    );
    for mount in &self.mounts {
      let mode = if mount.ro { "ro" } else { "rw" };
      let _ = writeln!(out, "      - {}:{}:{mode}", mount.host.display(), mount.container.display());
    }
    let _ = writeln!(
      out,
      "      - {}:/certs/ca.pem",
      config_dir()
        .unwrap_or_else(|| Path::new("~/.config/arkham").to_path_buf())
        .join("ca.pem")
        .display()
    );
    for mount in &self.fnox.mounts {
      let _ = writeln!(out, "      - {}:{}:ro", mount.host.display(), mount.container.display());
    }
    for mount in &self.grants_mounts {
      let _ = writeln!(out, "      - {}:{}:ro", mount.host.display(), mount.container.display());
      // The grant layer is the container's global config, mounted at the
      // standard path rather than named by ARKHAM_CONFIG: config discovery
      // derives `rules.d` from the config file's directory, so the env would
      // point that at /arkham/grants and hide the host's global rules.d mount.
      let _ = writeln!(
        out,
        "      - {}:/root/.config/arkham/config.toml:ro",
        mount.host.join("arkham.toml").display()
      );
    }
    out.push_str(&self.agent_service());
    out.push_str(&self.fwd_service());
    if !self.networks.is_empty() {
      // Joined networks are existing ones (a sidecar's project network, e.g.
      // headroom's): arkham creates none of them, so every one is external.
      out.push_str("networks:\n");
      for network in &self.networks {
        let _ = writeln!(out, "  \"{network}\":\n    external: true");
      }
    }
    out
  }
  /// Host entries both services render: `host.docker.internal` always points
  /// at the host gateway, then the configured extras. An explicitly stated
  /// gateway (either separator) is not repeated.
  fn effective_extra_hosts(&self) -> Vec<&str> {
    let mut hosts = vec!["host.docker.internal:host-gateway"];
    for entry in &self.extra_hosts {
      let stated_gateway = entry
        .split_once([':', '='])
        .is_some_and(|(host, target)| host.trim() == "host.docker.internal" && target.trim() == "host-gateway");
      if !stated_gateway {
        hosts.push(entry);
      }
    }
    hosts
  }

  /// The agent service: it shares arkham's network namespace and holds decoys
  /// only, plus the backend's cgroup placement when the capture needs one. The
  /// hooks only capture processes inside the cgroup they attach to, so this
  /// service lands in it and arkham stays outside.
  fn agent_service(&self) -> String {
    let cgroup = match self.backend {
      ProxyBackend::Ebpf => format!(
        "    # Both services sit in this cgroup and arkham attaches to it: the hooks\n\
       \x20   # capture what is inside, and arkham's own sockets are skipped by\n\
       \x20   # the recorded proxy PID.\n\
       \x20   cgroup_parent: arkham-{}.slice\n",
        self.project
      ),
      ProxyBackend::Tun | ProxyBackend::Tproxy | ProxyBackend::None => String::new(),
    };
    let caps = std::iter::once("SYS_CHROOT")
      .chain(["AUDIT_WRITE", "NET_ADMIN", "SETUID", "SETGID", "SYS_ADMIN"])
      .chain(self.agent.cap_add.iter().map(String::as_str))
      .collect::<Vec<_>>()
      .join(", ");
    let devices = std::iter::once("/dev/net/tun")
      .chain(self.agent.devices.iter().map(String::as_str))
      .collect::<Vec<_>>()
      .join(", ");
    let build = self
      .agent
      .build
      .as_ref()
      .map(|build| {
        format!(
          "    build:\n      context: {}\n      dockerfile: {}\n",
          build.context.display(),
          build.dockerfile.display()
        )
      })
      .unwrap_or_default();
    let mut out = String::new();
    let _ = write!(
      out,
      "\n\
     \x20 agent:\n\
     \x20   image: {image}\n\
      {build}\
     \x20   # The agent runs containers of its own, which is what the widened\n\
     \x20   # privileges are for: inner containers mount, chroot and raise their\n\
     \x20   # own networking, so seccomp/systempaths/apparmor are unconfined and\n\
     \x20   # SYS_ADMIN is granted. apparmor=unconfined is what Ubuntu's default\n\
     \x20   # profile requires and is inert where AppArmor is not loaded.\n\
     \x20   # systempaths=unconfined is podman-only: drop it under docker.\n\
     \x20   security_opt: [seccomp=unconfined, systempaths=unconfined, apparmor=unconfined]\n\
     \x20   cap_add: [{caps}]\n\
     \x20   devices: [{devices}]\n\
     {cgroup}\
     \x20   # docker-init (tini) as pid 1: signal handling and child reaping\n\
     \x20   # for the long-running shells this container hosts\n\
     \x20   init: true\n\
     \x20   user: \"{uid}\"\n\
     \x20   working_dir: \"{root}\"\n\
     \x20   entrypoint: [\"{home}/.config/arkham/agent-entrypoint.sh\"]\n\
     \x20   command: [\"sleep\", \"infinity\"]\n\
     \x20   environment:\n\
     \x20     # The entrypoint installs the CA into the system store. Node and\n\
     \x20     # Python's requests read their own bundle, so point them at it.\n\
     \x20     NODE_EXTRA_CA_CERTS: /etc/ssl/certs/ca-certificates.crt\n\
     \x20     REQUESTS_CA_BUNDLE: /etc/ssl/certs/ca-certificates.crt\n\
     \x20     # decoys — one per declared rule, swapped by arkham on grant match\n",
      root = self.agent.root.display(),
      home = self.agent.home,
      uid = self.agent.uid,
      image = self.agent.image,
      build = build,
    );
    self.agent_service_tail(&mut out);
    out
  }

  /// The agent service's environment and volumes: init chain, decoys,
  /// passthrough interpolation, and every mount layer with the entrypoint,
  /// CA, and inner container storage last.
  fn agent_service_tail(&self, out: &mut String) {
    if self.backend == ProxyBackend::Ebpf {
      // Where the entrypoint publishes podman subnets for arkham's bypass
      // list; the entrypoint only activates when this is set.
      let _ = writeln!(out, "      ARKHAM_EBPF_BYPASS_FILE: {BYPASS_CONTAINER_PATH}");
    }
    if let Some(init) = &self.init {
      let _ = writeln!(out, "      ARKHAM_INIT: \"{init}\"");
    }
    for decoy in &self.decoys {
      let _ = writeln!(out, "      {}: \"{}\"", decoy.env, decoy.value);
    }
    if !self.passthrough.is_empty() {
      out.push_str("      # passthrough — compose interpolates these from the host at `up`, never baked\n");
    }
    for name in &self.passthrough {
      // Single `$`: compose substitutes the host value when the stack starts,
      // so the file holds no secret and values stay fresh without regenerating.
      let _ = writeln!(out, "      {name}: \"${{{name}}}\"");
    }
    // No `extra_hosts` here: the daemon rejects custom host-to-IP mappings
    // on a service joined by `network_mode`. The arkham service owns the
    // namespace and its mappings; the agent shares that namespace.
    out.push_str("    volumes:\n");
    for mount in self
      .mounts
      .iter()
      .chain(&self.file_mounts)
      .chain(&self.tool_mounts)
      .chain(&self.guest)
    {
      let mode = if mount.ro { "ro" } else { "rw" };
      let _ = writeln!(out, "      - {}:{}:{mode}", mount.host.display(), mount.container.display());
    }
    let cfg_dir = config_dir();
    let entrypoint_host = cfg_dir
      .as_deref()
      .unwrap_or_else(|| Path::new("~/.config/arkham"))
      .join("agent-entrypoint.sh");
    let ca_crt_host = cfg_dir.as_deref().unwrap_or_else(|| Path::new("~/.config/arkham")).join("ca.crt");
    let _ = write!(
      out,
      "      - {}:{home}/.config/arkham/agent-entrypoint.sh:ro\n\
     \x20     - {}:/usr/local/share/ca-certificates/arkham-ca.crt:ro\n\
     \x20     # Inner container storage. Made at generation time under this\n\
     \x20     # workspace's state directory, owned by the user that runs the\n\
     \x20     # agent: a bind source the runtime creates itself is root-owned,\n\
     \x20     # and podman inside then dies without a word. A named volume needs\n\
     \x20     # the same ownership once, by hand.\n\
     \x20     - {storage}:{home}/.local/share/containers\n\
     \x20   network_mode: \"service:arkham\"\n",
      entrypoint_host.display(),
      ca_crt_host.display(),
      home = self.agent.home,
      storage = self.agent.storage.display()
    );
  }
  /// The exposure sidecar: arkham's netns to see every listener of the shared
  /// namespace, the agent's PID namespace so only agent-owned processes can
  /// ever be attributed a listener — arkham's capture and explicit-proxy
  /// listeners and docker's embedded DNS are structurally unattributable
  /// from here and are never forwarded. The arkham image runs it because the
  /// sidecar needs no image of its own and no payload inspection: `arkham
  /// fwd` relays raw bytes.
  fn fwd_service(&self) -> String {
    let mut out = String::new();
    let _ = write!(
      out,
      "\n\
     \x20 fwd:\n\
     \x20   image: ghcr.io/lotsaai/arkham:{version}\n\
     \x20   command: [\"fwd\"]\n\
     \x20   # Shares the netns and the agent's PID namespace; publishing is on\n\
     \x20   # the arkham service, and anything else it could reach is bound to\n\
     \x20   # the netns itself. Never a PID namespace shared with arkham: the\n\
     \x20   # agent holds the decoys, arkham the real secrets.\n\
     \x20   network_mode: \"service:arkham\"\n\
     \x20   pid: \"service:agent\"\n",
      version = self.arkham_version
    );
    out
  }
}

#[cfg(test)]
mod tests {
  use crate::decoys::{Decoy, uncovered_names, uncovered_warning, validate_passthrough};
  use crate::mounts::Layout;
  use arkham_config::config::{HostTlsCfg, IfMissing, RuleCfg};
  use arkham_config::grants::GuestTlsMode;
  use arkham_pki::ca::CertAuthority;
  use std::collections::{BTreeMap, BTreeSet};
  use std::fs;
  use std::path::PathBuf;

  fn mtls_rule(guest_cert: Option<&str>, guest_key: Option<&str>) -> BTreeMap<String, RuleCfg> {
    let mut tls = BTreeMap::new();
    tls.insert(
      "https://api.github.com".to_string(),
      HostTlsCfg {
        client_cert: None,
        client_key: None,
        root_cert: None,
        guest_tls_mode: GuestTlsMode::Mtls,
        guest_cert: guest_cert.map(PathBuf::from),
        guest_key: guest_key.map(PathBuf::from),
      },
    );
    let rule = RuleCfg {
      env: "GITHUB_TOKEN".into(),
      value: None,
      real: None,
      generated: false,
      fnox_key: None,
      allow: vec!["https://api.github.com".to_string()],
      pattern: None,
      registry: None,
      oauth2: None,
      tls,
      ssh: BTreeMap::new(),
      if_missing: IfMissing::default(),
    };
    let mut rules = BTreeMap::new();
    rules.insert("github".to_string(), rule);
    rules
  }

  /// One minted pair per rule, mounted read-only at the declared container
  /// paths, and the second call is a no-op: the pair on disk is kept.
  #[test]
  fn guest_identity_mounts_declared_paths_and_keeps_an_existing_pair() {
    let ca = CertAuthority::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::new(dir.path(), "/root".to_string(), None);
    let guests = dir.path().join("guests");
    let rules = mtls_rule(Some("/safe/cert.pem"), Some("/safe/cert.key"));
    let mounts = layout.guest_identity_mounts(&rules, &ca, &guests).unwrap();
    assert_eq!(mounts.len(), 2);
    assert_eq!(mounts[0].container, PathBuf::from("/safe/cert.pem"));
    assert_eq!(mounts[1].container, PathBuf::from("/safe/cert.key"));
    assert!(mounts.iter().all(|mount| mount.ro));
    assert!(mounts[0].host.is_file() && mounts[1].host.is_file());
    let cert_before = fs::read(&mounts[0].host).unwrap();
    let again = layout.guest_identity_mounts(&rules, &ca, &guests).unwrap();
    assert_eq!(again[0].host, mounts[0].host);
    assert_eq!(fs::read(&mounts[0].host).unwrap(), cert_before);
  }

  /// An entry that declares no container paths gets the per-rule default
  /// under the agent's home.
  #[test]
  fn guest_identity_defaults_the_container_paths_when_none_declared() {
    let ca = CertAuthority::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::new(dir.path(), "/root".to_string(), None);
    let rules = mtls_rule(None, None);
    let mounts = layout.guest_identity_mounts(&rules, &ca, &dir.path().join("guests")).unwrap();
    assert_eq!(mounts[0].container, PathBuf::from("/root/.config/arkham/guest/github.pem"));
    assert_eq!(mounts[1].container, PathBuf::from("/root/.config/arkham/guest/github.key"));
  }

  /// A passthrough name that is also a rule env or a decoy fails, naming
  /// the name; disjoint names pass.
  #[test]
  fn passthrough_overlapping_a_rule_or_decoy_fails() {
    let rules = mtls_rule(None, None);
    let decoys = vec![Decoy {
      env: "ANTHROPIC_API_KEY".to_string(),
      value: "decoy".to_string(),
    }];
    let error = validate_passthrough(&rules, &[], &["GITHUB_TOKEN".to_string()])
      .unwrap_err()
      .to_string();
    assert!(error.contains("GITHUB_TOKEN"), "{error}");
    let error = validate_passthrough(&rules, &decoys, &["ANTHROPIC_API_KEY".to_string()])
      .unwrap_err()
      .to_string();
    assert!(error.contains("ANTHROPIC_API_KEY"), "{error}");
    validate_passthrough(&rules, &decoys, &["DISPLAY".to_string()]).unwrap();
  }

  /// Uncovered keeps declared names minus selection, passthrough, and
  /// fnox's own wiring; the warning sorts and names them with a fix.
  #[test]
  fn uncovered_diff_excludes_selected_passthrough_and_fnox_wiring() {
    let declared = BTreeSet::from([
      "GITHUB_TOKEN".to_string(),
      "WAYLAND_DISPLAY".to_string(),
      "DISPLAY".to_string(),
      "FNOX_PROFILE".to_string(),
    ]);
    let uncovered = uncovered_names(&declared, &["GITHUB_TOKEN".to_string()], &["WAYLAND_DISPLAY".to_string()]);
    assert_eq!(uncovered, vec!["DISPLAY".to_string()]);
    let warning = uncovered_warning(&["B".to_string(), "A".to_string()]).unwrap();
    assert!(warning.contains("A, B"), "{warning}");
    assert!(warning.contains("[workspace] passthrough"), "{warning}");
    assert_eq!(uncovered_warning(&[]), None);
  }
}

#[cfg(test)]
mod moved_suite {

  use arkham_config::config::WorkspaceBuild;
  use std::fs;
  use tempfile::tempdir;

  use crate::stack::*;
  use crate::test_support::*;
  use crate::workspace::*;

  #[test]
  fn the_agent_service_carries_what_inner_containers_need() {
    let yaml = test_stack(ProxyBackend::Tproxy).render();
    for expected in [
      "image: ghcr.io/casualjim/devagent:26.04",
      "security_opt: [seccomp=unconfined, systempaths=unconfined, apparmor=unconfined]",
      "cap_add: [SYS_CHROOT, AUDIT_WRITE, NET_ADMIN, SETUID, SETGID, SYS_ADMIN]",
      "devices: [/dev/net/tun]",
      "user: \"1000\"",
      "- /state/arkham/ws/arkham/containers:/home/eng/.local/share/containers",
    ] {
      assert!(yaml.contains(expected), "missing {expected}:\n{yaml}");
    }
    // The agent runs its own runtime; it never reaches the host's.
    assert!(!yaml.contains("docker.sock") && !yaml.contains("/var/run/docker"), "{yaml}");
  }

  #[test]
  fn render_keeps_comments_at_their_key_indent() {
    let yaml = test_stack(ProxyBackend::Ebpf).render();
    for expected in [
      "    # Capture dies with this process: the eBPF attachments are fd-held\n    # and the listeners live in it",
      "    restart: unless-stopped",
      "# (global layer plus this workspace's .config/arkham/config.toml, discovered\n# from its working directory",
    ] {
      assert!(yaml.contains(expected), "{yaml}");
    }
    assert!(!yaml.contains("\n          #") && !yaml.contains("\n       # "), "{yaml}");
  }

  #[test]
  fn workspace_image_overrides_the_agent_image() {
    let mut stack = test_stack(ProxyBackend::Tproxy);
    stack.agent.image = "ghcr.io/example/devenv:1.0".to_string();
    let yaml = stack.render();
    assert!(yaml.contains("image: ghcr.io/example/devenv:1.0"), "{yaml}");
    assert!(!yaml.contains(DEFAULT_AGENT_IMAGE), "{yaml}");
  }

  #[test]
  fn agent_build_renders_context_and_dockerfile() {
    let mut stack = test_stack(ProxyBackend::Tproxy);
    let build = AgentBuild {
      context: PathBuf::from("/ws/docker"),
      dockerfile: PathBuf::from("/ws/docker/Dockerfile.agent"),
    };
    stack.agent.build = Some(build);
    let yaml = stack.render();
    assert!(
      yaml.contains("build:\n      context: /ws/docker\n      dockerfile: /ws/docker/Dockerfile.agent"),
      "{yaml}"
    );
  }

  #[test]
  fn default_agent_service_has_no_build_section() {
    let yaml = test_stack(ProxyBackend::Tproxy).render();
    assert!(!yaml.contains("\n    build:\n"), "{yaml}");
  }

  #[test]
  fn agent_image_resolution_prefers_config_then_build_then_default() {
    assert_eq!(
      AgentSpec::image("arkham", Some("ghcr.io/example/devenv:1.0"), false).unwrap(),
      "ghcr.io/example/devenv:1.0"
    );
    assert_eq!(AgentSpec::image("arkham", None, false).unwrap(), DEFAULT_AGENT_IMAGE);
    assert_eq!(AgentSpec::image("arkham", None, true).unwrap(), "arkham-agent-arkham:local");
    AgentSpec::image("arkham", Some(""), false).unwrap_err();
  }

  #[test]
  fn agent_build_resolution_rejects_missing_inputs() {
    let dir = tempdir().unwrap();
    let build = WorkspaceBuild {
      dockerfile: PathBuf::from("docker/Dockerfile.agent"),
      context: PathBuf::from("docker"),
    };
    let layout = Layout::new(dir.path(), String::new(), None);
    let err = layout.resolve_build(&build).unwrap_err();
    assert!(err.to_string().contains("dockerfile"), "{err:?}");
    let docker = dir.path().join("docker");
    fs::create_dir(&docker).unwrap();
    fs::write(docker.join("Dockerfile.agent"), "FROM scratch\n").unwrap();
    let (context, dockerfile) = layout.resolve_build(&build).unwrap();
    assert_eq!(context, docker);
    assert_eq!(dockerfile, docker.join("Dockerfile.agent"));
    fs::remove_dir_all(&docker).unwrap();
    fs::write(dir.path().join("Dockerfile.agent"), "FROM scratch\n").unwrap();
    let lone = WorkspaceBuild {
      dockerfile: PathBuf::from("Dockerfile.agent"),
      context: PathBuf::from("docker"),
    };
    let err = layout.resolve_build(&lone).unwrap_err();
    assert!(err.to_string().contains("context"), "{err:?}");
  }

  #[test]
  fn workspace_devices_and_caps_append_to_the_agent_builtin_set() {
    let mut stack = test_stack(ProxyBackend::Tproxy);
    stack.agent.devices = vec!["/dev/kvm".to_string()];
    stack.agent.cap_add = vec!["SYS_PTRACE".to_string()];
    let yaml = stack.render();
    assert!(yaml.contains("devices: [/dev/net/tun, /dev/kvm]"), "{yaml}");
    assert!(
      yaml.contains("cap_add: [SYS_CHROOT, AUDIT_WRITE, NET_ADMIN, SETUID, SETGID, SYS_ADMIN, SYS_PTRACE]"),
      "{yaml}"
    );
  }

  #[test]
  fn compose_yaml_indents_every_mapping_key_under_its_parent() {
    // The generated stack is parsed by docker's YAML loader, so a key at the
    // wrong depth is a hard failure, not a cosmetic one. In these literals a
    // `\`-continued line drops its leading whitespace while the first line
    // keeps it.
    let yaml = test_stack(ProxyBackend::Tproxy).render();
    for expected in [
      "\n    cap_add:\n      - NET_ADMIN\n",
      "\n    stop_grace_period: 1s\n",
      "\n    volumes:\n",
      "\n  agent:\n",
      "\n  arkham:\n",
      "\nservices:\n",
    ] {
      assert!(yaml.contains(expected), "missing {expected:?}:\n{yaml}");
    }
  }

  #[test]
  fn compose_yaml_mounts_the_workspace_at_its_translated_path() {
    let mounts = vec![
      mount("/home/ivan/github/arkham", "/home/eng/github/arkham", false),
      mount("/home/ivan/.config/mise", "/home/eng/.config/mise", true),
    ];
    let yaml = Stack {
      agent: agent_paths("/home/eng/github/arkham"),
      mounts: mounts.clone(),
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(yaml.contains("name: arkham\nservices:"), "{yaml}");
    assert!(yaml.contains("working_dir: \"/home/eng/github/arkham\""), "{yaml}");
    assert!(yaml.contains("- /home/ivan/github/arkham:/home/eng/github/arkham:rw"), "{yaml}");
    assert!(yaml.contains("- /home/ivan/.config/mise:/home/eng/.config/mise:ro"), "{yaml}");
    assert!(
      yaml.contains("entrypoint: [\"/home/eng/.config/arkham/agent-entrypoint.sh\"]"),
      "the entrypoint is the in-container path: {yaml}"
    );
    assert!(
      yaml.contains(":/home/eng/.config/arkham/agent-entrypoint.sh:ro"),
      "mounted where the entrypoint names it: {yaml}"
    );
    assert!(yaml.contains("network_mode: \"service:arkham\""), "{yaml}");
    assert!(yaml.contains(":/certs/ca.pem"), "the CA is mounted for arkham: {yaml}");
    assert!(!yaml.contains("/root/.config/fnox"), "no fnox mount without binds to mount: {yaml}");
    assert!(yaml.contains("init: true"), "{yaml}");
    assert!(yaml.contains(&format!("GITHUB_TOKEN: \"{}\"", decoys()[0].value)), "{yaml}");
  }

  #[test]
  fn slug_uses_path_segments() {
    assert_eq!(slug(Path::new("/home/ivan/github/arkham")), "home-ivan-github-arkham");
    assert_eq!(slug(Path::new("/srv/My_Project")), "srv-my-project");
  }

  #[test]
  fn each_backend_shapes_the_serve_command_and_its_host_wiring() {
    let render = |backend| test_stack(backend).render();

    let tproxy = render(ProxyBackend::Tproxy);
    assert!(tproxy.contains("command: [\"serve\", \"--proxy-backend\", \"tproxy\"]"), "{tproxy}");
    assert_eq!(
      tproxy.matches("/dev/net/tun").count(),
      1,
      "only the agent service asks for the tun device: {tproxy}"
    );
    assert!(!tproxy.contains("cgroup"), "{tproxy}");

    let tun = render(ProxyBackend::Tun);
    assert!(tun.contains("command: [\"serve\", \"--proxy-backend\", \"tun\"]"), "{tun}");
    assert_eq!(tun.matches("/dev/net/tun").count(), 2, "arkham needs the tun device too: {tun}");
    assert!(!tun.contains("--ebpf-cgroup"), "{tun}");

    let ebpf = render(ProxyBackend::Ebpf);
    assert!(
      ebpf.contains("command: [\"serve\", \"--proxy-backend\", \"ebpf\", \"--ebpf-cgroup\", \"enclosing\"]"),
      "{ebpf}"
    );
    for expected in ["    cgroup: host\n", "      - BPF\n      - PERFMON\n"] {
      assert!(ebpf.contains(expected), "missing {expected:?}:\n{ebpf}");
    }
    assert_eq!(
      ebpf.matches("    cgroup_parent: arkham-arkham.slice\n").count(),
      2,
      "both services carry the shared cgroup, so docker creates it as arkham starts: {ebpf}"
    );
    assert_eq!(ebpf.matches("/dev/net/tun").count(), 1, "ebpf needs no tun device: {ebpf}");
    assert_eq!(
      ebpf.matches("ARKHAM_EBPF_BYPASS_FILE: /arkham/ebpf-bypass\n").count(),
      2,
      "arkham reads and the agent writes the same shared bypass file: {ebpf}"
    );
    assert!(!tun.contains("ARKHAM_EBPF_BYPASS_FILE"), "{tun}");
    assert!(!tproxy.contains("ARKHAM_EBPF_BYPASS_FILE"), "{tproxy}");
  }

  #[test]
  fn the_bypass_mount_names_the_shared_state_file() {
    let mount = Layout::new(Path::new("/root"), String::new(), None).bypass_mount();
    assert_eq!(mount.container, Path::new("/arkham/ebpf-bypass"));
    assert!(
      mount.host.ends_with("ebpf-bypass"),
      "the host side is the per-workspace state file: {}",
      mount.host.display()
    );
    assert!(!mount.ro, "the agent entrypoint writes the file, so the shared mount is read-write");
  }

  #[test]
  fn workspace_ports_render_as_stable_host_bindings() {
    let yaml = Stack {
      ports: vec![3000, 5432],
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    let arkham_block = &yaml[..yaml.find("\n  agent:\n").unwrap()];
    assert!(
      arkham_block.contains("    ports:\n"),
      "ports belong to the arkham service: {arkham_block}"
    );
    for port in [3000, 5432] {
      assert!(
        arkham_block.contains(&format!("      - \"127.0.0.1:{port}:{port}\"\n")),
        "{arkham_block}"
      );
    }
    assert!(
      !arkham_block.contains("15000"),
      "the capture listener port is not published: {arkham_block}"
    );
    assert_eq!(
      arkham_block.matches("      - \"127.0.0.1:").count(),
      2,
      "exactly the declared ports, nothing else: {arkham_block}"
    );
    let empty = test_stack(ProxyBackend::Tproxy).render();
    assert!(!empty.contains("ports:"), "no ports key without declared ports: {empty}");
  }

  #[test]
  fn workspace_networks_extra_hosts_and_expose_render() {
    let yaml = Stack {
      ports: vec![3000],
      expose: vec![ExposeMap { port: 5173, host: 5174 }],
      networks: vec!["headroom_default".to_string()],
      extra_hosts: vec!["host.docker.internal:host-gateway".to_string()],
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    let arkham_block = &yaml[..yaml.find("\n  agent:\n").unwrap()];
    assert!(
      arkham_block.contains("      - \"127.0.0.1:3000:3000\"\n"),
      "symmetric ports keep rendering: {arkham_block}"
    );
    assert!(
      arkham_block.contains("      - \"127.0.0.1:5174:5173\"\n"),
      "expose maps host onto container port: {arkham_block}"
    );
    assert!(
      arkham_block.contains("    extra_hosts:\n      - \"host.docker.internal:host-gateway\"\n"),
      "arkham carries the hosts entry: {arkham_block}"
    );
    assert_eq!(
      arkham_block.matches("host.docker.internal").count(),
      1,
      "a stated gateway is not repeated beside the automatic one: {arkham_block}"
    );
    assert!(
      arkham_block.contains("    networks:\n      - \"headroom_default\"\n"),
      "arkham joins the named network: {arkham_block}"
    );
    assert!(
      yaml.contains("networks:\n  \"headroom_default\":\n    external: true\n"),
      "joined networks are declared external at the top level: {yaml}"
    );
    let agent_block = &yaml[yaml.find("\n  agent:\n").unwrap()..yaml.find("\n  fwd:\n").unwrap()];
    assert!(
      !agent_block.contains("extra_hosts:"),
      "the daemon rejects host mappings on a `network_mode` service: {agent_block}"
    );
    assert!(
      !agent_block.contains("networks:"),
      "a `network_mode` service takes no networks key: {agent_block}"
    );
    let empty = test_stack(ProxyBackend::Tproxy).render();
    let empty_arkham = &empty[..empty.find("\n  agent:\n").unwrap()];
    let empty_agent = &empty[empty.find("\n  agent:\n").unwrap()..empty.find("\n  fwd:\n").unwrap()];
    assert!(
      empty_arkham.contains("    extra_hosts:\n      - \"host.docker.internal:host-gateway\"\n"),
      "arkham always carries the gateway: {empty_arkham}"
    );
    assert!(
      !empty_agent.contains("extra_hosts:"),
      "the agent never carries host mappings: {empty_agent}"
    );
    assert!(!empty.contains("external: true"), "no networks block without joins: {empty}");
  }

  #[test]
  fn the_generated_stack_renders_the_sidecar_and_moves_the_explicit_proxy_off_8080() {
    let yaml = test_stack(ProxyBackend::Tproxy).render();
    assert!(
      yaml.starts_with("# generated by `arkham init`."),
      "the header leads the generated file: {yaml}"
    );
    assert!(
      !yaml.contains("# stack shape:"),
      "generated compose is compared as text, so it carries no shape marker: {yaml}"
    );
    assert!(
      yaml.contains("~/.config/arkham/compose.yaml") && yaml.contains(".config/arkham/compose.yaml"),
      "the header points at the override files: {yaml}"
    );
    assert!(!yaml.contains("edit freely"), "the generated file is not the edit surface: {yaml}");
    for expected in [
      "  fwd:\n",
      "    command: [\"fwd\"]\n",
      "    network_mode: \"service:arkham\"\n",
      "    pid: \"service:agent\"\n",
    ] {
      assert!(yaml.contains(expected), "missing {expected:?}:\n{yaml}");
    }
    assert_eq!(
      yaml.matches(&format!("    image: ghcr.io/lotsaai/arkham:{TEST_VERSION}\n")).count(),
      2,
      "arkham and fwd services both pin the threaded version:\n{yaml}"
    );
    // One service key each: a duplicated key is a compose parse error, not a
    // cosmetic slip.
    for service in ["arkham", "agent", "fwd"] {
      assert_eq!(
        yaml.matches(&format!("\n  {service}:\n")).count(),
        1,
        "service `{service}` must be defined exactly once:\n{yaml}"
      );
    }
    assert!(
      yaml.contains(&format!("ARKHAM_LISTEN: {EXPLICIT_LISTEN}")),
      "the explicit proxy must not hold the common dev-server port:\n{yaml}"
    );
    assert!(!yaml.contains("ARKHAM_LISTEN: 127.0.0.1:8080"), "{yaml}");
    // The sidecar shares the agent's PID namespace, never arkham's.
    assert!(!yaml.contains("pid: \"service:arkham\""), "{yaml}");
    // Only the agent and arkham get cgroup placement; the sidecar must stay
    // outside the captured subtree so its own relays are never rewritten.
    let fwd_block = &yaml[yaml.find("\n  fwd:\n").unwrap()..];
    assert!(!fwd_block.contains("cgroup"), "the sidecar is not captured: {fwd_block}");
  }

  /// Passthrough renders doubled so compose leaves a literal `${NAME}` for
  /// the agent; file mounts ride read-only right after workspace mounts.
  #[test]
  fn passthrough_renders_interpolated_and_file_mounts_follow_workspace_mounts() {
    let yaml = Stack {
      passthrough: vec!["WAYLAND_DISPLAY".to_string()],
      mounts: vec![mount("/srv/ws", "/home/eng/ws", false)],
      file_mounts: vec![mount("/state/files/00-npmrc", "/home/eng/.npmrc", true)],
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(yaml.contains("      WAYLAND_DISPLAY: \"${WAYLAND_DISPLAY}\"\n"), "{yaml}");
    let agent = &yaml[yaml.find("\n  agent:\n").unwrap()..];
    let workspace_at = agent.find("/srv/ws:/home/eng/ws:rw").unwrap();
    let file_at = agent.find("/state/files/00-npmrc:/home/eng/.npmrc:ro").unwrap();
    assert!(workspace_at < file_at, "rewrites overlay workspace mounts: {agent}");
  }
}
