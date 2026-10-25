//! `arkham init` plus the stack commands (`up`, `down`, `logs`):
//! regenerate when the render changes, then drive compose and enter the agent.

use std::collections::{BTreeMap, hash_map::DefaultHasher};
use std::ffi::OsString;
use std::fs;
use std::hash::{Hash as _, Hasher as _};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use tokio::process::Command;

use crate::error::Error;
use crate::expose::prune_workspace;
use crate::paths::{expand, translate};
use crate::stack::{current_uid, generate_stack};
use crate::workspace::Workspace;
use arkham_config::cli::{Cli, CliCommand, ProxyBackend};
use arkham_config::config::{AppConfig, RuleCfg, WorkspaceBuild, config_dir};
use arkham_pki::ca::load_or_generate;
use clap::Args;
use dirs::home_dir;
use libc::{SIG_DFL, SIGINT, c_int, sighandler_t, signal};
use toml_edit::{DocumentMut, Formatted, Item, Value};

/// The entrypoint the generated agent service runs: it makes arkham's CA trusted
/// inside the container before handing off, by installing it into the system
/// store every tool already reads, then chains to the image's own init —
/// `ARKHAM_INIT` when set, the common entrypoint script names otherwise, and
/// the command directly as the safe default. `arkham init` writes it when
/// absent, so an edited copy survives regeneration.
pub(crate) const ENTRYPOINT_SCRIPT: &str = r#"#!/bin/sh
set -e
# The compose file mounts arkham's certificate at the system CA location, so
# refreshing the store is the whole job. That needs root: run the agent service
# as root, or grant it passwordless sudo (devcontainer images usually do).
if [ "$(id -u)" = "0" ]; then
  update-ca-certificates >/dev/null 2>&1 || true
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo -n update-ca-certificates >/dev/null 2>&1 || true
else
  echo "arkham: run the agent as root or bake the certificate into the image" >&2
  echo "arkham: https://github.com/casualjim/arkham/blob/main/docs/user/how-to/trust-the-ca.md" >&2
fi
# Publish this container's podman subnets for arkham's eBPF bypass list.
# Podman networks are created here long after arkham starts, so the loader
# cannot know them up front: this loop rewrites the shared bypass file from
# `podman network inspect` and arkham reloads it live. Only when the stack
# wires the file (ARKHAM_EBPF_BYPASS_FILE); without podman the subshell exits
# quietly, and a failing podman keeps the previous file. The temp-file plus
# rename means arkham never reads a half-written list.
if [ -n "${ARKHAM_EBPF_BYPASS_FILE:-}" ]; then
  (
    set +e
    while true; do
      if names=$(podman network ls --format '{{.Name}}' 2>/dev/null); then
        if [ -z "$names" ]; then
          : > "${ARKHAM_EBPF_BYPASS_FILE}.tmp" && mv "${ARKHAM_EBPF_BYPASS_FILE}.tmp" "$ARKHAM_EBPF_BYPASS_FILE"
        elif out=$(printf '%s\n' "$names" | xargs -r podman network inspect --format '{{range .Subnets}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null); then
          printf '%s\n' "$out" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' | sort -u > "${ARKHAM_EBPF_BYPASS_FILE}.tmp" \
            && mv "${ARKHAM_EBPF_BYPASS_FILE}.tmp" "$ARKHAM_EBPF_BYPASS_FILE"
        fi
      fi
      sleep 10
    done
  ) >/dev/null 2>&1 &
fi
# Hand over to the image's own init when there is one, so the container's real
# startup (service supervisors, sockets, whatever the image ships) still runs:
# ARKHAM_INIT names it for images without a common name, the usual entrypoint
# script names are tried next, and with none of them the command runs directly.
if [ -n "${ARKHAM_INIT:-}" ] && [ -x "$ARKHAM_INIT" ]; then
  exec "$ARKHAM_INIT" "$@"
fi
for init in /usr/local/bin/docker-entrypoint.sh /docker-entrypoint.sh /usr/local/bin/entrypoint.sh /entrypoint.sh; do
  if [ -x "$init" ]; then
    exec "$init" "$@"
  fi
done
exec "$@"
"#;

/// Create the host files the generated stack mounts, when they are missing: the
/// CA at `<dir>/ca.pem` (`ca.crt` and `ca.key` come with it, and the stack
/// mounts `ca.pem` for arkham and `ca.crt` for the agent) and the agent
/// entrypoint. The CA is never overwritten, so one you installed elsewhere
/// survives; the entrypoint is regenerated whenever it differs from the
/// generated script, so stale or hand-edited copies cannot linger. The
/// directory is the arkham config directory, which is what the compose defaults
/// point at, not `[proxy] ca_file`: that describes a host-run arkham, not the
/// container's mount. The storage directory is this workspace's, under the
/// state directory.
pub(crate) fn ensure_support_files(dir: &Path, storage: &Path) -> Result<Vec<(PathBuf, bool)>, Error> {
  let ca = dir.join("ca.pem");
  let entrypoint = dir.join("agent-entrypoint.sh");
  let mut files = Vec::new();
  let created = !ca.exists();
  match load_or_generate(&ca) {
    Ok(_) => files.push((ca, created)),
    // A read-only or unwritable config directory only warns: the stack still
    // starts when a compose layer mounts a CA made with `arkham ca`.
    Err(err) => tracing::warn!(path = %ca.display(), %err, "could not prepare the CA"),
  }
  files.push((entrypoint.clone(), write_entrypoint(&entrypoint)?));
  // The agent's inner container storage — see the generated compose file for
  // why this directory has to exist before the stack starts.
  let storage_created = !storage.exists();
  match fs::create_dir_all(storage) {
    Ok(()) => files.push((storage.to_path_buf(), storage_created)),
    Err(err) => tracing::warn!(path = %storage.display(), %err, "could not prepare the agent storage directory"),
  }
  Ok(files)
}

/// Write the agent entrypoint, replacing a stale or edited copy so the two
/// never drift: the file is generated output, and a compose layer overriding
/// `entrypoint:` is the way to run a custom script instead. Executable: docker
/// runs it directly.
pub(crate) fn write_entrypoint(path: &Path) -> Result<bool, Error> {
  if let Ok(existing) = fs::read_to_string(path)
    && existing == ENTRYPOINT_SCRIPT
  {
    return Ok(false);
  }
  let regenerated = path.exists();
  fs::write(path, ENTRYPOINT_SCRIPT).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })?;
  fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|source| Error::ChmodFile {
    path: path.to_path_buf(),
    source,
  })?;
  if regenerated {
    println!("regenerated {} (replaced a stale or edited copy)", path.display());
  }
  Ok(!regenerated)
}

/// Resolve the config directory and this workspace's state directory, then
/// create what the stack mounts from them.
pub(crate) fn prepare_support_files(root: &Path) -> Result<Vec<(PathBuf, bool)>, Error> {
  let dir = config_dir().ok_or_else(|| Error::ConfigDir {
    detail: "unable to resolve the arkham config directory".to_string(),
  })?;
  ensure_support_files(&dir, &Workspace::new(root).state_dir().join("containers"))
}

/// Report the files the call actually created; absent ones are already there.
pub(crate) fn report_created(files: &[(PathBuf, bool)]) {
  for (path, created) in files {
    if *created {
      println!("wrote {}", path.display());
    }
  }
}

/// Skeleton content of a fresh bypass file: comments only, so arkham starts
/// with no runtime entries and the agent entrypoint's first rewrite replaces
/// the whole file atomically.
const BYPASS_FILE_SKELETON: &str = "# Arkham eBPF bypass CIDRs, one per line.\n# The agent entrypoint rewrites this file from `podman network inspect`;\n# arkham reloads it live. Blank lines and `#` comments are ignored.\n";

/// Create the runtime bypass file when missing; never overwrite it, since
/// the agent rewrites it at runtime. Returns whether it was created, so
/// callers can report it like the other support files.
async fn ensure_bypass_file(path: &Path) -> Result<bool, Error> {
  if path.exists() {
    return Ok(false);
  }
  tokio::fs::write(path, BYPASS_FILE_SKELETON)
    .await
    .map_err(|source| Error::WriteFile {
      path: path.to_path_buf(),
      source,
    })?;
  Ok(true)
}

/// The capture backend the generated stack runs: `--backend` when given,
/// `ebpf` otherwise. Linux only — the generated serve command and the host
/// wiring that goes with it exist for Linux capture backends, so any other
/// host is refused here rather than producing a stack that cannot capture.
pub(crate) fn resolve_backend(backend: Option<ProxyBackend>) -> Result<ProxyBackend, Error> {
  if !cfg!(target_os = "linux") {
    return Err(Error::LinuxOnly);
  }
  match backend {
    None => Ok(ProxyBackend::Ebpf),
    Some(ProxyBackend::None) => Err(Error::BackendNone),
    Some(backend) => Ok(backend),
  }
}

/// Write `content` unless the file is already there; `true` means it was
/// written now. Nothing existing is ever overwritten — that file is the
/// user's.
pub(crate) fn write_if_absent(path: &Path, content: &str) -> Result<bool, Error> {
  if path.exists() {
    return Ok(false);
  }
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent).map_err(|source| Error::CreateDir {
      path: parent.to_path_buf(),
      source,
    })?;
  }
  fs::write(path, content).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })?;
  Ok(true)
}

/// Write `mise.agent.toml` from `mise.local.toml` when the workspace uses
/// mise for local tasks and has no agent file yet: host-home path prefixes
/// become the container home so the agent's tasks find the same files.
/// Never overwrites; `true` means it was written now.
///
/// # Errors
///
/// Returns an error when the local file cannot be read, rewritten, or
/// written.
pub(crate) fn ensure_mise_agent(root: &Path, home: &str) -> Result<bool, Error> {
  if !root.join("mise.toml").is_file() || !root.join("mise.local.toml").is_file() || root.join("mise.agent.toml").exists() {
    return Ok(false);
  }
  let local = root.join("mise.local.toml");
  let content = fs::read_to_string(&local).map_err(|source| Error::ReadFile {
    path: local.clone(),
    source,
  })?;
  let rewritten = rewrite_mise_toml(&content, home_dir().as_deref(), home)?;
  write_if_absent(&root.join("mise.agent.toml"), &rewritten)
}

/// Copy `mise.local.toml` with host-home prefixes rewritten to the container
/// home, reusing [`translate`] semantics on path-looking string values.
/// URLs and non-paths stay intact.
///
/// # Errors
///
/// Returns an error when the content is not valid TOML.
pub(crate) fn rewrite_mise_toml(content: &str, host_home: Option<&Path>, home: &str) -> Result<String, Error> {
  let mut document: DocumentMut = content.parse().map_err(|source| Error::MiseParse { source })?;
  rewrite_mise_item(document.as_item_mut(), host_home, home);
  Ok(document.to_string())
}

/// Rewrite one TOML value tree in place: every string under a home prefix
/// moves to the container home.
fn rewrite_mise_item(item: &mut Item, host_home: Option<&Path>, home: &str) {
  match item {
    Item::Value(value) => rewrite_mise_value(value, host_home, home),
    Item::Table(table) => {
      for (_, item) in table.iter_mut() {
        rewrite_mise_item(item, host_home, home);
      }
    }
    Item::ArrayOfTables(tables) => {
      for table in tables.iter_mut() {
        for (_, item) in table.iter_mut() {
          rewrite_mise_item(item, host_home, home);
        }
      }
    }
    Item::None => {}
  }
}
/// Rewrite one TOML value: arrays recurse, strings under the host home move
/// to the container home, everything else stays.
fn rewrite_mise_value(value: &mut Value, host_home: Option<&Path>, home: &str) {
  match value {
    Value::String(text) => {
      let rewritten = rewrite_mise_string(text.value(), host_home, home);
      *text = Formatted::new(rewritten);
    }
    Value::Array(items) => {
      for item in items.iter_mut() {
        rewrite_mise_value(item, host_home, home);
      }
    }
    Value::InlineTable(table) => {
      for (_, value) in table.iter_mut() {
        rewrite_mise_value(value, host_home, home);
      }
    }
    _ => {}
  }
}

/// One mise string: URLs and non-paths stay intact; a value under the host
/// home (after `~` expansion) moves to the container home prefix.
fn rewrite_mise_string(value: &str, host_home: Option<&Path>, home: &str) -> String {
  if value.contains("://") {
    return value.to_string();
  }
  let expanded = if value == "~" || value.starts_with("~/") {
    match host_home {
      Some(host_home) => format!("{}{}", host_home.display(), &value[1..]),
      None => return value.to_string(),
    }
  } else {
    value.to_string()
  };
  match host_home.and_then(|host_home| Path::new(&expanded).strip_prefix(host_home).ok()) {
    Some(rest) => Path::new(home).join(rest).to_string_lossy().into_owned(),
    None => value.to_string(),
  }
}

/// A warning when nothing will substitute — no rule in play and nothing the
/// registry could turn into one — since then every credential the agent
/// holds stays a decoy; `None` when a rule or a derivable name is in effect.
pub(crate) fn rules_warning(rules: &BTreeMap<String, RuleCfg>, derivable: &[String]) -> Option<String> {
  if !rules.is_empty() || !derivable.is_empty() {
    return None;
  }
  Some(
    "warning: no [rules.*] in play and nothing derives from fnox through the registry, \
     so nothing will be substituted and every credential the agent holds stays a decoy; \
     `arkham rules` lists what fnox and the registry cover"
      .to_string(),
  )
}

/// The capture backend the stack on disk was generated with, when it can be
/// read back — a regeneration must not silently switch how traffic is
/// captured just because this run did not name a backend.
pub(crate) fn generated_backend(compose: &str) -> Option<ProxyBackend> {
  [
    ("ebpf", ProxyBackend::Ebpf),
    ("tun", ProxyBackend::Tun),
    ("tproxy", ProxyBackend::Tproxy),
  ]
  .into_iter()
  .find_map(|(name, backend)| compose.contains(&format!("\"--proxy-backend\", \"{name}\"")).then_some(backend))
}

/// Generate the workspace stack when it is absent, and rewrite it when the
/// rendered file would differ. An identical render is left untouched.
pub(crate) async fn init_workspace(
  workspace: &Workspace,
  backend: ProxyBackend,
  explicit_backend: bool,
  arkham_version: &str,
) -> Result<(), Error> {
  let state_ws = workspace.state_dir();
  let ws_compose = state_ws.join("compose.yml");
  tokio::fs::create_dir_all(&state_ws).await.map_err(|source| Error::CreateDir {
    path: state_ws.clone(),
    source,
  })?;
  // The runtime bypass file the ebpf stack mounts must exist before compose
  // starts: docker creates a directory at a missing file mount, which then
  // breaks both the agent writer and arkham's reader. Created once, never
  // overwritten — the agent owns its contents at runtime.
  if backend == ProxyBackend::Ebpf && ensure_bypass_file(&state_ws.join("ebpf-bypass")).await? {
    println!("wrote {}", state_ws.join("ebpf-bypass").display());
  }
  let config = workspace.config()?;
  let derivable = workspace.selection()?.derivable_envs();
  if let Some(warning) = rules_warning(&config.rules, &derivable) {
    println!("{warning}");
  }
  report_created(&prepare_support_files(workspace.root())?);
  if let Some(home) = config.workspace.home.as_deref()
    && ensure_mise_agent(workspace.root(), home)?
  {
    println!("wrote {}", workspace.root().join("mise.agent.toml").display());
  }
  let existing = tokio::fs::read_to_string(&ws_compose).await.ok();
  // An unnamed backend keeps whatever the stack on disk already runs.
  let backend = if explicit_backend {
    backend
  } else {
    existing.as_deref().and_then(generated_backend).unwrap_or(backend)
  };
  let stack = generate_stack(workspace.root(), backend, arkham_version).await?;
  if existing.as_deref() == Some(stack.as_str()) {
    println!("exists, left untouched: {}", ws_compose.display());
    return Ok(());
  }
  tokio::fs::write(&ws_compose, &stack).await.map_err(|source| Error::WriteFile {
    path: ws_compose.clone(),
    source,
  })?;
  if existing.is_some() {
    println!("regenerated: {}", ws_compose.display());
  } else {
    println!("generated: {}", ws_compose.display());
  }
  Ok(())
}

/// The compose files on disk, in layer order: global `compose.yaml` or
/// `compose.yml`, the generated stack, then the workspace override.
fn compose_layers(workspace: &Workspace) -> Vec<PathBuf> {
  let global = config_dir().and_then(|dir| {
    let yaml = dir.join("compose.yaml");
    if yaml.is_file() {
      Some(yaml)
    } else {
      let dotted = dir.join("compose.yml");
      dotted.is_file().then_some(dotted)
    }
  });
  [global, Some(workspace.state_dir().join("compose.yml")), Some(workspace.file())]
    .into_iter()
    .flatten()
    .filter(|path| path.is_file())
    .collect()
}

/// A `docker compose` command over those layers.
pub(crate) fn compose_command(workspace: &Workspace) -> Result<Command, Error> {
  let layers = compose_layers(workspace);
  if layers.is_empty() {
    return Err(Error::NoComposeLayers {
      root: workspace.root().to_path_buf(),
    });
  }
  let mut command = Command::new("docker");
  command.arg("compose");
  for layer in layers {
    command.arg("-f").arg(layer);
  }
  Ok(command)
}

/// Run a compose command and fail on a non-zero exit; its output is the user's.
async fn compose_status(command: &mut Command) -> Result<(), Error> {
  let status = command.status().await.map_err(|source| Error::SpawnCompose { source })?;
  if !status.success() {
    return Err(Error::ComposeFailed {
      status: status.to_string(),
    });
  }
  Ok(())
}

/// The same, for a compose command the user is meant to interrupt — an exec
/// session, a `--follow` log read. compose reports that interrupt as 130, and
/// an interrupt is the user getting what they asked for, not a failure.
async fn compose_status_interruptible(command: &mut Command) -> Result<(), Error> {
  let status = command.status().await.map_err(|source| Error::SpawnCompose { source })?;
  if !(status.success() || status.code() == Some(130)) {
    return Err(Error::ComposeFailed {
      status: status.to_string(),
    });
  }
  Ok(())
}

/// The compose arguments `arkham up` maps to: `--build` only when the agent
/// image must be (re)built, so a plain `up` never compiles a Dockerfile.
pub(crate) fn up_argv(will_build: bool) -> Vec<OsString> {
  let mut argv: Vec<OsString> = vec!["up".into(), "-d".into()];
  if will_build {
    argv.push("--build".into());
  }
  argv
}

/// Digest of the agent build inputs — the dockerfile bytes plus the context
/// tree's relative paths, sizes, and mtimes — so an edited Dockerfile or a
/// changed context rebuilds on the next `up` without a flag. Hashing file
/// contents across the whole context would resend it on every check;
/// metadata notices a change and stays cheap to read.
pub(crate) fn build_digest(root: &Path, build: &WorkspaceBuild) -> u64 {
  fn hash_file(path: &Path, hasher: &mut DefaultHasher) {
    match fs::read(path) {
      Ok(bytes) => bytes.hash(hasher),
      Err(_) => "absent".hash(hasher),
    }
    path.hash(hasher);
  }
  fn hash_tree(dir: &Path, root: &Path, hasher: &mut DefaultHasher) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
      .ok()
      .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
      .unwrap_or_default();
    entries.sort();
    for path in entries {
      if path.is_dir() {
        hash_tree(&path, root, hasher);
        continue;
      }
      path.strip_prefix(root).unwrap_or(&path).hash(hasher);
      match path.metadata() {
        Ok(meta) => {
          meta.len().hash(hasher);
          meta.modified().ok().hash(hasher);
        }
        Err(_) => "absent".hash(hasher),
      }
    }
  }
  let home = home_dir();
  let mut hasher = DefaultHasher::new();
  hash_file(&expand(&build.dockerfile, root, home.as_deref()), &mut hasher);
  hash_tree(
    &expand(&build.context, root, home.as_deref()),
    &expand(&build.context, root, home.as_deref()),
    &mut hasher,
  );
  hasher.finish()
}

/// State file holding the last successfully built inputs digest.
fn build_digest_file(root: &Path) -> PathBuf {
  Workspace::new(root).state_dir().join("build.digest")
}

/// Whether this `up` must (re)build the agent image: `--build` forces it,
/// otherwise a `[workspace.build]` whose inputs changed since the last
/// successful build. No build section means no build, and `--build` then is
/// a config error, not a silent no-op.
fn should_build(workspace: &Workspace, is_forced: bool) -> Result<bool, Error> {
  let Some(build) = workspace.config()?.workspace.build else {
    if is_forced {
      return Err(Error::BuildNotConfigured);
    }
    return Ok(false);
  };
  if is_forced {
    return Ok(true);
  }
  let stored = fs::read_to_string(build_digest_file(workspace.root())).unwrap_or_default();
  Ok(stored.trim() != build_digest(workspace.root(), &build).to_string())
}

/// Record a successful build's inputs digest, or drop a stale digest file
/// when no build section configures one.
fn record_build_digest(workspace: &Workspace, was_built: bool) -> Result<(), Error> {
  let path = build_digest_file(workspace.root());
  match workspace.config()?.workspace.build {
    Some(build) if was_built => fs::write(&path, build_digest(workspace.root(), &build).to_string()).map_err(|source| Error::WriteFile {
      path: path.clone(),
      source,
    }),
    Some(_) => Ok(()),
    None => {
      if path.exists() {
        fs::remove_file(&path).map_err(|source| Error::RemoveFile {
          path: path.clone(),
          source,
        })?;
      }
      Ok(())
    }
  }
}

/// Start the layered project, making sure what it mounts exists first.
pub(crate) async fn up_workspace(workspace: &Workspace, is_forced: bool) -> Result<(), Error> {
  report_created(&prepare_support_files(workspace.root())?);
  // The bypass file an ebpf stack mounts must exist before compose starts,
  // even when generation is skipped (a plain `up`): docker creates a
  // directory at a missing file mount, which then breaks both the agent
  // writer and arkham's reader. The generated backend decides, since `up`
  // takes no backend flag.
  let backend = tokio::fs::read_to_string(workspace.state_dir().join("compose.yml"))
    .await
    .ok()
    .and_then(|body| generated_backend(&body));
  if backend == Some(ProxyBackend::Ebpf) && ensure_bypass_file(&workspace.state_dir().join("ebpf-bypass")).await? {
    println!("wrote {}", workspace.state_dir().join("ebpf-bypass").display());
  }
  let will_build = should_build(workspace, is_forced)?;
  let mut command = compose_command(workspace)?;
  command.args(up_argv(will_build));
  compose_status(&mut command).await?;
  record_build_digest(workspace, will_build)
}

/// Stop the layered project.
async fn down_workspace(workspace: &Workspace) -> Result<(), Error> {
  let mut command = compose_command(workspace)?;
  command.arg("down");
  compose_status(&mut command).await
}

/// The compose arguments `arkham logs` maps to: its flags only when they were
/// asked for, the tail always (compose defaults it to everything), then the
/// named services — none means every service in the stack.
pub(crate) fn logs_argv(args: &LogsArgs) -> Vec<OsString> {
  let mut compose: Vec<OsString> = vec!["logs".into()];
  if args.follow {
    compose.push("--follow".into());
  }
  if args.no_log_prefix {
    compose.push("--no-log-prefix".into());
  }
  compose.push("--tail".into());
  compose.push(args.tail.clone().into());
  compose.extend(args.services.iter().map(Into::into));
  compose
}

/// Read the stack's logs.
async fn logs_workspace(workspace: &Workspace, args: &LogsArgs) -> Result<(), Error> {
  let mut command = compose_command(workspace)?;
  command.args(logs_argv(args));
  compose_status_interruptible(&mut command).await
}

/// Enter the agent environment at the translated workspace directory: the
/// configured shell, or `command` when the caller passed one.
async fn exec_agent(workspace: &Workspace, command: &[OsString]) -> Result<(), Error> {
  let config = workspace.config()?;
  let home = config.workspace.container_home().to_string();
  let workdir = translate(workspace.root(), home_dir().as_deref(), &home);
  warn_uncovered(workspace, &config);
  let uid = current_uid();
  let argv: Vec<OsString> = if command.is_empty() {
    vec![config.workspace.shell.clone().unwrap_or_else(|| "sh".to_string()).into()]
  } else {
    command.to_vec()
  };
  let mut compose = compose_command(workspace)?;
  compose
    .arg("exec")
    .arg("-i")
    .arg("--workdir")
    .arg(&workdir)
    .arg("--user")
    .arg(uid.to_string())
    .arg("agent")
    .args(argv);
  compose_status_interruptible(&mut compose).await
}

/// Print one sorted warning for fnox-declared names no rule, passthrough, or
/// provider wiring covers, every time the agent is entered. Never prints
/// values. A missing fnox setup means nothing to cover, so it stays silent.
fn warn_uncovered(workspace: &Workspace, config: &AppConfig) {
  let Ok(selection) = workspace.selection() else {
    return;
  };
  if let Some(warning) = selection.coverage_warning(&config.workspace.passthrough) {
    println!("{warning}");
  }
}
/// Arguments for the `up` command.
#[derive(Args, Debug, Clone)]
pub struct UpArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
  /// (Re)build the agent image even when its Dockerfile and context are
  /// unchanged; without it a build happens only when missing or stale.
  #[arg(long)]
  pub build: bool,
}

/// Arguments for the `down` command.
#[derive(Args, Debug, Clone)]
pub struct DownArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
}

/// Arguments for the `logs` command.
#[derive(Args, Debug, Clone)]
pub struct LogsArgs {
  /// Workspace directory; defaults to the current directory. A flag rather
  /// than a positional because the service names already take that slot.
  #[arg(long)]
  pub workspace: Option<PathBuf>,
  /// Keep the output open and follow new lines.
  #[arg(long, short = 'f')]
  pub follow: bool,
  /// Print bare log lines, without the service name in front of each one.
  #[arg(long)]
  pub no_log_prefix: bool,
  /// How many lines to show from the end of each service's log; `all` for
  /// everything.
  #[arg(long, default_value = "all")]
  pub tail: String,
  /// Services to read; every service in the stack when none are named.
  #[arg(value_name = "SERVICE")]
  pub services: Vec<String>,
}

/// Arguments for the `init` command.
#[derive(Args, Debug, Clone)]
pub struct InitArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
  /// Capture backend the generated stack runs. Linux only: the backend is
  /// chosen at generation time and defaults to `ebpf`.
  #[arg(long, value_enum)]
  pub backend: Option<ProxyBackend>,
}

/// Arguments for the `agent` command.
#[derive(Args, Debug, Clone)]
pub struct AgentArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
  /// Stop the workspace stack when the shell or command exits; without it the
  /// stack keeps running.
  #[arg(long)]
  pub rm: bool,
  /// (Re)build the agent image even when its Dockerfile and context are
  /// unchanged; without it a build happens only when missing or stale.
  #[arg(long)]
  pub build: bool,
  /// Command to run in the agent instead of the configured shell; the
  /// arguments after `--`.
  #[arg(last = true)]
  pub command: Vec<OsString>,
}

/// `arkham init [--backend <backend>] [workspace]`: write the support files, a
/// stub workspace config when the workspace has none (rules derive at serve
/// time, so the file holds overrides and `[workspace]` keys only), and the
/// workspace stack into `<state-dir>/arkham/ws/<slug>/compose.yml`. That file
/// is generated state. Overrides live in `~/.config/arkham/compose.yaml` or
/// `<workspace>/.config/arkham/compose.yaml`. An existing stack is rewritten
/// when the rendered file would change and left untouched when it matches.
impl CliCommand for InitArgs {
  type Error = Error;
  /// Runs the init generation.
  ///
  /// # Errors
  ///
  /// Returns an error when the host is not Linux, when the workspace cannot be
  /// resolved or its stack generated, or when the registry cannot be loaded.
  async fn run(self, _cli: &Cli, arkham_version: &str) -> Result<(), Self::Error> {
    let workspace = Workspace::resolve(self.workspace.as_deref())?;
    init_workspace(&workspace, resolve_backend(self.backend)?, self.backend.is_some(), arkham_version).await
  }
}

/// `arkham agent [workspace] [-- <command>...]`: the whole workspace lifecycle
/// in one idempotent run — generate what is missing, start the stack, then
/// enter the agent with the configured shell or `<command>`. The stack keeps
/// running when that exits, unless `rm` stops it, so the next call starts at
/// the exec.
impl CliCommand for AgentArgs {
  type Error = Error;
  /// Runs the agent lifecycle.
  ///
  /// # Errors
  ///
  /// Returns an error when the workspace cannot be resolved, generated, or
  /// started, plus when the compose command fails. A failed `rm` teardown is
  /// reported too, because the stack the caller asked to stop is still up.
  async fn run(self, _cli: &Cli, arkham_version: &str) -> Result<(), Self::Error> {
    let workspace = Workspace::resolve(self.workspace.as_deref())?;
    init_workspace(&workspace, resolve_backend(None)?, false, arkham_version).await?;
    up_workspace(&workspace, self.build).await?;
    if !self.rm {
      return exec_agent(&workspace, &self.command).await;
    }
    let exec = {
      let _survive_interrupt = SurviveInterrupt::new();
      exec_agent(&workspace, &self.command).await
    };
    let down = down_workspace(&workspace).await;
    exec?;
    down
  }
}

/// Ignore the terminal's interrupt for as long as it lives, so arkham reaches
/// the `rm` teardown after the agent session ends instead of dying beside it.
///
/// A handler rather than `SIG_IGN`: ignored dispositions survive `exec`, and
/// the agent would then be uninterruptible as well.
struct SurviveInterrupt;

impl SurviveInterrupt {
  #[must_use]
  fn new() -> Self {
    // Safety: the handler only returns, so no work happens inside the signal.
    unsafe { signal(SIGINT, swallow_interrupt as *const () as sighandler_t) };
    Self
  }
}

impl Drop for SurviveInterrupt {
  fn drop(&mut self) {
    // Safety: restores the disposition every process starts with.
    unsafe { signal(SIGINT, SIG_DFL) };
  }
}

extern "C" fn swallow_interrupt(_: c_int) {}

/// `arkham up [workspace]`: start the layered compose project `arkham init`
/// generated, making sure what it mounts exists first.
impl CliCommand for UpArgs {
  type Error = Error;
  /// Starts the stack.
  ///
  /// # Errors
  ///
  /// Returns an error when the workspace cannot be resolved, when the support
  /// files cannot be written, or when the compose command fails.
  async fn run(self, _cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    up_workspace(&Workspace::resolve(self.workspace.as_deref())?, self.build).await
  }
}

/// `arkham down [workspace]`: stop the layered compose project.
impl CliCommand for DownArgs {
  type Error = Error;
  /// Stops the stack.
  ///
  /// # Errors
  ///
  /// Returns an error when the workspace cannot be resolved or when the compose
  /// command fails.
  async fn run(self, _cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    let workspace = Workspace::resolve(self.workspace.as_deref())?;
    down_workspace(&workspace).await?;
    // Stopped publishings free their host ports: dropping the claims here
    // keeps the registry from pinning ports no stack holds. A registry
    // failure only warns — the stack is already down.
    match prune_workspace(&workspace.slug()) {
      Ok(true) => println!("released expose claims for {}", workspace.root().display()),
      Ok(false) => {}
      Err(err) => tracing::warn!(%err, "could not release expose claims"),
    }
    Ok(())
  }
}

/// `arkham logs [workspace]`: read the stack's logs.
impl CliCommand for LogsArgs {
  type Error = Error;
  /// Reads the stack's logs.
  ///
  /// # Errors
  ///
  /// Returns an error when the workspace cannot be resolved or when the compose
  /// command fails.
  async fn run(self, _cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    logs_workspace(&Workspace::resolve(self.workspace.as_deref())?, &self).await
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use crate::test_support::{set_env, unset_env};

  /// Global `compose.yaml` beats `compose.yml`, then the generated file, then the workspace override.
  #[test]
  fn compose_layers_read_global_yaml_or_yml_then_generated_then_workspace() {
    let root = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let previous_config = std::env::var_os("XDG_CONFIG_HOME");
    let previous_state = std::env::var_os("XDG_STATE_HOME");
    set_env("XDG_CONFIG_HOME", xdg.path());
    set_env("XDG_STATE_HOME", state.path());
    let workspace = Workspace::new(root.path());
    let global = xdg.path().join("arkham");
    std::fs::create_dir_all(&global).unwrap();
    let global_yaml = global.join("compose.yaml");
    let global_short = global.join("compose.yml");
    std::fs::write(&global_short, "global: yml\n").unwrap();
    let generated = workspace.state_dir().join("compose.yml");
    std::fs::create_dir_all(generated.parent().unwrap()).unwrap();
    std::fs::write(&generated, "generated: true\n").unwrap();
    let unified = root.path().join(".config").join("arkham");
    std::fs::create_dir_all(&unified).unwrap();
    let workspace_yaml = unified.join("compose.yaml");
    std::fs::write(&workspace_yaml, "workspace: yaml\n").unwrap();

    assert_eq!(
      compose_layers(&workspace),
      vec![global_short.clone(), generated.clone(), workspace_yaml.clone()]
    );

    std::fs::write(&global_yaml, "global: yaml\n").unwrap();
    assert_eq!(
      compose_layers(&workspace),
      vec![global_yaml, generated.clone(), workspace_yaml.clone()],
      "a global compose.yaml hides compose.yml"
    );

    std::fs::remove_file(&workspace_yaml).unwrap();
    let legacy = root.path().join(".config").join("arkham.compose.yml");
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    std::fs::write(&legacy, "legacy: yml\n").unwrap();
    assert_eq!(compose_layers(&workspace).last().unwrap(), &legacy);

    match previous_config {
      Some(value) => set_env("XDG_CONFIG_HOME", value),
      None => unset_env("XDG_CONFIG_HOME"),
    }
    match previous_state {
      Some(value) => set_env("XDG_STATE_HOME", value),
      None => unset_env("XDG_STATE_HOME"),
    }
  }

  #[test]
  fn up_argv_adds_build_only_when_asked() {
    assert_eq!(up_argv(false), vec![OsString::from("up"), OsString::from("-d")]);
    assert_eq!(
      up_argv(true),
      vec![OsString::from("up"), OsString::from("-d"), OsString::from("--build")]
    );
  }

  #[test]
  fn build_digest_follows_the_dockerfile_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let docker = dir.path().join("docker");
    std::fs::create_dir(&docker).unwrap();
    let dockerfile = docker.join("Dockerfile.agent");
    std::fs::write(&dockerfile, "FROM scratch\n").unwrap();
    let build = WorkspaceBuild {
      dockerfile: PathBuf::from("docker/Dockerfile.agent"),
      context: PathBuf::from("docker"),
    };
    let before = build_digest(dir.path(), &build);
    std::fs::write(&dockerfile, "FROM scratch\nRUN true\n").unwrap();
    assert_ne!(build_digest(dir.path(), &build), before, "edited dockerfile rebuilds");
    assert_eq!(
      build_digest(dir.path(), &build),
      build_digest(dir.path(), &build),
      "same tree is stable"
    );
  }
}

#[cfg(test)]
mod moved_suite {

  use crate::confine::*;

  use crate::mounts::*;

  use crate::stack::*;
  use crate::test_support::*;
  use crate::workspace::*;

  #[test]
  fn the_example_workspace_loads_and_inherits_registry_hosts() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/agentic-devenv/.config/arkham/config.toml");
    let cli = Cli {
      config: Some(example.clone()),
    };
    let (config, _) = arkham_config::config::load(&cli, None).unwrap_or_else(|err| panic!("{} does not load: {err}", example.display()));
    assert_eq!(config.workspace.home.as_deref(), Some("/home/eng"));
    assert_eq!(config.workspace.shell.as_deref(), Some("bash"));
    let registry = generation_registry(None).unwrap();
    for (label, env) in [("anthropic", "ANTHROPIC_API_KEY"), ("github", "GH_TOKEN")] {
      let rule = config
        .rules
        .get(label)
        .unwrap_or_else(|| panic!("`{label}` missing from {}", example.display()));
      assert_eq!(rule.env, env);
      assert!(rule.value.is_none(), "`{label}` must resolve from fnox, not carry a value");
      assert!(!registry.hosts_for(rule).is_empty(), "`{label}` needs hosts from the registry");
    }
  }

  #[test]
  fn includes_absorb_overlaps_and_reject_missing() {
    let host_home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let sibling = root.path().join("sibling");
    std::fs::create_dir_all(&sibling).unwrap();

    let layout = Layout::new(root.path(), "/home/eng".to_string(), Some(host_home.path().to_path_buf()));
    let mounts = layout.include_mounts(&[PathBuf::from("sibling:ro")]).unwrap();
    assert_eq!(mounts.len(), 1, "{mounts:?}");
    assert_eq!(mounts[0].host, root.path(), "{mounts:?}");
    assert!(!mounts[0].ro, "{mounts:?}");

    let err = layout.include_mounts(&[PathBuf::from("missing")]).unwrap_err();
    assert!(err.to_string().contains("does not exist"), "{err:?}");
    assert!(err.to_string().contains("missing"), "{err:?}");
  }

  #[test]
  fn fnox_binds_mount_only_what_exists_and_forward_present_credentials() {
    let home = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let fnox_dir = home.path().join(".config").join("fnox");
    std::fs::create_dir_all(&fnox_dir).unwrap();
    std::fs::write(fnox_dir.join("age.txt"), "AGE-SECRET-KEY-1\n").unwrap();
    std::fs::write(
      config_dir.path().join("fnox.toml"),
      "[secrets.X]\nprovider = \"plain\"\nvalue = \"x\"\n",
    )
    .unwrap();
    std::fs::write(config_dir.path().join("config.toml"), "[proxy]\n").unwrap();

    let binds = FnoxBinds::resolve(Some(&fnox_dir), Some(config_dir.path()));
    let rendered: Vec<String> = binds
      .mounts
      .iter()
      .map(|entry| format!("{}:{}:ro", entry.host.display(), entry.container.display()))
      .collect();
    assert_eq!(
      rendered,
      vec![
        format!("{}:/root/.config/fnox:ro", fnox_dir.display()),
        format!(
          "{}:/root/.config/arkham/fnox.toml:ro",
          config_dir.path().join("fnox.toml").display()
        ),
      ],
      "the fnox config directory and arkham's own fnox level, and not the host's arkham config.toml"
    );

    let empty = tempfile::tempdir().unwrap();
    assert!(
      FnoxBinds::resolve(Some(&empty.path().join("missing")), Some(empty.path()))
        .mounts
        .is_empty(),
      "a path that is not there is never mounted: docker would create a directory in its place"
    );

    // Credentials in the shell are not the proxy's business: whatever the
    // environment carries, the generated stack forwards nothing.
    let key = "BWS_ACCESS_TOKEN";
    let previous = std::env::var_os(key);
    set_env(key, "0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let yaml = Stack {
      fnox: FnoxBinds::resolve(None, None),
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(!yaml.contains("${"), "no environment interpolation survives generation: {yaml}");
    assert!(!yaml.contains(key), "the credential name is not forwarded either: {yaml}");
    assert!(
      !yaml.contains("0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
      "the value must not be written"
    );
    match previous {
      Some(value) => set_env(key, value),
      None => unset_env(key),
    }
  }

  #[test]
  fn rules_d_overrides_mount_into_the_arkham_service() {
    let config_dir = tempfile::tempdir().unwrap();
    let rules_d = config_dir.path().join("rules.d");
    std::fs::create_dir_all(&rules_d).unwrap();
    std::fs::write(
      rules_d.join("gitea.toml"),
      "[names.GITEA_TOKEN]\nhosts = [\"https://code.lotsa.ai\"]\n",
    )
    .unwrap();

    let binds = FnoxBinds::resolve(None, Some(config_dir.path()));
    let rendered: Vec<String> = binds
      .mounts
      .iter()
      .map(|entry| format!("{}:{}:ro", entry.host.display(), entry.container.display()))
      .collect();
    assert_eq!(
      rendered,
      vec![format!("{}:/root/.config/arkham/rules.d:ro", rules_d.display())],
      "serve derives rules from the registry in-container, so the global rules.d must be in view"
    );
  }

  #[test]
  fn support_files_are_written_when_absent_and_stale_entrypoints_regenerate() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let entrypoint = dir.path().join("agent-entrypoint.sh");
    let storage = dir.path().join("state").join("containers");

    let files = ensure_support_files(dir.path(), &storage).unwrap();
    assert!(files.iter().all(|(_, created)| *created), "{files:?}");
    let pem = std::fs::read_to_string(dir.path().join("ca.pem")).unwrap();
    let crt = std::fs::read_to_string(dir.path().join("ca.crt")).unwrap();
    let key = std::fs::read_to_string(dir.path().join("ca.key")).unwrap();
    assert!(entrypoint.is_file());
    assert!(storage.is_dir(), "storage belongs to the workspace state, not the config dir");
    assert!(
      !dir.path().join("agent-containers").exists(),
      "no storage under the config dir: {files:?}"
    );
    // `ca.pem` is what arkham reads; `ca.crt` is the certificate alone, which is
    // what the agent gets. A clean system needs both.
    assert!(
      pem.contains("BEGIN CERTIFICATE") && pem.contains("PRIVATE KEY"),
      "ca.pem carries both halves"
    );
    assert!(
      crt.contains("BEGIN CERTIFICATE") && !crt.contains("PRIVATE KEY"),
      "ca.crt carries the certificate only"
    );
    assert!(
      key.contains("PRIVATE KEY") && !key.contains("CERTIFICATE"),
      "ca.key carries the key only"
    );
    let script = std::fs::read_to_string(&entrypoint).unwrap();
    assert!(
      script.contains("update-ca-certificates"),
      "the entrypoint installs the CA into the system store"
    );
    assert!(
      script.contains("${ARKHAM_INIT:-}") && script.contains("docker-entrypoint.sh"),
      "the entrypoint chains to the image's init: ARKHAM_INIT first, common names next"
    );
    assert!(script.contains("exec \"$@\""), "the entrypoint hands off to the command");
    assert!(
      script.contains("${ARKHAM_EBPF_BYPASS_FILE:-}") && script.contains("podman network inspect"),
      "the entrypoint publishes podman subnets for arkham's bypass list when the stack wires the file"
    );
    assert_ne!(
      std::fs::metadata(&entrypoint).unwrap().permissions().mode() & 0o111,
      0,
      "the agent runs the entrypoint directly, so it must be executable"
    );

    std::fs::write(&entrypoint, "#!/bin/sh\necho mine\n").unwrap();
    std::fs::remove_file(dir.path().join("ca.pem")).unwrap();
    let files = ensure_support_files(dir.path(), &storage).unwrap();
    let created: BTreeMap<&str, bool> = files
      .iter()
      .map(|(path, created)| (path.file_name().unwrap().to_str().unwrap(), *created))
      .collect();
    assert_eq!(
      created.get("agent-entrypoint.sh"),
      Some(&false),
      "an edited entrypoint is replaced, not created anew"
    );
    assert_eq!(created.get("ca.pem"), Some(&true), "a deleted CA comes back");
    assert_eq!(
      std::fs::read_to_string(&entrypoint).unwrap(),
      ENTRYPOINT_SCRIPT,
      "a stale or edited entrypoint is regenerated"
    );
  }

  #[test]
  fn workspace_init_names_the_agent_images_init_script() {
    let yaml = Stack {
      init: Some("/usr/local/bin/devagent-entrypoint".to_string()),
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(
      yaml.contains("      ARKHAM_INIT: \"/usr/local/bin/devagent-entrypoint\"\n"),
      "the entrypoint chains to the image's init through ARKHAM_INIT: {yaml}"
    );
  }

  #[test]
  fn the_backend_defaults_to_ebpf_on_linux_and_none_is_refused() {
    #[cfg(target_os = "linux")]
    assert_eq!(resolve_backend(None).unwrap(), ProxyBackend::Ebpf);
    #[cfg(not(target_os = "linux"))]
    assert!(resolve_backend(None).is_err(), "no capture backend exists outside Linux");

    assert_eq!(resolve_backend(Some(ProxyBackend::Tun)).unwrap(), ProxyBackend::Tun);
    let err = resolve_backend(Some(ProxyBackend::None)).unwrap_err();
    assert!(err.to_string().contains("none"), "{err:?}");
  }

  /// `init` writes the workspace config once and never overwrites it: a stack
  /// that cannot substitute anything is worse than no stack, and an edited
  /// rules file is the user's.
  #[test]
  fn the_workspace_config_is_written_once_and_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".config").join("arkham.toml");

    assert!(write_if_absent(&path, "[rules.x]\n").unwrap(), "first write lands");
    assert!(
      !write_if_absent(&path, "something else\n").unwrap(),
      "an existing file is left alone"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "[rules.x]\n");
  }

  /// Pin cwd, XDG, and fnox discovery so host config cannot leak into generation.
  struct GenerationPin {
    _env: AmbientEnv,
    previous_cwd: std::path::PathBuf,
    previous_state: Option<std::ffi::OsString>,
  }

  impl GenerationPin {
    fn enter(root: &std::path::Path, home: &std::path::Path, xdg: &std::path::Path, state: &std::path::Path) -> Self {
      let previous_state = std::env::var_os("XDG_STATE_HOME");
      let env = AmbientEnv::isolate(home, xdg);
      unset_env("FNOX_CONFIG_DIR");
      unset_env("FNOX_PROFILE");
      set_env("XDG_STATE_HOME", state);
      let previous_cwd = std::env::current_dir().unwrap();
      std::env::set_current_dir(root).unwrap();
      Self {
        _env: env,
        previous_cwd,
        previous_state,
      }
    }
  }

  impl Drop for GenerationPin {
    fn drop(&mut self) {
      std::env::set_current_dir(&self.previous_cwd).unwrap();
      match self.previous_state.take() {
        Some(value) => set_env("XDG_STATE_HOME", value),
        None => unset_env("XDG_STATE_HOME"),
      }
    }
  }

  fn compose_path(root: &std::path::Path) -> std::path::PathBuf {
    Workspace::new(root).state_dir().join("compose.yml")
  }

  fn write_workspace_config(root: &std::path::Path, body: &str) {
    let path = root.join(".config").join("arkham").join("config.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
  }

  /// Same rendered bytes leave the file's content and mtime alone, and no digest is written.
  #[tokio::test]
  async fn init_workspace_leaves_an_identical_compose_file_untouched() {
    let root = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let _pin = GenerationPin::enter(root.path(), home.path(), xdg.path(), state.path());
    write_workspace_config(root.path(), "[workspace]\nname = \"kept\"\n");
    let workspace = Workspace::new(root.path());
    init_workspace(&workspace, ProxyBackend::Tun, true, "0.0.0-a").await.unwrap();
    let compose = compose_path(root.path());
    let body = std::fs::read_to_string(&compose).unwrap();
    let file = std::fs::File::options().write(true).open(&compose).unwrap();
    let stamp = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    file.set_modified(stamp).unwrap();
    drop(file);
    let config = root.path().join(".config").join("arkham").join("config.toml");
    std::fs::write(&config, "[workspace]\nname = \"kept\"\n# comment only\n").unwrap();
    init_workspace(&workspace, ProxyBackend::Tun, true, "0.0.0-a").await.unwrap();
    assert_eq!(std::fs::read_to_string(&compose).unwrap(), body);
    assert_eq!(std::fs::metadata(&compose).unwrap().modified().unwrap(), stamp);
    assert!(!workspace.state_dir().join("config.digest").exists());
  }

  /// A render change rewrites the file. An unnamed backend stays the one already rendered.
  #[tokio::test]
  async fn init_workspace_rewrites_compose_when_the_render_changes() {
    let root = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let _pin = GenerationPin::enter(root.path(), home.path(), xdg.path(), state.path());
    std::fs::write(
      root.path().join("fnox.toml"),
      "[secrets.GITHUB_TOKEN]\ndefault = \"not-the-decoy\"\n",
    )
    .unwrap();
    std::fs::write(root.path().join("notes.txt"), "plain\n").unwrap();
    write_workspace_config(root.path(), "[workspace]\nname = \"kept\"\n");
    let workspace = Workspace::new(root.path());
    init_workspace(&workspace, ProxyBackend::Tun, true, "0.0.0-a").await.unwrap();
    let compose = compose_path(root.path());
    let first = std::fs::read_to_string(&compose).unwrap();
    assert!(first.contains("ghcr.io/lotsaai/arkham:0.0.0-a"), "{first}");
    assert!(first.contains("\"--proxy-backend\", \"tun\""), "{first}");
    assert!(first.contains("name: kept"), "{first}");
    assert!(first.contains("GITHUB_TOKEN:"), "{first}");
    assert!(!first.contains("ghp_named_"), "{first}");
    assert!(!workspace.state_dir().join("config.digest").exists());

    init_workspace(&workspace, ProxyBackend::Tun, true, "0.0.0-b").await.unwrap();
    let versioned = std::fs::read_to_string(&compose).unwrap();
    assert_ne!(versioned, first);
    assert!(versioned.contains("ghcr.io/lotsaai/arkham:0.0.0-b"), "{versioned}");
    assert!(versioned.contains("\"--proxy-backend\", \"tun\""), "{versioned}");

    write_workspace_config(root.path(), "[workspace]\nname = \"renamed\"\n");
    init_workspace(&workspace, ProxyBackend::Tun, true, "0.0.0-b").await.unwrap();
    let renamed = std::fs::read_to_string(&compose).unwrap();
    assert!(renamed.contains("name: renamed"), "{renamed}");
    assert!(!renamed.contains("name: kept"), "{renamed}");

    let rules = root.path().join(".config").join("arkham").join("rules.d");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
      rules.join("10-github.toml"),
      "[names.GITHUB_TOKEN]\npattern = \"ghp_named_{hex:32}\"\n",
    )
    .unwrap();
    init_workspace(&workspace, ProxyBackend::Tun, true, "0.0.0-b").await.unwrap();
    let patterned = std::fs::read_to_string(&compose).unwrap();
    assert!(patterned.contains("ghp_named_"), "{patterned}");

    write_workspace_config(
      root.path(),
      "[workspace]\nname = \"renamed\"\n\n[[workspace.file_rewrite]]\nsource = \"notes.txt\"\ndest = \"/opt/rewritten.txt\"\n",
    );
    init_workspace(&workspace, ProxyBackend::Tun, true, "0.0.0-b").await.unwrap();
    let rewritten = std::fs::read_to_string(&compose).unwrap();
    assert!(rewritten.contains("/opt/rewritten.txt"), "{rewritten}");

    init_workspace(&workspace, ProxyBackend::Ebpf, true, "0.0.0-b").await.unwrap();
    let ebpf = std::fs::read_to_string(&compose).unwrap();
    assert!(ebpf.contains("\"--proxy-backend\", \"ebpf\""), "{ebpf}");
    assert!(!ebpf.contains("\"--proxy-backend\", \"tun\""), "{ebpf}");

    write_workspace_config(
      root.path(),
      "[workspace]\nname = \"renamed\"\ninit = \"/bin/from-config\"\n\n[[workspace.file_rewrite]]\nsource = \"notes.txt\"\ndest = \"/opt/rewritten.txt\"\n",
    );
    init_workspace(&workspace, ProxyBackend::Tproxy, false, "0.0.0-b").await.unwrap();
    let preserved = std::fs::read_to_string(&compose).unwrap();
    assert!(preserved.contains("ARKHAM_INIT: \"/bin/from-config\""), "{preserved}");
    assert!(preserved.contains("\"--proxy-backend\", \"ebpf\""), "{preserved}");
    assert!(!preserved.contains("\"--proxy-backend\", \"tproxy\""), "{preserved}");
  }

  /// A regeneration must not switch how traffic is captured: the backend is
  /// read back off the compose file, and the caller's default is only a
  /// fallback.
  #[test]
  fn the_generated_stack_reports_its_backend() {
    assert_eq!(
      generated_backend("      command: [\"serve\", \"--proxy-backend\", \"tun\"]\n"),
      Some(ProxyBackend::Tun)
    );
    assert_eq!(generated_backend("\"--proxy-backend\", \"ebpf\""), Some(ProxyBackend::Ebpf));
    assert_eq!(generated_backend("\"--proxy-backend\", \"tproxy\""), Some(ProxyBackend::Tproxy));
    assert_eq!(
      generated_backend("command: [\"serve\"]\n"),
      None,
      "a stack that names no backend keeps the caller's"
    );
  }

  /// Zero rules with nothing derivable answers every provider with a decoy:
  /// it has to be said out loud rather than served silently. A derivable
  /// name substitutes on its own, so it silences the warning.
  #[test]
  fn serving_no_rules_and_nothing_derivable_is_announced() {
    let warning = rules_warning(&BTreeMap::new(), &[]).expect("no rules and nothing derivable is worth a warning");
    assert!(warning.contains("no [rules.*]") && warning.contains("nothing derives"), "{warning}");

    let rules = BTreeMap::from([(
      "github".to_string(),
      toml_edit::de::from_str::<RuleCfg>("env = \"GH_TOKEN\"\n").unwrap(),
    )]);
    assert!(rules_warning(&rules, &[]).is_none(), "one rule is enough not to warn");
    assert!(
      rules_warning(&BTreeMap::new(), &["GITEA_TOKEN".to_string()]).is_none(),
      "a derivable name substitutes without any config rule"
    );
  }

  /// The flags map one-to-one onto compose's and services ride at the end: a
  /// wrong order here is a silently different log view, not an error.
  #[test]
  fn the_logs_command_maps_onto_compose_flags() {
    let bare = logs_argv(&LogsArgs {
      workspace: None,
      follow: false,
      no_log_prefix: false,
      tail: "all".into(),
      services: Vec::new(),
    });
    assert_eq!(bare, vec![OsString::from("logs"), OsString::from("--tail"), OsString::from("all")]);

    let full = logs_argv(&LogsArgs {
      workspace: Some(PathBuf::from("/srv/project")),
      follow: true,
      no_log_prefix: true,
      tail: "10".into(),
      services: vec!["arkham".into(), "agent".into()],
    });
    assert_eq!(
      full,
      ["logs", "--follow", "--no-log-prefix", "--tail", "10", "arkham", "agent"]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>()
    );
  }
}
