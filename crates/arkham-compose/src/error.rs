//! Crate error type: every fallible API returns `Result<T, Error>`.

use std::io::Error as IoError;
use std::path::PathBuf;

use arkham_config::Error as ConfigError;
use arkham_config::config::RewriteFormat;
use arkham_fnox::Error as FnoxError;
use kube_client::config::KubeconfigError;
use serde_json::Error as JsonError;
use serde_yaml::Error as YamlError;
use toml::de::Error as TomlDeError;
use toml::ser::Error as TomlSerializeError;
use toml_edit::TomlError;

/// Every way stack generation and workspace commands can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A `arkham-config` error passes through.
  #[error(transparent)]
  Config(Box<ConfigError>),
  /// A `arkham-fnox` error passes through.
  #[error(transparent)]
  Fnox(Box<FnoxError>),
  /// A `arkham-pki` error passes through.
  #[error(transparent)]
  Pki(#[from] arkham_pki::Error),
  /// An I/O failure with no extra context.
  #[error(transparent)]
  Io(#[from] IoError),
  /// A `[workspace] include` entry does not exist.
  #[error("[workspace] include `{}` does not exist; docker would mount an empty directory in its place", entry.display())]
  IncludeMissing {
    /// Missing entry.
    entry: PathBuf,
  },
  /// A `[workspace] include` entry would mount a wider tree than the project.
  #[error("[workspace] include `{}` widens the workspace", entry.display())]
  IncludeWidens {
    /// Entry that was refused.
    entry: PathBuf,
  },
  /// The arkham config directory does not resolve.
  #[error("{detail}")]
  ConfigDir {
    /// What needs the directory.
    detail: String,
  },
  /// The guest identity CA does not load.
  #[error("guest identity CA `{}`: {source}", path.display())]
  GuestCa {
    /// CA file.
    path: PathBuf,
    /// Underlying load failure.
    #[source]
    source: arkham_pki::Error,
  },
  /// A file cannot be read.
  #[error("read {}: {source}", path.display())]
  ReadFile {
    /// File that could not be read.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A file cannot be written.
  #[error("write {}: {source}", path.display())]
  WriteFile {
    /// File that could not be written.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A stale generated file cannot be pruned.
  #[error("remove {}: {source}", path.display())]
  RemoveFile {
    /// File that could not be removed.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A directory cannot be created.
  #[error("create {}: {source}", path.display())]
  CreateDir {
    /// Directory that could not be created.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A grant fragment fails to serialize.
  #[error("serializing a grant fragment: {source}")]
  SerializeFragment {
    /// Underlying serialization failure.
    #[source]
    source: TomlSerializeError,
  },
  /// A decoy document fails to serialize.
  #[error("serializing a decoy document: {source}")]
  SerializeDecoy {
    /// Underlying serialization failure.
    #[source]
    source: YamlError,
  },
  /// A config value does not expand.
  #[error("failed to expand config value: {detail}")]
  ExpandValue {
    /// Expansion failure, Debug-rendered (xpanda reports no std error).
    detail: String,
  },
  /// A fnox secret resolves to no value.
  #[error("fnox secret `{name}` resolved to no value")]
  SecretNoValue {
    /// Secret name.
    name: String,
  },
  /// A passthrough name is also a rule env.
  #[error("[workspace] passthrough `{name}` is also a [rules.*] env: pick one path")]
  PassthroughOverlapRule {
    /// Offending name.
    name: String,
  },
  /// A passthrough name overlaps a selected decoy.
  #[error("[workspace] passthrough `{name}` overlaps a selected decoy: pick one path")]
  PassthroughOverlapDecoy {
    /// Offending name.
    name: String,
  },
  /// `[workspace] image` names an empty tag.
  #[error("[workspace] image is empty: name a tag or drop the key for the default")]
  EmptyImage,
  /// `[workspace.build]` names a dockerfile that does not exist.
  #[error("[workspace.build] dockerfile `{}` does not exist", path.display())]
  BuildDockerfileMissing {
    /// Missing dockerfile.
    path: PathBuf,
  },
  /// `[workspace.build]` names a context directory that does not exist.
  #[error("[workspace.build] context `{}` does not exist", path.display())]
  BuildContextMissing {
    /// Missing context directory.
    path: PathBuf,
  },
  /// `--build` without a `[workspace.build]` to build.
  #[error("--build names no [workspace.build]: add the section or drop the flag")]
  BuildNotConfigured,
  /// A file rewrite names an env with no known real value.
  #[error("file rewrite `{}` names `{name}` with no known real value", file.display())]
  RewriteNoValue {
    /// Rewrite source.
    file: PathBuf,
    /// Env name.
    name: String,
  },
  /// A file rewrite names an env with no decoy.
  #[error("file rewrite `{}` names `{name}` with no decoy", file.display())]
  RewriteNoDecoy {
    /// Rewrite source.
    file: PathBuf,
    /// Env name.
    name: String,
  },
  /// A file rewrite dest is not an absolute container path.
  #[error("file rewrite dest `{dest}` does not expand to an absolute container path")]
  RewriteDestNotAbsolute {
    /// Offending dest.
    dest: String,
  },
  /// An adapted rewrite names envs: the file is the source, drop `envs`.
  #[error("file rewrite `{}` states format `{format}`: the file is the source, drop `envs`", file.display())]
  RewriteWithEnvs {
    /// Rewrite source.
    file: PathBuf,
    /// The format that took the adapter path.
    format: RewriteFormat,
  },
  /// A kubeconfig document failed to parse or merge.
  #[error("file rewrite `{}`: kubeconfig: {source}", file.display())]
  Kubeconfig {
    /// Rewrite source.
    file: PathBuf,
    /// Underlying kubeconfig failure.
    #[source]
    source: Box<KubeconfigError>,
  },
  /// An adapted rewrite is not valid YAML.
  #[error("file rewrite `{}`: does not parse as YAML: {source}", file.display())]
  RewriteYaml {
    /// Rewrite source.
    file: PathBuf,
    /// Underlying parse failure.
    #[source]
    source: YamlError,
  },
  /// An adapted rewrite does not map onto a grant.
  #[error("file rewrite `{}`: invalid {format}: {detail}", file.display())]
  RewriteInvalid {
    /// Rewrite source.
    file: PathBuf,
    /// The format that took the adapter path.
    format: RewriteFormat,
    /// What fails to map.
    detail: String,
  },
  /// A NATS decoy user seed could not be minted. The nkeys error is dropped
  /// because it can echo the seed.
  #[error("nats decoy seed could not be minted")]
  NatsDecoy,
  /// An ambient derivation source does not map onto grants or a decoy twin.
  #[error("derived source `{}`: {detail}", file.display())]
  SourceInvalid {
    /// The source file the derivation read.
    file: PathBuf,
    /// What fails to map.
    detail: String,
  },
  /// A mise file does not parse.
  #[error("parse mise.local.toml: {source}")]
  MiseParse {
    /// Underlying parse failure.
    #[source]
    source: TomlError,
  },
  /// A workspace cannot be resolved.
  #[error("resolve workspace {}: {source}", path.display())]
  ResolveWorkspace {
    /// Workspace that could not be resolved.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The host refuses stack generation.
  #[error("arkham init supports Linux only: there is no capture backend for this host")]
  LinuxOnly,
  /// `--backend none` cannot generate a stack.
  #[error("`--backend none` is not valid for init: the generated stack needs a capture backend")]
  BackendNone,
  /// No compose layers exist.
  #[error("no compose layers for {}; run `arkham init` first or create one of the layer files", root.display())]
  NoComposeLayers {
    /// Workspace root.
    root: PathBuf,
  },
  /// docker compose does not spawn.
  #[error("spawn docker compose: {source}")]
  SpawnCompose {
    /// Underlying spawn failure.
    #[source]
    source: IoError,
  },
  /// docker compose exits non-zero.
  #[error("docker compose failed: {status}")]
  ComposeFailed {
    /// Exit status.
    status: String,
  },
  /// A file mode cannot be set.
  #[error("chmod {}: {source}", path.display())]
  ChmodFile {
    /// File whose mode could not be set.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A `[tools.*]` name is not a plain directory name.
  #[error("[tools.{name}] is not a plain directory name to mount")]
  ToolNameInvalid {
    /// Offending tool name.
    name: String,
  },
  /// A `[tools.*]` `config_dir` is not an absolute container path.
  #[error("[tools.{name}] config_dir `{template}` does not expand to an absolute container path")]
  ToolConfigNotAbsolute {
    /// Tool name.
    name: String,
    /// Offending template.
    template: String,
  },
  /// The expose registry does not parse.
  #[error("read the expose registry: {source}")]
  ExposeRegistry {
    /// Underlying parse failure.
    #[source]
    source: JsonError,
  },
  /// An expose claim does not serialize.
  #[error("writing the expose registry: {source}")]
  SerializeExpose {
    /// Underlying serialization failure.
    #[source]
    source: JsonError,
  },
  /// A host port is already exposed by another workspace.
  #[error("host port {host} is already exposed by workspace {workspace} ({root}); rerun with `--host`", root = root.display())]
  ExposeInUse {
    /// Contested host port.
    host: u16,
    /// Owning workspace slug.
    workspace: String,
    /// Owning workspace root.
    root: PathBuf,
    /// Owning container port.
    port: u16,
  },
  /// The project config does not parse.
  #[error("parse {}: {source}", path.display())]
  ExposeConfigParse {
    /// Config file that could not be parsed.
    path: PathBuf,
    /// Underlying parse failure.
    #[source]
    source: TomlError,
  },
  /// The project config's `expose` is not `[[workspace.expose]]` tables.
  #[error("parse {}: `expose` must be `[[workspace.expose]]` tables with `port` and `host`; fix or drop it", path.display())]
  ExposeConfigType {
    /// Offending config file.
    path: PathBuf,
  },
  /// The published port does not verify after `up`.
  #[error("verify 127.0.0.1:{host}: `docker compose port arkham {port}` {status}")]
  ExposeVerify {
    /// Host port that should be bound.
    host: u16,
    /// Container port it should reach.
    port: u16,
    /// Compose exit status.
    status: String,
  },
  /// `expose` without a port or `--list` names nothing to do.
  #[error("`arkham expose` needs a container port or `--list`")]
  ExposeNoPort,
  /// The host wrapper found no daemon socket.
  #[error("no host daemon is running")]
  NoDaemon,
  /// `--isolate bwrap` was asked for on a system other than Linux.
  #[error("the host backend runs on Linux")]
  HostLinuxOnly,
  /// Host path translation needs a home directory.
  #[error("home directory is unset")]
  NoHome,
  /// The pid's start time changed, or the process is not in the session cgroup.
  #[error("session identity changed before the cgroup was confirmed")]
  SessionReused,
  /// The process cgroup does not allow a session child to be created.
  #[error("session cgroup {} cannot be created: {source}", path.display())]
  SessionCgroup {
    /// Directory that could not be created or written.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A socket path or a directory created for it is not owned by this user.
  #[error("daemon socket is not owned by this user")]
  SocketOwner,
  /// `$XDG_RUNTIME_DIR` is unset, missing, or not private to this user.
  #[error("XDG_RUNTIME_DIR is unset or not private")]
  RuntimeDir,
  /// `/proc/<pid>/stat` did not contain a start time.
  #[error("process {pid} has no start time")]
  NoStarttime {
    /// Process id that could not be identified.
    pid: u32,
  },
  /// `/proc/<pid>/cgroup` had no cgroup v2 line.
  #[error("process {pid} has no cgroup")]
  NoCgroup {
    /// Process id whose cgroup could not be read.
    pid: u32,
  },
  /// The daemon sent a rejection.
  #[error("daemon rejected the session: {detail}")]
  DaemonRejected {
    /// Message the daemon sent.
    detail: String,
  },
  /// The control client is a different user from the daemon.
  #[error("control client is not the daemon user")]
  ControlUnauthorized,
  /// The peer is already inside a daemon cgroup.
  #[error("a confined process cannot register")]
  AlreadyConfined,
  /// A control message exceeded the cap or was not the expected JSON.
  #[error("control message is not valid")]
  ControlMessage {
    /// Why the message was rejected.
    #[source]
    source: JsonError,
  },
  /// A control message was larger than the cap, or the socket closed mid-read.
  #[error("control message exceeds 1 MiB or ended early")]
  ControlLimit,
  /// A grant fragment does not parse as rules.
  #[error("grant fragment does not parse")]
  FragmentParse {
    /// Underlying parse failure.
    #[source]
    source: TomlDeError,
  },
  /// The session temp directory is missing or not private to this user.
  #[error("session tmp is not a private directory")]
  SessionTmp {
    /// Why the directory was rejected.
    #[source]
    source: IoError,
  },
  /// Landlock could not open a path it was asked to grant.
  #[cfg(target_os = "linux")]
  #[error("landlock path {path}", path = path.display())]
  LandlockPath {
    /// Path that could not be opened.
    path: PathBuf,
    /// Underlying open failure.
    #[source]
    source: landlock::PathFdError,
  },
  /// Landlock rejected the ruleset.
  #[cfg(target_os = "linux")]
  #[error("landlock restriction failed")]
  Landlock {
    /// Underlying ruleset failure.
    #[source]
    source: landlock::RulesetError,
  },
  /// Landlock applied nothing, or only part of the ruleset.
  #[cfg(target_os = "linux")]
  #[error("landlock did not enforce the profile")]
  LandlockIncomplete,
}

impl Error {
  /// Text a wrapper may print.
  ///
  /// Original paths and secret material stay in the operator log.
  #[must_use]
  pub fn registration_detail(&self) -> String {
    if self.registration_keeps_display() {
      return self.to_string();
    }
    self.registration_summary().to_string()
  }

  fn registration_keeps_display(&self) -> bool {
    matches!(
      self,
      Self::SessionCgroup { .. }
        | Self::SessionReused
        | Self::RuntimeDir
        | Self::SocketOwner
        | Self::NoDaemon
        | Self::AlreadyConfined
        | Self::ControlUnauthorized
        | Self::NoStarttime { .. }
        | Self::NoCgroup { .. }
        | Self::HostLinuxOnly
        | Self::SessionTmp { .. }
    )
  }

  fn registration_summary(&self) -> &'static str {
    match self {
      Self::Config(_)
      | Self::Fnox(_)
      | Self::Pki(_)
      | Self::IncludeMissing { .. }
      | Self::IncludeWidens { .. }
      | Self::ConfigDir { .. }
      | Self::GuestCa { .. }
      | Self::ReadFile { .. }
      | Self::ExpandValue { .. }
      | Self::SecretNoValue { .. }
      | Self::PassthroughOverlapRule { .. }
      | Self::PassthroughOverlapDecoy { .. }
      | Self::EmptyImage
      | Self::BuildDockerfileMissing { .. }
      | Self::BuildContextMissing { .. }
      | Self::BuildNotConfigured
      | Self::RewriteNoValue { .. }
      | Self::RewriteNoDecoy { .. }
      | Self::RewriteDestNotAbsolute { .. }
      | Self::RewriteWithEnvs { .. }
      | Self::Kubeconfig { .. }
      | Self::RewriteYaml { .. }
      | Self::RewriteInvalid { .. }
      | Self::SourceInvalid { .. }
      | Self::MiseParse { .. }
      | Self::ResolveWorkspace { .. }
      | Self::ToolNameInvalid { .. }
      | Self::ToolConfigNotAbsolute { .. }
      | Self::ExposeConfigParse { .. }
      | Self::ExposeConfigType { .. }
      | Self::FragmentParse { .. } => "configuration could not be read",
      Self::Io(_)
      | Self::WriteFile { .. }
      | Self::RemoveFile { .. }
      | Self::CreateDir { .. }
      | Self::SerializeFragment { .. }
      | Self::SerializeDecoy { .. }
      | Self::SerializeExpose { .. }
      | Self::ChmodFile { .. } => "session files could not be prepared",
      Self::NatsDecoy
      | Self::LinuxOnly
      | Self::BackendNone
      | Self::NoComposeLayers { .. }
      | Self::SpawnCompose { .. }
      | Self::ComposeFailed { .. }
      | Self::ExposeRegistry { .. }
      | Self::ExposeInUse { .. }
      | Self::ExposeVerify { .. }
      | Self::ExposeNoPort
      | Self::NoHome
      | Self::DaemonRejected { .. }
      | Self::ControlMessage { .. }
      | Self::ControlLimit
      | Self::SessionCgroup { .. }
      | Self::SessionReused
      | Self::RuntimeDir
      | Self::SocketOwner
      | Self::NoDaemon
      | Self::AlreadyConfined
      | Self::ControlUnauthorized
      | Self::NoStarttime { .. }
      | Self::NoCgroup { .. }
      | Self::HostLinuxOnly
      | Self::SessionTmp { .. } => "registration failed",
      #[cfg(target_os = "linux")]
      Self::LandlockPath { .. } | Self::Landlock { .. } | Self::LandlockIncomplete => "landlock did not enforce the profile",
    }
  }
}

impl From<ConfigError> for Error {
  fn from(source: ConfigError) -> Self {
    Self::Config(Box::new(source))
  }
}

impl From<FnoxError> for Error {
  fn from(source: FnoxError) -> Self {
    Self::Fnox(Box::new(source))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn a_fragment_parse_failure_names_neither_the_file_nor_the_secret() {
    let source = toml::from_str::<toml::Value>("MARKER_SECRET [").unwrap_err();
    let err = Error::FragmentParse { source };
    let text = err.registration_detail();
    assert_eq!(text, "configuration could not be read");
    assert!(!text.contains("MARKER_SECRET"));
  }

  #[test]
  fn a_missing_secret_name_does_not_reach_the_wrapper() {
    let err = Error::SecretNoValue {
      name: "MARKER_SECRET".to_string(),
    };
    assert_eq!(err.registration_detail(), "configuration could not be read");
  }

  #[test]
  fn a_cgroup_denial_keeps_the_directory_and_the_os_error() {
    let err = Error::SessionCgroup {
      path: PathBuf::from("/sys/fs/cgroup/arkham-host"),
      source: std::io::Error::from_raw_os_error(13),
    };
    let text = err.registration_detail();
    assert!(text.contains("/sys/fs/cgroup/arkham-host"), "{text}");
    assert!(text.to_ascii_lowercase().contains("permission denied"), "{text}");
  }

  #[test]
  fn a_private_runtime_failure_keeps_its_own_sentence() {
    assert_eq!(Error::RuntimeDir.registration_detail(), "XDG_RUNTIME_DIR is unset or not private");
  }

  #[test]
  fn a_shared_session_tmp_keeps_its_own_sentence() {
    let err = Error::SessionTmp {
      source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "mode"),
    };
    assert_eq!(err.registration_detail(), "session tmp is not a private directory");
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn a_landlock_failure_names_neither_a_path_nor_a_weaker_mode() {
    assert_eq!(
      Error::LandlockIncomplete.registration_detail(),
      "landlock did not enforce the profile"
    );
  }
}
