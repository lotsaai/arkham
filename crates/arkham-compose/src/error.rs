//! Crate error type: every fallible API returns `Result<T, Error>`.

use std::io::Error as IoError;
use std::path::PathBuf;

use arkham_config::Error as ConfigError;
use arkham_config::config::RewriteFormat;
use arkham_fnox::Error as FnoxError;
use serde_json::Error as JsonError;
use serde_yaml::Error as YamlError;
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
  /// The context named by `context.txt` did not become a grant.
  #[error("selected nats context `{}`: {skip}", file.display())]
  NatsSelected {
    /// The context file.
    file: PathBuf,
    /// Why that context was left out.
    #[source]
    skip: crate::nats::NatsSkip,
  },
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
