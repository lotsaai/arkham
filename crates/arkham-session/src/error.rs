//! Session preparation errors.

use arkham_config::Error as ConfigError;
use arkham_config::config::RewriteFormat;
use arkham_fnox::Error as FnoxError;
use std::io::Error as IoError;
use std::path::PathBuf;
use toml::de::Error as TomlDeError;

/// A session could not be prepared.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A shared tool configuration error.
  #[error(transparent)]
  ToolConfig(#[from] arkham_tool_config::Error),
  /// Git adaptation failed.
  #[error(transparent)]
  Git(#[from] arkham_tool_git::Error),
  /// SSH adaptation failed.
  #[error(transparent)]
  Ssh(#[from] arkham_tool_ssh::Error),
  /// NATS adaptation failed.
  #[error(transparent)]
  Nats(#[from] arkham_tool_nats::Error),
  /// Kubernetes adaptation failed.
  #[error(transparent)]
  Kube(#[from] arkham_tool_kube::Error),
  /// Talos adaptation failed.
  #[error(transparent)]
  Talos(#[from] arkham_tool_talos::Error),
  /// Profile mount selection failed.
  #[error(transparent)]
  Profiles(#[from] arkham_profiles::Error),
  /// Workspace input preparation failed.
  #[error(transparent)]
  Workspace(#[from] arkham_workspace::Error),
  /// Filesystem projection failed.
  #[error(transparent)]
  Projection(#[from] arkham_projection::Error),
  /// A `arkham-config` error passes through.
  #[error(transparent)]
  Config(Box<ConfigError>),
  /// A `arkham-fnox` error passes through.
  #[error(transparent)]
  Fnox(Box<FnoxError>),
  /// An I/O failure with no extra context.
  #[error(transparent)]
  Io(#[from] IoError),
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
  /// A file mode cannot be set.
  #[error("chmod {}: {source}", path.display())]
  ChmodFile {
    /// File whose mode could not be set.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// Host path translation needs a home directory.
  #[error("home directory is unset")]
  NoHome,
  /// A grant fragment does not parse as rules.
  #[error("grant fragment does not parse")]
  FragmentParse {
    /// Underlying parse failure.
    #[source]
    source: TomlDeError,
  },
  /// A grant blob directory could not be encoded.
  #[error("grant blob directory could not be encoded")]
  FragmentPathEncoding {
    /// Directory whose encoded path was invalid.
    path: PathBuf,
  },
}

impl Error {
  /// Return a safe registration message without source paths or secrets.
  #[must_use]
  pub fn registration_detail(&self) -> String {
    let summary = match self {
      Self::ToolConfig(source) => source.registration_summary(),
      Self::Git(source) => source.registration_summary(),
      Self::Ssh(source) => source.registration_summary(),
      Self::Nats(source) => source.registration_summary(),
      Self::Kube(source) => source.registration_summary(),
      Self::Talos(source) => source.registration_summary(),
      Self::Profiles(source) => source.registration_summary(),
      Self::Workspace(source) => source.registration_summary(),
      Self::Projection(source) => source.registration_summary(),
      Self::Config(_)
      | Self::Fnox(_)
      | Self::ConfigDir { .. }
      | Self::GuestCa { .. }
      | Self::ReadFile { .. }
      | Self::RewriteNoValue { .. }
      | Self::RewriteNoDecoy { .. }
      | Self::RewriteDestNotAbsolute { .. }
      | Self::RewriteWithEnvs { .. }
      | Self::FragmentParse { .. }
      | Self::FragmentPathEncoding { .. } => "configuration could not be read",
      Self::Io(_) | Self::WriteFile { .. } | Self::RemoveFile { .. } | Self::CreateDir { .. } | Self::ChmodFile { .. } => {
        "session files could not be prepared"
      }
      Self::NoHome => "registration failed",
    };
    summary.to_string()
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
    let text = Error::FragmentParse { source }.registration_detail();
    assert_eq!(text, "configuration could not be read");
    assert!(!text.contains("MARKER_SECRET"));
  }

  #[test]
  fn a_projected_fragment_error_stays_redacted_after_extraction() {
    let source = toml::from_str::<toml::Value>("MARKER_SECRET [").unwrap_err();
    let error = Error::Projection(arkham_projection::Error::FragmentParse { source });
    let text = error.registration_detail();
    assert_eq!(text, "configuration could not be read");
    assert!(!text.contains("MARKER_SECRET"));
  }

  #[test]
  fn a_profile_write_error_retains_its_safe_category() {
    let error = Error::Profiles(arkham_profiles::Error::CreateDir {
      path: PathBuf::from("/private/MARKER_SECRET"),
      source: IoError::new(std::io::ErrorKind::PermissionDenied, "MARKER_SECRET"),
    });
    let text = error.registration_detail();
    assert_eq!(text, "session files could not be prepared");
    assert!(!text.contains("MARKER_SECRET"));
    assert!(!text.contains("/private"));
  }
}
