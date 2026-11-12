//! Errors from workspace input discovery and selection.

use std::path::PathBuf;

/// A workspace input could not be resolved.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// Configuration could not be loaded.
  #[error(transparent)]
  Config(Box<arkham_config::Error>),
  /// Secret discovery or resolution failed.
  #[error(transparent)]
  Fnox(Box<arkham_fnox::Error>),
  /// Guest identity generation failed.
  #[error(transparent)]
  Pki(#[from] arkham_pki::Error),
  /// An I/O operation failed.
  #[error(transparent)]
  Io(#[from] std::io::Error),
  /// An include does not exist.
  #[error("[workspace] include `{}` does not exist; docker would mount an empty directory in its place", entry.display())]
  IncludeMissing {
    /// Missing entry.
    entry: PathBuf,
  },
  /// An include widens the workspace.
  #[error("[workspace] include `{}` widens the workspace", entry.display())]
  IncludeWidens {
    /// Entry that widens the workspace.
    entry: PathBuf,
  },
  /// A value could not be expanded.
  #[error("failed to expand config value: {detail}")]
  ExpandValue {
    /// Expansion failure.
    detail: String,
  },
  /// A secret resolved without a value.
  #[error("fnox secret `{name}` resolved to no value")]
  SecretNoValue {
    /// Secret name.
    name: String,
  },
  /// A passthrough conflicts with a rule.
  #[error("[workspace] passthrough `{name}` is also a [rules.*] env: pick one path")]
  PassthroughOverlapRule {
    /// Conflicting environment name.
    name: String,
  },
  /// A passthrough conflicts with a decoy.
  #[error("[workspace] passthrough `{name}` overlaps a selected decoy: pick one path")]
  PassthroughOverlapDecoy {
    /// Conflicting environment name.
    name: String,
  },
}

impl Error {
  /// A redacted category suitable for registration responses.
  #[must_use]
  pub fn registration_summary(&self) -> &'static str {
    match self {
      Self::Io(_) => "session files could not be prepared",
      _ => "configuration could not be read",
    }
  }
}

impl From<arkham_config::Error> for Error {
  fn from(source: arkham_config::Error) -> Self {
    Self::Config(Box::new(source))
  }
}

impl From<arkham_fnox::Error> for Error {
  fn from(source: arkham_fnox::Error) -> Self {
    Self::Fnox(Box::new(source))
  }
}

#[cfg(test)]
mod tests {
  use super::Error;

  #[test]
  fn a_missing_secret_name_does_not_reach_the_wrapper() {
    let error = Error::SecretNoValue {
      name: "MARKER_SECRET".to_string(),
    };
    assert_eq!(error.registration_summary(), "configuration could not be read");
    assert!(!error.registration_summary().contains("MARKER_SECRET"));
  }
}
