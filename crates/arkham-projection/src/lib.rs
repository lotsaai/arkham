//! Filesystem projection and protection for session preparation.

mod forge;
mod protected;

pub use forge::{forged_bytes, indexed_aliases, inode_index, projection_files, scan_roots};
pub use protected::{projected_files, protected_config_paths, push_with_aliases};

/// A failure while discovering or projecting protected files.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// An I/O failure with no extra context.
  #[error(transparent)]
  Io(#[from] std::io::Error),
  /// A grant fragment does not parse as rules.
  #[error("grant fragment does not parse")]
  FragmentParse {
    /// Underlying parse failure.
    #[source]
    source: toml::de::Error,
  },
}

impl Error {
  /// Return a safe summary for registration responses.
  #[must_use]
  pub fn registration_summary(&self) -> &'static str {
    match self {
      Self::Io(_) => "session files could not be prepared",
      Self::FragmentParse { .. } => "configuration could not be read",
    }
  }
}

/// Result of a projection operation.
pub type Result<T> = std::result::Result<T, Error>;
