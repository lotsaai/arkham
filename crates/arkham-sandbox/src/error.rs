//! Errors from confinement and process execution.

use std::path::PathBuf;

/// A confinement or process execution failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A configuration failure.
  #[error(transparent)]
  Config(Box<arkham_config::Error>),
  /// An I/O failure.
  #[error(transparent)]
  Io(#[from] std::io::Error),
  /// The session process identity changed.
  #[error("session identity changed before the cgroup was confirmed")]
  SessionReused,
  /// A session cgroup operation failed.
  #[error("session cgroup {}: {source}", path.display())]
  SessionCgroup {
    /// Cgroup directory.
    path: PathBuf,
    /// Underlying failure.
    #[source]
    source: std::io::Error,
  },
  /// Process start time is unavailable.
  #[error("process {pid} has no start time")]
  NoStarttime {
    /// Process ID.
    pid: u32,
  },
  /// Process cgroup is unavailable.
  #[error("process {pid} has no cgroup")]
  NoCgroup {
    /// Process ID.
    pid: u32,
  },
  /// The session temporary directory is unavailable.
  #[error("session tmp is not a private directory")]
  SessionTmp {
    /// Underlying failure.
    #[source]
    source: std::io::Error,
  },
  /// The plan cannot be decoded.
  #[error("control message is not valid")]
  ControlMessage {
    /// Underlying decoding failure.
    #[source]
    source: serde_json::Error,
  },
  /// The plan or command is missing.
  #[error("control message exceeds 1 MiB or ended early")]
  ControlLimit,
  /// Landlock cannot open a permitted path.
  #[cfg(target_os = "linux")]
  #[error("landlock path {path}", path = path.display())]
  LandlockPath {
    /// Path that could not be opened.
    path: PathBuf,
    /// Underlying failure.
    #[source]
    source: landlock::PathFdError,
  },
  /// Landlock rejected the ruleset.
  #[cfg(target_os = "linux")]
  #[error("landlock restriction failed")]
  Landlock {
    /// Underlying failure.
    #[source]
    source: landlock::RulesetError,
  },
  /// Landlock did not fully enforce the ruleset.
  #[cfg(target_os = "linux")]
  #[error("landlock did not enforce the profile")]
  LandlockIncomplete,
}

impl From<arkham_config::Error> for Error {
  fn from(source: arkham_config::Error) -> Self {
    Self::Config(Box::new(source))
  }
}

impl Error {
  /// Return a safe error for the registration peer.
  #[must_use]
  pub fn registration_detail(&self) -> String {
    match self {
      Self::SessionReused | Self::SessionCgroup { .. } | Self::NoStarttime { .. } | Self::NoCgroup { .. } | Self::SessionTmp { .. } => {
        self.to_string()
      }
      Self::Config(_) => "configuration could not be read".to_string(),
      Self::Io(_) => "session files could not be prepared".to_string(),
      Self::ControlMessage { .. } | Self::ControlLimit => "registration failed".to_string(),
      #[cfg(target_os = "linux")]
      Self::LandlockPath { .. } | Self::Landlock { .. } | Self::LandlockIncomplete => "landlock did not enforce the profile".to_string(),
    }
  }
}
