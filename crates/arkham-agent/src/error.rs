use std::path::PathBuf;

/// Failures while registering and running an agent.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A control protocol operation failed.
  #[error(transparent)]
  Protocol(#[from] arkham_session_protocol::Error),
  /// A confinement operation failed.
  #[error(transparent)]
  Sandbox(#[from] arkham_sandbox::Error),
  /// An I/O operation failed.
  #[error(transparent)]
  Io(#[from] std::io::Error),
  /// The requested workspace could not be resolved.
  #[error("resolve workspace {}: {source}", path.display())]
  ResolveWorkspace {
    /// Requested workspace.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: std::io::Error,
  },
  /// An inherited environment entry cannot be represented in the control protocol.
  #[error("agent environment contains non-Unicode data")]
  NonUnicodeEnvironment,
  /// The daemon rejected the session.
  #[error("daemon rejected the session: {detail}")]
  DaemonRejected {
    /// Message the daemon sent.
    detail: String,
  },
  /// The host backend was requested on a system other than Linux.
  #[error("the host backend runs on Linux")]
  HostLinuxOnly,
}

impl Error {
  /// Returns a safe explanation suitable for a registration response.
  #[must_use]
  pub fn registration_detail(&self) -> String {
    match self {
      Self::Protocol(source) => source.registration_detail(),
      Self::Sandbox(source) => source.registration_detail(),
      Self::Io(_) => "session files could not be prepared".to_owned(),
      Self::ResolveWorkspace { .. } => "configuration could not be read".to_owned(),
      Self::NonUnicodeEnvironment | Self::DaemonRejected { .. } => "registration failed".to_owned(),
      Self::HostLinuxOnly => self.to_string(),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn workspace_error_does_not_disclose_path_or_source() {
    let error = Error::ResolveWorkspace {
      path: PathBuf::from("/private/MARKER_SECRET"),
      source: std::io::Error::other("MARKER_SECRET"),
    };
    assert_eq!(error.registration_detail(), "configuration could not be read");
  }

  #[test]
  fn daemon_rejection_is_not_forwarded() {
    let error = Error::DaemonRejected {
      detail: "MARKER_SECRET".into(),
    };
    assert_eq!(error.registration_detail(), "registration failed");
  }
}
