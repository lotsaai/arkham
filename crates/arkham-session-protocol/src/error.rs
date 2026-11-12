/// Errors in session registration and socket ownership checks.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// An I/O failure with no extra context.
  #[error(transparent)]
  Io(#[from] std::io::Error),
  /// The host wrapper found no daemon socket.
  #[error("no host daemon is running")]
  NoDaemon,
  /// A socket path or a directory created for it is not owned by this user.
  #[error("daemon socket is not owned by this user")]
  SocketOwner,
  /// The runtime directory is unset, missing, or not private to this user.
  #[error("XDG_RUNTIME_DIR is unset or not private")]
  RuntimeDir,
  /// A control message was not valid JSON.
  #[error("control message is not valid")]
  ControlMessage {
    /// Why the message was rejected.
    #[source]
    source: serde_json::Error,
  },
  /// A control message exceeded the cap or ended early.
  #[error("control message exceeds 1 MiB or ended early")]
  ControlLimit,
}

/// Result of a protocol operation.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
  /// Return a safe registration error without exposing source details.
  #[must_use]
  pub fn registration_detail(&self) -> String {
    match self {
      Self::RuntimeDir | Self::SocketOwner | Self::NoDaemon => self.to_string(),
      Self::Io(_) => "session files could not be prepared".to_string(),
      Self::ControlMessage { .. } | Self::ControlLimit => "registration failed".to_string(),
    }
  }
}
