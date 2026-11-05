//! Line-delimited JSON between the wrapper and the daemon.
//!
//! The socket is the session. The message does not carry a session id or a
//! pid: those come from the kernel's peer credentials.

use std::path::PathBuf;

use arkham_config::WriteProfile;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

use crate::Error;
use crate::host::plan::LaunchPlan;

/// Largest control message accepted.
const CONTROL_CAP: usize = 1024 * 1024;

/// What the wrapper sends. `cwd` selects a project. It does not authorize one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
  /// Directory the wrapper was started in.
  pub cwd: PathBuf,
  /// Write profile for this launch.
  pub profile: WriteProfile,
}

/// What the daemon sends back. `plan` is present only when registration worked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
  /// Launch plan. Absent when `error` is set.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub plan: Option<LaunchPlan>,
  /// Why registration failed, when it did.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

/// Path of the daemon socket, `$XDG_RUNTIME_DIR/arkham/daemon.sock`.
///
/// A missing or empty runtime directory is an error, so a pre-created
/// `/tmp/arkham-<uid>` cannot capture the socket.
///
/// # Errors
///
/// Returns [`Error::RuntimeDir`] when `XDG_RUNTIME_DIR` is unset or empty.
pub fn daemon_socket_path() -> Result<PathBuf, Error> {
  let Some(base) = std::env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) else {
    return Err(Error::RuntimeDir);
  };
  Ok(PathBuf::from(base).join("arkham").join("daemon.sock"))
}

/// Decode one register request.
///
/// # Errors
///
/// Returns [`Error::ControlMessage`] when `bytes` is not the request JSON.
pub fn decode_request(bytes: &[u8]) -> Result<RegisterRequest, Error> {
  serde_json::from_slice(bytes).map_err(|source| Error::ControlMessage { source })
}

/// Encode one register response.
///
/// # Errors
///
/// Returns [`Error::ControlMessage`] when the response cannot be encoded.
pub fn encode_response(response: &RegisterResponse) -> Result<Vec<u8>, Error> {
  serde_json::to_vec(response).map_err(|source| Error::ControlMessage { source })
}

/// Read one line, capped at 1 MiB.
///
/// # Errors
///
/// Returns [`Error::ControlLimit`] when the peer closes early or the line
/// exceeds the cap.
pub async fn read_line(stream: &mut UnixStream) -> Result<Vec<u8>, Error> {
  let mut buf = Vec::new();
  let mut byte = [0u8; 1];
  loop {
    let n = stream.read(&mut byte).await?;
    if n == 0 {
      return Err(Error::ControlLimit);
    }
    if byte[0] == b'\n' {
      return Ok(buf);
    }
    if buf.len() == CONTROL_CAP {
      return Err(Error::ControlLimit);
    }
    buf.push(byte[0]);
  }
}

/// Write `bytes` and a newline.
///
/// # Errors
///
/// Returns an error when the write fails.
pub async fn write_line(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), Error> {
  stream.write_all(bytes).await?;
  stream.write_all(b"\n").await?;
  stream.flush().await?;
  Ok(())
}
