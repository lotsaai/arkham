//! Shared launch data for session preparation and confinement.

use std::path::{Path, PathBuf};

use arkham_config::WriteProfile;
use serde::{Deserialize, Serialize};

/// One bind the agent sees. `source` is the file the daemon wrote. `dest`
/// is the path inside the sandbox, which for a host session is the real path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bind {
  /// Host path of the projected bytes.
  pub source: PathBuf,
  /// Path the agent opens.
  pub dest: PathBuf,
  /// When set, the bind is read-only even if the profile allows writes.
  pub read_only: bool,
}

/// What the wrapper needs to launch. Real secrets never appear here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchPlan {
  /// Write profile the operator asked for.
  pub profile: WriteProfile,
  /// Workspace root.
  pub workspace: PathBuf,
  /// Projected files and the mounts compose would have made.
  pub binds: Vec<Bind>,
  /// Existing configuration paths and aliases hidden from the agent.
  pub protected: Vec<PathBuf>,
  /// Certificate PEM, without the CA key.
  pub ca_host: PathBuf,
  /// Where the certificate is mounted.
  pub ca_dest: PathBuf,
  /// Environment after `clearenv`: decoys, CA paths, and the kept names.
  pub env: Vec<(String, String)>,
  /// Working directory.
  pub workdir: PathBuf,
  /// Shell used when the wrapper was given no command.
  pub shell: String,
}

/// Container path of the CA certificate.
pub const CA_DEST: &str = "/arkham/ca.pem";

/// Sandbox path used when the resolved project would be the user's home.
/// Bubblewrap mounts a fresh tmpfs here rather than the host directory.
pub const PRIVATE_SESSION_ROOT: &str = "/tmp";

/// Whether `path` is the private session directory rather than a host project.
#[must_use]
pub fn is_private_session(path: &Path) -> bool {
  path == Path::new(PRIVATE_SESSION_ROOT)
}

/// Host system directories mounted into the sandbox and scanned for aliases.
#[cfg(target_os = "linux")]
pub const SYSTEM_ROOTS: &[&str] = &["bin", "etc", "lib", "lib64", "opt", "sbin", "usr"];
