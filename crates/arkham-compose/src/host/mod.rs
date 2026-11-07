//! Linux host backend: one daemon, a wrapper, and the same filesystem inputs
//! compose uses.
//!
//! The daemon holds real secrets. The wrapper receives a plan of decoys and
//! bind paths, probes a runner, and only then starts the agent.

mod discover;
mod forge;
mod plan;
mod prepare;
mod protocol;

#[cfg(target_os = "linux")]
mod linux;

pub use discover::{PRIVATE_SESSION_ROOT, cgroup_is_confined, parse_starttime, peer_uid_allowed, project_root};
pub use plan::LaunchPlan;
pub use prepare::{PreparedSession, prepare_session};
pub use protocol::{RegisterRequest, RegisterResponse, daemon_socket_path, decode_request, encode_response, read_line, write_line};

/// Register `workspace` (or the current directory) and launch. On a non-Linux
/// host this refuses before starting a process.
///
/// # Errors
///
/// Returns [`Error::HostLinuxOnly`] off Linux, [`Error::NoDaemon`] when the
/// socket is absent, and [`Error::NoRunner`] (via config) when bubblewrap
/// does not accept the profile.
#[cfg(target_os = "linux")]
pub async fn run_agent(
  profile: arkham_config::WriteProfile,
  workspace: Option<&std::path::Path>,
  command: &[std::ffi::OsString],
) -> Result<(), crate::Error> {
  linux::agent(profile, workspace, command).await
}

/// Register `workspace` and launch. This host has no bubblewrap runner.
///
/// # Errors
///
/// Returns [`Error::HostLinuxOnly`].
#[cfg(not(target_os = "linux"))]
pub fn run_agent(
  profile: arkham_config::WriteProfile,
  workspace: Option<&std::path::Path>,
  command: &[std::ffi::OsString],
) -> Result<(), crate::Error> {
  let _ = (profile, workspace, command);
  Err(crate::Error::HostLinuxOnly)
}

#[cfg(target_os = "linux")]
pub use linux::{SessionSlot, ensure_socket_dir, host_cgroup, landlock_exec, read_cgroup, read_starttime, release_session, session_cgroup};
