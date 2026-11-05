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

pub use discover::{cgroup_is_confined, parse_starttime, peer_uid_allowed, project_root};
pub use plan::LaunchPlan;
pub use prepare::{PreparedSession, prepare_session};
pub use protocol::{RegisterRequest, RegisterResponse, daemon_socket_path, decode_request, encode_response, read_line, write_line};

/// Register with the daemon and launch. On a non-Linux host this refuses
/// before starting a process.
///
/// # Errors
///
/// Returns [`Error::HostLinuxOnly`] off Linux, [`Error::NoDaemon`] when the
/// socket is absent, and [`Error::NoRunner`] (via config) when both probes fail.
pub async fn run_agent(profile: arkham_config::WriteProfile, command: &[std::ffi::OsString]) -> Result<(), crate::Error> {
  #[cfg(target_os = "linux")]
  {
    return linux::agent(profile, command).await;
  }
  #[cfg(not(target_os = "linux"))]
  {
    let _ = (profile, command);
    Err(crate::Error::HostLinuxOnly)
  }
}

#[cfg(target_os = "linux")]
pub use linux::{SessionSlot, ensure_socket_dir, host_cgroup, landlock_exec, read_cgroup, read_starttime, release_session, session_cgroup};
