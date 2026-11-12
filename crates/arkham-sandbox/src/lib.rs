//! Linux confinement and process execution.

#[cfg(target_os = "linux")]
mod cgroup;
mod error;
mod identity;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod plan;

#[cfg(target_os = "linux")]
pub use cgroup::{SessionSlot, host_cgroup, read_cgroup, read_starttime, release_session, session_cgroup};
pub use error::Error;
pub use identity::{cgroup_is_confined, parse_starttime, peer_uid_allowed};
#[cfg(target_os = "linux")]
pub use linux::{landlock_exec, spawn};
#[cfg(target_os = "linux")]
pub use plan::bwrap_argv;

/// Result of sandbox enforcement.
pub type Result<T> = std::result::Result<T, Error>;
