//! Workspace confinement and host agent session preparation.

mod adapt;
mod ambient;
mod confine;
mod decoys;
mod error;
mod expand;
mod git;
mod host;
mod jj;
mod kube;
mod mounts;
mod nats;
mod paths;
mod profiles;
mod rewrites;
mod ssh;
mod stack;
mod talos;
mod workspace;

pub use confine::AgentArgs;
pub use decoys::rules_command;
pub use error::Error;
pub use host::{
  CaPaths, LaunchPlan, PRIVATE_SESSION_ROOT, PreparedSession, RegisterRequest, RegisterResponse, cgroup_is_confined, daemon_socket_path,
  decode_request, encode_response, parse_starttime, peer_uid_allowed, prepare_session, project_root, read_line, write_line,
};
#[cfg(target_os = "linux")]
pub use host::{SessionSlot, ensure_socket_dir, host_cgroup, landlock_exec, read_cgroup, read_starttime, release_session, session_cgroup};

#[cfg(test)]
mod test_support;
