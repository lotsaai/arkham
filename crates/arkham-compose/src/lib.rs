//! Workspace confinement: `arkham rules` prints env-only rules for the
//! fnox-declared names the registry knows; `arkham init` generates the
//! workspace stack as generated state; `arkham up`/`down`/`logs` drive
//! the layered compose project; `arkham agent` runs that whole sequence
//! in one go.

mod adapt;
mod ambient;
mod confine;
mod decoys;
mod error;
mod expand;
mod expose;
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

pub use confine::{AgentArgs, DownArgs, InitArgs, LogsArgs, UpArgs};
pub use decoys::rules_command;
pub use error::Error;
pub use expose::ExposeArgs;
pub use host::{
  LaunchPlan, PRIVATE_SESSION_ROOT, PreparedSession, RegisterRequest, RegisterResponse, cgroup_is_confined, daemon_socket_path,
  decode_request, encode_response, parse_starttime, peer_uid_allowed, prepare_session, project_root, read_line, write_line,
};
#[cfg(target_os = "linux")]
pub use host::{SessionSlot, ensure_socket_dir, host_cgroup, landlock_exec, read_cgroup, read_starttime, release_session, session_cgroup};

#[cfg(test)]
mod test_support;
