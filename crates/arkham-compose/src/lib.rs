//! Workspace confinement: `arkham rules` prints env-only rules for the
//! fnox-declared names the registry knows; `arkham init` generates the
//! workspace stack once as an editable file; `arkham up`/`down`/`logs` drive
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
pub use nats::{NatsSkip, NatsUnsupported};

#[cfg(test)]
mod test_support;
