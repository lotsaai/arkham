//! Workspace discovery, configuration, secret selection and mount layout.

mod discover;
mod error;
mod expand;
mod mounts;
mod selection;
mod workspace;

pub use discover::project_root;
pub use error::Error;
pub use expand::{build_expander, expand_path, expand_value, resolution_env};
pub use mounts::Layout;
pub use selection::{Selection, rules_command, validate_passthrough};
pub use workspace::Workspace;

/// Result of a workspace operation.
pub type Result<T> = std::result::Result<T, Error>;
