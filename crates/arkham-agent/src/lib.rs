//! Wrapper registration and lifecycle for confined host agents.

mod args;
mod error;
#[cfg(target_os = "linux")]
mod linux;

pub use args::AgentArgs;
pub use error::Error;

/// Result of an agent operation.
pub type Result<T> = std::result::Result<T, Error>;
