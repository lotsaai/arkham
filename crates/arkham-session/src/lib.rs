//! Daemon-side session preparation.

mod ambient;
mod error;
mod format;
mod grant_state;
mod guest_ca;
mod material;
mod prepare;
mod rewrites;

pub use error::Error;
pub use prepare::{CaPaths, PreparedSession, prepare_session};

/// Result of session preparation.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test_support;
