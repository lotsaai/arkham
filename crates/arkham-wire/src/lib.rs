//! Shared TLS legs, the byte substitution machine, and the relay.
//!
//! Protocol crates depend on this crate. It depends on no grant type.

pub mod engine;
mod error;
pub mod identity;
pub mod raw;
pub mod relay;
pub mod tls;
mod types;

pub use error::{Error, Result};
pub use identity::client_identity;
pub use types::{GuestTlsMode, RootCert};
