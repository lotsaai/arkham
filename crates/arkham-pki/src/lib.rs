//! PKI: the signing CA and per-domain leaf certificates for test stubs.

pub mod ca;
mod error;
pub mod ssh;

pub use error::Error;
pub use ssh::load_or_generate_host_key;
