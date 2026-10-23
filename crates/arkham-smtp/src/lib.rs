//! SMTP grant parsing and the AUTH wire machine.
//!
//! Cleartext and TLS both swap. The shared TLS leg and the relay live in
//! `arkham-wire`.

mod error;
mod machine;
mod scope;
mod session;

pub use error::{Error, Result};
pub use machine::AuthMaterial;
pub use scope::{SmtpLeg, SmtpScope, SmtpUriError};
pub use session::{Dialogue, GuestLeg, ServerLeg, plain_guest, plain_server, run, tls_guest, tls_server};

#[cfg(test)]
mod props;
