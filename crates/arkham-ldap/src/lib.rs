//! LDAP grant parsing and the simple-bind wire machine.

mod error;
mod machine;
mod scope;

pub use error::{Error, Result};
pub use machine::{BindSwap, Ldap, starttls_success};
pub use scope::{LdapLeg, LdapScope, LdapUriError};

#[cfg(test)]
mod handoff;
#[cfg(test)]
mod props;
