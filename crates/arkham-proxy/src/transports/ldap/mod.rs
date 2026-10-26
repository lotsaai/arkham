//! LDAP vertical: transport halves, a lockstep `StartTLS` opening, and the BER machine.
//!
//! `ldaps://` settles TLS, then both sockets go to [`relay_guarded`].
//! `ldap://` reads only enough of the first message to recognize `StartTLS`.
//! That one exchange runs lockstep. A bind, a search, and every later byte
//! go through [`relay_guarded`] with no second session pump and no
//! hold-until-complete buffer.

pub(crate) mod machine;
pub(crate) mod transport;
