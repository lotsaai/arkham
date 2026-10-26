//! SMTP vertical: transport halves, then the shared relay.
//!
//! `smtp://` is cleartext until `STARTTLS`. The cleartext opening reads the
//! greeting and the upgrade, then both sockets go to `relay_guarded`.
//! `smtps://` is TLS from the first byte and relays immediately. The
//! upstream `smtps` leg, and a `starttls=required` leg after it upgrades,
//! verify the chain and the host name.

mod machine;
mod session;
pub(crate) mod transport;

#[cfg(test)]
pub(crate) use machine::{MAX_COMMAND, Smtp};
#[cfg(test)]
pub(crate) use session::{GuestLeg, acceptance_reply, plain_guest};
