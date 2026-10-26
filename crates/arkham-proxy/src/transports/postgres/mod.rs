//! Postgres vertical: transport halves, serve arm, and the pgwire framing
//! machine — everything postgres owns.

mod auth;
pub(crate) mod machine;
pub(crate) mod transport;
