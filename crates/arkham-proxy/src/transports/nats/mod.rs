//! NATS vertical: transport halves, the INFO-first opening, and the framer.
//!
//! The server speaks first. On `nats://` and `tls://` the proxy forwards one
//! cleartext INFO line. A `tls://` server leg then upgrades before CONNECT,
//! with the bytes read past INFO replayed into its handshake. A guest whose
//! next byte opens a TLS record is terminated here. With `handshake_first`
//! both legs settle TLS before any protocol byte. CONNECT carries the real
//! values on a cleartext server leg the same way it does on TLS.

pub mod machine;

#[cfg(test)]
pub(crate) mod fixtures;

#[cfg(test)]
mod props;
pub(crate) mod transport;
