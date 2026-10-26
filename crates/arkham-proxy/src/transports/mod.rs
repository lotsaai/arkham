//! Protocol transports. This root is protocol-blind: it holds the traits —
//! one per responsibility — the stream a transport is handed, and the
//! shared substitution engine. Each protocol vertical implements the
//! responsibilities it owns; the composition root (lib.rs) retains the
//! strategies, and the picker (identity.rs) routes one stream to one
//! strategy in one place.

pub mod amqp;
pub mod engine;
pub mod http;
pub mod ldap;
pub mod nats;
pub mod postgres;
pub mod redis;
pub mod smtp;
pub mod ssh;
pub mod tcp;
pub mod tls;

mod halves;
mod legs;

pub(crate) use halves::{ServeStream, TlsCache, TlsHalves, Transport, within};
pub(crate) use legs::{FlaggedOpen, PairCtx, Settled, TLS_RECORD_HANDSHAKE, matched_host, open_flagged, relay_settled};
