//! Grant model: a credential is one real secret, and a grant says what kind
//! of endpoints that secret may be presented at. A rule is one kind, inferred
//! from the URL schemes of its `allow` entries. The protocol verticals
//! (`postgres`, `redis`, `smtp`, `ldap`, `nats`, `amqp`) own their scope types and their connection-string
//! laws; this module owns the enum, the matching dispatch, and the
//! collection of rules into grants.

mod amqp;
mod ldap;
mod nats;
mod postgres;
mod redis;
mod resolve;
mod scope;
mod smtp;

#[cfg(test)]
mod tests;

pub use amqp::{AmqpLeg, AmqpScope, AmqpUriError};
pub use ldap::{LdapLeg, LdapScope, LdapUriError};
pub(crate) use nats::NatsUriScheme;
pub use nats::{
  AuthField, AuthSign, FieldPresence, NATS_DEFAULT_PORT, NatsAuth, NatsClientIdentity, NatsEndpoint, NatsField, NatsPair, NatsPlain,
  NatsScope, NatsSeed, NatsTlsOrder, NatsTrust, NatsUpstream, NatsUriError, check_user_jwt,
};
pub use postgres::{PostgresLeg, PostgresScope, SslMode, SslNegotiation};
pub use redis::{RedisLeg, RedisScope};
pub use smtp::{SmtpLeg, SmtpScope, SmtpUriError};

pub use resolve::{Grant, ResolvedConfig, decoy_for_rule, resolve, uri_match};
pub(crate) use resolve::{apply_guest_tls, downstream_covers, map_tls_row, password_credential, stated_fake};
pub use scope::{Credential, EndpointScope, GuestTlsMode, HostPat, RootCert, Scheme, SshScope};
