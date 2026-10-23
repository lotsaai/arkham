//! AMQP grant parsing and the SASL wire machine.

mod error;
mod machine;
mod scope;

pub use error::{Error, Result};
pub use machine::{Amqp, SaslSwap};
pub use scope::{AmqpLeg, AmqpScope, AmqpUriError};

#[cfg(test)]
mod props;
