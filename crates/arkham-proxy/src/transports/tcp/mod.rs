//! TCP vertical: the raw framing machine and the serve arm — everything
//! tcp owns. `splice` is the decline path every vertical hands to.

pub(crate) mod machine;
pub(crate) mod transport;
