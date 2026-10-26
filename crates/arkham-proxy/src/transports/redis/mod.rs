//! Redis vertical: transport halves, serve arm, and the RESP framing
//! machine — everything redis owns.

pub(crate) mod machine;
pub(crate) mod transport;
