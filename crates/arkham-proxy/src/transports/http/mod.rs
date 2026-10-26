//! HTTP vertical: the `https://` MITM arm, the `http://` cleartext arm, the
//! per-connection substitution service, and the HTTP/1 + HTTP/2 framing
//! machines — everything http owns.

pub(crate) mod h2;
pub(crate) mod machine;
pub(crate) mod transport;
