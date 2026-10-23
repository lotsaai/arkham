//! Re-export of the shared TLS legs. The implementation lives in `arkham-wire`.

pub(crate) use arkham_wire::tls::{Leg, TlsLegs, UpstreamTls, Verify, cached_leaf, cached_leaf_mtls, cached_roots, finish};
