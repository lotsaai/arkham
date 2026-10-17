//! Grant fixtures shared by NATS tests.

use arkham_config::grants::{Credential, Grant, NatsScope, NatsSeed};
use secrecy::SecretString;

/// User seed minted for tests. The `String` is the seed text a connection string carries.
pub(crate) fn mint_user() -> (String, NatsSeed) {
  let pair = nkeys::KeyPair::new_user();
  let raw = pair.seed().expect("user seed");
  let seed = NatsSeed::from_seed(SecretString::from(raw.clone())).expect("user seed");
  (raw, seed)
}

/// One NATS grant parsed from a decoy string and a real string.
pub(crate) fn nats_grants(fake: &str, real: &str) -> Vec<Grant> {
  let scope = NatsScope::from_strings(fake, real).expect("nats strings");
  let (fake, value) = scope.auth.credential();
  let (fake, value) = (fake.to_string(), value.clone());
  vec![Grant::Nats {
    credential: Credential {
      label: "nats".into(),
      fake,
      value,
    },
    scope: Box::new(scope),
  }]
}
