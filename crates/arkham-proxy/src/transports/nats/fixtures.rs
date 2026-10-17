//! Grant fixtures shared by NATS tests.

use arkham_config::grants::{Credential, Grant, NatsAuth, NatsScope};
use secrecy::SecretString;

/// One NATS grant parsed from a decoy string and a real string.
pub(crate) fn nats_grants(fake: &str, real: &str) -> Vec<Grant> {
  let scope = NatsScope::from_strings(fake, real).expect("nats strings");
  let (fake, value) = match &scope.auth {
    NatsAuth::UserPass { pass, .. } => (pass.fake.clone(), pass.real.clone()),
    NatsAuth::Token(token) => (token.fake.clone(), token.real.clone()),
    NatsAuth::Nkey(nkey) => (nkey.fake_public().to_string(), SecretString::from(nkey.real_public().to_string())),
    NatsAuth::UserJwt(jwt) => (jwt.fake_jwt().to_string(), jwt.real_jwt().clone()),
  };
  vec![Grant::Nats {
    credential: Credential {
      label: "nats".into(),
      fake,
      value,
    },
    scope: Box::new(scope),
  }]
}
