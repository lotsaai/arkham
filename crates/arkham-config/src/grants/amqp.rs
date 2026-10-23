use secrecy::ExposeSecret as _;

use arkham_amqp::{AmqpScope, Error as AmqpError};

use super::{Credential, Grant};
use crate::config::RuleCfg;
use crate::error::Error;

pub(super) fn grant(label: &str, rule: &RuleCfg, real: &str) -> Result<Grant, Error> {
  let fake = rule
    .value
    .as_ref()
    .map(|value| value.expose_secret().to_string())
    .unwrap_or_default();
  let mut scope = AmqpScope::from_strings(&fake, real).map_err(|source| AmqpError::Scope {
    label: label.to_string(),
    source,
  })?;
  for (key, tls) in &rule.tls {
    if key != &rule.env {
      return Err(Error::TlsEnvMismatch {
        label: label.to_string(),
        key: key.clone(),
        env: rule.env.clone(),
      });
    }
    if tls.client_cert.is_some() || tls.client_key.is_some() {
      return Err(AmqpError::Identity { label: label.to_string() }.into());
    }
    if tls.root_cert.is_some() {
      return Err(AmqpError::Trust { label: label.to_string() }.into());
    }
    scope.guest_tls = tls.guest_tls_mode;
  }
  let credential = Credential {
    label: label.to_string(),
    fake: scope.downstream.password.expose_secret().to_string(),
    value: scope.upstream.password.clone(),
  };
  Ok(Grant::Amqp {
    credential,
    scope: Box::new(scope),
  })
}
