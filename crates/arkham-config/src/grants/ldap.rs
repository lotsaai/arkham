use secrecy::ExposeSecret as _;

use arkham_ldap::{Error as LdapError, LdapScope};

use super::{Credential, Grant};
use crate::config::RuleCfg;
use crate::error::Error;

pub(super) fn grant(label: &str, rule: &RuleCfg, real: &str) -> Result<Grant, Error> {
  let fake = rule
    .value
    .as_ref()
    .map(|value| value.expose_secret().to_string())
    .unwrap_or_default();
  let mut scope = LdapScope::from_strings(&fake, real).map_err(|source| LdapError::Scope {
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
      return Err(LdapError::Identity { label: label.to_string() }.into());
    }
    if tls.root_cert.is_some() {
      return Err(LdapError::Trust { label: label.to_string() }.into());
    }
    scope.guest_tls = tls.guest_tls_mode;
  }
  let credential = Credential {
    label: label.to_string(),
    fake: scope.downstream.password.expose_secret().to_string(),
    value: scope.upstream.password.clone(),
  };
  Ok(Grant::Ldap {
    credential,
    scope: Box::new(scope),
  })
}
