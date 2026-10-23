//! SMTP grant assembly. The connection-string law lives in `arkham-smtp`.

use secrecy::ExposeSecret as _;

use arkham_smtp::{Error as SmtpError, SmtpScope};

use super::{Credential, Grant};
use crate::config::RuleCfg;
use crate::error::Error;

/// Assemble one SMTP grant from its rule. Cleartext and TLS both swap.
///
/// # Errors
///
/// Returns an error when either string fails the connection-string law, or
/// when a `tls` row tries to state what only the real string may state.
pub(super) fn grant(label: &str, rule: &RuleCfg, real: &str) -> Result<Grant, Error> {
  let fake = rule
    .value
    .as_ref()
    .map(|value| value.expose_secret().to_string())
    .unwrap_or_default();
  let mut scope = SmtpScope::from_strings(&fake, real).map_err(|source| SmtpError::Scope {
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
      return Err(SmtpError::Identity { label: label.to_string() }.into());
    }
    if tls.root_cert.is_some() {
      return Err(SmtpError::Trust { label: label.to_string() }.into());
    }
    scope.guest_tls = tls.guest_tls_mode;
  }
  let credential = Credential {
    label: label.to_string(),
    fake: scope.downstream.password.expose_secret().to_string(),
    value: scope.upstream.password.clone(),
  };
  Ok(Grant::Smtp {
    credential,
    scope: Box::new(scope),
  })
}
