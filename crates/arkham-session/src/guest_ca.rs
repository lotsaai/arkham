use crate::Error;
use arkham_config::config::config_dir;
use arkham_pki::ca::{CertAuthority, load_or_generate};

/// Load the guest CA from the arkham config directory, generating it when absent.
///
/// # Errors
///
/// Returns [`Error::ConfigDir`] when the directory does not resolve, or [`Error::GuestCa`] when the CA cannot be loaded or written.
pub(crate) fn load_guest_ca(detail: &str) -> Result<CertAuthority, Error> {
  let ca_path = config_dir()
    .ok_or_else(|| Error::ConfigDir {
      detail: detail.to_string(),
    })?
    .join("ca.pem");
  load_or_generate(&ca_path).map_err(|source| Error::GuestCa { path: ca_path, source })
}
