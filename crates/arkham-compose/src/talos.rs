//! Talosconfig adapter for `file_rewrite`: a talosconfig is the same
//! information a rule holds — endpoints, an upstream CA, and a client pair —
//! stated in talosctl's shape, so the adapter derives the grant from the file
//! instead of asking the operator to state it twice. Only the `context` maps;
//! the file is the secret source, so a talos entry stating `envs` is an
//! error rather than a second source.
//!
//! Detection is structural: a YAML mapping with `contexts:` and `endpoints:`
//! markers takes the adapter path, everything else keeps the raw byte-swap.
//! The decoy twin keeps the endpoints (transparent capture makes the
//! destination the identity) and swaps the trust and identity: arkham's CA
//! and the minted guest pair.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::config::{HostTlsCfg, RewriteFormat};
use arkham_config::grants::{EndpointScope, GuestTlsMode, Scheme};
use arkham_pki::ca::{CertAuthority, load_or_generate_client_pair};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_yaml::{Mapping, Value, from_str};

use crate::adapt::{GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, decode, render_decoy, render_fragment, rewrite_label};
use crate::error::Error;

/// A talosconfig document; unknown fields ignored.
#[derive(Debug, Deserialize, Default)]
struct TalosDoc {
  /// Active context name.
  #[serde(default)]
  context: String,
  /// Named contexts.
  #[serde(default)]
  contexts: BTreeMap<String, TalosContext>,
}

/// One `contexts` entry: endpoints plus the client identity.
#[derive(Debug, Deserialize, Default)]
struct TalosContext {
  /// Talos API endpoints: bare hosts, `host:port`, or an Omni URL.
  #[serde(default)]
  endpoints: Vec<String>,
  /// Base64 cluster CA.
  #[serde(default)]
  ca: String,
  /// Base64 client certificate.
  #[serde(default)]
  crt: String,
  /// Base64 client key.
  #[serde(default)]
  key: String,
  /// Alternative auth (Omni/SideroV1): detected so it errors clearly.
  #[serde(default)]
  auth: Option<Mapping>,
}

/// The validated client identity of the active context.
struct Identity {
  crt: Vec<u8>,
  key: Vec<u8>,
  ca: Vec<u8>,
}

impl TalosDoc {
  /// Resolve and validate the active context: known, with endpoints, no
  /// alternative auth, and a full `ca`/`crt`/`key` identity.
  ///
  /// # Errors
  ///
  /// Returns an error when the context is missing or unknown, states no
  /// endpoints, carries no client pair, or uses Omni auth.
  fn selected<'a>(&'a self, source: &Path, invalid: impl Fn(String) -> Error) -> Result<(&'a TalosContext, Identity), Error> {
    if self.context.is_empty() {
      return Err(invalid("missing `context`".to_string()));
    }
    let context = self
      .contexts
      .get(&self.context)
      .ok_or_else(|| invalid(format!("unknown context `{}`", self.context)))?;
    if context.endpoints.is_empty() {
      return Err(invalid(format!("context `{}` states no `endpoints`", self.context)));
    }
    if context.auth.is_some() {
      return Err(invalid(
        "alternative `auth` (Omni/SideroV1) is not supported: it carries no substitutable client pair".to_string(),
      ));
    }
    let crt = decode(source, RewriteFormat::Talos, Some(context.crt.as_str()), "crt")?;
    let key = decode(source, RewriteFormat::Talos, Some(context.key.as_str()), "key")?;
    let ca_bundle = decode(source, RewriteFormat::Talos, Some(context.ca.as_str()), "ca")?;
    if crt.is_none() || key.is_none() || ca_bundle.is_none() {
      return Err(invalid(format!(
        "context `{}` misses `ca`, `crt`, or `key`: nothing to substitute",
        self.context
      )));
    }
    Ok((
      context,
      Identity {
        crt: crt.unwrap_or_default(),
        key: key.unwrap_or_default(),
        ca: ca_bundle.unwrap_or_default(),
      },
    ))
  }

  /// One allow entry per endpoint, `https://`-normalized and validated.
  ///
  /// # Errors
  ///
  /// Returns an error when an endpoint does not map onto an allow entry or
  /// is not TLS.
  fn allows(context: &TalosContext, invalid: impl Fn(String) -> Error) -> Result<Vec<String>, Error> {
    let mut allows = Vec::new();
    for endpoint in &context.endpoints {
      let entry = normalize_endpoint(endpoint);
      let scope: EndpointScope = entry
        .parse()
        .map_err(|detail| invalid(format!("endpoint `{endpoint}` is not an allow entry: {detail}")))?;
      if scope.scheme != Scheme::Https {
        return Err(invalid(format!("endpoint `{endpoint}` is not TLS: the Talos API is TLS-only")));
      }
      allows.push(entry);
    }
    Ok(allows)
  }
}

/// Map a talosconfig onto its grant fragment and decoy twin.
///
/// # Errors
///
/// Returns an error when the document does not parse, names no context, the
/// context carries no endpoints or no client pair, or an endpoint does not
/// map onto an allow entry.
pub(crate) fn adapt(source: &Path, content: &[u8], ca: &CertAuthority, guests_dir: &Path) -> Result<RewriteAdapted, Error> {
  let text = String::from_utf8_lossy(content);
  let doc: TalosDoc = from_str(&text).map_err(|err| Error::RewriteYaml {
    file: source.to_path_buf(),
    source: err,
  })?;
  let invalid = |detail: String| Error::RewriteInvalid {
    file: source.to_path_buf(),
    format: RewriteFormat::Talos,
    detail,
  };
  let (active, identity) = doc.selected(source, invalid)?;
  let allows = TalosDoc::allows(active, invalid)?;
  let label = rewrite_label(source, &doc.context)?;
  let env = label.to_uppercase().replace('-', "_");
  // Identity-only grant: the certificate never reaches the wire as
  // application data, so it can never match the swap; it still needs a value
  // to resolve.
  let value = String::from_utf8_lossy(&identity.crt).into_owned();
  let (guest_cert_path, guest_key_path) = load_or_generate_client_pair(ca, guests_dir, &label)?;
  let guest_cert = fs::read(&guest_cert_path).map_err(|source| Error::ReadFile {
    path: guest_cert_path.clone(),
    source,
  })?;
  let guest_key = fs::read(&guest_key_path).map_err(|source| Error::ReadFile {
    path: guest_key_path.clone(),
    source,
  })?;
  let cert_name = format!("{label}.client.crt");
  let key_name = format!("{label}.client.key");
  let ca_name = format!("{label}.ca.crt");
  let materialized = vec![
    (cert_name.clone(), identity.crt),
    (key_name.clone(), identity.key),
    (ca_name.clone(), identity.ca),
  ];
  let tls = HostTlsCfg {
    client_cert: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{cert_name}"))),
    client_key: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{key_name}"))),
    root_cert: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{ca_name}"))),
    guest_tls_mode: GuestTlsMode::Mtls,
    guest_cert: None,
    guest_key: None,
  };
  let fragment = render_fragment(
    source,
    &label,
    &GrantFragment {
      env,
      registry: false,
      allow: allows.clone(),
      value: Some(value),
      real: None,
      if_missing: None,
      tls: allows.iter().map(|allow| (allow.clone(), tls.clone())).collect(),
      ssh: BTreeMap::new(),
    },
  )?;
  let decoy = decoy_doc(&text, source, ca, &guest_cert, &guest_key, &doc.context)?;
  Ok(RewriteAdapted {
    fragment,
    decoy,
    materialized,
    decoy_files: Vec::new(),
  })
}

/// One endpoint as an allow entry: the grant grammar needs a scheme, and the
/// Talos API is TLS-only, so bare hosts and `host:port` forms gain
/// `https://`; a bare host also gains the default API port 50000. URL forms
/// pass through for `EndpointScope` to judge.
fn normalize_endpoint(endpoint: &str) -> String {
  if endpoint.contains("://") {
    return endpoint.to_string();
  }
  let has_port = endpoint
    .rsplit_once(':')
    .is_some_and(|(_, port)| port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty());
  if has_port {
    format!("https://{endpoint}")
  } else {
    format!("https://{endpoint}:50000")
  }
}

/// The agent's decoy talosconfig: the parsed document verbatim, with trust
/// and identity swapped in every context — arkham's CA, the guest pair —
/// because only decoys may cross into the agent. `auth` blocks on contexts
/// beyond the active one are dropped: they carry Omni credential config the
/// adapter cannot substitute. Every other field round-trips unchanged.
fn decoy_doc(text: &str, source: &Path, ca: &CertAuthority, guest_cert: &[u8], guest_key: &[u8], active: &str) -> Result<String, Error> {
  let mut root: Value = from_str(text).map_err(|err| Error::RewriteYaml {
    file: source.to_path_buf(),
    source: err,
  })?;
  let guest_ca = Value::String(STANDARD.encode(ca.cert_pem()));
  let guest_cert = Value::String(STANDARD.encode(guest_cert));
  let guest_key = Value::String(STANDARD.encode(guest_key));
  let Some(contexts) = root
    .as_mapping_mut()
    .and_then(|map| map.get_mut(Value::String("contexts".to_string())))
    .and_then(Value::as_mapping_mut)
  else {
    return render_decoy(&root);
  };
  let names = contexts
    .keys()
    .filter_map(|key| key.as_str().map(str::to_string))
    .collect::<Vec<_>>();
  for name in names {
    let Some(context) = contexts.get_mut(Value::String(name.clone())).and_then(Value::as_mapping_mut) else {
      continue;
    };
    let ca_key = Value::String("ca".to_string());
    let crt_key = Value::String("crt".to_string());
    let key_key = Value::String("key".to_string());
    if context.contains_key(&ca_key) {
      context.insert(ca_key, guest_ca.clone());
    }
    if context.contains_key(&crt_key) || context.contains_key(&key_key) {
      context.insert(crt_key, guest_cert.clone());
      context.insert(key_key, guest_key.clone());
    }
    if name != active {
      context.remove(Value::String("auth".to_string()));
    }
  }
  render_decoy(&root)
}

#[cfg(test)]
mod tests {
  use super::*;

  const SOURCE: &str = "/home/ivan/.talos/config";

  fn test_ca() -> CertAuthority {
    CertAuthority::generate().unwrap()
  }

  fn doc(endpoints: &str) -> String {
    format!(
      "context: prod\ncontexts:\n  prod:\n    endpoints:\n{endpoints}    ca: {}\n    crt: {}\n    key: {}\n",
      STANDARD.encode(b"CA"),
      STANDARD.encode(b"CRT"),
      STANDARD.encode(b"KEY"),
    )
  }

  #[test]
  fn bare_endpoint_gains_talos_port() {
    assert_eq!(normalize_endpoint("10.5.0.6"), "https://10.5.0.6:50000");
    assert_eq!(normalize_endpoint("10.5.0.6:50001"), "https://10.5.0.6:50001");
    assert_eq!(normalize_endpoint("https://omni.example"), "https://omni.example");
  }

  #[test]
  fn valid_doc_adapts_with_https_grant_and_guest_identity() {
    let dir = tempfile::tempdir().unwrap();
    let adapted = adapt(Path::new(SOURCE), doc("      - 10.5.0.6\n").as_bytes(), &test_ca(), dir.path()).unwrap();
    assert!(
      adapted.fragment.contains("allow = [\"https://10.5.0.6:50000\"]"),
      "{}",
      adapted.fragment
    );
    assert!(
      adapted.fragment.contains("[rules.home-ivan-talos-config-prod]"),
      "{}",
      adapted.fragment
    );
    assert!(
      adapted.fragment.contains(&format!("client_cert = \"{GRANTS_STATE_DIR}/rules.d/")),
      "{}",
      adapted.fragment
    );
    assert!(adapted.decoy.contains("endpoints:\n    - 10.5.0.6"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("context: prod"), "{}", adapted.decoy);
    assert_eq!(adapted.materialized.len(), 3);
  }

  #[test]
  fn decoy_round_trips_every_context() {
    let body = format!(
      "context: prod\ncontexts:\n  prod:\n    endpoints:\n      - 10.5.0.6\n    ca: {}\n    crt: {}\n    key: {}\n  staging:\n    endpoints:\n      - 10.6.0.7\n    nodes:\n      - 10.6.0.8\n    ca: {}\n    crt: {}\n    key: {}\n",
      STANDARD.encode(b"CA"),
      STANDARD.encode(b"CRT"),
      STANDARD.encode(b"KEY"),
      STANDARD.encode(b"CA2"),
      STANDARD.encode(b"CRT2"),
      STANDARD.encode(b"KEY2"),
    );
    let dir = tempfile::tempdir().unwrap();
    let adapted = adapt(Path::new(SOURCE), body.as_bytes(), &test_ca(), dir.path()).unwrap();
    let decoy = &adapted.decoy;
    assert!(decoy.contains("staging:"), "{decoy}");
    assert!(decoy.contains("- 10.6.0.7"), "{decoy}");
    assert!(decoy.contains("- 10.6.0.8"), "{decoy}");
    assert!(
      !decoy.contains(&STANDARD.encode(b"CA2")),
      "no real CA survives in any context: {decoy}"
    );
    assert!(
      !decoy.contains(&STANDARD.encode(b"CRT2")),
      "no real identity survives in any context: {decoy}"
    );
    assert!(
      !decoy.contains(&STANDARD.encode(b"KEY2")),
      "no real key survives in any context: {decoy}"
    );
  }

  #[test]
  fn url_endpoint_passes_through() {
    let dir = tempfile::tempdir().unwrap();
    let adapted = adapt(
      Path::new(SOURCE),
      doc("      - https://omni.example:443\n").as_bytes(),
      &test_ca(),
      dir.path(),
    )
    .unwrap();
    assert!(
      adapted.fragment.contains("allow = [\"https://omni.example:443\"]"),
      "{}",
      adapted.fragment
    );
  }

  #[test]
  fn missing_or_unknown_context_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), b"context:\ncontexts: {}\n", &test_ca(), dir.path()).unwrap_err();
    assert!(err.to_string().contains("missing `context`"), "{err}");
    let err = adapt(
      Path::new(SOURCE),
      b"context: nope\ncontexts:\n  prod:\n    endpoints: [10.5.0.6]\n",
      &test_ca(),
      dir.path(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("unknown context `nope`"), "{err}");
  }

  #[test]
  fn empty_endpoints_or_half_identity_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let no_endpoints = doc("");
    let err = adapt(Path::new(SOURCE), no_endpoints.as_bytes(), &test_ca(), dir.path()).unwrap_err();
    assert!(err.to_string().contains("states no `endpoints`"), "{err}");
    let auth = doc("      - 10.5.0.6\n").replace(&STANDARD.encode(b"CRT"), "");
    let err = adapt(Path::new(SOURCE), auth.as_bytes(), &test_ca(), dir.path()).unwrap_err();
    assert!(err.to_string().contains("misses `ca`, `crt`, or `key`"), "{err}");
    let bad = doc("      - 10.5.0.6\n").replace("Q0E=", "not-base64");
    let err = adapt(Path::new(SOURCE), bad.as_bytes(), &test_ca(), dir.path()).unwrap_err();
    assert!(err.to_string().contains("not valid base64"), "{err}");
  }

  #[test]
  fn alternative_auth_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let omni = "context: omni\ncontexts:\n  omni:\n    endpoints: [omni.example]\n    auth:\n      siderov1:\n        identity: me\n";
    let err = adapt(Path::new(SOURCE), omni.as_bytes(), &test_ca(), dir.path()).unwrap_err();
    assert!(err.to_string().contains("`auth`"), "{err}");
  }

  #[test]
  fn nodes_carry_into_decoy() {
    let dir = tempfile::tempdir().unwrap();
    let with_nodes = doc("      - 10.5.0.6\n").replace("    ca:", "    nodes:\n      - 10.5.0.7\n    ca:");
    let adapted = adapt(Path::new(SOURCE), with_nodes.as_bytes(), &test_ca(), dir.path()).unwrap();
    assert!(adapted.decoy.contains("nodes:\n    - 10.5.0.7"), "{}", adapted.decoy);
  }
}
