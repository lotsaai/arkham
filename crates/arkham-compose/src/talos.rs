//! Talosconfig adapter for `file_rewrite`: a talosconfig is the same
//! information a rule holds — endpoints, an upstream CA, and a client pair —
//! stated in talosctl's shape, so the adapter derives one grant per context
//! instead of asking the operator to state it twice. The `context` key is
//! copied through and is not how a grant is chosen. A talos entry stating
//! `envs` is an error rather than a second source.
//!
//! Detection is structural: a YAML mapping with `contexts:` and `endpoints:`
//! markers takes the adapter path, everything else keeps the raw byte-swap.
//! The decoy twin keeps the endpoints (transparent capture makes the
//! destination the identity) and swaps the trust and identity of every
//! granted context: arkham's CA and that context's guest pair.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::config::{HostTlsCfg, RewriteFormat};
use arkham_config::context::{AmbientProtocol, ContextRef, Presented, identities, require_distinct};
use arkham_config::grants::{EndpointScope, GuestTlsMode, HostPat, Scheme};
use arkham_pki::ca::{CertAuthority, load_or_generate_client_pair};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_yaml::{Mapping, Value, from_str};

use crate::adapt::{GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, decode, render_decoy, render_fragment};
use crate::error::Error;

/// Why one context did not become a grant. The active context turns a skip
/// into [`Error::RewriteInvalid`]. Every other context is warned and omitted.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TalosSkip {
  /// The context lists no endpoints.
  #[error("context `{name}` states no `endpoints`")]
  NoEndpoints {
    /// Context name.
    name: String,
  },
  /// The context has no client pair to substitute.
  #[error("context `{name}` misses `ca`, `crt`, or `key`: nothing to substitute")]
  MissingIdentity {
    /// Context name.
    name: String,
  },
  /// Omni or another service-account `auth` block. Out of scope.
  #[error("context `{name}` uses alternative `auth` (Omni/SideroV1): it carries no substitutable client pair")]
  Auth {
    /// Context name.
    name: String,
  },
  /// An endpoint that is not TLS.
  #[error("context `{name}` endpoint `{endpoint}` is not TLS: the Talos API is TLS-only")]
  NotTls {
    /// Context name.
    name: String,
    /// Endpoint text from the file.
    endpoint: String,
  },
  /// An endpoint that does not parse as an allow entry.
  #[error("context `{name}` endpoint `{endpoint}` is not an allow entry: {detail}")]
  BadEndpoint {
    /// Context name.
    name: String,
    /// Endpoint text from the file.
    endpoint: String,
    /// Parser detail.
    detail: String,
  },
}

impl TalosSkip {
  fn name(&self) -> &str {
    match self {
      Self::NoEndpoints { name }
      | Self::MissingIdentity { name }
      | Self::Auth { name }
      | Self::NotTls { name, .. }
      | Self::BadEndpoint { name, .. } => name,
    }
  }
}

/// Grants derived from one talosconfig, plus the contexts that were skipped.
#[derive(Debug)]
pub(crate) struct TalosAdapted {
  /// One grant per context that carried a substitutable client pair.
  pub(crate) grants: Vec<RewriteAdapted>,
  /// Contexts that were named and left out.
  pub(crate) skipped: Vec<TalosSkip>,
}

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
  /// Alternative auth (Omni/SideroV1): detected so it is skipped or rejected.
  #[serde(default)]
  auth: Option<Mapping>,
}

/// One context that can become a grant, before its guest pair is minted.
struct Prepared {
  name: String,
  crt: Vec<u8>,
  key: Vec<u8>,
  ca: Vec<u8>,
  allows: Vec<Allowed>,
}

/// One allow entry and the scope parsed from it.
struct Allowed {
  entry: String,
  scope: EndpointScope,
}

/// Classification of one context.
enum Prep {
  Grant(Prepared),
  Skip(TalosSkip),
}

/// Map a talosconfig onto one grant per context and one decoy document.
///
/// # Errors
///
/// Returns an error when the document does not parse, the active context is
/// missing, unknown, or itself skipped, a certificate field is not base64,
/// or two granted contexts cannot be told apart on one destination.
pub(crate) fn adapt(source: &Path, content: &[u8], ca: &CertAuthority, guests_dir: &Path) -> Result<TalosAdapted, Error> {
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
  if doc.context.is_empty() {
    return Err(invalid("missing `context`".to_string()));
  }
  if !doc.contexts.contains_key(&doc.context) {
    return Err(invalid(format!("unknown context `{}`", doc.context)));
  }
  let mut prepared = Vec::new();
  let mut skipped = Vec::new();
  for (name, context) in &doc.contexts {
    match prepare(source, name, context)? {
      Prep::Skip(skip) if name == &doc.context => return Err(invalid(skip.to_string())),
      Prep::Skip(skip) => {
        tracing::warn!(%skip, "talos context skipped");
        skipped.push(skip);
      }
      Prep::Grant(item) => prepared.push(item),
    }
  }
  if prepared.is_empty() {
    return Err(invalid(format!("context `{}` did not produce a grant", doc.context)));
  }
  let refs = prepared
    .iter()
    .map(|item| ContextRef {
      source,
      protocol: AmbientProtocol::Talos,
      name: item.name.as_str(),
    })
    .collect::<Vec<_>>();
  let ids = identities(&refs)?;
  let mut guest_certs = Vec::with_capacity(prepared.len());
  let mut guest_keys = Vec::with_capacity(prepared.len());
  for id in &ids {
    let (cert_path, key_path) = load_or_generate_client_pair(ca, guests_dir, &id.label)?;
    guest_certs.push(fs::read(&cert_path).map_err(|source| Error::ReadFile { path: cert_path, source })?);
    guest_keys.push(fs::read(&key_path).map_err(|source| Error::ReadFile { path: key_path, source })?);
  }
  let mut presented = Vec::new();
  for ((item, id), guest_cert) in prepared.iter().zip(ids.iter()).zip(guest_certs.iter()) {
    for allow in &item.allows {
      let HostPat::Exact(host) = &allow.scope.host else {
        return Err(invalid(format!(
          "context `{}` endpoint `{}` is not an exact host",
          item.name, allow.entry
        )));
      };
      presented.push(Presented {
        identity: id,
        host: host.as_str(),
        port: allow.scope.port,
        decoy: guest_cert.as_slice(),
      });
    }
  }
  require_distinct(&presented)?;
  let decoy = decoy_doc(&text, source, ca, &prepared, &guest_certs, &guest_keys, &skipped)?;
  if ids.len() != prepared.len() {
    return Err(invalid("talos context identities did not cover every granted context".to_string()));
  }
  let mut grants = Vec::with_capacity(prepared.len());
  for ((item, id), guest_cert) in prepared.iter().zip(ids.iter()).zip(guest_certs.iter()) {
    grants.push(one_grant(source, item, id, guest_cert, &decoy)?);
  }
  Ok(TalosAdapted { grants, skipped })
}

/// Validate one context. A bad base64 field fails the file. Every other
/// problem is a skip the caller turns into an error only for the active name.
///
/// # Errors
///
/// Returns an error when `ca`, `crt`, or `key` is present and not base64.
fn prepare(source: &Path, name: &str, context: &TalosContext) -> Result<Prep, Error> {
  if context.endpoints.is_empty() {
    return Ok(Prep::Skip(TalosSkip::NoEndpoints { name: name.to_string() }));
  }
  if context.auth.is_some() {
    return Ok(Prep::Skip(TalosSkip::Auth { name: name.to_string() }));
  }
  let crt = decode(source, RewriteFormat::Talos, Some(context.crt.as_str()), "crt")?;
  let key = decode(source, RewriteFormat::Talos, Some(context.key.as_str()), "key")?;
  let ca_bundle = decode(source, RewriteFormat::Talos, Some(context.ca.as_str()), "ca")?;
  let (Some(crt), Some(key), Some(ca_bundle)) = (crt, key, ca_bundle) else {
    return Ok(Prep::Skip(TalosSkip::MissingIdentity { name: name.to_string() }));
  };
  match allows(name, context) {
    Ok(parsed) => Ok(Prep::Grant(Prepared {
      name: name.to_string(),
      crt,
      key,
      ca: ca_bundle,
      allows: parsed,
    })),
    Err(skip) => Ok(Prep::Skip(skip)),
  }
}

/// One allow entry per endpoint, `https://`-normalized and validated.
fn allows(name: &str, context: &TalosContext) -> Result<Vec<Allowed>, TalosSkip> {
  let mut parsed = Vec::new();
  for endpoint in &context.endpoints {
    let entry = normalize_endpoint(endpoint);
    let scope = match entry.parse::<EndpointScope>() {
      Ok(scope) => scope,
      Err(detail) => {
        return Err(TalosSkip::BadEndpoint {
          name: name.to_string(),
          endpoint: endpoint.clone(),
          detail,
        });
      }
    };
    if scope.scheme != Scheme::Https {
      return Err(TalosSkip::NotTls {
        name: name.to_string(),
        endpoint: endpoint.clone(),
      });
    }
    parsed.push(Allowed { entry, scope });
  }
  Ok(parsed)
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

/// The agent's decoy talosconfig. Granted contexts receive arkham's CA and
/// that context's guest pair. Skipped contexts lose `ca`, `crt`, `key`, and
/// `auth`, so real material is absent. Every other field round-trips,
/// including the active `context` name.
fn decoy_doc(
  text: &str,
  source: &Path,
  ca: &CertAuthority,
  prepared: &[Prepared],
  guest_certs: &[Vec<u8>],
  guest_keys: &[Vec<u8>],
  skipped: &[TalosSkip],
) -> Result<String, Error> {
  let mut root: Value = from_str(text).map_err(|err| Error::RewriteYaml {
    file: source.to_path_buf(),
    source: err,
  })?;
  let guest_ca = Value::String(STANDARD.encode(ca.cert_pem()));
  let Some(contexts) = root
    .as_mapping_mut()
    .and_then(|map| map.get_mut(Value::String("contexts".to_string())))
    .and_then(Value::as_mapping_mut)
  else {
    return render_decoy(&root);
  };
  for ((item, guest_cert), guest_key) in prepared.iter().zip(guest_certs.iter()).zip(guest_keys.iter()) {
    let Some(context) = contexts.get_mut(Value::String(item.name.clone())).and_then(Value::as_mapping_mut) else {
      continue;
    };
    context.insert(Value::String("ca".to_string()), guest_ca.clone());
    context.insert(Value::String("crt".to_string()), Value::String(STANDARD.encode(guest_cert)));
    context.insert(Value::String("key".to_string()), Value::String(STANDARD.encode(guest_key)));
  }
  for skip in skipped {
    let Some(context) = contexts
      .get_mut(Value::String(skip.name().to_string()))
      .and_then(Value::as_mapping_mut)
    else {
      continue;
    };
    for field in ["ca", "crt", "key", "auth"] {
      context.remove(Value::String(field.to_string()));
    }
  }
  render_decoy(&root)
}

/// One context's fragment, its materialized blobs, and the shared decoy.
///
/// # Errors
///
/// Returns an error when the fragment fails to serialize.
fn one_grant(
  source: &Path,
  item: &Prepared,
  id: &arkham_config::context::ContextIdentity,
  guest_cert: &[u8],
  decoy: &str,
) -> Result<RewriteAdapted, Error> {
  let label = &id.label;
  let value = String::from_utf8_lossy(&item.crt).into_owned();
  let cert_name = format!("{label}.client.crt");
  let key_name = format!("{label}.client.key");
  let ca_name = format!("{label}.ca.crt");
  let guest_name = format!("{label}.guest.crt");
  let materialized = vec![
    (cert_name.clone(), item.crt.clone()),
    (key_name.clone(), item.key.clone()),
    (ca_name.clone(), item.ca.clone()),
    (guest_name, guest_cert.to_vec()),
  ];
  let tls = HostTlsCfg {
    client_cert: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{cert_name}"))),
    client_key: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{key_name}"))),
    root_cert: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{ca_name}"))),
    guest_tls_mode: GuestTlsMode::Mtls,
    guest_cert: None,
    guest_key: None,
  };
  let allows = item.allows.iter().map(|allow| allow.entry.clone()).collect::<Vec<_>>();
  let fragment = render_fragment(
    source,
    label,
    &GrantFragment {
      env: id.env(),
      registry: false,
      allow: allows.clone(),
      value: Some(value),
      real: None,
      generated: false,
      if_missing: None,
      tls: allows.into_iter().map(|allow| (allow, tls.clone())).collect(),
      ssh: BTreeMap::new(),
    },
  )?;
  Ok(RewriteAdapted {
    fragment,
    decoy: decoy.to_string(),
    materialized,
    decoy_files: Vec::new(),
  })
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

  fn parts(adapted: &TalosAdapted) -> (String, String) {
    let fragment = adapted
      .grants
      .iter()
      .map(|grant| grant.fragment.as_str())
      .collect::<Vec<_>>()
      .join("\n");
    let decoy = adapted.grants.first().map(|grant| grant.decoy.clone()).unwrap_or_default();
    (fragment, decoy)
  }

  fn prod_label() -> String {
    identities(&[ContextRef {
      source: Path::new(SOURCE),
      protocol: AmbientProtocol::Talos,
      name: "prod",
    }])
    .unwrap()
    .into_iter()
    .next()
    .unwrap()
    .label
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
    let (fragment, decoy) = parts(&adapted);
    let label = prod_label();
    assert!(fragment.contains("allow = [\"https://10.5.0.6:50000\"]"), "{fragment}");
    assert!(fragment.contains(&format!("[rules.{label}]")), "{fragment}");
    assert!(
      fragment.contains(&format!("client_cert = \"{GRANTS_STATE_DIR}/rules.d/")),
      "{fragment}"
    );
    assert!(fragment.contains("guest_tls_mode = \"mtls\""), "{fragment}");
    assert!(decoy.contains("endpoints:\n    - 10.5.0.6"), "{decoy}");
    assert!(decoy.contains("context: prod"), "{decoy}");
    assert_eq!(adapted.grants[0].materialized.len(), 4);
    assert!(adapted.grants[0].materialized.iter().any(|(name, _)| name.ends_with(".guest.crt")));
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
    let (fragment, decoy) = parts(&adapted);
    assert!(fragment.contains("https://10.5.0.6:50000"), "{fragment}");
    assert!(fragment.contains("https://10.6.0.7:50000"), "{fragment}");
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
    let (fragment, _) = parts(&adapted);
    assert!(fragment.contains("allow = [\"https://omni.example:443\"]"), "{fragment}");
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
    let (_, decoy) = parts(&adapted);
    assert!(decoy.contains("nodes:\n    - 10.5.0.7"), "{decoy}");
  }

  #[test]
  fn two_contexts_each_get_a_grant_and_a_distinct_guest_cert() {
    let prod_ca = STANDARD.encode(b"CA-PROD-REAL");
    let prod_crt = STANDARD.encode(b"CRT-PROD-REAL");
    let prod_key = STANDARD.encode(b"KEY-PROD-REAL");
    let staging_ca = STANDARD.encode(b"CA-STAGING-REAL");
    let staging_crt = STANDARD.encode(b"CRT-STAGING-REAL");
    let staging_key = STANDARD.encode(b"KEY-STAGING-REAL");
    let body = format!(
      "context: prod\ncontexts:\n  prod:\n    endpoints:\n      - 10.5.0.6\n    ca: {prod_ca}\n    crt: {prod_crt}\n    key: {prod_key}\n  staging:\n    endpoints:\n      - 10.6.0.7\n    ca: {staging_ca}\n    crt: {staging_crt}\n    key: {staging_key}\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let adapted = adapt(Path::new(SOURCE), body.as_bytes(), &test_ca(), dir.path()).unwrap();
    let (fragment, decoy) = parts(&adapted);
    assert!(
      fragment.contains("https://10.5.0.6:50000") && fragment.contains("https://10.6.0.7:50000"),
      "grant allow for each endpoint missing from {fragment}"
    );
    let crts = crt_values(&decoy);
    assert_eq!(crts.len(), 2, "each granted context keeps a crt: {crts:?}\n{decoy}");
    assert_ne!(crts[0], crts[1], "guest crt values must differ: {crts:?}");
    for real in [&prod_ca, &prod_crt, &prod_key, &staging_ca, &staging_crt, &staging_key] {
      assert!(!decoy.contains(real), "real material `{real}` survives in the decoy");
    }
  }

  #[test]
  fn inactive_auth_context_is_skipped_and_named() {
    let identity = "real-looking-omni-identity";
    let body = format!(
      "context: prod\ncontexts:\n  prod:\n    endpoints:\n      - 10.5.0.6\n    ca: {}\n    crt: {}\n    key: {}\n  omni:\n    endpoints:\n      - https://omni.example:443\n    auth:\n      siderov1:\n        identity: {identity}\n",
      STANDARD.encode(b"CA"),
      STANDARD.encode(b"CRT"),
      STANDARD.encode(b"KEY"),
    );
    let dir = tempfile::tempdir().unwrap();
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let adapted = tracing::subscriber::with_default(WarnCapture(std::sync::Arc::clone(&lines)), || {
      adapt(Path::new(SOURCE), body.as_bytes(), &test_ca(), dir.path()).unwrap()
    });
    let (fragment, decoy) = parts(&adapted);
    assert!(fragment.contains("https://10.5.0.6:50000"), "prod is granted: {fragment}");
    assert!(!fragment.contains("omni.example"), "omni is not an allow entry: {fragment}");
    assert!(!decoy.contains(identity), "auth identity survives in the decoy: {decoy}");
    assert!(
      adapted
        .skipped
        .iter()
        .any(|skip| matches!(skip, TalosSkip::Auth { name } if name == "omni")),
      "skip names omni: {:?}",
      adapted.skipped
    );
    let warnings = lines.lock().unwrap();
    assert!(warnings.iter().any(|line| line.contains("omni")), "skip names omni: {warnings:?}");
  }

  #[test]
  fn selected_context_without_endpoints_still_fails() {
    let body = format!(
      "context: prod\ncontexts:\n  prod:\n    endpoints: []\n  staging:\n    endpoints:\n      - 10.6.0.7\n    ca: {}\n    crt: {}\n    key: {}\n",
      STANDARD.encode(b"CA-STAGING"),
      STANDARD.encode(b"CRT-STAGING"),
      STANDARD.encode(b"KEY-STAGING"),
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), body.as_bytes(), &test_ca(), dir.path()).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("prod"), "{text}");
    assert!(text.contains("endpoints"), "{text}");
  }

  fn crt_values(decoy: &str) -> Vec<String> {
    let value: serde_yaml::Value = serde_yaml::from_str(decoy).unwrap();
    let Some(contexts) = value.get("contexts").and_then(serde_yaml::Value::as_mapping) else {
      return Vec::new();
    };
    contexts
      .values()
      .filter_map(|context| context.get("crt").and_then(serde_yaml::Value::as_str).map(str::to_string))
      .collect()
  }

  struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

  impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
      *metadata.level() <= tracing::Level::WARN
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
      tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
      let mut message = String::new();
      event.record(&mut WarnVisit(&mut message));
      self.0.lock().unwrap().push(message);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
  }

  struct WarnVisit<'a>(&'a mut String);

  impl tracing::field::Visit for WarnVisit<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
      use std::fmt::Write as _;
      let _ = write!(self.0, "{}={value:?};", field.name());
    }
  }
}

#[cfg(test)]
mod moved_suite {

  use std::fs;

  use arkham_config::config::{FileRewrite, RewriteFormat};
  use tempfile::tempdir;

  use crate::decoys::*;
  use crate::expand::*;

  use crate::rewrites::*;

  /// Talosconfig sources adapt with no `envs`, stated or sniffed, and an
  /// `envs` statement is rejected either way. The decoy mounts writable.
  #[test]
  fn talos_rewrites_adapt_stated_or_sniffed() {
    use std::collections::HashMap;

    use arkham_pki::ca::CertAuthority;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let talos_doc = format!(
      "context: prod\ncontexts:\n  prod:\n    endpoints:\n      - 10.5.0.6\n    ca: {}\n    crt: {}\n    key: {}\n",
      STANDARD.encode(b"CA"),
      STANDARD.encode(b"CRT"),
      STANDARD.encode(b"KEY"),
    );
    let dir = tempdir().unwrap();
    let source = dir.path().join("talosconfig");
    fs::write(&source, talos_doc).unwrap();
    let ca = CertAuthority::generate().unwrap();
    let expander = build_expander(HashMap::new());
    let files = dir.path().join("files");
    let guests = dir.path().join("guests");
    for format in [None, Some(RewriteFormat::Talos)] {
      let outputs = write_rewrites(&RewriteInputs {
        files_dir: &files,
        root: dir.path(),
        rewrites: &[FileRewrite {
          source: source.clone(),
          dest: "{home}/.talos/config".to_string(),
          envs: Vec::new(),
          format,
        }],
        decoys: &[],
        env: &HashMap::new(),
        expander: &expander,
        home: "/home/eng",
        host_home: None,
        kube_ca: Some(&ca),
        guests_dir: &guests,
      })
      .unwrap();
      assert_eq!(outputs.grants.len(), 1);
      assert!(
        outputs.grants[0].fragment.contains("https://10.5.0.6:50000"),
        "{}",
        outputs.grants[0].fragment
      );
      assert!(!outputs.mounts[0].ro, "talos decoy is writable");
      let body = fs::read_to_string(&outputs.mounts[0].host).unwrap();
      assert!(body.contains("endpoints:\n    - 10.5.0.6"), "{body}");
      assert!(!body.contains(&STANDARD.encode(b"CRT")), "no real credential survives: {body}");
    }
    let error = write_rewrites(&RewriteInputs {
      files_dir: &files,
      root: dir.path(),
      rewrites: &[FileRewrite {
        source: source.clone(),
        dest: "{home}/.talos/config".to_string(),
        envs: vec!["TALOS_CERT".to_string()],
        format: Some(RewriteFormat::Talos),
      }],
      decoys: &[Decoy {
        env: "TALOS_CERT".to_string(),
        value: "decoy-cert".to_string(),
      }],
      env: &HashMap::from([("TALOS_CERT".to_string(), "real-cert".to_string())]),
      expander: &expander,
      home: "/home/eng",
      host_home: None,
      kube_ca: Some(&ca),
      guests_dir: &guests,
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("drop `envs`"), "{error}");
  }
}
