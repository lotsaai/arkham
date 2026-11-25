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

use arkham_config::config::RewriteFormat;
use arkham_config::grants::{EndpointScope, HostPat};
use arkham_pki::ca::{CertAuthority, load_or_generate_client_pair};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_yaml::{Mapping, Value, from_str};

use arkham_tool_config::context::{ContextIdentity, ContextRef, Presented, identities, require_distinct};
use arkham_tool_config::{GrantFragment, RewriteAdapted, decode, materialize_client_tls, render_decoy, render_fragment};

/// Prefix used for Talos client material in the grants state directory.
pub const BLOB_PREFIX_TALOS: &str = "talos-";

/// Context tag of one Talos context.
const CONTEXT_TAG: &str = "talos";

/// A fatal Talos adaptation failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A shared tool configuration failure.
  #[error(transparent)]
  Shared(#[from] arkham_tool_config::Error),
  /// A certificate authority failure.
  #[error(transparent)]
  Pki(#[from] arkham_pki::Error),
  /// An identity file could not be read.
  #[error("read {}: {source}", path.display())]
  ReadFile {
    /// File that could not be read.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: std::io::Error,
  },
  /// An adapted rewrite is not valid YAML.
  #[error("file rewrite `{}`: does not parse as YAML: {source}", file.display())]
  RewriteYaml {
    /// Rewrite source.
    file: PathBuf,
    /// Underlying parse failure.
    #[source]
    source: serde_yaml::Error,
  },
}

impl Error {
  /// Return a safe registration failure category without source details.
  #[must_use]
  pub fn registration_summary(&self) -> &'static str {
    match self {
      Self::Shared(source) => source.registration_summary(),
      Self::Pki(_) | Self::ReadFile { .. } | Self::RewriteYaml { .. } => "configuration could not be read",
    }
  }
}

/// A result produced by Talos adaptation.
pub type Result<T> = std::result::Result<T, Error>;

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
  /// Alternative auth (Omni/SideroV1): no client pair to substitute.
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

/// Map a talosconfig onto one grant per context and one decoy document. A
/// context without endpoints or a client pair, or with an `auth` block, gets
/// no grant and loses its real material in the decoy.
///
/// # Errors
///
/// Returns an error when the document does not parse, the active context is
/// missing, unknown, or has nothing to substitute, an endpoint is not an
/// allow entry, a certificate field is not base64, or two granted contexts
/// cannot be told apart on one destination.
pub fn adapt(source: &Path, content: &[u8], ca: &CertAuthority, guests_dir: &Path) -> Result<Vec<RewriteAdapted>> {
  let text = String::from_utf8_lossy(content);
  let doc: TalosDoc = from_str(&text).map_err(|err| Error::RewriteYaml {
    file: source.to_path_buf(),
    source: err,
  })?;
  let invalid = |detail: String| {
    Error::Shared(arkham_tool_config::Error::RewriteInvalid {
      file: source.to_path_buf(),
      format: RewriteFormat::Talos,
      detail,
    })
  };
  if doc.context.is_empty() {
    return Err(invalid("missing `context`".to_string()));
  }
  if !doc.contexts.contains_key(&doc.context) {
    return Err(invalid(format!("unknown context `{}`", doc.context)));
  }
  let mut prepared = Vec::new();
  let mut stripped = Vec::new();
  for (name, context) in &doc.contexts {
    match prepare(source, name, context)? {
      Some(item) => prepared.push(item),
      None if name == &doc.context => {
        return Err(invalid(format!(
          "context `{name}` has no endpoints, no `ca`/`crt`/`key` pair, or an `auth` block: nothing to substitute"
        )));
      }
      None => {
        tracing::warn!(context = %name, "talos context has no endpoints or client pair, or uses `auth`: no grant");
        stripped.push(name.as_str());
      }
    }
  }
  if prepared.is_empty() {
    return Err(invalid(format!("context `{}` did not produce a grant", doc.context)));
  }
  let refs = prepared
    .iter()
    .map(|item| ContextRef {
      source,
      tag: CONTEXT_TAG,
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
  for (item, id) in prepared.iter().zip(ids.iter()) {
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
        decoy: b"",
      });
    }
  }
  require_distinct(&presented)?;
  let decoy = decoy_doc(&text, source, ca, &prepared, &guest_certs, &guest_keys, &stripped)?;
  if ids.len() != prepared.len() {
    return Err(invalid("talos context identities did not cover every granted context".to_string()));
  }
  let mut grants = Vec::with_capacity(prepared.len());
  for (item, id) in prepared.iter().zip(ids.iter()) {
    grants.push(one_grant(source, item, id, &decoy)?);
  }
  Ok(grants)
}

/// Validate one context. `None` when it has nothing to substitute. A bad
/// base64 field or an endpoint that is not an allow entry fails the file.
///
/// # Errors
///
/// Returns an error when `ca`, `crt`, or `key` is present and not base64, or
/// an endpoint does not parse.
fn prepare(source: &Path, name: &str, context: &TalosContext) -> Result<Option<Prepared>> {
  if context.endpoints.is_empty() || context.auth.is_some() {
    return Ok(None);
  }
  let crt = decode(source, RewriteFormat::Talos, Some(context.crt.as_str()), "crt")?;
  let key = decode(source, RewriteFormat::Talos, Some(context.key.as_str()), "key")?;
  let ca_bundle = decode(source, RewriteFormat::Talos, Some(context.ca.as_str()), "ca")?;
  let (Some(crt), Some(key), Some(ca_bundle)) = (crt, key, ca_bundle) else {
    return Ok(None);
  };
  let mut allows = Vec::with_capacity(context.endpoints.len());
  for endpoint in &context.endpoints {
    let entry = normalize_endpoint(endpoint);
    let scope = entry.parse::<EndpointScope>().map_err(|detail| {
      Error::Shared(arkham_tool_config::Error::RewriteInvalid {
        file: source.to_path_buf(),
        format: RewriteFormat::Talos,
        detail: format!("context `{name}` endpoint `{endpoint}` is not an allow entry: {detail}"),
      })
    })?;
    allows.push(Allowed { entry, scope });
  }
  Ok(Some(Prepared {
    name: name.to_string(),
    crt,
    key,
    ca: ca_bundle,
    allows,
  }))
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
/// that context's guest pair. Contexts in `stripped` lose `ca`, `crt`, `key`,
/// and `auth`, so real material is absent. Every other field round-trips,
/// including the active `context` name.
fn decoy_doc(
  text: &str,
  source: &Path,
  ca: &CertAuthority,
  prepared: &[Prepared],
  guest_certs: &[Vec<u8>],
  guest_keys: &[Vec<u8>],
  stripped: &[&str],
) -> Result<String> {
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
    return Ok(render_decoy(&root)?);
  };
  for ((item, guest_cert), guest_key) in prepared.iter().zip(guest_certs.iter()).zip(guest_keys.iter()) {
    let Some(context) = contexts.get_mut(Value::String(item.name.clone())).and_then(Value::as_mapping_mut) else {
      continue;
    };
    context.insert(Value::String("ca".to_string()), guest_ca.clone());
    context.insert(Value::String("crt".to_string()), Value::String(STANDARD.encode(guest_cert)));
    context.insert(Value::String("key".to_string()), Value::String(STANDARD.encode(guest_key)));
  }
  for name in stripped {
    let Some(context) = contexts.get_mut(Value::String((*name).to_string())).and_then(Value::as_mapping_mut) else {
      continue;
    };
    for field in ["ca", "crt", "key", "auth"] {
      context.remove(Value::String(field.to_string()));
    }
  }
  Ok(render_decoy(&root)?)
}

const ED25519_PRIVATE_KEY: &str = "ED25519 PRIVATE KEY";

/// Talos writes PKCS#8 under `ED25519 PRIVATE KEY`. rustls reads that encoding
/// from a `PRIVATE KEY` section. Other labels pass through.
fn client_key_pem(raw: &[u8]) -> Vec<u8> {
  let Ok(blocks) = pem::parse_many(raw) else {
    return raw.to_vec();
  };
  if !blocks.iter().any(|block| block.tag() == ED25519_PRIVATE_KEY) {
    return raw.to_vec();
  }
  let renamed = blocks
    .into_iter()
    .map(|block| {
      let tag = if block.tag() == ED25519_PRIVATE_KEY {
        "PRIVATE KEY".to_string()
      } else {
        block.tag().to_string()
      };
      pem::Pem::new(tag, block.into_contents())
    })
    .collect::<Vec<_>>();
  pem::encode_many(&renamed).into_bytes()
}

/// One context's fragment, its materialized blobs, and the shared decoy.
///
/// # Errors
///
/// Returns an error when the fragment fails to serialize.
fn one_grant(source: &Path, item: &Prepared, id: &ContextIdentity, decoy: &str) -> Result<RewriteAdapted> {
  let label = &id.label;
  let value = String::from_utf8_lossy(&item.crt).into_owned();
  let (tls, materialized) = materialize_client_tls(label, Some((item.crt.clone(), client_key_pem(&item.key))), Some(item.ca.clone()));
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
  use arkham_tool_config::{Error as SharedError, GRANTS_STATE_DIR};
  use rustls::pki_types::pem::PemObject as _;

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

  fn parts(adapted: &[RewriteAdapted]) -> (String, String) {
    let fragment = adapted.iter().map(|grant| grant.fragment.as_str()).collect::<Vec<_>>().join("\n");
    let decoy = adapted.first().map_or_default(|grant| grant.decoy.clone());
    (fragment, decoy)
  }

  fn prod_label() -> String {
    identities(&[ContextRef {
      source: Path::new(SOURCE),
      tag: CONTEXT_TAG,
      name: "prod",
    }])
    .unwrap()
    .into_iter()
    .next()
    .unwrap()
    .label
  }

  fn ed25519_pkcs8() -> Vec<u8> {
    let mut der = vec![
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ];
    der.extend(std::iter::repeat_n(0x11, 32));
    der
  }

  fn ed25519_private_key_pem() -> String {
    let body = STANDARD.encode(ed25519_pkcs8());
    format!("-----BEGIN ED25519 PRIVATE KEY-----\n{body}\n-----END ED25519 PRIVATE KEY-----\n")
  }

  #[test]
  fn talos_ed25519_client_key_loads_as_pkcs8() {
    let key_pem = ed25519_private_key_pem();
    let body = format!(
      "context: prod\ncontexts:\n  prod:\n    endpoints:\n      - 10.5.0.6\n    ca: {}\n    crt: {}\n    key: {}\n",
      STANDARD.encode(b"CA"),
      STANDARD.encode(b"CRT"),
      STANDARD.encode(key_pem.as_bytes()),
    );
    let dir = tempfile::tempdir().unwrap();
    let adapted = adapt(Path::new(SOURCE), body.as_bytes(), &test_ca(), dir.path()).unwrap();
    let (_, key) = adapted[0]
      .materialized
      .iter()
      .find(|(name, _)| name.ends_with(".client.key"))
      .expect("client key");
    let parsed = rustls::pki_types::PrivateKeyDer::from_pem_slice(key).expect("rustls reads the written key");
    let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(&parsed).expect("signing key");
    assert_eq!(signing.algorithm(), rustls::SignatureAlgorithm::ED25519);
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
    assert_eq!(adapted[0].materialized.len(), 3);
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
    let original: Value = from_str(&body).unwrap();
    let rewritten: Value = from_str(&decoy).unwrap();
    for context in ["prod", "staging"] {
      for field in ["ca", "crt", "key"] {
        let real = original["contexts"][context][field].as_str().unwrap();
        let fake = rewritten["contexts"][context][field].as_str().unwrap();
        assert_ne!(
          STANDARD.decode(fake).unwrap(),
          STANDARD.decode(real).unwrap(),
          "real {context}.{field} survives"
        );
      }
    }
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
    assert!(
      err.to_string().contains("context `prod`") && err.to_string().contains("nothing to substitute"),
      "{err}"
    );
    let auth = doc("      - 10.5.0.6\n").replace(&STANDARD.encode(b"CRT"), "");
    let err = adapt(Path::new(SOURCE), auth.as_bytes(), &test_ca(), dir.path()).unwrap_err();
    assert!(
      err.to_string().contains("context `prod`") && err.to_string().contains("nothing to substitute"),
      "{err}"
    );
    let bad = doc("      - 10.5.0.6\n").replace("Q0E=", "not-base64");
    let err = adapt(Path::new(SOURCE), bad.as_bytes(), &test_ca(), dir.path()).unwrap_err();
    assert!(err.to_string().contains("not valid base64"), "{err}");
  }

  #[test]
  fn alternative_auth_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let omni = "context: omni\ncontexts:\n  omni:\n    endpoints: [omni.example]\n    auth:\n      siderov1:\n        identity: me\n";
    let err = adapt(Path::new(SOURCE), omni.as_bytes(), &test_ca(), dir.path()).unwrap_err();
    assert!(
      err.to_string().contains("context `omni`") && err.to_string().contains("`auth` block"),
      "{err}"
    );
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
  fn two_contexts_on_one_endpoint_are_ambiguous() {
    let body = format!(
      "context: prod\ncontexts:\n  prod:\n    endpoints:\n      - 10.5.0.6\n    ca: {}\n    crt: {}\n    key: {}\n  staging:\n    endpoints:\n      - 10.5.0.6:50000\n    ca: {}\n    crt: {}\n    key: {}\n",
      STANDARD.encode(b"CA"),
      STANDARD.encode(b"CRT"),
      STANDARD.encode(b"KEY"),
      STANDARD.encode(b"CA2"),
      STANDARD.encode(b"CRT2"),
      STANDARD.encode(b"KEY2"),
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), body.as_bytes(), &test_ca(), dir.path()).expect_err("shared endpoint");
    let Error::Shared(source) = err else {
      panic!("expected the context collision, got {err}");
    };
    assert!(matches!(source, SharedError::AmbiguousContexts(_)), "{source}");
  }

  #[test]
  fn inactive_auth_context_gets_no_grant_and_no_real_material() {
    let identity = "real-looking-omni-identity";
    let body = format!(
      "context: prod\ncontexts:\n  prod:\n    endpoints:\n      - 10.5.0.6\n    ca: {}\n    crt: {}\n    key: {}\n  omni:\n    endpoints:\n      - https://omni.example:443\n    auth:\n      siderov1:\n        identity: {identity}\n",
      STANDARD.encode(b"CA"),
      STANDARD.encode(b"CRT"),
      STANDARD.encode(b"KEY"),
    );
    let dir = tempfile::tempdir().unwrap();
    let adapted = adapt(Path::new(SOURCE), body.as_bytes(), &test_ca(), dir.path()).unwrap();
    let (fragment, decoy) = parts(&adapted);
    assert!(fragment.contains("https://10.5.0.6:50000"), "prod is granted: {fragment}");
    assert!(!fragment.contains("omni.example"), "omni is not an allow entry: {fragment}");
    assert!(!decoy.contains(identity), "auth identity survives in the decoy: {decoy}");
    assert!(decoy.contains("omni.example"), "omni context stays in the decoy: {decoy}");
  }

  #[test]
  fn cleartext_endpoint_becomes_a_grant() {
    let dir = tempfile::tempdir().unwrap();
    let adapted = adapt(
      Path::new(SOURCE),
      doc("      - http://10.5.0.6:50000\n").as_bytes(),
      &test_ca(),
      dir.path(),
    )
    .unwrap();
    let (fragment, _) = parts(&adapted);
    assert!(fragment.contains("allow = [\"http://10.5.0.6:50000\"]"), "{fragment}");
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
}
