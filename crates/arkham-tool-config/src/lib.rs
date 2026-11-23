//! Shared types and helpers for tool configuration adaptation.

pub mod context;

use arkham_config::config::{HostSshCfg, HostTlsCfg, IfMissing, RewriteFormat};
use arkham_config::grants::GuestTlsMode;
use arkham_paths::slug;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use context::{AmbiguousContexts, ContextCollision, NameFault, PathFault};

/// Tool configuration adaptation failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// Grant serialization failed.
  #[error("serializing a grant fragment: {source}")]
  SerializeFragment {
    /// Serialization failure.
    #[source]
    source: toml::ser::Error,
  },
  /// Decoy serialization failed.
  #[error("serializing a decoy document: {source}")]
  SerializeDecoy {
    /// Serialization failure.
    #[source]
    source: serde_yaml::Error,
  },
  /// An adapted document is invalid.
  #[error("file rewrite `{}`: invalid {format}: {detail}", file.display())]
  RewriteInvalid {
    /// Source document.
    file: PathBuf,
    /// Document format.
    format: RewriteFormat,
    /// Invalid field.
    detail: String,
  },
  /// A source cannot be adapted.
  #[error("derived source `{}`: {detail}", file.display())]
  SourceInvalid {
    /// Source document.
    file: PathBuf,
    /// Invalid source detail.
    detail: String,
  },
  /// A byte rewrite position is outside its input.
  #[error("file rewrite position is outside the input")]
  RewriteBounds,
  /// A source path cannot identify a context.
  #[error("source path `{}` {fault}", path.display())]
  ContextPathInvalid {
    /// Path the adapter passed.
    path: PathBuf,
    /// Why the path was rejected.
    #[source]
    fault: PathFault,
  },
  /// A context name cannot become a label.
  #[error("context `{name}` in `{}` on {tag} {fault}", path.display())]
  ContextNameInvalid {
    /// Path the adapter passed.
    path: PathBuf,
    /// Adapter tag of the context.
    tag: &'static str,
    /// Original name.
    name: String,
    /// Why the name was rejected.
    #[source]
    fault: NameFault,
  },
  /// Two different contexts share a label.
  #[error(transparent)]
  ContextCollision(Box<ContextCollision>),
  /// Two contexts present the same host, port, and decoy bytes.
  #[error(transparent)]
  AmbiguousContexts(Box<AmbiguousContexts>),
  /// A presented destination host is empty after trimming.
  #[error("wire host is empty")]
  WireHostEmpty,
}

/// Result of tool configuration adaptation.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
  /// Safe summary for the agent wrapper.
  #[must_use]
  pub fn registration_summary(&self) -> &'static str {
    match self {
      Self::SerializeFragment { .. } | Self::SerializeDecoy { .. } => "session files could not be prepared",
      Self::RewriteInvalid { .. }
      | Self::SourceInvalid { .. }
      | Self::RewriteBounds
      | Self::ContextPathInvalid { .. }
      | Self::ContextNameInvalid { .. }
      | Self::ContextCollision(_)
      | Self::AmbiguousContexts(_)
      | Self::WireHostEmpty => "configuration could not be read",
    }
  }
}

/// Container path the grant layer mounts at in the arkham service. Fragments
/// name blobs under it; host and container serve resolve the same entries
/// because the state dir mounts there.
pub const GRANTS_STATE_DIR: &str = "/arkham/grants";

/// Name client cert, key, and CA blobs on a [`HostTlsCfg`]. Absent materials stay unset.
#[must_use]
pub fn materialize_client_tls(
  label: &str,
  client_pair: Option<(Vec<u8>, Vec<u8>)>,
  root_cert: Option<Vec<u8>>,
) -> (HostTlsCfg, Vec<(String, Vec<u8>)>) {
  let (client_cert, client_key) = client_pair.unzip();
  let mut materialized = Vec::new();
  let mut tls = HostTlsCfg {
    client_cert: None,
    client_key: None,
    root_cert: None,
    guest_tls_mode: if client_cert.is_some() {
      GuestTlsMode::Mtls
    } else {
      GuestTlsMode::Tls
    },
    guest_cert: None,
    guest_key: None,
  };
  for (bytes, suffix, slot) in [
    (client_cert, "client.crt", &mut tls.client_cert),
    (client_key, "client.key", &mut tls.client_key),
    (root_cert, "ca.crt", &mut tls.root_cert),
  ] {
    let Some(bytes) = bytes else { continue };
    let name = format!("{label}.{suffix}");
    *slot = Some(blob_path(&name));
    materialized.push((name, bytes));
  }
  (tls, materialized)
}

fn blob_path(name: &str) -> PathBuf {
  PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/{name}"))
}

/// A tool config rewrite mapped onto its grant fragment and decoy twin.
#[derive(Debug)]
pub struct RewriteAdapted {
  /// Grant fragment TOML, holding the real credential.
  pub fragment: String,
  /// Decoy config for the agent: same endpoints, arkham CA, guest pair.
  pub decoy: String,
  /// Blobs to write beside the fragment: `(file name, bytes)`.
  pub materialized: Vec<(String, Vec<u8>)>,
  /// Extra agent-side decoy files beyond the document (ssh: the decoy
  /// private key and the decoy `known_hosts`), mounted read-only at their
  /// container paths. Written under the rewrite files dir by `name`.
  pub decoy_files: Vec<DecoyFile>,
}

/// One agent-side decoy file an adapter mounts itself.
#[derive(Debug)]
pub struct DecoyFile {
  /// File name under the rewrite files dir.
  pub name: String,
  /// File contents as written.
  pub bytes: Vec<u8>,
  /// Absolute container path the file mounts at, read-only.
  pub container: String,
}

/// A derived rule, minus the label: what both adapters hand the TOML
/// serializer. Serialization escapes every string the way TOML requires, so
/// no hand-rolled escaping exists anywhere on this path.
#[derive(Debug, Serialize)]
pub struct GrantFragment {
  /// Env name the rule resolves from.
  pub env: String,
  /// Registry-supplied shapes do not apply to derived rules.
  pub registry: bool,
  /// Allow entries the derived rule grants.
  pub allow: Vec<String>,
  /// Real credential, held inline. Absent for kinds whose secret is key
  /// material in `ssh` rather than a wire value. Connection-string rules
  /// put the fake string here.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub value: Option<String>,
  /// Connection-string rules: the real string, stated beside the fake
  /// `value`. Absent for token and ssh rules. [`Debug`] redacts it.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub real: Option<Redacted>,
  /// `true` on a fragment this adapter wrote. Fnox keeps a stated `real`
  /// only when this is set and fnox has no value for the rule.
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub generated: bool,
  /// What the rule does without a fnox value. Absent keeps the default.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub if_missing: Option<IfMissing>,
  /// Per-entry TLS identity.
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub tls: BTreeMap<String, HostTlsCfg>,
  /// Per-entry SSH key material.
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub ssh: BTreeMap<String, HostSshCfg>,
}

/// A real credential that serializes into the grant fragment and prints as
/// `redacted`.
#[derive(Serialize)]
#[serde(transparent)]
pub struct Redacted(pub String);

impl fmt::Debug for Redacted {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("redacted")
  }
}

/// Serialize one grant fragment under `[rules.{label}]`, with the generation
/// header.
///
/// # Errors
///
/// Returns an error when the fragment fails to serialize.
pub fn render_fragment(source: &Path, label: &str, fragment: &GrantFragment) -> Result<String> {
  #[derive(Serialize)]
  struct Rules<'a> {
    rules: BTreeMap<&'a str, &'a GrantFragment>,
  }
  let rules = Rules {
    rules: BTreeMap::from([(label, fragment)]),
  };
  Ok(format!(
    "# generated by arkham from {} — do not edit or commit: it holds the REAL credential.\n{}",
    source.display(),
    toml::to_string_pretty(&rules).map_err(|source| Error::SerializeFragment { source })?,
  ))
}

/// Serialize the agent's decoy document with its generation header.
///
/// # Errors
///
/// Returns an error when the document fails to serialize.
pub fn render_decoy<D: Serialize>(doc: &D) -> Result<String> {
  Ok(format!(
    "# generated by arkham — decoys only, safe to inspect.\n{}",
    serde_yaml::to_string(doc).map_err(|source| Error::SerializeDecoy { source })?,
  ))
}

/// Decode an optional base64 blob, erroring when the field is malformed.
///
/// # Errors
///
/// Returns [`Error::RewriteInvalid`] naming the file, format, and field.
pub fn decode(file: &Path, format: RewriteFormat, data: Option<&str>, field: &str) -> Result<Option<Vec<u8>>> {
  data
    .filter(|data| !data.is_empty())
    .map(|data| {
      STANDARD.decode(data.trim()).map_err(|source| Error::RewriteInvalid {
        file: file.to_path_buf(),
        format,
        detail: format!("field `{field}` is not valid base64: {source}"),
      })
    })
    .transpose()
}

/// Grant label from the source path and a distinguishing name:
/// `{path-slug}-{file-stem}-{name}`.
///
/// # Errors
///
/// Returns [`Error::SourceInvalid`] when the path or name sluggifies to
/// nothing.
pub fn rewrite_label(source: &Path, name: &str) -> Result<String> {
  let invalid = |detail: String| Error::SourceInvalid {
    file: source.to_path_buf(),
    detail,
  };
  let parent = source.parent().ok_or_else(|| invalid("has no parent directory".to_string()))?;
  let stem = source
    .file_stem()
    .map(|stem| stem.to_string_lossy())
    .ok_or_else(|| invalid("has no file name".to_string()))?;
  let path_slug = slug(parent);
  let clean = |text: &str| {
    let cleaned: String = text
      .to_lowercase()
      .chars()
      .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
      .collect();
    cleaned.trim_matches('-').to_string()
  };
  if path_slug.is_empty() || clean(&stem).is_empty() || clean(name).is_empty() {
    return Err(invalid("path or context sluggifies to nothing".to_string()));
  }
  Ok(format!("{}-{}-{}", path_slug, clean(&stem), clean(name)))
}

/// One selected env var with its decoy value.
#[derive(Debug)]
pub struct Decoy {
  /// Env var name as the rule declares it.
  pub env: String,
  /// Decoy value for the agent environment.
  pub value: String,
}

/// Byte-replace every real value with its decoy, longest reals first so a
/// real that contains a shorter one cannot partially shadow it.
///
/// # Errors
///
/// Returns [`Error::RewriteBounds`] if a replacement position falls outside the input.
pub fn apply_rewrites(content: &[u8], pairs: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<u8>> {
  let mut ordered: Vec<&(Vec<u8>, Vec<u8>)> = pairs.iter().collect();
  ordered.sort_by_key(|(real, _)| Reverse(real.len()));
  let mut out = content.to_vec();
  for (real, decoy) in ordered {
    if real.is_empty() {
      continue;
    }
    let mut replaced = Vec::with_capacity(out.len());
    let mut rest = out.as_slice();
    while let Some(at) = rest.windows(real.len()).position(|window| window == real.as_slice()) {
      let (prefix, tail) = rest.split_at_checked(at).ok_or(Error::RewriteBounds)?;
      replaced.extend_from_slice(prefix);
      replaced.extend_from_slice(decoy);
      rest = tail.get(real.len()..).ok_or(Error::RewriteBounds)?;
    }
    replaced.extend_from_slice(rest);
    out = replaced;
  }
  Ok(out)
}

/// Output file name for a rewrite inside the state `files/` directory:
/// index-prefixed basename so two sources with the same file name cannot
/// collide.
#[must_use]
pub fn rewrite_file_name(index: usize, source: &Path) -> PathBuf {
  let base = source.file_name().and_then(|name| name.to_str()).unwrap_or("rewrite");
  PathBuf::from(format!("{index:02}-{base}"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rewrites_longest_value_first_and_ignores_empty_values() {
    let pairs = [(b"abc".to_vec(), b"X".to_vec()), (b"abc12345".to_vec(), b"DECOY".to_vec())];
    assert_eq!(apply_rewrites(b"token=abc12345 user=abc", &pairs).unwrap(), b"token=DECOY user=X");
    assert_eq!(apply_rewrites(b"abc", &[(Vec::new(), b"X".to_vec())]).unwrap(), b"abc");
  }

  #[test]
  fn names_rewrite_outputs_stably() {
    assert_eq!(rewrite_file_name(3, Path::new("/home/u/.npmrc")), PathBuf::from("03-.npmrc"));
  }

  #[test]
  fn grant_fragment_debug_redacts_the_real_string() {
    let marker = "ZZZ-REAL-MARKER";
    let fragment = GrantFragment {
      env: "NATS_CONTEXT".to_string(),
      registry: false,
      allow: Vec::new(),
      value: Some("nats://fake@nats.internal:4222".to_string()),
      real: Some(Redacted(format!("nats://{marker}@nats.internal:4222"))),
      generated: true,
      if_missing: None,
      tls: BTreeMap::new(),
      ssh: BTreeMap::new(),
    };
    let rendered = format!("{fragment:?}");
    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains(marker));
  }
}
