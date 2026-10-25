//! Shared machinery for the structural `file_rewrite` adapters: one result
//! type, one state writer, and the format dispatch the adapters plug into.
//! Kubeconfig and talosconfig are the same idea — a tool's config file is a
//! rule stated in another shape — so they share everything except parsing.

use arkham_config::config::{HostSshCfg, HostTlsCfg, IfMissing, config_dir};
use arkham_config::grants::GuestTlsMode;
use arkham_pki::ca::{CertAuthority, load_or_generate};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
#[cfg(unix)]
use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use arkham_config::config::RewriteFormat;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;

use crate::error::Error;
use crate::workspace::slug;

/// Container path the grant layer mounts at in the arkham service. Fragments
/// name blobs under it; host and container serve resolve the same entries
/// because the state dir mounts there.
pub(crate) const GRANTS_STATE_DIR: &str = "/arkham/grants";

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

/// Name client cert, key, and CA blobs on a [`HostTlsCfg`]. Absent materials stay unset.
#[must_use]
pub(crate) fn materialize_client_tls(
  label: &str,
  client_cert: Option<Vec<u8>>,
  client_key: Option<Vec<u8>>,
  root_cert: Option<Vec<u8>>,
  guest_tls_mode: GuestTlsMode,
) -> (HostTlsCfg, Vec<(String, Vec<u8>)>) {
  let mut materialized = Vec::new();
  let mut tls = HostTlsCfg {
    client_cert: None,
    client_key: None,
    root_cert: None,
    guest_tls_mode,
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
pub(crate) struct RewriteAdapted {
  /// Grant fragment TOML, holding the real credential.
  pub(crate) fragment: String,
  /// Decoy config for the agent: same endpoints, arkham CA, guest pair.
  pub(crate) decoy: String,
  /// Blobs to write beside the fragment: `(file name, bytes)`.
  pub(crate) materialized: Vec<(String, Vec<u8>)>,
  /// Extra agent-side decoy files beyond the document (ssh: the decoy
  /// private key and the decoy `known_hosts`), mounted read-only at their
  /// container paths. Written under the rewrite files dir by `name`.
  pub(crate) decoy_files: Vec<DecoyFile>,
}

/// One agent-side decoy file an adapter mounts itself.
#[derive(Debug)]
pub(crate) struct DecoyFile {
  /// File name under the rewrite files dir.
  pub(crate) name: String,
  /// File contents as written.
  pub(crate) bytes: Vec<u8>,
  /// Absolute container path the file mounts at, read-only.
  pub(crate) container: String,
}

/// A derived rule, minus the label: what both adapters hand the TOML
/// serializer. Serialization escapes every string the way TOML requires, so
/// no hand-rolled escaping exists anywhere on this path.
#[derive(Debug, Serialize)]
pub(crate) struct GrantFragment {
  /// Env name the rule resolves from.
  pub(crate) env: String,
  /// Registry-supplied shapes do not apply to derived rules.
  pub(crate) registry: bool,
  /// Allow entries the derived rule grants.
  pub(crate) allow: Vec<String>,
  /// Real credential, held inline. Absent for kinds whose secret is key
  /// material in `ssh` rather than a wire value. Connection-string rules
  /// put the fake string here.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) value: Option<String>,
  /// Connection-string rules: the real string, stated beside the fake
  /// `value`. Absent for token and ssh rules. [`Debug`] redacts it.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) real: Option<Redacted>,
  /// `true` on a fragment this adapter wrote. Fnox keeps a stated `real`
  /// only when this is set and fnox has no value for the rule.
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub(crate) generated: bool,
  /// What the rule does without a fnox value. Absent keeps the default.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) if_missing: Option<IfMissing>,
  /// Per-entry TLS identity.
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub(crate) tls: BTreeMap<String, HostTlsCfg>,
  /// Per-entry SSH key material.
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub(crate) ssh: BTreeMap<String, HostSshCfg>,
}

/// A real credential that serializes into the grant fragment and prints as
/// `redacted`.
#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct Redacted(pub(crate) String);

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
pub(crate) fn render_fragment(source: &Path, label: &str, fragment: &GrantFragment) -> Result<String, Error> {
  #[derive(Serialize)]
  struct Rules<'a> {
    rules: BTreeMap<&'a str, &'a GrantFragment>,
  }
  let rules = Rules {
    rules: BTreeMap::from([(label, fragment)]),
  };
  Ok(format!(
    "# generated by `arkham init` from {} — do not edit or commit: it holds the REAL credential.\n# Regenerated when the workspace config changes.\n{}",
    source.display(),
    toml::to_string_pretty(&rules).map_err(|source| Error::SerializeFragment { source })?,
  ))
}

/// Serialize the agent's decoy document with its generation header.
///
/// # Errors
///
/// Returns an error when the document fails to serialize.
pub(crate) fn render_decoy<D: Serialize>(doc: &D) -> Result<String, Error> {
  Ok(format!(
    "# generated by `arkham init` — decoys only, safe to inspect.\n{}",
    serde_yaml::to_string(doc).map_err(|source| Error::SerializeDecoy { source })?,
  ))
}

/// The format an unstated rewrite probes as, if any. Kubeconfig first: its
/// markers are the more specific pair.
#[must_use]
pub(crate) fn sniff(content: &[u8]) -> Option<RewriteFormat> {
  let text = String::from_utf8_lossy(content);
  if text.contains("current-context:") && text.contains("clusters:") {
    return Some(RewriteFormat::Kubeconfig);
  }
  if text.contains("contexts:") && text.contains("endpoints:") {
    return Some(RewriteFormat::Talos);
  }
  None
}

/// Decode an optional base64 blob, erroring when the field is malformed.
///
/// # Errors
///
/// Returns [`Error::RewriteInvalid`] naming the file, format, and field.
pub(crate) fn decode(file: &Path, format: RewriteFormat, data: Option<&str>, field: &str) -> Result<Option<Vec<u8>>, Error> {
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
pub(crate) fn rewrite_label(source: &Path, name: &str) -> Result<String, Error> {
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

/// Blob-name prefixes the adapters write. [`write_state`] deletes a file
/// with one of these prefixes when the current adapt did not write it.
pub(crate) const BLOB_PREFIX_KUBE: &str = "kube-";
/// Talos client material.
pub(crate) const BLOB_PREFIX_TALOS: &str = "talos-";
/// SSH identity material.
pub(crate) const BLOB_PREFIX_SSH: &str = "ssh-";
/// Git identity material.
pub(crate) const BLOB_PREFIX_GIT: &str = "git-";
/// NATS client certificate, key, and CA.
pub(crate) const BLOB_PREFIX_NATS: &str = "nats-";

/// Every adapter blob prefix, in the order the writers name files.
pub(crate) const ADAPTER_BLOB_PREFIXES: &[&str] = &[
  BLOB_PREFIX_KUBE,
  BLOB_PREFIX_TALOS,
  BLOB_PREFIX_SSH,
  BLOB_PREFIX_GIT,
  BLOB_PREFIX_NATS,
];

/// Write the grant layer: the grant fragments concatenated into the marker
/// global config, plus the blobs under `rules.d`, pruning stale adapter blobs
/// so a removed rewrite stops granting. The arkham service mounts the marker
/// at `/root/.config/arkham/config.toml`, adding this layer without touching
/// user config.
///
/// # Errors
///
/// Returns an error when the directory, the marker, or a blob cannot be
/// written, or when a stale file cannot be pruned.
pub(crate) fn write_state(state_dir: &Path, adapted: &[RewriteAdapted]) -> Result<(), Error> {
  let marker = state_dir.join("arkham.toml");
  let rules_dir = state_dir.join("rules.d");
  if adapted.is_empty() && !marker.is_file() {
    return Ok(());
  }
  fs::create_dir_all(&rules_dir).map_err(|source| Error::CreateDir {
    path: rules_dir.clone(),
    source,
  })?;
  let mut toml = String::from(
    "# generated by `arkham init`: tool-config grant layer. The arkham service mounts this file at `/root/.config/arkham/config.toml`.\n",
  );
  let mut current = BTreeSet::new();
  for grant in adapted {
    toml.push_str(&grant.fragment);
    for (name, bytes) in &grant.materialized {
      write_secret(&rules_dir.join(name), bytes)?;
      current.insert(name.clone());
    }
  }
  write_secret(&marker, toml.as_bytes())?;
  let stale = |name: &str| ADAPTER_BLOB_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) && !current.contains(name);
  for entry in fs::read_dir(&rules_dir).map_err(|source| Error::ReadFile {
    path: rules_dir.clone(),
    source,
  })? {
    let path = entry
      .map_err(|source| Error::ReadFile {
        path: rules_dir.clone(),
        source,
      })?
      .path();
    if path.is_file() && path.file_name().is_some_and(|name| stale(&name.to_string_lossy())) {
      fs::remove_file(&path).map_err(|source| Error::RemoveFile {
        path: path.clone(),
        source,
      })?;
    }
  }
  Ok(())
}

/// Write a secret file the agent must never see: owner-only on unix.
pub(crate) fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), Error> {
  fs::write(path, bytes).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })?;
  #[cfg(unix)]
  fs::set_permissions(path, Permissions::from_mode(0o600)).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

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
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(!rendered.contains(marker), "{rendered}");
  }

  #[test]
  fn sniff_picks_kubeconfig_over_talos_on_shared_markers() {
    assert_eq!(
      sniff(b"context: c\ncontexts:\n  c:\n    endpoints:\n      - 10.0.0.1\n"),
      Some(RewriteFormat::Talos)
    );
    assert_eq!(
      sniff(b"current-context: c\nclusters:\n- name: c\n"),
      Some(RewriteFormat::Kubeconfig)
    );
    assert_eq!(sniff(b"just a file\n"), None);
  }

  #[test]
  fn write_state_prunes_stale_kube_and_talos_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("grants");
    let adapted = RewriteAdapted {
      fragment: "[rules.x]\n".to_string(),
      decoy: String::new(),
      materialized: vec![("kube-a.crt".to_string(), b"a".to_vec())],
      decoy_files: Vec::new(),
    };
    write_state(&state, &[adapted]).unwrap();
    let rules = state.join("rules.d");
    let stale_talos = rules.join("talos-old.crt");
    let stale_other = rules.join("other.crt");
    fs::write(&stale_talos, "stale").unwrap();
    fs::write(&stale_other, "stale").unwrap();
    write_state(&state, &[]).unwrap();
    assert!(!stale_talos.exists(), "removed talos rewrites stop granting");
    assert!(stale_other.exists(), "non-adapter blobs are untouched");
  }

  #[test]
  fn write_state_prunes_a_removed_nats_context() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("grants");
    let adapted = RewriteAdapted {
      fragment: "[rules.x]\n".to_string(),
      decoy: String::new(),
      materialized: vec![("kube-a.crt".to_string(), b"a".to_vec())],
      decoy_files: Vec::new(),
    };
    write_state(&state, &[adapted]).unwrap();
    let rules = state.join("rules.d");
    let stale_key = rules.join("nats-old.key");
    let stale_crt = rules.join("nats-old.crt");
    let stale_ca = rules.join("nats-old.ca");
    let stale_other = rules.join("other.crt");
    fs::write(&stale_key, "stale").unwrap();
    fs::write(&stale_crt, "stale").unwrap();
    fs::write(&stale_ca, "stale").unwrap();
    fs::write(&stale_other, "stale").unwrap();
    write_state(&state, &[]).unwrap();
    assert!(!stale_key.exists(), "a removed nats context drops its client key");
    assert!(!stale_crt.exists(), "a removed nats context drops its client cert");
    assert!(!stale_ca.exists(), "a removed nats context drops its ca");
    assert!(stale_other.exists(), "non-adapter blobs are untouched");
  }
}
