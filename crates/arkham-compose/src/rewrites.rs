//! Declared `file_rewrite` pass: each source expands, swaps its plain env
//! values or runs the format adapter, and lands in the state directory.
//! A kubeconfig or talosconfig mounts writable. Every other rewrite stays read-only.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::config::{FileRewrite, RewriteFormat};
use arkham_pki::ca::CertAuthority;
use xpanda::Xpanda;

use crate::adapt::{RewriteAdapted, load_guest_ca, sniff};
use crate::decoys::Decoy;
use crate::error::Error;
use crate::expand::{apply_rewrites, expand_path, expand_value, rewrite_file_name};
use crate::kube;
use crate::paths::{Mount, expand};
use crate::talos;

/// Real/decoy byte pairs for one rewrite's env names, in declared order.
pub(crate) type RewritePairs = Vec<(Vec<u8>, Vec<u8>)>;

/// Pairs each rewrite's env names with their real and decoy bytes.
///
/// # Errors
///
/// Returns an error naming the env when a name has no known real value or
/// no decoy.
fn rewrite_pairs(rewrite: &FileRewrite, env: &HashMap<String, String>, by_env: &BTreeMap<&str, &str>) -> Result<RewritePairs, Error> {
  let mut pairs = Vec::new();
  for name in &rewrite.envs {
    let real = env
      .get(name)
      .filter(|value| !value.is_empty())
      .ok_or_else(|| Error::RewriteNoValue {
        file: rewrite.source.clone(),
        name: name.clone(),
      })?;
    let decoy = by_env.get(name.as_str()).ok_or_else(|| Error::RewriteNoDecoy {
      file: rewrite.source.clone(),
      name: name.clone(),
    })?;
    pairs.push((real.as_bytes().to_vec(), decoy.as_bytes().to_vec()));
  }
  Ok(pairs)
}

/// Inputs for [`write_rewrites`]: the generation context the rewrite loop
/// reads, as one value instead of eight positional arguments.
pub(crate) struct RewriteInputs<'a> {
  /// State directory the rewritten files land in.
  pub(crate) files_dir: &'a Path,
  /// Workspace root relative sources resolve against.
  pub(crate) root: &'a Path,
  /// Rewrite entries from `[workspace] file_rewrite`.
  pub(crate) rewrites: &'a [FileRewrite],
  /// Selected decoys supplying the replacement values.
  pub(crate) decoys: &'a [Decoy],
  /// Resolved real values keyed by env name.
  pub(crate) env: &'a HashMap<String, String>,
  /// Xpanda expander for sources and dests.
  pub(crate) expander: &'a Xpanda,
  /// Container home expanding `{home}` in dests.
  pub(crate) home: &'a str,
  /// Host home relative sources and `~` expand against.
  pub(crate) host_home: Option<&'a Path>,
  /// Guest pairs mint here; the kube adapter reads them back for the decoy.
  pub(crate) guests_dir: &'a Path,
}

/// What `write_rewrites` produces: the agent mounts plus the tool-config
/// grants whose fragments land in the state grant layer.
#[derive(Debug)]
pub(crate) struct RewriteOutputs {
  /// Read-only mounts of the rewritten files at their dests.
  pub(crate) mounts: Vec<Mount>,
  /// Grants adapted from kubeconfig and talosconfig sources.
  pub(crate) grants: Vec<RewriteAdapted>,
}

/// Rewrite each `file_rewrite` source with decoys and write the outputs under
/// `files_dir`, returning a read-only mount per entry at its `{home}`-expanded
/// dest. Kubeconfig sources take the adapter path instead: the file is the
/// secret source, so they state no `envs`, and the grant layer writes from
/// the returned grants.
///
/// # Errors
///
/// Returns an error naming the variable when a path fails to expand, naming
/// the env name when a rewrite names one with no known real value or no
/// decoy, when a kubeconfig source states `envs` or does not map, or when a
/// source file cannot be read or an output written.
pub(crate) fn write_rewrites(inputs: &RewriteInputs<'_>) -> Result<RewriteOutputs, Error> {
  let RewriteInputs {
    files_dir,
    root,
    rewrites,
    decoys,
    env,
    expander,
    home,
    host_home,
    guests_dir,
  } = *inputs;
  if rewrites.is_empty() {
    return Ok(RewriteOutputs {
      mounts: Vec::new(),
      grants: Vec::new(),
    });
  }
  let by_env: BTreeMap<&str, &str> = decoys.iter().map(|decoy| (decoy.env.as_str(), decoy.value.as_str())).collect();
  let mut pass = ExplicitRewrites {
    files_dir,
    guests_dir,
    expander,
    home,
    ca: None,
    collector: RewriteCollector::new(files_dir)?,
  };
  for (index, rewrite) in rewrites.iter().enumerate() {
    pass.write(index, rewrite, root, host_home, env, &by_env)?;
  }
  Ok(pass.collector.outputs())
}

/// Grants and decoy mounts collected from adapted documents: emitting one
/// document writes its decoy side files into the state directory and mounts
/// each read-only at its stated container path. Shared by the declared pass
/// and the ambient pass, which is why the collected vecs stay crate-visible.
pub(crate) struct RewriteCollector {
  /// State directory the decoy files land in.
  files_dir: PathBuf,
  /// Read-only mounts collected with the grants.
  pub(crate) mounts: Vec<Mount>,
  /// Grants adapted from the documents.
  pub(crate) grants: Vec<RewriteAdapted>,
}

impl RewriteCollector {
  /// Create the state directory the decoy files land in.
  ///
  /// # Errors
  ///
  /// Returns an error when the directory cannot be created.
  pub(crate) fn new(files_dir: &Path) -> Result<Self, Error> {
    fs::create_dir_all(files_dir).map_err(|source| Error::CreateDir {
      path: files_dir.to_path_buf(),
      source,
    })?;
    Ok(Self {
      files_dir: files_dir.to_path_buf(),
      mounts: Vec::new(),
      grants: Vec::new(),
    })
  }

  /// Write one adapted document's decoy side files and mount them.
  ///
  /// # Errors
  ///
  /// Returns an error when a side file cannot be written.
  fn decoy_files(&mut self, first: &RewriteAdapted) -> Result<(), Error> {
    for file in &first.decoy_files {
      let file_path = self.files_dir.join(&file.name);
      fs::write(&file_path, &file.bytes).map_err(|source| Error::WriteFile {
        path: file_path.clone(),
        source,
      })?;
      self.mounts.push(Mount {
        host: file_path,
        container: PathBuf::from(&file.container),
        ro: true,
      });
    }
    Ok(())
  }

  /// Emit one adapted source: its decoy twin at `twin_dest`, its side
  /// files, and the grant set. An empty adaptation derives nothing.
  ///
  /// # Errors
  ///
  /// Returns an error when an output cannot be written.
  pub(crate) fn twin(&mut self, adapted: Vec<RewriteAdapted>, twin_name: &str, twin_dest: &str) -> Result<(), Error> {
    self.twin_mode(adapted, twin_name, twin_dest, true)
  }

  /// [`Self::twin`] with the decoy mount's read-only bit chosen by the caller.
  /// Kubeconfig and talos pass `ro = false` so the tool can rewrite the active
  /// context name. The host file is not this mount.
  ///
  /// # Errors
  ///
  /// Returns an error when an output cannot be written.
  pub(crate) fn twin_mode(&mut self, adapted: Vec<RewriteAdapted>, twin_name: &str, twin_dest: &str, ro: bool) -> Result<(), Error> {
    let Some(first) = adapted.first() else {
      return Ok(());
    };
    let twin_path = self.files_dir.join(twin_name);
    fs::write(&twin_path, first.decoy.as_bytes()).map_err(|source| Error::WriteFile {
      path: twin_path.clone(),
      source,
    })?;
    self.mounts.push(Mount {
      host: twin_path,
      container: PathBuf::from(twin_dest),
      ro,
    });
    self.decoy_files(first)?;
    self.grants.extend(adapted);
    Ok(())
  }

  /// The collected mounts and grants.
  pub(crate) fn outputs(self) -> RewriteOutputs {
    RewriteOutputs {
      mounts: self.mounts,
      grants: self.grants,
    }
  }
}

/// One workspace's explicit `[[workspace.file_rewrite]]` pass: each source
/// expands, swaps its plain env values or runs the format adapter, and
/// lands in the state directory with a read-only mount at its dest.
struct ExplicitRewrites<'a> {
  /// State directory the rewritten files land in.
  files_dir: &'a Path,
  /// Guest-identity directory the kube and talos adapters mint into.
  guests_dir: &'a Path,
  /// Xpanda expander for dest values.
  expander: &'a Xpanda,
  /// Container home for `{home}` substitution.
  home: &'a str,
  /// The guest CA this pass loaded, on first adapter use.
  ca: Option<CertAuthority>,
  /// Grants and decoy mounts collected along the way.
  collector: RewriteCollector,
}

impl ExplicitRewrites<'_> {
  /// The guest CA for the format adapters, loaded from the config directory
  /// on first use.
  ///
  /// # Errors
  ///
  /// Returns an error when the arkham config directory or the CA cannot be
  /// loaded.
  fn ca(&mut self) -> Result<&CertAuthority, Error> {
    if self.ca.is_none() {
      self.ca = Some(load_guest_ca(
        "an adapted rewrite needs the arkham config directory to load the CA from",
      )?);
    }
    self.ca.as_ref().ok_or_else(|| Error::ConfigDir {
      detail: "the adapted-rewrite CA slot is empty after loading it".to_string(),
    })
  }

  /// One rewrite's output bytes: the format adapter's decoy document with
  /// its side files emitted, or the plain env-value swap.
  ///
  /// # Errors
  ///
  /// Returns an error when the adapter rejects the document, a side file
  /// cannot be written, or a stated format does not match the document.
  fn output(&mut self, rewrite: &FileRewrite, host: &Path, content: &[u8], pairs: &RewritePairs) -> Result<Vec<u8>, Error> {
    let Some(format) = rewrite.format.or_else(|| sniff(content)) else {
      return Ok(apply_rewrites(content, pairs));
    };
    if !rewrite.envs.is_empty() {
      return Err(Error::RewriteWithEnvs {
        file: rewrite.source.clone(),
        format,
      });
    }
    let adapted: Vec<RewriteAdapted> = {
      let guests_dir = self.guests_dir;
      let ca = self.ca()?;
      match format {
        RewriteFormat::Kubeconfig => kube::adapt(host, content, ca, guests_dir)?.into_iter().collect(),
        RewriteFormat::Talos => {
          let found = talos::adapt(host, content, ca, guests_dir)?;
          tracing::debug!(skipped = found.skipped.len(), "talos contexts left out of the grant set");
          found.grants
        }
      }
    };
    match adapted.first() {
      Some(first) => {
        let bytes = first.decoy.clone().into_bytes();
        self.collector.decoy_files(first)?;
        self.collector.grants.extend(adapted);
        Ok(bytes)
      }
      None if rewrite.format.is_some() => Err(Error::RewriteInvalid {
        file: host.to_path_buf(),
        format,
        detail: "the document does not carry the format's markers".to_string(),
      }),
      None => Ok(apply_rewrites(content, pairs)),
    }
  }

  /// Write one declared rewrite's output and mount it at its dest.
  ///
  /// # Errors
  ///
  /// Returns an error when a path fails to expand, the source cannot be
  /// read, or an output cannot be written.
  fn write(
    &mut self,
    index: usize,
    rewrite: &FileRewrite,
    root: &Path,
    host_home: Option<&Path>,
    env: &HashMap<String, String>,
    by_env: &BTreeMap<&str, &str>,
  ) -> Result<(), Error> {
    let pairs = rewrite_pairs(rewrite, env, by_env)?;
    let expanded_source = PathBuf::from(expand_path(self.expander, &rewrite.source.to_string_lossy())?);
    let host = expand(&expanded_source, root, host_home);
    let content = fs::read(&host).map_err(|source| Error::ReadFile {
      path: host.clone(),
      source,
    })?;
    let writable = match rewrite.format {
      Some(RewriteFormat::Talos | RewriteFormat::Kubeconfig) => true,
      None => matches!(sniff(&content), Some(RewriteFormat::Talos | RewriteFormat::Kubeconfig)),
    };
    let out_bytes = self.output(rewrite, &host, &content, &pairs)?;
    let out_path = self.files_dir.join(rewrite_file_name(index, &host));
    fs::write(&out_path, out_bytes).map_err(|source| Error::WriteFile {
      path: out_path.clone(),
      source,
    })?;
    let container = expand_value(self.expander, &rewrite.dest)?.replace("{home}", self.home);
    if !container.starts_with('/') {
      return Err(Error::RewriteDestNotAbsolute {
        dest: rewrite.dest.clone(),
      });
    }
    self.collector.mounts.push(Mount {
      host: out_path,
      container: PathBuf::from(container),
      ro: !writable,
    });
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::expand::*;
  use std::slice::from_ref;
  use tempfile::tempdir;

  /// Sources rewrite reals to decoys on disk and mount read-only at the
  /// `{home}`-expanded dest; unknown names fail naming the name.
  #[test]
  fn file_rewrites_swap_reals_for_decoys_on_disk() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("npmrc");
    fs::write(&source, "//registry.npmjs.org/:_authToken=real-secret-1\n").unwrap();
    let rewrite = FileRewrite {
      source: source.clone(),
      dest: "{home}/.npmrc".to_string(),
      envs: vec!["NPM_TOKEN".to_string()],
      format: None,
    };
    let decoys = vec![Decoy {
      env: "NPM_TOKEN".to_string(),
      value: "decoy-9".to_string(),
    }];
    let env = HashMap::from([("NPM_TOKEN".to_string(), "real-secret-1".to_string())]);
    let expander = build_expander(HashMap::new());
    let files = dir.path().join("files");
    let outputs = write_rewrites(&RewriteInputs {
      files_dir: &files,
      root: dir.path(),
      rewrites: from_ref(&rewrite),
      decoys: &decoys,
      env: &env,
      expander: &expander,
      home: "/home/eng",
      host_home: None,
      guests_dir: dir.path(),
    })
    .unwrap();
    assert_eq!(outputs.mounts.len(), 1);
    assert!(outputs.mounts[0].ro);
    assert_eq!(outputs.mounts[0].container, PathBuf::from("/home/eng/.npmrc"));
    let body = fs::read_to_string(&outputs.mounts[0].host).unwrap();
    assert!(body.contains("decoy-9"), "{body}");
    assert!(!body.contains("real-secret-1"), "{body}");
    let error = write_rewrites(&RewriteInputs {
      files_dir: &files,
      root: dir.path(),
      rewrites: &[FileRewrite {
        source: source.clone(),
        dest: "{home}/.npmrc".to_string(),
        envs: vec!["UNKNOWN_NAME".to_string()],
        format: None,
      }],
      decoys: &decoys,
      env: &env,
      expander: &expander,
      home: "/home/eng",
      host_home: None,
      guests_dir: dir.path(),
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("UNKNOWN_NAME"), "{error}");
  }

  #[test]
  fn kubeconfig_file_rewrite_mounts_writable() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("kube.yaml");
    fs::write(
      &source,
      "apiVersion: v1\nkind: Config\ncurrent-context: prod\ncontexts:\n- name: prod\n  context: {cluster: prod, user: alice}\nclusters:\n- name: prod\n  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}\nusers:\n- name: alice\n  user: {token: alice-token}\n",
    )
    .unwrap();
    let expander = build_expander(HashMap::new());
    let outputs = write_rewrites(&RewriteInputs {
      files_dir: &dir.path().join("files"),
      root: dir.path(),
      rewrites: &[FileRewrite {
        source,
        dest: "{home}/.kube/other".to_string(),
        envs: Vec::new(),
        format: Some(RewriteFormat::Kubeconfig),
      }],
      decoys: &[],
      env: &HashMap::new(),
      expander: &expander,
      home: "/home/eng",
      host_home: None,
      guests_dir: dir.path(),
    })
    .unwrap();
    assert_eq!(outputs.mounts.len(), 1);
    assert!(!outputs.mounts[0].ro, "kubectl config use-context writes the mounted kubeconfig");
    assert_eq!(outputs.mounts[0].container, PathBuf::from("/home/eng/.kube/other"));
  }
}
