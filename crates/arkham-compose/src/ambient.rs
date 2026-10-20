//! Ambient-source pass: the authentication sources every workspace carries —
//! gitconfig, jj, ssh, nats, kubectl, talosctl — mapped onto grants plus the
//! agent's decoy twin at each tool's default path.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::decoys::Decoy;
use crate::error::Error;
use crate::expand::expand_path;
use crate::git;
use crate::jj;
use crate::kube;
use crate::nats;
use crate::paths::{Mount, expand};
use crate::rewrites::{RewriteCollector, RewriteOutputs};
use crate::ssh;
use crate::talos;
use arkham_config::config::{FileRewrite, config_dir};
use arkham_config::registry::Registry;
use arkham_pki::ca::{CertAuthority, load_or_generate};
use dirs::config_dir as dirs_config_dir;
use xpanda::Xpanda;

/// Inputs for [`derive_sources`]: the generation context the ambient
/// sources read.
pub(crate) struct DeriveInputs<'a> {
  /// State directory the decoy twins land in.
  pub(crate) files_dir: &'a Path,
  /// Workspace root git resolution starts from.
  pub(crate) root: &'a Path,
  /// Host-known registry joining forge hosts to env names.
  pub(crate) registry: &'a Registry,
  /// Selected decoys supplying the replacement values.
  pub(crate) decoys: &'a [Decoy],
  /// Xpanda expander for comparing declared sources.
  pub(crate) expander: &'a Xpanda,
  /// Container home the twins mount under.
  pub(crate) home: &'a str,
  /// Host home the default source paths live under.
  pub(crate) host_home: Option<&'a Path>,
  /// Guest-identity directory the kube and talos adapters mint into.
  pub(crate) guests_dir: &'a Path,
  /// Declared rewrites: an explicitly-declared source stays with its
  /// declaration, not the ambient default.
  pub(crate) rewrites: &'a [FileRewrite],
}

/// Read the ambient authentication sources every workspace carries — no
/// declaration, like fnox's own chain — and map each onto grants plus the
/// agent's decoy twin at the tool's default path. The gitconfig resolves
/// from the workspace root the way `git` there resolves it; jj reads its
/// user chain; the ssh, nats, kubectl, and talosctl configs come from their
/// default paths. An absent source derives nothing; a present one that
/// does not map fails closed naming the file.
///
/// # Errors
///
/// Returns an error naming the source when it cannot be read or does not
/// map, when the guest CA cannot be loaded, or when an output cannot be
/// written.
///
/// ponytail: no opt-out exists yet; none has been asked for.
/// `KUBECONFIG` is a colon-separated list, merged first-wins. An empty
/// value reads `~/.kube/config`. `TALOSCONFIG` stays one path: a list warns
/// and falls back to the default.
pub(crate) fn derive_sources(inputs: &DeriveInputs<'_>) -> Result<RewriteOutputs, Error> {
  let DeriveInputs {
    files_dir,
    root,
    registry,
    decoys,
    expander,
    home,
    host_home,
    guests_dir,
    rewrites,
  } = *inputs;
  let Some(host_home) = host_home else {
    return Ok(RewriteOutputs {
      mounts: Vec::new(),
      grants: Vec::new(),
    });
  };
  let declared = rewrites
    .iter()
    .map(|rewrite| {
      let expanded = PathBuf::from(expand_path(expander, &rewrite.source.to_string_lossy())?);
      Ok(expand(&expanded, root, Some(host_home)))
    })
    .collect::<Result<Vec<_>, Error>>()?;
  let mut deriver = AmbientDeriver {
    root,
    registry,
    decoys,
    home,
    host_home,
    guests_dir,
    declared,
    ca: None,
    collector: RewriteCollector::new(files_dir)?,
  };
  deriver.git()?;
  deriver.jj()?;
  deriver.ssh()?;
  deriver.nats()?;
  deriver.kube_and_talos()?;
  Ok(deriver.collector.outputs())
}

/// One workspace's ambient-source pass: the authentication sources every
/// workspace carries — gitconfig, jj, ssh, nats, kubectl, talosctl — map onto
/// grants plus the agent's decoy twin at the tool's default path. A source
/// the workspace declared explicitly stays with its declaration; a present
/// source that does not map warns, and one whose guest CA is unavailable
/// skips.
struct AmbientDeriver<'a> {
  /// Workspace root git resolution starts from.
  root: &'a Path,
  /// Host-known registry joining forge hosts to env names.
  registry: &'a Registry,
  /// Selected decoys supplying the replacement values.
  decoys: &'a [Decoy],
  /// Container home the twins mount under.
  home: &'a str,
  /// Host home the default source paths live under.
  host_home: &'a Path,
  /// Guest-identity directory the kube and talos adapters mint into.
  guests_dir: &'a Path,
  /// Sources the workspace declared explicitly; the ambient pass leaves
  /// them to their declarations.
  declared: Vec<PathBuf>,
  /// The guest CA, loaded on first use.
  ca: Option<CertAuthority>,
  /// Grants and decoy mounts collected along the way.
  collector: RewriteCollector,
}

impl AmbientDeriver<'_> {
  /// The gitconfig chain `git` at the workspace root resolves.
  ///
  /// # Errors
  ///
  /// Returns an error when the twin output cannot be written.
  fn git(&mut self) -> Result<(), Error> {
    let mut git_sources = vec![self.host_home.join(".gitconfig")];
    if let Some(dir) = dirs_config_dir() {
      git_sources.push(dir.join("git").join("config"));
    }
    if let Some(path) = env::var_os("GIT_CONFIG_GLOBAL") {
      git_sources.push(PathBuf::from(path));
    }
    if git_sources.iter().any(|path| self.declared.contains(path)) {
      return Ok(());
    }
    let first = &git_sources[0];
    match git::adapt(first, self.root, self.registry, self.decoys, self.home, self.host_home) {
      Ok(adapted) => self.collector.twin(adapted, "gitconfig", &format!("{}/.gitconfig", self.home)),
      Err(err) => {
        tracing::warn!(source = %first.display(), %err, "gitconfig source skipped");
        Ok(())
      }
    }
  }

  /// The full host jj config dir, mounted writable.
  ///
  /// # Errors
  ///
  /// Returns an error when the twin output cannot be written.
  fn jj(&mut self) -> Result<(), Error> {
    if jj::chain_paths().iter().any(|path| self.declared.contains(path)) {
      return Ok(());
    }
    let host_jj = jj::config_path().parent().map(Path::to_path_buf).unwrap_or_default();
    if !host_jj.as_os_str().is_empty() {
      if self.declared.iter().any(|path| path == &host_jj || path.starts_with(&host_jj)) {
        return Ok(());
      }
      if host_jj.is_dir() {
        self.collector.mounts.push(Mount {
          host: host_jj,
          container: PathBuf::from(format!("{}/.config/jj", self.home)),
          ro: false,
        });
        return Ok(());
      }
    }
    if let Some(adapted) = jj::adapt(self.root) {
      let dest = format!("{}/.config/jj/config.toml", self.home);
      return self.collector.twin(vec![adapted], "jj-config", &dest);
    }
    Ok(())
  }

  /// The ssh config at its default path.
  ///
  /// # Errors
  ///
  /// Returns an error when the config cannot be read or the twin output
  /// cannot be written.
  fn ssh(&mut self) -> Result<(), Error> {
    let ssh_config = self.host_home.join(".ssh").join("config");
    if self.declared.contains(&ssh_config) || !ssh_config.is_file() {
      return Ok(());
    }
    let content = fs::read(&ssh_config).map_err(|source| Error::ReadFile {
      path: ssh_config.clone(),
      source,
    })?;
    let dest = format!("{}/.ssh/config", self.home);
    match ssh::adapt(&ssh_config, &content, self.home, self.host_home) {
      Ok(adapted) => self.collector.twin(adapted, "ssh-config", &dest),
      Err(err) => {
        tracing::warn!(source = %ssh_config.display(), %err, "ssh source skipped");
        Ok(())
      }
    }
  }

  /// The selected NATS CLI context under `~/.config/nats`.
  ///
  /// # Errors
  ///
  /// Returns an error when the twin output cannot be written. A context
  /// that does not map warns and derives nothing.
  fn nats(&mut self) -> Result<(), Error> {
    let root = self.host_home.join(".config").join("nats");
    let selected = root.join("context.txt");
    if self.declared.iter().any(|path| path == &root || path.starts_with(&root)) || !selected.is_file() {
      return Ok(());
    }
    match nats::adapt(&root, self.home, self.host_home) {
      Ok(Some(found)) => self.collector.twin(found.adapted, "nats-context", &found.context_dest),
      Ok(None) => Ok(()),
      Err(err) => {
        tracing::warn!(source = %root.display(), %err, "nats source skipped");
        Ok(())
      }
    }
  }

  /// The kubeconfig list and the talosconfig at their default paths.
  ///
  /// # Errors
  ///
  /// Returns an error when a twin output cannot be written.
  fn kube_and_talos(&mut self) -> Result<(), Error> {
    self.kube()?;
    self.talos()
  }

  /// Readable undeclared files from `KUBECONFIG`, merged first-wins.
  ///
  /// # Errors
  ///
  /// Returns an error when the twin output cannot be written.
  fn kube(&mut self) -> Result<(), Error> {
    let mut loaded = Vec::new();
    for path in kubeconfig_paths(self.host_home) {
      if self.declared.contains(&path) || !path.is_file() {
        continue;
      }
      if let Ok(content) = fs::read(&path) {
        loaded.push((path, content));
      } else {
        tracing::warn!(source = %path.display(), "kubeconfig source skipped: it cannot be read");
      }
    }
    let Some(source) = loaded.first().map(|(path, _)| path.clone()) else {
      return Ok(());
    };
    let guests_dir = self.guests_dir;
    let ca = match self.ca() {
      Ok(ca) => ca,
      Err(err) => {
        tracing::warn!(source = %source.display(), %err, "kubeconfig source skipped: the guest CA is unavailable");
        return Ok(());
      }
    };
    let refs: Vec<(&Path, &[u8])> = loaded.iter().map(|(path, bytes)| (path.as_path(), bytes.as_slice())).collect();
    let adapted = kube::adapt_sources(&refs, ca, guests_dir)
      .ok()
      .flatten()
      .into_iter()
      .collect::<Vec<_>>();
    if adapted.is_empty() {
      tracing::warn!(source = %source.display(), "kubeconfig source skipped: it does not map onto a grant");
      return Ok(());
    }
    self.collector.twin(adapted, "kube-config", &format!("{}/.kube/config", self.home))
  }

  /// The talosconfig at `TALOSCONFIG` or `~/.talos/config`.
  ///
  /// # Errors
  ///
  /// Returns an error when the twin output cannot be written.
  fn talos(&mut self) -> Result<(), Error> {
    let path = env_source("TALOSCONFIG", ".talos/config", self.host_home);
    if self.declared.contains(&path) || !path.is_file() {
      return Ok(());
    }
    let Ok(content) = fs::read(&path) else {
      tracing::warn!(source = %path.display(), "talosconfig source skipped: it cannot be read");
      return Ok(());
    };
    let guests_dir = self.guests_dir;
    let ca = match self.ca() {
      Ok(ca) => ca,
      Err(err) => {
        tracing::warn!(source = %path.display(), %err, "talosconfig source skipped: the guest CA is unavailable");
        return Ok(());
      }
    };
    let adapted = talos::adapt(&path, &content, ca, guests_dir).ok().into_iter().collect::<Vec<_>>();
    if adapted.is_empty() {
      tracing::warn!(source = %path.display(), "talosconfig source skipped: it does not map onto a grant");
      return Ok(());
    }
    self
      .collector
      .twin(adapted, "talos-config", &format!("{}/.talos/config", self.home))
  }

  /// The guest CA for the kubeconfig and talosconfig adapters, loaded on
  /// first use.
  ///
  /// # Errors
  ///
  /// Returns an error when the arkham config directory or the CA cannot be
  /// loaded.
  fn ca(&mut self) -> Result<&CertAuthority, Error> {
    if self.ca.is_none() {
      let ca_path = config_dir()
        .ok_or_else(|| Error::ConfigDir {
          detail: "ambient kubeconfig derivation needs the arkham config directory to load the CA from".to_string(),
        })?
        .join("ca.pem");
      self.ca = Some(load_or_generate(&ca_path).map_err(|source| Error::GuestCa { path: ca_path, source })?);
    }
    match self.ca.as_ref() {
      Some(ca) => Ok(ca),
      None => Err(Error::ConfigDir {
        detail: "the ambient guest CA slot is empty after loading it".to_string(),
      }),
    }
  }
}

/// The source path one single-path override names, or the default under
/// the host home. A value containing `:` is not a list here.
fn env_source(env_name: &str, default: &str, host_home: &Path) -> PathBuf {
  match env::var(env_name) {
    Ok(value) if !value.contains(':') => PathBuf::from(value),
    Ok(value) => {
      tracing::warn!(env_name, value, "names multiple paths; using the default location instead");
      host_home.join(default)
    }
    Err(_) => host_home.join(default),
  }
}

/// Files named by `KUBECONFIG`, in order. An empty value is `~/.kube/config`.
fn kubeconfig_paths(host_home: &Path) -> Vec<PathBuf> {
  let Ok(value) = env::var("KUBECONFIG") else {
    return vec![host_home.join(".kube/config")];
  };
  let paths: Vec<PathBuf> = value.split(':').filter(|part| !part.is_empty()).map(PathBuf::from).collect();
  if paths.is_empty() {
    vec![host_home.join(".kube/config")]
  } else {
    paths
  }
}

#[cfg(test)]
mod moved_suite {

  use std::ffi::OsString;
  use tempfile::tempdir;

  use crate::ambient::*;

  use crate::expand::*;

  use crate::test_support::*;

  /// The automatic pass maps the default-path sources onto decoy twins at
  /// their default container paths and mints grants, with no declaration.
  #[test]
  fn derive_sources_maps_default_paths_to_twins_and_grants() {
    use arkham_config::registry::Registry;
    use arkham_pki::ssh::SshKey;
    use std::collections::HashMap;
    use std::env;
    use std::ffi::OsString;
    use std::path::Path;

    let host = tempdir().unwrap();
    let gitconfig = host.path().join(".gitconfig");
    fs::write(&gitconfig, "[credential \"https://github.com\"]\n\tusername = casualjim\n").unwrap();
    let key = SshKey::generate().unwrap().to_openssh().unwrap();
    fs::create_dir_all(host.path().join(".ssh")).unwrap();
    fs::write(host.path().join(".ssh").join("forge"), key).unwrap();
    fs::write(
      host.path().join(".ssh").join("config"),
      "Host git.internal\n\tIdentityFile ~/.ssh/forge\n",
    )
    .unwrap();
    let work = tempdir().unwrap();
    let git = work.path().join(".git");
    fs::create_dir_all(git.join("objects")).unwrap();
    fs::create_dir_all(git.join("refs").join("heads")).unwrap();
    fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
      git.join("config"),
      "[remote \"origin\"]\n\turl = https://github.com/casualjim/arkham.git\n[remote \"internal\"]\n\turl = git@git.internal:org/repo.git\n",
    )
    .unwrap();
    let empty_xdg = tempdir().unwrap();
    let saved: Vec<(&str, Option<OsString>)> = [
      "KUBECONFIG",
      "TALOSCONFIG",
      "GIT_CONFIG_GLOBAL",
      "GIT_CONFIG_NOSYSTEM",
      "HOME",
      "XDG_CONFIG_HOME",
      "JJ_CONFIG",
    ]
    .map(|name| (name, env::var_os(name)))
    .to_vec();
    unset_env("KUBECONFIG");
    unset_env("TALOSCONFIG");
    unset_env("JJ_CONFIG");
    set_env("GIT_CONFIG_GLOBAL", &gitconfig);
    set_env("GIT_CONFIG_NOSYSTEM", "1");
    set_env("HOME", host.path());
    set_env("XDG_CONFIG_HOME", empty_xdg.path());
    let files = work.path().join("files");
    let decoys = vec![Decoy {
      env: "GITHUB_TOKEN".to_string(),
      value: "ghp_decoy_decoy_decoy_decoy_decoy".to_string(),
    }];
    let outputs = derive_sources(&DeriveInputs {
      files_dir: &files,
      root: work.path(),
      registry: &Registry::load(None).unwrap(),
      decoys: &decoys,
      expander: &build_expander(HashMap::new()),
      home: "/home/eng",
      host_home: Some(host.path()),
      guests_dir: &work.path().join("guests"),
      rewrites: &[],
    })
    .unwrap();
    for (name, value) in saved {
      match value {
        Some(value) => set_env(name, value),
        None => unset_env(name),
      }
    }
    let containers: Vec<String> = outputs.mounts.iter().map(|mount| mount.container.display().to_string()).collect();
    for expected in [
      "/home/eng/.gitconfig",
      "/home/eng/.ssh/config",
      "/home/eng/.ssh/forge",
      "/home/eng/.ssh/known_hosts",
    ] {
      assert!(containers.contains(&expected.to_string()), "{expected} missing from {containers:?}");
    }
    assert!(
      !containers.iter().any(|path| path.ends_with(".config/jj/config.toml")),
      "no jj chain, no jj twin"
    );
    let gitconfig_mount = outputs
      .mounts
      .iter()
      .find(|mount| mount.container == Path::new("/home/eng/.gitconfig"))
      .unwrap();
    let twin = fs::read_to_string(&gitconfig_mount.host).unwrap();
    assert!(
      twin.contains("helper = !sh /home/eng/.config/arkham/git-credential-arkham"),
      "{twin}"
    );
    assert!(twin.contains("casualjim"), "{twin}");
    assert!(
      outputs.grants.iter().any(|grant| grant.fragment.contains("ssh://git.internal")),
      "the ssh config source minted the identity grant: {:?}",
      outputs.grants.iter().map(|grant| grant.fragment.clone()).collect::<Vec<_>>()
    );
  }

  /// An nkey context mounts a decoy seed. The real seed stays in the grant.
  #[test]
  fn derive_sources_mounts_a_decoy_nkey() {
    use arkham_config::grants::NatsSeed;
    use secrecy::SecretString;

    let host = tempdir().unwrap();
    let nats = host.path().join(".config").join("nats");
    fs::create_dir_all(nats.join("context")).unwrap();
    let seed = nkeys::KeyPair::new_user().seed().unwrap();
    let nkey = nats.join("user.nk");
    fs::write(&nkey, format!("{seed}\n")).unwrap();
    fs::write(nats.join("context.txt"), "demo\n").unwrap();
    fs::write(
      nats.join("context").join("demo.json"),
      format!(r#"{{"url":"nats://nats.internal:4222","nkey":"{}"}}"#, nkey.display()),
    )
    .unwrap();
    let derived = derive_home(host.path());
    let guest = mounted_text(&derived.outputs, "/.config/nats/user.nk");
    assert!(!guest.contains(&seed), "{guest}");
    NatsSeed::from_seed(SecretString::from(guest.trim().to_string())).expect("decoy seed");
    assert!(derived.outputs.grants.iter().any(|grant| grant.fragment.contains(&seed)));
    assert!(!mounted_text(&derived.outputs, "context/demo.json").contains(&seed));
  }

  /// A creds context mounts a decoy file. The real seed and JWT stay in the grant.
  #[test]
  fn derive_sources_mounts_a_decoy_creds_file() {
    use arkham_config::grants::NatsSeed;
    use base64::Engine as _;
    use secrecy::SecretString;

    let host = tempdir().unwrap();
    let nats = host.path().join(".config").join("nats");
    let creds_dir = nats.join("creds");
    fs::create_dir_all(creds_dir).unwrap();
    fs::create_dir_all(nats.join("context")).unwrap();
    let seed = nkeys::KeyPair::new_user().seed().unwrap();
    let public = NatsSeed::from_seed(SecretString::from(seed.clone())).unwrap().public;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{public}"}}"#).as_bytes());
    let jwt = format!(
      "{header}.{payload}.{}",
      base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig")
    );
    let creds = nats.join("creds").join("user.creds");
    fs::write(
      &creds,
      format!("-----BEGIN NATS USER JWT-----\n{jwt}\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n{seed}\n------END USER NKEY SEED------\n"),
    )
    .unwrap();
    fs::write(nats.join("context.txt"), "demo\n").unwrap();
    fs::write(
      nats.join("context").join("demo.json"),
      r#"{"url":"nats://nats.internal:4222","creds":"creds/user.creds"}"#,
    )
    .unwrap();
    let derived = derive_home(host.path());
    let guest = mounted_text(&derived.outputs, "/.config/nats/creds/user.creds");
    assert!(!guest.contains(&seed), "{guest}");
    assert!(!guest.contains(&jwt), "{guest}");
    let fragment = derived
      .outputs
      .grants
      .iter()
      .find(|grant| grant.fragment.contains(&seed))
      .expect("grant holds the real seed");
    assert!(fragment.fragment.contains(&jwt));
    assert!(!mounted_text(&derived.outputs, "context/demo.json").contains(&seed));
  }

  /// The selected `~/.config/nats` context becomes one grant. The guest
  /// mounts that context only.
  #[test]
  fn derive_sources_mounts_the_selected_nats_context() {
    use arkham_config::registry::Registry;
    use std::collections::HashMap;

    let host = tempdir().unwrap();
    token_context(host.path());
    let work = tempdir().unwrap();
    let empty_xdg = tempdir().unwrap();
    let _env = AmbientEnv::isolate(host.path(), empty_xdg.path());
    let outputs = derive_sources(&DeriveInputs {
      files_dir: &work.path().join("files"),
      root: work.path(),
      registry: &Registry::load(None).unwrap(),
      decoys: &[],
      expander: &build_expander(HashMap::new()),
      home: "/home/eng",
      host_home: Some(host.path()),
      guests_dir: &work.path().join("guests"),
      rewrites: &[],
    })
    .unwrap();
    let containers: Vec<String> = outputs.mounts.iter().map(|mount| mount.container.display().to_string()).collect();
    for expected in ["/home/eng/.config/nats/context.txt", "/home/eng/.config/nats/context/demo.json"] {
      assert!(containers.contains(&expected.to_string()), "{expected} missing from {containers:?}");
    }
    assert!(!containers.iter().any(|path| path.ends_with("other.json")), "{containers:?}");
    let context = outputs
      .mounts
      .iter()
      .find(|mount| mount.container == Path::new("/home/eng/.config/nats/context/demo.json"))
      .unwrap();
    let twin = fs::read_to_string(&context.host).unwrap();
    assert!(twin.contains("app"), "{twin}");
    assert!(!twin.contains("real-token"), "{twin}");
    assert!(outputs.grants.iter().any(|grant| grant.fragment.contains("real-token")));
    assert!(!outputs.grants.iter().any(|grant| grant.fragment.contains("other-real")));
  }

  /// A declared path under `~/.config/nats` stays with that declaration.
  #[test]
  fn declared_nats_context_is_not_derived_again() {
    use arkham_config::registry::Registry;
    use std::collections::HashMap;

    let host = tempdir().unwrap();
    let nats = token_context(host.path());
    let work = tempdir().unwrap();
    let empty_xdg = tempdir().unwrap();
    let _env = AmbientEnv::isolate(host.path(), empty_xdg.path());
    let declared = [FileRewrite {
      source: nats.join("context.txt"),
      dest: "{home}/.config/nats/context.txt".to_string(),
      envs: Vec::new(),
      format: None,
    }];
    let skipped = derive_sources(&DeriveInputs {
      files_dir: &work.path().join("files"),
      root: work.path(),
      registry: &Registry::load(None).unwrap(),
      decoys: &[],
      expander: &build_expander(HashMap::new()),
      home: "/home/eng",
      host_home: Some(host.path()),
      guests_dir: &work.path().join("guests"),
      rewrites: &declared,
    })
    .unwrap();
    assert!(!skipped.mounts.iter().any(|mount| mount.container.ends_with("context/demo.json")));
  }

  /// Broken ambient sources warn and skip; the healthy ones still map.
  #[test]
  fn broken_ambient_sources_skip_without_failing() {
    use arkham_config::registry::Registry;
    use std::collections::HashMap;
    use std::env;

    let host = tempdir().unwrap();
    let gitconfig = host.path().join(".gitconfig");
    fs::write(&gitconfig, "[credential \"https://github.com\"]\n\tusername = casualjim\n").unwrap();
    fs::create_dir_all(host.path().join(".ssh")).unwrap();
    fs::write(host.path().join(".ssh").join("config"), "Include work-stuff\nMatch final all\n").unwrap();
    fs::create_dir_all(host.path().join(".kube")).unwrap();
    fs::write(host.path().join(".kube").join("config"), "not: [valid: yaml\n").unwrap();
    let work = tempdir().unwrap();
    let git = work.path().join(".git");
    fs::create_dir_all(git.join("objects")).unwrap();
    fs::create_dir_all(git.join("refs").join("heads")).unwrap();
    fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
      git.join("config"),
      "[remote \"origin\"]\n\turl = https://github.com/casualjim/arkham.git\n",
    )
    .unwrap();
    let empty_xdg = tempdir().unwrap();
    let saved: Vec<(&str, Option<OsString>)> = [
      "KUBECONFIG",
      "TALOSCONFIG",
      "GIT_CONFIG_GLOBAL",
      "GIT_CONFIG_NOSYSTEM",
      "HOME",
      "XDG_CONFIG_HOME",
      "JJ_CONFIG",
    ]
    .map(|name| (name, env::var_os(name)))
    .to_vec();
    unset_env("KUBECONFIG");
    unset_env("TALOSCONFIG");
    unset_env("JJ_CONFIG");
    set_env("GIT_CONFIG_GLOBAL", &gitconfig);
    set_env("GIT_CONFIG_NOSYSTEM", "1");
    set_env("HOME", host.path());
    set_env("XDG_CONFIG_HOME", empty_xdg.path());
    let outputs = derive_sources(&DeriveInputs {
      files_dir: &work.path().join("files"),
      root: work.path(),
      registry: &Registry::load(None).unwrap(),
      decoys: &[Decoy {
        env: "GITHUB_TOKEN".to_string(),
        value: "ghp_decoy_decoy_decoy_decoy_decoy".to_string(),
      }],
      expander: &build_expander(HashMap::new()),
      home: "/home/eng",
      host_home: Some(host.path()),
      guests_dir: &work.path().join("guests"),
      rewrites: &[],
    })
    .unwrap();
    for (name, value) in saved {
      match value {
        Some(value) => set_env(name, value),
        None => unset_env(name),
      }
    }
    let containers: Vec<String> = outputs.mounts.iter().map(|mount| mount.container.display().to_string()).collect();
    assert!(
      containers.contains(&"/home/eng/.gitconfig".to_string()),
      "the healthy source still maps: {containers:?}"
    );
    assert!(
      !containers.contains(&"/home/eng/.ssh/config".to_string()),
      "the Include-only ssh config derives nothing: {containers:?}"
    );
    assert!(
      !containers.contains(&"/home/eng/.kube/config".to_string()),
      "the broken kubeconfig derives nothing: {containers:?}"
    );
  }
}
