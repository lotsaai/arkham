//! Helpers shared by the compose crate tests.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use tempfile::tempdir;

use crate::ambient::{DeriveInputs, derive_sources};
use crate::rewrites::RewriteOutputs;
use arkham_workspace::build_expander;

/// Test-only env write and removal, so the unsafe call lives in one place.
pub(crate) fn set_env(key: &str, value: impl AsRef<std::ffi::OsStr>) {
  // SAFETY: test-only mutation, and nextest runs one test per process.
  unsafe { std::env::set_var(key, value) };
}

pub(crate) fn unset_env(key: &str) {
  // SAFETY: test-only mutation, and nextest runs one test per process.
  unsafe { std::env::remove_var(key) };
}

pub(crate) const KUBE_DOC: &str = r"apiVersion: v1
kind: Config
current-context: k3s-local
contexts:
- name: k3s-local
  context: {cluster: k3s, user: admin}
clusters:
- name: k3s
  cluster: {server: https://10.0.0.1:6443}
users:
- name: admin
  user: {token: probe-token}
";

/// Puts the ambient-source environment on a temp home and puts it back.
#[must_use]
pub(crate) struct AmbientEnv {
  saved: Vec<(&'static str, Option<OsString>)>,
}

impl AmbientEnv {
  pub(crate) fn isolate(home: &Path, xdg: &Path) -> Self {
    let saved = [
      "KUBECONFIG",
      "TALOSCONFIG",
      "GIT_CONFIG_GLOBAL",
      "GIT_CONFIG_NOSYSTEM",
      "HOME",
      "XDG_CONFIG_HOME",
      "JJ_CONFIG",
    ]
    .map(|name| (name, std::env::var_os(name)))
    .to_vec();
    unset_env("KUBECONFIG");
    unset_env("TALOSCONFIG");
    unset_env("JJ_CONFIG");
    unset_env("GIT_CONFIG_GLOBAL");
    set_env("GIT_CONFIG_NOSYSTEM", "1");
    set_env("HOME", home);
    set_env("XDG_CONFIG_HOME", xdg);
    Self { saved }
  }
}

impl Drop for AmbientEnv {
  fn drop(&mut self) {
    for (name, value) in self.saved.drain(..) {
      match value {
        Some(value) => set_env(name, value),
        None => unset_env(name),
      }
    }
  }
}

pub(crate) fn token_context(host: &Path) -> PathBuf {
  let nats = host.join(".config").join("nats");
  fs::create_dir_all(nats.join("context")).unwrap();
  fs::write(nats.join("context.txt"), "demo\n").unwrap();
  fs::write(
    nats.join("context").join("demo.json"),
    r#"{"url":"nats://nats.internal:4222","token":"real-token","jetstream_domain":"app"}"#,
  )
  .unwrap();
  fs::write(nats.join("context").join("other.json"), r#"{"token":"other-real"}"#).unwrap();
  nats
}

pub(crate) struct DerivedHome {
  pub(crate) _work: tempfile::TempDir,
  pub(crate) _xdg: tempfile::TempDir,
  pub(crate) _env: AmbientEnv,
  pub(crate) outputs: RewriteOutputs,
}

pub(crate) async fn derive_home(host: &Path) -> DerivedHome {
  use arkham_config::registry::Registry;
  use std::collections::HashMap;

  let work = tempdir().unwrap();
  let xdg = tempdir().unwrap();
  let env = AmbientEnv::isolate(host, xdg.path());
  let outputs = derive_sources(&DeriveInputs {
    files_dir: &work.path().join("files"),
    root: work.path(),
    registry: &Registry::load(None).unwrap(),
    decoys: &[],
    expander: &build_expander(HashMap::new()),
    home: "/home/eng",
    host_home: Some(host),
    guests_dir: &work.path().join("guests"),
    rewrites: &[],
  })
  .await
  .unwrap();
  DerivedHome {
    _work: work,
    _xdg: xdg,
    _env: env,
    outputs,
  }
}

pub(crate) fn mounted_text(outputs: &RewriteOutputs, suffix: &str) -> String {
  let mount = outputs
    .mounts
    .iter()
    .find(|mount| mount.container.to_string_lossy().ends_with(suffix))
    .unwrap_or_else(|| panic!("{suffix} missing"));
  fs::read_to_string(&mount.host).unwrap()
}
