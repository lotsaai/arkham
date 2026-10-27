//! Helpers shared by the compose crate tests.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::cli::ProxyBackend;
use arkham_config::config::fake_for;
use arkham_config::registry::Registry;
use tempfile::tempdir;

use crate::ambient::*;
use crate::decoys::*;
use crate::expand::*;
use crate::mounts::*;
use crate::paths::*;
use crate::profiles::*;
use crate::rewrites::*;
use crate::stack::*;

pub(crate) fn decoys() -> Vec<Decoy> {
  vec![
    Decoy {
      env: "GITHUB_TOKEN".to_string(),
      value: fake_for("GITHUB_TOKEN", None),
    },
    Decoy {
      env: "ANTHROPIC_API_KEY".to_string(),
      value: "sk-ant-api03-example".to_string(),
    },
  ]
}

pub(crate) fn mount(host: &str, container: &str, ro: bool) -> Mount {
  Mount {
    host: PathBuf::from(host),
    container: PathBuf::from(container),
    ro,
  }
}

/// Test agent spec: `root` inside the container, home `/home/eng`, and the
/// workspace-state storage directory the agent service mounts.
pub(crate) fn agent_paths(root: &str) -> AgentSpec {
  AgentSpec {
    root: PathBuf::from(root),
    home: "/home/eng".to_string(),
    storage: PathBuf::from("/state/arkham/ws/arkham/containers"),
    uid: 1000,
    devices: Vec::new(),
    cap_add: Vec::new(),
    image: DEFAULT_AGENT_IMAGE.to_string(),
    build: None,
  }
}

/// Image tag the test stack renders: obviously fake, so a leaked `:latest`
/// or a hardcoded version fails the assertion instead of passing silently.
pub(crate) const TEST_VERSION: &str = "0.0.0-test";

/// A default-ish stack to render in tests; override fields struct-update style.
pub(crate) fn test_stack(backend: ProxyBackend) -> Stack {
  Stack {
    backend,
    project: "arkham".to_string(),
    decoys: decoys(),
    agent: agent_paths("/home/eng"),
    mounts: Vec::new(),
    tool_mounts: Vec::new(),
    fnox: FnoxBinds::default(),
    guest: Vec::new(),
    init: None,
    ports: Vec::new(),
    expose: Vec::new(),
    networks: Vec::new(),
    extra_hosts: Vec::new(),
    passthrough: Vec::new(),
    file_mounts: Vec::new(),
    grants_mounts: Vec::new(),
    arkham_version: TEST_VERSION.to_string(),
  }
}

/// Test-only env write and removal, so the unsafe call lives in one place.
pub(crate) fn set_env(key: &str, value: impl AsRef<std::ffi::OsStr>) {
  // SAFETY: test-only mutation, and nextest runs one test per process.
  unsafe { std::env::set_var(key, value) };
}

pub(crate) fn unset_env(key: &str) {
  // SAFETY: test-only mutation, and nextest runs one test per process.
  unsafe { std::env::remove_var(key) };
}

/// Roots over a temp global config dir: the profiles dir plus the config
/// dir holding the profiles tree.
pub(crate) fn temp_global(dir: &tempfile::TempDir) -> PathBuf {
  dir.path().join(".config").join("arkham").join("profiles")
}

pub(crate) fn temp_roots(profiles: &Path) -> ProfileRoots<'_> {
  ProfileRoots {
    project: None,
    global: Some(profiles),
  }
}

pub(crate) fn rendered_mounts(mounts: &[Mount]) -> Vec<String> {
  mounts
    .iter()
    .map(|entry| {
      format!(
        "{}:{}:{}",
        entry.host.display(),
        entry.container.display(),
        if entry.ro { "ro" } else { "rw" }
      )
    })
    .collect()
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

pub(crate) fn derive_home(host: &Path) -> DerivedHome {
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
  .unwrap();
  DerivedHome {
    _work: work,
    _xdg: xdg,
    _env: env,
    outputs,
  }
}

pub(crate) struct WarnCapture(pub(crate) std::sync::Arc<std::sync::Mutex<Vec<String>>>);

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
    let _ = write!(self.0, "{}={value:?};", field.name());
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
