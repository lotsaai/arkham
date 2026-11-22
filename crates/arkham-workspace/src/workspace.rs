//! Workspace roots: identity, state, config, registry, and secret selection.
//! Commands resolve one owner instead of threading a bare root through free
//! functions.

use std::path::{Path, PathBuf};

use arkham_config::cli::Cli;
use arkham_config::config::{AppConfig, load, project_config_file, project_config_write_path, project_rules_dir, rules_dir};
use arkham_config::registry::Registry;
use arkham_paths::slug;

use crate::Result;

/// Registry for the generation commands: bundled table, global `rules.d`,
/// then the workspace's own. The loader primitive behind both selection
/// loading and the tests that need a registry without a workspace.
pub(crate) fn generation_registry(root: Option<&Path>) -> Result<Registry> {
  Ok(Registry::load_union(
    rules_dir().as_deref(),
    root.map(project_rules_dir).as_deref(),
  )?)
}

/// A workspace root and everything derived from it: slug, state directory,
/// override file, config, registry, and secret selection.
#[derive(Debug)]
pub struct Workspace {
  root: PathBuf,
}

impl Workspace {
  /// A workspace over an already-resolved root: generation and tests.
  #[must_use]
  pub fn new(root: &Path) -> Self {
    Self { root: root.to_path_buf() }
  }

  /// Stable directory slug for the root.
  #[must_use]
  pub fn slug(&self) -> String {
    slug(&self.root)
  }

  /// The workspace's state directory: `<state-dir>/arkham/ws/<slug>`. The
  /// generated stack lives here and the agent's inner-runtime storage sits
  /// beside it.
  #[must_use]
  pub fn state_dir(&self) -> PathBuf {
    arkham_config::config::user_state_dir()
      .unwrap_or_else(|| PathBuf::from("."))
      .join("arkham")
      .join("ws")
      .join(self.slug())
  }

  /// The workspace's own config, as generation and support-file setup read
  /// it: the unified project layer when it exists, the legacy flat file
  /// otherwise, and the unified path itself when neither does — a workspace
  /// with no config has no project layer at all, never one discovered from
  /// the process cwd.
  ///
  /// # Errors
  ///
  /// Returns an error if the workspace configuration cannot be loaded.
  pub fn config(&self) -> Result<AppConfig> {
    let cli = Cli {
      config: Some(project_config_file(&self.root).unwrap_or_else(|| project_config_write_path(&self.root))),
    };
    Ok(load(&cli, None)?.0)
  }
}
