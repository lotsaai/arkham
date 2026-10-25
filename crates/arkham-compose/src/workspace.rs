//! Workspace roots: identity, state, config, registry, and secret selection.
//! Commands resolve one owner instead of threading a bare root through free
//! functions.

use std::path::{Component, Path, PathBuf};

use arkham_config::cli::Cli;
use arkham_config::config::{
  AppConfig, load, project_config_dir, project_config_file, project_config_write_path, project_rules_dir, rules_dir,
};
use arkham_config::registry::Registry;
use dirs::state_dir;

use crate::decoys::Selection;
use crate::error::Error;

/// Stable directory slug for an arbitrary path: lowercase segments joined
/// with dashes. Workspace identity and grant labels share it, so the helper
/// lives here rather than beside either caller.
pub(crate) fn slug(path: &Path) -> String {
  let slug: Vec<String> = path
    .components()
    .filter_map(|component| match component {
      Component::Normal(part) => {
        let text = part.to_string_lossy().to_lowercase();
        let cleaned: String = text.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
        (!cleaned.trim_matches('-').is_empty()).then(|| cleaned.trim_matches('-').to_string())
      }
      _ => None,
    })
    .collect();
  slug.join("-")
}

/// Registry for the generation commands: bundled table, global `rules.d`,
/// then the workspace's own. The loader primitive behind both selection
/// loading and the tests that need a registry without a workspace.
pub(crate) fn generation_registry(root: Option<&Path>) -> Result<Registry, Error> {
  Ok(Registry::load_union(
    rules_dir().as_deref(),
    root.map(project_rules_dir).as_deref(),
  )?)
}

/// A workspace root and everything derived from it: slug, state directory,
/// override file, config, registry, and secret selection.
pub(crate) struct Workspace {
  root: PathBuf,
}

impl Workspace {
  /// A workspace over an already-resolved root: generation and tests.
  pub(crate) fn new(root: &Path) -> Self {
    Self { root: root.to_path_buf() }
  }

  /// Resolve the workspace a command names, defaulting to the current
  /// directory and canonicalizing: every command entry starts here.
  ///
  /// # Errors
  ///
  /// Returns an error when the directory cannot be canonicalized.
  pub(crate) fn resolve(workspace: Option<&Path>) -> Result<Self, Error> {
    let root = workspace.unwrap_or(Path::new(".")).to_path_buf();
    root
      .canonicalize()
      .map(|root| Self { root })
      .map_err(|source| Error::ResolveWorkspace { path: root, source })
  }

  /// The absolute workspace root.
  pub(crate) fn root(&self) -> &Path {
    &self.root
  }

  /// Stable directory slug for the root.
  pub(crate) fn slug(&self) -> String {
    slug(&self.root)
  }

  /// The workspace's state directory: `<state-dir>/arkham/ws/<slug>`. The
  /// generated stack lives here and the agent's inner-runtime storage sits
  /// beside it.
  pub(crate) fn state_dir(&self) -> PathBuf {
    state_dir()
      .unwrap_or_else(|| PathBuf::from("."))
      .join("arkham")
      .join("ws")
      .join(self.slug())
  }

  /// The workspace's override file. Unified `.config/arkham/compose.yaml`
  /// wins, then `.yml`, then the legacy flat names. Absent files still
  /// report the canonical unified path.
  pub(crate) fn file(&self) -> PathBuf {
    let dir = project_config_dir(&self.root);
    for name in ["compose.yaml", "compose.yml"] {
      let path = dir.join(name);
      if path.is_file() {
        return path;
      }
    }
    for name in ["arkham.compose.yaml", "arkham.compose.yml"] {
      let path = self.root.join(".config").join(name);
      if path.is_file() {
        return path;
      }
    }
    dir.join("compose.yaml")
  }

  /// The workspace's own config, as generation and support-file setup read
  /// it: the unified project layer when it exists, the legacy flat file
  /// otherwise, and the unified path itself when neither does — a workspace
  /// with no config has no project layer at all, never one discovered from
  /// the process cwd.
  pub(crate) fn config(&self) -> Result<AppConfig, Error> {
    let cli = Cli {
      config: Some(project_config_file(&self.root).unwrap_or_else(|| project_config_write_path(&self.root))),
    };
    Ok(load(&cli, None)?.0)
  }

  /// The secret selection for this workspace: its registry joined against
  /// fnox discovery.
  pub(crate) fn selection(&self) -> Result<Selection, Error> {
    Selection::load(Some(self.root()))
  }
}

#[cfg(test)]
mod moved_suite {

  use std::fs;
  use std::path::Path;

  use tempfile::tempdir;

  use crate::confine::*;
  use crate::workspace::Workspace;

  /// Unified compose files win over the legacy flat names. Absent files report the canonical path.
  #[test]
  fn workspace_override_file_prefers_unified_compose_then_legacy() {
    let root = tempfile::tempdir().unwrap();
    let ws = Workspace::new(root.path());
    let unified = root.path().join(".config").join("arkham");
    let canonical = unified.join("compose.yaml");
    assert_eq!(ws.file(), canonical, "no override yet names the canonical path");

    fs::create_dir_all(root.path().join(".config")).unwrap();
    let older_short = root.path().join(".config").join("arkham.compose.yml");
    fs::write(&older_short, "legacy: yml\n").unwrap();
    assert_eq!(ws.file(), older_short);

    let older_long = root.path().join(".config").join("arkham.compose.yaml");
    fs::write(&older_long, "legacy: yaml\n").unwrap();
    assert_eq!(ws.file(), older_long);

    fs::create_dir_all(&unified).unwrap();
    let nested_short = unified.join("compose.yml");
    fs::write(&nested_short, "unified: yml\n").unwrap();
    assert_eq!(ws.file(), nested_short);

    fs::write(&canonical, "unified: yaml\n").unwrap();
    assert_eq!(ws.file(), canonical);
  }

  /// Home prefixes move to the container home; URLs, relative paths, and
  /// off-home absolutes stay intact.
  #[test]
  fn mise_rewrite_translates_home_paths_only() {
    let home = Path::new("/home/ivan");
    let rewritten = rewrite_mise_toml(
      "[tools]\nnode = \"22\"\n[env]\nTOKEN_FILE = \"/home/ivan/.npmrc\"\nURL = \"https://example.com/x\"\nREL = \"./bin/tool\"\nOTHER = \"/etc/hosts\"\nTILDE = \"~/.config/mise\"\nLIST = [\"/home/ivan/a\", \"b\"]\n",
      Some(home),
      "/home/eng",
    )
    .unwrap();
    assert!(rewritten.contains("/home/eng/.npmrc"), "{rewritten}");
    assert!(rewritten.contains("https://example.com/x"), "{rewritten}");
    assert!(rewritten.contains("./bin/tool"), "{rewritten}");
    assert!(rewritten.contains("/etc/hosts"), "{rewritten}");
    assert!(rewritten.contains("/home/eng/.config/mise"), "{rewritten}");
    assert!(rewritten.contains("/home/eng/a"), "{rewritten}");
  }

  /// The agent file is created once from the local file and never
  /// overwritten; without the mise pair nothing happens.
  #[test]
  fn mise_agent_file_is_created_once_and_never_overwritten() {
    let dir = tempdir().unwrap();
    assert!(!ensure_mise_agent(dir.path(), "/home/eng").unwrap());
    fs::write(dir.path().join("mise.toml"), "[tools]\n").unwrap();
    fs::write(dir.path().join("mise.local.toml"), "[env]\nA = \"1\"\n").unwrap();
    assert!(ensure_mise_agent(dir.path(), "/home/eng").unwrap());
    fs::write(dir.path().join("mise.agent.toml"), "edited").unwrap();
    assert!(!ensure_mise_agent(dir.path(), "/home/eng").unwrap());
    assert_eq!(fs::read_to_string(dir.path().join("mise.agent.toml")).unwrap(), "edited");
  }
}
