//! Tool profile mounts: the selected profile's tool configs mounted where the
//! tools read them by default.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::config::SHARED_PROFILE;
use arkham_config::config::{ToolCfg, profile_chain, valid_profile};

use arkham_paths::Mount;

/// Errors while selecting tool profile mounts.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// Profile configuration could not be read.
  #[error(transparent)]
  Config(Box<arkham_config::Error>),
  /// A directory could not be created.
  #[error("create {}: {source}", path.display())]
  CreateDir {
    /// Directory that could not be created.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: std::io::Error,
  },
  /// A tool name is not a plain directory name.
  #[error("[tools.{name}] is not a plain directory name to mount")]
  ToolNameInvalid {
    /// Invalid tool name.
    name: String,
  },
  /// A tool configuration destination is not absolute.
  #[error("[tools.{name}] config_dir `{template}` does not expand to an absolute container path")]
  ToolConfigNotAbsolute {
    /// Tool name.
    name: String,
    /// Configured destination.
    template: String,
  },
}

impl From<arkham_config::Error> for Error {
  fn from(source: arkham_config::Error) -> Self {
    Self::Config(Box::new(source))
  }
}

impl Error {
  /// Returns a safe summary for registration clients.
  #[must_use]
  pub fn registration_summary(&self) -> &'static str {
    match self {
      Self::CreateDir { .. } => "session files could not be prepared",
      Self::Config(_) | Self::ToolNameInvalid { .. } | Self::ToolConfigNotAbsolute { .. } => "configuration could not be read",
    }
  }
}

/// Result of selecting profile mounts.
pub type Result<T> = std::result::Result<T, Error>;

/// Container location each tool reads its config from by default, keyed by the
/// directory name under `profiles/<profile>/`. `{home}` expands to
/// `[workspace] home`. `[tools.<name>] config_dir` overrides an entry or adds
/// one the table does not carry.
const TOOL_CONFIG_DIRS: &[(&str, &str)] = &[
  ("amazon-q", "{home}/.aws/amazonq"),
  ("amazonq", "{home}/.aws/amazonq"),
  ("amp", "{home}/.config/amp"),
  ("auggie", "{home}/.augment"),
  ("augment", "{home}/.augment"),
  ("claude", "{home}/.claude"),
  ("claude-code", "{home}/.claude"),
  ("cline", "{home}/.cline"),
  ("codebuddy", "{home}/.codebuddy"),
  ("codebuff", "{home}/.config/manicode"),
  ("codex", "{home}/.codex"),
  ("codex-cli", "{home}/.codex"),
  ("continue", "{home}/.continue"),
  ("copilot", "{home}/.copilot"),
  ("crush", "{home}/.config/crush"),
  ("cursor", "{home}/.cursor"),
  ("deepagents", "{home}/.deepagents"),
  ("droid", "{home}/.factory"),
  ("dsh", "{home}/.dsh"),
  ("factory", "{home}/.factory"),
  ("forge", "{home}/.forge"),
  ("gemini", "{home}/.gemini"),
  ("gemini-cli", "{home}/.gemini"),
  ("gh", "{home}/.config/gh"),
  ("goose", "{home}/.config/goose"),
  ("gptme", "{home}/.config/gptme"),
  ("grok", "{home}/.grok"),
  ("grok-build", "{home}/.grok"),
  ("hermes", "{home}/.hermes"),
  ("iflow", "{home}/.iflow"),
  ("junie", "{home}/.junie"),
  ("junie-cli", "{home}/.junie"),
  ("kilo", "{home}/.config/kilo"),
  ("kimi", "{home}/.kimi"),
  ("kimi-code", "{home}/.kimi-code"),
  ("kiro", "{home}/.kiro"),
  ("kiro-cli", "{home}/.kiro"),
  ("mimo", "{home}/.mimo-code"),
  ("mimo-code", "{home}/.mimo-code"),
  ("muse", "{home}/.muse-code"),
  ("muse-code", "{home}/.muse-code"),
  ("omp", "{home}/.omp"),
  ("open-interpreter", "{home}/.config/open-interpreter"),
  ("openclaw", "{home}/.openclaw"),
  ("openhands", "{home}/.openhands"),
  ("openinterpreter", "{home}/.config/open-interpreter"),
  ("opencode", "{home}/.config/opencode"),
  ("pi", "{home}/.pi"),
  ("qoder", "{home}/.qoder"),
  ("qwen", "{home}/.qwen"),
  ("qwen-code", "{home}/.qwen"),
  ("roo", "{home}/.config/roo"),
  ("roo-code", "{home}/.config/roo"),
  ("tea", "{home}/.config/tea"),
  ("trae", "{home}/.trae"),
  ("vibe", "{home}/.vibe"),
  ("warp", "{home}/.config/warp-terminal"),
  ("workbuddy", "{home}/.codebuddy"),
];

/// Profile roots searched for tool configs: the workspace's own directory
/// first, the global one next.
#[derive(Debug)]
pub struct ProfileRoots<'a> {
  /// `<root>/.config/arkham/profiles/`, when generation knows the workspace.
  pub project: Option<&'a Path>,
  /// `<config-dir>/arkham/profiles/`, when the global config resolves.
  pub global: Option<&'a Path>,
}

impl ProfileRoots<'_> {
  /// A profile-chain layer carrying `name`, project first: the directory to
  /// mount when the tool is already installed somewhere.
  fn chain_dir(&self, chain: &[String], name: &str) -> Option<PathBuf> {
    [self.project, self.global]
      .into_iter()
      .flatten()
      .flat_map(|layer| chain.iter().map(move |parent| layer.join(parent).join(name)))
      .find(|dir| dir.is_dir())
  }

  /// Where a configured tool's missing profile dir is made: the global
  /// profiles dir only. The workspace's project layer is read-only — arkham
  /// never creates anything inside the project root.
  fn create_base(&self, profile: &str) -> Option<PathBuf> {
    self.global.map(|global| global.join(profile))
  }
}

/// Mount the selected profile's tool configs at the locations the tools read
/// by default, so nothing has to point a tool at them. Explicitly configured
/// tools mount (their missing profile dir is created in the global profiles
/// dir, never the project); known tools mount only a directory the profile
/// chain already carries — nothing is mapped for a tool nobody installed,
/// and nothing is ever generated inside the project root.
///
/// # Errors
///
/// Returns an error for an invalid profile chain, tool name, or destination,
/// or when a global profile directory cannot be created.
pub fn profile_mounts(roots: &ProfileRoots<'_>, profile: &str, configured: &BTreeMap<String, ToolCfg>, home: &str) -> Result<Vec<Mount>> {
  let chain = profile_chain(roots.project, roots.global, profile)?;
  if let Some(global) = roots.global {
    let dir = global.join(SHARED_PROFILE);
    fs::create_dir_all(&dir).map_err(|source| Error::CreateDir { path: dir.clone(), source })?;
  }
  // Explicit `[tools]` entries are opted in: their profile dir is made under
  // the global profiles dir when no layer carries it, so a first-run setup
  // persists — and the project root stays untouched.
  let mut mounts = Vec::new();
  for (name, tool) in configured {
    if !valid_profile(name) {
      return Err(Error::ToolNameInvalid { name: name.clone() });
    }
    let container = tool.config_dir.replace("{home}", home);
    if !container.starts_with('/') {
      return Err(Error::ToolConfigNotAbsolute {
        name: name.clone(),
        template: tool.config_dir.clone(),
      });
    }
    let host = match (roots.chain_dir(&chain, name), roots.create_base(profile)) {
      (Some(existing), _) => existing,
      (None, Some(base)) => {
        let dir = base.join(name);
        fs::create_dir_all(&dir).map_err(|source| Error::CreateDir { path: dir.clone(), source })?;
        dir
      }
      (None, None) => continue,
    };
    mounts.push(Mount {
      host,
      container: PathBuf::from(container),
      ro: false,
    });
  }
  // Known tools nobody configured mount only a directory the profile chain
  // already has: nothing is mapped for a tool nobody installed.
  for (name, template) in TOOL_CONFIG_DIRS {
    if configured.contains_key(*name) {
      continue;
    }
    let Some(host) = roots.chain_dir(&chain, name) else {
      continue;
    };
    mounts.push(Mount {
      host,
      container: PathBuf::from(template.replace("{home}", home)),
      ro: false,
    });
  }
  Ok(mounts)
}

#[cfg(test)]
mod tests {
  use super::*;
  fn temp_global(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join(".config").join("arkham").join("profiles")
  }

  fn temp_roots(profiles: &Path) -> ProfileRoots<'_> {
    ProfileRoots {
      project: None,
      global: Some(profiles),
    }
  }

  fn rendered_mounts(mounts: &[Mount]) -> Vec<String> {
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

  #[test]
  fn shared_profile_mounts_tools_at_each_tools_default_location() {
    let dir = tempfile::tempdir().unwrap();
    let profiles = temp_global(&dir);
    let shared = profiles.join("__shared__");
    std::fs::create_dir_all(shared.join("pi")).unwrap();
    std::fs::create_dir_all(shared.join("opencode")).unwrap();
    std::fs::create_dir_all(shared.join("not-a-tool")).unwrap();
    std::fs::write(shared.join("stray-file"), "x").unwrap();

    let roots = temp_roots(&profiles);
    let mounts = profile_mounts(&roots, "__shared__", &BTreeMap::new(), "/home/eng").unwrap();
    let rendered = rendered_mounts(&mounts);
    assert!(
      rendered.contains(&format!("{}:/home/eng/.config/opencode:rw", shared.join("opencode").display())),
      "{rendered:?}"
    );
    assert!(
      rendered.contains(&format!("{}:/home/eng/.pi:rw", shared.join("pi").display())),
      "{rendered:?}"
    );
    assert!(!rendered.iter().any(|mount| mount.contains("not-a-tool")), "{rendered:?}");
  }

  #[test]
  fn shared_root_is_created_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let profiles = temp_global(&dir);
    let roots = temp_roots(&profiles);
    let mounts = profile_mounts(&roots, "__shared__", &BTreeMap::new(), "/home/eng").unwrap();
    assert!(
      profiles.join("__shared__").is_dir(),
      "the base every profile inherits is always made"
    );
    assert!(
      rendered_mounts(&mounts).is_empty(),
      "unconfigured tools with no profile dir mount nothing: {mounts:?}"
    );
  }

  #[test]
  fn named_profile_inherits_shared_tools_it_does_not_name() {
    let dir = tempfile::tempdir().unwrap();
    let profiles = temp_global(&dir);
    std::fs::create_dir_all(profiles.join("__shared__").join("pi")).unwrap();
    std::fs::create_dir_all(profiles.join("work").join("gh")).unwrap();

    let roots = temp_roots(&profiles);
    let mounts = profile_mounts(&roots, "work", &BTreeMap::new(), "/home/eng").unwrap();
    assert!(
      rendered_mounts(&mounts).contains(&format!("{}:/home/eng/.config/gh:rw", profiles.join("work").join("gh").display())),
      "{mounts:?}"
    );
    assert!(
      rendered_mounts(&mounts).contains(&format!("{}:/home/eng/.pi:rw", profiles.join("__shared__").join("pi").display())),
      "{mounts:?}"
    );
  }

  #[test]
  fn cookie_chains_inherit_grandparent_tools() {
    let dir = tempfile::tempdir().unwrap();
    let profiles = temp_global(&dir);
    std::fs::create_dir_all(profiles.join("__shared__").join("pi")).unwrap();
    std::fs::create_dir_all(profiles.join("mid").join("opencode")).unwrap();
    std::fs::create_dir_all(profiles.join("leaf")).unwrap();
    std::fs::write(profiles.join("mid").join("profile.toml"), "[profile]\nparent = \"__shared__\"\n").unwrap();
    std::fs::write(profiles.join("leaf").join("profile.toml"), "[profile]\nparent = \"mid\"\n").unwrap();

    let roots = temp_roots(&profiles);
    let mounts = profile_mounts(&roots, "leaf", &BTreeMap::new(), "/home/eng").unwrap();
    assert!(
      rendered_mounts(&mounts).contains(&format!(
        "{}:/home/eng/.config/opencode:rw",
        profiles.join("mid").join("opencode").display()
      )),
      "{mounts:?}"
    );
    assert!(
      rendered_mounts(&mounts).contains(&format!("{}:/home/eng/.pi:rw", profiles.join("__shared__").join("pi").display())),
      "{mounts:?}"
    );
  }

  #[test]
  fn project_layer_beats_global_at_each_inheritance_tier() {
    let dir = tempfile::tempdir().unwrap();
    let profiles = temp_global(&dir);
    let project = dir.path().join("ws").join(".config").join("arkham").join("profiles");
    std::fs::create_dir_all(project.join("work").join("pi")).unwrap();
    std::fs::create_dir_all(profiles.join("work").join("pi")).unwrap();
    std::fs::create_dir_all(project.join("__shared__").join("opencode")).unwrap();
    std::fs::create_dir_all(profiles.join("__shared__").join("opencode")).unwrap();

    let roots = ProfileRoots {
      project: Some(project.as_path()),
      global: Some(profiles.as_path()),
    };
    let mounts = profile_mounts(&roots, "work", &BTreeMap::new(), "/home/eng").unwrap();
    assert!(
      rendered_mounts(&mounts).contains(&format!(
        "{}:/home/eng/.config/opencode:rw",
        project.join("__shared__").join("opencode").display()
      )),
      "{mounts:?}"
    );
    assert!(
      rendered_mounts(&mounts).contains(&format!("{}:/home/eng/.pi:rw", project.join("work").join("pi").display())),
      "{mounts:?}"
    );
  }

  #[test]
  fn project_default_beats_global_named_profile() {
    let dir = tempfile::tempdir().unwrap();
    let profiles = temp_global(&dir);
    let project = dir.path().join("ws").join(".config").join("arkham").join("profiles");
    std::fs::create_dir_all(project.join("__shared__").join("pi")).unwrap();
    std::fs::create_dir_all(profiles.join("work").join("pi")).unwrap();

    let roots = ProfileRoots {
      project: Some(project.as_path()),
      global: Some(profiles.as_path()),
    };
    let mounts = profile_mounts(&roots, "work", &BTreeMap::new(), "/home/eng").unwrap();
    assert!(
      rendered_mounts(&mounts).contains(&format!("{}:/home/eng/.pi:rw", project.join("__shared__").join("pi").display())),
      "{mounts:?}"
    );
  }

  #[test]
  fn configured_tools_extend_and_override_the_built_in_table() {
    let dir = tempfile::tempdir().unwrap();
    let profiles = temp_global(&dir);
    let shared = profiles.join("__shared__");
    std::fs::create_dir_all(shared.join("pi")).unwrap();
    std::fs::create_dir_all(shared.join("trae")).unwrap();

    let configured = BTreeMap::from([
      (
        "pi".to_string(),
        ToolCfg {
          config_dir: "{home}/.pi-alt".to_string(),
        },
      ),
      (
        "trae".to_string(),
        ToolCfg {
          config_dir: "{home}/.trae".to_string(),
        },
      ),
    ]);
    let roots = temp_roots(&profiles);
    let mounts = profile_mounts(&roots, "__shared__", &configured, "/home/eng").unwrap();
    let rendered: Vec<String> = mounts
      .iter()
      .map(|entry| format!("{}:{}", entry.host.display(), entry.container.display()))
      .collect();
    assert!(
      rendered.contains(&format!("{}:/home/eng/.pi-alt", shared.join("pi").display())),
      "{rendered:?}"
    );
    assert!(
      rendered.contains(&format!("{}:/home/eng/.trae", shared.join("trae").display())),
      "{rendered:?}"
    );

    let relative = BTreeMap::from([(
      "pi".to_string(),
      ToolCfg {
        config_dir: "relative/pi".to_string(),
      },
    )]);
    let err = profile_mounts(&roots, "__shared__", &relative, "/home/eng").unwrap_err();
    assert!(err.to_string().contains("absolute"), "{err:?}");
  }

  #[test]
  fn configured_tool_names_must_be_plain_directory_names() {
    let dir = tempfile::tempdir().unwrap();
    let profiles = temp_global(&dir);
    let configured = BTreeMap::from([(
      "../escape".to_string(),
      ToolCfg {
        config_dir: "{home}/.escape".to_string(),
      },
    )]);
    let roots = temp_roots(&profiles);
    let err = profile_mounts(&roots, "__shared__", &configured, "/home/eng").unwrap_err();
    assert!(err.to_string().contains("not a plain directory name"), "{err:?}");
    assert!(
      !profiles
        .parent()
        .and_then(|p| p.parent())
        .is_some_and(|config| config.join("escape").is_dir()),
      "the escape must not create anything outside the profiles root"
    );
  }

  #[test]
  fn configured_tool_is_created_under_the_selected_profile() {
    let dir = tempfile::tempdir().unwrap();
    let profiles = temp_global(&dir);
    let configured = BTreeMap::from([(
      "custom".to_string(),
      ToolCfg {
        config_dir: "{home}/.custom".to_string(),
      },
    )]);

    let roots = temp_roots(&profiles);
    let mounts = profile_mounts(&roots, "work", &configured, "/home/eng").unwrap();
    let host = profiles.join("work").join("custom");
    assert!(host.is_dir(), "explicit intent makes the directory");
    assert!(
      rendered_mounts(&mounts).contains(&format!("{}:/home/eng/.custom:rw", host.display())),
      "{mounts:?}"
    );
  }

  #[test]
  fn profile_cycles_and_unknown_parents_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let profiles = temp_global(&dir);
    for name in ["aaa", "bbb"] {
      std::fs::create_dir_all(profiles.join(name)).unwrap();
    }
    std::fs::write(profiles.join("aaa").join("profile.toml"), "[profile]\nparent = \"bbb\"\n").unwrap();
    std::fs::write(profiles.join("bbb").join("profile.toml"), "[profile]\nparent = \"aaa\"\n").unwrap();
    std::fs::create_dir_all(profiles.join("orphan")).unwrap();
    std::fs::write(profiles.join("orphan").join("profile.toml"), "[profile]\nparent = \"missing\"\n").unwrap();

    let roots = temp_roots(&profiles);
    let err = profile_mounts(&roots, "aaa", &BTreeMap::new(), "/home/eng").unwrap_err();
    assert!(err.to_string().contains("cycle"), "{err:?}");
    let err = profile_mounts(&roots, "orphan", &BTreeMap::new(), "/home/eng").unwrap_err();
    assert!(err.to_string().contains("missing"), "{err:?}");
    let err = profile_mounts(&roots, "../x", &BTreeMap::new(), "/home/eng").unwrap_err();
    assert!(err.to_string().contains("plain directory name"), "{err:?}");
  }
}
