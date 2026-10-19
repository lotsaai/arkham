//! Decoy selection and `arkham rules` rendering: which fnox-declared names get
//! decoys, which still need hosts, and the env-only TOML both commands print.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use arkham_config::config::RuleCfg;
use arkham_config::registry::Registry;
use arkham_fnox::{FNOX_ENV, FnoxSource, selected_envs};

use crate::error::Error;
use crate::workspace::generation_registry;

/// One selected env var with its decoy value.
pub(crate) struct Decoy {
  /// Env var name as the rule declares it.
  pub env: String,
  /// Decoy value for the agent environment.
  pub value: String,
}

/// A passthrough name that is also a rule env or a selected decoy is a
/// generation-time error: one name takes one path, never both. A pure
/// relation over three collections owned by different parties, so it stays
/// a free function instead of pretending one of them owns it.
///
/// # Errors
///
/// Returns an error naming the offending name when it overlaps.
pub(crate) fn validate_passthrough(rules: &BTreeMap<String, RuleCfg>, decoys: &[Decoy], passthrough: &[String]) -> Result<(), Error> {
  for name in passthrough {
    if rules.values().any(|rule| &rule.env == name) {
      return Err(Error::PassthroughOverlapRule { name: name.clone() });
    }
    if decoys.iter().any(|decoy| &decoy.env == name) {
      return Err(Error::PassthroughOverlapDecoy { name: name.clone() });
    }
  }
  Ok(())
}

/// The secret selection for one run: fnox discovery joined against the
/// registry. Every decoy query reads through this owner instead of threading
/// the pair through free functions.
pub(crate) struct Selection {
  /// The secret source, when one is configured.
  pub(crate) fnox: Option<FnoxSource>,
  /// Host-known registry joined with fnox names.
  pub(crate) registry: Registry,
}

/// fnox-declared names nothing covers: not registry-selected, not
/// passthrough, and not fnox's own provider wiring (which the proxy forwards
/// itself). A pure relation over a declared set owned by neither this module
/// nor its callers, so it stays free and directly testable.
pub(crate) fn uncovered_names(declared: &BTreeSet<String>, selected: &[String], passthrough: &[String]) -> Vec<String> {
  declared
    .iter()
    .filter(|name| !selected.contains(name) && !passthrough.contains(name) && !FNOX_ENV.contains(&name.as_str()))
    .cloned()
    .collect()
}

/// One sorted warning naming uncovered names and the fix; `None` when every
/// declared name is covered.
pub(crate) fn uncovered_warning(names: &[String]) -> Option<String> {
  if names.is_empty() {
    return None;
  }
  let mut sorted = names.to_vec();
  sorted.sort();
  Some(format!(
    "warning: fnox declares {} with no rule or passthrough ({}); add [rules.*] entries or [workspace] passthrough names, or remove them from fnox if unused",
    if sorted.len() == 1 { "a secret" } else { "secrets" },
    sorted.join(", ")
  ))
}

impl Selection {
  /// Load the selection for `root`: bundled plus global plus workspace
  /// `rules.d`, joined against fnox discovery with no arkham-specific env
  /// vars. `None` matches what generation derives decoys from.
  ///
  /// # Errors
  ///
  /// Returns an error when the registry or the fnox source cannot be opened.
  pub(crate) fn load(root: Option<&Path>) -> Result<Self, Error> {
    Ok(Self {
      fnox: FnoxSource::open()?,
      registry: generation_registry(root)?,
    })
  }

  /// Select every fnox-declared name the registry knows, with its decoy.
  pub(crate) fn select(&self) -> Vec<Decoy> {
    selected_envs(self.fnox.as_ref(), &self.registry)
      .into_iter()
      .map(|env| {
        let value = self.registry.decoy(&env, None);
        Decoy { env, value }
      })
      .collect()
  }

  /// Reshape a selection with each rule's own pattern. Serve-time
  /// substitution derives its fake from `rule.pattern`, so a decoy built
  /// from the registry default instead would never match and the swap would
  /// silently not happen.
  pub(crate) fn apply_rule_patterns(&self, decoys: Vec<Decoy>, rules: &BTreeMap<String, RuleCfg>) -> Vec<Decoy> {
    decoys
      .into_iter()
      .map(|decoy| {
        let pattern = rules
          .values()
          .find(|rule| rule.env == decoy.env)
          .and_then(|rule| rule.pattern.as_deref());
        Decoy {
          value: self.registry.decoy(&decoy.env, pattern),
          ..decoy
        }
      })
      .collect()
  }

  /// Split a selection by whether the registry states hosts for the name.
  /// Active rules come first, names with no endpoint second.
  pub(crate) fn split_by_hosts(&self, decoys: Vec<Decoy>) -> (Vec<Decoy>, Vec<Decoy>) {
    decoys
      .into_iter()
      .partition(|decoy| self.registry.lookup(&decoy.env).is_some_and(|known| !known.hosts.is_empty()))
  }

  /// Env names serve-time derivation turns into rules: fnox-declared,
  /// registry-known, with hosts.
  pub(crate) fn derivable_envs(&self) -> Vec<String> {
    self.split_by_hosts(self.select()).0.into_iter().map(|decoy| decoy.env).collect()
  }

  /// Coverage warning for entering the agent: one sorted warning for
  /// fnox-declared names no rule, passthrough, or provider wiring covers.
  /// Never prints values.
  pub(crate) fn coverage_warning(&self, passthrough: &[String]) -> Option<String> {
    let selected = selected_envs(self.fnox.as_ref(), &self.registry);
    let uncovered = self
      .fnox
      .as_ref()
      .map(|fnox| uncovered_names(fnox.declared(), &selected, passthrough))
      .unwrap_or_default();
    uncovered_warning(&uncovered)
  }

  /// Names fnox declares that no registry entry covers, so nothing derives
  /// for them.
  pub(crate) fn unregistered(&self, known: &[String]) -> Vec<String> {
    self
      .fnox
      .as_ref()
      .map(|fnox| {
        fnox
          .declared()
          .iter()
          .filter(|name| !known.contains(name))
          .cloned()
          .collect::<Vec<_>>()
      })
      .unwrap_or_default()
  }

  /// The report `arkham rules` prints: what derivation substitutes, what
  /// still needs a host, and what no registry entry covers.
  pub(crate) fn report(&self) -> Report {
    let (active, hostless) = self.split_by_hosts(self.select());
    let known = selected_envs(self.fnox.as_ref(), &self.registry);
    Report {
      active,
      hostless,
      unregistered: self.unregistered(&known),
    }
  }
}

/// What derivation substitutes, what still needs a host, and what no
/// registry entry covers: the three lists `arkham rules` renders.
pub(crate) struct Report {
  /// Decoys with registry hosts: what substitutes at serve time.
  pub(crate) active: Vec<Decoy>,
  /// Registry-known names with no endpoint: what still needs a host.
  pub(crate) hostless: Vec<Decoy>,
  /// fnox declarations no registry entry covers: what never derives.
  pub(crate) unregistered: Vec<String>,
}

impl Report {
  /// Render the env-only TOML for the selection.
  pub(crate) fn render(&self) -> String {
    let mut out = String::from(
      "# `arkham rules` — what this workspace's proxy substitutes.\n\
       #\n\
       # The catalog derives at serve time: every fnox-declared name the registry\n\
       # gives hosts becomes a rule, its value resolving from fnox. Config states\n\
       # overrides only — a [rules.<env>] block in the workspace\n\
       # `.config/arkham/config.toml` or the global `<config-dir>/arkham/config.toml`,\n\
       # where the workspace file wins per label; its `allow` unions with the\n\
       # registry hosts, and `registry = false` keeps only `allow`. To give a name\n\
       # hosts in every workspace instead, add an override file in\n\
       # `<config-dir>/arkham/rules.d/` or `<workspace root>/.config/arkham/rules.d/`.\n",
    );
    if !self.active.is_empty() {
      out.push_str("#\n# derives automatically at serve time, hosts from the registry:\n");
      for decoy in &self.active {
        let _ = writeln!(out, "[rules.{}]\nenv = \"{}\"\n", decoy.env.to_lowercase(), decoy.env);
      }
    }
    if !self.hostless.is_empty() {
      out.push_str(
        "#\n\
         # The registry knows these names but states no hosts: either the endpoint is\n\
         # per deployment (self-hosted control planes) or the value is a signing input\n\
         # that never reaches the wire (exchange API secrets — see\n\
         # https://github.com/casualjim/arkham/issues/19). Name the endpoint to use the\n\
         # key as a rule, or drop it from fnox to stop emitting a decoy:\n\
         #\n",
      );
      for decoy in &self.hostless {
        let _ = writeln!(
          out,
          "# [rules.{}]\n# env = \"{}\"\n# allow = [\"https://<your-host>\"]\n",
          decoy.env.to_lowercase(),
          decoy.env
        );
      }
    }
    if !self.unregistered.is_empty() {
      let _ = writeln!(
        out,
        "#\n# fnox declares these but no registry entry covers them, so nothing derives:\n# {}\n",
        self.unregistered.join(", ")
      );
    }
    out
  }
}

/// `arkham rules`: env-only rules for the secrets this workspace can get, plus
/// a note naming the fnox declarations no registry entry covers. One
/// `[rules.<label>]` block per env var fnox declares that the registry knows
/// how to swap; `arkham init` writes the same blocks into a fresh workspace
/// config.
///
/// `root` adds the workspace's own `rules.d` overrides, so the printed rules
/// match the ones generation derives decoys from.
///
/// # Errors
///
/// Returns an error when the registry or the fnox source cannot be opened.
pub fn rules_command(root: Option<&Path>) -> Result<String, Error> {
  Ok(Selection::load(root)?.report().render())
}

#[cfg(test)]
mod moved_suite {
  use std::path::PathBuf;

  use arkham_config::cli::ProxyBackend;

  use crate::decoys::*;

  use crate::paths::*;

  use crate::test_support::*;

  #[test]
  fn rules_toml_prints_derived_rules_as_blocks() {
    let toml = Report {
      active: decoys(),
      hostless: Vec::new(),
      unregistered: Vec::new(),
    }
    .render();
    assert!(toml.contains("[rules.github_token]\nenv = \"GITHUB_TOKEN\""), "{toml}");
    assert!(toml.contains("[rules.anthropic_api_key]\nenv = \"ANTHROPIC_API_KEY\""), "{toml}");
    assert!(!toml.contains("value ="), "{toml}");
  }

  #[test]
  fn grants_layer_mounts_at_the_standard_config_path() {
    let mut stack = test_stack(ProxyBackend::Ebpf);
    stack.grants_mounts = vec![Mount {
      host: Path::new("/state/arkham/ws/arkham/grants").to_path_buf(),
      container: PathBuf::from("/arkham/grants"),
      ro: true,
    }];
    let yaml = stack.render();
    assert!(yaml.contains("- /state/arkham/ws/arkham/grants:/arkham/grants:ro"), "{yaml}");
    assert!(
      yaml.contains("- /state/arkham/ws/arkham/grants/arkham.toml:/root/.config/arkham/config.toml:ro"),
      "the grant layer must BE the global config so rules.d resolves beside it: {yaml}"
    );
    assert!(!yaml.contains("ARKHAM_CONFIG"), "{yaml}");
  }

  #[test]
  fn names_the_registry_states_no_hosts_for_split_out_of_the_active_rules() {
    let selection = Selection {
      fnox: None,
      registry: generation_registry(None).unwrap(),
    };
    let decoys = vec![
      Decoy {
        env: "GITHUB_TOKEN".to_string(),
        value: "decoy".to_string(),
      },
      Decoy {
        env: "VAULT_TOKEN".to_string(),
        value: "decoy".to_string(),
      },
    ];
    let (with_hosts, hostless) = selection.split_by_hosts(decoys);
    assert_eq!(with_hosts.len(), 1);
    assert_eq!(with_hosts[0].env, "GITHUB_TOKEN");
    assert_eq!(hostless.len(), 1);
    assert_eq!(hostless[0].env, "VAULT_TOKEN");
  }

  #[test]
  fn rules_toml_comments_out_names_the_registry_knows_without_hosts() {
    let hostless = vec![Decoy {
      env: "ARGO_CD_TOKEN".to_string(),
      value: "decoy".to_string(),
    }];
    let toml = Report {
      active: decoys(),
      hostless,
      unregistered: vec!["TAVILY_API_KEY".to_string()],
    }
    .render();
    assert!(toml.contains("# [rules.argo_cd_token]"), "{toml}");
    assert!(toml.contains("# env = \"ARGO_CD_TOKEN\""), "{toml}");
    assert!(toml.contains("# allow = [\"https://<your-host>\"]"), "{toml}");
    assert!(toml.contains("# TAVILY_API_KEY"), "{toml}");
  }

  #[test]
  fn generated_decoys_follow_the_rule_pattern() {
    let registry = arkham_config::registry::Registry::load(None).unwrap();
    let default = registry.decoy("ANTHROPIC_API_KEY", None);
    let rule: arkham_config::config::RuleCfg =
      toml_edit::de::from_str("env = \"ANTHROPIC_API_KEY\"\npattern = \"sk-ant-api03-{hex:8}\"\n").unwrap();
    let rules = BTreeMap::from([("anthropic".to_string(), rule)]);

    let selection = Selection { fnox: None, registry };
    let shaped = selection.apply_rule_patterns(
      vec![Decoy {
        env: "ANTHROPIC_API_KEY".to_string(),
        value: default.clone(),
      }],
      &rules,
    );

    assert_eq!(
      shaped[0].value,
      selection.registry.decoy("ANTHROPIC_API_KEY", Some("sk-ant-api03-{hex:8}"))
    );
    assert_ne!(shaped[0].value, default);
  }
}
