//! Workspace confinement: `arkham rules` prints env-only rules for the
//! fnox-declared names the registry knows; `arkham init` generates the
//! workspace stack once as an editable file; `arkham up`/`down`/`logs` drive
//! the layered compose project; `arkham agent` runs that whole sequence
//! in one go.

mod adapt;
mod ambient;
mod confine;
mod decoys;
mod error;
mod expand;
mod expose;
mod git;
mod jj;
mod kube;
mod mounts;
mod nats;
mod paths;
mod profiles;
mod rewrites;
mod ssh;
mod stack;
mod talos;
mod workspace;

pub use confine::{AgentArgs, DownArgs, InitArgs, LogsArgs, UpArgs};
pub use decoys::rules_command;
pub use error::Error;
pub use expose::ExposeArgs;

#[cfg(test)]
mod tests {
  use std::collections::BTreeMap;
  use std::ffi::OsString;
  use std::fs;
  use std::path::{Path, PathBuf};
  use std::slice::from_ref;

  use arkham_config::cli::{Cli, ProxyBackend};
  use arkham_config::config::{ExposeMap, FileRewrite, RewriteFormat, RuleCfg, ToolCfg, WorkspaceBuild, fake_for};
  use tempfile::tempdir;

  use crate::ambient::*;
  use crate::confine::*;
  use crate::decoys::*;
  use crate::expand::*;
  use crate::mounts::*;
  use crate::paths::*;
  use crate::profiles::*;
  use crate::rewrites::*;
  use crate::stack::*;
  use crate::workspace::*;

  fn decoys() -> Vec<Decoy> {
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

  fn mount(host: &str, container: &str, ro: bool) -> Mount {
    Mount {
      host: PathBuf::from(host),
      container: PathBuf::from(container),
      ro,
    }
  }

  /// Test agent spec: `root` inside the container, home `/home/eng`, and the
  /// workspace-state storage directory the agent service mounts.
  fn agent_paths(root: &str) -> AgentSpec {
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
  const TEST_VERSION: &str = "0.0.0-test";
  /// A default-ish stack to render in tests; override fields struct-update style.
  fn test_stack(backend: ProxyBackend) -> Stack {
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
  fn set_env(key: &str, value: impl AsRef<std::ffi::OsStr>) {
    // SAFETY: test-only mutation, and nextest runs one test per process.
    unsafe { std::env::set_var(key, value) };
  }

  fn unset_env(key: &str) {
    // SAFETY: test-only mutation, and nextest runs one test per process.
    unsafe { std::env::remove_var(key) };
  }

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
  fn under_home_paths_translate_into_the_container_home() {
    let host_home = Path::new("/home/ivan");
    assert_eq!(
      translate(Path::new("/home/ivan/github/arkham"), Some(host_home), "/home/eng"),
      PathBuf::from("/home/eng/github/arkham")
    );
    assert_eq!(translate(Path::new("/data"), Some(host_home), "/home/eng"), PathBuf::from("/data"));
    assert_eq!(
      translate(Path::new("/home/ivan"), Some(host_home), "/home/eng"),
      PathBuf::from("/home/eng")
    );
  }

  #[test]
  fn covering_mounts_absorb_overlaps() {
    let mounts = vec![
      mount("/home/ivan/github/arkham", "/home/eng/github/arkham", false),
      mount("/home/ivan/github", "/home/eng/github", false),
      mount("/home/ivan/.config/mise", "/home/eng/.config/mise", true),
      mount("/opt/data", "/opt/data", false),
    ];
    let kept = covering(mounts);
    let hosts: Vec<String> = kept.iter().map(|m| m.host.display().to_string()).collect();
    assert_eq!(hosts, vec!["/home/ivan/github", "/home/ivan/.config/mise", "/opt/data"], "{kept:?}");
    assert!(kept[1].ro, "the surviving mount keeps its own mode");
  }

  #[test]
  fn include_entries_split_their_mount_mode() {
    assert_eq!(split_mode(Path::new("~/.config/mise:ro")), (PathBuf::from("~/.config/mise"), true));
    assert_eq!(split_mode(Path::new("/data/cache:rw")), (PathBuf::from("/data/cache"), false));
    assert_eq!(split_mode(Path::new("/data/cache")), (PathBuf::from("/data/cache"), false));
  }

  #[test]
  fn tilde_and_relative_includes_expand_against_root_and_home() {
    let root = Path::new("/home/ivan/github/arkham");
    let host_home = Some(Path::new("/home/ivan"));
    assert_eq!(
      expand(Path::new("~/.config/mise"), root, host_home),
      PathBuf::from("/home/ivan/.config/mise")
    );
    assert_eq!(
      expand(Path::new("../sibling"), root, host_home),
      PathBuf::from("/home/ivan/github/sibling")
    );
    assert_eq!(expand(Path::new("/opt/data"), root, host_home), PathBuf::from("/opt/data"));
  }

  /// Roots over a temp global config dir: the profiles dir plus the config
  /// dir holding the profiles tree.
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

    let yaml = Stack {
      agent: agent_paths("/home/eng/github/arkham"),
      tool_mounts: mounts.clone(),
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(
      yaml.contains(&format!("- {}:/home/eng/.pi:rw", shared.join("pi").display())),
      "{yaml}"
    );
    assert!(!yaml.contains("not-a-tool"), "{yaml}");
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

  #[test]
  fn the_agent_service_carries_what_inner_containers_need() {
    let yaml = test_stack(ProxyBackend::Tproxy).render();
    for expected in [
      "image: ghcr.io/casualjim/devagent:26.04",
      "security_opt: [seccomp=unconfined, systempaths=unconfined, apparmor=unconfined]",
      "cap_add: [SYS_CHROOT, AUDIT_WRITE, NET_ADMIN, SETUID, SETGID, SYS_ADMIN]",
      "devices: [/dev/net/tun]",
      "user: \"1000\"",
      "- /state/arkham/ws/arkham/containers:/home/eng/.local/share/containers",
    ] {
      assert!(yaml.contains(expected), "missing {expected}:\n{yaml}");
    }
    // The agent runs its own runtime; it never reaches the host's.
    assert!(!yaml.contains("docker.sock") && !yaml.contains("/var/run/docker"), "{yaml}");
  }
  #[test]
  fn render_keeps_comments_at_their_key_indent() {
    let yaml = test_stack(ProxyBackend::Ebpf).render();
    for expected in [
      "    # Capture dies with this process: the eBPF attachments are fd-held\n    # and the listeners live in it",
      "    restart: unless-stopped",
      "# (global layer plus this workspace's .config/arkham/config.toml, discovered\n# from its working directory",
    ] {
      assert!(yaml.contains(expected), "{yaml}");
    }
    assert!(!yaml.contains("\n          #") && !yaml.contains("\n       # "), "{yaml}");
  }
  #[test]
  fn workspace_image_overrides_the_agent_image() {
    let mut stack = test_stack(ProxyBackend::Tproxy);
    stack.agent.image = "ghcr.io/example/devenv:1.0".to_string();
    let yaml = stack.render();
    assert!(yaml.contains("image: ghcr.io/example/devenv:1.0"), "{yaml}");
    assert!(!yaml.contains(DEFAULT_AGENT_IMAGE), "{yaml}");
  }

  #[test]
  fn agent_build_renders_context_and_dockerfile() {
    let mut stack = test_stack(ProxyBackend::Tproxy);
    let build = AgentBuild {
      context: PathBuf::from("/ws/docker"),
      dockerfile: PathBuf::from("/ws/docker/Dockerfile.agent"),
    };
    stack.agent.build = Some(build);
    let yaml = stack.render();
    assert!(
      yaml.contains("build:\n      context: /ws/docker\n      dockerfile: /ws/docker/Dockerfile.agent"),
      "{yaml}"
    );
  }

  #[test]
  fn default_agent_service_has_no_build_section() {
    let yaml = test_stack(ProxyBackend::Tproxy).render();
    assert!(!yaml.contains("\n    build:\n"), "{yaml}");
  }

  #[test]
  fn agent_image_resolution_prefers_config_then_build_then_default() {
    assert_eq!(
      AgentSpec::image("arkham", Some("ghcr.io/example/devenv:1.0"), false).unwrap(),
      "ghcr.io/example/devenv:1.0"
    );
    assert_eq!(AgentSpec::image("arkham", None, false).unwrap(), DEFAULT_AGENT_IMAGE);
    assert_eq!(AgentSpec::image("arkham", None, true).unwrap(), "arkham-agent-arkham:local");
    AgentSpec::image("arkham", Some(""), false).unwrap_err();
  }

  #[test]
  fn agent_build_resolution_rejects_missing_inputs() {
    let dir = tempdir().unwrap();
    let build = WorkspaceBuild {
      dockerfile: PathBuf::from("docker/Dockerfile.agent"),
      context: PathBuf::from("docker"),
    };
    let layout = Layout::new(dir.path(), String::new(), None);
    let err = layout.resolve_build(&build).unwrap_err();
    assert!(err.to_string().contains("dockerfile"), "{err:?}");
    let docker = dir.path().join("docker");
    fs::create_dir(&docker).unwrap();
    fs::write(docker.join("Dockerfile.agent"), "FROM scratch\n").unwrap();
    let (context, dockerfile) = layout.resolve_build(&build).unwrap();
    assert_eq!(context, docker);
    assert_eq!(dockerfile, docker.join("Dockerfile.agent"));
    fs::remove_dir_all(&docker).unwrap();
    fs::write(dir.path().join("Dockerfile.agent"), "FROM scratch\n").unwrap();
    let lone = WorkspaceBuild {
      dockerfile: PathBuf::from("Dockerfile.agent"),
      context: PathBuf::from("docker"),
    };
    let err = layout.resolve_build(&lone).unwrap_err();
    assert!(err.to_string().contains("context"), "{err:?}");
  }

  #[test]
  fn workspace_devices_and_caps_append_to_the_agent_builtin_set() {
    let mut stack = test_stack(ProxyBackend::Tproxy);
    stack.agent.devices = vec!["/dev/kvm".to_string()];
    stack.agent.cap_add = vec!["SYS_PTRACE".to_string()];
    let yaml = stack.render();
    assert!(yaml.contains("devices: [/dev/net/tun, /dev/kvm]"), "{yaml}");
    assert!(
      yaml.contains("cap_add: [SYS_CHROOT, AUDIT_WRITE, NET_ADMIN, SETUID, SETGID, SYS_ADMIN, SYS_PTRACE]"),
      "{yaml}"
    );
  }

  #[test]
  fn compose_yaml_indents_every_mapping_key_under_its_parent() {
    // The generated stack is parsed by docker's YAML loader, so a key at the
    // wrong depth is a hard failure, not a cosmetic one. In these literals a
    // `\`-continued line drops its leading whitespace while the first line
    // keeps it.
    let yaml = test_stack(ProxyBackend::Tproxy).render();
    for expected in [
      "\n    cap_add:\n      - NET_ADMIN\n",
      "\n    stop_grace_period: 1s\n",
      "\n    volumes:\n",
      "\n  agent:\n",
      "\n  arkham:\n",
      "\nservices:\n",
    ] {
      assert!(yaml.contains(expected), "missing {expected:?}:\n{yaml}");
    }
  }

  #[test]
  fn compose_yaml_mounts_the_workspace_at_its_translated_path() {
    let mounts = vec![
      mount("/home/ivan/github/arkham", "/home/eng/github/arkham", false),
      mount("/home/ivan/.config/mise", "/home/eng/.config/mise", true),
    ];
    let yaml = Stack {
      agent: agent_paths("/home/eng/github/arkham"),
      mounts: mounts.clone(),
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(yaml.contains("name: arkham\nservices:"), "{yaml}");
    assert!(yaml.contains("working_dir: \"/home/eng/github/arkham\""), "{yaml}");
    assert!(yaml.contains("- /home/ivan/github/arkham:/home/eng/github/arkham:rw"), "{yaml}");
    assert!(yaml.contains("- /home/ivan/.config/mise:/home/eng/.config/mise:ro"), "{yaml}");
    assert!(
      yaml.contains("entrypoint: [\"/home/eng/.config/arkham/agent-entrypoint.sh\"]"),
      "the entrypoint is the in-container path: {yaml}"
    );
    assert!(
      yaml.contains(":/home/eng/.config/arkham/agent-entrypoint.sh:ro"),
      "mounted where the entrypoint names it: {yaml}"
    );
    assert!(yaml.contains("network_mode: \"service:arkham\""), "{yaml}");
    assert!(yaml.contains(":/certs/ca.pem"), "the CA is mounted for arkham: {yaml}");
    assert!(!yaml.contains("/root/.config/fnox"), "no fnox mount without binds to mount: {yaml}");
    assert!(yaml.contains("init: true"), "{yaml}");
    assert!(yaml.contains(&format!("GITHUB_TOKEN: \"{}\"", decoys()[0].value)), "{yaml}");
  }

  #[test]
  fn slug_uses_path_segments() {
    assert_eq!(slug(Path::new("/home/ivan/github/arkham")), "home-ivan-github-arkham");
    assert_eq!(slug(Path::new("/srv/My_Project")), "srv-my-project");
  }

  #[test]
  fn the_example_workspace_loads_and_inherits_registry_hosts() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/agentic-devenv/.config/arkham/config.toml");
    let cli = Cli {
      config: Some(example.clone()),
    };
    let (config, _) = arkham_config::config::load(&cli, None).unwrap_or_else(|err| panic!("{} does not load: {err}", example.display()));
    assert_eq!(config.workspace.home.as_deref(), Some("/home/eng"));
    assert_eq!(config.workspace.shell.as_deref(), Some("bash"));
    let registry = generation_registry(None).unwrap();
    for (label, env) in [("anthropic", "ANTHROPIC_API_KEY"), ("github", "GH_TOKEN")] {
      let rule = config
        .rules
        .get(label)
        .unwrap_or_else(|| panic!("`{label}` missing from {}", example.display()));
      assert_eq!(rule.env, env);
      assert!(rule.value.is_none(), "`{label}` must resolve from fnox, not carry a value");
      assert!(!registry.hosts_for(rule).is_empty(), "`{label}` needs hosts from the registry");
    }
  }

  #[test]
  fn includes_absorb_overlaps_and_reject_missing() {
    let host_home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let sibling = root.path().join("sibling");
    std::fs::create_dir_all(&sibling).unwrap();

    let layout = Layout::new(root.path(), "/home/eng".to_string(), Some(host_home.path().to_path_buf()));
    let mounts = layout.include_mounts(&[PathBuf::from("sibling:ro")]).unwrap();
    assert_eq!(mounts.len(), 1, "{mounts:?}");
    assert_eq!(mounts[0].host, root.path(), "{mounts:?}");
    assert!(!mounts[0].ro, "{mounts:?}");

    let err = layout.include_mounts(&[PathBuf::from("missing")]).unwrap_err();
    assert!(err.to_string().contains("does not exist"), "{err:?}");
    assert!(err.to_string().contains("missing"), "{err:?}");
  }

  #[test]
  fn fnox_binds_mount_only_what_exists_and_forward_present_credentials() {
    let home = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let fnox_dir = home.path().join(".config").join("fnox");
    std::fs::create_dir_all(&fnox_dir).unwrap();
    std::fs::write(fnox_dir.join("age.txt"), "AGE-SECRET-KEY-1\n").unwrap();
    std::fs::write(
      config_dir.path().join("fnox.toml"),
      "[secrets.X]\nprovider = \"plain\"\nvalue = \"x\"\n",
    )
    .unwrap();
    std::fs::write(config_dir.path().join("config.toml"), "[proxy]\n").unwrap();

    let binds = FnoxBinds::resolve(Some(&fnox_dir), Some(config_dir.path()));
    let rendered: Vec<String> = binds
      .mounts
      .iter()
      .map(|entry| format!("{}:{}:ro", entry.host.display(), entry.container.display()))
      .collect();
    assert_eq!(
      rendered,
      vec![
        format!("{}:/root/.config/fnox:ro", fnox_dir.display()),
        format!(
          "{}:/root/.config/arkham/fnox.toml:ro",
          config_dir.path().join("fnox.toml").display()
        ),
      ],
      "the fnox config directory and arkham's own fnox level, and not the host's arkham config.toml"
    );

    let empty = tempfile::tempdir().unwrap();
    assert!(
      FnoxBinds::resolve(Some(&empty.path().join("missing")), Some(empty.path()))
        .mounts
        .is_empty(),
      "a path that is not there is never mounted: docker would create a directory in its place"
    );

    // Credentials in the shell are not the proxy's business: whatever the
    // environment carries, the generated stack forwards nothing.
    let key = "BWS_ACCESS_TOKEN";
    let previous = std::env::var_os(key);
    set_env(key, "0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let yaml = Stack {
      fnox: FnoxBinds::resolve(None, None),
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(!yaml.contains("${"), "no environment interpolation survives generation: {yaml}");
    assert!(!yaml.contains(key), "the credential name is not forwarded either: {yaml}");
    assert!(
      !yaml.contains("0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
      "the value must not be written"
    );
    match previous {
      Some(value) => set_env(key, value),
      None => unset_env(key),
    }
  }

  #[test]
  fn rules_d_overrides_mount_into_the_arkham_service() {
    let config_dir = tempfile::tempdir().unwrap();
    let rules_d = config_dir.path().join("rules.d");
    std::fs::create_dir_all(&rules_d).unwrap();
    std::fs::write(
      rules_d.join("gitea.toml"),
      "[names.GITEA_TOKEN]\nhosts = [\"https://code.lotsa.ai\"]\n",
    )
    .unwrap();

    let binds = FnoxBinds::resolve(None, Some(config_dir.path()));
    let rendered: Vec<String> = binds
      .mounts
      .iter()
      .map(|entry| format!("{}:{}:ro", entry.host.display(), entry.container.display()))
      .collect();
    assert_eq!(
      rendered,
      vec![format!("{}:/root/.config/arkham/rules.d:ro", rules_d.display())],
      "serve derives rules from the registry in-container, so the global rules.d must be in view"
    );
  }

  #[test]
  fn support_files_are_written_when_absent_and_stale_entrypoints_regenerate() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let entrypoint = dir.path().join("agent-entrypoint.sh");
    let storage = dir.path().join("state").join("containers");

    let files = ensure_support_files(dir.path(), &storage).unwrap();
    assert!(files.iter().all(|(_, created)| *created), "{files:?}");
    let pem = std::fs::read_to_string(dir.path().join("ca.pem")).unwrap();
    let crt = std::fs::read_to_string(dir.path().join("ca.crt")).unwrap();
    let key = std::fs::read_to_string(dir.path().join("ca.key")).unwrap();
    assert!(entrypoint.is_file());
    assert!(storage.is_dir(), "storage belongs to the workspace state, not the config dir");
    assert!(
      !dir.path().join("agent-containers").exists(),
      "no storage under the config dir: {files:?}"
    );
    // `ca.pem` is what arkham reads; `ca.crt` is the certificate alone, which is
    // what the agent gets. A clean system needs both.
    assert!(
      pem.contains("BEGIN CERTIFICATE") && pem.contains("PRIVATE KEY"),
      "ca.pem carries both halves"
    );
    assert!(
      crt.contains("BEGIN CERTIFICATE") && !crt.contains("PRIVATE KEY"),
      "ca.crt carries the certificate only"
    );
    assert!(
      key.contains("PRIVATE KEY") && !key.contains("CERTIFICATE"),
      "ca.key carries the key only"
    );
    let script = std::fs::read_to_string(&entrypoint).unwrap();
    assert!(
      script.contains("update-ca-certificates"),
      "the entrypoint installs the CA into the system store"
    );
    assert!(
      script.contains("${ARKHAM_INIT:-}") && script.contains("docker-entrypoint.sh"),
      "the entrypoint chains to the image's init: ARKHAM_INIT first, common names next"
    );
    assert!(script.contains("exec \"$@\""), "the entrypoint hands off to the command");
    assert!(
      script.contains("${ARKHAM_EBPF_BYPASS_FILE:-}") && script.contains("podman network inspect"),
      "the entrypoint publishes podman subnets for arkham's bypass list when the stack wires the file"
    );
    assert_ne!(
      std::fs::metadata(&entrypoint).unwrap().permissions().mode() & 0o111,
      0,
      "the agent runs the entrypoint directly, so it must be executable"
    );

    std::fs::write(&entrypoint, "#!/bin/sh\necho mine\n").unwrap();
    std::fs::remove_file(dir.path().join("ca.pem")).unwrap();
    let files = ensure_support_files(dir.path(), &storage).unwrap();
    let created: BTreeMap<&str, bool> = files
      .iter()
      .map(|(path, created)| (path.file_name().unwrap().to_str().unwrap(), *created))
      .collect();
    assert_eq!(
      created.get("agent-entrypoint.sh"),
      Some(&false),
      "an edited entrypoint is replaced, not created anew"
    );
    assert_eq!(created.get("ca.pem"), Some(&true), "a deleted CA comes back");
    assert_eq!(
      std::fs::read_to_string(&entrypoint).unwrap(),
      ENTRYPOINT_SCRIPT,
      "a stale or edited entrypoint is regenerated"
    );
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

  #[test]
  fn each_backend_shapes_the_serve_command_and_its_host_wiring() {
    let render = |backend| test_stack(backend).render();

    let tproxy = render(ProxyBackend::Tproxy);
    assert!(tproxy.contains("command: [\"serve\", \"--proxy-backend\", \"tproxy\"]"), "{tproxy}");
    assert_eq!(
      tproxy.matches("/dev/net/tun").count(),
      1,
      "only the agent service asks for the tun device: {tproxy}"
    );
    assert!(!tproxy.contains("cgroup"), "{tproxy}");

    let tun = render(ProxyBackend::Tun);
    assert!(tun.contains("command: [\"serve\", \"--proxy-backend\", \"tun\"]"), "{tun}");
    assert_eq!(tun.matches("/dev/net/tun").count(), 2, "arkham needs the tun device too: {tun}");
    assert!(!tun.contains("--ebpf-cgroup"), "{tun}");

    let ebpf = render(ProxyBackend::Ebpf);
    assert!(
      ebpf.contains("command: [\"serve\", \"--proxy-backend\", \"ebpf\", \"--ebpf-cgroup\", \"enclosing\"]"),
      "{ebpf}"
    );
    for expected in ["    cgroup: host\n", "      - BPF\n      - PERFMON\n"] {
      assert!(ebpf.contains(expected), "missing {expected:?}:\n{ebpf}");
    }
    assert_eq!(
      ebpf.matches("    cgroup_parent: arkham-arkham.slice\n").count(),
      2,
      "both services carry the shared cgroup, so docker creates it as arkham starts: {ebpf}"
    );
    assert_eq!(ebpf.matches("/dev/net/tun").count(), 1, "ebpf needs no tun device: {ebpf}");
    assert_eq!(
      ebpf.matches("ARKHAM_EBPF_BYPASS_FILE: /arkham/ebpf-bypass\n").count(),
      2,
      "arkham reads and the agent writes the same shared bypass file: {ebpf}"
    );
    assert!(!tun.contains("ARKHAM_EBPF_BYPASS_FILE"), "{tun}");
    assert!(!tproxy.contains("ARKHAM_EBPF_BYPASS_FILE"), "{tproxy}");
  }

  #[test]
  fn the_bypass_mount_names_the_shared_state_file() {
    let mount = Layout::new(Path::new("/root"), String::new(), None).bypass_mount();
    assert_eq!(mount.container, Path::new("/arkham/ebpf-bypass"));
    assert!(
      mount.host.ends_with("ebpf-bypass"),
      "the host side is the per-workspace state file: {}",
      mount.host.display()
    );
    assert!(!mount.ro, "the agent entrypoint writes the file, so the shared mount is read-write");
  }

  #[test]
  fn workspace_init_names_the_agent_images_init_script() {
    let yaml = Stack {
      init: Some("/usr/local/bin/devagent-entrypoint".to_string()),
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(
      yaml.contains("      ARKHAM_INIT: \"/usr/local/bin/devagent-entrypoint\"\n"),
      "the entrypoint chains to the image's init through ARKHAM_INIT: {yaml}"
    );
  }

  #[test]
  fn the_backend_defaults_to_ebpf_on_linux_and_none_is_refused() {
    #[cfg(target_os = "linux")]
    assert_eq!(resolve_backend(None).unwrap(), ProxyBackend::Ebpf);
    #[cfg(not(target_os = "linux"))]
    assert!(resolve_backend(None).is_err(), "no capture backend exists outside Linux");

    assert_eq!(resolve_backend(Some(ProxyBackend::Tun)).unwrap(), ProxyBackend::Tun);
    let err = resolve_backend(Some(ProxyBackend::None)).unwrap_err();
    assert!(err.to_string().contains("none"), "{err:?}");
  }

  /// `init` writes the workspace config once and never overwrites it: a stack
  /// that cannot substitute anything is worse than no stack, and an edited
  /// rules file is the user's.
  #[test]
  fn the_workspace_config_is_written_once_and_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".config").join("arkham.toml");

    assert!(write_if_absent(&path, "[rules.x]\n").unwrap(), "first write lands");
    assert!(
      !write_if_absent(&path, "something else\n").unwrap(),
      "an existing file is left alone"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "[rules.x]\n");
  }

  /// Regeneration keys off the workspace config: a stack generated before a
  /// rule existed holds decoys that can never be swapped, and a stack with no
  /// digest beside it predates the check.
  #[test]
  fn the_stack_is_stale_until_its_digest_matches_the_workspace_config() {
    let root = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let config = root.path().join(".config");
    std::fs::create_dir_all(config.join("arkham")).unwrap();

    assert!(
      stack_is_stale(state.path(), root.path()),
      "no digest means the stack predates the check"
    );
    std::fs::write(state.path().join("config.digest"), config_digest(root.path()).to_string()).unwrap();
    assert!(!stack_is_stale(state.path(), root.path()), "an untouched config keeps the stack");

    std::fs::write(config.join("arkham").join("config.toml"), "[rules.x]\nenv = \"X\"\n").unwrap();
    assert!(
      stack_is_stale(state.path(), root.path()),
      "a config that appeared after generation is a change"
    );
    std::fs::write(state.path().join("config.digest"), config_digest(root.path()).to_string()).unwrap();
    assert!(!stack_is_stale(state.path(), root.path()));
  }

  /// Generation reads the `rules.d` override trees on both layers, so an
  /// edit there changes the derived decoys and must regenerate the stack.
  #[test]
  fn the_stack_is_stale_when_the_rules_overrides_change() {
    let root = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let global = tempfile::tempdir().unwrap();
    set_env("XDG_CONFIG_HOME", global.path());
    let global_rules = global.path().join("arkham").join("rules.d");
    let project_rules = root.path().join(".config").join("arkham").join("rules.d");

    std::fs::write(state.path().join("config.digest"), config_digest(root.path()).to_string()).unwrap();
    assert!(!stack_is_stale(state.path(), root.path()), "absent rules trees are stable");

    std::fs::create_dir_all(&project_rules).unwrap();
    std::fs::write(
      project_rules.join("10-late.toml"),
      "[names.LATE_TOKEN]\nhosts = [\"https://late.example\"]\n",
    )
    .unwrap();
    assert!(
      stack_is_stale(state.path(), root.path()),
      "a project rules.d file that appeared after generation is a change"
    );
    std::fs::write(state.path().join("config.digest"), config_digest(root.path()).to_string()).unwrap();
    assert!(!stack_is_stale(state.path(), root.path()));

    std::fs::create_dir_all(&global_rules).unwrap();
    std::fs::write(
      global_rules.join("10-glob.toml"),
      "[names.GLOB_TOKEN]\nhosts = [\"https://glob.example\"]\n",
    )
    .unwrap();
    assert!(
      stack_is_stale(state.path(), root.path()),
      "a global rules.d file that appeared after generation is a change"
    );
    unset_env("XDG_CONFIG_HOME");
  }

  /// Generation reads the global layer too, so an edit there — where `[workspace]`
  /// settings like `init` live — must regenerate the stack, not just workspace edits.
  #[test]
  fn the_stack_is_stale_when_the_global_config_changes() {
    let root = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let global = tempfile::tempdir().unwrap();
    set_env("XDG_CONFIG_HOME", global.path());
    let arkham_dir = global.path().join("arkham");
    std::fs::create_dir_all(&arkham_dir).unwrap();

    std::fs::write(state.path().join("config.digest"), config_digest(root.path()).to_string()).unwrap();
    assert!(!stack_is_stale(state.path(), root.path()), "absent global layer is stable");

    std::fs::write(arkham_dir.join("config.toml"), "[workspace]\ninit = \"/init\"\n").unwrap();
    assert!(
      stack_is_stale(state.path(), root.path()),
      "a global config that appeared after generation is a change"
    );
    std::fs::write(state.path().join("config.digest"), config_digest(root.path()).to_string()).unwrap();
    assert!(!stack_is_stale(state.path(), root.path()));

    std::fs::write(arkham_dir.join("config.toml"), "[workspace]\ninit = \"/init2\"\n").unwrap();
    assert!(stack_is_stale(state.path(), root.path()), "a global config edit is a change");
    unset_env("XDG_CONFIG_HOME");
  }

  /// A digest that matches can only be made stale by the shape: an older
  /// shape — or none at all, which is every stack generated before the
  /// marker existed — regenerates, so the bundled `arkham agent` cannot leave
  /// an old wiring behind.
  #[test]
  fn a_stack_of_an_older_shape_is_stale() {
    assert_eq!(stack_shape_in("# stack shape: 2\nservices:\n"), Some(2));
    assert_eq!(stack_shape_in("services:\n"), None, "a pre-marker stack carries no shape");
    assert_eq!(stack_shape_in("# stack shape: nope\n"), None);

    let root = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    std::fs::write(state.path().join("config.digest"), config_digest(root.path()).to_string()).unwrap();

    std::fs::write(
      state.path().join("compose.yml"),
      format!("# stack shape: {STACK_SHAPE}\nname: arkham\n"),
    )
    .unwrap();
    assert!(
      !stack_is_stale(state.path(), root.path()),
      "current shape and matching digest keep the stack"
    );

    std::fs::write(state.path().join("compose.yml"), "# stack shape: 1\nname: arkham\n").unwrap();
    assert!(stack_is_stale(state.path(), root.path()), "an older shape regenerates");

    std::fs::write(state.path().join("compose.yml"), "name: arkham\n").unwrap();
    assert!(stack_is_stale(state.path(), root.path()), "a pre-marker stack regenerates");
  }

  /// A regeneration must not switch how traffic is captured: the backend is
  /// read back off the compose file, and the caller's default is only a
  /// fallback.
  #[test]
  fn the_generated_stack_reports_its_backend() {
    assert_eq!(
      generated_backend("      command: [\"serve\", \"--proxy-backend\", \"tun\"]\n"),
      Some(ProxyBackend::Tun)
    );
    assert_eq!(generated_backend("\"--proxy-backend\", \"ebpf\""), Some(ProxyBackend::Ebpf));
    assert_eq!(generated_backend("\"--proxy-backend\", \"tproxy\""), Some(ProxyBackend::Tproxy));
    assert_eq!(
      generated_backend("command: [\"serve\"]\n"),
      None,
      "a stack that names no backend keeps the caller's"
    );
  }

  /// Zero rules with nothing derivable answers every provider with a decoy:
  /// it has to be said out loud rather than served silently. A derivable
  /// name substitutes on its own, so it silences the warning.
  #[test]
  fn serving_no_rules_and_nothing_derivable_is_announced() {
    let warning = rules_warning(&BTreeMap::new(), &[]).expect("no rules and nothing derivable is worth a warning");
    assert!(warning.contains("no [rules.*]") && warning.contains("nothing derives"), "{warning}");

    let rules = BTreeMap::from([(
      "github".to_string(),
      toml_edit::de::from_str::<RuleCfg>("env = \"GH_TOKEN\"\n").unwrap(),
    )]);
    assert!(rules_warning(&rules, &[]).is_none(), "one rule is enough not to warn");
    assert!(
      rules_warning(&BTreeMap::new(), &["GITEA_TOKEN".to_string()]).is_none(),
      "a derivable name substitutes without any config rule"
    );
  }

  #[test]
  fn workspace_ports_render_as_stable_host_bindings() {
    let yaml = Stack {
      ports: vec![3000, 5432],
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    let arkham_block = &yaml[..yaml.find("\n  agent:\n").unwrap()];
    assert!(
      arkham_block.contains("    ports:\n"),
      "ports belong to the arkham service: {arkham_block}"
    );
    for port in [3000, 5432] {
      assert!(
        arkham_block.contains(&format!("      - \"127.0.0.1:{port}:{port}\"\n")),
        "{arkham_block}"
      );
    }
    assert!(
      !arkham_block.contains("15000"),
      "the capture listener port is not published: {arkham_block}"
    );
    assert_eq!(
      arkham_block.matches("      - \"127.0.0.1:").count(),
      2,
      "exactly the declared ports, nothing else: {arkham_block}"
    );
    let empty = test_stack(ProxyBackend::Tproxy).render();
    assert!(!empty.contains("ports:"), "no ports key without declared ports: {empty}");
  }

  #[test]
  fn workspace_networks_extra_hosts_and_expose_render() {
    let yaml = Stack {
      ports: vec![3000],
      expose: vec![ExposeMap { port: 5173, host: 5174 }],
      networks: vec!["headroom_default".to_string()],
      extra_hosts: vec!["host.docker.internal:host-gateway".to_string()],
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    let arkham_block = &yaml[..yaml.find("\n  agent:\n").unwrap()];
    assert!(
      arkham_block.contains("      - \"127.0.0.1:3000:3000\"\n"),
      "symmetric ports keep rendering: {arkham_block}"
    );
    assert!(
      arkham_block.contains("      - \"127.0.0.1:5174:5173\"\n"),
      "expose maps host onto container port: {arkham_block}"
    );
    assert!(
      arkham_block.contains("    extra_hosts:\n      - \"host.docker.internal:host-gateway\"\n"),
      "arkham carries the hosts entry: {arkham_block}"
    );
    assert_eq!(
      arkham_block.matches("host.docker.internal").count(),
      1,
      "a stated gateway is not repeated beside the automatic one: {arkham_block}"
    );
    assert!(
      arkham_block.contains("    networks:\n      - \"headroom_default\"\n"),
      "arkham joins the named network: {arkham_block}"
    );
    assert!(
      yaml.contains("networks:\n  \"headroom_default\":\n    external: true\n"),
      "joined networks are declared external at the top level: {yaml}"
    );
    let agent_block = &yaml[yaml.find("\n  agent:\n").unwrap()..yaml.find("\n  fwd:\n").unwrap()];
    assert!(
      !agent_block.contains("extra_hosts:"),
      "the daemon rejects host mappings on a `network_mode` service: {agent_block}"
    );
    assert!(
      !agent_block.contains("networks:"),
      "a `network_mode` service takes no networks key: {agent_block}"
    );
    let empty = test_stack(ProxyBackend::Tproxy).render();
    let empty_arkham = &empty[..empty.find("\n  agent:\n").unwrap()];
    let empty_agent = &empty[empty.find("\n  agent:\n").unwrap()..empty.find("\n  fwd:\n").unwrap()];
    assert!(
      empty_arkham.contains("    extra_hosts:\n      - \"host.docker.internal:host-gateway\"\n"),
      "arkham always carries the gateway: {empty_arkham}"
    );
    assert!(
      !empty_agent.contains("extra_hosts:"),
      "the agent never carries host mappings: {empty_agent}"
    );
    assert!(!empty.contains("external: true"), "no networks block without joins: {empty}");
  }

  #[test]
  fn the_generated_stack_renders_the_sidecar_and_moves_the_explicit_proxy_off_8080() {
    let yaml = test_stack(ProxyBackend::Tproxy).render();
    assert!(
      yaml.starts_with(&format!("# stack shape: {STACK_SHAPE}\n")),
      "the shape marker leads the generated file, so staleness can see it: {yaml}"
    );
    for expected in [
      "  fwd:\n",
      "    command: [\"fwd\"]\n",
      "    network_mode: \"service:arkham\"\n",
      "    pid: \"service:agent\"\n",
    ] {
      assert!(yaml.contains(expected), "missing {expected:?}:\n{yaml}");
    }
    assert_eq!(
      yaml
        .matches(&format!("    image: ghcr.io/casualjim/arkham:{TEST_VERSION}\n"))
        .count(),
      2,
      "arkham and fwd services both pin the threaded version:\n{yaml}"
    );
    // One service key each: a duplicated key is a compose parse error, not a
    // cosmetic slip.
    for service in ["arkham", "agent", "fwd"] {
      assert_eq!(
        yaml.matches(&format!("\n  {service}:\n")).count(),
        1,
        "service `{service}` must be defined exactly once:\n{yaml}"
      );
    }
    assert!(
      yaml.contains(&format!("ARKHAM_LISTEN: {EXPLICIT_LISTEN}")),
      "the explicit proxy must not hold the common dev-server port:\n{yaml}"
    );
    assert!(!yaml.contains("ARKHAM_LISTEN: 127.0.0.1:8080"), "{yaml}");
    // The sidecar shares the agent's PID namespace, never arkham's.
    assert!(!yaml.contains("pid: \"service:arkham\""), "{yaml}");
    // Only the agent and arkham get cgroup placement; the sidecar must stay
    // outside the captured subtree so its own relays are never rewritten.
    let fwd_block = &yaml[yaml.find("\n  fwd:\n").unwrap()..];
    assert!(!fwd_block.contains("cgroup"), "the sidecar is not captured: {fwd_block}");
  }

  /// The flags map one-to-one onto compose's and services ride at the end: a
  /// wrong order here is a silently different log view, not an error.
  #[test]
  fn the_logs_command_maps_onto_compose_flags() {
    let bare = logs_argv(&LogsArgs {
      workspace: None,
      follow: false,
      no_log_prefix: false,
      tail: "all".into(),
      services: Vec::new(),
    });
    assert_eq!(bare, vec![OsString::from("logs"), OsString::from("--tail"), OsString::from("all")]);

    let full = logs_argv(&LogsArgs {
      workspace: Some(PathBuf::from("/srv/project")),
      follow: true,
      no_log_prefix: true,
      tail: "10".into(),
      services: vec!["arkham".into(), "agent".into()],
    });
    assert_eq!(
      full,
      ["logs", "--follow", "--no-log-prefix", "--tail", "10", "arkham", "agent"]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>()
    );
  }

  /// Passthrough renders doubled so compose leaves a literal `${NAME}` for
  /// the agent; file mounts ride read-only right after workspace mounts.
  #[test]
  fn passthrough_renders_interpolated_and_file_mounts_follow_workspace_mounts() {
    let yaml = Stack {
      passthrough: vec!["WAYLAND_DISPLAY".to_string()],
      mounts: vec![mount("/srv/ws", "/home/eng/ws", false)],
      file_mounts: vec![mount("/state/files/00-npmrc", "/home/eng/.npmrc", true)],
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(yaml.contains("      WAYLAND_DISPLAY: \"${WAYLAND_DISPLAY}\"\n"), "{yaml}");
    let agent = &yaml[yaml.find("\n  agent:\n").unwrap()..];
    let workspace_at = agent.find("/srv/ws:/home/eng/ws:rw").unwrap();
    let file_at = agent.find("/state/files/00-npmrc:/home/eng/.npmrc:ro").unwrap();
    assert!(workspace_at < file_at, "rewrites overlay workspace mounts: {agent}");
  }

  /// Sources rewrite reals to decoys on disk and mount read-only at the
  /// `{home}`-expanded dest; unknown names fail naming the name.
  #[test]
  fn file_rewrites_swap_reals_for_decoys_on_disk() {
    use std::collections::HashMap;

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
      kube_ca: None,
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
      kube_ca: None,
      guests_dir: dir.path(),
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("UNKNOWN_NAME"), "{error}");
  }

  const KUBE_DOC: &str = r"apiVersion: v1
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

  /// Kubeconfig sources adapt with no `envs`, stated or sniffed.
  #[test]
  fn kube_rewrites_adapt_stated_or_sniffed() {
    use std::collections::HashMap;

    use arkham_pki::ca::CertAuthority;

    let dir = tempdir().unwrap();
    let source = dir.path().join("k3s.yaml");
    fs::write(&source, KUBE_DOC).unwrap();
    let ca = CertAuthority::generate().unwrap();
    let expander = build_expander(HashMap::new());
    let files = dir.path().join("files");
    let guests = dir.path().join("guests");
    for format in [None, Some(RewriteFormat::Kubeconfig)] {
      let outputs = write_rewrites(&RewriteInputs {
        files_dir: &files,
        root: dir.path(),
        rewrites: &[FileRewrite {
          source: source.clone(),
          dest: "{home}/.kube/config".to_string(),
          envs: Vec::new(),
          format,
        }],
        decoys: &[],
        env: &HashMap::new(),
        expander: &expander,
        home: "/home/eng",
        host_home: None,
        kube_ca: Some(&ca),
        guests_dir: &guests,
      })
      .unwrap();
      assert_eq!(outputs.mounts.len(), 1);
      assert_eq!(outputs.grants.len(), 1);
      assert!(
        outputs.grants[0].fragment.contains("https://10.0.0.1:6443"),
        "{}",
        outputs.grants[0].fragment
      );
      let body = fs::read_to_string(&outputs.mounts[0].host).unwrap();
      assert!(body.contains("current-context: k3s-local"), "{body}");
      assert!(!body.contains("probe-token"), "no real credential survives: {body}");
    }
  }

  /// A stated kubeconfig format on a foreign file fails closed.
  #[test]
  fn stated_kubeconfig_on_plain_text_is_an_error() {
    use std::collections::HashMap;

    use arkham_pki::ca::CertAuthority;

    let dir = tempdir().unwrap();
    let source = dir.path().join("npmrc");
    fs::write(&source, "//registry.npmjs.org/:_authToken=real-secret-1\n").unwrap();
    let ca = CertAuthority::generate().unwrap();
    let guests = dir.path().join("guests");
    let expander = build_expander(HashMap::new());
    let error = write_rewrites(&RewriteInputs {
      files_dir: &dir.path().join("files"),
      root: dir.path(),
      rewrites: &[FileRewrite {
        source,
        dest: "{home}/.npmrc".to_string(),
        envs: Vec::new(),
        format: Some(RewriteFormat::Kubeconfig),
      }],
      decoys: &[],
      env: &HashMap::new(),
      expander: &expander,
      home: "/home/eng",
      host_home: None,
      kube_ca: Some(&ca),
      guests_dir: &guests,
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("does not parse as YAML"), "{error}");
  }

  /// Talosconfig sources adapt with no `envs`, stated or sniffed, and an
  /// `envs` statement is rejected either way.
  #[test]
  fn talos_rewrites_adapt_stated_or_sniffed() {
    use std::collections::HashMap;

    use arkham_pki::ca::CertAuthority;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let talos_doc = format!(
      "context: prod\ncontexts:\n  prod:\n    endpoints:\n      - 10.5.0.6\n    ca: {}\n    crt: {}\n    key: {}\n",
      STANDARD.encode(b"CA"),
      STANDARD.encode(b"CRT"),
      STANDARD.encode(b"KEY"),
    );
    let dir = tempdir().unwrap();
    let source = dir.path().join("talosconfig");
    fs::write(&source, talos_doc).unwrap();
    let ca = CertAuthority::generate().unwrap();
    let expander = build_expander(HashMap::new());
    let files = dir.path().join("files");
    let guests = dir.path().join("guests");
    for format in [None, Some(RewriteFormat::Talos)] {
      let outputs = write_rewrites(&RewriteInputs {
        files_dir: &files,
        root: dir.path(),
        rewrites: &[FileRewrite {
          source: source.clone(),
          dest: "{home}/.talos/config".to_string(),
          envs: Vec::new(),
          format,
        }],
        decoys: &[],
        env: &HashMap::new(),
        expander: &expander,
        home: "/home/eng",
        host_home: None,
        kube_ca: Some(&ca),
        guests_dir: &guests,
      })
      .unwrap();
      assert_eq!(outputs.grants.len(), 1);
      assert!(
        outputs.grants[0].fragment.contains("https://10.5.0.6:50000"),
        "{}",
        outputs.grants[0].fragment
      );
      let body = fs::read_to_string(&outputs.mounts[0].host).unwrap();
      assert!(body.contains("endpoints:\n    - 10.5.0.6"), "{body}");
      assert!(!body.contains(&STANDARD.encode(b"CRT")), "no real credential survives: {body}");
    }
    let error = write_rewrites(&RewriteInputs {
      files_dir: &files,
      root: dir.path(),
      rewrites: &[FileRewrite {
        source: source.clone(),
        dest: "{home}/.talos/config".to_string(),
        envs: vec!["TALOS_CERT".to_string()],
        format: Some(RewriteFormat::Talos),
      }],
      decoys: &[Decoy {
        env: "TALOS_CERT".to_string(),
        value: "decoy-cert".to_string(),
      }],
      env: &HashMap::from([("TALOS_CERT".to_string(), "real-cert".to_string())]),
      expander: &expander,
      home: "/home/eng",
      host_home: None,
      kube_ca: Some(&ca),
      guests_dir: &guests,
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("drop `envs`"), "{error}");
  }

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

  /// Puts the ambient-source environment on a temp home and puts it back.
  #[must_use]
  struct AmbientEnv {
    saved: Vec<(&'static str, Option<OsString>)>,
  }

  impl AmbientEnv {
    fn isolate(home: &Path, xdg: &Path) -> Self {
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

  fn token_context(host: &Path) -> PathBuf {
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
