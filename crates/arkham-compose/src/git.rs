//! Gitconfig adapter for `file_rewrite`: the resolved configuration is a
//! per-forge-host authentication map, never a secret store. Hosts come from
//! remotes (rewritten through `url.<base>.insteadOf`) and the
//! `credential.<url>` scopes; git itself resolves the chain — globals,
//! includes, repository-local, environment — starting from the workspace
//! root, so the adapter reads exactly what a `git` run there would see.
//!
//! * https — for hosts whose registry names carry a decoy the twin points
//!   git's credential lookup at one generated helper script
//!   (`~/.config/arkham/git-credential-arkham`, mounted read-only) answering
//!   `get` with the username plus the decoy password. One static script
//!   instead of inline snippets: every fetcher honors `credential.helper` —
//!   the git CLI, cargo's libgit2 path (`git2::Cred::credential_helper`),
//!   and gitoxide — where an `http.<url>.extraHeader` reaches only the git
//!   CLI, so cargo would fail to authenticate. The proxy swaps the decoy
//!   password for the fnox value inside the Basic credential.
//! * git+ssh — a remote with a `core.sshCommand -i` identity mints the same
//!   per-host ssh grant the ssh-config adapter mints: real key blob, decoy
//!   guest key, decoy private key mounted at the mirrored path.
//!
//! Credential-shaped values in the chain fail closed instead of flowing
//! into the agent: in arkham's model gitconfigs hold no secrets. Host
//! `credential.*.helper` entries are the one thing the twin rewrites: they
//! name host binaries absent from the agent, so they are dropped and the
//! minted script is the only helper left.
//!
//! ponytail: a `core.sshCommand` stated only in repository-local config
//! cannot gain `StrictHostKeyChecking accept-new` through the twin (local
//! beats global), so first contact to an unpinned forge host still prompts.
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Error as IoError;
use std::path::{Path, PathBuf};

use arkham_config::config::{HostSshCfg, IfMissing};
use arkham_config::grants::Scheme;
use arkham_config::registry::Registry;
use arkham_pki::ssh::SshKey;
use gix_config::file::{SectionId, SectionRef};
use gix_config::{File as GitConfig, Source as ConfigSource};
use url::Url;

use crate::adapt::{DecoyFile, GRANTS_STATE_DIR, GrantFragment, RewriteAdapted, render_fragment, rewrite_label};
use crate::decoys::Decoy;
use crate::error::Error;
use crate::ssh::{host_identity_path, mirror_container_path};

/// One forge endpoint a remote or credential scope names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ForgeEndpoint {
  scheme: Scheme,
  host: String,
  port: u16,
}

impl ForgeEndpoint {
  /// The `allow`-shaped entry and `http` scope for this endpoint.
  fn entry(&self) -> String {
    let port = match (self.scheme, self.port) {
      (Scheme::Https, 443) | (Scheme::Ssh, 22) => String::new(),
      _ => format!(":{}", self.port),
    };
    let scheme = match self.scheme {
      Scheme::Https => "https",
      Scheme::Ssh => "ssh",
      _ => "unreachable: endpoints are https or ssh",
    };
    format!("{scheme}://{}{port}", self.host)
  }
}

/// Map a gitconfig onto the agent's decoy twin plus one ssh grant per
/// identity-backed remote. The first entry always carries the twin and, for
/// https coverage, the generated credential helper script; https coverage
/// needs no grant, because the rule already derives from the
/// fnox-declared name whose registry hosts cover the endpoint.
///
/// # Errors
///
/// Returns [`Error::SourceInvalid`] naming the workspace when resolution
/// fails, or when the chain carries a credential-shaped value (an
/// `Authorization` extra header, an insteadOf base with embedded userinfo)
/// or an unreadable ssh identity. A workspace with no git repository
/// derives nothing.
pub(crate) fn adapt(
  source: &Path,
  root: &Path,
  registry: &Registry,
  decoys: &[Decoy],
  home: &str,
  host_home: &Path,
) -> Result<Vec<RewriteAdapted>, Error> {
  let invalid = |detail: String| Error::SourceInvalid {
    file: source.to_path_buf(),
    detail,
  };
  let Some(config) = (match resolve(root) {
    Ok(config) => config,
    Err(detail) => {
      tracing::warn!(workspace = %root.display(), detail, "gitconfig source skipped: resolution failed");
      return Ok(Vec::new());
    }
  }) else {
    return Ok(Vec::new());
  };
  if let Some(detail) = embedded_credentials(&config) {
    tracing::warn!(workspace = %root.display(), detail, "gitconfig source skipped: the agent's copy must carry decoys only — move the credential to fnox");
    return Ok(Vec::new());
  }
  let rules = insteadof_rules(&config);
  let mut endpoints: Vec<ForgeEndpoint> = Vec::new();
  for url in remote_urls(&config, &rules) {
    if let Some(endpoint) = endpoint_of(&url) {
      include_endpoint(&mut endpoints, endpoint);
    }
  }
  let usernames = credential_usernames(&config, &mut endpoints);
  let mut mints = Vec::new();
  let mut ssh_grants = Vec::new();
  for endpoint in &endpoints {
    match endpoint.scheme {
      Scheme::Https => {
        if let Some(mint) = https_mint(endpoint, registry, decoys, &usernames) {
          mints.push(mint);
        }
      }
      Scheme::Ssh => {
        if let Some(grant) = ssh_mint(source, &config, endpoint, home, host_home)? {
          ssh_grants.push(grant);
        }
      }
      _ => {}
    }
  }
  let mut twin = global_layer(&config).map_err(|source| invalid(format!("cannot serialize the global layer: {source}")))?;
  let mut decoy_files = Vec::new();
  if !mints.is_empty() {
    let container = format!("{home}/.config/arkham/git-credential-arkham");
    twin.push_str("\n# arkham: decoy credentials for granted remotes — generated, do not edit.\n");
    let _ = write!(twin, "[credential]\n\thelper = !sh {container}\n");
    decoy_files.push(DecoyFile {
      name: "git-credential-arkham".to_string(),
      bytes: credential_helper_script(&mints).into_bytes(),
      container,
    });
  }
  let mut adapted = vec![RewriteAdapted {
    fragment: String::new(),
    decoy: format!("# generated by `arkham init` — decoys only, safe to inspect.\n{twin}"),
    materialized: Vec::new(),
    decoy_files,
  }];
  adapted.extend(ssh_grants.into_iter().map(|grant| RewriteAdapted {
    fragment: grant.fragment,
    decoy: String::new(),
    materialized: grant.materialized,
    decoy_files: grant.decoy_files,
  }));
  Ok(adapted)
}

/// Resolve the configuration `git` itself would see from `root`: discovery
/// upwards (linked worktrees resolve to their common dir), then globals +
/// includes + repository-local + worktree + environment. `None` when no
/// repository is found — nothing to derive from.
pub(crate) fn resolve(root: &Path) -> Result<Option<GitConfig>, String> {
  let Some((path, _)) = gix_discover::upwards(root).ok() else {
    return Ok(None);
  };
  let (git_dir, _) = path.into_repository_and_work_tree_directories();
  GitConfig::from_git_dir(common_dir(&git_dir))
    .map(Some)
    .map_err(|err| format!("gitconfig resolution failed: {err}"))
}

/// Linked worktrees keep the repository config in the dir `commondir`
/// names; plain repositories are their own common dir.
fn common_dir(git_dir: &Path) -> PathBuf {
  fs::read_to_string(git_dir.join("commondir")).map_or_else(|_| git_dir.to_path_buf(), |raw| git_dir.join(raw.trim()))
}

/// Lossy UTF-8 of one config value; gitconfigs are byte strings.
pub(crate) fn text(value: impl AsRef<[u8]>) -> String {
  String::from_utf8_lossy(value.as_ref()).into_owned()
}

/// Why the chain cannot flow into the agent unchanged, when it cannot: the
/// twin carries the global layer, so an `Authorization` extra header or an
/// insteadOf base with embedded userinfo must live in fnox, not the file.
fn embedded_credentials(config: &GitConfig) -> Option<String> {
  for section in config.sections_by_name("http").into_iter().flatten() {
    for header in section.values("extraheader") {
      let header = text(&header);
      if header.trim_start().to_ascii_lowercase().starts_with("authorization") {
        return Some(format!(
          "`http.{}` extraheader carries an Authorization credential",
          section.header().subsection_name().map_or_else(String::new, text)
        ));
      }
    }
  }
  for section in config.sections_by_name("url").into_iter().flatten() {
    if let Some(base) = section.header().subsection_name()
      && Url::parse(&text(base)).is_ok_and(|url| !url.username().is_empty() || url.password().is_some())
    {
      return Some(format!("insteadOf base `{base}` embeds userinfo"));
    }
  }
  None
}

/// `(prefix, base)` pairs from `url.<base>.insteadOf` entries, in file
/// order; the longest matching prefix rewrites a remote URL.
fn insteadof_rules(config: &GitConfig) -> Vec<(String, String)> {
  let mut rules = Vec::new();
  for section in config.sections_by_name("url").into_iter().flatten() {
    let Some(base) = section.header().subsection_name() else {
      continue;
    };
    for prefix in section.values("insteadof") {
      rules.push((text(&prefix), text(base)));
    }
  }
  rules
}

/// Every remote URL after insteadOf rewriting.
fn remote_urls(config: &GitConfig, rules: &[(String, String)]) -> Vec<String> {
  config
    .sections_by_name("remote")
    .into_iter()
    .flatten()
    .filter_map(|section| section.value("url"))
    .map(|url| rewrite_insteadof(&text(&url), rules))
    .collect()
}

/// Apply the longest matching insteadOf prefix, or return the URL as stated.
fn rewrite_insteadof(url: &str, rules: &[(String, String)]) -> String {
  rules
    .iter()
    .filter(|(prefix, _)| !prefix.is_empty() && url.starts_with(prefix.as_str()))
    .max_by_key(|(prefix, _)| prefix.len())
    .map_or_else(|| url.to_string(), |(prefix, base)| format!("{base}{}", &url[prefix.len()..]))
}

/// Map one (rewritten) remote URL onto its endpoint; only https and ssh
/// addresses are forge transports. scp-style `user@host:path` is ssh.
fn endpoint_of(url: &str) -> Option<ForgeEndpoint> {
  if url.contains("://") {
    let parsed = Url::parse(url).ok()?;
    let scheme = match parsed.scheme() {
      "https" => Scheme::Https,
      "ssh" => Scheme::Ssh,
      _ => return None,
    };
    return Some(ForgeEndpoint {
      scheme,
      host: parsed.host_str()?.to_string(),
      port: parsed.port_or_known_default()?,
    });
  }
  let (authority, rest) = url.split_once(':')?;
  if authority.contains('/') || rest.starts_with("//") || rest.chars().all(|character| character.is_ascii_digit()) {
    return None;
  }
  Some(ForgeEndpoint {
    scheme: Scheme::Ssh,
    host: authority.rsplit('@').next()?.to_string(),
    port: 22,
  })
}

/// `credential.<url>.username` per endpoint, registering each scope's host.
fn credential_usernames(config: &GitConfig, endpoints: &mut [ForgeEndpoint]) -> Vec<(ForgeEndpoint, String)> {
  let mut usernames = Vec::new();
  for section in config.sections_by_name("credential").into_iter().flatten() {
    let (Some(scope), Some(username)) = (section.header().subsection_name(), section.value("username")) else {
      continue;
    };
    let scope = text(scope);
    let url = if scope.contains("://") { scope } else { format!("https://{scope}") };
    let Some(endpoint) = endpoint_of(&url) else {
      continue;
    };
    if let Some(existing) = endpoints.iter_mut().find(|candidate| **candidate == endpoint) {
      usernames.push((existing.clone(), text(&username)));
    } else {
      usernames.push((endpoint.clone(), text(&username)));
    }
  }
  usernames
}

/// Insert an endpoint unless an equal one is already present.
fn include_endpoint(endpoints: &mut Vec<ForgeEndpoint>, endpoint: ForgeEndpoint) {
  if !endpoints.contains(&endpoint) {
    endpoints.push(endpoint);
  }
}
/// Decoy auth material for one covered https endpoint, feeding the generated
/// helper script. `None` when nothing covers the endpoint. A
/// registry-covered host with no declared name warns: the remote cannot
/// authenticate from the agent until fnox declares it.
struct HttpsMint {
  /// Lowercased host the script's `case` matches against.
  host: String,
  /// Stated username, or `oauth2` when the chain states none.
  username: String,
  /// Decoy password the proxy swaps for the fnox value.
  decoy: String,
}

/// Collect the decoy auth material for one covered https endpoint.
fn https_mint(endpoint: &ForgeEndpoint, registry: &Registry, decoys: &[Decoy], usernames: &[(ForgeEndpoint, String)]) -> Option<HttpsMint> {
  let covering = registry.envs_for_host(endpoint.scheme, &endpoint.host, endpoint.port);
  let decoy = covering
    .iter()
    .find_map(|env| decoys.iter().find(|decoy| decoy.env == *env))
    .map(|decoy| decoy.value.clone())
    .or_else(|| {
      if covering.is_empty() {
        None
      } else {
        tracing::warn!(
          host = %endpoint.host,
          names = ?covering,
          "registry covers this remote but no declared name resolves for it: the agent cannot authenticate here until fnox declares one"
        );
        None
      }
    })?;
  let username = usernames
    .iter()
    .find(|(candidate, _)| candidate == endpoint)
    .map_or_else(|| "oauth2".to_string(), |(_, username)| username.clone());
  Some(HttpsMint {
    host: endpoint.host.to_lowercase(),
    username,
    decoy,
  })
}

/// Render the agent's git credential helper: a POSIX shell script answering
/// `get` with the minted username and decoy password per covered host. One
/// static script instead of inline `!` snippets: no per-value shell quoting
/// at the call site, port and path dispatch in one place, and `store` plus
/// `erase` exit silently without persisting decoys. Unknown hosts exit
/// nonzero so git falls through to the next helper.
fn credential_helper_script(mints: &[HttpsMint]) -> String {
  let mut out = String::from(
    "#!/bin/sh\n\
     # generated by `arkham init` — decoy credentials for granted remotes, safe to inspect.\n\
     # git credential helper protocol: `get` prints username/password for a covered host;\n\
     # anything else exits silently.\n\
     op=${1:-get}\n\
     host=\"\"\n\
     username=\"\"\n\
     protocol=\"\"\n\
     while IFS= read -r line; do\n\
     \x20 [ -z \"$line\" ] && break\n\
     \x20 case \"$line\" in\n\
     \x20 \x20 host=*) host=${line#host=} ;;\n\
     \x20 \x20 username=*) username=${line#username=} ;;\n\
     \x20 \x20 protocol=*) protocol=${line#protocol=} ;;\n\
     \x20 esac\n\
     done\n\
     [ \"$op\" = \"get\" ] || exit 0\n\
     case \"$protocol\" in\n\
     \x20 \"\"|https) ;;\n\
     \x20 *) exit 1 ;;\n\
     esac\n\
     host=${host%%:*}\n\
     host=$(printf '%s' \"$host\" | tr 'A-Z' 'a-z')\n\
     case \"$host\" in\n",
  );
  for mint in mints {
    let _ = writeln!(
      out,
      "  {})\n    [ -z \"$username\" ] && username={}\n    printf 'username=%s\\npassword=%s\\n' \"$username\" {}\n    ;;",
      mint.host,
      shell_quote(&mint.username),
      shell_quote(&mint.decoy)
    );
  }
  out.push_str("  *)\n    exit 1\n    ;;\nesac\n");
  out
}

/// Shell-single-quote one value for the helper script: `'` becomes `'\''`,
/// so no metacharacter in a username or decoy can execute.
fn shell_quote(value: &str) -> String {
  format!("'{}'", value.replace('\'', "'\\''"))
}

/// The ssh grant pieces `adapt` assembles for one identity-backed remote.
struct SshGrant {
  fragment: String,
  materialized: Vec<(String, Vec<u8>)>,
  decoy_files: Vec<DecoyFile>,
}

/// One ssh grant for an identity-backed remote, `None` when
/// `core.sshCommand` names no identity (the ssh-config adapter owns that
/// path).
///
/// # Errors
///
/// Returns an error when the stated identity is unreadable or the decoy
/// key cannot be minted.
fn ssh_mint(source: &Path, config: &GitConfig, endpoint: &ForgeEndpoint, home: &str, host_home: &Path) -> Result<Option<SshGrant>, Error> {
  let Some(command) = config.string_by("core", None, "sshcommand").map(|value| text(&value)) else {
    tracing::warn!(host = %endpoint.host, "ssh remote without a core.sshCommand identity: declare `format = \"ssh\"` to cover it");
    return Ok(None);
  };
  let Some(identity) = ssh_command_identity(&command) else {
    tracing::warn!(host = %endpoint.host, command = %command, "core.sshCommand states no -i identity: the ssh-config adapter covers identity selection");
    return Ok(None);
  };
  let real_path = host_identity_path(&identity, host_home);
  let Ok(real) = fs::read_to_string(&real_path) else {
    tracing::warn!(host = %endpoint.host, identity = %real_path.display(), "ssh remote skipped: the identity is unreadable");
    return Ok(None);
  };
  let label = rewrite_label(source, &endpoint.host)?;
  let entry = endpoint.entry();
  let decoy = SshKey::generate()?;
  let fragment = render_fragment(
    source,
    &label,
    &GrantFragment {
      env: label.to_uppercase().replace('-', "_"),
      registry: false,
      allow: vec![entry.clone()],
      value: None,
      real: None,
      if_missing: Some(IfMissing::Ignore),
      tls: BTreeMap::new(),
      ssh: BTreeMap::from([(
        entry,
        HostSshCfg {
          identity: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/git-{label}.identity"))),
          guest_key: Some(PathBuf::from(format!("{GRANTS_STATE_DIR}/rules.d/git-{label}.guest_key"))),
        },
      )]),
    },
  )?;
  let decoy_key = decoy.to_openssh()?;
  let Some(container) = mirror_container_path(&identity, host_home, home) else {
    tracing::warn!(host = %endpoint.host, identity = %identity, "ssh remote skipped: the identity does not mirror under the container home");
    return Ok(None);
  };
  Ok(Some(SshGrant {
    fragment,
    materialized: vec![
      (format!("git-{label}.identity"), real.into_bytes()),
      (format!("git-{label}.guest_key"), decoy.public_line()?.into_bytes()),
    ],
    decoy_files: vec![DecoyFile {
      name: format!("git-{label}.decoy-key"),
      bytes: decoy_key.into_bytes(),
      container,
    }],
  }))
}

/// The `-i` identity of a `core.sshCommand`, when it states one.
fn ssh_command_identity(command: &str) -> Option<String> {
  let mut args = command.split_whitespace();
  while let Some(arg) = args.next() {
    if arg == "-i" {
      return args.next().map(str::to_string);
    }
    if let Some(path) = arg.strip_prefix("--identity-file=") {
      return Some(path.to_string());
    }
  }
  None
}

/// The global layer of the resolved chain, serialized losslessly, minus the
/// `credential.*.helper` entries: they name binaries from the host (gopass,
/// tea, gh, keychains) that do not exist in the agent, so keeping them only
/// produces failing helper noise behind the minted script. Usernames survive.
/// Local, worktree, and environment values stay behind on the host.
fn global_layer(config: &GitConfig) -> Result<String, IoError> {
  let mut filtered = config.clone();
  let ids: Vec<SectionId> = filtered
    .sections_and_ids_by_name("credential")
    .map(|sections| sections.map(|(_, id)| id).collect())
    .unwrap_or_default();
  for id in ids {
    if let Some(mut section) = filtered.section_mut_by_id(id) {
      while section.remove("helper").is_some() {}
    }
  }
  let mut bytes = Vec::new();
  filtered.write_to_filter(&mut bytes, is_global)?;
  Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Whether a section belongs to the global configuration layer.
fn is_global(section: &SectionRef<'_>) -> bool {
  matches!(
    section.meta().source,
    ConfigSource::GitInstallation | ConfigSource::System | ConfigSource::Git | ConfigSource::User
  )
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::env;
  use std::ffi::OsString;
  use std::sync::{Mutex, MutexGuard, PoisonError};

  static ENV_LOCK: Mutex<()> = Mutex::new(());

  fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
  }

  /// Pin git's global resolution to a fixture and scrub `GIT_CONFIG_*`,
  /// `HOME`, and `XDG_CONFIG_HOME` so the host's environment cannot leak
  /// into the assertion.
  fn git_env<T>(global: &Path, test: impl FnOnce() -> T) -> T {
    let _guard = lock_env();
    let pinned_home = tempfile::tempdir().unwrap();
    let saved: Vec<(String, Option<OsString>)> = [
      "GIT_CONFIG_GLOBAL",
      "GIT_CONFIG_NOSYSTEM",
      "GIT_CONFIG_COUNT",
      "HOME",
      "XDG_CONFIG_HOME",
    ]
    .into_iter()
    .map(|name| (name.to_string(), env::var_os(name)))
    .collect();
    let mut keys: Vec<String> = env::vars()
      .map(|(name, _)| name)
      .filter(|name| name.starts_with("GIT_CONFIG_KEY"))
      .collect();
    keys.sort();
    let saved_keys: Vec<(String, String)> = keys
      .iter()
      .filter_map(|name| env::var(name).ok().map(|value| (name.clone(), value)))
      .collect();
    for name in &keys {
      // SAFETY: test-only mutation, serialized by ENV_LOCK.
      unsafe { env::remove_var(name) };
    }
    // SAFETY: test-only mutation, serialized by ENV_LOCK.
    unsafe {
      env::set_var("GIT_CONFIG_GLOBAL", global);
      env::set_var("GIT_CONFIG_NOSYSTEM", "1");
      env::set_var("HOME", pinned_home.path());
      env::set_var("XDG_CONFIG_HOME", pinned_home.path().join("xdg"));
      env::remove_var("GIT_CONFIG_COUNT");
    };
    let result = test();
    for (name, value) in saved {
      // SAFETY: test-only mutation, serialized by ENV_LOCK.
      unsafe {
        match value {
          Some(value) => env::set_var(&name, value),
          None => env::remove_var(&name),
        }
      }
    }
    for (name, value) in saved_keys {
      // SAFETY: test-only mutation, serialized by ENV_LOCK.
      unsafe { env::set_var(&name, value) };
    }
    result
  }

  /// A minimal valid repository with the given local config.
  fn repo(dir: &Path, local: &str) {
    let git = dir.join(".git");
    fs::create_dir_all(git.join("objects")).unwrap();
    fs::create_dir_all(git.join("refs").join("heads")).unwrap();
    fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
      git.join("refs").join("heads").join("main"),
      b"1111111111111111111111111111111111111111\n",
    )
    .unwrap();
    fs::write(git.join("config"), local).unwrap();
  }

  fn decoys() -> Vec<Decoy> {
    vec![Decoy {
      env: "GITHUB_TOKEN".to_string(),
      value: "ghp_decoy_decoy_decoy_decoy_decoy".to_string(),
    }]
  }

  #[test]
  fn https_remote_without_stated_username_defaults_to_oauth2() {
    let home = tempfile::tempdir().unwrap();
    let global = home.path().join("gitconfig");
    fs::write(&global, "[user]\n\tname = Ivan\n").unwrap();
    let work = tempfile::tempdir().unwrap();
    repo(
      work.path(),
      "[remote \"origin\"]\n\turl = https://github.com/casualjim/arkham.git\n",
    );
    let adapted = git_env(&global, || {
      adapt(
        &global,
        work.path(),
        &Registry::load(None).unwrap(),
        &decoys(),
        "/home/eng",
        home.path(),
      )
      .unwrap()
    });
    assert_eq!(adapted.len(), 1, "https coverage mints no grant");
    let script = adapted[0]
      .decoy_files
      .iter()
      .find(|file| file.name == "git-credential-arkham")
      .expect("one helper script rides the twin");
    let body = String::from_utf8_lossy(&script.bytes);
    assert!(body.contains("username='oauth2'"), "{body}");
  }

  #[test]
  fn https_mints_render_into_one_helper_script() {
    let home = tempfile::tempdir().unwrap();
    let global = home.path().join("gitconfig");
    fs::write(&global, "[credential \"https://github.com\"]\n\tusername = casualjim\n").unwrap();
    let work = tempfile::tempdir().unwrap();
    repo(
      work.path(),
      "[remote \"origin\"]\n\turl = https://github.com/casualjim/arkham.git\n",
    );
    let adapted = git_env(&global, || {
      adapt(
        &global,
        work.path(),
        &Registry::load(None).unwrap(),
        &decoys(),
        "/home/eng",
        home.path(),
      )
      .unwrap()
    });
    assert_eq!(adapted.len(), 1, "https coverage mints no grant");
    let twin = &adapted[0].decoy;
    let script = adapted[0]
      .decoy_files
      .iter()
      .find(|file| file.name == "git-credential-arkham")
      .expect("one helper script rides the twin");
    assert_eq!(script.container, "/home/eng/.config/arkham/git-credential-arkham");
    let body = String::from_utf8_lossy(&script.bytes);
    assert!(body.starts_with("#!/bin/sh"), "{body}");
    assert!(body.contains("github.com)"), "{body}");
    assert!(
      body.contains(&format!(
        "printf 'username=%s\\npassword=%s\\n' \"$username\" '{}'",
        decoys()[0].value
      )),
      "{body}"
    );
    assert!(body.contains("exit 1"), "unknown hosts fall through: {body}");
    assert!(
      twin.contains("helper = !sh /home/eng/.config/arkham/git-credential-arkham"),
      "{twin}"
    );
    assert!(!twin.contains("!f()"), "no inline shell snippet remains: {twin}");
    assert!(!twin.contains("extraHeader"), "{twin}");
  }

  #[test]
  fn host_credential_helpers_are_scrubbed_from_the_twin() {
    let home = tempfile::tempdir().unwrap();
    let global = home.path().join("gitconfig");
    fs::write(
      &global,
      "[credential \"https://github.com\"]\n\tusername = casualjim\n[credential]\n\thelper = gopass\n",
    )
    .unwrap();
    let work = tempfile::tempdir().unwrap();
    repo(
      work.path(),
      "[remote \"origin\"]\n\turl = https://github.com/casualjim/arkham.git\n",
    );
    let adapted = git_env(&global, || {
      adapt(
        &global,
        work.path(),
        &Registry::load(None).unwrap(),
        &decoys(),
        "/home/eng",
        home.path(),
      )
      .unwrap()
    });
    let twin = &adapted[0].decoy;
    assert!(!twin.contains("gopass"), "host helpers name binaries absent from the agent: {twin}");
    assert!(twin.contains("casualjim"), "usernames survive the scrub: {twin}");
    assert_eq!(twin.matches("helper =").count(), 1, "only the minted helper remains: {twin}");
  }

  #[test]
  fn insteadof_rewrites_the_remote_host() {
    let home = tempfile::tempdir().unwrap();
    let global = home.path().join("gitconfig");
    fs::write(&global, "[url \"https://github.com/\"]\n\tinsteadOf = https://gh.internal/\n").unwrap();
    let work = tempfile::tempdir().unwrap();
    repo(
      work.path(),
      "[remote \"origin\"]\n\turl = https://gh.internal/casualjim/arkham.git\n",
    );
    let adapted = git_env(&global, || {
      adapt(
        &global,
        work.path(),
        &Registry::load(None).unwrap(),
        &decoys(),
        "/home/eng",
        home.path(),
      )
      .unwrap()
    });
    assert!(
      adapted[0]
        .decoy
        .contains("helper = !sh /home/eng/.config/arkham/git-credential-arkham"),
      "{}",
      adapted[0].decoy
    );
  }

  #[test]
  fn authorization_extraheader_skips_the_source() {
    let home = tempfile::tempdir().unwrap();
    let global = home.path().join("gitconfig");
    fs::write(
      &global,
      "[http \"https://github.com/\"]\n\textraHeader = \"AUTHORIZATION: basic aW92YW46c2VjcmV0\"\n",
    )
    .unwrap();
    let work = tempfile::tempdir().unwrap();
    repo(
      work.path(),
      "[remote \"origin\"]\n\turl = https://github.com/casualjim/arkham.git\n",
    );
    let adapted = git_env(&global, || {
      adapt(
        &global,
        work.path(),
        &Registry::load(None).unwrap(),
        &decoys(),
        "/home/eng",
        home.path(),
      )
      .unwrap()
    });
    assert!(
      adapted.is_empty(),
      "no twin leaves the host carrying a real credential: {adapted:?}"
    );
  }

  #[test]
  fn insteadof_base_with_userinfo_skips_the_source() {
    let home = tempfile::tempdir().unwrap();
    let global = home.path().join("gitconfig");
    fs::write(
      &global,
      "[url \"https://ivan:secret@github.com/\"]\n\tinsteadOf = https://github.com/\n",
    )
    .unwrap();
    let work = tempfile::tempdir().unwrap();
    repo(
      work.path(),
      "[remote \"origin\"]\n\turl = https://github.com/casualjim/arkham.git\n",
    );
    let adapted = git_env(&global, || {
      adapt(
        &global,
        work.path(),
        &Registry::load(None).unwrap(),
        &decoys(),
        "/home/eng",
        home.path(),
      )
      .unwrap()
    });
    assert!(
      adapted.is_empty(),
      "no twin leaves the host carrying a real credential: {adapted:?}"
    );
  }

  #[test]
  fn worktree_pointer_resolves_the_common_config() {
    let main = tempfile::tempdir().unwrap();
    repo(
      main.path(),
      "[remote \"origin\"]\n\turl = https://github.com/casualjim/arkham.git\n",
    );
    let worktree = tempfile::tempdir().unwrap();
    let admin = main.path().join(".git").join("worktrees").join("feature");
    fs::create_dir_all(&admin).unwrap();
    fs::write(worktree.path().join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
    fs::write(admin.join("commondir"), "../..\n").unwrap();
    fs::write(admin.join("gitdir"), format!("{}\n", worktree.path().display())).unwrap();
    fs::write(admin.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    let home = tempfile::tempdir().unwrap();
    let global = home.path().join("gitconfig");
    fs::write(&global, "").unwrap();
    let adapted = git_env(&global, || {
      adapt(
        &global,
        worktree.path(),
        &Registry::load(None).unwrap(),
        &decoys(),
        "/home/eng",
        home.path(),
      )
      .unwrap()
    });
    assert!(
      adapted[0]
        .decoy
        .contains("helper = !sh /home/eng/.config/arkham/git-credential-arkham"),
      "{}",
      adapted[0].decoy
    );
  }

  #[test]
  fn ssh_remote_with_sshcommand_identity_mints_the_ssh_grant() {
    let home = tempfile::tempdir().unwrap();
    let key = SshKey::generate().unwrap().to_openssh().unwrap();
    fs::create_dir_all(home.path().join(".ssh")).unwrap();
    fs::write(home.path().join(".ssh").join("forge_key"), &key).unwrap();
    let global = home.path().join("gitconfig");
    fs::write(&global, "[core]\n\tsshCommand = ssh -i ~/.ssh/forge_key\n").unwrap();
    let work = tempfile::tempdir().unwrap();
    repo(work.path(), "[remote \"origin\"]\n\turl = git@github.com:casualjim/arkham.git\n");
    let adapted = git_env(&global, || {
      adapt(
        &global,
        work.path(),
        &Registry::load(None).unwrap(),
        &decoys(),
        "/home/eng",
        home.path(),
      )
      .unwrap()
    });
    assert_eq!(adapted.len(), 2, "twin carrier plus one ssh grant: {adapted:?}");
    let grant = &adapted[1];
    assert!(grant.fragment.contains("ssh://github.com"), "{}", grant.fragment);
    assert!(grant.fragment.contains("git-"), "{}", grant.fragment);
    assert!(grant.materialized.iter().any(|(name, _)| name.starts_with("git-")));
    let mount = &grant.decoy_files[0];
    assert_eq!(mount.container, "/home/eng/.ssh/forge_key");
    assert!(String::from_utf8_lossy(&mount.bytes).contains("BEGIN OPENSSH PRIVATE KEY"));
  }

  #[test]
  fn scp_style_and_ssh_urls_map_to_ssh_endpoints() {
    let ssh_url = endpoint_of("ssh://git@github.com:2222/org/repo.git").unwrap();
    assert_eq!((ssh_url.scheme, ssh_url.port), (Scheme::Ssh, 2222));
    let scp = endpoint_of("git@github.com:org/repo.git").unwrap();
    assert_eq!((scp.scheme, scp.host, scp.port), (Scheme::Ssh, "github.com".to_string(), 22));
    let https = endpoint_of("https://github.com/org/repo.git").unwrap();
    assert_eq!((https.scheme, https.port), (Scheme::Https, 443));
    assert!(endpoint_of("git://github.com/org/repo.git").is_none());
    assert!(endpoint_of("/local/path:hint").is_none());
  }
}
