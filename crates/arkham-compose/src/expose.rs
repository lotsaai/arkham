//! `arkham expose`: on-demand host publishings with cross-workspace overlap protection.
//!
//! Static `[workspace] ports` are symmetric and fixed at container create, so
//! two workspaces running the same dev server (two Vite instances on 3000)
//! cannot both publish it. `expose` automates the whole loop instead: it
//! claims a host port in a global registry (`<state-dir>/arkham/exposed.json`,
//! keyed by host port so a second workspace claiming it fails naming the
//! owner), appends the `[[workspace.expose]]` mapping to the project config,
//! regenerates, and `up`s. Publishing is still create-time container state —
//! the command recreates the arkham service (and the agent riding its netns),
//! so exec sessions drop. `down` releases the workspace's claims.

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use arkham_config::Error as ConfigError;
use arkham_config::cli::{Cli, CliCommand};
use arkham_config::config::project_config_write_path;
use arkham_config::config::user_state_dir;
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string_pretty};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, value};

use crate::confine::{compose_command, init_workspace, resolve_backend, up_workspace};
use crate::error::Error;
use crate::workspace::Workspace;

/// One recorded host-port claim: which workspace owns it and what container
/// port it reaches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Claim {
  /// Owning workspace slug.
  pub(crate) workspace: String,
  /// Owning workspace root, naming the owner in conflict errors.
  pub(crate) root: PathBuf,
  /// Container port the host port forwards to.
  pub(crate) port: u16,
}

/// The global claim registry: `<state-dir>/arkham/exposed.json`, one entry per
/// claimed host port. `None` when the state directory does not resolve.
pub(crate) fn registry_file() -> Option<PathBuf> {
  user_state_dir().map(|dir| dir.join("arkham").join("exposed.json"))
}

/// Read the claim registry; absent or unresolvable means no claims.
pub(crate) fn read_registry() -> Result<BTreeMap<u16, Claim>, Error> {
  let Some(path) = registry_file() else {
    return Ok(BTreeMap::new());
  };
  read_registry_from(&path)
}

/// Read the claim registry at `path`; missing means no claims.
pub(crate) fn read_registry_from(path: &Path) -> Result<BTreeMap<u16, Claim>, Error> {
  let content = match fs::read_to_string(path) {
    Ok(content) => content,
    Err(source) if source.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
    Err(source) => {
      return Err(Error::ReadFile {
        path: path.to_path_buf(),
        source,
      });
    }
  };
  from_str(&content).map_err(|source| Error::ExposeRegistry { source })
}

/// Write the claim registry atomically (temp file plus rename, so a crash
/// never leaves a half-written registry behind) and report the file.
pub(crate) fn write_registry_to(path: &Path, registry: &BTreeMap<u16, Claim>) -> Result<(), Error> {
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent).map_err(|source| Error::CreateDir {
      path: parent.to_path_buf(),
      source,
    })?;
  }
  let content = to_string_pretty(registry).map_err(|source| Error::SerializeExpose { source })?;
  let tmp = path.with_extension("json.tmp");
  fs::write(&tmp, content).map_err(|source| Error::WriteFile { path: tmp.clone(), source })?;
  fs::rename(&tmp, path).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })
}

/// Write the global claim registry.
pub(crate) fn write_registry(registry: &BTreeMap<u16, Claim>) -> Result<PathBuf, Error> {
  let path = registry_file().ok_or_else(|| Error::ConfigDir {
    detail: "the expose registry needs the arkham state directory".to_string(),
  })?;
  write_registry_to(&path, registry)?;
  Ok(path)
}

/// Refuse a host port another claim holds: the same workspace reclaiming its
/// own identical mapping is idempotent, anything else names the owner.
pub(crate) fn check_claim(registry: &BTreeMap<u16, Claim>, slug: &str, host: u16, port: u16) -> Result<(), Error> {
  let Some(claim) = registry.get(&host) else {
    return Ok(());
  };
  if claim.workspace == slug && claim.port == port {
    return Ok(());
  }
  Err(Error::ExposeInUse {
    host,
    workspace: claim.workspace.clone(),
    root: claim.root.clone(),
    port: claim.port,
  })
}

/// Drop every claim a workspace holds; `true` when any was dropped. Missing
/// registry means nothing held.
pub(crate) fn prune_workspace(slug: &str) -> Result<bool, Error> {
  let mut registry = read_registry()?;
  let held = registry.len();
  registry.retain(|_, claim| claim.workspace != slug);
  if registry.len() == held {
    return Ok(false);
  }
  write_registry(&registry)?;
  Ok(true)
}

/// Append a `[[workspace.expose]]` mapping to the project config, creating
/// the file (and its `[workspace]` table) when absent; `true` when added.
/// `toml_edit` keeps every other byte — comments, order, formatting — intact.
pub(crate) fn ensure_expose_entry(path: &Path, port: u16, host: u16) -> Result<bool, Error> {
  let content = match fs::read_to_string(path) {
    Ok(content) => content,
    Err(source) if source.kind() == ErrorKind::NotFound => String::new(),
    Err(source) => {
      return Err(Error::ReadFile {
        path: path.to_path_buf(),
        source,
      });
    }
  };
  let mut document: DocumentMut = content.parse().map_err(|source| Error::ExposeConfigParse {
    path: path.to_path_buf(),
    source,
  })?;
  if document["workspace"].is_none() {
    document["workspace"] = Item::Table(Table::new());
  }
  let workspace = document["workspace"]
    .as_table_mut()
    .ok_or_else(|| Error::ExposeConfigType { path: path.to_path_buf() })?;
  // `Table` indexing panics on absent keys (only the document auto-vivifies),
  // so absent tables go through `insert`.
  if !workspace.contains_key("expose") {
    workspace.insert("expose", Item::ArrayOfTables(ArrayOfTables::new()));
  }
  let tables = workspace["expose"]
    .as_array_of_tables_mut()
    .ok_or_else(|| Error::ExposeConfigType { path: path.to_path_buf() })?;
  for table in tables.iter() {
    let same_port = table.get("port").and_then(Item::as_integer) == Some(i64::from(port));
    let same_host = table.get("host").and_then(Item::as_integer) == Some(i64::from(host));
    if same_port && same_host {
      return Ok(false);
    }
  }
  let mut table = Table::new();
  table.insert("port", value(i64::from(port)));
  table.insert("host", value(i64::from(host)));
  tables.push(table);
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent).map_err(|source| Error::CreateDir {
      path: parent.to_path_buf(),
      source,
    })?;
  }
  fs::write(path, document.to_string()).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })?;
  Ok(true)
}

/// `docker compose port arkham <port>`: the host binding compose reports for
/// the container port, proving the publish survived `up`.
async fn compose_port(workspace: &Workspace, port: u16) -> Result<String, Error> {
  let mut command = compose_command(workspace)?;
  command.arg("port").arg("arkham").arg(port.to_string());
  let output = command.output().await.map_err(|source| Error::SpawnCompose { source })?;
  if !output.status.success() {
    return Err(Error::ExposeVerify {
      host: 0,
      port,
      status: output.status.to_string(),
    });
  }
  Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Arguments for the `expose` command.
#[derive(Args, Debug, Clone)]
pub struct ExposeArgs {
  /// Workspace directory; defaults to the current directory. A flag rather
  /// than a positional because the container port already takes that slot.
  #[arg(long)]
  pub workspace: Option<PathBuf>,
  /// Container port to publish (an agent listener the `fwd` sidecar exposes
  /// on the shared namespace's bridge address).
  #[arg(required_unless_present = "list")]
  pub port: Option<u16>,
  /// Host port to bind on `127.0.0.1`; defaults to the container port. A host
  /// port another workspace claimed fails the command naming that workspace.
  #[arg(long)]
  pub host: Option<u16>,
  /// List this workspace's publishings plus every workspace's expose claims.
  #[arg(long)]
  pub list: bool,
}

/// `arkham expose <port> [--host <host-port>]`: claim the host port,
/// persist the mapping, regenerate, `up`, and verify the binding.
/// `arkham expose --list` reports instead of changing anything.
impl CliCommand for ExposeArgs {
  type Error = Error;
  /// Exposes the port.
  ///
  /// # Errors
  ///
  /// Returns an error when the workspace cannot be resolved, the host port is
  /// unusable (zero, a capture listener) or claimed by another workspace, the
  /// project config cannot be updated, or the compose commands fail.
  async fn run(self, _cli: &Cli, arkham_version: &str) -> Result<(), Self::Error> {
    let workspace = Workspace::resolve(self.workspace.as_deref())?;
    if self.list {
      return list_exposes(&workspace);
    }
    let Some(port) = self.port else {
      return Err(Error::ExposeNoPort);
    };
    let host = self.host.unwrap_or(port);
    // Pre-check mirroring `AppConfig::validate` (literals stay in step with
    // it); the config load inside regeneration is the enforcing boundary.
    if port == 0 || host == 0 {
      return Err(Error::Config(Box::new(ConfigError::PortZero)));
    }
    for refused in [port, host] {
      if refused == 15_000 || refused == 15_001 {
        return Err(Error::Config(Box::new(ConfigError::CapturePort { port: refused })));
      }
    }
    let slug = workspace.slug();
    check_claim(&read_registry()?, &slug, host, port)?;
    let config_path = project_config_write_path(workspace.root());
    ensure_expose_entry(&config_path, port, host)?;
    // An unnamed backend keeps whatever the stack on disk already runs —
    // exposing a port must never silently switch how traffic is captured.
    init_workspace(&workspace, resolve_backend(None)?, false, arkham_version).await?;
    // Publishings are create-time state: this recreates the arkham service
    // (and the agent riding its netns), so exec sessions drop.
    up_workspace(&workspace, false).await?;
    let mut registry = read_registry()?;
    registry.insert(
      host,
      Claim {
        workspace: slug.clone(),
        root: workspace.root().to_path_buf(),
        port,
      },
    );
    write_registry(&registry)?;
    let published = compose_port(&workspace, port).await.map_err(|err| match err {
      Error::ExposeVerify { port, status, .. } => Error::ExposeVerify { host, port, status },
      err => err,
    })?;
    println!("exposed 127.0.0.1:{host} -> {slug}:{port} ({published})");
    println!("note: publishing recreated the arkham service (and the agent riding its netns); exec sessions dropped");
    Ok(())
  }
}

/// Print this workspace's publishings plus every workspace's expose claims.
fn list_exposes(workspace: &Workspace) -> Result<(), Error> {
  let config = workspace.config()?;
  println!("workspace {}:", workspace.root().display());
  for port in &config.workspace.ports {
    println!("  127.0.0.1:{port} -> :{port} ([workspace] ports)");
  }
  for map in &config.workspace.expose {
    println!("  127.0.0.1:{} -> :{} ([[workspace.expose]])", map.host, map.port);
  }
  if config.workspace.ports.is_empty() && config.workspace.expose.is_empty() {
    println!("  (no publishings)");
  }
  println!("claims across workspaces:");
  let registry = read_registry()?;
  if registry.is_empty() {
    println!("  (none)");
  }
  for (host, claim) in &registry {
    println!(
      "  127.0.0.1:{host} -> {} :{} ({})",
      claim.workspace,
      claim.port,
      claim.root.display()
    );
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Registry round-trips through one file: write, read back, prune drops
  /// only the named workspace's claims.
  #[test]
  fn registry_round_trip_and_prune() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exposed.json");
    assert!(read_registry_from(&path).unwrap().is_empty(), "missing registry means no claims");
    let mut registry = BTreeMap::new();
    registry.insert(
      3000,
      Claim {
        workspace: "ws-a".to_string(),
        root: PathBuf::from("/a"),
        port: 3000,
      },
    );
    registry.insert(
      3001,
      Claim {
        workspace: "ws-b".to_string(),
        root: PathBuf::from("/b"),
        port: 3000,
      },
    );
    write_registry_to(&path, &registry).unwrap();
    let back = read_registry_from(&path).unwrap();
    assert_eq!(back, registry);
    // check_claim through the shared helper, not the command: identical
    // reclaim passes, a foreign host port fails naming the owner.
    check_claim(&back, "ws-a", 3000, 3000).unwrap();
    let err = check_claim(&back, "ws-b", 3000, 4000).unwrap_err().to_string();
    assert!(err.contains("ws-a") && err.contains("3000"), "{err}");
  }

  /// Config edit appends the mapping table, keeps the rest byte-identical,
  /// and is idempotent on rerun.
  #[test]
  fn expose_entry_appends_and_reruns_quietly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, "[workspace]\nports = [3000]\n").unwrap();
    assert!(ensure_expose_entry(&path, 5173, 5174).unwrap());
    let body = fs::read_to_string(&path).unwrap();
    assert!(body.contains("ports = [3000]"), "{body}");
    assert!(body.contains("[[workspace.expose]]"), "{body}");
    assert!(!ensure_expose_entry(&path, 5173, 5174).unwrap(), "identical mapping is a no-op");
    assert!(ensure_expose_entry(&path, 5173, 5175).unwrap(), "a new host port is a new mapping");
  }

  /// A non-table `expose` value fails naming the file instead of
  /// overwriting user content.
  #[test]
  fn expose_entry_refuses_a_non_table_expose() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, "[workspace]\nexpose = \"nope\"\n").unwrap();
    let err = ensure_expose_entry(&path, 3000, 3000).unwrap_err().to_string();
    assert!(err.contains("[[workspace.expose]]"), "{err}");
  }
}
