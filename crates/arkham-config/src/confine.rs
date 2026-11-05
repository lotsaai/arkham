//! Shared confinement policy for host backends.
//!
//! One profile names the writable set. Every renderer and every test reads
//! [`fs_policy`]. A renderer does not invent its own roots.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::Error;

/// How `arkham agent` confines the command.
///
/// `compose` is the default. `bwrap` is the Linux host backend. Landlock can
/// add restrictions inside bubblewrap. It is not a runner and not a flag.
#[derive(ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Isolate {
  /// The compose stack.
  #[default]
  Compose,
  /// The Linux host backend.
  Bwrap,
}

/// Filesystem write profile. Orthogonal to secret projection: decoy env,
/// forged secret files, and capture still apply when the profile is
/// [`WriteProfile::DangerFullAccess`].
#[derive(ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WriteProfile {
  /// Workspace root plus the backend temp directory are writable.
  #[default]
  WorkspaceWrite,
  /// Writes are denied except the `/dev/null` sink shells need.
  ReadOnly,
  /// No filesystem read or write restriction. Secret projection still applies.
  DangerFullAccess,
}

/// What a confinement backend is allowed to report.
///
/// `Full` is only returned after a probe that enforced every requested
/// restriction. An older Landlock ABI reports [`Enforcement::Partial`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Enforcement {
  /// The probe enforced the whole profile.
  Full,
  /// The probe passed, and some requested restriction is absent.
  Partial,
}

/// Which host runner won the probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerKind {
  /// Bubblewrap.
  Bwrap,
}

/// The runner a probe sequence selected, and the enforcement it reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerChoice {
  /// Selected runner.
  pub runner: RunnerKind,
  /// Enforcement that runner reported.
  pub enforcement: Enforcement,
}

/// Writable set for one profile.
///
/// The variants are the whole policy. A read-only profile has no writable
/// root, and an unrestricted profile has no list a renderer could half-apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsPolicy {
  /// Deny writes. `sink` is the only writable path (`/dev/null`).
  ReadOnly {
    /// Path shells may open for writing.
    sink: PathBuf,
  },
  /// These directories are writable. Everything else is read-only.
  WorkspaceWrite {
    /// Workspace root, then the temp directory.
    roots: Vec<PathBuf>,
  },
  /// No read or write restriction from this profile.
  Unrestricted,
}

/// Derive the writable set for `profile`.
///
/// `temp` is the backend's temp directory (`/tmp` inside a bwrap tmpfs).
/// Callers pass it. The helper does not pick a path of its own.
#[must_use]
pub fn fs_policy(profile: WriteProfile, workspace: &Path, temp: &Path) -> FsPolicy {
  match profile {
    WriteProfile::ReadOnly => FsPolicy::ReadOnly {
      sink: PathBuf::from("/dev/null"),
    },
    WriteProfile::WorkspaceWrite => FsPolicy::WorkspaceWrite {
      roots: vec![workspace.to_path_buf(), temp.to_path_buf()],
    },
    WriteProfile::DangerFullAccess => FsPolicy::Unrestricted,
  }
}

/// Pick a runner from probe results.
///
/// `bwrap` is true only when `true` exited 0 under the real profile.
/// `landlock` is accepted so a caller can pass a probe result, and it never
/// selects a runner. Bubblewrap reports full. Anything else refuses to start.
///
/// # Errors
///
/// Returns [`Error::NoRunner`] when bubblewrap did not accept the profile.
pub fn choose_runner(bwrap: bool, landlock: Option<Enforcement>) -> Result<RunnerChoice, Error> {
  let _ = landlock;
  if bwrap {
    return Ok(RunnerChoice {
      runner: RunnerKind::Bwrap,
      enforcement: Enforcement::Full,
    });
  }
  Err(Error::NoRunner)
}

/// Refuse a host-backend listen address that is not loopback.
///
/// # Errors
///
/// Returns [`Error::HostListen`] when `addr` is not a loopback address.
pub fn require_loopback_listen(addr: SocketAddr) -> Result<(), Error> {
  if addr.ip().is_loopback() {
    Ok(())
  } else {
    Err(Error::HostListen { listen: addr.to_string() })
  }
}

/// Whether `name` is a fnox config file name fnox itself loads.
///
/// Covers `fnox.toml`, `fnox.*.toml`, `.fnox.toml`, `.fnox.*.toml`, and
/// `.fnox.local.toml`. `config.toml` at the global fnox directory is a
/// separate path check.
#[must_use]
pub fn is_fnox_config_name(name: &str) -> bool {
  if name == "fnox.toml" || name == ".fnox.toml" {
    return true;
  }
  let bare = name.strip_prefix('.').unwrap_or(name);
  let Some(rest) = bare.strip_prefix("fnox.") else {
    return false;
  };
  let Some(profile) = rest.strip_suffix(".toml") else {
    return false;
  };
  !profile.is_empty() && !profile.contains('/')
}

/// Whether `path` is a fnox file the projection must cover.
///
/// File names from [`is_fnox_config_name`], plus the global `config.toml`
/// and `age.txt` that live directly in a `fnox` directory.
#[must_use]
pub fn is_fnox_config_path(path: &Path) -> bool {
  let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
    return false;
  };
  if is_fnox_config_name(name) {
    return true;
  }
  if name != "config.toml" && name != "age.txt" {
    return false;
  }
  path
    .parent()
    .and_then(|parent| parent.file_name())
    .and_then(|parent| parent.to_str())
    == Some("fnox")
}

#[cfg(test)]
mod tests {
  use std::net::Ipv4Addr;

  use super::*;

  #[test]
  fn workspace_write_lists_the_workspace_and_the_temp_dir() {
    let policy = fs_policy(WriteProfile::WorkspaceWrite, Path::new("/work"), Path::new("/tmp"));
    assert_eq!(
      policy,
      FsPolicy::WorkspaceWrite {
        roots: vec![PathBuf::from("/work"), PathBuf::from("/tmp")],
      }
    );
  }

  #[test]
  fn read_only_keeps_only_the_dev_null_sink() {
    let policy = fs_policy(WriteProfile::ReadOnly, Path::new("/work"), Path::new("/tmp"));
    assert_eq!(
      policy,
      FsPolicy::ReadOnly {
        sink: PathBuf::from("/dev/null"),
      }
    );
  }

  #[test]
  fn danger_full_access_has_no_writable_list() {
    let policy = fs_policy(WriteProfile::DangerFullAccess, Path::new("/work"), Path::new("/tmp"));
    assert!(matches!(policy, FsPolicy::Unrestricted));
  }

  #[test]
  fn a_passing_bwrap_probe_wins_and_reports_full() {
    let choice = choose_runner(true, Some(Enforcement::Partial)).unwrap();
    assert_eq!(choice.runner, RunnerKind::Bwrap);
    assert_eq!(choice.enforcement, Enforcement::Full);
  }

  #[test]
  fn landlock_without_bwrap_does_not_start() {
    let partial = choose_runner(false, Some(Enforcement::Partial)).unwrap_err();
    assert!(matches!(partial, Error::NoRunner));
    let full = choose_runner(false, Some(Enforcement::Full)).unwrap_err();
    assert!(matches!(full, Error::NoRunner));
  }

  #[test]
  fn no_passing_probe_refuses() {
    let err = choose_runner(false, None).unwrap_err();
    assert!(matches!(err, Error::NoRunner));
  }

  #[test]
  fn host_listen_must_be_loopback() {
    require_loopback_listen(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))).unwrap();
    require_loopback_listen("[::1]:9".parse().unwrap()).unwrap();
    let err = require_loopback_listen(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080))).unwrap_err();
    assert!(matches!(err, Error::HostListen { .. }));
  }

  #[test]
  fn fnox_names_cover_hidden_profile_and_local_files() {
    assert!(is_fnox_config_name("fnox.toml"));
    assert!(is_fnox_config_name(".fnox.toml"));
    assert!(is_fnox_config_name("fnox.local.toml"));
    assert!(is_fnox_config_name(".fnox.local.toml"));
    assert!(is_fnox_config_name("fnox.work.toml"));
    assert!(is_fnox_config_name(".fnox.work.toml"));
    assert!(!is_fnox_config_name("notes.toml"));
    assert!(!is_fnox_config_name("fnox.toml.bak"));
    assert!(is_fnox_config_path(Path::new("/work/.config/fnox.toml")));
    assert!(is_fnox_config_path(Path::new("/home/u/.config/fnox/config.toml")));
    assert!(is_fnox_config_path(Path::new("/home/u/.config/fnox/age.txt")));
    assert!(!is_fnox_config_path(Path::new("/work/config.toml")));
    assert!(!is_fnox_config_path(Path::new("/work/age.txt")));
  }
}
