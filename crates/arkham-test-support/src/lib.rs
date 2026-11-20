//! Test-only environment isolation: a [`test_context`] context that points the
//! process at a private home directory so tests never read or write the real one.

use std::{
  env,
  ffi::OsString,
  future::ready,
  path::Path,
  sync::{Condvar, Mutex, PoisonError},
};

use tempfile::TempDir;
use test_context::AsyncTestContext;

/// Process-wide environment lock. A flag guarded by a condvar rather than a
/// `MutexGuard`, because a guard is `!Send` and the async context must be `Send`.
static ENV_LOCK: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

/// Holds [`ENV_LOCK`] until dropped.
#[derive(Debug)]
struct EnvLock;

impl EnvLock {
  fn acquire() -> Self {
    let (flag, released) = &ENV_LOCK;
    let mut held = flag.lock().unwrap_or_else(PoisonError::into_inner);
    while *held {
      held = released.wait(held).unwrap_or_else(PoisonError::into_inner);
    }
    *held = true;
    Self
  }
}

impl Drop for EnvLock {
  fn drop(&mut self) {
    let (flag, released) = &ENV_LOCK;
    *flag.lock().unwrap_or_else(PoisonError::into_inner) = false;
    released.notify_one();
  }
}

/// Variables pointed into the private home.
const HOME_VARS: [(&str, &str); 6] = [
  ("HOME", ""),
  ("XDG_CONFIG_HOME", ".config"),
  ("XDG_STATE_HOME", ".local/state"),
  ("XDG_DATA_HOME", ".local/share"),
  ("XDG_CACHE_HOME", ".cache"),
  ("JJ_CONFIG", ".jjconfig.toml"),
];

/// Variables removed for the duration of the test.
const CLEARED_VARS: [&str; 4] = ["ARKHAM_CONFIG", "FNOX_CONFIG_DIR", "KUBECONFIG", "TALOSCONFIG"];

/// Isolated process environment: `HOME`, the XDG directories and `JJ_CONFIG`
/// point into a fresh temporary directory, and `ARKHAM_CONFIG`,
/// `FNOX_CONFIG_DIR`, `KUBECONFIG` and `TALOSCONFIG` are unset. Holds a
/// process-wide lock for its whole lifetime, so contexts never overlap. The
/// previous values are restored when the context ends.
///
/// Implements [`AsyncTestContext`]; `test-context` derives the sync
/// `TestContext` from it.
#[derive(Debug)]
pub struct IsolatedHome {
  saved: Vec<(&'static str, Option<OsString>)>,
  // Field order is drop order: the directory goes before the lock is released.
  dir: TempDir,
  _lock: EnvLock,
}

impl IsolatedHome {
  /// The private home directory.
  #[must_use]
  pub fn path(&self) -> &Path {
    self.dir.path()
  }
}

impl AsyncTestContext for IsolatedHome {
  fn setup() -> impl Future<Output = Self> {
    let lock = EnvLock::acquire();
    let dir = TempDir::new().expect("create isolated home");
    let mut saved = Vec::with_capacity(HOME_VARS.len() + CLEARED_VARS.len());
    for (name, relative) in HOME_VARS {
      saved.push((name, env::var_os(name)));
      let value = if relative.is_empty() {
        dir.path().to_path_buf()
      } else {
        dir.path().join(relative)
      };
      // SAFETY: `ENV_LOCK` is held, so no other isolated test touches the environment.
      unsafe { env::set_var(name, &value) };
    }
    for name in CLEARED_VARS {
      saved.push((name, env::var_os(name)));
      // SAFETY: `ENV_LOCK` is held, so no other isolated test touches the environment.
      unsafe { env::remove_var(name) };
    }
    for relative in [".config", ".local/state", ".local/share", ".cache"] {
      std::fs::create_dir_all(dir.path().join(relative)).expect("create isolated xdg directory");
    }
    ready(Self { saved, dir, _lock: lock })
  }
}

impl Drop for IsolatedHome {
  fn drop(&mut self) {
    for (name, value) in self.saved.drain(..) {
      match value {
        // SAFETY: `ENV_LOCK` is still held; `_lock` drops after this body.
        Some(value) => unsafe { env::set_var(name, value) },
        // SAFETY: as above.
        None => unsafe { env::remove_var(name) },
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use std::env;

  use test_context::TestContext;

  use super::IsolatedHome;

  #[test]
  fn the_environment_is_private_inside_and_restored_after() {
    let before: Vec<_> = ["HOME", "XDG_CONFIG_HOME", "ARKHAM_CONFIG"].map(env::var_os).into();

    let ctx = <IsolatedHome as TestContext>::setup();
    assert_eq!(env::var_os("HOME").as_deref(), Some(ctx.path().as_os_str()));
    assert_eq!(env::var_os("XDG_CONFIG_HOME"), Some(ctx.path().join(".config").into_os_string()));
    assert!(env::var_os("ARKHAM_CONFIG").is_none());
    TestContext::teardown(ctx);

    let after: Vec<_> = ["HOME", "XDG_CONFIG_HOME", "ARKHAM_CONFIG"].map(env::var_os).into();
    assert_eq!(before, after);
  }
}
