//! Forged copies of every file fnox loads.
//!
//! Reads succeed and return bytes that are not the original file. Writes
//! land on the forged copy because the bind is read-only.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use arkham_config::is_fnox_config_name;
use std::os::unix::fs::MetadataExt as _;

use crate::Error;

const FORGED_TOML: &[u8] = b"# arkham projection\nvalue = \"arkham-decoy\"\n";
const FORGED_KEY: &[u8] = b"ARKHAM-DECOY-KEY\n";

/// Fnox config files from `workspace` up through its parents, the global
/// fnox directory, and every `import` or `age_key_file` those files name.
///
/// # Errors
///
/// Returns an error when a discovered fnox file is not valid TOML, because
/// an unreadable import list would leave a secret file unprojected.
pub(crate) fn projection_files(workspace: &Path) -> Result<Vec<PathBuf>, Error> {
  let mut out = Vec::new();
  let mut dir = Some(workspace.to_path_buf());
  while let Some(current) = dir {
    push_dir(&mut out, &current)?;
    let nested = current.join(".config");
    if nested.is_dir() {
      push_dir(&mut out, &nested)?;
    }
    dir = current.parent().map(Path::to_path_buf);
  }
  if let Some(global) = fnox_config_dir() {
    for name in ["config.toml", "age.txt"] {
      let path = global.join(name);
      if path.is_file() {
        push_unique(&mut out, path);
      }
    }
  }
  let mut index = 0;
  while index < out.len() {
    let path = out[index].clone();
    for imported in imports_of(&path)? {
      push_unique(&mut out, imported);
    }
    index = index.saturating_add(1);
  }
  Ok(out)
}

fn push_dir(out: &mut Vec<PathBuf>, dir: &Path) -> Result<(), Error> {
  let entries = match std::fs::read_dir(dir) {
    Ok(entries) => entries,
    Err(source) if source.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
    Err(source) => return Err(source.into()),
  };
  for entry in entries {
    let entry = entry?;
    let name = entry.file_name();
    let Some(name) = name.to_str() else {
      continue;
    };
    if is_fnox_config_name(name) && entry.path().is_file() {
      push_unique(out, entry.path());
    }
  }
  Ok(())
}

fn push_unique(out: &mut Vec<PathBuf>, path: PathBuf) {
  if !out.iter().any(|existing| existing == &path) {
    out.push(path);
  }
}

fn fnox_config_dir() -> Option<PathBuf> {
  if let Some(dir) = std::env::var_os("FNOX_CONFIG_DIR") {
    return Some(PathBuf::from(dir));
  }
  dirs::config_dir().map(|dir| dir.join("fnox"))
}

fn imports_of(path: &Path) -> Result<Vec<PathBuf>, Error> {
  let text = match std::fs::read_to_string(path) {
    Ok(text) => text,
    Err(source) if source.kind() == std::io::ErrorKind::PermissionDenied => return Ok(Vec::new()),
    Err(source) => return Err(source.into()),
  };
  if path.extension().and_then(|ext| ext.to_str()) != Some("toml") && path.file_name().and_then(|name| name.to_str()) != Some("config.toml")
  {
    return Ok(Vec::new());
  }
  let value: toml::Value = toml::from_str(&text).map_err(|source| Error::FragmentParse { source })?;
  let parent = path.parent().unwrap_or(Path::new("/"));
  let mut found = Vec::new();
  if let Some(imports) = value.get("import").and_then(toml::Value::as_array) {
    for item in imports {
      if let Some(raw) = item.as_str() {
        let joined = resolve_ref(parent, raw);
        if joined.is_file() {
          found.push(joined);
        }
      }
    }
  }
  if let Some(age) = value.get("age_key_file").and_then(toml::Value::as_str) {
    let joined = resolve_ref(parent, age);
    if joined.is_file() {
      found.push(joined);
    }
  }
  Ok(found)
}

fn resolve_ref(parent: &Path, raw: &str) -> PathBuf {
  let path = Path::new(raw);
  if path.is_absolute() {
    path.to_path_buf()
  } else {
    parent.join(path)
  }
}

/// Bytes written over a projected file. The contents are fixed and carry
/// nothing from the original.
#[must_use]
pub(crate) fn forged_bytes(path: &Path) -> Vec<u8> {
  let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
  let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
  if name == "age.txt" || extension.eq_ignore_ascii_case("age") {
    FORGED_KEY.to_vec()
  } else {
    FORGED_TOML.to_vec()
  }
}

/// Map `(device, inode)` to every non-directory path on `devices`.
///
/// Directories on any other device are not entered, so `/proc`, `/sys`, and
/// `/dev` drop out when the secret files live on the root filesystem.
#[must_use]
pub(crate) fn inode_index(devices: &HashSet<u64>) -> HashMap<(u64, u64), Vec<PathBuf>> {
  let mut index = HashMap::new();
  if devices.is_empty() {
    return index;
  }
  let mut pending = vec![PathBuf::from("/")];
  while let Some(dir) = pending.pop() {
    let Ok(entries) = std::fs::read_dir(&dir) else {
      continue;
    };
    for entry in entries.flatten() {
      let path = entry.path();
      let Ok(meta) = std::fs::symlink_metadata(&path) else {
        continue;
      };
      if !devices.contains(&meta.dev()) || meta.file_type().is_symlink() {
        continue;
      }
      if meta.is_dir() {
        pending.push(path);
        continue;
      }
      index.entry((meta.dev(), meta.ino())).or_default().push(path);
    }
  }
  index
}

/// Paths in `index` that share `target`'s inode, excluding `target` itself.
#[must_use]
pub(crate) fn indexed_aliases(index: &HashMap<(u64, u64), Vec<PathBuf>>, target: &Path) -> Vec<PathBuf> {
  let Ok(meta) = std::fs::symlink_metadata(target) else {
    return Vec::new();
  };
  index
    .get(&(meta.dev(), meta.ino()))
    .map(|paths| paths.iter().filter(|path| path.as_path() != target).cloned().collect())
    .unwrap_or_default()
}

/// Other paths on `start`'s walk that name the same inode as `target`.
///
/// Symlinks are skipped: opening one follows it onto the overlaid target.
/// Directories on another device are not entered.
#[cfg(test)]
#[must_use]
pub(crate) fn inode_aliases(start: &Path, target: &Path) -> Vec<PathBuf> {
  let Ok(target_meta) = std::fs::symlink_metadata(target) else {
    return Vec::new();
  };
  let dev = target_meta.dev();
  let ino = target_meta.ino();
  let mut found = Vec::new();
  let mut pending = vec![start.to_path_buf()];
  while let Some(dir) = pending.pop() {
    let Ok(entries) = std::fs::read_dir(&dir) else {
      continue;
    };
    for entry in entries.flatten() {
      let path = entry.path();
      let Ok(meta) = std::fs::symlink_metadata(&path) else {
        continue;
      };
      if meta.dev() != dev || meta.file_type().is_symlink() {
        continue;
      }
      if meta.ino() == ino {
        if path != target {
          found.push(path);
        }
        continue;
      }
      if meta.is_dir() {
        pending.push(path);
      }
    }
  }
  found
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn a_hard_link_is_an_alias_and_a_symlink_is_not() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("fnox.toml");
    std::fs::write(&real, "REAL_SECRET_VALUE\n").unwrap();
    let hard = root.path().join("hard.toml");
    std::fs::hard_link(&real, &hard).unwrap();
    let link = root.path().join("link.toml");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let aliases = inode_aliases(root.path(), &real);
    assert!(aliases.contains(&hard));
    assert!(!aliases.iter().any(|path| path == &link));
    let forged = forged_bytes(&real);
    assert!(
      !forged
        .windows(b"REAL_SECRET_VALUE".len())
        .any(|window| window == b"REAL_SECRET_VALUE")
    );
  }

  #[test]
  fn imports_and_hidden_names_join_the_projection() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(".fnox.local.toml"), "imported = true\n").unwrap();
    std::fs::create_dir(root.path().join("keys")).unwrap();
    let age = root.path().join("keys").join("age.txt");
    std::fs::write(&age, "AGE-SECRET-KEY-REAL\n").unwrap();
    std::fs::write(
      root.path().join("fnox.toml"),
      format!("import = [\"keys/missing.toml\"]\nage_key_file = \"{}\"\n", age.display()),
    )
    .unwrap();
    let files = projection_files(root.path()).unwrap();
    assert!(files.iter().any(|path| path.ends_with(".fnox.local.toml")));
    assert!(files.iter().any(|path| path.ends_with("fnox.toml")));
    assert!(files.iter().any(|path| path == &age));
  }
}
