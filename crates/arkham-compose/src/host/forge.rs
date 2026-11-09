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

/// Fnox config files inside `workspace`, the global fnox directory, and
/// every `import` or `age_key_file` those files name.
///
/// The walk does not leave `workspace`. Directory symlinks are not entered.
/// `/` and the private session directory are not candidates. A symlinked
/// config contributes the link path and its target file, not the target's
/// sibling tree.
///
/// # Errors
///
/// Returns an error when a discovered fnox file is not valid TOML, because
/// an unreadable import list would leave a secret file unprojected.
pub(crate) fn projection_files(workspace: &Path) -> Result<Vec<PathBuf>, Error> {
  let mut out = Vec::new();
  if workspace != Path::new("/") && !super::discover::is_private_session(workspace) {
    collect_tree(&mut out, workspace)?;
  }
  if let Some(global) = fnox_config_dir() {
    for name in ["config.toml", "age.txt"] {
      let path = global.join(name);
      consider(&mut out, path);
    }
  }
  let mut index = 0;
  while index < out.len() {
    let path = out[index].clone();
    for imported in imports_of(&path)? {
      consider(&mut out, imported);
    }
    index = index.saturating_add(1);
  }
  Ok(out)
}

fn collect_tree(out: &mut Vec<PathBuf>, dir: &Path) -> Result<(), Error> {
  let meta = match std::fs::symlink_metadata(dir) {
    Ok(meta) => meta,
    Err(source) if source.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
    Err(source) => return Err(source.into()),
  };
  if meta.file_type().is_symlink() || !meta.is_dir() {
    return Ok(());
  }
  push_dir(out, dir)?;
  let config = dir.join(".config");
  if std::fs::symlink_metadata(&config).is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink()) {
    push_dir(out, &config)?;
  }
  let entries = match std::fs::read_dir(dir) {
    Ok(entries) => entries,
    Err(source) if source.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
    Err(source) => return Err(source.into()),
  };
  for entry in entries {
    let path = entry?.path();
    let Ok(child) = std::fs::symlink_metadata(&path) else {
      continue;
    };
    if child.is_dir() && !child.file_type().is_symlink() {
      collect_tree(out, &path)?;
    }
  }
  Ok(())
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
    if is_fnox_config_name(name) {
      consider(out, entry.path());
    }
  }
  Ok(())
}

fn consider(out: &mut Vec<PathBuf>, path: PathBuf) {
  let Ok(meta) = std::fs::symlink_metadata(&path) else {
    return;
  };
  if meta.file_type().is_symlink() {
    // The target is recorded first. Its forged bytes follow the target file,
    // and a later alias of the link must not replace that bind.
    if let Ok(target) = std::fs::canonicalize(&path) {
      push_unique(out, target);
    }
    push_unique(out, path.clone());
    return;
  }
  if meta.is_file() {
    push_unique(out, path);
  }
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

/// Directories whose trees may contain a hard link of a projected file.
///
/// The workspace, the fnox config directory, and the directory of each
/// projected path. A root nested under one already listed is dropped.
#[must_use]
pub(crate) fn scan_roots(workspace: &Path, projected: &[PathBuf]) -> Vec<PathBuf> {
  let mut roots = Vec::new();
  if workspace != Path::new("/") && !super::discover::is_private_session(workspace) {
    roots.push(workspace.to_path_buf());
  }
  if let Some(dir) = fnox_config_dir().filter(|dir| dir != Path::new("/")) {
    roots.push(dir);
  }
  for path in projected {
    if let Some(parent) = path
      .parent()
      .filter(|parent| *parent != Path::new("/") && !parent.as_os_str().is_empty())
    {
      roots.push(parent.to_path_buf());
    }
  }
  roots.sort();
  let mut kept = Vec::new();
  for root in roots {
    if kept.iter().any(|earlier: &PathBuf| root.starts_with(earlier)) {
      continue;
    }
    kept.push(root);
  }
  kept
}

/// Map `(device, inode)` to regular files under `roots` on `devices`.
///
/// Directories on any other device are not entered. Symlinks are not entered
/// and are not indexed: the projection lists the link path itself, and the
/// target is indexed when its directory is one of `roots`.
#[must_use]
pub(crate) fn inode_index(devices: &HashSet<u64>, roots: &[PathBuf]) -> HashMap<(u64, u64), Vec<PathBuf>> {
  let mut index = HashMap::new();
  if devices.is_empty() {
    return index;
  }
  let mut pending = Vec::new();
  for root in roots {
    let Ok(meta) = std::fs::symlink_metadata(root) else {
      continue;
    };
    if !devices.contains(&meta.dev()) || meta.file_type().is_symlink() {
      continue;
    }
    if meta.is_dir() {
      pending.push(root.clone());
      continue;
    }
    if meta.is_file() {
      index.entry((meta.dev(), meta.ino())).or_default().push(root.clone());
    }
  }
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
  let Ok(meta) = std::fs::metadata(target) else {
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
    let outside = tempfile::tempdir().unwrap();
    let outside_hard = outside.path().join("hard.toml");
    std::fs::hard_link(&real, &outside_hard).unwrap();
    let meta = std::fs::metadata(&real).unwrap();
    let index = inode_index(&HashSet::from([meta.dev()]), &[root.path().to_path_buf()]);
    let names = index.get(&(meta.dev(), meta.ino())).unwrap();
    assert!(names.contains(&real) && names.contains(&hard), "{names:?}");
    assert!(!names.iter().any(|path| path.starts_with(outside.path())), "{names:?}");
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

  #[test]
  fn a_symlinked_fnox_toml_projects_the_link_the_target_and_its_hard_links() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().canonicalize().unwrap();
    let vault = base.as_path().join("vault");
    std::fs::create_dir(&vault).unwrap();
    let real = vault.join("real.toml");
    std::fs::write(&real, "# REAL_SECRET_VALUE\n").unwrap();
    let link = base.as_path().join("fnox.toml");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let hard = vault.join("alias.toml");
    std::fs::hard_link(&real, &hard).unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::hard_link(&real, outside.path().join("alias.toml")).unwrap();
    let files = projection_files(base.as_path()).unwrap();
    assert!(files.iter().any(|path| path == &link), "{files:?}");
    assert!(files.iter().any(|path| path == &real), "{files:?}");
    let mut devices = HashSet::new();
    devices.insert(std::fs::metadata(&real).unwrap().dev());
    let index = inode_index(&devices, &scan_roots(base.as_path(), &files));
    let aliases = indexed_aliases(&index, &link);
    assert!(aliases.iter().any(|path| path == &hard), "{aliases:?}");
    assert!(aliases.iter().all(|path| path.starts_with(base.as_path())), "{aliases:?}");
  }

  #[test]
  fn a_symlinked_import_and_age_key_project_the_link_and_the_target() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().canonicalize().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside = outside.path().canonicalize().unwrap();
    let real_import = outside.join("real-import.toml");
    std::fs::write(&real_import, "# IMPORT_SECRET_VALUE\n").unwrap();
    let import_link = base.join("import-link.toml");
    std::os::unix::fs::symlink(&real_import, &import_link).unwrap();
    let real_age = outside.join("real.age");
    std::fs::write(&real_age, "AGE-SECRET-KEY-REAL\n").unwrap();
    let age_link = base.join("age-link");
    std::os::unix::fs::symlink(&real_age, &age_link).unwrap();
    std::fs::write(
      base.join("fnox.toml"),
      "import = [\"import-link.toml\"]\nage_key_file = \"age-link\"\n",
    )
    .unwrap();
    let files = projection_files(&base).unwrap();
    assert!(files.iter().any(|path| path == &import_link), "{files:?}");
    assert!(files.iter().any(|path| path == &real_import), "{files:?}");
    assert!(files.iter().any(|path| path == &age_link), "{files:?}");
    assert!(files.iter().any(|path| path == &real_age), "{files:?}");
  }

  #[test]
  fn a_nested_fnox_file_is_projected_and_an_outside_symlink_is_not_walked() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().canonicalize().unwrap();
    let project = base.join("project");
    let nested = project.join("sub").join("fnox.toml");
    std::fs::create_dir_all(project.join("sub")).unwrap();
    std::fs::write(&nested, "nested = true\n").unwrap();
    let above = base.join("fnox.toml");
    std::fs::write(&above, "above = true\n").unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside = outside.path().canonicalize().unwrap();
    std::fs::write(outside.join("fnox.toml"), "secret = true\n").unwrap();
    std::fs::create_dir(outside.join("deeper")).unwrap();
    std::fs::write(outside.join("deeper").join(".fnox.toml"), "deeper = true\n").unwrap();
    std::os::unix::fs::symlink(outside.join("fnox.toml"), project.join("fnox.toml")).unwrap();
    let files = projection_files(&project).unwrap();
    assert!(files.iter().any(|path| path == &nested), "{files:?}");
    assert!(files.iter().any(|path| path == &outside.join("fnox.toml")), "{files:?}");
    assert!(!files.iter().any(|path| path == &above), "{files:?}");
    assert!(!files.iter().any(|path| path.ends_with("deeper/.fnox.toml")), "{files:?}");
  }
}
