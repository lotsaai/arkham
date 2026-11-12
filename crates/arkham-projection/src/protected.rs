use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

#[cfg(not(target_os = "linux"))]
use crate::inode_index;
use crate::{Error, indexed_aliases, projection_files};
use arkham_launch_plan::Bind;
use arkham_paths::Mount;

/// Find protected configuration files and their aliases.
///
/// # Errors
///
/// Returns an error if protected files or mount information cannot be read.
pub fn protected_config_paths(workspace: &Path, binds: &[Bind], ca_source: &Path) -> Result<Vec<PathBuf>, Error> {
  let mut candidates = vec![
    workspace.join(".config/arkham"),
    workspace.join(".config/arkham.toml"),
    ca_source.to_path_buf(),
    ca_source.with_extension("key"),
  ];
  if let Some(home) = dirs::home_dir() {
    candidates.push(home.join(".config/arkham"));
  }
  candidates.extend(arkham_config::config::user_config_dirs().into_iter().map(|dir| dir.join("arkham")));
  if let Some(path) = std::env::var_os("ARKHAM_CONFIG") {
    candidates.push(PathBuf::from(path));
  }
  if let Some(path) = arkham_config::config::rules_dir() {
    candidates.push(path);
  }

  let mut targets = BTreeSet::new();
  let mut files = BTreeSet::new();
  for candidate in candidates {
    match std::fs::symlink_metadata(&candidate) {
      Ok(_) => collect_protected(&candidate, &mut targets, &mut files)?,
      Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
      Err(source) => return Err(source.into()),
    }
  }

  #[cfg(not(target_os = "linux"))]
  let devices: std::collections::HashSet<u64> = files
    .iter()
    .map(std::fs::metadata)
    .collect::<std::io::Result<Vec<_>>>()?
    .into_iter()
    .map(|meta| meta.dev())
    .collect();
  let mut roots = crate::scan_roots(workspace, &files.iter().cloned().collect::<Vec<_>>());
  for bind in binds {
    roots.push(std::fs::canonicalize(&bind.source).unwrap_or_else(|_| bind.source.clone()));
  }
  #[cfg(target_os = "linux")]
  for name in arkham_launch_plan::SYSTEM_ROOTS {
    if let Ok(path) = std::fs::canonicalize(Path::new("/").join(name)) {
      roots.push(path);
    }
  }
  #[cfg(target_os = "linux")]
  if !files.is_empty() {
    let mounts = mounted_roots()?;
    let mounted = mounts
      .iter()
      .filter(|mount| roots.iter().any(|root| mount.mountpoint.starts_with(root)))
      .map(|mount| mount.mountpoint.clone())
      .collect::<Vec<_>>();
    roots.extend(mounted);
    targets.extend(protected_aliases(&files, &roots, &mounts)?);
  }
  #[cfg(not(target_os = "linux"))]
  {
    let inodes = inode_index(&devices, &roots);
    for file in &files {
      targets.extend(indexed_aliases(&inodes, file));
    }
  }
  let source_paths: Vec<_> = targets.iter().cloned().collect();
  for bind in binds {
    let source = std::fs::canonicalize(&bind.source).unwrap_or_else(|_| bind.source.clone());
    for path in &source_paths {
      if let Ok(relative) = path.strip_prefix(&source) {
        targets.insert(bind.dest.join(relative));
      }
    }
  }
  Ok(targets.into_iter().collect())
}

#[cfg(target_os = "linux")]
fn mounted_roots() -> Result<Vec<ConfigMount>, Error> {
  use std::os::unix::ffi::OsStringExt as _;

  fn decode(encoded: &[u8]) -> PathBuf {
    let mut path = Vec::with_capacity(encoded.len());
    let mut bytes = encoded.iter().copied();
    while let Some(byte) = bytes.next() {
      if byte == b'\\' {
        match (bytes.next(), bytes.next(), bytes.next()) {
          (Some(b'0'), Some(b'4'), Some(b'0')) => path.push(b' '),
          (Some(b'0'), Some(b'1'), Some(b'1')) => path.push(b'\t'),
          (Some(b'0'), Some(b'1'), Some(b'2')) => path.push(b'\n'),
          (Some(b'1'), Some(b'3'), Some(b'4')) => path.push(b'\\'),
          _ => {}
        }
      } else {
        path.push(byte);
      }
    }
    PathBuf::from(std::ffi::OsString::from_vec(path))
  }

  let mountinfo = std::fs::read("/proc/self/mountinfo")?;
  let mut mounted = Vec::new();
  for line in mountinfo.split(|byte| *byte == b'\n') {
    let mut fields = line.split(|byte| *byte == b' ');
    if let (Some(id), Some(device), Some(root), Some(mountpoint)) = (fields.next(), fields.nth(1), fields.next(), fields.next()) {
      mounted.push(ConfigMount {
        id: id.to_vec(),
        device: device.to_vec(),
        root: decode(root),
        mountpoint: decode(mountpoint),
      });
    }
  }
  Ok(mounted)
}

#[cfg(target_os = "linux")]
struct ConfigMount {
  id: Vec<u8>,
  device: Vec<u8>,
  root: PathBuf,
  mountpoint: PathBuf,
}

#[cfg(target_os = "linux")]
struct ConfigInode {
  links: u64,
  names: std::collections::HashMap<(Vec<u8>, PathBuf), PathBuf>,
}

#[cfg(target_os = "linux")]
impl ConfigInode {
  fn complete(&self) -> bool {
    usize::try_from(self.links).is_ok_and(|links| self.names.len() >= links)
  }
}

// Count backing names rather than visible paths: file and directory bind mounts
// can expose the same directory entry more than once without increasing nlink.
#[cfg(target_os = "linux")]
fn protected_aliases(files: &BTreeSet<PathBuf>, roots: &[PathBuf], mounts: &[ConfigMount]) -> Result<BTreeSet<PathBuf>, Error> {
  use std::collections::{HashMap, HashSet};
  use std::os::fd::AsRawFd as _;
  use std::os::unix::fs::OpenOptionsExt as _;

  let mut names: HashMap<(u64, u64), ConfigInode> = HashMap::new();
  for file in files {
    let meta = std::fs::metadata(file)?;
    names.entry((meta.dev(), meta.ino())).or_insert_with(|| ConfigInode {
      links: meta.nlink(),
      names: HashMap::new(),
    });
  }
  let devices: HashSet<_> = names.keys().map(|(device, _)| *device).collect();
  let mut paths = BTreeSet::new();
  let record = |path: &Path, meta: &std::fs::Metadata, names: &mut HashMap<_, ConfigInode>| -> Result<(), Error> {
    if let Some(target) = names.get_mut(&(meta.dev(), meta.ino())) {
      let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_PATH).open(path)?;
      let actual = file.metadata()?;
      if (actual.dev(), actual.ino()) != (meta.dev(), meta.ino()) {
        return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
      }
      let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
      let id = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:").map(str::trim))
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
      for mount in mounts.iter().filter(|mount| mount.id == id.as_bytes()) {
        if let Ok(relative) = path.strip_prefix(&mount.mountpoint) {
          target
            .names
            .entry((mount.device.clone(), mount.root.join(relative)))
            .or_insert_with(|| path.to_path_buf());
        }
      }
    }
    Ok(())
  };
  for file in files {
    record(file, &std::fs::metadata(file)?, &mut names)?;
  }
  let complete = |names: &HashMap<_, ConfigInode>| names.values().all(ConfigInode::complete);
  let mut visited = HashSet::new();
  for root in roots {
    if complete(&names) {
      break;
    }
    let mut pending = vec![root.clone()];
    while let Some(path) = pending.pop() {
      if visited.contains(&path) {
        continue;
      }
      let Ok(meta) = std::fs::symlink_metadata(&path) else {
        continue;
      };
      if !devices.contains(&meta.dev()) || meta.file_type().is_symlink() {
        continue;
      }
      if meta.is_dir() {
        visited.insert(path.clone());
        let Ok(entries) = std::fs::read_dir(path) else {
          continue;
        };
        pending.extend(entries.flatten().map(|entry| entry.path()));
      } else if meta.is_file() {
        if names.contains_key(&(meta.dev(), meta.ino())) {
          paths.insert(path.clone());
        }
        record(&path, &meta, &mut names)?;
        if complete(&names) {
          break;
        }
      }
    }
  }
  for ((device, inode), target) in names {
    for ((mount_device, backing), path) in target.names {
      paths.insert(path);
      for mount in mounts.iter().filter(|mount| mount.device == mount_device) {
        let Ok(relative) = backing.strip_prefix(&mount.root) else {
          continue;
        };
        let alias = if relative.as_os_str().is_empty() {
          mount.mountpoint.clone()
        } else {
          mount.mountpoint.join(relative)
        };
        if roots.iter().any(|root| alias.starts_with(root))
          && std::fs::metadata(&alias).is_ok_and(|meta| meta.dev() == device && meta.ino() == inode)
        {
          paths.insert(alias);
        }
      }
    }
  }
  Ok(paths)
}

fn collect_protected(path: &Path, targets: &mut BTreeSet<PathBuf>, files: &mut BTreeSet<PathBuf>) -> Result<(), Error> {
  let path = match std::fs::canonicalize(path) {
    Ok(path) => path,
    Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
    Err(source) => return Err(source.into()),
  };
  if !targets.insert(path.clone()) {
    return Ok(());
  }
  let metadata = std::fs::metadata(&path)?;
  if metadata.is_dir() {
    for entry in std::fs::read_dir(path)? {
      collect_protected(&entry?.path(), targets, files)?;
    }
  } else if metadata.is_file() {
    files.insert(path);
  }
  Ok(())
}

/// Add a read-only bind and its inode aliases.
pub fn push_with_aliases(
  binds: &mut Vec<Bind>,
  inodes: &std::collections::HashMap<(u64, u64), Vec<PathBuf>, impl std::hash::BuildHasher>,
  source: PathBuf,
  dest: PathBuf,
) {
  for alias in indexed_aliases(inodes, &dest) {
    push_file_bind(binds, source.clone(), alias);
  }
  push_file_bind(binds, source, dest);
}

fn push_file_bind(binds: &mut Vec<Bind>, source: PathBuf, dest: PathBuf) {
  if std::fs::symlink_metadata(&dest).is_ok_and(|meta| meta.file_type().is_symlink()) {
    return;
  }
  if binds.iter().any(|existing| existing.dest == dest) {
    return;
  }
  binds.push(Bind {
    source,
    dest,
    read_only: true,
  });
}

/// Secret files in the enlisted root and in every include tree.
///
/// The include walk uses the same projection as the root. A mount of the
/// root itself is already covered. `/` is not a candidate.
///
/// # Errors
///
/// Returns an error when a discovered fnox file is not valid TOML.
pub fn projected_files(root: &Path, mounts: &[Mount]) -> Result<Vec<PathBuf>, Error> {
  let mut projected = projection_files(root)?;
  let workspace = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
  for mount in mounts {
    if mount.host == root || mount.host == workspace || mount.host == Path::new("/") {
      continue;
    }
    let tree = std::fs::canonicalize(&mount.host)?;
    if tree == workspace || tree == Path::new("/") || !tree.is_dir() {
      continue;
    }
    for path in projection_files(&tree)? {
      let dest = match path.strip_prefix(&tree) {
        Ok(relative) if !relative.as_os_str().is_empty() => mount.container.join(relative),
        _ => path,
      };
      if !projected.iter().any(|existing| existing == &dest) {
        projected.push(dest);
      }
    }
  }
  Ok(projected)
}

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::WriteProfile;
  use arkham_launch_plan::{CA_DEST, LaunchPlan};

  #[cfg(target_os = "linux")]
  #[test]
  fn hardlinks_are_found_across_overlapping_roots() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let original = root.join("original");
    std::fs::write(&original, "secret").unwrap();
    let mounts = mounted_roots().unwrap();
    let files = BTreeSet::from([original.clone()]);
    let aliases = protected_aliases(&files, std::slice::from_ref(&root), &mounts).unwrap();
    assert!(aliases.contains(&original));

    let nested = root.join("nested");
    std::fs::create_dir(&nested).unwrap();
    let hardlink = nested.join("hardlink");
    std::fs::hard_link(&original, &hardlink).unwrap();
    let roots = vec![root.clone(), nested, root];
    let aliases = protected_aliases(&files, &roots, &mounts).unwrap();
    assert!(aliases.contains(&original));
    assert!(aliases.contains(&hardlink));
  }

  #[test]
  fn a_dangling_config_link_does_not_hide_existing_config_files() {
    let root = tempfile::tempdir().unwrap();
    let existing = root.path().join("config.toml");
    std::fs::write(&existing, "# PRIVATE_CONTENT\n").unwrap();
    std::os::unix::fs::symlink("missing.toml", root.path().join("dangling.toml")).unwrap();
    let mut targets = BTreeSet::new();
    let mut files = BTreeSet::new();
    collect_protected(root.path(), &mut targets, &mut files).unwrap();
    assert_eq!(files, BTreeSet::from([existing.canonicalize().unwrap()]));
    assert!(!root.path().join("missing.toml").exists());
  }

  #[test]
  fn symlink_targets_and_translated_hardlinks_are_protected() {
    let base = tempfile::tempdir().unwrap();
    let base_path = base.path().canonicalize().unwrap();
    let workspace = base_path.join("workspace");
    let source = base_path.join("source");
    let dest = base_path.join("destination");
    std::fs::create_dir_all(workspace.join(".config")).unwrap();
    std::fs::create_dir_all(workspace.join("real-config")).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    let config = workspace.join("real-config/config.toml");
    std::fs::write(&config, "# PRIVATE_CONTENT\n").unwrap();
    std::os::unix::fs::symlink("../real-config", workspace.join(".config/arkham")).unwrap();
    std::fs::hard_link(&config, source.join("alias")).unwrap();
    let binds = vec![Bind {
      source,
      dest: dest.clone(),
      read_only: false,
    }];
    let protected = protected_config_paths(&workspace, &binds, &workspace.join("missing-ca")).unwrap();
    assert!(protected.contains(&workspace.join("real-config")));
    assert!(protected.contains(&config));
    assert!(protected.contains(&dest.join("alias")));
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn a_remapped_ca_bundle_and_hardlink_are_hidden_from_the_sandbox() {
    let base = tempfile::Builder::new().tempdir_in("/var/tmp").unwrap();
    let workspace = base.path().join("workspace");
    let source = base.path().join("source");
    let dest = workspace.join("mounted");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::create_dir(&source).unwrap();
    let bundle = source.join("bundle.pem");
    std::fs::write(&bundle, "PRIVATE_CA_MARKER\n").unwrap();
    std::fs::hard_link(&bundle, source.join("alias.pem")).unwrap();
    let cert = base.path().join("public.pem");
    std::fs::write(&cert, "PUBLIC_CERTIFICATE\n").unwrap();
    let binds = vec![Bind {
      source,
      dest: dest.clone(),
      read_only: true,
    }];
    let protected = protected_config_paths(&workspace, &binds, &bundle).unwrap();
    let plan = LaunchPlan {
      profile: WriteProfile::ReadOnly,
      workspace: workspace.clone(),
      binds,
      protected,
      ca_host: cert,
      ca_dest: PathBuf::from(CA_DEST),
      env: Vec::new(),
      workdir: workspace,
      shell: "sh".into(),
    };
    let script = format!(
      "if cat '{0}/bundle.pem' '{0}/alias.pem' 2>/dev/null | grep -q PRIVATE_CA_MARKER; then exit 1; fi; grep -q PUBLIC_CERTIFICATE /arkham/ca.pem",
      dest.display()
    );
    let command = vec!["sh".into(), "-c".into(), script.into()];
    let args = arkham_sandbox::bwrap_argv(&plan, &command).unwrap();
    let output = std::process::Command::new("bwrap").args(args).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(std::fs::read_to_string(bundle).unwrap(), "PRIVATE_CA_MARKER\n");
  }
}
