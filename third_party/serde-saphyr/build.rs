use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
  let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
  let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
  let archive = manifest.join("serde-saphyr-0.0.29.crate");
  println!("cargo:rerun-if-changed={}", archive.display());

  let status = Command::new("tar")
    .arg("-xzf")
    .arg(&archive)
    .arg("-C")
    .arg(&out)
    .status()
    .expect("tar extracts the published serde-saphyr crate");
  assert!(status.success(), "tar failed to extract {}", archive.display());

  let src = out.join("serde-saphyr-0.0.29").join("src");
  let lib = fs::read_to_string(src.join("lib.rs")).expect("published crate has src/lib.rs");
  let body = strip_inner_attrs(&lib);
  let entry = rewrite_mods(body, &src);
  fs::write(out.join("entry.rs"), entry).expect("write entry.rs");
}

fn strip_inner_attrs(lib: &str) -> &str {
  let mut rest = lib;
  loop {
    let trimmed = rest.trim_start_matches(['\n', '\r']);
    let Some(after) = trimmed.strip_prefix("#!") else {
      return rest.trim_start_matches(['\n', '\r']);
    };
    let Some(nl) = after.find('\n') else {
      return "";
    };
    rest = &after[nl + 1..];
  }
}

fn rewrite_mods(lib: &str, src: &Path) -> String {
  let mut out = String::with_capacity(lib.len().saturating_add(1024));
  for line in lib.lines() {
    if let Some(name) = mod_name(line)
      && let Some(path) = module_file(src, name)
    {
      let rendered = path.display().to_string().replace('\\', "\\\\").replace('"', "\\\"");
      out.push_str("#[path = \"");
      out.push_str(&rendered);
      out.push_str("\"]\n");
    }
    out.push_str(line);
    out.push('\n');
  }
  out
}

fn mod_name(line: &str) -> Option<&str> {
  let rest = line
    .strip_prefix("pub(crate) mod ")
    .or_else(|| line.strip_prefix("pub mod "))
    .or_else(|| line.strip_prefix("mod "))?;
  let name = rest.strip_suffix(';')?;
  if !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
    Some(name)
  } else {
    None
  }
}

fn module_file(src: &Path, name: &str) -> Option<PathBuf> {
  let file = src.join(format!("{name}.rs"));
  if file.is_file() {
    return Some(file);
  }
  let nested = src.join(name).join("mod.rs");
  nested.is_file().then_some(nested)
}
