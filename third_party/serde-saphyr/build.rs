use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CRATE_URL: &str = "https://static.crates.io/crates/serde-saphyr/serde-saphyr-0.0.29.crate";
const CRATE_SHA256: &str = "7bd22781911de0ca6debda95f073c8f18bec65d1a94f1fa9573f3102e514cea4";

fn main() {
  let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
  let archive = fetch_crate(&out);

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

fn fetch_crate(out: &Path) -> PathBuf {
  let dest = out.join("serde-saphyr-0.0.29.crate");
  if !checksum_matches(&dest) {
    let status = Command::new("curl")
      .args(["-fsSL", "--retry", "3", "-o"])
      .arg(&dest)
      .arg(CRATE_URL)
      .status()
      .unwrap_or_else(|err| panic!("curl is required to fetch serde-saphyr: {err}"));
    if !status.success() {
      panic!("curl failed to fetch {CRATE_URL}");
    }
    if !checksum_matches(&dest) {
      panic!("serde-saphyr 0.0.29 checksum mismatch");
    }
  }
  dest
}

fn checksum_matches(path: &Path) -> bool {
  if !path.is_file() {
    return false;
  }
  let output = Command::new("sha256sum")
    .arg(path)
    .output()
    .unwrap_or_else(|err| panic!("sha256sum is required to check serde-saphyr: {err}"));
  if !output.status.success() {
    return false;
  }
  String::from_utf8_lossy(&output.stdout).starts_with(CRATE_SHA256)
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
