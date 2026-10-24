use std::fs;
use std::path::PathBuf;

#[test]
fn cleartext_swaps_like_tls() {
  let banned = [
    concat!("Cleartext", "Mtls"),
    concat!("Postgres", "GuestPlaintext"),
    concat!("Nats", "GuestPlaintext"),
    concat!("Nats", "TlsRequired"),
    concat!("Nats", "InfoUnreadable"),
    concat!("TLS opening on a ", "cleartext"),
    concat!("forwards the ", "decoy"),
    concat!("keeps the ", "decoy"),
  ];
  let mut pending = vec![
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"),
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../arkham-config/src"),
  ];
  let mut hits = Vec::new();
  while let Some(dir) = pending.pop() {
    for entry in fs::read_dir(&dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display())) {
      let path = entry.unwrap().path();
      if path.is_dir() {
        pending.push(path);
        continue;
      }
      if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
        continue;
      }
      let text = fs::read_to_string(&path).unwrap();
      for needle in banned {
        if text.contains(needle) {
          hits.push(format!("{} contains {needle}", path.display()));
        }
      }
    }
  }
  assert!(
    hits.is_empty(),
    "cleartext must swap the real credential the way TLS does; see AGENTS.md:\n{}",
    hits.join("\n")
  );
}
