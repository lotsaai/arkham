//! Differential check vs `.cursor/skills/formal-verify-grant-host/oracle.py`.
//!
//! See that skill for property, bounds, and sync commit. Run via
//! `.cursor/skills/formal-verify-grant-host/run.sh`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;

use arkham_config::{EndpointScope, HostPat, Scheme};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct Case {
  id: String,
  kind: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  pattern: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  hostname: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  allow_scheme: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  allow_host_pat: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  allow_port: Option<u16>,
  #[serde(skip_serializing_if = "Option::is_none")]
  scheme: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  host: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  port: Option<u16>,
  rust: bool,
}

#[derive(Deserialize)]
struct OracleRow {
  id: String,
  expected: bool,
}

fn host_cases() -> Vec<Case> {
  let patterns = [
    "*",
    "*.example.com",
    "example.com",
    "*.com",
    "a.example.com",
    "EXAMPLE.com",
    "*.github.com",
  ];
  let hosts = [
    "",
    "a",
    "com",
    "example.com",
    "a.example.com",
    "b.a.example.com",
    "EXAMPLE.COM",
    "a.EXAMPLE.com",
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "notexample.com",
    "example.com.evil",
  ];
  let mut out = Vec::new();
  let mut n = 0u32;
  for pat in patterns {
    for host in hosts {
      let rust = HostPat::from_str(pat).expect("infallible").matches(host);
      out.push(Case {
        id: format!("host-{n}"),
        kind: "host",
        pattern: Some(pat.to_string()),
        hostname: Some(host.to_string()),
        allow_scheme: None,
        allow_host_pat: None,
        allow_port: None,
        scheme: None,
        host: None,
        port: None,
        rust,
      });
      n = n.saturating_add(1);
    }
  }
  out
}

fn parse_scheme(s: &str) -> Scheme {
  match s {
    "http" => Scheme::Http,
    "https" => Scheme::Https,
    "tcp" => Scheme::Tcp,
    other => panic!("grid only enumerates http/https/tcp, got {other}"),
  }
}

fn token_cases() -> Vec<Case> {
  let allow_pats = ["*", "*.example.com", "example.com"];
  let allow_schemes = ["http", "https", "tcp"];
  let allow_ports = [80u16, 443, 8080];
  let req_hosts = ["example.com", "a.example.com", "other.com"];
  let req_schemes = ["http", "https", "tcp"];
  let req_ports = [80u16, 443, 8080];
  let mut out = Vec::new();
  let mut n = 0u32;
  for ap in allow_pats {
    for ascheme in allow_schemes {
      for aport in allow_ports {
        let entry: EndpointScope = format!("{ascheme}://{ap}:{aport}")
          .parse()
          .unwrap_or_else(|e| panic!("parse allow {ascheme}://{ap}:{aport}: {e}"));
        for rscheme in req_schemes {
          for rhost in req_hosts {
            for rport in req_ports {
              let scheme = parse_scheme(rscheme);
              let rust = entry.scheme == scheme && entry.port == rport && entry.host.matches(rhost);
              out.push(Case {
                id: format!("token-{n}"),
                kind: "token",
                pattern: None,
                hostname: None,
                allow_scheme: Some(ascheme.to_string()),
                allow_host_pat: Some(ap.to_string()),
                allow_port: Some(aport),
                scheme: Some(rscheme.to_string()),
                host: Some((*rhost).to_string()),
                port: Some(rport),
                rust,
              });
              n = n.saturating_add(1);
            }
          }
        }
      }
    }
  }
  out
}

#[test]
fn hostpat_and_token_endpoint_match_independent_oracle() {
  let mut cases = host_cases();
  cases.extend(token_cases());

  let oracle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.cursor/skills/formal-verify-grant-host/oracle.py");
  assert!(oracle.is_file(), "missing oracle at {}", oracle.display());

  let payload = serde_json::to_vec(&cases).expect("serialize cases");
  let mut child = Command::new("python3")
    .arg(&oracle)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .spawn()
    .unwrap_or_else(|e| panic!("spawn python3 {}: {e}", oracle.display()));
  let mut stdin = child.stdin.take().expect("stdin");
  stdin.write_all(&payload).expect("write cases");
  drop(stdin);
  let output = child.wait_with_output().expect("wait oracle");
  assert!(output.status.success(), "oracle.py failed with {}", output.status);

  let rows: Vec<OracleRow> = serde_json::from_slice(&output.stdout).expect("oracle json");
  assert_eq!(rows.len(), cases.len());

  let mut mismatches = Vec::new();
  for (case, row) in cases.iter().zip(rows.iter()) {
    assert_eq!(case.id, row.id);
    if case.rust != row.expected {
      mismatches.push(format!(
        "{}: rust={} oracle={} case={}",
        case.id,
        case.rust,
        row.expected,
        serde_json::to_string(case).unwrap_or_default()
      ));
    }
  }
  assert!(
    mismatches.is_empty(),
    "formal-verify-grant-host mismatches ({}):\n{}",
    mismatches.len(),
    mismatches.iter().take(32).cloned().collect::<Vec<_>>().join("\n")
  );
}
