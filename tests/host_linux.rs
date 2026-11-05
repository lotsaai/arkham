//! Linux host-backend acceptance. These run under nextest without root.
//! Bubblewrap has to win the probe: a Landlock-only result is a failure,
//! because the projection checks need the bind mounts.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Isolated {
  runtime: tempfile::TempDir,
  home: tempfile::TempDir,
  config_home: tempfile::TempDir,
  fnox_dir: tempfile::TempDir,
  ca_file: PathBuf,
  path: std::ffi::OsString,
}

impl Isolated {
  fn new() -> Self {
    let runtime = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let config_home = tempfile::tempdir().unwrap();
    let fnox_dir = tempfile::tempdir().unwrap();
    let ca_file = runtime.path().join("ca.pem");
    let path = std::env::var_os("PATH").unwrap();
    Self {
      runtime,
      home,
      config_home,
      fnox_dir,
      ca_file,
      path,
    }
  }

  fn command(&self, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_arkham"));
    command.args(args).env_clear().envs(self.envs());
    command
  }

  fn envs(&self) -> Vec<(&str, &std::ffi::OsStr)> {
    vec![
      ("PATH", self.path.as_os_str()),
      ("HOME", self.home.path().as_os_str()),
      ("USER", "ubuntu".as_ref()),
      ("LOGNAME", "ubuntu".as_ref()),
      ("XDG_RUNTIME_DIR", self.runtime.path().as_os_str()),
      ("XDG_CONFIG_HOME", self.config_home.path().as_os_str()),
      ("FNOX_CONFIG_DIR", self.fnox_dir.path().as_os_str()),
      ("ARKHAM_CA_FILE", self.ca_file.as_os_str()),
      ("HTTP_PROXY", "http://secret-proxy.invalid".as_ref()),
      ("http_proxy", "http://secret-proxy.invalid".as_ref()),
      ("HTTPS_PROXY", "http://secret-proxy.invalid".as_ref()),
      ("ALL_PROXY", "http://secret-proxy.invalid".as_ref()),
    ]
  }
}

struct Daemon {
  child: Child,
}

impl Daemon {
  fn start(isolated: &Isolated) -> Self {
    let mut child = isolated
      .command(&["daemon"])
      .env("ARKHAM_LISTEN", "127.0.0.1:0")
      .stdout(Stdio::null())
      .stderr(Stdio::piped())
      .spawn()
      .unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
      let mut buf = Vec::new();
      let mut byte = [0u8; 1];
      while stderr.read(&mut byte).unwrap_or(0) == 1 {
        buf.push(byte[0]);
        if buf.windows(13).any(|window| window == b"daemon: ready") {
          let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
          let _ = std::io::copy(&mut stderr, &mut std::io::sink());
          return;
        }
      }
      let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
    });
    let stderr = rx.recv_timeout(Duration::from_secs(60)).unwrap_or_else(|_| String::new());
    if !stderr.contains("daemon: ready") {
      let _ = child.kill();
      let _ = child.wait();
      panic!("daemon did not become ready: {stderr}");
    }
    Self { child }
  }
}

impl Drop for Daemon {
  fn drop(&mut self) {
    let _ = self.child.kill();
    let _ = self.child.wait();
  }
}

fn wait_child(child: &mut Child, limit: Duration) -> std::process::ExitStatus {
  let started = Instant::now();
  loop {
    if let Some(status) = child.try_wait().unwrap() {
      return status;
    }
    if started.elapsed() > limit {
      let _ = child.kill();
      let _ = child.wait();
      panic!("command exceeded {limit:?}");
    }
    std::thread::sleep(Duration::from_millis(50));
  }
}

#[test]
fn agent_refuses_to_start_without_a_daemon() {
  let isolated = Isolated::new();
  let marker = isolated.runtime.path().join("marker");
  let output = isolated
    .command(&["agent", "--isolate", "bwrap", "--", "touch", marker.to_str().unwrap()])
    .output()
    .unwrap();
  assert!(!output.status.success(), "agent started without a daemon: {output:?}");
  assert!(!marker.exists(), "the command ran without a daemon");
}

#[test]
fn a_daemon_does_not_adopt_a_process_that_started_first() {
  let isolated = Isolated::new();
  let mut sleeper = Command::new("sleep").arg("60").spawn().unwrap();
  let _daemon = Daemon::start(&isolated);
  let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", sleeper.id())).unwrap();
  assert!(!cgroup.contains("arkham-host"), "{cgroup}");
  let _ = sleeper.kill();
  let _ = sleeper.wait();
}

#[test]
fn the_daemon_refuses_a_non_loopback_listen_address() {
  let isolated = Isolated::new();
  let output = isolated.command(&["daemon"]).env("ARKHAM_LISTEN", "0.0.0.0:8080").output().unwrap();
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(!output.status.success(), "{stderr}");
  assert!(stderr.contains("non-loopback"), "{stderr}");
  assert!(!stderr.contains("daemon: ready"), "{stderr}");
}

#[test]
fn bwrap_hides_secret_files_and_proxy_env() {
  let isolated = Isolated::new();
  let workspace = tempfile::tempdir().unwrap();
  let root = workspace.path();
  std::fs::create_dir_all(root.join(".config/arkham")).unwrap();
  std::fs::write(
    root.join(".config/arkham/config.toml"),
    "[workspace]\npassthrough = [\"HTTP_PROXY\"]\n",
  )
  .unwrap();
  let secret = "# REAL_SECRET_VALUE\n";
  std::fs::write(root.join("fnox.toml"), format!("import = [\"imported.toml\"]\n{secret}")).unwrap();
  std::fs::write(root.join("imported.toml"), secret).unwrap();
  std::fs::write(root.join(".fnox.local.toml"), secret).unwrap();
  std::fs::hard_link(root.join("fnox.toml"), root.join("secret-hard")).unwrap();
  std::os::unix::fs::symlink(root.join("fnox.toml"), root.join("secret-symlink")).unwrap();
  let outside_hard = isolated.home.path().join("secret-hard");
  std::fs::hard_link(root.join("fnox.toml"), &outside_hard).unwrap();
  let outside_sym = isolated.home.path().join("secret-symlink");
  std::os::unix::fs::symlink(root.join("fnox.toml"), &outside_sym).unwrap();
  let age = isolated.fnox_dir.path().join("age.txt");
  std::fs::write(&age, "AGE-SECRET-KEY-REAL\n").unwrap();
  let host_tmp = std::env::temp_dir().join(format!("arkham-host-marker-{}", std::process::id()));
  std::fs::write(&host_tmp, "HOST-TMP-MARKER\n").unwrap();

  let script = root.join("probe.sh");
  write_probe(&script, &outside_hard, &outside_sym, &age, &host_tmp);
  let _daemon = Daemon::start(&isolated);
  let stdout = root.join("stdout.txt");
  let stderr = root.join("stderr.txt");
  let mut child = isolated
    .command(&["agent", "--isolate", "bwrap", "--", "sh", "probe.sh"])
    .current_dir(root)
    .env("HTTP_PROXY", "http://wrapper-proxy.invalid")
    .stdout(File::create(&stdout).unwrap())
    .stderr(File::create(&stderr).unwrap())
    .spawn()
    .unwrap();
  let status = wait_child(&mut child, Duration::from_secs(120));
  let out = std::fs::read_to_string(&stdout).unwrap();
  let err = std::fs::read_to_string(&stderr).unwrap();
  assert!(status.success(), "status {status:?}\nstdout:\n{out}\nstderr:\n{err}");
  assert!(err.contains("enforcement: full"), "{err}");
  assert!(!out.contains("REAL_SECRET_VALUE"), "{out}");
  assert!(!out.contains("AGE-SECRET-KEY-REAL"), "{out}");
  assert!(!out.contains("PRIVATE KEY"), "{out}");

  for label in ["FILE", "LOCAL", "IMPORT", "HARD", "SYM", "OUTHARD", "OUTSYM"] {
    let line = line_of(&out, label);
    assert!(!line.is_empty(), "{label} was empty\n{out}");
    assert!(!line.contains("REAL_SECRET_VALUE"), "{label}: {line}");
    assert!(line.contains("arkham-decoy"), "{label}: {line}");
  }
  let ca = line_of(&out, "CA");
  assert!(ca.contains("BEGIN CERTIFICATE"), "{ca}");
  assert!(!ca.contains("PRIVATE KEY"), "{ca}");
  assert_eq!(line_of(&out, "SSL"), "/arkham/ca.pem");
  assert_eq!(line_of(&out, "NODE"), "/arkham/ca.pem");
  assert_eq!(line_of(&out, "REQ"), "/arkham/ca.pem");
  assert!(line_of(&out, "CGROUP").contains("arkham-host"), "{out}");
  assert_ne!(line_of(&out, "OUTSIDE"), "0", "a path outside the workspace was writable");
  assert_ne!(line_of(&out, "WRITE"), "0", "the forged file accepted a write");
  assert_ne!(line_of(&out, "AGEWRITE"), "0", "the age file accepted a write");
  assert!(line_of(&out, "AGE").contains("ARKHAM-DECOY-KEY"), "{out}");
  assert!(!line_of(&out, "AGE").contains("AGE-SECRET-KEY-REAL"), "{out}");
  assert!(!line_of(&out, "TMP").contains("HOST-TMP-MARKER"), "{out}");
  assert_eq!(line_of(&out, "WROTE"), "ok");

  let env_out = std::fs::read_to_string(root.join("env-out")).unwrap();
  let lowered = env_out.to_ascii_lowercase();
  assert!(!lowered.contains("http_proxy"), "{env_out}");
  assert!(!lowered.contains("https_proxy"), "{env_out}");
  assert!(!lowered.contains("all_proxy"), "{env_out}");
  assert!(!outside_hard_changed(&outside_hard), "hard link write reached the host");
  assert_eq!(
    std::fs::read_to_string(root.join("fnox.toml")).unwrap(),
    format!("import = [\"imported.toml\"]\n{secret}")
  );
  assert_eq!(std::fs::read_to_string(&age).unwrap(), "AGE-SECRET-KEY-REAL\n");
  assert!(!isolated.home.path().join("outside-probe").exists());
  assert!(!std::env::temp_dir().join(format!("from-agent-{}", std::process::id())).exists());
  assert_eq!(std::fs::read_to_string(&host_tmp).unwrap(), "HOST-TMP-MARKER\n");
  let _ = std::fs::remove_file(&host_tmp);
}

fn outside_hard_changed(path: &Path) -> bool {
  std::fs::read_to_string(path).unwrap().contains("pwned")
}

fn line_of(output: &str, label: &str) -> String {
  output
    .lines()
    .find_map(|line| line.strip_prefix(&format!("{label}:")))
    .unwrap_or("")
    .to_string()
}

fn write_probe(path: &Path, outside_hard: &Path, outside_sym: &Path, age: &Path, host_tmp: &Path) {
  let script = format!(
    r#"set +e
one() {{ printf '%s\n' "$1:$(cat "$2" 2>/dev/null | tr '\n' ' ')"; }}
one FILE fnox.toml
one LOCAL .fnox.local.toml
one IMPORT imported.toml
one HARD secret-hard
one SYM secret-symlink
one OUTHARD {outside_hard}
one OUTSYM {outside_sym}
one CA /arkham/ca.pem
one AGE {age}
printf '%s\n' "SSL:$SSL_CERT_FILE"
printf '%s\n' "NODE:$NODE_EXTRA_CA_CERTS"
printf '%s\n' "REQ:$REQUESTS_CA_BUNDLE"
printf '%s\n' "CGROUP:$(tr '\n' ' ' < /proc/self/cgroup)"
printf '%s\n' "TMP:$(cat {host_tmp} 2>/dev/null | tr '\n' ' ')"
touch "$HOME/outside-probe"
printf '%s\n' "OUTSIDE:$?"
printf '%s\n' pwned > fnox.toml
printf '%s\n' "WRITE:$?"
printf '%s\n' pwned > {age}
printf '%s\n' "AGEWRITE:$?"
printf '%s\n' agent-tmp > /tmp/from-agent-{pid}
env | sort > env-out
printf '%s\n' ok > workspace-write
printf '%s\n' "WROTE:$(cat workspace-write)"
exit 0
"#,
    outside_hard = outside_hard.display(),
    outside_sym = outside_sym.display(),
    age = age.display(),
    host_tmp = host_tmp.display(),
    pid = std::process::id(),
  );
  let mut file = File::create(path).unwrap();
  file.write_all(script.as_bytes()).unwrap();
}
