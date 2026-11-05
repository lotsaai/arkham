//! Linux host-backend acceptance. These run under nextest without root.
//! Bubblewrap has to win the probe: a Landlock-only result is a failure,
//! because the projection checks need the bind mounts.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
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
  assert!(err.contains("runner: bwrap"), "{err}");
  assert!(err.contains("enforcement: full"), "{err}");
  assert!(!out.contains("REAL_SECRET_VALUE"), "{out}");
  assert!(!out.contains("AGE-SECRET-KEY-REAL"), "{out}");
  assert!(!out.contains("PRIVATE KEY"), "{out}");

  for label in ["FILE", "LOCAL", "IMPORT", "HARD", "SYM"] {
    let line = line_of(&out, label);
    assert!(!line.is_empty(), "{label} was empty\n{out}");
    assert!(!line.contains("REAL_SECRET_VALUE"), "{label}: {line}");
    assert!(line.contains("arkham-decoy"), "{label}: {line}");
  }
  for label in ["OUTHARD", "OUTSYM"] {
    let line = line_of(&out, label);
    assert!(!line.contains("REAL_SECRET_VALUE"), "{label}: {line}");
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

#[test]
fn agent_with_bwrap_unavailable_starts_nothing_and_hides_the_secret() {
  let isolated = Isolated::new();
  let workspace = tempfile::tempdir().unwrap();
  let secret = "# REAL_SECRET_VALUE\n";
  std::fs::write(workspace.path().join("fnox.toml"), secret).unwrap();
  let fake = tempfile::tempdir().unwrap();
  std::fs::write(fake.path().join("bwrap"), "#!/bin/sh\nexit 1\n").unwrap();
  std::fs::set_permissions(fake.path().join("bwrap"), std::fs::Permissions::from_mode(0o755)).unwrap();
  let mut path = fake.path().as_os_str().to_os_string();
  path.push(":");
  path.push(&isolated.path);
  let _daemon = Daemon::start(&isolated);
  let output = isolated
    .command(&["agent", "--isolate", "bwrap", "--", "cat", "fnox.toml"])
    .current_dir(workspace.path())
    .env("PATH", path)
    .output()
    .unwrap();
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(!output.status.success(), "agent started without bubblewrap\n{stdout}{stderr}");
  assert!(
    !stdout.contains("REAL_SECRET_VALUE") && !stderr.contains("REAL_SECRET_VALUE"),
    "{stdout}{stderr}"
  );
}

#[test]
fn no_child_runs_when_neither_probe_accepts() {
  let isolated = Isolated::new();
  let workspace = tempfile::tempdir().unwrap();
  std::fs::write(workspace.path().join("fnox.toml"), "# REAL_SECRET_VALUE\n").unwrap();
  let marker = workspace.path().join("ran");
  let fake = tempfile::tempdir().unwrap();
  std::fs::write(fake.path().join("bwrap"), "#!/bin/sh\nexit 1\n").unwrap();
  std::fs::set_permissions(fake.path().join("bwrap"), std::fs::Permissions::from_mode(0o755)).unwrap();
  let mut path = fake.path().as_os_str().to_os_string();
  path.push(":");
  path.push(&isolated.path);
  let _daemon = Daemon::start(&isolated);
  let output = isolated
    .command(&["agent", "--isolate", "bwrap", "--", "touch", marker.to_str().unwrap()])
    .current_dir(workspace.path())
    .env("PATH", path)
    .output()
    .unwrap();
  assert!(!output.status.success(), "{output:?}");
  assert!(!marker.exists(), "a child ran after both probes failed");
}

#[test]
fn fnox_projection_names_are_forged() {
  let isolated = Isolated::new();
  let workspace = tempfile::tempdir().unwrap();
  let root = workspace.path();
  let secret = "# REAL_SECRET_VALUE\n";
  std::fs::write(root.join(".fnox.toml"), secret).unwrap();
  std::fs::write(root.join(".fnox.work.toml"), secret).unwrap();
  std::fs::write(isolated.fnox_dir.path().join("config.toml"), secret).unwrap();
  let script = root.join("names.sh");
  std::fs::write(
    &script,
    format!(
      "one() {{ printf '%s\\n' \"$1:$(cat \"$2\" 2>/dev/null | tr '\\n' ' ')\"; }}\none DOT .fnox.toml\none PROFILE .fnox.work.toml\none GLOBAL {}\n",
      isolated.fnox_dir.path().join("config.toml").display()
    ),
  )
  .unwrap();
  let _daemon = Daemon::start(&isolated);
  let output = isolated
    .command(&["agent", "--isolate", "bwrap", "--", "sh", "names.sh"])
    .current_dir(root)
    .output()
    .unwrap();
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(output.status.success(), "{stdout}{stderr}");
  for label in ["DOT", "PROFILE", "GLOBAL"] {
    let line = line_of(&stdout, label);
    assert!(line.contains("arkham-decoy"), "{label}: {line}\n{stdout}");
    assert!(!line.contains("REAL_SECRET_VALUE"), "{label}: {line}");
  }
}

#[test]
fn the_secret_set_does_not_change_after_launch() {
  let isolated = Isolated::new();
  let workspace = tempfile::tempdir().unwrap();
  let other = tempfile::tempdir().unwrap();
  let root = workspace.path();
  std::fs::write(root.join("fnox.toml"), "# REAL_SECRET_VALUE\n").unwrap();
  std::fs::write(other.path().join("fnox.toml"), "OTHER_SECRET_MARKER\n").unwrap();
  let ready = root.join("ready");
  let go = root.join("go");
  let script = root.join("hold.sh");
  std::fs::write(
    &script,
    format!(
      "echo ready > '{}'\nwhile [ ! -f '{}' ]; do sleep 0.05; done\ncat fnox.toml\necho ---\ncat '{}' 2>/dev/null || true\n",
      ready.display(),
      go.display(),
      other.path().join("fnox.toml").display()
    ),
  )
  .unwrap();
  let _daemon = Daemon::start(&isolated);
  let mut child = isolated
    .command(&["agent", "--isolate", "bwrap", "--", "sh", "hold.sh"])
    .current_dir(root)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
  let started = Instant::now();
  while !ready.exists() {
    if started.elapsed() > Duration::from_secs(30) {
      let _ = child.kill();
      panic!("session did not become ready");
    }
    std::thread::sleep(Duration::from_millis(20));
  }
  std::fs::write(root.join("fnox.toml"), "NEW_SECRET_MARKER\n").unwrap();
  std::fs::write(other.path().join("fnox.toml"), "OTHER_SECRET_MARKER\n").unwrap();
  std::fs::write(&go, "go\n").unwrap();
  let output = child.wait_with_output().unwrap();
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(output.status.success(), "{stdout}{stderr}");
  assert!(stdout.contains("arkham-decoy"), "{stdout}");
  assert!(!stdout.contains("NEW_SECRET_MARKER"), "{stdout}");
  assert!(!stdout.contains("OTHER_SECRET_MARKER"), "{stdout}");
  assert!(
    !stderr.contains("NEW_SECRET_MARKER") && !stderr.contains("OTHER_SECRET_MARKER"),
    "{stderr}"
  );
}

#[test]
fn a_peer_with_the_wrong_uid_gets_no_plan() {
  let isolated = Isolated::new();
  let workspace = tempfile::tempdir().unwrap();
  std::fs::write(workspace.path().join("fnox.toml"), "REAL_SECRET_VALUE\n").unwrap();
  let _daemon = Daemon::start(&isolated);
  let sock = isolated.runtime.path().join("arkham").join("daemon.sock");
  std::fs::set_permissions(isolated.runtime.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
  std::fs::set_permissions(isolated.runtime.path().join("arkham"), std::fs::Permissions::from_mode(0o755)).unwrap();
  std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o777)).unwrap();
  let output = Command::new("sudo")
    .args([
      "-n",
      "-u",
      "nobody",
      "python3",
      "-c",
      "import socket,sys\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\ns.settimeout(5)\ns.connect(sys.argv[1])\ns.sendall(b'{\"cwd\":\"/tmp\",\"profile\":\"workspace-write\"}\\n')\nsys.stdout.buffer.write(s.recv(65536))\n",
      sock.to_str().unwrap(),
    ])
    .output()
    .unwrap();
  let text = String::from_utf8_lossy(&output.stdout);
  let err = String::from_utf8_lossy(&output.stderr);
  assert!(output.status.success(), "{text}{err}");
  assert!(!text.contains("\"plan\""), "{text}");
  assert!(!text.contains("REAL_SECRET_VALUE"), "{text}");
}

#[test]
fn a_hijacked_fallback_socket_directory_is_refused() {
  let uid = current_uid();
  let dir = format!("/tmp/arkham-{uid}");
  let _cleanup = SudoRemove(dir.clone());
  let removed = Command::new("sudo").args(["-n", "rm", "-rf", &dir]).status().unwrap();
  assert!(removed.success(), "could not clear {dir}");
  let made = Command::new("sudo")
    .args(["-n", "-u", "nobody", "mkdir", "-p", &dir])
    .status()
    .unwrap();
  assert!(made.success(), "could not plant {dir}");
  let isolated = Isolated::new();
  let mut child = isolated
    .command(&["daemon"])
    .env_remove("XDG_RUNTIME_DIR")
    .env("ARKHAM_LISTEN", "127.0.0.1:0")
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
  let mut stderr = child.stderr.take().unwrap();
  let mut buf = Vec::new();
  let started = Instant::now();
  let mut byte = [0u8; 1];
  while started.elapsed() < Duration::from_secs(5) {
    if stderr.read(&mut byte).unwrap_or(0) == 0 {
      break;
    }
    buf.push(byte[0]);
    if buf.windows(13).any(|window| window == b"daemon: ready") {
      break;
    }
  }
  let _ = child.kill();
  let _ = child.wait();
  let text = String::from_utf8_lossy(&buf);
  assert!(!text.contains("daemon: ready"), "{text}");
}

#[test]
fn a_root_owned_cgroup_names_the_denial_and_hides_the_secret() {
  let isolated = Isolated::new();
  let workspace = tempfile::tempdir().unwrap();
  let secret = "# REAL_SECRET_VALUE\n";
  std::fs::write(workspace.path().join("fnox.toml"), secret).unwrap();
  let daemon = Daemon::start(&isolated);
  let pid = daemon.child.id().to_string();
  let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
  let rel = cgroup.lines().find_map(|line| line.strip_prefix("0::")).unwrap();
  let parent = PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
  let locked = parent.join(format!("arkham-locked-{}", std::process::id()));
  let locked_arg = locked.to_str().unwrap().to_string();
  let made = Command::new("sudo").args(["-n", "mkdir", "-p", &locked_arg]).status().unwrap();
  assert!(made.success(), "mkdir {locked_arg}");
  for args in [["chown", "root:root", locked_arg.as_str()], ["chmod", "755", locked_arg.as_str()]] {
    let status = Command::new("sudo").arg("-n").args(args).status().unwrap();
    assert!(status.success(), "{args:?}");
  }
  let _locked = CgroupDir(locked.clone());
  let procs = locked.join("cgroup.procs");
  let mut migrate = Command::new("sudo")
    .args(["-n", "tee", procs.to_str().unwrap()])
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
  let mut stdin = migrate.stdin.take().unwrap();
  stdin.write_all(pid.as_bytes()).unwrap();
  drop(stdin);
  let wrote = migrate.wait_with_output().unwrap();
  assert!(wrote.status.success(), "{}", String::from_utf8_lossy(&wrote.stderr));
  let output = isolated
    .command(&["agent", "--isolate", "bwrap", "--", "cat", "fnox.toml"])
    .current_dir(workspace.path())
    .output()
    .unwrap();
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(!output.status.success(), "{stdout}{stderr}");
  assert!(stderr.contains("session cgroup"), "{stderr}");
  assert!(stderr.to_ascii_lowercase().contains("permission denied"), "{stderr}");
  assert!(
    !stdout.contains("REAL_SECRET_VALUE") && !stderr.contains("REAL_SECRET_VALUE"),
    "{stdout}{stderr}"
  );
  drop(daemon);
}

struct CgroupDir(PathBuf);

impl Drop for CgroupDir {
  fn drop(&mut self) {
    if let Ok(text) = std::fs::read_to_string(self.0.join("cgroup.procs")) {
      for pid in text.split_whitespace() {
        let _ = Command::new("sudo").args(["-n", "kill", "-9", pid]).status();
      }
    }
    let _ = Command::new("sudo").args(["-n", "rmdir", &self.0.to_string_lossy()]).status();
  }
}

#[test]
fn the_wrapper_refuses_a_socket_it_does_not_own() {
  let isolated = Isolated::new();
  let workspace = tempfile::tempdir().unwrap();
  std::fs::write(workspace.path().join("fnox.toml"), "# REAL_SECRET_VALUE\n").unwrap();
  let _daemon = Daemon::start(&isolated);
  let sock = isolated.runtime.path().join("arkham").join("daemon.sock");
  std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).unwrap();
  let chown = Command::new("sudo")
    .args(["-n", "chown", "nobody", sock.to_str().unwrap()])
    .status()
    .unwrap();
  assert!(chown.success(), "chown failed");
  let output = isolated
    .command(&["agent", "--isolate", "bwrap", "--", "cat", "fnox.toml"])
    .current_dir(workspace.path())
    .output()
    .unwrap();
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(!output.status.success(), "{stdout}{stderr}");
  assert!(
    !stdout.contains("REAL_SECRET_VALUE") && !stderr.contains("REAL_SECRET_VALUE"),
    "{stdout}{stderr}"
  );
  assert!(!stderr.contains("enforcement:"), "{stderr}");
}

#[test]
fn bwrap_registers_the_workspace_argument() {
  let isolated = Isolated::new();
  let here = tempfile::tempdir().unwrap();
  let there = tempfile::tempdir().unwrap();
  std::fs::write(here.path().join("marker.txt"), "FROM-HERE\n").unwrap();
  std::fs::write(there.path().join("marker.txt"), "FROM-THERE\n").unwrap();
  std::fs::write(there.path().join("fnox.toml"), "# workspace\n").unwrap();
  let _daemon = Daemon::start(&isolated);
  let output = isolated
    .command(&[
      "agent",
      "--isolate",
      "bwrap",
      there.path().to_str().unwrap(),
      "--",
      "cat",
      "marker.txt",
    ])
    .current_dir(here.path())
    .output()
    .unwrap();
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(output.status.success(), "{stdout}{stderr}");
  assert!(stdout.contains("FROM-THERE"), "{stdout}");
  assert!(!stdout.contains("FROM-HERE"), "{stdout}");
}

#[test]
fn a_symlinked_fnox_toml_and_its_target_are_forged() {
  let isolated = Isolated::new();
  let workspace = tempfile::tempdir().unwrap();
  let root = workspace.path();
  let vault = root.join("vault");
  std::fs::create_dir(&vault).unwrap();
  let real = vault.join("real.toml");
  std::fs::write(&real, "# REAL_SECRET_VALUE\n").unwrap();
  std::os::unix::fs::symlink(&real, root.join("fnox.toml")).unwrap();
  std::fs::hard_link(&real, vault.join("alias.toml")).unwrap();
  let script = root.join("links.sh");
  std::fs::write(
    &script,
    "one() { printf '%s\\n' \"$1:$(cat \"$2\" 2>/dev/null | tr '\\n' ' ')\"; }\none LINK fnox.toml\none TARGET vault/real.toml\none HARD vault/alias.toml\n",
  )
  .unwrap();
  let _daemon = Daemon::start(&isolated);
  let output = isolated
    .command(&["agent", "--isolate", "bwrap", "--", "sh", "links.sh"])
    .current_dir(root)
    .output()
    .unwrap();
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(output.status.success(), "{stdout}{stderr}");
  for label in ["LINK", "TARGET", "HARD"] {
    let line = line_of(&stdout, label);
    assert!(line.contains("arkham-decoy"), "{label}: {line}\n{stdout}");
    assert!(!line.contains("REAL_SECRET_VALUE"), "{label}: {line}");
  }
}

#[test]
fn a_prepare_error_does_not_reach_the_wrapper() {
  let isolated = Isolated::new();
  let workspace = tempfile::tempdir().unwrap();
  let root = workspace.path();
  let marker = "MARKER_SECRET_FRAGMENT_9f3a";
  std::fs::create_dir_all(root.join(".config/arkham")).unwrap();
  std::fs::write(root.join(format!("{marker}.yaml")), format!("not: [yaml\n{marker}\n")).unwrap();
  std::fs::write(
    root.join(".config/arkham/config.toml"),
    format!("[[workspace.file_rewrite]]\nsource = \"{marker}.yaml\"\ndest = \"/opt/kube.yaml\"\nformat = \"kubeconfig\"\n"),
  )
  .unwrap();
  let _daemon = Daemon::start(&isolated);
  let output = isolated
    .command(&["agent", "--isolate", "bwrap", "--", "true"])
    .current_dir(root)
    .output()
    .unwrap();
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(!output.status.success(), "{stdout}{stderr}");
  assert!(!stdout.contains(marker) && !stderr.contains(marker), "{stdout}{stderr}");
}

struct SudoRemove(String);

impl Drop for SudoRemove {
  fn drop(&mut self) {
    let _ = Command::new("sudo").args(["-n", "rm", "-rf", &self.0]).status();
  }
}

fn current_uid() -> u32 {
  let status = std::fs::read_to_string("/proc/self/status").unwrap();
  status
    .lines()
    .find_map(|line| line.strip_prefix("Uid:"))
    .unwrap()
    .split_whitespace()
    .next()
    .unwrap()
    .parse()
    .unwrap()
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
