//! Project discovery and the pure checks the control plane applies.
//!
//! The cwd names a project. It does not authorize one. A session's project
//! is fixed at registration.

/// Field index of `starttime` in `/proc/<pid>/stat` after the `comm` field.
const STARTTIME_AFTER_COMM: usize = 19;

/// Parse `starttime` from a `/proc/<pid>/stat` line.
///
/// `comm` is wrapped in parentheses and may contain spaces, so the clock
/// tick is the 20th whitespace field after the last `)`.
#[must_use]
pub fn parse_starttime(stat: &str) -> Option<u64> {
  let rest = stat.rsplit_once(')')?.1;
  rest.split_whitespace().nth(STARTTIME_AFTER_COMM)?.parse().ok()
}

/// Whether a control peer's uid is the daemon's uid.
#[must_use]
pub fn peer_uid_allowed(peer: u32, daemon: u32) -> bool {
  peer == daemon
}

/// Whether `path` is already inside a daemon-managed cgroup.
///
/// A process there must not register again: the agent would be able to open
/// a second session.
#[must_use]
pub fn cgroup_is_confined(path: &str) -> bool {
  path.split('/').any(|part| part == "arkham-host")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn starttime_is_the_field_after_comm() {
    let stat = "123 (agent proc) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 999 0\n";
    assert_eq!(parse_starttime(stat), Some(999));
    assert_eq!(parse_starttime("no-paren"), None);
  }

  #[test]
  fn a_different_starttime_does_not_match() {
    let first = parse_starttime("1 (a) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 10 0").unwrap();
    let reused = parse_starttime("1 (b) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 11 0").unwrap();
    assert_ne!(first, reused);
  }

  #[test]
  fn only_the_daemon_uid_may_register() {
    assert!(peer_uid_allowed(1000, 1000));
    assert!(!peer_uid_allowed(1001, 1000));
  }

  #[test]
  fn a_session_cgroup_is_already_confined() {
    assert!(cgroup_is_confined("/user.slice/arkham-host/12-99"));
    assert!(!cgroup_is_confined("/user.slice/workload"));
  }
}
