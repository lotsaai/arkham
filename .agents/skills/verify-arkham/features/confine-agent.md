# Confined agent session

`arkham daemon run` holds the real values and captures traffic with eBPF. `arkham agent -- <command>` runs the command under bubblewrap and Landlock with decoy env, and its unproxied connections to granted hosts carry the real value upstream while the agent only sees the decoy.

## Sub-features

- `agent-confined` agent stderr reports `runner: bwrap` and `enforcement: full`.
- `agent-decoy-env` the fnox-declared, registry-known name holds its decoy inside the sandbox.
- `agent-captured-swap` plain `curl`, no proxy setting: the upstream records the real value and the agent gets the decoy back.
- `agent-no-leak` the real value appears nowhere in the agent's output.

## How to get to it (user POV)

- confine-a-workspace how-to: `arkham daemon run`, then `arkham agent` or `arkham agent -- <cmd>` from the workspace.

## Driving it with mise tasks

- **Run.** `mise run verify:agent`.
- **Observe.** `agent-stdout.txt`, `agent-stderr.txt`, `upstream-seen.txt`, `daemon.log`.
- **Pass when.** `PASS agent`.
- **Refusals and hiding.** `mise run --force test` runs `tests/host_linux.rs` (`bwrap_hides_secret_files_and_proxy_env`, `agent_refuses_to_start_without_a_daemon`, `the_sandbox_cannot_read_the_home_credential_or_the_ca_key`, …).

## Gotchas

- Decoy env comes only from fnox-declared names the registry knows. A config rule with an inline `value` grants but sets no env var.
- Loopback is never captured; the task runs the upstream in a container.
- The task grants the daemon binary its eBPF file capabilities the way `test:rust` does and removes them on exit. It refuses when a daemon already serves `$XDG_RUNTIME_DIR/arkham/daemon.sock`.
