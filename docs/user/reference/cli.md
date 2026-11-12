# CLI reference

Every subcommand, flag, and environment variable, as the binary accepts them. `serve` is the default when no subcommand is given.

## Global flags

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--config <FILE>` | `ARKHAM_CONFIG` | Config file replacing the project layer. |

## `arkham serve`

Serve the proxy.

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--listen <ADDR>` | `ARKHAM_LISTEN` | Explicit-proxy listen address. Default `127.0.0.1:8080`. |
| `--ca-file <PATH>` | `ARKHAM_CA_FILE` | CA PEM path (certificate followed by key). Default `<config-dir>/arkham/ca.pem`. |
| `--proxy-backend <BACKEND>` | `ARKHAM_PROXY_BACKEND` | Transparent capture backend: `none` (default, explicit listener only) or `ebpf` (Linux only). |
| `--ebpf-cgroup <PATH>` | `ARKHAM_EBPF_CGROUP` | With `--proxy-backend ebpf`, the cgroup v2 directory whose member processes get captured, or `enclosing` for the enclosing cgroup. Required for that backend; otherwise arkham itself must live outside the named cgroup. |
| `--ebpf-bypass <CIDR>` | `ARKHAM_EBPF_BYPASS` | With `--proxy-backend ebpf`, extra CIDRs that are never captured. Repeat the flag, or separate values with commas. Linux only. |
| `--ebpf-bypass-file <PATH>` | `ARKHAM_EBPF_BYPASS_FILE` | With `--proxy-backend ebpf`, a file of bypass CIDRs, one per line, re-read while capture runs. |

The eBPF backend uses cgroup v2 socket hooks to redirect traffic to arkham's loopback listeners. Connected UDP is relayed unchanged. Unconnected `sendto` traffic such as typical DNS is not captured. The process owns the attachment handles, so exit detaches the programs without leaving netfilter or routing state.

The kernel floor for `ebpf` is 5.15. It captures IPv4 and IPv6. Hosts without IPv6 support run IPv4-only and log that once; IPv6 listener or hook failures on a capable host stop startup. Capture is scoped to arkham's own network namespace. Containers the agent spawns with separate network namespaces are left alone, while egress through the agent's namespace stays captured. Loopback and configured bypass destinations are excluded.

With `--proxy-backend ebpf`, the `serving` log appears only after capture is active. A failed capture leg ends the process.

## `arkham fake <ENV> [--pattern <PATTERN>]`

Print the deterministic decoy for an env var name. `--pattern` overrides the registry-supplied shape for this invocation only. See [decoy patterns](decoy-patterns.md).

## `arkham schemes`

Print each URL scheme the proxy serves, one per line. The list is every `Scheme` variant.

## `arkham ca`

Generate or load the CA, print its certificate PEM to stdout, and write `ca.crt` and `ca.key` beside the CA file. The printed PEM is the trust anchor to install into workload containers; the private key stays in the CA file and in `ca.key`.

## `arkham rules`

Print `[rules.*]` blocks for the secrets this workspace can get: the intersection of fnox declarations and the known-host registry. Values resolve from fnox at serve time; the output carries env names only. Names the registry knows but states no hosts for are printed commented out; fnox declarations no registry entry covers are listed at the end.

## `arkham config`

Print a reference config. Each setting appears with its default and its doc comment. Load errors surface first. Secrets never appear.

## `arkham registry from-oidc <FILE> <SLUG> <ENV>` / `arkham registry from-openapi <FILE> <SLUG> <ENV>`

Curate an `oauth2` registry fragment from a saved discovery or OpenAPI document. `from-oidc` maps `token_endpoint` and `grant_types_supported`; `from-openapi` maps every `type: oauth2` security scheme and reports `openIdConnect` schemes as skipped. Both print a complete `[providers.<slug>]` TOML fragment to stdout for review and placement in `rules.d`; they never fetch, never write files, and never touch the bundled table. See [the registry reference](registry.md).

## `arkham daemon`

Linux only. One loopback proxy and a per-user control socket for host-confined agents. A non-loopback `ARKHAM_LISTEN` is refused, and a second daemon exits when one is already listening. Prints `daemon: ready` on stderr once the socket is bound and capture is active.

With no subcommand, prints help without starting anything. `arkham daemon run`
runs in the foreground. The Linux service commands use
`systemctl --user` and the unit name `arkham-daemon.service`:

| Subcommand | Behaviour |
| --- | --- |
| `run [--background]` | Run in the foreground, or start the installed user service with `--background` |
| `unit` | Print a user unit using the current executable's absolute path |
| `install` | Write `$XDG_CONFIG_HOME/systemd/user/arkham-daemon.service` (normally `~/.config/systemd/user/`) and reload the user manager; does not start or enable it |
| `start`, `stop`, `restart` | Control the installed service |
| `status` | Show systemd status, preserving its exit code |
| `enable`, `disable` | Control startup with the user manager, without starting or stopping it |
| `logs` | Follow the service's user journal |

Stopping or restarting the service terminates its active agent sessions.
`start` confirms process execution, not capture readiness; check the journal for
`daemon: ready`.

The user unit delegates its cgroup subtree. It does not grant privileges:
the installed executable still needs the Linux capabilities required for eBPF
capture (`CAP_BPF` and `CAP_NET_ADMIN`, and `CAP_PERFMON` where required by the
kernel). An administrator must provision these on a trusted installation.
Reinstalling the binary can clear file capabilities. Without them the daemon
fails closed. The unit does not use sudo.

Run `arkham daemon install`, then `arkham daemon enable` and
`arkham daemon start`. The user manager normally starts at login; running without
a login requires an administrator to enable lingering for the account.

## `arkham agent [WORKSPACE] [--write-profile <PROFILE>] [-- <COMMAND>...]`

Linux only. Requires a running `arkham daemon` under the same user. Runs the configured shell or `COMMAND` under bubblewrap with a decoy environment and forged secret files. `--write-profile` is `workspace-write` (the default), `read-only`, or `danger-full-access`. Stderr reports `runner: bwrap` and `enforcement: full`. With no daemon, when bubblewrap cannot run the profile, or when Landlock does not fully enforce it, the command starts nothing. `danger-full-access` does not apply Landlock.

See [how to secure your workspace](../how-to/confine-a-workspace.md).

## Exit behaviour

Malformed client traffic closes the connection quietly; it never fails the process. Configuration errors, CA errors, and a failed capture leg fail startup or the process. Listening on a non-loopback address logs a warning: anyone reaching the port can trigger real-secret substitution.
