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
| `--ca-file <PATH>` | `ARKHAM_CA_FILE` | CA PEM path (certificate followed by key). Default `/certs/ca.pem` when the generated stack mounted it there, else `<config-dir>/arkham/ca.pem`. |
| `--proxy-backend <BACKEND>` | `ARKHAM_PROXY_BACKEND` | Transparent capture backend: `none` (default, explicit listener only) or `ebpf` (Linux only). |
| `--ebpf-cgroup <PATH>` | `ARKHAM_EBPF_CGROUP` | With `--proxy-backend ebpf`, the cgroup v2 directory whose member processes get captured, or the literal `enclosing` for the cgroup this process's own cgroup lives under (what a compose stack with one `cgroup_parent` per service uses). Required for that backend; otherwise arkham itself must live outside the named cgroup. |
| `--ebpf-bypass <CIDR>` | `ARKHAM_EBPF_BYPASS` | With `--proxy-backend ebpf`, extra CIDRs that are never captured. Repeat the flag, or separate values with commas. Linux only. |
| `--ebpf-bypass-file <PATH>` | `ARKHAM_EBPF_BYPASS_FILE` | With `--proxy-backend ebpf`, a file of bypass CIDRs, one per line, re-read while capture runs. |

The eBPF backend uses cgroup v2 socket hooks to redirect traffic to arkham's loopback listeners. Connected UDP is relayed unchanged. Unconnected `sendto` traffic such as typical DNS is not captured. The process owns the attachment handles, so exit detaches the programs without leaving netfilter or routing state.

The kernel floor for `ebpf` is 5.15. It captures IPv4 and IPv6. Hosts without IPv6 support run IPv4-only and log that once; IPv6 listener or hook failures on a capable host stop startup. Capture is scoped to arkham's own network namespace. Containers the agent spawns with separate network namespaces are left alone, while egress through the agent's namespace stays captured. Loopback and configured bypass destinations are excluded.

The listener binds before capture attaches kernel programs. A failed capture leg ends the process rather than silently serving explicit-proxy only.

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

## `arkham init [WORKSPACE]`

Generate the workspace stack: the CA and the agent entrypoint when they are missing, and `<state-dir>/arkham/ws/<slug>/compose.yml`. That compose file is generated state. Overrides go in `~/.config/arkham/compose.yaml` or `<workspace>/.config/arkham/compose.yaml`. Rules derive at serve time from fnox declarations the registry knows, and config holds overrides only. An existing stack is rewritten when the rendered file would change and left untouched when it matches. Prints a warning when no rule is in play.

## `arkham daemon`

Linux only. One loopback proxy and a per-user control socket for host-confined agents. A non-loopback `ARKHAM_LISTEN` is refused, and a second daemon exits when one is already listening. Prints `daemon: ready` on stderr once the socket is bound.

## `arkham agent [WORKSPACE] [--rm] [--isolate <compose|bwrap>] [--write-profile <PROFILE>] [-- <COMMAND>...]`

The whole lifecycle in one idempotent run: what `init` does, then `up`, then the configured shell (or `COMMAND`) in the agent. The stack keeps running when that exits, so the next call starts at the exec. `--rm` stops the stack instead: teardown runs after the shell or command exits, including when the terminal's interrupt ends it.

`--isolate` defaults to `compose`. `--isolate bwrap` (Linux) does not start a stack. It requires a running `arkham daemon`, then runs `COMMAND` with decoy environment and forged secret files. `--write-profile` is `workspace-write` (the default), `read-only`, or `danger-full-access`. Stderr reports `runner: bwrap` and `enforcement: full`. With no daemon, when bubblewrap cannot run the profile, or when Landlock does not fully enforce it, the command starts nothing. `danger-full-access` does not apply Landlock.

## `arkham up [WORKSPACE]`

Start the layered compose project `arkham init` generated, creating the CA and entrypoint if they are still missing. `WORKSPACE` defaults to the current directory; when no layer file exists, the compose command refuses rather than guess.

## `arkham expose <PORT> [--host <HOST>] [--workspace <PATH>]` / `arkham expose --list`

Publish container port `PORT` on `127.0.0.1`. `--host` defaults to `PORT`. `--workspace` defaults to the current directory. The command claims that host port across workspaces, adds `[[workspace.expose]]` when that mapping is absent, regenerates, and runs `up`. A host port another workspace already claimed fails and names that workspace. `--list` prints this workspace's publishings and every workspace's claims, and changes nothing.

## `arkham down [WORKSPACE]`

Stop the layered compose project.

## `arkham logs [-f] [--no-log-prefix] [--tail <N>] [--workspace <PATH>] [SERVICE...]`

Read the stack's logs. `--tail` defaults to `all`; no service means every service. `--workspace` defaults to the current directory and is a flag rather than a positional because the service names already take that slot.

See [how to secure your workspace](../how-to/confine-a-workspace.md).

## `arkham fwd`

Sidecar of the generated compose stack, not a user command: it runs on the `fwd` service with arkham's network namespace and the agent's PID namespace, forwards every agent-owned loopback listener to the namespace's own bridge address (the one the host reaches and docker publishes to), and relays raw bytes without inspecting payloads. Anything not attributable to an agent process — arkham's own listeners, docker's embedded DNS — is never forwarded. Loopback listeners only; a listener already bound to a wildcard address is directly reachable and needs no forwarder. Two listeners sharing one port on different loopback addresses cannot both be exposed and are logged and skipped.

## Exit behaviour

Malformed client traffic closes the connection quietly; it never fails the process. Configuration errors, CA errors, and a failed capture leg fail startup or the process. Listening on a non-loopback address logs a warning: anyone reaching the port can trigger real-secret substitution.
