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
| `--proxy-backend <BACKEND>` | `ARKHAM_PROXY_BACKEND` | Transparent capture backend: `none` (default, explicit listener only), `tun`, `tproxy`, or `ebpf`. Linux only; every backend is compiled in, so no build flags are needed. |
| `--tproxy-allow-root-netns` | `ARKHAM_TPROXY_ALLOW_ROOT_NETNS` | With `--proxy-backend tproxy`, allow unscoped capture rules in the host network namespace. Disposable machines only. |
| `--ebpf-cgroup <PATH>` | `ARKHAM_EBPF_CGROUP` | With `--proxy-backend ebpf`, the cgroup v2 directory whose member processes get captured, or the literal `enclosing` for the cgroup this process's own cgroup lives under (what a compose stack with one `cgroup_parent` per service uses). Required for that backend; otherwise arkham itself must live outside the named cgroup. |
| `--ebpf-bypass <CIDR>` | `ARKHAM_EBPF_BYPASS` | With `--proxy-backend ebpf`, extra CIDRs that are never captured. Repeat the flag, or separate values with commas. Linux only. |
| `--ebpf-bypass-file <PATH>` | `ARKHAM_EBPF_BYPASS_FILE` | With `--proxy-backend ebpf`, a file of bypass CIDRs, one per line, re-read while capture runs. |

`--proxy-backend`, `--tproxy-allow-root-netns`, `--ebpf-cgroup`, `--ebpf-bypass`, and `--ebpf-bypass-file` are CLI and environment only, deliberately absent from config files. Capture mutates host routes, nft rules, and kernel programs, so enabling it is an explicit act, not ambient configuration.

What each backend does:

| Backend | Mechanism | UDP |
| --- | --- | --- |
| `tproxy` | nftables rules and policy routes hand TCP to an `IP_TRANSPARENT` listener. Needs `CAP_NET_ADMIN`. | Passes through untouched, except QUIC on `:443`, which is dropped so HTTP/3 clients fall back to TCP. |
| `tun` | A TUN device plus an in-process TCP/IP stack. Needs root. | Relayed inside arkham: DNS to the system resolver, QUIC dropped, other flows to their original destination. |
| `ebpf` | cgroup v2 socket hooks (`connect4`, `recvmsg4`, and an egress hook) rewrite destinations to arkham's loopback listeners. No netfilter, no policy routes, no `IP_TRANSPARENT`. Needs `CAP_BPF` + `CAP_NET_ADMIN`, and a cgroup holding the workload with arkham outside it. | Connected UDP only (what a `connect()`ed socket sends) is relayed unchanged. Unconnected `sendto` traffic such as typical DNS is never captured. |

All three are peers: same interception contract (a captured connection's destination is its identity), different mechanism. `tun` is the one to reach for when you need the UDP path handled; `tproxy` when you want the kernel to terminate TCP with nftables you can inspect; `ebpf` when you want no netfilter rules on the host and are scoping capture by cgroup rather than by network namespace. The eBPF backend's attach handles are owned by the process, so exit detaches the programs and leaves no host state behind.

Kernel floor for `ebpf` is 5.15, and it is IPv4-only. Capture is scoped to arkham's own network namespace: containers the agent spawns — inner compose stacks, podman — carry their own namespaces and are left alone, while egress through the agent's namespace stays captured.

The listener binds before any capture side effect, so a bad listen address fails before routes, nft rules, or kernel programs touch the host. A failed capture leg ends the process rather than silently serving explicit-proxy only.

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

## `arkham init [--backend <BACKEND>] [WORKSPACE]`

Generate the workspace stack as editable files: the CA and the agent entrypoint when they are missing, and `<state-dir>/arkham/ws/<slug>/compose.yml`. Rules are not written anywhere: they derive at serve time from fnox declarations the registry knows, and config holds overrides only. Nothing existing is overwritten; the stack is regenerated when the workspace config or the generator's stack shape changed since it was generated. `--backend` picks the capture backend (`ebpf` by default, Linux only) and only applies to a stack that does not exist yet — a regeneration keeps the backend the stack already runs. Prints a warning when no rule is in play, since then nothing would be substituted.

## `arkham agent [WORKSPACE] [--rm] [-- <COMMAND>...]`

The whole lifecycle in one idempotent run: what `init` does, then `up`, then the configured shell (or `COMMAND`) in the agent. The stack keeps running when that exits, so the next call starts at the exec. `--rm` stops the stack instead: teardown runs after the shell or command exits, including when the terminal's interrupt ends it.

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
