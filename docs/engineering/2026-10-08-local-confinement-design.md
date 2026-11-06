# Local confinement without containers: full plan

Scope captured here: a local execution backend for `arkham agent` that confines the agent on the host with OS primitives instead of a container. Transparent traffic capture is the mechanism on all three OSes. Nothing about networking is imposed on the sandbox: no `HTTP_PROXY` or `HTTPS_PROXY` variables, no proxy flags, no cooperation from agent tooling. Those variables belong to the tools now, and the space only gets more crowded. The platform routes traffic into arkham whether the sandbox knows or not. Explicit proxy remains as a fallback and debug path only. This plan covers Linux, macOS, and Windows end to end. No track is parked.

## Constraints

1. The sandbox carries decoys only, delivered as env values. Env stays the secret-input channel. It must never carry network behavior.
2. Real secrets live in arkham processes. The sandbox never sees them.
3. One portable policy (write profiles), one renderer per OS for filesystem confinement, one capture design per OS.
4. Capture failure must not leak secrets. Agents hold decoys, so direct egress on capture failure sends decoys upstream and upstream rejects them. Breakage, not leakage. Substitution paths keep their fail-closed latches regardless.
5. Per-workspace secret sets must never union. Decoys are deterministic per env name (`fake_for` hashes the seed alone), so two workspaces sharing `GITHUB_TOKEN` mint the same fake for different reals. Selection of the secret set happens per connection before pairs are built. Unknown source splices with no swap.

## Current state, from source

- Confinement today is the compose stack. `generate_stack` (`crates/arkham-compose/src/stack.rs:461`) resolves `WorkspaceInputs`, selects decoys, writes rewrites, derives ambient sources, writes grants state, resolves profile mounts, and renders a `Stack`. The agent service holds decoys only. Arkham holds real secrets. `AgentArgs::run` (`crates/arkham-compose/src/confine.rs:842`) runs generate, start, then enter.
- The proxy is single tenant. `ProxyState` holds one `Arc<ResolvedConfig>` and one plugin registry, write once, no reload (`crates/arkham-proxy/src/lib.rs:63`). Routing is destination only via `grant.matches(scheme, host, port)`. The peer address is read for a debug log and never selects rules (`lib.rs:245`). No `Proxy-Authorization` handling exists anywhere in `arkham-proxy`.
- Linux capture exists. `arkham-tproxy` installs nftables rules plus policy routes over netlink (`crates/arkham-tproxy/src/nft.rs`, `route.rs`) and refuses unscoped host-namespace installs without an explicit flag (`error.rs:91`). `arkham-ebpf` attributes by cgroup membership plus PID check, with byte-explicit map structs. The Linux decision is eBPF: each sandbox lands in its own cgroup, capture attaches per cgroup, attribution is structural.
- Rama abstracts per-OS capture. Linux has `ip_transparent` socket options plus a tproxy connector layer (`rama-net/src/socket/opts.rs`, `socket/linux/tproxy.rs`). Windows has a WFP redirect-context reader (`socket/windows/tproxy.rs`): the redirect record is queried with `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`, our code provides the `WfpContextDecoder`, and an absent record (`WSAEINVAL`) means the socket was not redirected. macOS has the `rama-net-apple-networkextension` crate plus a full transparent-proxy example (`ffi/apple/examples/transparent_proxy`) with container app, system extension, signing scripts, and install flow.
- Public precedent for one policy with per-OS backends is Chromium: Linux combines namespaces with seccomp-bpf, macOS uses Seatbelt profiles (`sandbox/mac/seatbelt.cc`), and Windows combines a restricted token with a job object, a separate desktop, and integrity levels (`docs/design/sandbox.md`).

## Daemon and wrapper

Protection for host backends comes from a long-running daemon: a LaunchDaemon plus an optional menu-bar app on macOS, a systemd service plus an optional tray icon on Linux, and a Windows service plus an optional tray icon on Windows. The daemon owns the proxy and its project registry, the capture backend, and on macOS the `arkham` user and the FUSE mounts.

Agents start only through the required wrapper, `arkham agent -- <agent command>`. The wrapper connects to the running daemon, registers the session, and only then launches the agent confined: under bwrap or Landlock projections on Linux, and as the `arkham` user under Seatbelt with the FUSE projection on macOS. Both give the same boundary. If no daemon is running, the wrapper fails closed at once and starts no process. A daemon that starts after an agent was launched some other way does nothing for that agent: it was never registered, so it never gets confinement or substitution.

The wrapper's cwd is configuration, not authorization. It links the session's pid to a project before launch. Project discovery canonicalizes the cwd and resolves the project through code-workspace markers (a git repository, a Cargo workspace, and the other markers that crate walks). The nearest registered root is the ceiling and the fallback when no marker is found. A fnox file does not choose the project; it names the files to rewrite inside the enlisted project and its includes. The result contains the canonical start, so a directory symlink enlists the target's project and never the lexical parent. When the resolved root is the user's home directory, the session enlists nothing from home and uses the private `/tmp` tmpfs as its working directory and workspace. The project and its secret set are fixed when the session registers. Later cwd changes inside the agent never switch credentials.

## Write profiles

A profile names readable paths and writable paths for one workspace execution. Modes are `read-only` (deny writes, keep the `/dev/null` sink shells require) and `workspace-write` (writable workspace root plus a backend-defined temp area). A third spelling, `danger-full-access`, drops filesystem write and read restrictions only (no Landlock, Seatbelt, or token policy). It is orthogonal to secret protection: decoy env, forged secret files (`fnox.toml`, `fnox.*.toml`), and transparent capture still apply, so the agent still never holds a real secret. Network and process visibility stay outside this vocabulary: the network is governed by capture, not by policy flags. One shared helper derives the writable set, and every renderer plus every test reads that helper. No renderer invents its own roots.

Renderers are per OS. Linux runs bubblewrap. Landlock adds restrictions inside that sandbox and does not launch a process on its own. macOS uses Seatbelt. Windows uses the restricted-token runner. Bubblewrap probes once with the real profile (`true` under it, exit 0 wins). A failed probe refuses to start the agent. A Landlock error, or a ruleset that is not fully enforced, refuses to start the command. `danger-full-access` does not apply Landlock. That skip is the profile.

## Linux: eBPF capture with cgroup attribution

Each sandbox runs in its own cgroup. The eBPF programs (`arkham-ebpf-programs`: `connect4`, `recvmsg4`, `capture_egress`, `CONFIG` / `ORIG_DST` / `FLOW` maps) attach per cgroup, so flows arrive already attributed to a workspace. The userspace half hands accepted streams to `serve_transparent_stream`. No env vars, no proxy flags, no cooperation from the agent. Tools inside may set `HTTP_PROXY` to anything: the TCP connection itself is captured either way.

The bwrap invocation keeps the filesystem shape from the compose inputs (workspace root and `include` entries with their ro flags, `file_mounts` and guest mounts read only, `tool_mounts` with their flags, fnox binds and grants mounts never entering) plus `--unshare-pid --unshare-uts --unshare-ipc --die-with-parent --new-session`, the CA as a read-only bind with trust env pointers, and decoy env values. `--unshare-net` stays off: the sandbox shares the host stack and eBPF sees its flows through cgroup membership.

## macOS: arkham user, FUSE projection, NetworkExtension dispatcher

The agent runs as a dedicated local user, `arkham`. The OS user boundary is the primary wall: the agent cannot read the operator's home, keychain, 1Password, `~/.ssh`, or fnox identity because they belong to another user. Seatbelt narrows further on top of that. Nothing moves and there is no migrate step: the daemon owns the user, the FUSE mounts, and the proxy, and `arkham agent` registers the session with it (see Daemon and wrapper).

### User story

The operator runs `arkham agent` in `~/github/foo`. Arkham registers the project and its secret mapping with the controller, projects the enlisted roots into `/Users/arkham` through FUSE, and starts the agent as `arkham` in `/Users/arkham/github/foo` with decoy env only. The agent edits files and the edits land in the operator's real tree. It reads `fnox.toml`, finds a valid fnox setup, and every value resolves to a decoy. Its network traffic is captured by the system extension, attributed to the `arkham` user and the project, and substituted by the proxy. The operator's own tree, tools, and fnox keep working untouched.

### Filesystem: FUSE fake-data provider plus permission projections

A FUSE filesystem, built on macFUSE through libfuse3 (not FSKit), mounts each configured entry under `/Users/arkham`. Entries come in two kinds:

- `enlist`: broad source roots such as `~/wagyu` and `~/github`, mounted whole at the mirrored path (`/Users/arkham/wagyu`, `/Users/arkham/github`). The agent can search across them. Projects are subdirectories the registry knows.
- `mirror`: supporting tool state the agent needs, such as hindsight data and heimdall config, mounted at its usual location under `/Users/arkham`.

Each entry is read-only or writable. Files pass through to the operator's real tree, with one exception: secret files are forged. The initial set is `fnox.toml` and `fnox.*.toml`. A forged fnox file declares the same names with decoy values encrypted to a fresh age identity that exists only under `/Users/arkham`, so `fnox` inside the agent works and only ever yields decoys.

Reads of secret files are allowed by design. In practice an agent that finds a broken or unreadable fnox setup tries to fix its environment and uploads the file while doing so; that happened under the compose stack, where the workspace bind exposed the real `fnox.toml` to the agent even though the identity stayed hidden. The requirement is that every byte the agent can read is bogus, not that reads fail. Writes to forged files never reach the real file, so the agent cannot overwrite real config with decoys.

Everything outside the mounts is a permission projection: the `arkham` user's ownership and ACLs decide what is reachable at all, and a Seatbelt profile restricts writes to the mounts plus temp and denies `mach-lookup` to credential services. Seatbelt is defense in depth; the user boundary holds if `sandbox-exec` breaks.

### Network: one proxy, project registry, per-flow secret selection

Project isolation is not a goal. Guarding secrets is, which means knowing which secrets apply to which flow. The proxy follows the shared host shape (see Proxy shape): one process with a project registry. The controller registers and unregisters projects as `arkham agent` starts and exits.

Three components follow the rama example layout. A host controller app installs and manages the proxy profile through `NETransparentProxyManager` and owns the project registry and agent process table, pushed to the extension over XPC (`rama-net-apple-xpc`) and re-pushed on every extension start. A system extension implements `NETransparentProxyProvider` and links a Rust dispatcher through the rama C ABI bridge. The proxy accepts dispatched flows on a Unix socket, not loopback TCP.

Per-flow data path. `handleNewFlow` snapshots `NEFlowMetaData` (audit token, PID when set, bundle identifier, endpoints). The audit token carries the UID, so flows from the `arkham` user are agent flows; everything else bypasses. The agent process table (PIDs with start times) resolves the flow to a project. Project discovery works across broad enlisted roots: the controller reads the source process's cwd with `proc_pidinfo` (`PROC_PIDVNODEPATHINFO`), canonicalizes it, and resolves the project through code-workspace markers. The nearest registered root is the fallback when no marker is found. A fnox file does not choose the project. A resolved root that is the user's home directory is not enlisted; the workspace is the private `/tmp`. The dispatcher connects to the proxy over a Unix socket. The proxy checks the peer uid with getpeereid (macOS/BSD) or `SO_PEERCRED` (Linux) and admits only the Network Extension or daemon uid — not any loopback TCP client, and not a shared secret. The dispatcher then writes a PROXY header carrying the original destination plus a TLV naming the project, and relays bytes. The proxy selects the project's secret set before building substitution pairs; it never infers the project from a decoy value, because decoys are deterministic per env name and collide across projects. Interception rules stay TCP only and exclude loopback, private ranges, and DNS. Unattributed flows bypass and carry decoys only.

The CA follows the example: the sysext generates the MITM root into `/Library/Keychains/System.keychain` with boring TLS and the controller rotates or clears it over XPC. The agent trusts it through `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, and `REQUESTS_CA_BUNDLE`. Secrets never cross Apple-logged paths: the opaque provider config carries timeouts and exclusions only.

Packaging is an app bundle with the embedded extension, copied to `/Applications`, approved once under Filters and Proxies. Two signing tracks share one implementation: Apple Development for local work, Developer ID with notarize plus staple for distribution, distinct bundle IDs per track.

Verification: install developer signed with SIP on, prove an unattributed `curl` bypasses, prove an agent flow as `arkham` substitutes with zero proxy env set, prove the agent reads a forged `fnox.toml` while the operator reads the real one at the same project, prove writes to the forged file never reach the real one, and rotate the CA live over XPC.

## Windows: WFP callout driver plus Rama

Two parts with a hard responsibility split. A kernel callout driver decides what happens to traffic. Rama in userspace decides how redirected traffic is handled. The driver holds no proxy logic and no secrets.

Filters select TCP v4 and v6 while excluding loopback, private ranges, DNS, and UDP 443 (QUIC drops to force fallback, parity with the nft rules). The redirect callout sits at `ALE_CONNECT_REDIRECT`, where the destination can still change. Its classify function reads the originating process ID, looks it up in the driver-side process table arkham pushes (agent PID subtrees tagged per workspace), rewrites the destination to the proxy listener on `127.0.0.1`, attaches the redirect handle, and writes the context blob carrying the original destination plus the workspace tag. An `ALE_AUTH_CONNECT` callout owns allow-or-block decisions: QUIC drops, pinned-app bypasses, system-service exclusions. Unknown processes get no tag and their flows are permitted direct.

The proxy accepts the redirected socket, queries `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` on the socket, and decodes the record with arkham `WfpContextDecoder`: original destination and workspace tag out, the tag selecting the project's secret set. The flow then continues down the existing transparent-stream path. An absent record (`WSAEINVAL`) means the socket was not redirected, and the flow splices. No PROXY header is needed here: the context already carries the original destination.

Driver and proxy talk through a device object with IOCTLs. Arkham pushes the proxy endpoint and process-table deltas on agent spawn and exit, and pulls counters for verification. All runtime state lives in driver memory only, is set at proxy startup, and clears automatically when arkham exits, tracked through kernel process notifications. Proxy updates need no reboot: start the new instance, let it register, confirm substitution, stop the old one, where the tracked PID keeps the old instance from clearing the new config. Driver updates need a reboot. Verification reads driver load state, the service entry, registered filters and callouts, and the Base Filtering Engine status. Debug tooling is DebugView for kernel output, WinDbg in a VM for deep work, Process Explorer and WinObj for inspection.

The installer needs admin rights: service registration with a BFE dependency, a private sublayer with a documented weight for coexistence with VPNs and other WFP products, persistent filter install, and clean removal undoing all of it. Development uses test signing. The production signing path is an open question below.

Failure strategy is fail open for connectivity: no proxy configured, local or private destination, uninterceptive protocol, or redirect failure all permit direct. Secret safety is unaffected per the constraints, since direct flows carry decoys.

## Proxy shape

Compose keeps its shape: one arkham process per stack, holding one `ResolvedConfig` on the fixed `127.0.0.1:8099` inside the stack's own netns.

Every host backend (Linux bwrap and Landlock, macOS, Windows) uses one arkham proxy process with a project registry. Project isolation is not the goal; guarding secrets is, which means knowing which secrets apply to which flow. Each registered project maps its root to its secret set (resolved config, plugin registry, mint store). `arkham agent` registers its project on start and unregisters on exit. The capture backend attributes each flow to a project (cgroup on Linux, audit token plus process table on macOS, the WFP workspace tag on Windows), and the proxy selects that project's secret set before building substitution pairs. Attribution reaches the proxy per backend as follows: Linux reads the cgroup id from the eBPF `FLOW` map, macOS reads a project TLV from the PROXY v2 header on the Unix-socket handoff, and Windows reads the workspace tag from the WFP redirect context. It never infers the project from a decoy value: decoys are deterministic per env name and collide across projects. Unknown source splices with no swap.

One TCP listener on loopback serves every project, so there are no per-workspace ports, no claim records, and no state directory for host backends. `ARKHAM_LISTEN` keeps overriding the listen address for operators and tests. Host backends refuse a non-loopback value; compose's proxy listens on `0.0.0.0` inside its container network. The NE/daemon handoff is a separate Unix socket. `arkham serve` binds that socket alongside the explicit TCP listener. Operators set `proxy.handoff_socket` / `ARKHAM_HANDOFF_SOCKET` (default `<config-dir>/arkham/handoff.sock`) and `proxy.handoff_uid` / `ARKHAM_HANDOFF_UID` (default: the serve process's uid). `ProxyState` grows from one write-once snapshot to a registry with live add and remove; that change, plus the per-flow selection step, is the proxy work for host backends.

## Filesystem backends

Linux argv shape for `workspace-write`, before the `--` separator and the agent command:

```sh
bwrap \
  --ro-bind / / \
  --dev /dev --proc /proc \
  --unshare-pid --unshare-uts --unshare-ipc \
  --tmpfs /tmp \
  --bind <workspace-root> <workspace-root> \
  --ro-bind <rewritten-file> <dest> ... \
  --ro-bind <tool-dir> <config-dir> ... \
  --ro-bind <ca.pem> /arkham/ca.pem \
  --die-with-parent --new-session --clearenv \
  --setenv SSL_CERT_FILE /arkham/ca.pem \
  --setenv NODE_EXTRA_CA_CERTS /arkham/ca.pem \
  --setenv REQUESTS_CA_BUNDLE /arkham/ca.pem \
  --setenv <DECOY> <fake> ... \
  -- <shell-or-command>
```

No `HTTP_PROXY` variables appear. The `/tmp` tmpfs is private to the session. Host directories under `/tmp` are not bind-mounted. Landlock adds read and write rules from the same profile inside the bubblewrap process. A ruleset the kernel does not fully enforce refuses to start the command. `danger-full-access` does not apply Landlock. `read-only` mode drops the workspace bind and the tmpfs.

macOS emits SBPL from the shared writable roots as a second layer under the `arkham` user and the FUSE projection (see the macOS section):

```
(version 1) (allow default) (deny file-write*)
(allow file-write* (literal "/dev/null"))
(allow file-write* (subpath "<root>") (subpath "<tmp>"))
```

Every root is canonicalized first: Seatbelt matches resolved paths, so `/tmp` renders as `/private/tmp` and symlinked ancestors resolve. Launch is `sandbox-exec -p <profile> -- <command>` as the `arkham` user. A missing `sandbox-exec` fails the probe and starts nothing. The App Sandbox entitlement path is rejected because it needs a signed bundle and Xcode packaging for a CLI tool.

Windows uses raw restricted tokens, not AppContainer. The child token derives from `CreateRestrictedToken` with `WRITE_RESTRICTED`, `DISABLE_MAX_PRIVILEGE`, and `LUA_TOKEN`, with distinct workspace and private-temp capability SIDs. The token intersects writes only, so reads keep ambient access. AppContainer is rejected because its token carries no ambient reads: every readable path would need pre-granting, which means wholesale host DACL mutation for an agent that reads toolchains across the disk. One standing workspace ACE per workspace plus a random private temp directory with a revocable ACE per live session pair keeps sessions from inheriting each other temp authority. The Low integrity layer applies, and ambient deletes are denied through the parent `FILE_DELETE_CHILD` right. Hard-link aliasing, unconfined reads, and trees ACLed by other tools stay outside the token.

## Invariants and acceptance tests

Every secret file is a projection. There is no passthrough for secret files on any backend. AWS credentials, kubeconfig, Talos config, and the rest use the existing rewrites, and fnox files are forged. Reads of forged files succeed and return bogus content. Each invariant below needs an acceptance test with equivalent assertions on Linux and macOS (and Windows once that backend exists):

- Original-path denial: the real original of every projected file is unreachable from the agent by absolute path, symlink, hard link, or any alternate path into the enlisted tree.
- Complete projection: every config file fnox loads is a projection, not only `fnox.toml` and `fnox.*.toml`. That includes `.fnox.toml`, `.fnox.<profile>.toml`, `.fnox.local.toml`, imported files, global config, and identity paths.
- Immutable session configuration: a session cannot change its registered project or secret set after launch. Agent-writable project arkham config is snapshotted before launch, and later edits have no effect on the running session.
- Daemon-required wrapper: `arkham agent --` starts no process without a running daemon.
- Session identity: the pid-to-session link cannot be raced or reused by another process.
- Authenticated handoff: the proxy accepts the NE/daemon handoff on a Unix socket and checks the peer uid with getpeereid (macOS/BSD) or `SO_PEERCRED` (Linux). Only that uid is admitted, so a confined agent cannot forge a PROXY header naming another destination or project. This is not loopback TCP and not a shared secret. Host backends refuse a non-loopback `ARKHAM_LISTEN`.
- Authenticated control plane: the privileged daemon and XPC endpoints authenticate their clients. CA signing stays with the daemon.
- Read confidentiality on macOS: Seatbelt `(allow default)` gives none, so reads are governed by the separate user plus the FUSE projection, and tests assert reads through that path.

## Security analysis

Threat model: the agent is untrusted code holding decoys only. Real secrets live in arkham processes. Host data outside the profile stays unreadable where the backend allows (bwrap hides, Seatbelt and Windows deny) and unwritable everywhere. Workspaces cannot reach each other secrets or writable roots.

Per-backend gaps: bwrap leaves kernel exploits and abstract-socket or D-Bus peers outside the mount view, covered by the denylist (`--unshare-ipc`, minimal env, no host socket binds). Landlock refuses to start when the kernel cannot enforce the whole ruleset. Seatbelt leaves reads visible, depends on deprecated `sandbox-exec`, and overbroad network denies break unix-socket IPC. Windows tokens leave reads unconfined, including hard-link aliasing. Capture leaves pinned or embedded-trust flows bypassed, which carries decoys only.

## Work areas

Policy and scaffold: policy types plus the shared writable-roots helper in `arkham-config`, one `Error` variant when bubblewrap rejects the profile, the probe harness running `true` under a `read-only` profile, the project registry, and the `--isolate bwrap|compose` switch with compose default.

Linux: bwrap argv renderer from stack inputs, Landlock rules inside bubblewrap that refuse to start unless fully enforced, eBPF per-workspace cgroup capture with the cgroup selecting the project, project registration in `AgentArgs`.

macOS: `arkham` user provisioning, FUSE projection with `enlist` and `mirror` entries and forged `fnox.toml` / `fnox.*.toml`, Seatbelt renderer with canonicalization, host controller plus sysext packaging from the rama example layout, project registry and agent process table over XPC, both signing tracks, CA lifecycle, `NENetworkRule` selection, unified logging.

Windows: restricted-token renderer with ACE lifecycle, callout driver (minimal, redirect plus tagging), filter set, installer with service and BFE wiring, redirect-context decoder, verification and debug docs.

Proxy: one process with a project registry for every host backend, live project add and remove, and per-flow secret-set selection from capture attribution. Compose keeps one process per stack.

Verification throughout: e2e per backend proving outside-root writes fail in the backend denial dialect, reads fail where the backend governs them, decoys substitute through transparent capture with no proxy env set on the agent, host `/tmp` stays untouched under bwrap, and unknown-source flows splice. Run `mise run format` and `mise run --force test` for Rust changes.

## Open questions

- Forged fnox contents: how decoy values and the fresh age identity are generated so `fnox` behaves identically, and whether other secret file shapes join `fnox.toml` and `fnox.*.toml`.
- Windows driver signing path for production (attestation versus EV) and the installer shape. Test signing covers development.
- Windows redirect-context schema and its versioning between driver and arkham releases. The driver writes it, arkham decodes it, so both sides stay in this repo.
- Whether `danger-full-access` stays at all, given it only relaxes filesystem policy and secret protection is unaffected.

## References

- Current stack: `crates/arkham-compose/src/stack.rs` (`generate_stack:461`, `Stack:1347`, `EXPLICIT_LISTEN:266`), `crates/arkham-compose/src/confine.rs` (`AgentArgs:785`).
- Proxy: `crates/arkham-proxy/src/lib.rs` (`ProxyState:63`, `ExplicitService:239`), `crates/arkham-config/src/grants.rs` (`ResolvedConfig:652`), `crates/arkham-config/src/config.rs` (`fake_for:832`, `ProxyCfg.listen:278`).
- Linux capture: `crates/arkham-tproxy/src` (`nft.rs`, `route.rs`, `tproxy.rs`, `error.rs`), `crates/arkham-ebpf` plus `crates/arkham-ebpf-programs`.
- Rama: `rama-net/src/socket/opts.rs` (`ip_transparent`), `rama-net/src/socket/linux/tproxy.rs`, `rama-net/src/socket/windows/tproxy.rs`, `rama-net-apple-networkextension` plus `ffi/apple/examples/transparent_proxy`, `docs/book/src/proxies/operate/transparent/windows.md`, `docs/book/src/proxies/operate/transparent/macos.md`.
- Chromium: `sandbox/mac/seatbelt.cc`, `docs/design/sandbox.md` (Windows token plus job plus desktop plus integrity).
