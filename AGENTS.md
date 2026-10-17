# AGENTS.md - arkham

Grant-scoped MITM proxy. Terminates client TLS with per-domain leaf certificates, swaps format-valid decoy fakes for real secrets only on URI-grant match, and redacts real values back to fakes on responses; everything else splices byte-identical.

## Crate Roles & Boundaries

### Terminology

- **Face**: the `arkham` binary (`src/main.rs`, `src/commands/`, `src/fwd/`): owns clap parsing, config-load dispatch, the fail-closed `with_capture` select, and the global allocator. It calls into the libraries; no library calls back into it.
- **Config core**: `arkham-config`: owns `Cli`, `ServeArgs`, and the `CliCommand` dispatch trait, the confique overlay, rule schema, `fake_for`, grant matching (`HostPat`, `EndpointScope`'s `FromStr`, `uri_match`, `Grant::matches`), the host registry, and plugin resolution records.
- **Secrets source**: `arkham-fnox`: owns fnox discovery layers, value resolution, and provider-credential export.
- **PKI**: `arkham-pki`: owns the signing CA, leaf and client-pair generation, and the SSH key helpers (host key load-or-generate, decoy keys, `known_hosts` pinning).
- **Proxy core**: `arkham-proxy`: owns `ProxyState`, `serve`, `serve_connect_stream` / `serve_transparent_stream`, `relay_guarded`, connection sniffing with SNI resolved through rama's ClientHello parser, and the substitution engines (`transports/http`, `transports/postgres`, `transports/redis`, `transports/smtp`, `transports/ldap`, `transports/nats`, `transports/ssh`, `transports/tcp`, and the shared machine in `transports/engine`).
- **Plugin host**: `arkham-plugin`: owns wasmtime component-model hosting of rewrite guests around the in-core value swap.
- **Stack generation**: `arkham-compose`: owns compose/stack generation, path expansion, confinement entry, and ambient source adapters (git, jj, ssh, nats, kube, talos). The stack-command args (`Init`, `Up`, `Down`, `Logs`, `Agent`, `Fwd`) live here behind `arkham-config`'s `CliCommand` trait.
- **Capture backends**: `arkham-tproxy`, `arkham-tun`, `arkham-ebpf` (userspace halves): own packet capture and hand accepted streams to the proxy core.
- **BPF programs**: `arkham-ebpf-programs`: owns the no_std kernel-side eBPF programs and the shared map ABI.

| Crate | Role | Dependencies Allowed |
|---|---|---|
| `arkham` (binary) | Face: CLI dispatch, `with_capture`, allocator | `arkham-config`, `arkham-fnox`, `arkham-pki`, `arkham-proxy`, `arkham-compose`, `arkham-tproxy`, `arkham-tun`, `arkham-ebpf`; external `clap`, `eyre`, `miette`, `tokio`, `tracing` |
| `arkham-config` | Config overlay, grants, registry, CLI types | No workspace crates; external `base62`, `base64`, `clap`, `code-workspace`, `confique`, `dirs`, `hex`, `nkeys`, `percent-encoding`, `secrecy`, `serde`, `serde_json`, `sha2`, `strum`, `toml`, `tracing`, `url`, `validator`, `thiserror` |
| `arkham-fnox` | fnox discovery and value resolution | `arkham-config`; external `fnox-core`, `miette`, `secrecy`, `serde`, `tokio`, `toml`, `tracing`, `thiserror` |
| `arkham-pki` | CA, leaf generation, SSH key helpers | No workspace crates; external `rama` (boring), `rcgen`, `rand`, `russh`, `rustls`, `time`, `tracing`, `thiserror` |
| `arkham-proxy` | MITM relay and substitution engines | `arkham-config`, `arkham-pki`, `arkham-plugin`; external `base64`, `bytes`, `rama`, `rasn`, `rasn-ldap`, `rustls`, `rustls-native-certs`, `tokio-rustls`, `httparse`, `httlib-hpack`, `pgwire`, `russh`, `secrecy`, `serde_json`, `smtp-proto`, `strum`, `url`, `tracing`, `thiserror` |
| `arkham-plugin` | WASM rewrite-guest host | `arkham-config`; external `wasmtime`, `wasmtime-wasi`, `tracing`, `thiserror` |
| `arkham-compose` | Stack generation and confinement | `arkham-config`, `arkham-fnox`, `arkham-pki`; external `base64`, `clap`, `dirs`, `gix-config`, `gix-discover`, `libc`, `secrecy`, `serde`, `serde_yaml`, `shellexpand`, `toml`, `toml_edit`, `tracing`, `url`, `xpanda`, `tokio`, `thiserror` |
| `arkham-tproxy` | Kernel TPROXY capture backend | `arkham-config`, `arkham-pki`, `arkham-proxy`; external `futures-util`, `libc`, `netlink-packet-core`, `netlink-packet-netfilter`, `netlink-sys`, `rama` (tcp), `rtnetlink`, `rustls`, `secrecy`, `tokio-rustls`, `tracing`, `thiserror` |
| `arkham-tun` | Userspace TUN capture backend | `arkham-config`, `arkham-pki`, `arkham-proxy`; external `futures-sink`, `futures-util`, `rtnetlink`, `rustls`, `secrecy`, `smoltcp`, `socket2`, `tokio-rustls`, `tokio-util`, `tracing`, `tun`, `thiserror` |
| `arkham-ebpf` | eBPF capture backend (userspace half) | `arkham-config`, `arkham-proxy`; external `aya`, `dashmap`, `libc`, `tokio`, `tracing`, `thiserror` (`aya-build` build-dep only) |
| `arkham-ebpf-programs` | Kernel-side BPF programs | No workspace crates, no host crates; `aya-ebpf` only |

### Dependency Rules (STRICT)

1. **Face depends on the libraries only.** `arkham` (binary) may depend on any library crate; no library crate may depend on the binary.
2. **Dependencies point downward only.** A crate may depend only on the crates named in its `Dependencies Allowed` row; adding a new workspace dependency is a boundary change and needs an AGENTS.md row update.
3. **`arkham-config` is the bottom.** It depends on no workspace crate; every rule, grant, and registry type flows out of it, never into it.
4. **`arkham-pki` is a leaf.** It depends on no workspace crate; PKI never imports proxy, compose, fnox, or backend types.
5. **`arkham-fnox` depends on `arkham-config` only.** Value resolution reads rule shapes from config; it never imports proxy, pki, compose, plugin, or backends.
6. **`arkham-plugin` depends on `arkham-config` only.** The guest host reads grant and plugin records; it never imports proxy internals, PKI, fnox values, or compose.
7. **`arkham-proxy` is the sole substitution owner.** Only `arkham-proxy` (`transports/*`, `relay`, `connection`) implements fake-to-real and real-to-fake swaps; backends and the face reuse `serve_transparent_stream` and never reimplement MITM logic.
8. **`arkham-config` is the sole grant gate.** Only `arkham-config` (`grants/`) implements `EndpointScope` parsing / `uri_match` / `Grant::matches`; proxy, plugin, and backends call it and never reimplement host matching.
9. **Capture backends depend on the proxy core, never the reverse.** `arkham-tproxy`, `arkham-tun`, `arkham-ebpf` may depend on `arkham-proxy` (plus `arkham-config`, and `arkham-pki` for tproxy/tun); `arkham-proxy` never imports a backend.
10. **`arkham-compose` never touches the relay.** It may depend on `arkham-config`, `arkham-fnox`, `arkham-pki`; it never imports `arkham-proxy`, `arkham-plugin`, or any capture backend.
11. **`arkham-ebpf-programs` is fully isolated.** It depends on `aya-ebpf` only, inherits no workspace lints, ships no host code, and every host-wide command excludes it (`--exclude arkham-ebpf-programs`); `dist = false` keeps it out of releases.
12. **No workspace-hack crate.** This workspace deliberately has no `<name>-workspace-hack` crate; `[workspace.dependencies]` (one declaration per external dependency) is the version-dedup mechanism, and `cargo sort --grouped` keeps it ordered.

## Non-negotiable Rules

### No Optionality / No Fallbacks

- **Never introduce optionality to "make it pass/work".** Do not add silent defaults, degrade required behavior to `Option`, return early with `Ok(())`, swallow errors, or otherwise mask missing configuration/state.
- **Never weaken tests to go green.** Do not "skip" by returning success early, loosen assertions, add broad retries/timeouts, or ignore errors unless explicitly instructed.
- **Never add gating/ignores without explicit instruction.** No `#[ignore]`, feature flags, env-var gates, or conditional compilation to hide failing tests or behavior changes unless the user explicitly asks for it.

### No Panics in Production Code

- **A panic is a programmer error.** Forbidden in any non-test path: `panic!`, `unreachable!`, `todo!`, `unimplemented!`, `assert!*`, `.unwrap()`, `.expect()`, indexing/slicing that can go out of bounds or split a char boundary (use `get`/`get_mut`), arithmetic that can overflow or divide by zero (use `checked_*`/`saturating_*`).
- **Instead**: return `Result` with a typed error. The dangerous `.expect()` is the one justified by an invariant enforced somewhere else — a comment, not a guarantee. If an invariant is real, encode it in a type. If it cannot be encoded, handle the failure.
- **Narrow exceptions**: test code, benchmarks, build scripts, `examples/`; poisoned-lock recovery via `.unwrap_or_else(PoisonError::into_inner)`; `const` evaluation that fails at compile time. Anything else: ask first.

### Terminology

Use standard software engineering vocabulary. Architectural metaphors are banned: never write "load-bearing", "spine", "seam", "pillar", "streak", or similar. Say the technical thing directly: "X is required by Y", "Z depends on W", "the boundary between A and B", "integration point", "failure mode".

Banned domain vocabulary with required replacements: "birth"/"born" → "join"/"membership".

### Mise Environment

> **CRITICAL: Do not ever try to fix `mise` environment related issues. Escalate to the user immediately.**

### Linting & Code Quality

- **Fix, Don't Suppress**: address all lint errors and warnings by fixing the code.
- **No `allow` Attributes**: **NEVER** use `#![allow(...)]` or `#[allow(...)]` to suppress warnings.
- **Strict Mode**: the project compiles with `-D warnings`. If it doesn't compile cleanly, it's broken.
- **Read the Tool's Output, Not the Wrapper's Exit Code**: `mise format` runs a report pass then a `--fix` pass; the aggregate exit reflects the fix pass and can mask report-pass findings `--fix` cannot resolve. A zero exit does **not** mean clean — read each step.

## Data Flow & Validation Strategy

> **CRITICAL: Validate ONCE. Do not repeat validation logic across layers.**

### Face: parse only

- Responsibility: clap parse (`ArkhamCli`, per-subcommand args), 4-layer config load dispatch, CA path resolution, `with_capture` fail-closed select over the explicit listener plus the selected capture backend.
- Validation: none beyond what clap and `config::load` enforce; the face adds no second check.
- Normalization: subcommand absent means `serve`; `--proxy-backend` / `--ebpf-cgroup` / `--tproxy-allow-root-netns` stay CLI/env-only by design and never enter files.
- ❌ SIN: re-checking grant syntax, registry hosts, or fnox names at the face.

### Config and grants: the single semantic boundary

- Responsibility: `arkham-config` owns the overlay (CLI > env `ARKHAM_*` > project `.config/arkham.toml` > global config), the rule schema, `fake_for`, `HostPat` (`Exact` / `Wildcard` / `Any`), `EndpointScope`'s `FromStr`, `uri_match`, the bundled plus `rules.d` registry, and plugin resolution records.
- Validation: grant strings (`scheme://host[:port]`, `http` / `https` / `tcp` with port required for `tcp`, ASCII case-insensitive hosts), wildcard shape, and registry-entry shape are validated here, once, into typed values.
- Normalization: hosts lowercased once; leaves mint on first connection through rama's cached in-memory issuer, bounded per window by the `MintBucket` burst guard.
- ❌ SIN: any second grant/host parser in proxy, plugin, compose, or backends.

### Secrets: resolve, never validate shape twice

- Responsibility: `arkham-fnox` derives rules in-memory at the top of `resolve` from fnox-declared names joined against registry hosts, then fetches values; explicit config rules act only as per-env exceptions overriding derived rules.
- Validation: missing fnox names and uncovered declarations surface as warnings at generation/shell-entry time, never as silent empty rules.
- Normalization: values stay in `secrecy::SecretString`; logs carry label plus header/basic-auth/body location only, never values.
- ❌ SIN: minting credential fragments from git/jj/ssh/kube/talos configs (those are host and identity sources only; a fragment found in a shared mounted config fails closed with the file named).

### Proxy core: trusts typed inputs, degrades to opaque forward

- Responsibility: `arkham-proxy` accepts on the explicit listener or via a backend's `serve_transparent_stream`, resolves the identity through rama's ClientHello parser (SNI) or the HTTP `Host` head, mints the leaf, peeks H1 vs H2-preface vs raw, then pumps guest chunks through the request machine (fake to real) and server chunks through the response machine (real to fake) around the plugin hooks.
- Validation: none repeated; typed grants and resolved secrets are trusted. Malformed client traffic closes quietly (`Ok(())`), framing uncertainty degrades to opaque scan-and-forward, never blocks.
- Normalization: per-connection `tokio::spawn` under 10s pre-auth/dial budgets; `ProxyState` behind plain `Arc` (write-once, no reload); leaf issuance bounded by the `MintBucket` burst guard.
- ❌ SIN: returning `Ok(())` early to hide a resolution failure, or adding a fallback path around a missing grant.

### Capture and BPF: identity from the socket, bytes explicit

- Responsibility: `tproxy` (IP_TRANSPARENT plus nft over netlink and policy routes), `tun` (TUN device plus userspace smoltcp stack, classify, tracker, UDP relay), `ebpf` (loader, map lookups, TCP MITM leg, UDP relay plus janitor) all treat the captured destination as the identity and hand streams to the proxy core. `arkham-ebpf-programs` owns `connect4`, `recvmsg4`, `capture_egress` and the `CONFIG` / `ORIG_DST` / `FLOW` maps.
- Validation: exclusion by `SO_MARK` fwmark (`tproxy`, `tun`) or cgroup membership plus PID check (`ebpf`); QUIC :443 dropped, TUN DNS goes to the system resolver.
- Normalization: map structs (`Config`, `OrigDst`, `FlowKey`) are `repr(C)` with every byte explicit including padding; byte-order helpers (`decode_addr` / `encode_addr` / `decode_port`) are the only conversion path, pinned by layout tests.
- ❌ SIN: a `repr(C)` struct with implicit padding, or a second address codec.

## Configuration

Owner: the face (`arkham` binary) owns file/env loading mechanics via `arkham-config::config::load(&Cli)`; `arkham-config::cli.rs` owns the clap types (`Cli`, `ServeArgs`, `ProxyBackend`). Libraries consume typed settings only and never read files or env themselves.

Precedence: CLI > env (`ARKHAM_*`) > project (`<root>/.config/arkham.toml`) > global (`$ARKHAM_CONFIG` or `<config-dir>/arkham/config.toml`). `rules.d` layers are registry-only (bundled `rules/registry.toml`, then global `rules.d`, then project `rules.d`).

Subcommands are enum variants with args that own a `run` method — never separate binaries. Current set: `serve` (default), `fake`, `schemes`, `ca`, `rules`, `config`, `registry` (curate), `init`, `agent`, `fwd` (stack sidecar, not a user command), `up`, `down`, `logs`. Add an entrypoint by adding a variant plus its args struct, not a new package.

## Coding Standards

- **Error Handling**:
  - Each crate that defines a local error boundary must expose exactly one `Error` type and one `Result<T>` alias at the crate root (`lib.rs` or the binary root).
  - Do **not** define module-local `Result` aliases or duplicate error enums in child modules.
  - Child modules must import the crate-root `Error` and `Result`.
  - Libraries use `thiserror`; `main`/faces use `eyre`/`color-eyre` at the edge only.
  - `#[from]` for transparent conversions, `#[source]` for contextual variants. Variants carry typed context from the boundary that knows the entity. No stringly wrappers (`Other(String)` and kin fail review); never `to_string()` a source.
  - Arkham notes: one `thiserror::Error` enum per library crate under `mod error` re-exported at the root; keep `Display` strings stable when replacing behavior; malformed guest traffic closes quietly instead of erroring; the BPF programs crate defines no host error type at all.
- **Builders**: use `typed-builder` for non-trivial request/configuration types. No long constructor arg lists.
- **Simplicity**: boring over clever; deletion over addition.
- **Naming**: `UpperCamelCase` types and variants, `snake_case` fns/modules/variables, `SCREAMING_SNAKE_CASE` consts. CLI subcommands are kebab-case, TOML keys are snake_case, WIT worlds are `arkham:rewrite` `request` / `response`.
- **Testing**: inline `#[cfg(test)] mod tests` per file over `cargo-nextest`; `tokio::test` for async; helpers co-located (`MitmFixture` in proxy, `make_tun` in tun, `lock_env` plus `tempdir` in config); `pretty_assertions` plus `tempfile` only. Behavior-descriptive `snake_case` names with no `test_` prefix; live capture tests are `tun_live_*` / `tproxy_live_*` / `ebpf_live_*`, `#[ignore]`d, root-only and serial.

## Development Workflow (Mise)

**ALWAYS** use `mise` tasks for development. Only run direct toolchain commands if no `mise` wrapper exists.

**NEVER** run "targeted" tests, the cost is not the test it's the compilation of the modules.
**NEVER** run `cargo test`, it is not a win, it has the opposite outcome.

| Task | Description |
|---|---|
| `mise run format` (`mise format` gate) | Checks for this codebase (check, clippy `-D warnings`, rustfmt, cargo-sort, toml/whitespace guards). |
| `mise run test` | All tests (Rust `nextest`). |
| `mise run --force test` | Force a fresh full test run (bypass cache). |

Live and demo variants: `mise run test:tun`, `mise run test:tproxy`, `mise run test:ebpf` (root, serial, `#[ignore]`d live tests), `mise run test:rust` (unit plus plugin e2e via `build:plugins` and `ARKHAM_PLUGIN_FIXTURES`), `mise run demo` (docker compose substitution/splice proof). Start discovery with `mise tasks`; tasks are executable files under `.mise/tasks/`.

**IMPORTANT**: After changes, **ALWAYS** run:
1. `mise format` (invoke as `mise run format` in this repo)
2. If Rust code was modified: `mise run --force test`

## Agent Guidelines

Do not:

- Do not add a workspace dependency outside `[workspace.dependencies]` or bypass `cargo sort --grouped`.
- Do not let a library depend on the `arkham` binary or on a sibling it does not already allow (proxy never imports backends or compose; compose never imports proxy/plugin/backends; plugin/fnox never import proxy internals).
- Do not reimplement grant matching, SNI parsing, substitution, or the `with_capture` fail-closed select outside their owning modules.
- Do not add `Option` fallbacks, early-`Ok(())` skips, `#[ignore]` gates, or feature/env gates to hide a failure.
- Do not add a panic path (`unwrap`, `expect`, indexing, unchecked arithmetic) in non-test code.
- Do not touch `arkham-ebpf-programs` from host commands or inherit workspace lints into it; keep the `--exclude arkham-ebpf-programs` on every workspace-wide invocation.
- Do not log secret values or add credential-shaped fixtures outside the allowed `betterleaks` scope.

Do:

- Reuse the owning boundary: grants from `arkham-config`, leaves from `arkham-pki`, streams from `arkham-proxy::serve_transparent_stream`, stack pieces from `arkham-compose`.
- Keep the smallest diff that fixes the root cause where all callers route through.
- Adding a credential-rewriting protocol: follow [`.agents/skills/add-protocol/SKILL.md`](.agents/skills/add-protocol/SKILL.md).

When adding a capture backend: add an arm to the face dispatch plus one crate that depends on proxy/config only, reusing `serve_transparent_stream`; never copy the `with_capture` block.

When adding a wire protocol: follow [`.agents/skills/add-protocol/SKILL.md`](.agents/skills/add-protocol/SKILL.md). Redis is the worked example in [`.agents/skills/add-protocol/reference/redis.md`](.agents/skills/add-protocol/reference/redis.md): a vertical under `crates/arkham-proxy/src/transports/`, grant types in `arkham-config`, and a compose scenario whose `retry` records the scheme.

When adding a WIT world or plugin hook: extend `arkham-plugin/wit/world.wit` plus the `arkham-plugin` host, keep grant ownership in config and secret ownership in the relay, and fail guest errors closed to `Verdict::Close`.

When adding a config setting or ambient source: extend `arkham-config` schema plus the `arkham-compose` adapter with warn-and-skip tolerance; never read files/env from a library outside config, and never mint credentials from tool configs.

## Before Committing Checklist

- [ ] `mise format` passes (each step read, not just the exit code)
- [ ] `mise run --force test` passes (if Rust changed)
- [ ] **No `allow` attributes**: all lint warnings fixed, not suppressed
- [ ] No `.unwrap()` or `.expect()` in production paths
- [ ] **Error boundary**: one `Error` + `Result` at root per boundary crate, children import from root, `eyre` only at the edge
- [ ] Grant gate intact: matching only in `arkham-config`, no second parser
- [ ] Substitution intact: swaps only in `arkham-proxy`, backends reuse `serve_transparent_stream`
- [ ] BPF isolation intact: host commands keep `--exclude arkham-ebpf-programs`, map structs stay byte-explicit, no workspace-hack crate added
- [ ] All public items have doc comments; no debug `println!` or `dbg!`
- [ ] No hardcoded credentials; no spec ids in code comments or error strings
- [ ] Banned vocabulary absent (`seam`, `spine`, `streak`, `pillar`, `load-bearing`, `birth`, `born`)
