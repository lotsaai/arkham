# rust-review

Strict, evidence-based Rust review. No praise, no summary fluff, no hedging. Every finding cites file, lines, and the violated rule. If the evidence is thin, say so and move on.

## Precedence

1. This repo's `AGENTS.md` and the actual crate boundaries in `Cargo.toml` files.
2. Actual call graph over claimed architecture.
3. Upstream Rust conventions.

No internet fetching. No guessing at upstream docs. Read the code in front of you.

## Posture

- `must fix`: violates `AGENTS.md` STRICT rules, introduces a panic path, breaks an error boundary, duplicates validation, or widens a dependency against the allowed table.
- `should fix`: correct but unidiomatic, wasteful, or likely to rot into a `must fix` (unchecked index adjacent to untrusted input, second codec, log that risks a value).
- `consider`: genuine tradeoff with no clear winner; state the cost of changing versus keeping.

Diff-first when a diff exists; map-first when reviewing a crate or workspace slice without a diff.

## Mission

Cover these 10 areas; skip none silently, mark clean ones clean with one line of evidence:

1. Architecture and crate boundaries.
2. API design (types carry invariants; no long arg lists).
3. Ownership and borrowing (no clones at boundaries, no `&String` style).
4. Errors and panics.
5. Async discipline (no blocking in async, budgets and shutdown honored).
6. Documentation (every public item documented, docs state contracts not mechanics).
7. `unsafe` (justified, scoped, documented).
8. Traits (no single-implementation interfaces, no speculative generality).
9. Testability (behavior tests at the boundary, live tests gated correctly).
10. Performance (no avoidable allocation, copy, or computation on hot paths).

## Repository-specific rules you must enforce first

### 1. Crate roles and dependency directions

Face `arkham` calls libraries; libraries never call the face. `arkham-config` and `arkham-pki` are leaves. `arkham-fnox` and `arkham-plugin` depend on `arkham-config` only. `arkham-proxy` owns substitution and may depend on config, pki, plugin only. Backends depend on proxy; proxy never imports a backend. `arkham-compose` never imports proxy, plugin, or backends. `arkham-ebpf-programs` is isolated (`aya-ebpf` only).

Hard violations: a new workspace dep outside the allowed table; proxy importing a backend; compose importing proxy; plugin importing proxy or fnox; any crate importing the binary.

### 2. No optionality, no weakened tests, no hidden gates

Never introduce `Option` defaults, silent fallbacks, early-`Ok(())` returns, or swallowed errors to make a failure pass. Never loosen an assertion, add retries, or gate a failing test behind `ignore`, features, env vars, or cfg without explicit instruction.

Flag: any new `Option` on required config, any early return that converts a failure into success, any new `ignore` / feature / env gate.

### 3. No panics in production paths

`panic!`, `unreachable!`, `todo!`, `unimplemented!`, `assert!*`, `.unwrap()`, `.expect()`, index/slice without `get`, arithmetic without `checked_*`/`saturating_*` are forbidden outside the accepted exceptions. Malformed guest traffic closes quietly; framing uncertainty degrades to opaque forward.

Hard violations: any of the above in `src/` or `crates/*/src/` outside `#[cfg(test)]`, benches, build scripts, or `examples/`.

### 4. Validate once

Grants parse once in `arkham-config`; secrets resolve once in `arkham-fnox`; the proxy trusts typed values. No second grant parser, host matcher, SNI parser, address codec, or credential check anywhere else.

Flag: a second `uri_match`-shaped function, a second ClientHello parse, a second addr/port codec, validation repeated at the face or in a backend.

### 5. Config ownership

Only the face loads files/env via `arkham-config::config::load`; libraries take typed settings. Subcommands are enum variants with `run` methods, never new binaries. CLI/env-only flags never enter files.

Flag: `std::env` or file reads outside config/face, a new binary target for a subcommand, a CLI-only flag persisted into TOML.

### 6. Error boundaries

One `Error` plus one `Result<T>` at each library crate root; children import from the root; `thiserror` inside, `eyre` only at the binary edge. `#[from]` for transparent conversion, `#[source]` for context; no stringly `Other(String)`; never `to_string()` a source.

Hard violations: a second error enum or module-local `Result` alias, `eyre` in a library crate, a stringly variant, a `map_err` that stringifies the source.

### 7. Arkham gates

Substitution lives only in `arkham-proxy` behind `serve_transparent_stream`; grant gating lives only in `arkham-config`; leaf issue and rotation live only in `arkham-pki`; guest failures close to `Verdict::Close`. BPF map structs stay `repr(C)` byte-explicit behind the single byte-order helpers; every host-wide command keeps `--exclude arkham-ebpf-programs`; no workspace-hack crate.

Flag: a swap outside `transports/*`, a forward path that bypasses redaction, implicit padding in a map struct, a host command missing the ebpf-programs exclusion, a new hack crate.

### 8. Linting and docs

`-D warnings` clean, rustfmt edition 2024, `cargo sort --grouped`, no `allow` attributes, every public item documented, no `println!`/`dbg!`, no hardcoded credentials.

Hard violations: any `allow` attribute, undocumented `pub` item, debug print left in, credential-shaped literal without a `betterleaks:allow` marker inside the scanned trees.

### Accepted exceptions

- `arkham-ebpf-programs` does not inherit workspace lints: `aya-ebpf` macros emit undocumented wrappers no annotation can satisfy.
- Poisoned-lock recovery via `.unwrap_or_else(PoisonError::into_inner)`: the lock state, not program logic, is unrecoverable.
- `const`-evaluation failure at compile time: fails the build, never production.
- `unwrap`/`expect` in `#[cfg(test)]`, benches, build scripts, `examples/`: test-only paths.
- `rama` tracks git `main` on purpose: the needed 0.5 line is unpublished; this is the documented pin, not drift.
- Nightly plus `bpf-linker` and `-Z build-std` for the `bpf` target only: the target ships no prebuilt `core`.

## General Rust lenses

Repo-frequent reminders only:

- Encode invariants in types (typed `HostPat`, typed errors with context) instead of re-checking strings at each layer.
- Keep keygen and allocation off locks (`DashMap` leaf cache: keygen on caller).
- Prefer boring control flow and deletion over a new abstraction, helper, or wrapper type.
- Async: `tokio::spawn` per connection, 10s pre-auth/dial budgets, fail-closed `select!` in `with_capture`, never block the runtime.

## High-signal anti-patterns

Grep these before judging:

- banned vocabulary (`seam`, `spine`, `streak`, `pillar`, `load-bearing`, `birth`, `born`) in comments, docs, names, or strings
- `unwrap(` / `expect(` outside tests, benches, build scripts, examples
- `[` indexing / slicing on untrusted or variable-length input without `get`
- `eyre` outside the `arkham` binary edge
- second error enums or module-local `Result` aliases
- `&String` / `&Vec` / `&PathBuf` in public APIs
- `allow(` suppressions of any shape
- `pub` items without doc comments
- glob re-exports that widen a crate's surface (`pub use foo::*`)
- `dbg!` / `println!` left in non-test code
- `to_string()` on an error source or secret-adjacent value
- `Ok(())` early returns that mask missing config, grants, or secrets

## Workflow

1. Map: list the touched crates, their allowed deps, and the entry points (face subcommand, backend arm, wire leg, WIT hook, config setting).
2. Boundaries: check every new import against the allowed table and the STRICT rules; trace callers and callees of the touched function across crates.
3. Public API: read every new or changed `pub` item for docs, ownership shape, error type, and validation placement.
4. Smells: run the anti-pattern greps above over the diff and the immediate callers.
5. Judge: assign `must fix` / `should fix` / `consider` with rule references; propose the smallest root-cause fix at the owning boundary.
6. Report: emit the output format below; never recommend anything `AGENTS.md` forbids.

## Output format

Executive summary: 3-8 lines, verdict first, worst violation first.

Rubric: one line per mission area (clean with evidence, or finding IDs).

Findings grouped by topic (never tables). Each finding:

- ID, severity (`must fix` / `should fix` / `consider`), category (one of the 10 mission areas), rule reference (`AGENTS.md` section or skill section).
- Location: exact file and line range.
- Evidence: quoted code or diff hunk.
- Problem: what breaks, who calls it, what input triggers it.
- Why: the invariant or boundary it violates.
- Refactor: concrete change in the owning module, smallest diff that fixes all callers.
- Scope: files that must change, files that must not change.
- Confidence: high / medium / low with one-line reason.

Then:

- Rule-violations map: each violated `AGENTS.md` rule with the finding IDs that prove it.
- Free-function audit: every new free function, its owning type alternative, and keep-or-move verdict.
- Trait audit: every new or changed trait, implementor count, and why a trait (not a type or function) is warranted.
- API and ownership audit: new `pub` items, clone/allocation behavior at boundaries, error-variant shapes.
- Async audit: spawned tasks, budgets, shutdown paths, blocking risks.
- Unsafe, panic, and lint audit: `unsafe` blocks, panic paths, `allow` attributes, doc gaps, with locations.
- Top-10 refactors: ordered by risk reduction per diff size; the first item is the single change to make if only one is possible.
- False positives: required section listing every flagged-but-clean pattern with the evidence that clears it. Never omit; write "none" only after running the greps.

## Style constraints

Be strict, concrete, and evidence-led. No praise, no encouragement, no process narration. Quote code, not impressions. Never propose an `AGENTS.md` violation as a fix (no new optionality, no suppression, no gate, no second parser, no backend import into proxy). When the code is clean, say so in one line per area and stop.
