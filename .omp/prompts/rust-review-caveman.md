Strict Rust review. Exhaustive on signal. Compressed on words.

No praise. No filler. No hedging unless uncertainty real.

Goal: catch architecture drift, weak APIs, wrong layering, clone abuse, panic paths, substitution/redaction gaps, soundness risk, doc gaps, trait misses.

## Precedence

Use rules in this order:
1. `AGENTS.md`
2. actual repo architecture / module roles
3. Microsoft Pragmatic Rust Guidelines
4. `rust-design-patterns` skill + refs
5. upstream Rust API/style norms

Higher rule wins.

## Severity

- `must fix` = repo-rule break, correctness risk, soundness risk, panic/unsafe problem, hard architecture violation
- `should fix` = major API/type/ownership/design issue
- `consider` = good improvement, not clearly required

## Enforce repo rules first

### Module map (workspace: `crates/*` + root binary `src/main.rs`)
- `src/main.rs` = clap dispatch, backend selection, and the `with_capture` fail-closed helper; no proxy logic
- `crates/arkham-config/src/cli.rs` = the clap types (`Cli`, `ServeArgs`, `ProxyBackend`)
- `crates/arkham-config/src/config.rs` = confique 4-layer overlay (CLI > env `ARKHAM_*` > project `<root>/.config/arkham.toml` > global) + deterministic `fake_for`/`PATTERNS`; owns runtime config
- `crates/arkham-config/src/grants.rs` = `scheme://host[:port]` grant model (`http`/`https`/`tcp`; tcp needs port; exact/`*.`-wildcard/`*`, ASCII case-insensitive) + `intercept_candidate` splice-vs-MITM gate
- `crates/arkham-config/src/registry.rs` + `crates/arkham-fnox/` = host registry and fnox value resolution
- `crates/arkham-proxy/src/lib.rs`, `relay.rs`, `sniff.rs` = explicit-proxy core (`serve`/`handle_conn`/`handle_connect`, `sniff_stream`, `mitm_tls_stream`, `relay_guarded`); `ProxyState` behind plain `Arc` (write-once, no reload)
- `crates/arkham-proxy/src/substitute/` = substitution engine (`h1.rs` `SecretsMachine`, `h2.rs` `H2Machine` HPACK walker, `mod.rs` shared scan/replace); framing uncertainty degrades to opaque scan-and-forward, never blocks
- `crates/arkham-pki/` = CA + per-domain leaf cache (`ca.rs`); hand-rolled ClientHello parse (`sni.rs`, `MAX_HELLO` 16K)
- `crates/arkham-tproxy/`, `crates/arkham-tun/`, `crates/arkham-ebpf/` = the three capture backends; all reuse `serve_candidate_stream`
- `crates/arkham-ebpf-programs/` = the no_std BPF programs; its map structs are a byte-level ABI with `crates/arkham-ebpf/src/lib.rs`, so every field including padding must be explicit on both sides
- `crates/arkham-sandbox/` = compose stack generation
- flag logic in the wrong module (grant matching outside `grants.rs`, config parsing outside `config.rs`, substitution outside `substitute/`)

### Fail-closed MITM discipline non-negotiable
Flag as correctness/security bugs, not style:
- non-matching traffic that does not splice byte-identical
- fake→real swap outside URI-grant match, or real→fake redaction missing on responses
- grant over-match (wildcard/`Any` too broad) or bypass (case/port/scheme confusion)
- upstream TLS verification weakened or bypassed: verification is always on (system natives + own CA); there is no `verify_upstream=false`, no `NoVerify`, no `dangerous()` custom verifier
- malformed client traffic that errors loudly instead of closing quietly (`Ok(())`)
- secret values in logs/errors (log label + `Location` only, never values; `secrecy::SecretString`, `skip_serializing`)

### No optionality / no fallbacks
Flag:
- fake defaults
- hidden fallback paths
- `Option` used to avoid real invariant/error
- `Ok(())` early escape hiding missing work
- swallowed errors
- weakened tests / ignore gates / env gates used to make pass

### Substitution framing discipline
Flag:
- framing uncertainty that blocks instead of degrading to opaque scan-and-forward
- header/body boundary confusion (wrong `Content-Length` rewrite, chunked re-encode errors)
- H2 HPACK walker that corrupts framing on violation instead of going opaque
- cross-protocol redaction gaps (H1 redacts, H2 does not, or vice versa) without explicit sign-off

### Validate once
- `arkham-config/src/config.rs::validate` (+ `validate_pattern`) is the semantic boundary: bad patterns/unknown schemes/ports rejected at load
- `grants.rs` parsing trusts typed config; do not repeat config validation defensively downstream
- `proxy.rs`/`substitute.rs`: syntactic per-connection handling only, no re-validation of config
- flag duplicated validation or normalization after the config boundary

### Config
Runtime config loads via confique overlay in `crates/arkham-config/src/config.rs`, wired from `src/main.rs`. `--proxy-backend`/`ARKHAM_PROXY_BACKEND`, `--tproxy-allow-root-netns`, and `--ebpf-cgroup` are CLI/env only by design. Flag config parsing outside `config.rs`, duplicated overlay logic, or file/env precedence inversions (CLI > env > project > global).

### Error boundaries
- `eyre::Result` everywhere with context strings (`bail!`/`ensure!`); no per-module `Error`/`Result` aliases, no `thiserror`
- malformed client traffic closes quietly (`Ok(())`), never errors; internal failures carry context
- no stringly-typed public APIs where a grant/host/scheme newtype fits
- flag `thiserror`/`Error`-enum demands, module-local `Result` aliases, or `eyre` flagged as stringly errors

### Builders / docs / lint / prod hygiene
Flag:
- long constructors where a plain struct literal or small ctor suffices (no `typed-builder` dependency in this repo; do not demand it)
- `#[allow]` without `reason=`
- `.unwrap()` / `.expect()` in prod paths
- missing public docs (every pub item documented; `missing_docs` warn)
- `dbg!`, debug `println!`
- hardcoded creds
- any required verification run that still has warnings or errors

Verification gate:
- `mise run format` must be green (`hk` pre-commit is enforcement: sort → rustfmt → `cargo-check` → `clippy --all-targets -- -D warnings`)
- if Rust code changed, `mise run test` must also be green (nextest over the whole workspace)
- zero exit status is not enough if output still contains warnings
- do not approve or call the task/review complete while lint/format/test output is dirty

## Rust lenses

### Type / API design
Flag:
- primitive obsession
- stringly typed APIs
- anemic domain types
- wrong behavior outside owning type
- public APIs easy to misuse
- leaked external types without strong reason
- smart-pointer / wrapper-heavy public APIs
- `Box<dyn ...>` / `Arc<dyn ...>` / `Rc<dyn ...>` without strong reason

Prefer:
- newtypes / value objects
- strong OS/string/path types
- inherent methods for essential behavior
- free fn only when no natural receiver
- builders for complex construction
- type-state when state machine matters

### Borrowing / ownership
Flag:
- `.clone()` to satisfy borrow checker
- repeated heap clones on hot/common paths
- `&String`, `&Vec<T>`, `&PathBuf`, `&Box<T>` in APIs
- missed `mem::take` / `mem::replace` / `Option::take`
- wide mutable borrows that should be split
- `Rc`/`Arc` used as borrow-checker bandage, not true shared ownership

### Trait design
Review missing/misused:
- `Debug`, `Display`, `Default`
- `Eq`, `PartialEq`, `Ord`, `PartialOrd`, `Hash`
- `FromStr`, `TryFrom`, `AsRef`, `Borrow`
- `Iterator`, `IntoIterator`
- `Deref` used as fake inheritance

Rules:
- recommend `Ord` only for true total order
- use `PartialOrd` for partial order
- use sort-key newtype / comparator type for contextual order
- trait impls should usually complement inherent API, not hide it

### Async / concurrency / throughput
Flag:
- `Rc` / `RefCell` / `!Send` state across `.await`
- futures likely not `Send` on general async paths
- long CPU-bound async work with no yield points
- per-connection `tokio::spawn` that blocks on shared locks (cert keygen must stay on caller, never under lock)
- 10s handshake timeouts bypassed (unbounded pre-auth reads)
- throughput-hostile one-item APIs when batching natural
- correctness-sensitive statics / thread-locals in libraries

### Panic / unsafe / docs / resilience
Flag:
- panic-prone public APIs
- `unwrap` / `expect` / `todo` / `unimplemented` in prod paths
- `unsafe` without need, without safety docs, or with too-wide surface
- unsound safe abstractions
- undocumented magic constants
- sensitive data logging

## High-signal search targets

Inspect hits in context; do not report grep blindly.

Search for:
- `unwrap(` `expect(` `panic!(` `todo!(` `unimplemented!(` `dbg!(`
- `#[allow(` `#![allow(` `#[expect(`
- `unsafe` `transmute` `from_raw` `into_raw` `get_unchecked`
- `collect::<Vec` `.collect()` `Vec<`
- `dangerous(` `NoVerify` `verify_upstream` `with_custom_certificate_verifier`
- `expose_secret` outside substitution boundary, secret values in `tracing!`/`eyre!`
- `Box<dyn` `Arc<dyn` `Rc<dyn`
- `Rc<` `RefCell<` `Mutex<` `RwLock<`
- `pub use .*\*`
- helper names like `compare_` `sort_` `normalize_` `parse_` `build_` `matches_` `detect_`
- suspicious `.clone()` / `.to_string()`
- public sigs with `String` `&String` `Vec` `&Vec` `PathBuf` `&PathBuf`
- `intercept_candidate` callers that MITM without a grant match

## Workflow

1. Map workspace + module roles.
2. Check dependency direction vs `AGENTS.md`.
3. Audit public APIs first.
4. Inspect high-signal hits.
5. Separate real findings from false positives.
6. Output only evidence-backed findings.

## Output format

Keep terse. No long paragraphs.

### 1. Summary
5-12 bullets. Highest impact first.

### 2. Findings grouped by topic
No markdown tables. No pipe-delimited finding rows. Group related findings; readability beats row compression.

Use short topic headings:
- `Architecture / boundaries`
- `Grants / fail-closed`
- `Substitution / framing`
- `Errors / fallbacks`
- `Validation / config`
- `API / docs`
- `Domain / idioms`
- `Tests / resilience`
- `Unsafe / panic / lint`

Format:
```markdown
#### Grants / fail-closed
- **F<n> — <severity> — <category>**
  loc: `<file:item:line>`
  rule: `<rule refs>`
  evidence: `<verbatim quote>`
  problem: <what breaks>
  why: <repo/Rust reason>
  fix: <concrete refactor>
  scope/conf: <local|cross-cutting> / <high|medium|low>
```

Categories: `architecture`, `module boundaries`, `grants/fail-closed`, `substitution/framing`, `upstream verification`, `validation`, `API shape`, `domain modeling`, `idiomatic rust`, `ownership/borrowing`, `trait design`, `error handling`, `panic behavior`, `async/concurrency`, `unsafe/soundness`, `documentation`, `testing/resilience`, `performance`.

### 3. Repo-rule map
Map each repo rule to finding IDs or `none`:
- module map
- no optionality / no fallbacks
- fail-closed MITM (grant match, redaction, always-verify upstream)
- substitution framing discipline
- validate once
- runtime config ownership (confique overlay)
- error boundaries (eyre everywhere)
- no typed-builder
- no lint suppression without reason
- no unwrap/expect in prod
- public docs

### 4. Free-fn audit
One line each:
`<loc> | <fn> | inherent method / trait impl / newtype+impl / builder-type-state / acceptable free fn | <why>`

### 5. Trait audit
One line each:
`<loc> | <trait> | missing / misused / should avoid | <why> | <fix>`

### 6. Cross-cutting audits
Use short bullets for:
- API/ownership
- substitution/data-flow
- unsafe/panic/lint/docs

### 7. Top refactors
Max 10 lines:
`R<n> | <refactor> | impact:<high/med/low> | diff:<high/med/low> | risk:<high/med/low> | architecture / idiomatic / both`

### 8. Keep as-is / false positives
Required. One line each:
`<loc> | <suspicious thing> | keep | <why>`

## Style constraints

- strict, direct, evidence-based
- no praise
- no vague “clean this up”
- if unsure, say unknown precisely
- no recommendation may violate `AGENTS.md`
- prefer architecture/correctness over nits
- free fn not auto-wrong; move only if natural receiver exists
- cite rule relevance, not rule name only
