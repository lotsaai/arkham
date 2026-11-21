# Print a decoy

`arkham fake <ENV>` prints the deterministic format-valid decoy for an env var name. The same name always yields the same value, different names differ, and `--pattern` overrides the registry shape for one invocation.

## Sub-features

- `fake-print` prints one decoy line and exits 0 (`DEMO_TOKEN` → `f92b2afa339693227aa209aac3eb48f9`).
- `fake-stable` the same name gives the identical string.
- `fake-distinct` two names give two strings.
- `fake-pattern` `--pattern 'ghp_{hex:36}'` gives that shape.

## How to get to it (user POV)

- `arkham fake <ENV_NAME> [--pattern <PATTERN>]` from any directory.

## Driving it with mise tasks

- **Run.** `mise run verify:fake`.
- **Pass when.** `PASS fake`; `artifacts/fake-<runid>/stdout.txt` holds the last decoy printed.

## Gotchas

- `fake` still loads config and fnox discovery; when a rule resolves, INFO logs go to stdout ahead of the decoy (product gap). The task isolates `HOME` and sets `RUST_LOG=warn`.
- A registry-known name (`GITHUB_TOKEN`) gets the registry's shape, not `{hex:32}`.
