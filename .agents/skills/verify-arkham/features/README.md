# arkham verification map

Maintained source for verifying user-facing arkham CLI behavior. Read this index, then the matching feature file.

## Baseline preconditions

- Build `target/debug/arkham` with `mise run build:debug` (or set `ARKHAM_BIN`).
- Run `.cursor/skills/verify-arkham/helpers/doctor.sh` and require exit 0.
- Use isolated ports (helpers default to 18080 / 18000 / 18001). Never drive a proxy you did not start.
- Work from a disposable config directory the helper creates; do not write into the developer's `~/.config/arkham`.

## Driving conventions

- Start every recipe from doctor-ok with no shared proxy.
- Treat commands as literal; keep quoted flags unchanged.
- Capture stdout, stderr, exit codes, and named artifact files.
- Restore nothing global; only helper-owned processes and temp dirs.

## Proof and skip reporting

- Capture the user action and the resulting state (client view and upstream view for swaps).
- Mutation / side-effect proof: upstream file contents, not only curl exit 0.
- Record the feature ID and entry point with every artifact (`SUMMARY.txt`).
- Report an unreachable path with the unmet precondition; do not mark it verified via another path.

## Feature entry contract

Each feature file: H1, one paragraph, then exactly `Sub-features`, `How to get to it (user POV)`, `Driving it with verify-arkham helpers`, `Gotchas`.

## Features

- [Print a decoy](./fake.md) — `arkham fake` deterministic decoy for an env name.
- [HTTP credential swap](./credential-swap.md) — tutorial path: serve + curl through proxy; upstream sees real, client sees decoy.
- [Grant gate](./grant-gate.md) — non-allowed destination keeps the decoy; real secret must not appear.
- [List schemes](./schemes.md) — `arkham schemes` prints supported URL schemes.
- [Mint a CA](./ca.md) — `arkham ca` writes `ca.pem` / `ca.crt` / `ca.key` beside the configured CA path.
