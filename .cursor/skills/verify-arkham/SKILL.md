---
name: verify-arkham
description: Drive the arkham CLI the way a user does (fake, serve, HTTP credential swap, grant gate). Use when proving a change to proxy substitution, grants, CA, or CLI dispatch without relying only on unit tests.
---

# Verify arkham (CLI)

Primary surface: the `arkham` binary. Secondary surfaces (do not use as the default proof): `mise run demo` (docker tproxy compose), `mise run demo:bwrap`, live capture tests (`test:tun` / `test:tproxy` / `test:ebpf`, root).

## Launch

From the repo root:

```sh
mise run build:debug
```

Ready when `./target/debug/arkham --version` prints a version line. There is no long-lived app server for CLI features; each drive starts its own isolated proxy and upstream (see helpers). Do not attach to a user's existing `arkham serve` on `:8080`.

Teardown: kill only the PIDs the helper started (the helper's `trap` does this). Proof under `.cursor/skills/verify-arkham/artifacts/` must survive teardown.

## Doctor

```sh
.cursor/skills/verify-arkham/helpers/doctor.sh
```

Requires an executable `target/debug/arkham` (override with `ARKHAM_BIN`), `curl`, and `python3`. Exit non-zero means do not drive.

## Drive

Prefer feature recipes under `features/`. For the core credential-swap journey:

```sh
.cursor/skills/verify-arkham/helpers/tutorial-http-swap.sh
```

Optional env: `ARKHAM_BIN`, `LISTEN_PORT` (default 18080), `UPSTREAM_PORT` (18000), `OFF_PORT` (18001), `ARTIFACTS`, `KEEP_WORK=1`.

Harness handles are CLI flags and HTTP headers from `docs/user/tutorial.md`, not UI selectors.

Heavy path (optional, not required for a routine proof): `mise run demo` asserts the scenario table in `integration/README.md`. Needs docker and `integration/.env`.

## Evidence

Default location: `.cursor/skills/verify-arkham/artifacts/<feature>-<runid>/`.

Proof standards:

- Exercise the real user path (`arkham fake`, `arkham serve --config`, `curl -x`, grant miss).
- Capture action and resulting state: decoy value, client response body, upstream `seen` header file, off-grant response.
- Side effects: upstream file must show the real secret on a grant hit; client body and off-grant path must not.
- Do not treat `mise run test` alone as proof of the user path.

## Cleanup

Helpers remove their temp workdirs and stop only the processes they spawned. Never `pkill arkham`. Leave `artifacts/` in place.

## Helpers

| Script | Invocation |
| --- | --- |
| doctor | `.cursor/skills/verify-arkham/helpers/doctor.sh` |
| tutorial HTTP swap + grant gate | `.cursor/skills/verify-arkham/helpers/tutorial-http-swap.sh` |

Both are executable. Read `features/README.md` before picking a recipe.

## Feature map

See [features/README.md](features/README.md). After product changes, refresh the map with `/maintain-verification-skill`.
