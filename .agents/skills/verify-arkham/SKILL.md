---
name: verify-arkham
description: Prove arkham's user-facing behaviour (decoys, HTTP/HTTPS swap, grant gate, CA, rules, registry curation, daemon + confined agent, protocol fixtures) through the repo's mise tasks. Use when a change to substitution, grants, CA, CLI, or confinement needs proof beyond unit tests.
---

# Verify arkham

Every drive is a mise task. Never run arkham, its helpers, docker fixtures, or test scripts directly. On the Arch workstation `mise.arch.toml` attaches each task to the `sandbox` daemon, which brings the `arkham-dev` machine up when it is down.

## Launch

Nothing to launch by hand. Each `verify:*` task depends on `build:debug` and stops what it started on exit. Upstreams are `python:3-alpine` containers on docker-assigned ports; `arkham serve` and `arkham daemon run` run natively on `127.0.0.1:0` and the task reads the bound port from their `serving` / `host daemon ready` line. No port is chosen ahead of time.

## Doctor

`mise tasks ls` lists `verify` and `verify:*`. A task that fails before its first `expect` (`verify fail: …`) is an environment problem: stop and report it to the user; never work around it.

## Drive

| Task | Feature | Proves |
|---|---|---|
| `mise run verify` | all of the below | runs each `verify:*` in turn |
| `mise run verify:fake` | [fake](features/fake.md) | stable, distinct, `--pattern` |
| `mise run verify:schemes` | [schemes](features/schemes.md) | every served scheme listed |
| `mise run verify:ca` | [ca](features/ca.md) | `ca.pem`/`ca.crt`/`ca.key`, key never on stdout |
| `mise run verify:rules` | [rules](features/rules.md) | derived and uncovered fnox names |
| `mise run verify:config` | [config](features/config.md) | reference config |
| `mise run verify:registry` | [registry](features/registry.md) | `from-oidc` / `from-openapi` fragments |
| `mise run verify:http-swap` | [credential-swap](features/credential-swap.md), [grant-gate](features/grant-gate.md) | tutorial §1–6 |
| `mise run verify:https-swap` | [https-swap](features/https-swap.md) | tutorial §7, offline |
| `mise run verify:agent` | [confine-agent](features/confine-agent.md) | daemon + agent, eBPF capture |
| `mise run --force test` | [protocol-swaps](features/protocol-swaps.md) and everything above at unit/e2e level | the repo's full suite |

The tasks live in `.mise/tasks/verify/`; their shared code and fixtures in `integration/verify/`.

## Evidence

Each `verify:*` writes `.agents/skills/verify-arkham/artifacts/<feature>-<runid>/` (gitignored): `command.txt`, `stdout.txt`, `stderr.txt`, `exit.txt`, `workspace-files.txt` for CLI features; client body, upstream record, and logs for swaps; `SUMMARY.txt` on pass. A failing `expect` prints `proof fail: <what>; see <dir>`.

Proof standards: the real user path (CLI, `curl -x`, `arkham agent --`); both sides of the wire; off-grant upstream records the decoy. `mise run test` green alone is not a user-path proof.

## Cleanup

Tasks remove their own processes, containers (`arkham-verify-*`), temp work dirs, and the temporary file capabilities `verify:agent` grants. Evidence stays.

## Feature map

See [features/README.md](features/README.md). After product changes, refresh it with `/skill:maintain-verification-skill`.
