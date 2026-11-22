# arkham verification map

Maintained source for verifying user-facing arkham behaviour. Read this index, then the matching feature file.

## Baseline preconditions

- Drive only through mise tasks (`mise run verify:<feature>`, `mise run --force test`). Never run binaries or scripts directly.
- The tasks build `target/debug/arkham` themselves and isolate `HOME` and `XDG_CONFIG_HOME`.

## Driving conventions

- One task per feature; `mise run verify` runs them all.
- Treat task names as literal.

## Proof and skip reporting

- Capture the user action and the resulting state; for swaps, the client view and the upstream record.
- A task that fails with `verify fail:` is an environment failure: report it, do not mark the feature verified another way.

## Feature entry contract

Each feature file: H1, one paragraph, then exactly `Sub-features`, `How to get to it (user POV)`, `Driving it with mise tasks`, `Gotchas`.

## Features

- [Print a decoy](./fake.md) — `arkham fake`.
- [List schemes](./schemes.md) — `arkham schemes`.
- [Mint a CA](./ca.md) — `arkham ca`.
- [Preview rules](./rules.md) — `arkham rules`.
- [Reference config](./config.md) — `arkham config`.
- [Curate OAuth registry entries](./registry.md) — `arkham registry from-oidc` / `from-openapi`.
- [HTTP credential swap](./credential-swap.md) — tutorial §1–5.
- [Grant gate](./grant-gate.md) — tutorial §6.
- [HTTPS swap with CA trust](./https-swap.md) — tutorial §7.
- [Confined agent session](./confine-agent.md) — `arkham daemon run` + `arkham agent`.
- [Protocol swaps](./protocol-swaps.md) — Postgres, Redis, SMTP, LDAP, NATS, AMQP, SSH, HTTP/OAuth2 fixtures.

Not yet mapped: `serve --proxy-backend ebpf` with a hand-made cgroup, `[plugins]`, profiles, `[[workspace.file_rewrite]]`, `daemon install/start`.
