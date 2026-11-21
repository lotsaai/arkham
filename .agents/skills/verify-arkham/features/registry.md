# Curate OAuth registry entries

`arkham registry from-oidc` and `from-openapi` turn a saved discovery or OpenAPI document into a `[providers.<slug>]` TOML fragment with an `oauth2` block, printed for review. They never fetch and never write files.

## Sub-features

- `registry-oidc` maps `token_endpoint` and `grant_types_supported`.
- `registry-openapi` maps every `type: oauth2` scheme and reports `openIdConnect` schemes as skipped.
- `registry-no-writes` the workspace holds only the input documents afterwards.

## How to get to it (user POV)

- `arkham registry from-oidc <FILE> <SLUG> <ENV>` and `arkham registry from-openapi <FILE> <SLUG> <ENV>` (registry reference).

## Driving it with mise tasks

- **Run.** `mise run verify:registry` (fixtures `integration/verify/fixtures/registry/`).
- **Pass when.** `PASS registry`.

## Gotchas

- Product gap: the "skipped security scheme" WARN lands on stdout inside the TOML (logs go to stdout), so stdout is not pasteable TOML. Report it; do not filter it out of the proof.
