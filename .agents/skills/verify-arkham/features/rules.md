# Preview rules

`arkham rules` prints the `[rules.*]` blocks the workspace gets: every fnox-declared name the registry knows becomes a rule with its env name only, and fnox declarations no registry entry covers are listed at the end.

## Sub-features

- `rules-derived` `[rules.github_token]` / `env = "GITHUB_TOKEN"` for a registry-known declaration.
- `rules-uncovered` `# UNKNOWN_THING` under the "nothing derives" comment.
- `rules-no-values` no secret value is printed.

## How to get to it (user POV)

- `arkham rules` from the workspace root (confine-a-workspace how-to, "Preview your rules").

## Driving it with mise tasks

- **Run.** `mise run verify:rules` (fixture `integration/verify/fixtures/rules/fnox.toml`).
- **Pass when.** `PASS rules`.

## Gotchas

- fnox discovery also reads the user's global fnox config; the task isolates `HOME`, so only the fixture counts.
