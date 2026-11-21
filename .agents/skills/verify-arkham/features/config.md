# Reference config

`arkham config` prints a reference config with every setting, its default, and its doc comment. Load errors surface first and secrets never appear.

## Sub-features

- `config-print` prints the reference with `[proxy]` and `#listen = "127.0.0.1:8080"`, and exits 0.

## How to get to it (user POV)

- `arkham config` (CLI reference).

## Driving it with mise tasks

- **Run.** `mise run verify:config`.
- **Pass when.** `PASS config`.

## Gotchas

- `--config` is global: it goes before the subcommand.
- The load-error path (a broken project config) has no task yet.
