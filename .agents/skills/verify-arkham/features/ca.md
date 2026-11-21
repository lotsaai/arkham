# Mint a CA

`arkham ca` generates or loads the MITM CA at the configured `ca_file`, prints the certificate PEM to stdout, and writes `ca.crt` (certificate) and `ca.key` (key) beside it so clients can trust arkham-terminated TLS.

## Sub-features

- `ca-write` creates `ca.pem`, `ca.crt`, `ca.key`; `ca.pem` and `ca.key` are mode 600.
- `ca-stdout` prints the certificate only, never the key.

## How to get to it (user POV)

- `arkham ca` with `[proxy] ca_file` set, or `arkham ca --config <file>` (tutorial §7, trust-the-ca how-to).

## Driving it with mise tasks

- **Run.** `mise run verify:ca` (fixture `integration/verify/fixtures/ca/arkham.toml`).
- **Pass when.** `PASS ca`; `workspace-files.txt` shows the modes.

## Gotchas

- `--ca-file` is a `serve` flag; `arkham ca` rejects it. Use `--config` or `ARKHAM_CA_FILE`.
- A second run loads the existing CA and re-syncs `ca.crt`/`ca.key`; it does not rotate.
