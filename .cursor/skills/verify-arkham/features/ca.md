# Mint a CA

`arkham ca` generates or loads the MITM CA and writes `ca.pem`, `ca.crt`, and `ca.key` beside the configured `ca_file` so clients can trust arkham-terminated TLS.

## Sub-features

- `ca-write` creates the three files in a disposable config directory.
- `ca-stdout` prints the certificate PEM to stdout.

## How to get to it (user POV)

- Write a config with `[proxy] ca_file = "ca.pem"`, then run `arkham ca --config <that-file>` (see tutorial §7).

## Driving it with verify-arkham helpers

Preconditions:

- `doctor.sh` exited 0.
- Disposable work directory (do not use the user's real CA path).

- **Config.** Create `WORK/arkham.toml` with `listen` unused for this feature and `ca_file = "ca.pem"`.
- **Mint.** `(cd "$WORK" && "$ARKHAM" ca --config arkham.toml) > artifacts/ca-<runid>/stdout.pem`
- **Pass when.** `WORK/ca.pem`, `WORK/ca.crt`, and `WORK/ca.key` exist and `stdout.pem` contains `BEGIN CERTIFICATE`.
- **Cleanup.** Delete `WORK` only; keep `artifacts/ca-<runid>/`.

## Gotchas

- Running `ca` against a shared config dir can overwrite a developer CA — always use a temp dir.
- HTTPS swap proof needs `--cacert ca.crt` on curl; that is beyond this feature's mint-only scope.
