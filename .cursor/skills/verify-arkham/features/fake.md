# Print a decoy

`arkham fake` prints the deterministic format-valid decoy for an env var name. The same name always yields the same value; different names yield different values.

## Sub-features

- `fake-print` prints one decoy on stdout and exits 0.
- `fake-stable` repeats the same name and gets the identical string.
- `fake-distinct` uses two names and gets two different strings.

## How to get to it (user POV)

- Run `arkham fake <ENV_NAME>` from any directory (no config required for the default hex decoy).

## Driving it with verify-arkham helpers

Preconditions:

- `doctor.sh` exited 0.
- `ARKHAM` is `target/debug/arkham` or `ARKHAM_BIN`.

- **Print decoy.** Run `"$ARKHAM" fake DEMO_TOKEN`. Exit 0; stdout is a non-empty single line (known value `f92b2afa339693227aa209aac3eb48f9` for `DEMO_TOKEN`).
- **Stability.** Run the same command again. Stdout equals the first run byte-for-byte.
- **Distinct.** Run `"$ARKHAM" fake OTHER_TOKEN`. Stdout differs from `DEMO_TOKEN`'s decoy.
- **Proof.** Write both outputs under `artifacts/fake-<runid>/` as `demo.txt` and `other.txt` plus the commands in `SUMMARY.txt`.

## Gotchas

- Do not pass `--config` unless checking config-related decoy templates; the default path needs none.
- Trailing newlines: compare trimmed single lines.
- Never log or commit a real secret while proving decoys; this feature only prints fakes.
