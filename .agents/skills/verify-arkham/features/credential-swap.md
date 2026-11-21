# HTTP credential swap

On a grant match, the explicit proxy replaces the client's decoy bearer with the real secret toward the upstream, and redacts the real secret back to the decoy in the response the client sees.

## Sub-features

- `swap-upstream` the upstream records the real secret.
- `swap-client` the client body carries the decoy.

## How to get to it (user POV)

- `docs/user/tutorial.md` steps 1–5: config, `arkham fake`, upstream, `arkham serve`, `curl -x`.

## Driving it with mise tasks

- **Run.** `mise run verify:http-swap`.
- **Observe.** `artifacts/http-swap-<runid>/client-body.txt`, `upstream-seen.txt`, `proxy.log`.
- **Pass when.** `PASS http-swap`.
- **Transparent capture.** `mise run --force test` runs integration scenarios 1–4 and 7 (`integration/README.md`), the same swap without a proxy setting.

## Gotchas

- The task uses a real value of the decoy's length. The tutorial's `real-secret-value-xyz` is shorter, and an unequal-length response redaction empty-replies the client (product gap).
- A green curl exit is not proof; the upstream record is.
