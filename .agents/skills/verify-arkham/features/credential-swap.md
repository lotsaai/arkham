# HTTP credential swap

On a grant match, the proxy replaces the client's decoy bearer with the real secret toward the upstream and redacts the real secret back to the decoy in the response the client sees.

## Sub-features

- `swap-serve` starts the proxy from a disposable config with one HTTP allow entry.
- `swap-request` sends the decoy through `curl -x` to the granted upstream.
- `swap-upstream` shows the upstream recorded the real secret.
- `swap-client` shows the client body still carries the decoy.

## How to get to it (user POV)

- Follow `docs/user/tutorial.md` steps 1–5 (config, fake, upstream, serve, curl).
- Or run the packaged helper that automates that path.

## Driving it with verify-arkham helpers

Preconditions:

- `doctor.sh` exited 0.
- Ports 18080 / 18000 free (or override `LISTEN_PORT` / `UPSTREAM_PORT`).

- **Run journey.** `.cursor/skills/verify-arkham/helpers/tutorial-http-swap.sh`
- **Observe.** Open `artifacts/tutorial-http-swap-<runid>/SUMMARY.txt`, `client-body.txt`, `upstream-seen.txt`, `decoy.txt`.
- **Pass when.** `upstream-seen.txt` is `Bearer <real>` (helper’s equal-length real) and `client-body.txt` is `upstream saw: Bearer <decoy>` matching `decoy.txt`.

## Gotchas

- Helpers pick ephemeral ports by default; do not assume 18080.
- A green curl exit alone is not proof — always read the upstream `seen` file.
- `docs/user/tutorial.md` uses `real-secret-value-xyz` (≠ decoy length). On the current binary that yields curl empty-reply after a successful upstream swap; the helper pads to equal length so the client-visible redact can be proven. Treat unequal-length HTTP body redact as a separate product defect if still present.
- HTTPS / CA trust is a separate journey (`ca.md` plus tutorial §7); this feature is cleartext HTTP only.
