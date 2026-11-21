# Grant gate

When the destination is not on the rule's allow list, arkham must not substitute: the upstream (or response path) keeps the decoy, and the real secret never appears.

## Sub-features

- `gate-miss` sends the same decoy to a host/port with no allow entry.
- `gate-no-leak` asserts the real secret string is absent from the client-visible result.

## How to get to it (user POV)

- Tutorial §6: second upstream on an uncovered port, same `curl -x` with the decoy.
- Packaged inside `tutorial-http-swap.sh` after the grant-hit proof (off-port check).

## Driving it with verify-arkham helpers

Preconditions:

- Same as credential-swap; the helper runs the gate after the swap proof.

- **Run journey.** `.cursor/skills/verify-arkham/helpers/tutorial-http-swap.sh`
- **Observe.** `artifacts/tutorial-http-swap-<runid>/off-grant-body.txt` and `SUMMARY.txt`.
- **Pass when.** The file does not contain the helper’s real secret string. Helper exits 0.

## Gotchas

- A splice may still return some HTTP body from `python3 -m http.server`; absence of the real secret is the proof, not a specific body string.
- Do not weaken the check to "proxy logged splice" — logs are not the user-visible guarantee.
