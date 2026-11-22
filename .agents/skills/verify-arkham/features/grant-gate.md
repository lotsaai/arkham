# Grant gate

When the destination is not on the rule's allow list, arkham splices instead of substituting: the upstream receives the decoy and the real secret never leaves the proxy.

## Sub-features

- `gate-decoy-upstream` the off-grant upstream records the decoy.

## How to get to it (user POV)

- Tutorial §6: a second upstream on an uncovered port, same `curl -x`.

## Driving it with mise tasks

- **Run.** `mise run verify:http-swap` (the gate runs after the swap).
- **Observe.** `off-upstream-seen.txt`, `off-grant-body.txt`.
- **Pass when.** `PASS http-swap`.
- **Transparent capture.** Integration scenarios 5 and 28 under `mise run --force test`.

## Gotchas

- The upstream's own record is the proof. Absence of the real value in a body that never echoes headers proves nothing.
