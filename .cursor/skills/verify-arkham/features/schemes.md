# List schemes

`arkham schemes` prints each supported grant URL scheme, one per line, so a user can see which allow entry spellings the proxy understands.

## Sub-features

- `schemes-list` prints the scheme set and exits 0.

## How to get to it (user POV)

- Run `arkham schemes`.

## Driving it with verify-arkham helpers

Preconditions:

- `doctor.sh` exited 0.

- **List.** `"$ARKHAM" schemes`. Exit 0.
- **Pass when.** Stdout includes at least `http`, `https`, `tcp`, `postgres`, `redis`, `ssh` (full set grows with protocols; compare against current `arkham schemes` in this checkout).
- **Proof.** Save stdout to `artifacts/schemes-<runid>/schemes.txt`.

## Gotchas

- Order is stable in practice but assert by set membership, not byte-identical dump across releases, unless the change under test claims a specific ordering.
