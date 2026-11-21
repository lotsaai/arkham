# Protocol swaps

Connection-string rules (`postgres://`, `redis://`, `smtp://`, `ldap://`, `nats://`, `amqp://` and their TLS forms), SSH grants, and HTTP/HTTPS/TCP/OAuth2 grants swap the decoy for the real credential against official servers, with the client in a captured namespace and no proxy setting.

## Sub-features

- `proto-<scheme>` one per scheme in `arkham schemes`; the scenario table is `integration/README.md`.

## How to get to it (user POV)

- Write a connection-string rule (configuration reference, per-protocol sections), then connect with the protocol's own client.

## Driving it with mise tasks

- **Run.** `mise run --force test` (runs every `test:<protocol>` fixture).
- **Pass when.** Each protocol prints `=== test:<protocol> passed ===`; `target/integration/results/covered.json` lists every scheme.

## Gotchas

- Do not run a single `test:<protocol>` as a shortcut; the suite is the unit of proof.
- `integration/.env` and `integration/docker/arkham` are written into the checkout.
