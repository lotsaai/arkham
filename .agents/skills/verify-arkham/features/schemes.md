# List schemes

`arkham schemes` prints each URL scheme the proxy serves, one per line, so a user can see which allow entry and connection-string spellings arkham understands.

## Sub-features

- `schemes-list` prints `http https tcp postgres redis rediss ldap ldaps ssh smtp smtps nats amqp amqps` and exits 0.

## How to get to it (user POV)

- `arkham schemes`.

## Driving it with mise tasks

- **Run.** `mise run verify:schemes`.
- **Pass when.** `PASS schemes`.

## Gotchas

- Assert by set membership unless the change under test claims an ordering.
- A new scheme must also be claimed by a `test:<protocol>` task; the e2e harness fails otherwise.
