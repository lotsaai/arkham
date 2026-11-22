# HTTPS swap with CA trust

For an `https://` allow entry, arkham terminates the client's TLS with a leaf signed by its CA, swaps the decoy for the real value, and re-encrypts toward the upstream. A client that does not trust `ca.crt` is refused.

## Sub-features

- `https-untrusted` curl without `--cacert` fails verification (exit 60) and the upstream sees nothing.
- `https-trusted` with `--cacert ca.crt` the upstream records the real value and the client gets the decoy.
- `https-root-cert` the upstream's self-signed certificate is trusted through `[rules.<label>.tls."<entry>"] root_cert`.

## How to get to it (user POV)

- Tutorial §7 and the trust-the-ca how-to. The tutorial uses `https://example.com`; the task uses a local TLS upstream so no network is needed.

## Driving it with mise tasks

- **Run.** `mise run verify:https-swap`.
- **Observe.** `untrusted-exit.txt`, `client-body.txt`, `upstream-seen.txt`.
- **Pass when.** `PASS https-swap`.

## Gotchas

- The allow entry and the `tls` table key must be the same string.
- Same equal-length caveat as the HTTP swap.
