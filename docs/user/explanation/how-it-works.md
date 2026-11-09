# How arkham works

The machinery behind the credential swap, and why each piece is shaped the way it is. Nothing on this page is needed to run arkham; it is for the person asking what actually happens to a packet.

## The problem arkham solves

A coding agent needs credentials to talk to APIs. The moment the agent holds the real credential, every path it has to exfiltration (a prompt-injected `curl`, a dependency that phones home, a log line, a paste) carries the real value. You cannot fix this with a secret manager, because the manager hands the real value to exactly the party you do not fully trust.

arkham inverts who holds what. The agent holds a decoy: deterministic for the env name, format-valid, and useless everywhere except the hosts you granted. The real value lives in fnox, resolved by arkham at serve time, and appears on the wire only to a granted authority. The agent never sees it, not even in memory — and because the swap happens in the proxy, the agent works unchanged.

## The life of a connection

Two capture paths feed the same machinery.

**Explicit proxy.** The client points `HTTP(S)_PROXY` at arkham's listener. Every connection arrives labelled with its destination host and port.

**Transparent capture (Linux).** `--proxy-backend ebpf` captures IPv4 and IPv6 TCP and connected UDP from the selected cgroup in arkham's network namespace. It restores the original source on UDP replies and removes closed-socket records. Hosts without IPv6 support run IPv4-only. Capture does not require client proxy settings, but has exclusions. The cgroup and a PID check exclude arkham's own upstream connections.

Then, per connection:

1. **Gate.** arkham parses the connection head and checks the destination against the rules' allow entries. No match means splice: both directions are pumped through byte for byte, the client sees the real upstream certificate, and the decoy travels untouched. This is the default for the internet at large, and it is why non-matching traffic keeps working.
2. **Terminate.** For a matching TLS connection, arkham terminates TLS with a leaf signed by its own CA. This is why granted HTTPS hosts require client trust in the CA.
3. **Sniff.** arkham peeks at the plaintext stream to tell HTTP/1 from HTTP/2 (h2 preface) from raw bytes.
4. **Substitute.** Guest-to-server chunks pass through a request machine that swaps decoy for real; server-to-guest chunks pass through a response machine that swaps real back to decoy. The substitution engine walks HTTP/1 headers and bodies, and HTTP/2 headers via an hpack frame walker. Raw TCP (a `tcp://` grant) gets a byte-level scan-and-forward: framing uncertainty degrades to opaque scanning, never blocks.
5. **Mint (token issuers).** When the rule's registry entry declares an OAuth2 flow for this endpoint, the response machine buffers a token response whole, mints a decoy for each flow field (`access_token`, `refresh_token`), rewrites the body and its `Content-Length`, and records the pair in a process-lifetime store. Later request machines union the minted pairs, so a decoy minted on one connection substitutes on the next.
6. **Log.** A substitution logs its rule label and the location (`Header`, `BasicAuth`, `Body`), never a value.

## Why the pieces are shaped this way

**Grant by authority, not URL.** The client dials a host:port; the grant names a host:port. Path-level authorisation would require arkham to understand every API's semantics, and a workload that re-encodes or signs the credential defeats substitution anyway. Authority-level grants keep the model honest about what is enforceable.

**Decoys are deterministic.** A decoy seeded from the env name survives restarts and is safe to commit, which is what lets a compose file carry it as a plain environment variable. The cost is that renaming an env var changes the decoy, and a stale decoy stops matching.

**Splice is byte-identical.** Non-granted traffic is not re-serialised or re-framed. Performance and correctness both depend on the non-matching path being a pipe.

**Write-once state.** `ProxyState` is built once at startup behind an `Arc`; there is no reload. A `DashMap` holds `ServerConfig` for the Postgres, Redis, SMTP, LDAP, NATS, and AMQP transports, and the minted pairs. Per-connection work is a `tokio::spawn`, with a 10-second budget on pre-auth and dial phases.

**Capture opts in at the CLI only.** arkham requires an explicit flag to attach eBPF programs. It binds its listener before attaching them, and the programs detach on exit.

## Where the secrets live

Real values come from an inline `value` (wins) or from fnox, whose discovery chain arkham extends with one level of its own (`<config-dir>/arkham/fnox.toml`). arkham logs label and location only. Environment redactions (`*_TOKEN`, `*_SECRET`, `*_KEY`, `*_PASSWORD`) keep values out of its own environment dumps.

The CA is a file pair: certificate plus key in `ca.pem` for arkham, certificate alone in `ca.crt` for clients. Whoever holds the key can mint leaves, so `ca.key` goes nowhere.
