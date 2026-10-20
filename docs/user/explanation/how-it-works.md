# How arkham works

The machinery behind the credential swap, and why each piece is shaped the way it is. Nothing on this page is needed to run arkham; it is for the person asking what actually happens to a packet.

## The problem arkham solves

A coding agent needs credentials to talk to APIs. The moment the agent holds the real credential, every path it has to exfiltration (a prompt-injected `curl`, a dependency that phones home, a log line, a paste) carries the real value. You cannot fix this with a secret manager, because the manager hands the real value to exactly the party you do not fully trust.

arkham inverts who holds what. The agent holds a decoy: deterministic for the env name, format-valid, and useless everywhere except the hosts you granted. The real value lives in fnox, resolved by arkham at serve time, and appears on the wire only to a granted authority. The agent never sees it, not even in memory — and because the swap happens in the proxy, the agent works unchanged.

## The life of a connection

Two capture paths feed the same machinery.

**Explicit proxy.** The client points `HTTP(S)_PROXY` at arkham's listener. Every connection arrives labelled with its destination host and port.

**Transparent capture (Linux).** `--proxy-backend` selects a backend. `tproxy` installs an `IP_TRANSPARENT` listener plus nftables rules and policy routes over netlink, so the kernel redirects every outbound TCP connection in the namespace to arkham; UDP passes through and QUIC on port 443 is dropped so HTTP/3 clients fall back to TCP. `tun` opens a TUN device and feeds it into a userspace stack (smoltcp, medium-ip, any-ip), with policy routes in a dedicated table pointing at the device, and handles UDP itself: DNS relayed to the system resolver, QUIC dropped, other flows relayed to their destination. `ebpf` attaches three programs to a cgroup over `bpf(2)` — a `connect4` hook that records the real destination in a map keyed by socket cookie and rewrites the address to arkham's loopback listener, an egress hook that indexes the redirected flow by its local 4-tuple so the accepted connection can be resolved back, and a `recvmsg4` hook that restores the original source on relayed UDP replies. No netfilter, no policy routes, no `IP_TRANSPARENT`; the attach handles belong to the process, so exit detaches the programs. All three are peers — same interception contract, different mechanism — and in all three the client configured nothing and cannot bypass the proxy. arkham keeps its own upstream dials out of its own capture: a fwmark for `tproxy` and `tun`, cgroup membership plus a PID comparison for `ebpf`.

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

**Capture opts in at the CLI only.** Capture mutates host routes, and TPROXY also host nft rules. Reading it from a config file would make it ambient; arkham requires the explicit flag, binds its listener before touching the host, and tears the rules down on exit.

## Where the secrets live

Real values come from an inline `value` (wins) or from fnox, whose discovery chain arkham extends with one level of its own (`<config-dir>/arkham/fnox.toml`). arkham logs label and location only. Environment redactions (`*_TOKEN`, `*_SECRET`, `*_KEY`, `*_PASSWORD`) keep values out of its own environment dumps.

The CA is a file pair: certificate plus key in `ca.pem` for arkham, certificate alone in `ca.crt` for clients. Whoever holds the key can mint leaves, so `ca.key` goes nowhere.
