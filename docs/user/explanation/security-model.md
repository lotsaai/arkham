# The security model

What arkham defends against, what it does not, and the edges you are choosing to accept. Read this before relying on it for anything that matters.

## The property arkham buys you

A credential that leaves the agent is the decoy. The agent holds only a format-valid fake and works unchanged — the swap is transparent. Concretely:

- **Exfiltration to a third party.** A prompt-injected tool, a curious dependency, or a log sink receives the decoy. Any host outside the allow entries gets the decoy and rejects it. The real value never travels there.
- **Leaked environment or config.** A container dump, a screenshot, a paste of `env`: all carry decoys, which are deterministic and safe to commit.
- **The token-issuance path.** When a rule's registry entry declares an OAuth2 flow, freshly issued tokens never reach the agent: the proxy rewrites the token response, the agent holds a minted decoy, and later requests swap it back. Rotating refresh tokens get one decoy per issued value.
- **The response path.** arkham redacts real values back to decoys in responses, so even output from a granted host shows the client the fake.

## Runtime token minting

Static decoys are seeded on the env name; minted decoys are seeded on the real token value and render from the same registry pattern, so a minted decoy has the same shape as every other decoy. Minted pairs live in the proxy's memory for the process lifetime and are shared across connections, because agents reuse tokens across connections.

The trigger is a grant plus a declared flow, never shape alone: a JSON body on an ungranted host that happens to contain `access_token` is untouched. On a flow-granted endpoint, a token response that cannot be parsed as a flat JSON object passes through unchanged; the proxy mints only what it can positively identify. A token body larger than the internal cap, or a chunked body whose framing does not validate, fails closed: the connection drops rather than forward a real token. Compressed token responses are opaque to the proxy and pass through; a vendor that compresses token responses reduces coverage, not safety.

The proxy translates and never participates in the protocol: it does not initiate refreshes, hold expiry timers, or schedule token acquisition. What the agent does, the proxy observes and translates.

### Edges you accept

| Edge | Consequence |
| --- | --- |
| Proxy restart | Minted decoys are memory-only. A restarted proxy does not know the decoys the agent still holds; the next request sends an unknown decoy, the upstream rejects it, and the agent re-authenticates. |
| Authorization-code browser leg | The redirect `code` reaches the agent unchanged. A human login on their own machine is outside the model. |
| Compressed token responses | Not rewritten (opaque to the proxy). Coverage gap, not a leak direction. |
| Mint-failure passthrough | A body that is JSON but unparseable, or a mint error, passes through with the field it could not mint. Rare and logged. |

The grant list is the blast radius. `https://api.anthropic.com` means the real key reaches exactly that authority (any path on it, see below) and nowhere else.

## What arkham is not

- **Not a sandbox.** arkham constrains where a real credential travels on the wire. It does not constrain what the workload computes, reads, or writes. A workload that can exfiltrate data can exfiltrate everything except the real credential.
- **Not path authorisation.** Grants match the authority. A grant to `https://api.example.com` permits `/admin` as much as `/v1/models`. If an API's paths differ in sensitivity, treat the credential as granted to all of them.
- **Not protection against credential-derived payloads.** arkham swaps the decoy where it appears verbatim, in headers, basic auth, and bodies, over HTTP/1 and HTTP/2. A workload that hashes, signs, or re-encodes the credential before sending sends a decoy-derived value, and the upstream rejects the request. That rejection is the system working; it is also a workload arkham cannot help.
- **Not anonymous.** arkham terminates TLS on granted hosts, which means it reads that traffic. You are moving trust from the API's certificate to your CA, deliberately, for a scoped set of hosts.

## Edges you accept

| Edge | Consequence |
| --- | --- |
| `*` as a grant host | Matches any destination. arkham warns at startup; the exposure is yours to accept. |
| A non-loopback listen address | Anyone reaching the port triggers real-secret substitution. Warned at startup. |
| CA key distribution | Whoever holds `ca.key` or `ca.pem` can mint leaf certificates and intercept granted traffic. Distribute `ca.crt` only. |
| Compromised arkham process | It holds every real value and the CA. It runs as root with capture enabled, and with `CAP_NET_ADMIN` under TPROXY. Treat the arkham container as tier-zero; keep its mounts minimal. |
| Workload trusts extra CAs | A workload with its own MITM proxy in front of arkham sees pre-substitution traffic only if it holds the real credential, which it does not; but it can still see decoy traffic and everything else in the namespace. |
| QUIC to non-443 ports | Passes through unintercepted. Only `:443` QUIC is dropped. |

With `--proxy-backend tun`, UDP is not a pass-through: DNS is relayed to the system resolver and other non-443 UDP flows are relayed to their original destination from inside arkham, so the workload's UDP leaves from arkham's sockets.

With `--proxy-backend ebpf`, connected UDP is relayed unchanged (no substitution), and unconnected `sendto` traffic such as typical DNS is not captured at all. Capture is scoped by cgroup membership rather than by network namespace, so a process that escapes the cgroup leaves the capture; arkham must be run outside that cgroup, which the PID check enforces a second time. The capability set is `CAP_BPF` + `CAP_NET_ADMIN` rather than the wider privileges `tun` needs.

## Fail-closed defaults

The design prefers refusal over degradation:

- A fnox-declared key that cannot resolve fails startup, whatever `if_missing` says. Only an undeclared key honours `warn`/`ignore`.
- A capture leg that dies ends the process rather than silently serving explicit-proxy only.
- Malformed traffic closes the connection quietly; framing uncertainty degrades to opaque byte forwarding, never to skipping substitution.
- Two rules sharing an env name, an empty value, a malformed grant or pattern: startup refuses.

## Residual trust

You still trust, in order: the arkham binary and its config path (anyone who edits the config can add a grant), the host running it, and the CA file's location. arkham shrinks the trusted surface from "every process in the workload" to "one process whose only job is not to leak".
