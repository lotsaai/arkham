# Secure agent workspace

This is a workspace you can secure. `.config/arkham/config.toml` is the whole input, and `arkham init` turns it into a two-service docker compose stack: arkham, and the agent. `arkham agent` does that, starts it, and drops you into the agent in one go.

The agent container holds decoy credentials and shares arkham's network namespace, so every connection it makes is captured, with no proxy setting to find and no way around the proxy. arkham swaps a decoy for the real value only on the hosts your rules allow, and puts the decoy back on the response.

## What the two services do

| Service | Job |
| --- | --- |
| `arkham` | Captures egress transparently (backend chosen by `arkham init --backend`, `ebpf` by default), terminates TLS on a grant match, swaps decoys for real values, redacts them back on the response. Holds the CA, and resolves real values from fnox itself. |
| `agent` | Runs the agent behind an entrypoint that trusts arkham's CA, which is all it takes to make a secure agent work. Holds decoys only. |

## Topology

```text
  agent            shares arkham's network namespace, no proxy setting
    |
    |  every connection, captured transparently in the shared namespace
    v
  arkham            grant match: terminate TLS, swap the decoy for the real value
    |
    +--> api.anthropic.com   grant matched, the real key goes on the wire
    +--> anything else       spliced byte for byte, the decoy stays on the wire
```

## Before you start

- docker with compose, and arkham on `PATH`.
- The secrets this workspace uses, declared to fnox. `.config/arkham/config.toml` names `[rules.anthropic]` and `[rules.github]`. The registry supplies their hosts and decoy shapes.
- The arkham service mounts your fnox config directory and arkham's fnox files read-only. The generated compose file contains no provider credential from your environment.

## Run it

From this directory:

```sh
arkham rules            # preview what derives: fnox declarations ∩ registry, as [rules.*] blocks
arkham init             # the stack, the CA, and the entrypoint (--backend ebpf by default)
arkham up               # start both services
arkham logs -f          # the stack's logs, following
arkham agent            # init, up, and a shell in the agent — one idempotent command
arkham agent --rm       # the same, stopping both when the shell exits
arkham down             # stop both
```

`init` writes three things. It replaces `agent-entrypoint.sh` when the copy differs from the generated script. `init` replaces the compose file when the workspace config or the stack shape changes. When neither has changed, `init` leaves the compose file in place. `init` leaves an existing `ca.pem` in place.

| Path | What it is |
| --- | --- |
| `<state-dir>/arkham/ws/<slug>/compose.yml` | the generated stack, which is yours to edit (`<state-dir>` is `~/.local/state` on Linux) |
| `~/.config/arkham/ca.pem` | arkham's CA, with `ca.crt` and `ca.key` written beside it |
| `~/.config/arkham/agent-entrypoint.sh` | the agent's entrypoint |

`up` merges three compose layers, later winning: `<config-dir>/arkham/compose.yml`, the generated file above, then this workspace's `.config/arkham.compose.yaml` if you create one.

## Where the secrets live

The real values stay in fnox; the arkham service resolves them itself when a request matches a grant. The agent gets one deterministic decoy per rule, shaped by that rule's pattern:

```sh
arkham fake ANTHROPIC_API_KEY    # what the agent sends
arkham fake GH_TOKEN
```

A decoy follows the env name, so renaming a variable changes its decoy and substitution stops matching until you regenerate. A rule whose key fnox does not declare produces no decoy at all.

## Check that it works

```sh
arkham agent -- curl -sS https://api.anthropic.com/v1/models -H "x-api-key: $ANTHROPIC_API_KEY"
```

No proxy variable is set anywhere: the connection is captured on its way out. `api.anthropic.com` is a grant, so arkham terminates TLS with its own CA and the upstream sees your real key rather than the decoy.

To watch the swap, set `RUST_LOG: debug` on the arkham service in the generated compose file and read its log. The matching lines name the label and the location, never a value:

```sh
docker compose -f ~/.local/state/arkham/ws/<slug>/compose.yml logs arkham | grep substituted
```

```text
substituted label=anthropic location=Header
```

## Notes

- Capture covers every destination in the namespace, LAN included. A connection with no matching grant is spliced byte for byte, so nothing on your network breaks.
- UDP is passed through. DNS goes to the system resolver, and QUIC on port 443 is dropped, so clients fall back to TCP.
- The listener is on loopback in the shared namespace, so `HTTPS_PROXY=http://127.0.0.1:8099` works as a fallback if you would rather not rely on capture. Both paths can be live at once.
- Keep your own mounts, devices, and environment on the `agent` service: the generated file is a normal compose file for you to edit. To run other images, override `image:` in a compose layer.
- Each `profiles/<name>/<tool>/` directory mounts into the agent at that tool's default config location, writable. `__shared__` is the base every profile inherits.
- Recreate the two services together. The agent shares arkham's network namespace, so recreating arkham alone leaves it attached to a dead namespace and its DNS stops resolving.

[How to secure your workspace](../../docs/user/how-to/confine-a-workspace.md) covers the whole flow, and the [main README](../../README.md) covers allow entries, decoy patterns, and the rest of the configuration.
