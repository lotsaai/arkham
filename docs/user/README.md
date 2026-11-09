# arkham user documentation

arkham keeps your coding agent productive while it protects your secrets. The agent holds only decoys and works as before. Real values stay in fnox. The proxy swaps them transparently on granted hosts.

Pick by what you need right now. New here? Secure your workspace.

| You want to | Go to |
| --- | --- |
| **Run an agent with decoys only** | [Secure your workspace](how-to/confine-a-workspace.md) — the primary flow. Your agent holds decoys and arkham swaps them transparently |
| **Learn the raw swap, first time** | [Tutorial](tutorial.md) — one credential swap through the proxy, end to end, both sides of the wire |
| **Get something done** | How-to guides, below |
| **Look something up while working** | Reference, below |
| **Understand why it works this way** | Explanation, below |
## How-to guides

Directions for a working practitioner, one goal each:

- [Secure your workspace](how-to/confine-a-workspace.md) — run a coding agent in a container that holds only decoys.
- [Capture traffic transparently](how-to/capture-traffic-transparently.md) — Linux eBPF capture without client proxy settings.
- [Get values from fnox](how-to/get-values-from-fnox.md) — keep real secrets out of arkham's config entirely.
- [Extend the known-host registry](how-to/extend-the-registry.md) — teach arkham a private endpoint or token shape.
- [Trust the arkham CA](how-to/trust-the-ca.md) — make clients and containers accept the intercepting certificate.

## Reference

Facts, austere and complete:

- [CLI](reference/cli.md) — every subcommand, flag, environment variable.
- [Configuration](reference/configuration.md) — the four layers and every key.
- [Allow entries](reference/allow-entries.md) — grant syntax and matching rules.
- [Decoy patterns](reference/decoy-patterns.md) — pattern verbs and selection order.
- [Registry](reference/registry.md) — the bundled known-host table and its override format.

## Explanation

The why behind the machinery:

- [How arkham works](explanation/how-it-works.md) — the life of a connection, splice versus substitution, and why each piece is shaped as it is.
- [The security model](explanation/security-model.md) — what arkham defends against, what it does not, and the edges you accept.
