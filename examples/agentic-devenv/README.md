# Secure agent workspace

This example runs a host-confined agent with decoy credentials. The arkham daemon resolves the real values from fnox and substitutes them for matching grants. The agent uses the host network namespace; supported traffic is captured without proxy settings, subject to the exclusions in the [security model](../../docs/user/explanation/security-model.md).

## Before you start

Install arkham and bubblewrap on Linux. The host also needs Landlock and the privileges required for eBPF capture. Declare the workspace's secrets to fnox. The example config names the Anthropic and GitHub rules; the registry supplies their hosts and decoy patterns.

## Run it

Start the daemon in one terminal:

```sh
arkham daemon run
```

From this directory in another terminal, preview the rules and enter the agent shell:

```sh
arkham rules
arkham agent
```

Run a command instead of a shell by placing it after `--`:

```sh
arkham agent -- sh -c 'curl -sS https://api.anthropic.com/v1/models -H "x-api-key: $ANTHROPIC_API_KEY"'
```

The variable expands inside the confined shell, where it contains the decoy. A granted HTTPS request needs a client that trusts arkham's CA. The daemon supplies the certificate to supported clients; see [how to trust the CA](../../docs/user/how-to/trust-the-ca.md) for other clients.

Exit the agent shell to end the session. Stop the daemon separately when finished. [How to secure your workspace](../../docs/user/how-to/confine-a-workspace.md) covers write profiles and troubleshooting.
