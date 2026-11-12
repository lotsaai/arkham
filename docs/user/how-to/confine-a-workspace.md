# How to secure your workspace

Run a coding agent on Linux with bubblewrap and Landlock. The agent receives decoy credentials, while the arkham daemon holds the real values and captures supported traffic. Install arkham and bubblewrap, make sure Landlock and eBPF capture are available, and declare your secrets to fnox.

## Preview your rules

From the workspace root, inspect the rules derived from fnox declarations and the known-host registry:

```sh
arkham rules
```

To override a derived rule, add it to `.config/arkham/config.toml`:

```toml
[rules.github_token]
env = "GITHUB_TOKEN"
if_missing = "warn"
```

A rule without `value` resolves its real value from fnox. See [how to get values from fnox](get-values-from-fnox.md) if a name is missing.

## Start the daemon and agent

Start the daemon in a terminal and leave it running:

```sh
arkham daemon run
```

In another terminal, enter your workspace and launch the agent:

```sh
arkham agent
```

Pass a command after `--` to run it instead of the configured shell:

```sh
arkham agent -- cargo test
```

The daemon prepares decoy environment variables and rewritten credential files for the session. The agent shares the host network namespace, but eBPF redirects supported traffic to the daemon. Loopback, configured bypass destinations, and unconnected UDP are not captured. See the [security model](../explanation/security-model.md) for the capture boundaries.

The default `workspace-write` profile allows workspace writes. To select another profile, use `--write-profile read-only` or `--write-profile danger-full-access`. The latter does not apply Landlock. If bubblewrap or the required Landlock enforcement is unavailable, the command does not start.

Exit the agent shell to end its session. Stop the daemon separately when no sessions need it.

## Trust the CA

The daemon supplies its public CA certificate to the agent and sets certificate bundle environment variables for supported clients. Clients that use a separate trust store may need additional configuration. See [how to trust the CA](trust-the-ca.md). Never distribute the CA private key.

## Troubleshooting

- If the agent cannot connect to the daemon, start `arkham daemon` as the same user.
- If confinement fails, check that bubblewrap, user namespaces, and the required Landlock support are available.
- If a provider rejects a decoy, run `arkham rules` and check the fnox declaration, grant, and decoy pattern.
