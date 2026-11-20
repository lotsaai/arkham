# Run Arkham's Linux tests in smolvm

Run builds and tests in the `arkham-dev` machine, not on the workstation. The
machine shares the checkout live and keeps `target`, Docker images, and
containerd data on its own ext4 disks. Use only a trusted checkout: guest writes
outside the guest-only mounts can change host files in the checkout.

Requires an x86_64 Linux host with Podman, smolvm, readable and writable
`/dev/kvm`, nested KVM enabled, and `arch` in `MISE_ENV`. The `sandbox` daemon
is declared in `mise.arch.toml`.

| Command | Does |
| --- | --- |
| `mise run sandbox:shell` | Starts the daemon if needed and opens a shell as `eng` in the checkout |
| `mise run sandbox:test` | Starts the daemon if needed and runs `mise run --force test` there |
| `mise daemons stop sandbox` | Stops the daemon, which destroys the machine and its disks |

The daemon runs `sandbox:start`, which builds the image and creates the
machine when it does not exist. When the daemon exits, its `on_exit` hook runs
`sandbox:destroy`. `mise daemons logs sandbox` shows its output.
