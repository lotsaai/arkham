# Run Arkham's Linux tasks in smolvm

Builds, tests, checks and verifies run in a smolvm machine, not on the
workstation. `sandbox:init` creates the `arkham-dev` machine from the
`Smolfile` and `ghcr.io/lotsaai/arkham-dev`, installs the toolchain, builds the
debug binary, plugins and test binaries, pulls the test fixture images, and
stops it. Every routed task boots `arkham-dev`, brings its `target/` up to
date, runs as `eng`, and stops the machine. `target/`, `/var/lib/docker` and
`/var/lib/containerd` live on the machine's disk, so builds and images carry
over between tasks. The checkout is shared live.
Use only a trusted checkout: guest writes to the checkout change host files.

Requires an x86_64 Linux host with smolvm, readable and writable `/dev/kvm`,
nested KVM enabled, and `arch` in `MISE_ENV`. `mise.arch.toml` names the
machine and the image.

| Command | Does |
| --- | --- |
| `mise run test` (or any routed task) | Recreates `arkham-dev` if stale or missing, boots it, builds there, runs the task, and stops it |
| `mise run sandbox:init` | Recreates `arkham-dev` when `Smolfile`, `mise.toml`, `mise.lock`, `mise.arch.toml`, `mise.arch.lock`, `integration/compose.yaml` or the sandbox scripts changed |
| `mise run sandbox:shell` | Boots `arkham-dev`, opens a shell as `eng`, and stops it on exit |
| `mise run sandbox:destroy` | Deletes `arkham-dev` |

To change the image, build `Dockerfile.sandbox`, push it to
`ghcr.io/lotsaai/arkham-dev`, and put the pushed digest in `mise.arch.toml`.
