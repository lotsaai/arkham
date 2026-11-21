# Run Arkham's Linux tasks in smolvm

Builds, tests, checks and verifies run in a smolvm machine, not on the
workstation. `sandbox:init` boots `ghcr.io/lotsaai/arkham-dev`, installs the
toolchain, builds the debug binary, plugins and test binaries, pulls the test
fixture images, and checkpoints the machine. Every routed task then restores
that checkpoint into a throwaway machine, runs there as `eng`, and deletes it.
The checkout is shared live; everything else the task writes is discarded.
Use only a trusted checkout: guest writes to the checkout change host files.

Requires an x86_64 Linux host with smolvm, readable and writable `/dev/kvm`,
nested KVM enabled, and `arch` in `MISE_ENV`. `mise.arch.toml` names the
image and the checkpoint.

| Command | Does |
| --- | --- |
| `mise run test` (or any routed task) | Refreshes the checkpoint if stale, then runs the task in a restored machine |
| `mise run sandbox:init` | Rebuilds the checkpoint when `Smolfile`, `mise.toml`, `mise.lock`, `mise.arch.toml`, `Cargo.lock` or `integration/compose.yaml` changed |
| `mise run sandbox:shell` | Opens a shell as `eng` in a restored machine, deleted on exit |
| `mise run sandbox:destroy` | Deletes the checkpoint |

To change the image, build `Dockerfile.sandbox`, push it to
`ghcr.io/lotsaai/arkham-dev`, and put the pushed digest in `mise.arch.toml`.
