# Run Arkham's Linux tasks in smolvm

Builds, tests, checks and verifies run in a smolvm machine, not on the
workstation. `sandbox:init` boots `ghcr.io/lotsaai/arkham-dev`, installs the
toolchain, builds the debug binary, plugins and test binaries, pulls the test
fixture images, and checkpoints the machine. The `arkham-dev` machine, created
from that checkpoint, stays running and keeps `target/`. Every routed task
first brings that `target/` up to date in `arkham-dev`, then branches a
throwaway machine from it, runs there as `eng`, and deletes it. Builds stay
incremental across tasks. The checkout is shared live; everything else the
task writes is discarded.
Use only a trusted checkout: guest writes to the checkout change host files.

Requires an x86_64 Linux host with smolvm, readable and writable `/dev/kvm`,
nested KVM enabled, and `arch` in `MISE_ENV`. `mise.arch.toml` names the
image and the checkpoint.

| Command | Does |
| --- | --- |
| `mise run test` (or any routed task) | Refreshes the checkpoint if stale, starts `arkham-dev` if needed, builds there, then runs the task in a branch of it |
| `mise run sandbox:init` | Rebuilds the checkpoint, and replaces `arkham-dev`, when `Smolfile`, `mise.toml`, `mise.lock`, `mise.arch.toml`, `Cargo.lock`, `integration/compose.yaml` or the sandbox scripts changed |
| `mise run sandbox:shell` | Opens a shell as `eng` in a restored machine, deleted on exit |
| `mise run sandbox:destroy` | Deletes `arkham-dev` and the checkpoint |

To change the image, build `Dockerfile.sandbox`, push it to
`ghcr.io/lotsaai/arkham-dev`, and put the pushed digest in `mise.arch.toml`.
