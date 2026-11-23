#!/usr/bin/env bash
# Runs as eng in the arkham-dev source machine before every routed task, so the
# branch the task runs in starts with a current target/.
set -euo pipefail

# Every target's crates: test:rust runs cargo metadata, which needs them all.
cargo fetch --locked
mise run --force build:debug
mise run --force build:plugins
# The test binaries test:rust runs, built the way it builds them.
cargo nextest list --locked --cargo-quiet --workspace --exclude arkham-ebpf-programs --list-type binaries-only
