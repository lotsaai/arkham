#!/usr/bin/env bash
# Runs as eng inside the machine sandbox:init checkpoints: everything a routed
# task would otherwise rebuild or pull on each run.
set -euo pipefail

# Every target's crates: test:rust runs cargo metadata, which needs them all.
cargo fetch --locked
mise run --force build:debug
mise run --force build:plugins
# The test binaries test:rust runs, built the way it builds them.
cargo nextest list --locked --cargo-quiet --workspace --exclude arkham-ebpf-programs --list-type binaries-only

# Compose interpolates these for every service, as integration/e2e.sh prepares them.
test -f integration/.env || cp integration/.env.example integration/.env
bash integration/gen-nats.sh
cp target/debug/arkham integration/docker/arkham
compose=(docker compose --progress plain -f integration/compose.yaml --env-file integration/.env)
"${compose[@]}" pull --quiet --ignore-buildable
"${compose[@]}" build

talos_pattern='^talos_version="\$\{ARKHAM_TALOS_VERSION:-(.*)\}"$'
while IFS= read -r line; do
  [[ $line =~ $talos_pattern ]] && talos_version=${BASH_REMATCH[1]}
done < .mise/tasks/test/talos
mapfile -t k3d_lines < <(k3d version)
read -r _ _ k3d_v <<<"${k3d_lines[0]}"
read -r _ _ k3s_v _ <<<"${k3d_lines[1]}"
for image in \
  "ghcr.io/siderolabs/talos:${talos_version}" \
  "rancher/k3s:${k3s_v}" \
  "ghcr.io/k3d-io/k3d-tools:${k3d_v#v}" \
  "ghcr.io/k3d-io/k3d-proxy:${k3d_v#v}" \
  python:3-alpine; do
  docker pull --quiet "$image"
done
