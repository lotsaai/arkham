#!/usr/bin/env bash
# Compose plumbing for the test:<protocol> tasks. Source it; it runs nothing.

compose="docker compose -f integration/compose.yaml --env-file integration/.env"
client=arkham-integration-client-1
client_log=/tmp/arkham-client.log

# Prepare a clean stack for one protocol client (integration/client/<name>.ts).
e2e_init() {
  ARKHAM_CLIENT=$1
  HOST_UID="$(id -u)"
  HOST_GID="$(id -g)"
  export ARKHAM_CLIENT HOST_UID HOST_GID

  e2e_every_scheme_has_a_task
  if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    echo "test:${ARKHAM_CLIENT} needs a docker daemon" >&2
    return 1
  fi
  # The demo values are throwaways (gitignored copy of the example).
  if [ ! -f integration/.env ]; then
    cp integration/.env.example integration/.env
    echo "seeded integration/.env from the example"
  fi
  # Compose interpolates the NATS material for every service.
  bash integration/gen-nats.sh
  # The image is runtime-only; compose mounts the `build:debug` binary.
  cp target/debug/arkham integration/docker/arkham

  $compose down --remove-orphans -v --timeout 3
  # The bind-mounted result survives `down` and must not satisfy this run.
  rm -f target/integration/results/covered.json
  trap e2e_teardown EXIT
}

# Every scheme arkham supports must be claimed by some test task.
e2e_every_scheme_has_a_task() {
  local scheme
  while IFS= read -r scheme; do
    if ! grep -Eqs "^e2e_covered( [a-z]+)* ${scheme}( |\$)" .mise/tasks/test/*; then
      echo "scheme ${scheme} has no test task" >&2
      return 1
    fi
  done < <(target/debug/arkham schemes)
}

# Start arkham plus the named protocol servers and wait until they are healthy.
e2e_up() {
  $compose up -d --build --wait --wait-timeout 600 arkham "$@"
}

# Run the client to completion and print its log.
e2e_client() {
  local state code
  $compose up -d --no-deps client
  for _ in $(seq 1 300); do
    state=$(docker inspect -f '{{.State.Status}}' "$client" 2>/dev/null || echo missing)
    [ "$state" = exited ] || [ "$state" = missing ] && break
    sleep 1
  done
  docker logs "$client" >"$client_log" 2>&1 || true
  cat "$client_log"
  [ "$state" = exited ] || { echo "client did not finish (${state})"; return 124; }
  code=$(docker inspect -f '{{.State.ExitCode}}' "$client")
  [ "$code" = 0 ] || { echo "client exited ${code}"; return "$code"; }
}

# Fail unless the client recorded a passing scenario for every named scheme.
e2e_covered() {
  local scheme covered=target/integration/results/covered.json
  for scheme in "$@"; do
    if ! grep -Fqs "\"${scheme}\"" "$covered"; then
      echo "scheme ${scheme} has no passing e2e scenario"
      return 1
    fi
  done
  echo "=== test:${ARKHAM_CLIENT} passed ==="
}

# Keep every service's logs on failure (CI prints this file), then tear down.
e2e_teardown() {
  local code=$?
  if [ "$code" != 0 ]; then
    {
      echo "=== compose logs (test:${ARKHAM_CLIENT}, exit ${code}) ==="
      $compose logs --no-color || true
    } >>/tmp/arkham-integration-compose.log
    echo "=== test:${ARKHAM_CLIENT} FAILED (exit ${code}); logs in /tmp/arkham-integration-compose.log ==="
  fi
  $compose down --remove-orphans -v --timeout 3
  find target/integration/nats-discovery -mindepth 1 -delete
  exit "$code"
}
