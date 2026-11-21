# shellcheck shell=bash
# Sourced by the verify:* mise tasks; runs nothing on its own.
# verify_init <feature> gives each drive: an isolated HOME and XDG config (the
# developer's fnox/arkham config and handoff socket never leak in), a temp WORK
# dir as cwd, an ARTIFACTS dir that survives cleanup, and an EXIT trap that
# stops only what this drive started.

ROOT="${MISE_CONFIG_ROOT:?run through mise run verify:<feature>}"
VERIFY="$ROOT/integration/verify"
ARKHAM="$ROOT/target/debug/arkham"
RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
PIDS=()
# Shell commands verify_cleanup evals first (e.g. docker rm -f <name>).
CLEANUPS=()

verify_init() {
  ARTIFACTS="$ROOT/.agents/skills/verify-arkham/artifacts/$1-$RUN_ID"
  WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/arkham-verify-$RUN_ID.XXXXXX")}"
  mkdir -p "$ARTIFACTS" "$WORK/home/.config"
  export HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config"
  cd "$WORK"
  trap verify_cleanup EXIT
}

verify_cleanup() {
  local pid cmd
  for cmd in "${CLEANUPS[@]}"; do
    eval "$cmd" || true
  done
  for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$WORK"
}

# No port is chosen ahead of time. Upstreams run as containers and docker
# publishes them on a port it picks; arkham binds 127.0.0.1:0 and its
# `serving` line names the port it bound.

# start_upstream <name> [docker run args...]: run upstream.py in a container,
# published on a docker-assigned loopback port. Sets UPSTREAM_NAME and
# UPSTREAM_HOST_PORT; the request it records is read with upstream_seen.
start_upstream() {
  UPSTREAM_NAME="arkham-verify-$1-$RUN_ID"
  shift
  CLEANUPS+=("docker rm -f $UPSTREAM_NAME >/dev/null 2>&1")
  docker run -d --name "$UPSTREAM_NAME" -p 127.0.0.1::8000 -v "$VERIFY:/v:ro" \
    -e SEEN_PATH=/tmp/seen.txt -e UPSTREAM_PORT=8000 -e UPSTREAM_HOST=0.0.0.0 "$@" \
    python:3-alpine python3 -u /v/upstream.py >"$ARTIFACTS/$UPSTREAM_NAME.id"
  for _ in $(seq 1 100); do
    docker logs "$UPSTREAM_NAME" 2>&1 | grep -q "upstream ready" && break
    sleep 0.1
  done
  UPSTREAM_HOST_PORT="$(docker port "$UPSTREAM_NAME" 8000/tcp)"
  UPSTREAM_HOST_PORT="${UPSTREAM_HOST_PORT##*:}"
}

# upstream_seen <name>: the Authorization header that container received.
upstream_seen() {
  docker exec "$1" cat /tmp/seen.txt
}

# bound_port <log>: the port from arkham's `serving` / `host daemon ready` line.
bound_port() {
  grep -o 'listen: [^,]*' "$1" | head -n1 | sed 's/.*://'
}

# spawn <log> <cmd...>: start a background process owned by this drive.
spawn() {
  local log=$1
  shift
  "$@" >"$log" 2>&1 &
  PIDS+=("$!")
  export LAST_PID=$!
}

# wait_log <log> <pid> <pattern> [seconds]: wait (default 5 s) for pattern;
# fail if pid dies first.
wait_log() {
  local log=$1 pid=$2 pattern=$3 seconds=${4:-5}
  for _ in $(seq 1 $((seconds * 10))); do
    if grep -q -- "$pattern" "$log" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "verify fail: process exited before '$pattern'; see $log" >&2
      exit 3
    fi
    sleep 0.1
  done
  echo "verify fail: '$pattern' never appeared; see $log" >&2
  exit 3
}

# equal_length_real <decoy>: a real value the same length as the decoy.
# Unequal lengths empty-reply the client on HTTP response redaction.
equal_length_real() {
  python3 -c 'import sys; d = sys.argv[1]; print(("real-secret-" + "x" * len(d))[:len(d)])' "$1"
}

# run_cli <setup-dir|-> <arkham args...>: run one subcommand in the workspace,
# keeping command, stdout, stderr, exit, and the files it wrote.
run_cli() {
  local setup=$1 code
  shift
  if [[ "$setup" != - ]]; then
    cp -a "$VERIFY/fixtures/$setup/." "$WORK/"
  fi
  printf '%q ' arkham "$@" >"$ARTIFACTS/command.txt"
  echo >>"$ARTIFACTS/command.txt"
  set +e
  RUST_LOG=warn "$ARKHAM" "$@" >"$ARTIFACTS/stdout.txt" 2>"$ARTIFACTS/stderr.txt"
  code=$?
  set -e
  echo "$code" >"$ARTIFACTS/exit.txt"
  find . -path ./home -prune -o -type f -printf '%m %P\n' | sort >"$ARTIFACTS/workspace-files.txt"
  export CLI_EXIT=$code
}

# expect <description> <condition...>: fail the drive when the test fails.
expect() {
  local what=$1
  shift
  if ! "$@"; then
    echo "proof fail: $what; see $ARTIFACTS" >&2
    exit 4
  fi
}

# fails <cmd...>: succeeds only when the command fails; an expect condition.
fails() {
  ! "$@"
}

verify_pass() {
  printf 'feature: %s\nresult: PASS\n' "$1" >"$ARTIFACTS/SUMMARY.txt"
  echo "PASS $1: $ARTIFACTS"
}
