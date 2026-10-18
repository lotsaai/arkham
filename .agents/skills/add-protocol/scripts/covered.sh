#!/usr/bin/env bash
# Confirm every backend test:ssh started passed, and recorded every named scheme.
# Usage: covered.sh LOG SCHEME [SCHEME...]
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: covered.sh LOG SCHEME [SCHEME...]" >&2
  exit 2
fi

log=$1
shift

if [ ! -f "$log" ]; then
  echo "no log at $log" >&2
  exit 1
fi

if grep -q 'skip: test:ssh' "$log"; then
  echo "test:ssh skipped; a missing docker daemon is not a pass" >&2
  exit 1
fi

if grep -Fq 'FAILED (exit' "$log"; then
  echo "test:ssh log records a failed backend" >&2
  exit 1
fi

started=$(grep -Eo '=== backend: [^ ]+ ===' "$log" || true)
if [ -z "$started" ]; then
  echo "test:ssh log names no backend" >&2
  exit 1
fi

while IFS= read -r line; do
  backend=${line#=== backend: }
  backend=${backend% ===}
  if ! grep -Fq "=== backend ${backend} passed ===" "$log"; then
    echo "backend ${backend} has no passed line" >&2
    exit 1
  fi
done <<< "$started"

root=$(git rev-parse --show-toplevel)
covered="$root/integration/out/results/covered.json"
if [ ! -f "$covered" ]; then
  echo "missing $covered" >&2
  exit 1
fi

for scheme in "$@"; do
  if ! grep -Fq "\"${scheme}\"" "$covered"; then
    echo "scheme ${scheme} is not in $covered" >&2
    exit 1
  fi
done

echo "every backend passed; schemes present in $covered"
