#!/usr/bin/env bash
# Read-only: is this checkout worth driving for verify-arkham?
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
ARKHAM="${ARKHAM_BIN:-$ROOT/target/debug/arkham}"

fail() { echo "doctor fail: $*" >&2; exit 1; }

[[ -x "$ARKHAM" ]] || fail "missing $ARKHAM (run: mise run build:debug)"
ver="$("$ARKHAM" --version 2>&1)" || fail "arkham --version failed"
"$ARKHAM" schemes >/dev/null || fail "arkham schemes failed"
command -v curl >/dev/null || fail "curl not on PATH"
command -v python3 >/dev/null || fail "python3 not on PATH"

# Refuse to claim a shared default proxy port that we did not start.
if command -v lsof >/dev/null; then
  if lsof -nP -iTCP:8080 -sTCP:LISTEN >/dev/null 2>&1; then
    echo "doctor warn: 127.0.0.1:8080 already listening; tutorial helper uses 18080/18000 instead"
  fi
fi

echo "doctor ok: $ver"
echo "binary: $ARKHAM"
echo "root: $ROOT"
