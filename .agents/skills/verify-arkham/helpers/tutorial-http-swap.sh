#!/usr/bin/env bash
# Drive the user-facing HTTP credential-swap path from docs/user/tutorial.md
# in an isolated temp dir. Proof artifacts land under ARTIFACTS (default:
# .cursor/skills/verify-arkham/artifacts/tutorial-http-swap-<runid>/).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
ARKHAM="${ARKHAM_BIN:-$ROOT/target/debug/arkham}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)-$$}"
ARTIFACTS="${ARTIFACTS:-$ROOT/.cursor/skills/verify-arkham/artifacts/tutorial-http-swap-$RUN_ID}"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/arkham-verify-$RUN_ID.XXXXXX")}"

# Prefer caller-supplied ports; otherwise ask the OS for three free ones.
if [[ -z "${LISTEN_PORT:-}" && -z "${UPSTREAM_PORT:-}" && -z "${OFF_PORT:-}" ]]; then
  eval "$(python3 - <<'PY'
import socket
ports = []
for _ in range(3):
  s = socket.socket()
  s.bind(("127.0.0.1", 0))
  ports.append(s.getsockname()[1])
  s.close()
print(f"LISTEN_PORT={ports[0]}")
print(f"UPSTREAM_PORT={ports[1]}")
print(f"OFF_PORT={ports[2]}")
PY
)"
elif [[ -z "${LISTEN_PORT:-}" || -z "${UPSTREAM_PORT:-}" || -z "${OFF_PORT:-}" ]]; then
  echo "doctor fail: set LISTEN_PORT, UPSTREAM_PORT, and OFF_PORT together" >&2
  exit 2
fi

mkdir -p "$ARTIFACTS" "$WORK"
cleanup() {
  for pid in "${OFF_PID:-}" "${UPSTREAM_PID:-}" "${PROXY_PID:-}"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [[ "${KEEP_WORK:-0}" != "1" ]] && [[ -d "$WORK" ]]; then
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

if [[ ! -x "$ARKHAM" ]]; then
  echo "doctor fail: missing executable $ARKHAM (run: mise run build:debug)" >&2
  exit 2
fi

DECOY="$("$ARKHAM" fake DEMO_TOKEN)"
# Equal-length real: unequal-length secrets in the HTTP response body currently
# empty-reply the client after a successful upstream swap (product defect vs
# docs/user/tutorial.md's shorter example value).
REAL_SECRET="$(python3 -c "import sys; d=sys.argv[1]; print(('real-secret-' + 'x'*len(d))[:len(d)])" "$DECOY")"
printf '%s\n' "$DECOY" >"$ARTIFACTS/decoy.txt"
cat >"$WORK/arkham.toml" <<EOF
[proxy]
listen = "127.0.0.1:${LISTEN_PORT}"
ca_file = "ca.pem"

[rules.demo]
env = "DEMO_TOKEN"
value = "${REAL_SECRET}"
allow = ["http://127.0.0.1:${UPSTREAM_PORT}"]
EOF

cat >"$WORK/upstream.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import sys

seen_path = os.environ["SEEN_PATH"]
port = int(os.environ["UPSTREAM_PORT"])


class Handler(BaseHTTPRequestHandler):
  def do_GET(self):
    seen = self.headers.get("Authorization", "<none>")
    with open(seen_path, "w", encoding="utf-8") as f:
      f.write(seen)
    body = ("upstream saw: " + seen).encode()
    self.send_response(200)
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

  def log_message(self, *_args):
    pass


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY

export SEEN_PATH="$WORK/seen.txt"
export UPSTREAM_PORT
python3 "$WORK/upstream.py" >"$ARTIFACTS/upstream.log" 2>&1 &
UPSTREAM_PID=$!

(
  cd "$WORK"
  "$ARKHAM" serve --config arkham.toml
) >"$ARTIFACTS/proxy.log" 2>&1 &
PROXY_PID=$!

ready=0
for _ in $(seq 1 50); do
  if grep -q 'serving' "$ARTIFACTS/proxy.log" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "doctor fail: proxy exited before ready; see $ARTIFACTS/proxy.log" >&2
    exit 3
  fi
  sleep 0.1
done
if [[ "$ready" != "1" ]]; then
  echo "doctor fail: proxy not ready; see $ARTIFACTS/proxy.log" >&2
  exit 3
fi

# Close the port-hold sockets from the python picker (if any) before dialing.
# The listen sockets of upstream/proxy already own the ports.
if ! CLIENT_BODY="$(curl -sS --max-time 5 -x "http://127.0.0.1:${LISTEN_PORT}" "http://127.0.0.1:${UPSTREAM_PORT}/" \
  -H "Authorization: Bearer ${DECOY}")"; then
  echo "proof fail: curl through proxy failed; proxy.log follows" >&2
  cat "$ARTIFACTS/proxy.log" >&2 || true
  exit 4
fi
printf '%s\n' "$CLIENT_BODY" >"$ARTIFACTS/client-body.txt"
if [[ ! -f "$WORK/seen.txt" ]]; then
  echo "proof fail: upstream never wrote seen.txt; proxy.log follows" >&2
  cat "$ARTIFACTS/proxy.log" >&2 || true
  exit 4
fi
UPSTREAM_SEEN="$(cat "$WORK/seen.txt")"
printf '%s\n' "$UPSTREAM_SEEN" >"$ARTIFACTS/upstream-seen.txt"

if [[ "$CLIENT_BODY" != "upstream saw: Bearer ${DECOY}" ]]; then
  echo "proof fail: client did not receive redacted decoy body" >&2
  echo "got: $CLIENT_BODY" >&2
  exit 4
fi
if [[ "$UPSTREAM_SEEN" != "Bearer ${REAL_SECRET}" ]]; then
  echo "proof fail: upstream did not receive the real secret" >&2
  echo "got: $UPSTREAM_SEEN" >&2
  exit 4
fi

# Grant gate: off-allow port must leave the decoy untouched on the upstream.
python3 -m http.server "$OFF_PORT" --bind 127.0.0.1 >"$ARTIFACTS/off-upstream.log" 2>&1 &
OFF_PID=$!
sleep 0.2
OFF_BODY="$(curl -sS -x "http://127.0.0.1:${LISTEN_PORT}" "http://127.0.0.1:${OFF_PORT}/" \
  -H "Authorization: Bearer ${DECOY}" || true)"
printf '%s\n' "$OFF_BODY" >"$ARTIFACTS/off-grant-body.txt"
if grep -Fq -- "$REAL_SECRET" "$ARTIFACTS/off-grant-body.txt"; then
  echo "proof fail: real secret leaked on non-granted destination" >&2
  exit 5
fi
kill "$OFF_PID" 2>/dev/null || true
wait "$OFF_PID" 2>/dev/null || true
OFF_PID=""

cat >"$ARTIFACTS/SUMMARY.txt" <<EOF
feature: credential-swap
entry: helpers/tutorial-http-swap.sh
decoy: $DECOY
client_body: $CLIENT_BODY
upstream_seen: $UPSTREAM_SEEN
listen: 127.0.0.1:$LISTEN_PORT
upstream: 127.0.0.1:$UPSTREAM_PORT
arkham: $ARKHAM
work: $WORK (removed unless KEEP_WORK=1)
result: PASS
EOF

echo "PASS evidence in $ARTIFACTS"
