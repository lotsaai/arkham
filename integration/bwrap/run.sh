#!/usr/bin/env bash
# Transparent capture with the API and client in separate network namespaces.
# The client shares arkham's namespace and joins its capture cgroup under bwrap.
#
# Requires: sudo, iproute2, openssl, ssh-keygen, bun, curl, bwrap.
# Run: mise run demo:bwrap
set -euo pipefail

proj_dir=$(cd "$(dirname "$0")/../.." && pwd)
binary=$proj_dir/target/release/arkham

NS=arkham-bwrap-$$
API_NS=arkham-api-$$
API_IF=apa$$
NS_IF=apc$$
API_IP=10.99.0.20
REAL=ghp_deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
# arkham stays outside the client's cgroup, so its upstream dials bypass capture.
EBPF_CGROUP=/sys/fs/cgroup/arkham-bwrap-$$

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root (sudo)"
for tool in ip openssl ssh-keygen bun curl bwrap; do
  command -v "$tool" >/dev/null || fail "missing tool: $tool"
done
[ -x "$binary" ] || fail "build first: mise run build -- --release"

work=$(mktemp -d /tmp/arkham-bwrap.XXXXXX)
certs=$work/certs
mkdir -p "$certs"
export certs

api_pid=""
arkham_pid=""
cleanup() {
  [ -n "$api_pid" ] && kill "$api_pid" 2>/dev/null || true
  [ -n "$arkham_pid" ] && kill "$arkham_pid" 2>/dev/null || true
  [ -z "$api_pid" ] || wait "$api_pid" 2>/dev/null || true
  [ -z "$arkham_pid" ] || wait "$arkham_pid" 2>/dev/null || true
  rm -rf "$work"
  ip netns del "$NS" 2>/dev/null || true
  ip netns del "$API_NS" 2>/dev/null || true
  rmdir "$EBPF_CGROUP" 2>/dev/null || true
}
trap cleanup EXIT

bash "$proj_dir/integration/gen-certs.sh" "$certs" >/dev/null

FAKE=$("$binary" fake GH_TOKEN)

printf '[proxy]\nlisten = "127.0.0.1:8080"\n' >"$work/config.toml"
cat >"$work/fnox.toml" <<EOF
[providers.plain]
type = "plain"

[secrets.GH_TOKEN]
provider = "plain"
value = "$REAL"
EOF

# Separate namespaces keep the API address out of arkham's local-address
# bypass list while leaving the proxy and captured client in the same netns.
ip netns add "$NS"
ip netns add "$API_NS"
ip link add "$API_IF" type veth peer name "$NS_IF"
ip link set "$API_IF" netns "$API_NS"
ip link set "$NS_IF" netns "$NS"
ip netns exec "$API_NS" ip addr add "$API_IP/24" dev "$API_IF"
ip netns exec "$API_NS" ip link set "$API_IF" up
ip netns exec "$API_NS" ip link set lo up
ip netns exec "$NS" ip addr add 10.99.0.2/24 dev "$NS_IF"
ip netns exec "$NS" ip link set "$NS_IF" up
ip netns exec "$NS" ip link set lo up

cat >"$work/arkham.toml" <<EOF
[proxy]
listen = "0.0.0.0:8080"
ca_file = "$certs/ca.pem"

[rules.demo]
env = "GH_TOKEN"
registry = false
allow = ["https://api:8443", "tcp://$API_IP:9000"]

# The api leaf is signed by the loaded CA itself: egress trusts it per
# entry, since the arkham CA is no egress anchor.
[rules.demo.tls."https://api:8443"]
root_cert = "$certs/ca.crt"
EOF

# API server (validates only the real token) outside the client's namespace.
ip netns exec "$API_NS" env ARKHAM_REAL="$REAL" CERT_DIR="$certs" \
  bun run "$proj_dir/integration/api/server.ts" >"$work/api.log" 2>&1 &
api_pid=$!

# Sandbox wrapper: bwrap shares the netns (no --unshare-net) but isolates
# the filesystem; the client needs /certs for the CA and nothing else.
sandbox() {
  bwrap \
    --ro-bind /usr /usr \
    --symlink usr/bin /bin \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --dev /dev \
    --tmpfs /tmp \
    --dir /certs \
    --ro-bind "$certs/ca.crt" /certs/ca.crt \
    --clearenv \
    --setenv PATH /usr/bin:/bin \
    "$@"
}
export -f sandbox

mkdir -p "$EBPF_CGROUP"
ip netns exec "$NS" env RUST_LOG=info ARKHAM_CONFIG="$work/config.toml" "$binary" serve --proxy-backend ebpf --ebpf-cgroup "$EBPF_CGROUP" --config "$work/arkham.toml" >"$work/arkham.log" 2>&1 &
arkham_pid=$!

# The child joins the capture cgroup before starting bwrap.
# shellcheck disable=SC2016
client() {
  ip netns exec "$NS" bash -c 'echo "$BASHPID" >"$1/cgroup.procs"; shift; sandbox "$@"' arkham-client "$EBPF_CGROUP" "$@"
}

wait_port() {
  for _ in $(seq 1 50); do
    if ip netns exec "$NS" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then
      return 0
    fi
    kill -0 "$api_pid" 2>/dev/null || fail "api server died (see $work/api.log)"
    kill -0 "$arkham_pid" 2>/dev/null || fail "arkham died (see $work/arkham.log)"
    sleep 0.2
  done
  fail "timeout waiting for $1:$2 in the namespace"
}

wait_port "$API_IP" 8443
wait_port "$API_IP" 9000

# Scenario 1: HTTPS with the fake bearer -> server sees real, response
# redacts back to the fake.
body=$(client curl -sS --max-time 10 --cacert /certs/ca.crt \
  --resolve "api:8443:$API_IP" \
  -H "Authorization: Bearer $FAKE" \
  https://api:8443/)
[ "$body" = "token:$FAKE" ] || fail "https scenario: got '$body', want 'token:$FAKE'"

# Scenario 2: raw TCP line protocol under a tcp:// grant -> AUTH fake
# becomes AUTH real upstream, OK real comes back as OK fake.
reply=$(client timeout 10 bash -c "exec 3<>/dev/tcp/$API_IP/9000; printf 'AUTH $FAKE\n' >&3; head -n1 <&3")
[ "$reply" = "OK $FAKE" ] || fail "tcp scenario: got '$reply', want 'OK $FAKE'"

api_log_auth_prefix_len=14
real_auth="Bearer ${REAL}"
fake_auth="Bearer ${FAKE}"
grep -q "auth=${real_auth:0:api_log_auth_prefix_len}" "$work/api.log" || fail "api never saw the real token"
if grep -q "auth=${fake_auth:0:api_log_auth_prefix_len}" "$work/api.log"; then
  fail "api saw the fake token: capture did not substitute"
fi

echo "bwrap demo: all scenarios passed (fake never left the namespace)"
