#!/usr/bin/env bash
# Transparent-capture demo without docker: a network namespace, a veth up
# to the host, and arkham capturing the client's egress inside the netns.
# The client runs under bwrap (filesystem-sandboxed) while sharing the
# netns, so it is captured like any proxy-unaware workload.
#
# Set ARKHAM_BACKEND=ebpf to capture with the cgroup eBPF backend instead of
# TPROXY; the scenarios asserted are identical either way.
#
# Requires: sudo (netns, veth, host nft), iproute2, nft, openssl, bun, curl, bwrap.
# Run: mise run demo:bwrap (builds as you, escalates only this script)
set -euo pipefail

proj_dir=$(cd "$(dirname "$0")/../.." && pwd)
binary=$proj_dir/target/release/arkham

NS=arkham-bwrap
HOST_IF=hb-host
NS_IF=hb-ns
API_IP=10.99.0.20
GW_IP=10.99.0.1
REAL=ghp_deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
NAT_TABLE=arkham_bwrap_nat
# `tproxy` (default) or `ebpf`. Both capture kernel-side; eBPF needs its
# workload in a cgroup and uses no netfilter at all.
BACKEND=${ARKHAM_BACKEND:-tproxy}
# cgroup the client is placed in when BACKEND=ebpf. arkham itself stays in the
# root cgroup, so its own upstream dials are never captured.
EBPF_CGROUP=/sys/fs/cgroup/arkham-bwrap

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root (sudo)"
case "$BACKEND" in
tproxy | ebpf) ;;
*) fail "ARKHAM_BACKEND must be tproxy or ebpf, got '$BACKEND'" ;;
esac
for tool in ip nft openssl bun curl bwrap; do
  command -v "$tool" >/dev/null || fail "missing tool: $tool"
done
[ -x "$binary" ] || fail "build first: mise run build -- --release"

work=$(mktemp -d /tmp/arkham-bwrap.XXXXXX)
certs=$work/certs
mkdir -p "$certs"

api_pid=""
arkham_pid=""
cleanup() {
  [ -n "$api_pid" ] && kill "$api_pid" 2>/dev/null || true
  [ -n "$arkham_pid" ] && kill "$arkham_pid" 2>/dev/null || true
  rm -rf "$work"
  ip netns del "$NS" 2>/dev/null || true
  nft delete table inet "$NAT_TABLE" 2>/dev/null || true
  # Only the ebpf backend creates this; the client is gone by now, so the
  # empty cgroup can be removed.
  rmdir "$EBPF_CGROUP" 2>/dev/null || true
}
trap cleanup EXIT

bash "$proj_dir/integration/gen-certs.sh" "$certs" >/dev/null

FAKE=$("$binary" fake GH_TOKEN)

# Netns + veth + NAT: the client namespace reaches the world only through
# the host, and arkham captures everything on the way out.
ip netns add "$NS"
mkdir -p "/etc/netns/$NS"
printf 'nameserver 1.1.1.1\n' >"/etc/netns/$NS/resolv.conf"
ip link add "$HOST_IF" type veth peer name "$NS_IF"
ip link set "$NS_IF" netns "$NS"
ip addr add "$GW_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip addr add 10.99.0.2/24 dev "$NS_IF"
ip netns exec "$NS" ip link set "$NS_IF" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via "$GW_IP"
sysctl -qw net.ipv4.ip_forward=1
nft add table inet "$NAT_TABLE"
nft "add chain inet ${NAT_TABLE} postrouting { type nat hook postrouting priority srcnat; }"
nft add rule inet "$NAT_TABLE" postrouting ip saddr 10.99.0.0/24 oifname "$HOST_IF" masquerade

cat >"$work/arkham.toml" <<EOF
[proxy]
listen = "0.0.0.0:8080"
ca_file = "$certs/ca.pem"

[rules.demo]
env = "GH_TOKEN"
value = "$REAL"
registry = false
allow = ["https://api:8443", "tcp://$API_IP:9000"]

# The api leaf is signed by the loaded CA itself: egress trusts it per
# entry, since the arkham CA is no egress anchor.
[rules.demo.tls."https://api:8443"]
root_cert = "$certs/ca.crt"
EOF

# API server (validates only the real token) inside the namespace.
ip netns exec "$NS" env ARKHAM_REAL="$REAL" CERT_DIR="$certs" \
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
    --ro-bind "$certs" /certs \
    --clearenv \
    --setenv PATH /usr/bin:/bin \
    "$@"
}
export -f sandbox

case "$BACKEND" in
tproxy)
  # arkham with kernel TPROXY inside the same namespace.
  ip netns exec "$NS" RUST_LOG=info "$binary" serve --proxy-backend tproxy --config "$work/arkham.toml" >"$work/arkham.log" 2>&1 &
  client() { ip netns exec "$NS" sandbox "$@"; }
  ;;
ebpf)
  # cgroup holding only the client. Membership is what scopes capture: arkham
  # itself stays in the root cgroup, so its upstream dials are never
  # redirected back into it.
  mkdir -p "$EBPF_CGROUP"
  ip netns exec "$NS" RUST_LOG=info "$binary" serve --proxy-backend ebpf --ebpf-cgroup "$EBPF_CGROUP" --config "$work/arkham.toml" >"$work/arkham.log" 2>&1 &
  # The client migrates itself before exec'ing the sandbox, so bwrap and
  # everything it spawns are captured. `$BASHPID` is this child shell's pid;
  # it must be read by the child, so the script is passed with the cgroup as
  # a positional argument rather than interpolated here. SC2016 is that
  # intent, not an oversight.
  # shellcheck disable=SC2016
  client() {
    ip netns exec "$NS" bash -c 'echo "$BASHPID" >"$1/cgroup.procs"; shift; sandbox "$@"' arkham-client "$EBPF_CGROUP" "$@"
  }
  ;;
esac
arkham_pid=$!

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
