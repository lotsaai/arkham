#!/usr/bin/env bash
# Prepare NATS discovery through the host session pipeline, append the
# discovered grant to arkham's global config, and restart arkham to read it.
# Compose provisions protocol servers only; it does not generate the agent
# environment. Run by test:nats after the stack is healthy.
set -euo pipefail
source integration/e2e.sh

nats_env_value() {
  local line value
  line=$(grep -E "^$1=" target/integration/nats/nats.env || true)
  value=${line#*=}
  value=${value#\'}
  value=${value%\'}
  printf '%s' "$value"
}

fail() {
  echo "$*" >&2
  exit 1
}

real_seed=$(nats_env_value NATS_NKEY_REAL_SEED)
[ -n "$real_seed" ] || fail "missing NATS_NKEY_REAL_SEED in target/integration/nats/nats.env"
if grep -q 'generated = true' integration/arkham.toml target/integration/arkham.toml; then
  fail "a hand-written nats rule is marked generated"
fi

# Certs already exited successfully: `up --wait` started its dependents.
# Starting it again would rerun gen-secrets.sh and truncate the config.
certs_cid=$($compose ps -aq certs)
certs_cid=${certs_cid%%$'\n'*}
[ -n "$certs_cid" ] || fail "certs container is absent"

isolate=$(mktemp -d /tmp/arkham-nats-discovery.XXXXXX)
trap 'rm -rf "$isolate"' EXIT
home=$isolate/home
mkdir -p "$home/.config/nats/context" "$isolate/workspace" "$isolate/xdg-config" "$isolate/xdg-state" "$isolate/xdg-data"
docker cp "$certs_cid":/certs/ca.crt "$home/.config/nats/ca.crt"
printf '%s\n' "$real_seed" >"$home/.config/nats/user.nk"
chmod 600 "$home/.config/nats/user.nk"
printf 'discovered\n' >"$home/.config/nats/context.txt"
cat >"$home/.config/nats/context/discovered.json" <<EOF
{
  "description": "integration discovery",
  "url": "tls://nats:4222",
  "nkey": "${home}/.config/nats/user.nk",
  "ca": "${home}/.config/nats/ca.crt"
}
EOF

echo "=== nats discovery: host session preparation ==="
env -u ARKHAM_CONFIG -u KUBECONFIG -u TALOSCONFIG \
  HOME="$home" \
  XDG_CONFIG_HOME="$isolate/xdg-config" \
  XDG_STATE_HOME="$isolate/xdg-state" \
  XDG_DATA_HOME="$isolate/xdg-data" \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_SYSTEM=/dev/null \
  target/debug/examples/prepare-session "$isolate/workspace" "$isolate/session" "$home/.config/nats/ca.crt"

grant_toml=$isolate/session/grants/arkham.toml
plan_file=$isolate/session/plan.json
[ -f "$grant_toml" ] && [ -f "$plan_file" ] || fail "host preparation did not produce a grant and launch plan"
grep -q 'generated = true' "$grant_toml" || fail "discovered grant is not marked generated"
grep -q 'if_missing = "ignore"' "$grant_toml" || fail "discovered grant does not ignore a missing fnox key"
grep -q 'sslrootcert=' "$grant_toml" || fail "discovered grant does not name a CA"
[ -n "$(find "$(dirname "$grant_toml")/rules.d" -name 'nats-*.ca' -type f -print -quit)" ] || fail "discovered grant did not copy the CA"
grep -F -q -- "$real_seed" "$grant_toml" || fail "discovered grant does not state the real nkey"

env_name=$(grep -m 1 -E '^env = ' "$grant_toml" || true)
env_name=${env_name#env = }
env_name=${env_name//[\"\']/}
label=$(grep -m 1 -E '^\[rules\.' "$grant_toml" || true)
label=${label#\[rules.}
label=${label%\]}
[ -n "$env_name" ] && [ -n "$label" ] || fail "discovered grant has no env name"
if grep -F -q -- "[rules.${label}]" target/integration/arkham.toml integration/arkham.toml; then
  fail "discovered rule is hand-written in the project config"
fi

dest=target/integration/nats-discovery
# The grants directory is bind-mounted into arkham: clear contents, not the mount.
find "$dest/grants" "$dest/guest" -mindepth 1 -delete
cp -a "$(dirname "$grant_toml")/." "$dest/grants/"
python3 integration/copy-nats-plan.py "$plan_file" "$home/.config/nats" "$dest/guest"
[ -f "$dest/guest/context.txt" ] || fail "discovery did not mount a nats context into the guest"
if grep -R -F -q -- "$real_seed" "$dest/guest"; then
  fail "discovered guest tree contains the real nkey"
fi

$compose run --rm --no-deps -T \
  -v "${grant_toml}:/discovered.toml:ro" \
  --entrypoint bash certs \
  -c 'cat /discovered.toml >> /arkham-config/config.toml'
docker cp "$certs_cid":/arkham-config/config.toml "$dest/config.toml"
docker cp "$certs_cid":/arkham-config/fnox.toml "$dest/fnox.toml"
grep -q 'generated = true' "$dest/config.toml" || fail "global config is missing the discovered grant"
if grep -F -q -- "[secrets.${env_name}]" "$dest/fnox.toml"; then
  fail "discovered grant env is a fnox secret"
fi

# Reload arkham so it reads the appended grant; --no-deps leaves certs alone.
$compose up -d --no-deps --force-recreate arkham
