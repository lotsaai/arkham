#!/usr/bin/env bash
# Mint the demo operator, accounts, and users with nsc (mise tool
# github:nats-io/nsc). The trusted account is the only JWT the operator-mode
# server preloads. The fake user JWT is signed by a different account, so it
# cannot authenticate unless the proxy rewrites CONNECT. Seeds and JWTs land
# in integration/out (gitignored) and integration/.env (gitignored). The nsc
# store is removed when this script exits.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if [[ ! -f integration/.env ]]; then
  cp integration/.env.example integration/.env
fi

if ! command -v mise >/dev/null 2>&1; then
  echo "mise is required so nsc can mint the NATS fixtures" >&2
  exit 1
fi

store=$(mktemp -d)
trap 'rm -rf "$store"' EXIT

nsc() {
  mise exec -- nsc --all-dirs "$store" "$@"
}

describe_raw() {
  nsc describe "$@" --raw | tr -d '[:space:]'
}

describe_field() {
  local value
  value=$(nsc describe "$@" | tr -d '[:space:]')
  value=${value//\"/}
  if [[ -z $value ]]; then
    echo "nsc describe returned an empty field: $*" >&2
    exit 1
  fi
  printf '%s' "$value"
}

user_seed() {
  local account=$1
  local name=$2
  local file="$store/creds/arkham-demo/${account}/${name}.creds"
  local seed
  seed=$(awk 'found { print; exit } $0 == "-----BEGIN USER NKEY SEED-----" { found = 1 }' "$file")
  if [[ ! $seed =~ ^SU[A-Z2-7]+$ ]]; then
    echo "nsc did not write a user seed for ${account}/${name}" >&2
    exit 1
  fi
  printf '%s' "$seed"
}

require_jwt() {
  local name=$1
  local value=$2
  if [[ ! $value =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
    echo "nsc did not write a compact jwt for ${name}" >&2
    exit 1
  fi
}

nsc add operator --name arkham-demo
nsc add account --name demo
nsc add account --name untrusted
nsc add user --name jwt-real --account demo --allow-pubsub '>'
nsc add user --name jwt-fake --account untrusted --allow-pubsub '>'
nsc add user --name jwt-foreign --account untrusted
nsc add user --name nkey-real --account demo
nsc add user --name nkey-fake --account demo
nsc add user --name nkey-foreign --account demo

demo_account=$(describe_field account --name demo --field sub)
untrusted_account=$(describe_field account --name untrusted --field sub)
operator_jwt=$(describe_raw operator --name arkham-demo)
account_jwt=$(describe_raw account --name demo)
jwt_real=$(describe_raw user --account demo --name jwt-real)
jwt_fake=$(describe_raw user --account untrusted --name jwt-fake)
jwt_foreign=$(describe_raw user --account untrusted --name jwt-foreign)
nkey_real_public=$(describe_field user --account demo --name nkey-real --field sub)
real_iss=$(describe_field user --account demo --name jwt-real --field iss)
fake_iss=$(describe_field user --account untrusted --name jwt-fake --field iss)

require_jwt operator "$operator_jwt"
require_jwt account "$account_jwt"
require_jwt jwt-real "$jwt_real"
require_jwt jwt-fake "$jwt_fake"
require_jwt jwt-foreign "$jwt_foreign"

if [[ $real_iss != "$demo_account" ]]; then
  echo "jwt-real must be signed by the preloaded account" >&2
  exit 1
fi
if [[ $fake_iss != "$untrusted_account" || $fake_iss == "$demo_account" ]]; then
  echo "the fake user jwt must be signed by the account the server does not preload" >&2
  exit 1
fi

jwt_real_seed=$(user_seed demo jwt-real)
jwt_fake_seed=$(user_seed untrusted jwt-fake)
jwt_foreign_seed=$(user_seed untrusted jwt-foreign)
nkey_real_seed=$(user_seed demo nkey-real)
nkey_fake_seed=$(user_seed demo nkey-fake)
nkey_foreign_seed=$(user_seed demo nkey-foreign)

nkey_fake_url="nats://nkey:${nkey_fake_seed}@nats:4222"
nkey_real_url="tls://nkey:${nkey_real_seed}@nats:4222?sslrootcert=/certs/ca.crt"
jwt_fake_url="nats://creds:${jwt_fake_seed}:${jwt_fake}@nats-jwt:4223"
jwt_real_url="tls://creds:${jwt_real_seed}:${jwt_real}@nats-jwt:4223?sslrootcert=/certs/ca.crt"

out=integration/out
nats=$out/nats
mkdir -p "$nats" "$out/results"

template=integration/arkham.toml
rendered=$(mktemp)
cp "$template" "$rendered"
replace_sentinel() {
  local sentinel=$1
  local value=$2
  local next
  if ! grep -q -F -- "$sentinel" "$rendered"; then
    echo "integration/arkham.toml is missing ${sentinel}" >&2
    exit 1
  fi
  next=$(mktemp)
  awk -v sentinel="$sentinel" -v value="$value" '{ gsub(sentinel, value); print }' "$rendered" >"$next"
  mv "$next" "$rendered"
}
replace_sentinel SU_FAKE_USER_SEED "$nkey_fake_seed"
replace_sentinel SU_FAKE_JWT_SEED "$jwt_fake_seed"
replace_sentinel FAKE_USER_JWT "$jwt_fake"
mv "$rendered" "$out/arkham.toml"

printf '%s\n' "$operator_jwt" >"$nats/operator.jwt"

# The password matches ARKHAM_NATS_REAL. betterleaks:allow
cat >"$nats/server.conf" <<EOF
port: 4222
http_port: 8222
tls {
  cert_file: /certs/nats.crt
  key_file: /certs/nats.key
}
authorization {
  users: [
    { user: agent, password: arkham_real_nats_pass }
    { nkey: ${nkey_real_public} }
  ]
}
cluster {
  no_advertise: true
}
EOF

cat >"$nats/jwt.conf" <<EOF
port: 4223
http_port: 8222
tls {
  cert_file: /certs/nats.crt
  key_file: /certs/nats.key
}
operator: /etc/nats/operator.jwt
resolver: MEMORY
resolver_preload: {
  ${demo_account}: "${account_jwt}"
}
cluster {
  no_advertise: true
}
EOF

fragment=$nats/nats.env
cat >"$fragment" <<EOF
ARKHAM_NATS_NKEY_REAL='${nkey_real_url}'
ARKHAM_NATS_JWT_REAL='${jwt_real_url}'
NATS_NKEY_URL='${nkey_fake_url}'
NATS_JWT_URL='${jwt_fake_url}'
NATS_NKEY_FOREIGN='${nkey_foreign_seed}'
NATS_JWT_FOREIGN_SEED='${jwt_foreign_seed}'
NATS_JWT_FOREIGN_JWT='${jwt_foreign}'
NATS_NKEY_REAL_SEED='${nkey_real_seed}'
NATS_JWT_REAL_ASSERT='${jwt_real}'
EOF
chmod 600 "$fragment"

tmp=$(mktemp)
awk -F= '
  NR==FNR { keys[$1] = 1; next }
  ($1 in keys) { next }
  { print }
' "$fragment" integration/.env >"$tmp"
printf '\n' >>"$tmp"
cat "$fragment" >>"$tmp"
mv "$tmp" integration/.env
chmod 600 integration/.env
