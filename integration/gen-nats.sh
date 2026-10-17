#!/usr/bin/env bash
# Mint operator, account, and user nkeys for the demo. Seeds land in
# integration/out (gitignored) and in integration/.env (gitignored).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if [[ ! -f integration/.env ]]; then
  cp integration/.env.example integration/.env
fi

cargo run --locked --quiet -p arkham-config --example gen-nats-demo -- "$root"

fragment=integration/out/nats/nats.env
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
