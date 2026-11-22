#!/usr/bin/env bash
# The NATS client must not see the real nkey seed or user JWT, in its log or
# through a mount of the host-side material gen-nats.sh wrote.
set -euo pipefail
source integration/e2e.sh

for key in NATS_NKEY_REAL_SEED NATS_JWT_REAL_ASSERT; do
  line=$(grep -E "^${key}=" target/integration/nats/nats.env || true)
  value=${line#*=}
  value=${value//\'/}
  if [ -z "$value" ]; then
    echo "missing ${key} in target/integration/nats/nats.env" >&2
    exit 1
  fi
  if grep -F -q -- "$value" "$client_log"; then
    echo "client log contains ${key}" >&2
    exit 1
  fi
done

while IFS= read -r source; do
  case "$source" in
    */target/integration|*/target/integration/nats|*/target/integration/nats-discovery)
      echo "client mount exposes ${source}" >&2
      exit 1
      ;;
  esac
done < <(docker inspect -f '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$client")
