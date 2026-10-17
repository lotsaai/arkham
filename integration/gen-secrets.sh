#!/usr/bin/env bash
# One-shot secret provisioning for the demo: renders the fnox plain-provider
# config the arkham container resolves its rule values from. Values arrive by
# environment at runtime (integration/.env, gitignored) — never from a
# committed rules file.
set -euo pipefail

dir=${1:-/arkham-config}

: "${ARKHAM_REAL:?ARKHAM_REAL not set: copy integration/.env.example to integration/.env and export it}"
: "${ARKHAM_DB_REAL:?ARKHAM_DB_REAL not set: copy integration/.env.example to integration/.env and export it}"
: "${OIDC_CLIENT_SECRET:?OIDC_CLIENT_SECRET not set: copy integration/.env.example to integration/.env and export it}"
: "${ARKHAM_REDIS_REAL:?ARKHAM_REDIS_REAL not set: copy integration/.env.example to integration/.env and export it}"
: "${ARKHAM_REDIS_TLS_REAL:?ARKHAM_REDIS_TLS_REAL not set: copy integration/.env.example to integration/.env and export it}"
: "${ARKHAM_SMTP_REAL:?ARKHAM_SMTP_REAL not set: copy integration/.env.example to integration/.env and export it}"
: "${ARKHAM_SMTPS_REAL:?ARKHAM_SMTPS_REAL not set: copy integration/.env.example to integration/.env and export it}"
: "${ARKHAM_LDAP_REAL:?ARKHAM_LDAP_REAL not set: copy integration/.env.example to integration/.env and export it}"
: "${ARKHAM_LDAP_TLS_REAL:?ARKHAM_LDAP_TLS_REAL not set: copy integration/.env.example to integration/.env and export it}"
: "${ARKHAM_NATS_REAL:?ARKHAM_NATS_REAL not set: copy integration/.env.example to integration/.env and export it}"
: "${ARKHAM_NATS_NKEY_REAL:?ARKHAM_NATS_NKEY_REAL not set: run integration/gen-nats.sh}"
: "${ARKHAM_NATS_JWT_REAL:?ARKHAM_NATS_JWT_REAL not set: run integration/gen-nats.sh}"

mkdir -p "$dir"

# The global config layer arkham derives its config-dir from; the demo's real
# config arrives via --config, so this one only anchors the directory.
printf '[proxy]\nlisten = "127.0.0.1:8080"\n' >"$dir/config.toml"

# Arkham's fnox level: with ARKHAM_CONFIG=$dir/config.toml, the config dir is
# $dir and the level file sits directly in it.
cat >"$dir/fnox.toml" <<EOF
[providers.plain]
type = "plain"

[secrets.GH_TOKEN]
provider = "plain"
value = "$ARKHAM_REAL"

[secrets.OIDC_CLIENT_SECRET]
provider = "plain"
value = "$OIDC_CLIENT_SECRET"

[secrets.DATABASE_URL]
provider = "plain"
value = "$ARKHAM_DB_REAL"

[secrets.REDIS_URL]
provider = "plain"
value = "$ARKHAM_REDIS_REAL"

[secrets.REDIS_TLS_URL]
provider = "plain"
value = "$ARKHAM_REDIS_TLS_REAL"

[secrets.SMTP_URL]
provider = "plain"
value = "$ARKHAM_SMTP_REAL"

[secrets.SMTPS_URL]
provider = "plain"
value = "$ARKHAM_SMTPS_REAL"

[secrets.LDAP_URL]
provider = "plain"
value = "$ARKHAM_LDAP_REAL"

[secrets.LDAP_TLS_URL]
provider = "plain"
value = "$ARKHAM_LDAP_TLS_REAL"

[secrets.NATS_URL]
provider = "plain"
value = "$ARKHAM_NATS_REAL"

[secrets.NATS_NKEY_URL]
provider = "plain"
value = "$ARKHAM_NATS_NKEY_REAL"

[secrets.NATS_JWT_URL]
provider = "plain"
value = "$ARKHAM_NATS_JWT_REAL"
EOF
chmod -R a+rX "$dir"
echo "fnox config ready in $dir"
