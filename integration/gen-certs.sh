#!/usr/bin/env bash
# One-shot PKI for the demo: a throwaway CA plus one leaf for the api
# service (SAN DNS:api). arkham loads ca.pem (cert + PKCS#8 key), verifies
# the api leaf as its upstream TLS peer, and mints MITM leaves from the
# same key. The client trusts ca.crt only.
set -euo pipefail

dir=${1:-/certs}

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/ca.key"
openssl req -new -x509 -key "$dir/ca.key" -out "$dir/ca.crt" -days 2 \
  -subj "/CN=arkham demo CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/api.key"
openssl req -new -key "$dir/api.key" -out "$dir/api.csr" -subj "/CN=api"
printf "subjectAltName=DNS:api\n" >"$dir/api.ext"
openssl x509 -req -in "$dir/api.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -out "$dir/api.crt" -days 2 -extfile "$dir/api.ext"

# The db service presents this leaf on its TLS leg. SAN carries the static
# address because the transparent grant identifies the captured destination
# by address and the client dials the IP literal.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/pg.key"
openssl req -new -key "$dir/pg.key" -out "$dir/pg.csr" -subj "/CN=db"
printf "subjectAltName=IP:10.202.0.30,DNS:db\n" >"$dir/pg.ext"
openssl x509 -req -in "$dir/pg.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -out "$dir/pg.crt" -days 2 -extfile "$dir/pg.ext"

# Redis TLS: the same pattern, SAN carries both the static IP and hostname.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/redis.key"
openssl req -new -key "$dir/redis.key" -out "$dir/redis.csr" -subj "/CN=redis"
printf "subjectAltName=IP:10.202.0.50,DNS:redis\n" >"$dir/redis.ext"
openssl x509 -req -in "$dir/redis.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -out "$dir/redis.crt" -days 2 -extfile "$dir/redis.ext"

# Mail TLS: docker-mailserver presents this leaf for both STARTTLS (587)
# and implicit TLS (465). The proxy verifies the name `mail`.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/mail.key"
openssl req -new -key "$dir/mail.key" -out "$dir/mail.csr" -subj "/CN=mail.demo.test"
printf "subjectAltName=IP:10.202.0.60,DNS:mail,DNS:mail.demo.test\n" >"$dir/mail.ext"
openssl x509 -req -in "$dir/mail.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -out "$dir/mail.crt" -days 2 -extfile "$dir/mail.ext"
# The mail image reads the key as a non-root service after it copies the
# file. A demo CA key stays 600; this leaf key is world-readable on purpose.
chmod 644 "$dir/mail.key" "$dir/mail.crt"

# LDAP TLS: 389ds imports this leaf at bootstrap. SAN carries the hostname
# the connection strings dial and the static address on the server net.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/ldap.key"
openssl req -new -key "$dir/ldap.key" -out "$dir/ldap.csr" -subj "/CN=ldap"
printf "subjectAltName=IP:10.202.0.80,DNS:ldap\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n" >"$dir/ldap.ext"
openssl x509 -req -in "$dir/ldap.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -out "$dir/ldap.crt" -days 2 -extfile "$dir/ldap.ext"

# Guest identity for the LDAP mTLS scenario. Arkham's CA is this same key
# (`ca.pem`), and the client container drops privileges, so the key is
# world-readable the way the mail leaf is.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/ldap-guest.key"
openssl req -new -key "$dir/ldap-guest.key" -out "$dir/ldap-guest.csr" -subj "/CN=ldap-guest"
printf "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n" >"$dir/ldap-guest.ext"
openssl x509 -req -in "$dir/ldap-guest.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -out "$dir/ldap-guest.crt" -days 2 -extfile "$dir/ldap-guest.ext"
chmod 644 "$dir/ldap-guest.key" "$dir/ldap-guest.crt"

# NATS TLS: nats-server presents this leaf after its cleartext INFO line.
# SAN carries the hostname the connection strings dial and the static address.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/nats.key"
openssl req -new -key "$dir/nats.key" -out "$dir/nats.csr" -subj "/CN=nats"
printf "subjectAltName=IP:10.202.0.90,IP:10.202.0.91,DNS:nats,DNS:nats-jwt\n" >"$dir/nats.ext"
openssl x509 -req -in "$dir/nats.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -out "$dir/nats.crt" -days 2 -extfile "$dir/nats.ext"
# The nats image reads this leaf as its service user. Match mail.key.
chmod 644 "$dir/nats.key" "$dir/nats.crt"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/amqp.key"
openssl req -new -key "$dir/amqp.key" -out "$dir/amqp.csr" -subj "/CN=amqp"
printf "subjectAltName=IP:10.202.0.100,DNS:amqp\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n" >"$dir/amqp.ext"
openssl x509 -req -in "$dir/amqp.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -out "$dir/amqp.crt" -days 2 -extfile "$dir/amqp.ext"

cat "$dir/ca.crt" "$dir/ca.key" >"$dir/ca.pem"
chmod 600 "$dir/ca.key" "$dir/ca.pem"

# SSH legs. arkham's host key is the one the agent's ssh verifies; the
# identity is what arkham presents upstream (its public half is the sshd's
# authorized key); the decoy is the only private key that ever mounts into
# the client. No pins: both sides run ssh's own accept-new.
mkdir -p "$dir/ssh"
rm -f "$dir/ssh/arkham_host" "$dir/ssh/arkham_host.pub" "$dir/ssh/identity" "$dir/ssh/identity.pub" "$dir/ssh/decoy" "$dir/ssh/decoy.pub"
ssh-keygen -q -t ed25519 -N "" -C arkham-guest-host -f "$dir/ssh/arkham_host"
ssh-keygen -q -t ed25519 -N "" -C demo-real-identity -f "$dir/ssh/identity"
ssh-keygen -q -t ed25519 -N "" -C demo-decoy -f "$dir/ssh/decoy"
cp "$dir/ssh/identity.pub" "$dir/ssh/authorized_keys"
chmod 600 "$dir/ssh/identity" "$dir/ssh/decoy" "$dir/ssh/arkham_host"
echo "certs ready in $dir"
