# Integration demo (transparent capture)

Runs the real container image (runtime-only `Dockerfile`, prebuilt
binary) in the deployment shape arkham exists for: the
client container shares arkham's network namespace and knows nothing about
any proxy. arkham runs `serve --proxy-backend tproxy` and installs its nft rules and
policy routing inside the shared netns, so every client connection is
captured on the way out.

This demo pins `tproxy` because the eBPF backend captures by cgroup
membership, and a compose service's cgroup path is not something the demo
can fix. For the same scenarios over eBPF, run the docker-free
[bwrap demo](bwrap/README.md) with `ARKHAM_BACKEND=ebpf`.

Topology:

- `client` — `network_mode: service:arkham`; talks to `api` by plain
  hostname:port. Holds only the deterministic fake (`arkham fake GH_TOKEN`).
- `arkham` — legs on the default bridge and the `server` network;
  `cap_add: NET_ADMIN` for the TPROXY listener, nft rules, and policy
  routes (all self-installed over netlink — the runtime image ships no
  `nft`/`ip`). Marked upstream dials bypass capture (fwmark rule).
- `api` — bun server on `server` only, static IP `10.202.0.20`,
  validates only the real token.
- `db` — real PostgreSQL 17 (Alpine) on `server` only, static IP
  `10.202.0.30`, TLS with a demo-CA leaf, validates only the real password.
- `server` subnet is RFC1918 on purpose: arkham captures LAN traffic too
  (the capture routes are default-route-only), and this demo proves it.

| # | Client does | Grant | Passes when |
| --- | ------------- | ------- | ------------- |
| 1 | HTTPS GET `api:8443` with the fake bearer | `https://api:8443` | server saw the real bearer, response body redacted back to the fake |
| 2 | Cleartext HTTP GET `api:8000` with the fake bearer | `http://api:8000` | same as 1 through transparent plain-HTTP capture (Host header identity) |
| 3 | Cleartext line protocol to `api:9000` | `tcp://10.202.0.20:9000` | `AUTH fake` became `AUTH real`, `OK real` came back as `OK fake` |
| 4 | TLS line protocol to `api:9443` | `https://api:9443` | same as 3 through terminated TLS legs |
| 5 | TLS line protocol to `api:9444` | none | tunnel splices untouched: fake arrives as-is, server rejects |
| 6 | Postgres wire protocol driven by the client's own `DATABASE_URL` (the rule's stated fake string): SSLRequest, TLS, cleartext password auth, `SELECT` | `[rules.db]`: `env = "DATABASE_URL"`, `value` the fake URL; the real URL in fnox | the fake password authenticates against real PostgreSQL — arkham swapped the real one in from the secret source — and the query row comes back |
| 7 | OAuth2 `client_credentials` POST `api:8000/token` with the fake client secret, then GET with the minted token | `[rules.oidc]` + `oauth2` block | issuer saw the real client secret, the client received a minted decoy access token (never the real one), and the decoy swapped back to the real access token on the API call |
| 8 | OpenSSH client with the decoy identity to `10.202.0.40` | `[rules.ssh]` `ssh://10.202.0.40:22` | `echo ssh-ok`, and `known_hosts` records arkham's host key |
| 9 | Redis RESP via Bun's `RedisClient` to `redis:6379`: requirepass, ACL user, `HELLO 3 AUTH`, a pipeline, and `WRONGPASS` | `[rules.redis_plain]`: fake `redis://` URL; real URL rendered into fnox by `gen-secrets.sh` | official Redis accepts the swapped password; the real password is absent from the client error |
| 10 | Same client to `redis:6380` over TLS. Bun sends no SNI | `[rules.redis_tls]`: fake `rediss://` URL; real URL carries `sslrootcert` | same swap. The guest leaf is minted for the scope host. Redis is started with `tls-auth-clients no` |
| 11 | Python `smtplib` to `mail:587`: AUTH before STARTTLS is refused; AUTH PLAIN and `SMTP.login` after STARTTLS succeed; a wrong password fails; a one-shot on the server network dials the decoy at `mail` and is refused | `[rules.smtp]`: fake `smtp://` URL; real URL says `starttls=required` and carries `sslrootcert` | docker-mailserver accepts the swapped password and the client never sees it; the decoy is refused when the dial is outside the captured namespace |
| 12 | Same client to `mail:465` with implicit TLS | `[rules.smtps]`: fake `smtps://` URL; real URL carries `sslrootcert` | same swap on a session that is TLS from the first byte |
| 13 | `ldapts` simple bind to `ldap:3389` before StartTLS | `[rules.ldap_plain]`: fake `ldap://` URL | 389ds refuses the bind (`confidentialityRequired`, code 13) because `nsslapd-require-secure-binds` is on. The error text does not contain the real password. Code 13 is the same for the decoy and the real password; the in-process test checks that the cleartext bytes are still the decoy |
| 14 | Same client: StartTLS, then a simple bind with the decoy password. Two more connections on the same rule: a refused cleartext bind (code 13) and then StartTLS on that socket; a root-DSE search and then StartTLS on that socket. Each continues with the decoy bind | `[rules.ldap_plain]` | the directory accepts each protected bind. Arkham swapped the decoy for the real password after the upgrade, including when StartTLS was not the first message |
| 15 | `ldapts` simple bind to `ldap:3636` over LDAPS with the decoy password | `[rules.ldap_tls]`: fake `ldaps://` URL; real URL carries `sslrootcert` | same swap on a leg that is TLS from the first byte |
| 16 | StartTLS and LDAPS binds with a password that is not the decoy | the same two rules | the directory returns `invalidCredentials` (code 49). The password was not swapped, and the error text does not contain the real password |
| 17 | `nats` client to `nats:4222` with the decoy password: TLS upgrade after INFO, subscribe, publish a payload that carries the decoy, receive it | `[rules.nats]`: fake `nats://` URL; real `tls://` URL carries `sslrootcert` | nats-server accepts the swapped password, and the message comes back with the decoy unchanged |
| 18 | Same client with a password that is not the decoy | `[rules.nats]` | nats-server returns `Authorization Violation`. The password was not swapped, and the error text does not contain the real password |
| 19 | `nkeyAuthenticator` to `nats:4222`. The client writes the decoy seed under `~/.config/nats`, selects it from `context.txt`, and reads the `nkey` path: subscribe and publish | `[rules.nats_nkey]`: `nats://nkey:<user-seed>@nats:4222`; the real string is the same form on `tls://` | nats-server accepts the session, which is the proof the proxy signed the nonce with the real seed. The client never sends that seed |
| 20 | Same client with a user seed that is not the decoy | `[rules.nats_nkey]` | nats-server returns `Authorization Violation`. The CONNECT was not swapped. The error text contains neither the real seed nor the real user JWT |
| 21 | `credsAuthenticator` to `nats-jwt:4223`. The client writes the decoy creds file under `~/.config/nats`, selects it from `context.txt`, and reads the `creds` path | `[rules.nats_jwt]`: `nats://creds:<user-seed>:<user-jwt>@nats-jwt:4223`; the account JWT is preloaded on the operator server | publish and subscribe succeed only when the proxy replaces the decoy JWT and signs with the real seed |
| 22 | Same client with a user JWT that is not the decoy | `[rules.nats_jwt]` | nats-server returns `Authorization Violation`. The CONNECT was not swapped. The error text contains neither the real seed nor the real user JWT |
| 23 | The client reads the decoy nkey context that host discovery mounted, then subscribes and publishes. `test:ssh` is the only path that runs it | no hand-written `[rules.nats_*]` and no fnox key. `arkham init` reads a host `~/.config/nats` context whose nkey file is the real seed and whose `ca` is the demo CA. The generated fragment (`generated = true`, `if_missing = ignore`) is appended to the global config. The arkham service mounts the CA blob. The client receives only the decoy files | nats-server accepts the session, so the proxy swapped the mounted decoy for the real seed. The real seed is absent from the guest tree |
| 24 | `amqplib` (AMQP 0-9-1) to `amqp:5672` with the decoy user and password: open, declare a queue, publish with a confirm, read the message back | `[rules.amqp_plain]`: fake `amqp://` URL; the real URL is `amqps://` and carries `sslrootcert` | RabbitMQ accepts the swapped user and password on its TLS port 5671 and the message comes back |
| 25 | `rhea` (AMQP 1.0) to `amqp:5672` with the decoy: SASL `PLAIN`, then `open` | `[rules.amqp_plain]` | the broker sends `open`, which it never does after a refused login |
| 26 | Both clients to `amqp:5671` over TLS with the decoy | `[rules.amqp_tls]`: fake `amqps://` URL; real URL carries `sslrootcert` | same swaps on a guest leg that is TLS from the first byte |
| 27 | Both clients on both rules with a password that is not the decoy | the same two rules | 0-9-1 gets `ACCESS_REFUSED` and 1.0 gets a failed SASL outcome (`amqp:unauthorized-access`). The password was not swapped, and the error text does not contain the real password |
| 28 | `amqplib` to port 5673, which has no grant. The client bytes are compared with a tcpflow recording on the broker | no AMQP grant. The witness shares the broker network namespace, drops every capability, and adds `NET_RAW`, `CHOWN`, and `DAC_OVERRIDE`. It is not mounted into the client | RabbitMQ answers `ACCESS_REFUSED` (403). Start-Ok still carries the decoy. The bytes match. `ss` shows a second established socket to 5673, so a bypass cannot pass |

Scenario 3's grant host is the literal destination IP because raw TCP
capture has no SNI — the destination address is the identity
(`crates/arkham-tproxy/src/tproxy.rs` `tproxy_conn_task`). Scenario 5 is the fail-closed control: without a grant
arkham splices TLS byte-identical, so no secret can leak and the server
refuses the fake.
Scenario 6's entry is a real
libpq URL naming the host (`db`); a transparently captured connection
carries no hostname arkham can key on (libpq sent no SNI before PostgreSQL
17), so the transparent path shortlists by port alone — any captured
connection to :5432 resolves to the entry, whatever address DNS resolved.
Both connection strings name the host the way real deployments do —
the `db` hostname, never an IP. The client keeps full TLS hostname
verification on: it dials by that name, and arkham mints the guest leaf
for it. Scenario 6 is gated on `DATABASE_URL`, so `run.ts` still runs when that service is absent.
Scenario 7 exercises runtime token minting
(`crates/arkham-proxy/src/mint.rs`): the client secret is a static
substitution (`arkham fake OIDC_CLIENT_SECRET`, pinned in
`compose.yaml`), and the access token is minted per issue, so no real
access token ever reaches the client container.
Scenarios 9 and 10 are the official `redis:7-alpine` image and Bun's
`RedisClient`. The proxy is the only code we wrote on that path. A
`tls-ca-cert-file` makes Redis require a client certificate; this demo
authenticates with passwords and the upstream client has no certificate,
so the server is started with `tls-auth-clients no`. Scenarios 9 and 10 are gated on `REDIS_URL` and `REDIS_TLS_URL`, so `run.ts` still runs when the Redis service is absent. `integration/bwrap/run.sh` does not run `run.ts`.
Scenarios 11 and 12 are `mailserver/docker-mailserver` 16.0.1 (pinned by digest) and Python's `smtplib`. The proxy is the only code we wrote on that path. `SMTP_ONLY` stays unset because Dovecot answers SASL. `setup email add` runs before supervisord so the account is in Dovecot's user database at first start. The server presents a demo-CA leaf and does not ask for a client certificate; the demo authenticates with passwords. Scenarios 11 and 12 are gated on `SMTP_URL` and `SMTPS_URL`.

AUTH before STARTTLS being refused in scenario 11 is Postfix's own `530`. That refusal does not show which password was on the wire. The proof that the real password stays off the cleartext upstream is the in-process test `smtp_auth_before_starttls_stays_the_decoy_and_swaps_after`. The decoy-only failure against the real server is `smtp-direct`: a one-shot on the server network, outside the captured namespace, that runs `SMTP.login` of the decoy against `mail:587` and `mail:465`. It does not run when `SMTP_URL` is empty. The client container never holds `NET_ADMIN`. The wrong-password check in the scenario is a different password sent through the proxy, not that dial.
Scenarios 13–16 use `quay.io/389ds/dirsrv` (the manifest list was last
pushed June 2025; the pin is a multi-arch digest, not a Docker Hub tag)
and `ldapts` 9.2.0. The directory listens on 3389 and 3636. After it is
up, `dsconf` sets `nsslapd-require-secure-binds: on`. Before the
service waits, `ldapsearch` inside the container binds with the decoy
password over LDAPS and again over StartTLS. Both must exit 49. Those
binds do not pass through the proxy. The flag requires TLS
for a simple bind. It does not require a client certificate, and this
demo does not present one: the proxy's upstream leg has no client
identity, the same way the Redis demo sets `tls-auth-clients no`. The
trust anchor is the demo CA from `gen-certs.sh`, imported into the
directory at bootstrap and named by `sslrootcert` on both real strings.
`ldap://` carries that anchor because StartTLS verifies the upstream
certificate after the upgrade. A refused bind leaves the `ldapts` socket
open, and an anonymous root-DSE search is a different first message. Both
then call `startTLS` on that socket and bind with the decoy. Scenarios
13–16 are gated on `LDAP_URL` and `LDAP_TLS_URL`.
Scenarios 17 and 18 use the official `nats:2.15.1-alpine` image and the
`nats` npm package 2.29.3. The server requires TLS: it writes one
cleartext INFO line, then expects a handshake on the same socket. Its only
account holds the real password, so a session that authenticates with the
decoy proves the swap. The tls block sets no `verify`, so the server does
not ask for a client certificate, and this demo does not present one: the
proxy's upstream leg has no client identity. `cluster { no_advertise: true }`
keeps cluster client URLs out of INFO. The real string is `tls://`, which
is what lets arkham swap: the CONNECT password is replaced only after the
upstream leg is TLS. Payloads are never rewritten, so the decoy in the
published message arrives unchanged. Scenarios 17 and 18 are gated on
`NATS_URL`. Scenarios 19 and 20 use the same server, with a user nkey
added beside the password user. `integration/gen-nats.sh` mints the
operator, accounts, and users with `nsc` and writes `integration/out`, which is gitignored.
The fake user JWT is signed by an account the server does not preload.
Scenarios 21 and 22 use a second `nats:2.15.1-alpine` service in
operator mode. The account JWT is preloaded under `resolver: MEMORY`,
so the server checks the user JWT. The client uses `nkeyAuthenticator`
and `credsAuthenticator` from the `nats` package 2.29.3. Scenarios 19
and 20 are gated on `NATS_NKEY_URL`. Scenarios 21 and 22 are gated on
`NATS_JWT_URL`. Scenarios 19 and 21 write the fnox decoy into the client
container's own `~/.config/nats` and read it back. That is not discovery:
the proxy grant is still the fnox URL, and `compose::nats::adapt` does not
run. Scenario 23 is the discovery proof. `test:ssh` writes a host
`~/.config/nats` context, runs `arkham init` in an empty workspace with no
`[rules.nats_*]` and no fnox entry for that grant, and mounts the decoy
files into the client. The client reads those files before scenarios 19 and
21 overwrite the same directory. `credsAuthenticator` sends `jwt`, `nkey`, and `sig`. A matching `nkey` is
rewritten to the real public key. The client container does not receive the
real nkey seed or the real user JWT. `test:ssh` greps the client log for
those values in `integration/out/nats/nats.env`.
Scenarios 24–27 use the official `rabbitmq` 4.3.6 Alpine image (pinned
by its manifest-list digest), `amqplib` 2.2.0, and `rhea` 3.0.5. The
proxy is the only code we wrote on that path. The broker's one user is
`svc` with the real password; the client holds the user `agent` and the
decoy, so a pass shows that the user and the password were both swapped.
AMQP 1.0 is a core protocol in RabbitMQ 4.x; the service still enables
`rabbitmq_amqp1_0`, the no-op plugin 4.x keeps for deployment tools. The
broker listens on 5672 and on 5671 with a demo-CA leaf. Its TLS sets
`ssl_options.verify = verify_none` and
`ssl_options.fail_if_no_peer_cert = false`, so it does not ask for a
client certificate. The demo authenticates with SASL passwords, and the
proxy's upstream leg has no client identity, the same way the Redis demo
sets `tls-auth-clients no`. The broker is healthy only when
`rabbitmqctl authenticate_user` accepts the real password and refuses the
decoy password. Those checks run inside the container and do not pass
through the proxy. Both real strings are `amqps://` because arkham writes
the real password only to a TLS upstream. The cleartext-upstream case,
where the decoy is forwarded, is the in-process test
`amqp_cleartext_start_ok_forwards_the_decoy`. Scenarios 24–27 are gated
on `AMQP_URL` and `AMQP_TLS_URL`. Scenario 28 is gated on `AMQP_URL`.
The broker also listens on 5673. That port is not a grant, so arkham
splices it. An empty capture retries. A byte mismatch fails on the
first attempt.

## Run

```sh
mise run demo
```

First run only: the demo's real values resolve from fnox at serve time, so
no committed rule file carries a `value`. `gen-secrets.sh` renders the
arkham container's fnox config from the environment:

```sh
cp integration/.env.example integration/.env   # gitignored; adjust freely
```



The task builds the release binary, packs it into
the runtime image via the repo `Dockerfile`, and runs
`docker compose up --abort-on-container-exit --exit-code-from client`.
Client exit code 0 means every scenario passed.

Recomputing the fake after changing `env` in `arkham.toml`:

```sh
mise run build -- --release
target/release/arkham fake GH_TOKEN
```

Update the value in `compose.yaml` (`client.environment.ARKHAM_FAKE`) to match.
