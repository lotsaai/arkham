# Configuration reference

Every configuration layer, file, and key. Values merge across layers; a higher layer wins.

## Layers

1. CLI flags: `--listen`, `--ca-file`, `--config`.
2. Environment variables: `ARKHAM_LISTEN`, `ARKHAM_CA_FILE`, `ARKHAM_CONFIG`, `ARKHAM_PROXY_BACKEND`, `ARKHAM_TPROXY_ALLOW_ROOT_NETNS`.
3. The project file at `<workspace root>/.config/arkham/config.toml` (legacy `.config/arkham.toml` still reads). The workspace root is found by walking up from the working directory.
4. The global file at `$ARKHAM_CONFIG` or `<config-dir>/arkham/config.toml`.

`--config <FILE>` replaces the project layer, it does not add a fifth one.

`[rules]` merges by label: a project `[rules.demo]` replaces a global `[rules.demo]` wholesale. Other sections merge per key.

## `[proxy]`

| Key | Default | Environment | Purpose |
| --- | --- | --- | --- |
| `listen` | `127.0.0.1:8080` | `ARKHAM_LISTEN` | Address the explicit proxy listens on. |
| `ca_file` | `/certs/ca.pem` when mounted there, else `<config-dir>/arkham/ca.pem` | `ARKHAM_CA_FILE` | Path to the CA file, which holds the certificate followed by the key. `arkham ca` also writes `ca.crt` and `ca.key` beside it. |
| `ssh_host_key` | `<config-dir>/arkham/ssh_host_ed25519` | `ARKHAM_SSH_HOST_KEY` | Host key the guest leg presents. Generated on first run. |
| `ssh_known_hosts` | `<config-dir>/arkham/ssh_known_hosts` | `ARKHAM_SSH_KNOWN_HOSTS` | Upstream `known_hosts`. First-seen keys are recorded. Arkham rejects a changed key on a known host. |
| `root_certs` | `[]` | — | Extra upstream CA bundles trusted on egress, additive to webpki roots. Config file only, one path per bundle. Entries extend this further with their own `root_cert`. |
| `handshake_timeout_secs` | `10` | `ARKHAM_HANDSHAKE_TIMEOUT_SECS` | Seconds the pre-auth or handshake reads may wait on a peer before the connection closes: the TLS `ClientHello`, the HTTP head, the Postgres greeting, the Redis command, the LDAP StartTLS reply, and the upstream `SSLRequest` answer all share this budget. The NATS server's INFO line is not on this budget. |

## `[rules.<label>]`

A rule wires an environment name to the hosts it may reach, the decoy shape the client sees, and where the real value comes from. `[rules.<label>]` replaces the older `[secrets.<label>]` table; a leftover `[secrets]` table is ignored silently.

| Key | Required | Purpose |
| --- | --- | --- |
| `env` | yes | Environment variable name. Seeds the decoy, keys the registry lookup, and defaults the fnox key. |
| `value` | no | Inline real secret value. Wins over fnox. Never serialized. |
| `fnox_key` | no | fnox secret name. Defaults to `env`. |
| `allow` | no | List of `scheme://host[:port]` allow entries. Unions with the hosts the registry supplies. See [allow entries](allow-entries.md) for the grammar and host forms. |
| `pattern` | no | Decoy pattern, overriding the registry. |
| `oauth2` | no | An OAuth2 flow block overriding the registry's: declares a token issuer whose freshly issued tokens get minted as decoys. See [the registry reference](registry.md). |
| `registry` | no | Whether this rule uses registry hosts. Default `true`; `false` keeps only `allow`. |
| `if_missing` | no | `error` (default), `warn`, or `ignore`. Governs a value or hosts the rule cannot resolve. |

`env = "GITHUB_TOKEN"` alone is a complete rule when the registry knows the name: registry supplies hosts and shape, fnox supplies the value.

The registry knows public API hosts, so services it cannot bundle need explicit `allow` entries. A self-hosted or internal TLS host:

```toml
[rules.internal-api]
env = "INTERNAL_API_TOKEN"
pattern = "internal_{hex:32}"
allow = ["https://api.internal.corp"]
```

A raw TCP service such as Postgres. There is no SNI on a raw TCP connection, so the entry names the literal dialled address and port; substitution is equal-length byte swap only:

```toml
[rules.db]
env = "PGPASSWORD"
allow = ["tcp://10.0.0.8:5432"]
```

A `tcp://` entry has no framing to rewrite, so the substitution is equal-length only, and arkham satisfies that by construction: the decoy for a rule with a `tcp://` entry is generated at the real value's length, falling back from the registry shape only when the shape renders another length. See [capture traffic transparently](../how-to/capture-traffic-transparently.md) for the capture side.

### Database rules

A rule whose `value` states a `postgres://` connection string is a database rule. The rule states the FAKE connection string in `value` (a proper URL, so the env var holds a URL the client can dial through arkham), and the REAL one resolves from the secret source under `env`/`fnox_key` into `real`. A hand-written rule's stated `real` is ignored. A generated grant fragment sets `generated = true` and may state `real`. Fnox still wins when it has the key. No `allow` entries: the connection string is the grant.

The connection strings carry the upstream TLS policy as libpq parameters: `sslmode` (`disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`; default `prefer`), `sslnegotiation` (`postgres`, default, or `direct`), `sslrootcert` (upstream trust anchor, required for a verifying sslmode), and `sslcert`/`sslkey` (upstream client identity). These parameters belong on database connection strings only; endpoint rules state the same capabilities through `[rules.<label>.tls]`.

The guest chooses its own transport. `guest_tls_mode = mtls` stays legal on `postgres://`. A guest that opens in cleartext is closed before arkham dials upstream, so the real credential is not presented. That includes a cleartext `CancelRequest` from a client that already authenticated on another connection. A guest that opens TLS still has to present a client certificate signed by the arkham CA.

```toml
[rules.db]
env = "DATABASE_URL"
value = "postgres://app:decoy@db.internal:5432/app"
```

### Redis rules

A rule whose `value` states a `redis://` or `rediss://` connection string is a Redis rule. The rule states the FAKE string in `value` (a proper URL, so the env var holds a URL the client can dial). The REAL string resolves from the secret source under `env`/`fnox_key` into `real`. No `allow` entries: the connection string is the grant, matched on the fake string's port.

`redis://` is cleartext. `rediss://` is TLS. The scheme states the transport; a `sslmode` or `sslnegotiation` query is rejected. The default port is `6379`. The real `rediss://` string may carry `sslrootcert` (a PEM path, or `system` for the platform store) and `sslcert`/`sslkey` together (the upstream client certificate). Arkham reads that query and removes it before dialing. The guest leg's mode is `[rules.<label>.tls."<env>"]`, keyed by the rule's env name: `guest_tls_mode` is `tls` (default) or `mtls`. `mtls` requires a `rediss://` fake. A `redis://` fake with `mtls` is rejected at load whether the real string is `redis://` or `rediss://`. AUTH is rewritten on a cleartext upstream, and Redis has no upgrade that forwards the decoy until the guest presents a certificate.

The wire machine swaps the fake password for the real one on `AUTH` and `HELLO`. When the two strings name different users, the user swaps too.

```toml
[rules.cache]
env = "REDIS_URL"
value = "redis://app:decoy@cache.internal:6379/0"
```

```toml
[rules.cache_tls]
env = "REDIS_TLS_URL"
value = "rediss://app:decoy@cache.internal:6380/0"
```

The real `rediss://` value in fnox carries the trust anchor, for example `rediss://app:real@cache.internal:6380/0?sslrootcert=/path/ca.pem`.

### SMTP rules

A rule whose `value` states an `smtp://` or `smtps://` connection string is an SMTP rule. The rule states the FAKE string in `value`. The REAL string resolves from the secret source under `env`/`fnox_key` into `real`. No `allow` entries: the connection string is the grant, matched on the fake string's port.

`smtp://` is cleartext. `smtps://` is TLS from the first byte. The default ports are 587 (submission) and 465 (implicit TLS). Resend also publishes 25, 2465, and 2587; write the port in the string. 25 stays cleartext SMTP. 2465 is implicit TLS (`smtps://`). 2587 is STARTTLS (`smtp://` with `starttls=required`). An explicit port is never rewritten to the default, and the port does not change the scheme. The user and the password are both required, and the user is percent-encoded when it contains `@` (`agent%40demo.test`). A `%` that is not two hex digits stays as written; a sequence that is not UTF-8 is rejected. A path is rejected. `sslmode` and `sslnegotiation` are rejected: the scheme states the transport.

`starttls=required` is legal only on a real `smtp://` string. AUTH is rewritten only once the upstream leg is TLS: after that upgrade, or on `smtps://` from the first byte. A session that stays cleartext forwards the decoy. Loading a real `smtp://` string with no `starttls` query logs that the decoy is what travels until the upstream leg is TLS. `sslrootcert` (a PEM path, or `system`) and `sslcert`/`sslkey` together belong on `smtps://` or on `smtp://` with `starttls=required`.

`guest_tls_mode = mtls` on an `smtp://` fake is rejected at load only when the real string is `smtps://`. AUTH is rewritten from the first byte on that upstream, and a cleartext guest can send `AUTH` before it presents a client certificate. A real `smtp://` string still loads, including `starttls=required`. `AUTH` before `STARTTLS` forwards the decoy. The `STARTTLS` upgrade demands a client certificate before AUTH is rewritten.

`DATA` passes bytes until the terminating dot, and `BDAT n` passes the next `n` octets. Neither payload is buffered. Upstream replies redact an equal-length password and leave the username as the server wrote it. A `334` challenge is not rewritten.

The wire machine rewrites `AUTH PLAIN` (inline or after `334`), `AUTH LOGIN` (two-step, or with the username inline), `AUTH XOAUTH2`, and `AUTH OAUTHBEARER`. `AUTH CRAM-MD5` and `AUTH DIGEST-MD5` are relayed unchanged. The guest leg's mode is `[rules.<label>.tls."<env>"]`, keyed by the rule's env name.

```toml
[rules.smtp]
env = "SMTP_URL"
value = "smtp://agent%40demo.test:decoy@mail.internal:587"
```

```toml
[rules.smtps]
env = "SMTPS_URL"
value = "smtps://agent%40demo.test:decoy@mail.internal:465"
```

The real submission value in fnox carries the upgrade and the trust anchor, for example `smtp://agent%40demo.test:real@mail.internal:587?starttls=required&sslrootcert=/path/ca.pem`.

### LDAP rules

A rule whose `value` states an `ldap://` or `ldaps://` connection string is an LDAP rule. The rule states the FAKE string in `value`. The REAL string resolves from the secret source under `env`/`fnox_key`. No `allow` entries: the connection string is the grant, matched on the fake string's port. The bind DN is the URL user and the simple-bind password is the URL password; both are required, and the string has no path.

`ldap://` is cleartext and may upgrade with StartTLS. `ldaps://` is TLS from the first byte. The scheme states the transport. A `sslmode` or `sslnegotiation` query is rejected. The default port is `389` for `ldap://` and `636` for `ldaps://`. Both schemes may carry `sslrootcert` (a PEM path, or `system` for the platform store) and `sslcert`/`sslkey` together. `ldaps://` uses that material on connect. `ldap://` uses it after StartTLS, because the cleartext leg becomes TLS. Arkham reads the query off the real string and does not send it to the directory. The guest leg's mode is `[rules.<label>.tls."<env>"]`, keyed by the rule's env name: `guest_tls_mode` is `tls` (default) or `mtls`. `mtls` on an `ldap://` fake is rejected at load only when the real string is `ldaps://`. A bind is rewritten from the first byte on that upstream. A real `ldap://` string still loads. A bind before StartTLS forwards the decoy. StartTLS then demands a client certificate before the real password is used.

The wire machine swaps the fake simple-bind password for the real one and reframes the BER message, so the two passwords need not be the same length. When the bind DN equals the fake string's DN and the real string names a different DN, the DN swaps too. A bind whose password is not the decoy is forwarded byte-identical. SASL binds are forwarded unchanged.

```toml
[rules.directory]
env = "LDAP_URL"
value = "ldap://cn%3DDirectory%20Manager:decoy@ldap.internal:389"
```

```toml
[rules.directory_tls]
env = "LDAP_TLS_URL"
value = "ldaps://cn%3DDirectory%20Manager:decoy@ldap.internal:636"
```

The real value in fnox carries the trust anchor on either scheme, for example `ldap://cn%3DDirectory%20Manager:real@ldap.internal:389?sslrootcert=/path/ca.pem`.

### NATS rules

A rule whose `value` states a `nats://` or `tls://` connection string is a NATS rule. The rule states the FAKE string in `value`. The REAL string resolves from the secret source under `env`/`fnox_key`, or from a generated grant fragment that sets `generated = true`. A hand-written stated `real` is ignored. No `allow` entries: the connection string is the grant, matched on the fake string's port. The default port is `4222`. `user:pass` userinfo maps CONNECT `user` and `pass`. `user:@host` is a user with an empty password. A lone userinfo value is a token and maps CONNECT `auth_token`, including the literal names `nkey` and `creds`. A username `nkey` with a user-seed password maps CONNECT `nkey` to that seed's public key, `nats://nkey:<user-seed>@host:port`. A username `creds` with password `<user-seed>:<user-jwt>` maps CONNECT `jwt`, `nats://creds:<user-seed>:<user-jwt>@host:port`. The user JWT is three non-empty base64url segments, and its payload `sub` is that seed's public key. Any other `user:pass` stays a user and password. Both strings must use the same kind. Userinfo is required, and the string has no path.

The fake string takes no query; its spelling does not matter, because the guest picks its own TLS after the server's INFO line. The real string states how arkham reaches the server. `nats://` is cleartext: the leg never upgrades, CONNECT forwards the decoy, and loading the rule logs a warning. If that server's INFO sets `tls_required`, the session closes. `tls://` reads the server's cleartext INFO line, upgrades the upstream leg, and only then swaps CONNECT. With `handshake_first=true`, both legs do TLS before any protocol byte. A real `tls://` string may carry `sslrootcert` (a PEM path, or `system` for the platform store) and `sslcert`/`sslkey` together. Arkham reads the query off the real string and does not send it to the server. The guest leg's mode is `[rules.<label>.tls."<env>"]`, keyed by the rule's env name: `guest_tls_mode` is `tls` (default) or `mtls`. That table rejects `root_cert`, `client_cert`, and `client_key`, because upstream trust and identity belong on the real string.

The wire machine swaps a user/password or token CONNECT when every mapped field holds the decoy, and re-encodes that CONNECT as compact JSON. Those kinds ignore the INFO nonce. Unmapped `nkey`, `jwt`, and `sig` fields are copied through that re-encode. An nkey CONNECT is swapped only after the first INFO line has been read and it carried a nonce, `nkey` equals the decoy public key, `jwt` is absent, and `sig` verifies under the decoy public key over the nonce bytes. The rewritten line sets `nkey` to the real public key and `sig` to the raw URL base64 signature of the nonce under the real seed. A user-JWT CONNECT uses the same nonce and signature check against the decoy JWT. `nkey` may be absent. When `nkey` is present it must equal the decoy public key, and the rewritten line sets it to the real public key along with the real JWT and the new `sig`. That is the CONNECT `credsAuthenticator` sends. A foreign `nkey`, a bad signature, a missing nonce, or a line longer than 16 KiB is forwarded byte-identical. A cleartext upstream never swaps. PUB and HPUB payloads stream untouched. Server lines such as INFO and `-ERR` redact the real password, token, public key, or user JWT back to the decoy. MSG and HMSG payloads are never rewritten. A payload that carries the real public key or the real JWT closes the connection. A payload that carries the seed is left as it is.

```toml
[rules.bus]
env = "NATS_URL"
value = "nats://app:decoy@nats.internal:4222"
```

The real value in fnox is `tls://` and carries the trust anchor, for example `tls://app:real@nats.internal:4222?sslrootcert=/path/ca.pem`.

### AMQP rules

A rule whose `value` states an `amqp://` or `amqps://` connection string is an AMQP rule. The rule states the FAKE string in `value`. The REAL string resolves from the secret source under `env`/`fnox_key`. No `allow` entries: the connection string is the grant, matched on the fake string's port. The SASL user is the URL user and the password is the URL password; both are required. The vhost is the path without its leading slash, percent-decoded; no path is `/`. Arkham does not rewrite the vhost.

`amqp://` is cleartext. `amqps://` is TLS from the first byte. There is no in-band upgrade: a 1.0 client that asks for TLS inside the stream (protocol id 2) is forwarded without a swap. The scheme states the transport. A `sslmode`, `ssl`, or `sslnegotiation` query is rejected, and so is any other unknown query key. The default port is `5672` for `amqp://` and `5671` for `amqps://`. Only `amqps://` may carry `sslrootcert` (a PEM path, or `system` for the platform store) and `sslcert`/`sslkey` together. Arkham reads the query off the real string and does not send it to the broker. The guest leg's mode is `[rules.<label>.tls."<env>"]`, keyed by the rule's env name: `guest_tls_mode` is `tls` (default) or `mtls`. `mtls` requires an `amqps://` fake. A cleartext `amqp://` fake cannot present a client certificate, and that combination is rejected.

The PLAIN response is rewritten only when the real string is `amqps://`. A cleartext real string forwards the decoy. With `guest_tls_mode = tls`, the fake string's scheme does not decide the swap: a cleartext guest leg to an `amqps://` real string is rewritten. The wire machine reads the 0-9-1 `connection.start-ok` and the 1.0 `sasl-init` (or the `sasl-response` that carries the initial response). When the mechanism is `PLAIN` and the password is the decoy, it writes the real string's user and password, keeps the client's authorization identity, and re-encodes the frame, so the two passwords need not be the same length. A `PLAIN` response whose password is not the decoy is forwarded byte-identical. `AMQPLAIN`, `EXTERNAL`, `ANONYMOUS`, and `RABBIT-CR-DEMO` are forwarded unchanged. Server close and error texts (0-9-1 `connection.close` and `channel.close`, 1.0 `close`, `end`, and `detach`) that carry the real password reach the client with the decoy instead. The real password anywhere else in server bytes closes the connection. Content and transfer frames are not buffered.

```toml
[rules.broker]
env = "AMQP_URL"
value = "amqp://app:decoy@mq.internal:5672"
```

```toml
[rules.broker_tls]
env = "AMQP_TLS_URL"
value = "amqps://app:decoy@mq.internal:5671"
```

The real value in fnox is `amqps://` and carries the trust anchor, for example `amqps://app:real@mq.internal:5671?sslrootcert=/path/ca.pem`.

## `[rules.<label>.tls."<entry>"]`

Per-entry TLS, keyed by the exact `allow` entry string. All keys optional.

| Key | Purpose |
| --- | --- |
| `client_cert` / `client_key` | Upstream client identity the proxy presents to this entry. Come together. |
| `root_cert` | Upstream CA bundle trusting this entry's host, additive to webpki roots plus global `root_certs`. |
| `guest_tls_mode` | `tls` (default) or `mtls`: demand a guest client certificate signed by the arkham CA. `mtls` on a `redis://` fake is rejected at load. `mtls` on an `smtp://` or `ldap://` fake is rejected only when the real string is `smtps://` or `ldaps://`. Postgres keeps `mtls` and closes a guest that opens in cleartext, including a cleartext `CancelRequest`. |
| `guest_cert` / `guest_key` | Container-internal path the guest's minted certificate and key mount at. Defaults are under the workspace state directory; set these when the client reads its pair from a fixed location. |

## `[workspace]`

Controls the compose stack `arkham init` generates.

| Key | Default | Purpose |
| --- | --- | --- |
| `home` | `/home/eng` | `$HOME` inside the agent container. Host paths under the host home translate into this prefix; other paths mount at their own path. |
| `name` | workspace path slug | Compose project name. |
| `shell` | `sh` | Shell `arkham agent` runs in the container when no command is given. |
| `init` | none | Init script inside the agent image that the generated entrypoint chains to after installing the CA (`ARKHAM_INIT`). The common entrypoint script names are tried when unset; the command runs directly otherwise. |
| `include` | empty | Extra host paths the agent service mounts, translated into the container home. `~` expands; relative paths resolve against the workspace root; a trailing `:ro`/`:rw` sets the mode. Overlapping paths reuse the covering mount. A path that does not exist fails generation, because docker would mount an empty directory in its place. |
| `ports` | empty | Ports published on the host as stable `127.0.0.1:<port>` bindings, forwarded to the same port inside the agent's shared network namespace. The generated stack's `fwd` sidecar exposes every agent-owned loopback listener there; a published port names one reliably from the host instead of through a changing container IP. Applying a change needs a stack restart. Port `0` and the capture listener ports (`15000`, `15001`) are refused at load. |
| `expose` | empty | `[[workspace.expose]]` mappings with `port` (container) and `host` (host port) keys, publishing `127.0.0.1:<host>` onto a container port that differs — so two workspaces running the same dev server both publish it under distinct host ports. Managed by `arkham expose`, which claims the host port across workspaces. Same load rules as `ports`, and every host port must be distinct across `ports` and `expose`. |
| `networks` | empty | Existing compose networks the arkham service joins, each declared `external` at the top level: the agent inherits them through the shared network namespace, so a sidecar like `headroom` on one of these networks is reachable by name from the agent. Joining any network moves arkham off the default project network. Applying a change needs a stack restart. |
| `extra_hosts` | `host.docker.internal:host-gateway` only | Further `host:ip` (or `host=ip`) entries rendered as `extra_hosts` on the arkham and agent services — `/etc/hosts` is per container, so both need each entry: the agent resolves the name, arkham dials the upstream. `host.docker.internal:host-gateway` is always rendered, reaching host-bound services through the capture (which splices unmatched traffic, never blocks it). Applying a change needs a stack restart. |

## Profiles

Isolated tool-config namespaces for the secure stack. Global profiles live under `<config-dir>/arkham/profiles/<name>/`; project ones under `<workspace root>/.config/arkham/profiles/<name>/`. Each `<tool>/` directory inside a profile mounts into the agent container at the location that tool reads its own configuration from by default, so nothing has to set a config-directory variable. The workspace selects its profile with `[workspace] profile`; unset selects `__shared__`, the base every other profile inherits off and arkham always creates.

```toml
[workspace]
profile = "work"
```

```toml
# profiles/work/profile.toml
[profile]
parent = "__shared__"
```

A profile mounts its own tool dirs plus every tool its cookie parent names that it does not override. The mounts are writable: what the tool writes lands beside the profile on the host. No cookie means `__shared__` directly, and when both layers hold a `profile.toml` the project one wins outright. Cycles, unknown parents, and non-segment names fail generation.

## Automatic sources

`arkham agent` derives a working, decoy-only development environment from the authentication sources a workspace already carries — no declaration, the same way fnox's own chain is read. Each source present on the host maps onto grants plus a decoy twin mounted at the tool's default path; an absent source derives nothing, and the pass is liberal: a source that does not map — an ssh config whose blocks carry `Include`/`Match`/`ProxyJump` or a second identity, a broken kubeconfig — is skipped with a warning, never a failure. Only a credential-shaped gitconfig value (an `Authorization` extra header, an insteadOf base with userinfo) skips its whole source, because mounting a twin would carry a real secret.

| Source | Resolution | Twin mounts at |
| --- | --- | --- |
| gitconfig | The chain `git` itself resolves from the workspace root: globals with their `include.path`/`includeIf` follows, the repository's own config (linked worktrees resolve to the common dir), and `GIT_CONFIG_*` environment overrides. | `{home}/.gitconfig` |
| jj config | jj's user chain: `JJ_CONFIG` (a file, a `*.toml` directory, or a path list; even empty it replaces the defaults), else `~/.jjconfig.toml`, then `<config-dir>/jj/config.toml` and `<config-dir>/jj/conf.d/*.toml` in name order. `user.name`/`user.email` fall back to the resolved git chain, as jj itself falls back. | `{home}/.config/jj/config.toml` |
| ssh config | `~/.ssh/config`, per exact-host `Host` block carrying exactly one `IdentityFile`. | `{home}/.ssh/config` plus the decoy key at the mirrored path and a fresh `known_hosts` |
| kubeconfig | `KUBECONFIG`, a `:`-separated list merged in order. An empty value means `~/.kube/config`. A file-reference kubeconfig must be flattened first: `kubectl config view --flatten`. | `{home}/.kube/config` (writable) |
| talosconfig | `TALOSCONFIG` when it names a single path. An empty value or a colon-separated list keeps `~/.talos/config`. | `{home}/.talos/config` (writable) |
| nats context | `~/.config/nats`. `context.txt` names the selected context; `context/<name>.json` holds it. `creds`, `user_jwt`, `user_seed`, `cert`, `key`, and `ca` are paths or, for `user_jwt` and `user_seed`, inline text. `nkey` is a file path. | `{home}/.config/nats/context.txt`, the selected `{home}/.config/nats/context/<name>.json`, and a decoy credential file when the context names one |

The gitconfig is a per-forge-host authentication map, never a secret store: an `Authorization` extra header or an insteadOf base with embedded userinfo fails closed, because the agent's copy must carry decoys only. For each https remote (rewritten through `url.<base>.insteadOf`) and `credential.<url>` scope whose host a fnox-declared registry name covers, the twin mints an `http.<url>.extraHeader` holding basic auth over that name's decoy — the agent runs no credential helpers, and the proxy decodes, swaps decoy for the real value, and re-encodes. Remotes over git+ssh with a `core.sshCommand -i` identity mint the same per-host ssh grant the ssh config source mints; ssh remotes without one warn. A kubeconfig source is adapted rather than byte-swapped. `KUBECONFIG` is a `:`-separated list read in order: a context, cluster, or user name already defined stays, a new name is added, and `current-context` is the first non-empty value. The winning entry keeps the path of the file that defined it, so an identity from another file is a different label. An empty value means `~/.kube/config`. Every derivable context becomes one grant per user. The label, env, decoy, and guest pair come from that user's `kube-user` identity, and each cluster CA blob is named by the cluster's `kube-cluster` identity. The allow list is that user's API server URLs. A client certificate and key materialize into that grant's TLS identity. Cert users still present the minted guest pair (`guest_tls_mode` mutual TLS); token-only users stay plain TLS. The decoy twin keeps every context, points at the same servers, and carries the arkham CA, a minted guest pair per user, and that user's decoy token when the user has a `token` field. A user whose only credential is an auth-provider is not a grant: the context is skipped with a warning that names it, and when that context is `current-context` the file fails. A user that also has a `token` or a client pair keeps that grant. Every string under `auth-provider.config` is still a placeholder, and the grant decoy is not written there. Selecting an auth-provider user from the guest is left open. Token users of one server each get a grant, because the bearer decoy selects the real token. Two client-certificate users of one host and port are ambiguous: when one of those contexts is `current-context` the file fails with that typed error, and otherwise those contexts are skipped with a warning that names them. Any other context that cannot be derived is skipped with a warning, unless it is the current context, which fails the file. The twin mounts writable so `kubectl config use-context` can change the active name. An explicit kubeconfig `file_rewrite` stays read-only. A talosconfig gives every context that carries endpoints and a `ca`/`crt`/`key` pair its own mTLS grant. The label comes from the context helper. The `context` key is copied into the guest file and is not how a credential is chosen: the endpoint selects the grant. Two contexts that share a host and port fail closed. `TALOSCONFIG` is one path; talosctl does not split it on `:`, so a colon-separated list keeps `~/.talos/config`, and an empty value means that default too. A context with an `auth` block (Omni/SideroV1) is skipped with a warning. When that context is the active one, the file fails closed. Bare endpoints gain the Talos API port 50000. An endpoint that is an IP is the upstream TLS name. The decoy mounts writable so `talosctl config context` can change the active name. The host file stays unmounted. A NATS context becomes one `nats://` or `tls://` connection-string grant. The guest mounts the selected context only. The decoy keeps `description`, the jetstream prefixes, `inbox_prefix`, `color_scheme`, and `tls_first`, and replaces the password, token, seed, and user JWT. Unknown JSON keys are dropped. A creds or nkey path mounts at the path the context named when that path is lexically under the host home and has no `..` segment. A symlink is not canonicalized: the read follows it, and the decoy mounts at the named path. A path that escapes mounts under `{home}/.config/nats/decoy/`. A user with an empty password stays user and password. `nkey` has to be a file path. `user_seed` may be inline text. `guest_tls_mode` is not taken from the context. That field is the guest leg, and the context describes the upstream dial. Set it on the rule `tls` table. `nsc://` credential URIs, a comma-separated server list, the Windows cert store, and a socks proxy are skipped. `$XDG_CONFIG_HOME` and `NATS_*` environment overrides are not the discovery root.

## `[[workspace.file_rewrite]]`

Host files rewritten with decoys and mounted read-only into the agent — the escape hatch for files outside the automatic sources above. Each listed env name's real value is byte-replaced by its decoy in the file, and the rewritten copy lands under the workspace state directory — the agent sees decoys only; arkham holds the real values.

| Key | Required | Purpose |
| --- | --- | --- |
| `source` | yes | Host file to read. `~` and `$VAR` expand; relative paths resolve against the workspace root. |
| `dest` | yes | Container path the rewritten file mounts at, read-only, except a talos document, which mounts writable. `{home}` expands to `[workspace] home` and `$VAR` expands first. |
| `envs` | no | Env names whose real values are replaced by their decoys in the file. Empty for the structural formats — `kubeconfig` (kubectl), `talos` (talosctl): the adapter knows where the secrets live. |
| `format` | no | Declared format, skipping detection. Known: `format = "kubeconfig"` and `format = "talos"`, each failing closed when the file does not parse as one. Absent, both are detected by content and other files keep the raw byte-swap. A source matching an automatic location stays with its declaration; the automatic pass skips it. A `talos` document mounts writable so `talosctl config context` can update the active context. Other rewrites stay read-only. |

```toml
[[workspace.file_rewrite]]
source = "~/.kube/other-cluster.yaml"
dest = "{home}/.kube/other-config"
format = "kubeconfig"
```

```toml
[[workspace.file_rewrite]]
source = ".npmrc"
dest = "{home}/.npmrc"
envs = ["NPM_TOKEN"]
```

## `[plugins.<name>]`

WASM rewrite plugins, loaded at startup; load failures fail closed. Plugins match on scheme, host and port like rule grants.

| Key | Required | Purpose |
| --- | --- | --- |
| `path` | yes | Filesystem path to the component (`.wasm`). |
| `allow` | no | Raw `scheme://host[:port]` allow entries scoping where the plugin runs. |
| `direction` | no | `both` (default), `request`, or `response`. |

```toml
[plugins.marker-request]
path = "target/plugins/marker_request.wasm"
allow = ["https://api.github.com"]
direction = "request"
```

## `[tools.<name>]`

Tool config mounts for the secure stack, by tool name.

| Key | Required | Purpose |
| --- | --- | --- |
| `config_dir` | yes | Container path the directory mounts at. `{home}` expands to `[workspace] home`. Must expand to an absolute path. |

```toml
[tools.trae]
config_dir = "{home}/.trae"
```

An entry overrides a built-in path for that name or adds a name the table does not carry; a named tool found nowhere is created under the selected profile. The built-in table covers the agent CLIs plus `gh` at `{home}/.config/gh`.

## Environment variables

| Variable | Effect |
| --- | --- |
| `ARKHAM_LISTEN` | Sets `[proxy] listen`. |
| `ARKHAM_CA_FILE` | Sets `[proxy] ca_file`. |
| `ARKHAM_CONFIG` | Sets the global config file path. |
| `ARKHAM_PROXY_BACKEND` | Same as `--proxy-backend`. CLI and environment only. |
| `ARKHAM_TPROXY_ALLOW_ROOT_NETNS` | Same as `--tproxy-allow-root-netns`. |
| `ARKHAM_EBPF_CGROUP` | Same as `--ebpf-cgroup`. CLI and environment only. |

## Validation

Startup rejects:

- two rules that share an env name,
- an empty `env` or `value`,
- a malformed allow entry,
- a malformed pattern.

A `*` host in an allow entry logs a warning that the grant matches any host and the secret is at risk of exfiltration.
