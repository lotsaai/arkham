# Per-context grant identity

Several contexts in one kubeconfig, Talos config, NATS directory, or SSH config can share a destination and still be different subjects. This note is the contract for choosing among them. The helper added here names each subject and fails when two of them cannot be told apart. The proxy changes that apply the choice belong to the sibling issues.

The choice uses the destination host and port, the client identity, and the decoy bytes.

`current-context`, the Talos `context` key, and NATS `context.txt` copy the host's current value into the guest. The proxy leaves them unread. Changing them inside the guest changes the guest's default command. The proxy does not read that pointer when a sibling issue chooses the credential. `kubectl --context`, `talosctl --context`, and `nats --context` work because every granted context is present in the decoy file with its own decoy credential. `kubectl config use-context`, `talosctl config context`, and `nats context select` rewrite that pointer. Sibling issues mount the generated decoy so those writes succeed, and they leave the host file unmounted for writes. This change does not change mounts.

No new config key is added.

## One subject, one identity

`identities` and `require_distinct` live in `arkham_config::context`. `identities` is the constructor adapters call while they write grants. `from_label` rebuilds the same identity from a label that was already issued. `require_distinct` is the only check for two identities that cannot be told apart on one destination. `Grant::matches` stays the only host matcher. Adapters call `require_distinct` before they write a grant that shares a destination with another. Sibling issues stop treating the first scope in label order as the credential when more than one grant matches the destination. The grant whose decoy the guest presented supplies the upstream material.

A subject is one source path, one protocol, and one original name. The path is stored as the adapter passed it. `identities` does not canonicalize it. A repeated triple keeps the first record. `prod` and `Prod` both succeed and stay distinct, because the original spelling is part of the canonical bytes. An empty name fails. A label longer than 240 bytes fails. There is no suffix that shortens a long name.

The canonical bytes are the protocol tag, U+001F, the path, U+001F, and the name. The label is the tag, `--`, and the lowercase hex of those bytes. The env name is that label with ASCII letters uppercased and `-` replaced by `_`. It still has to pass `valid_env_name`. `secret()` is `fake_for` of that env with no pattern. It is the bearer, password, or token written into the guest file. `key_seed()` is the SHA-256 of the canonical bytes. It is the ed25519 seed for a NATS user nkey through `KeyPair::new_from_raw`, and for an SSH decoy key. `pair_stem()` is the argument to `load_or_generate_client_pair`. It is the tag, `-`, and the first 32 hex characters of `key_seed()`. Siblings call neither `KeyPair::new_user` nor `SshKey::generate` for these decoys. `SshKey::from_seed` belongs to #65.

For source `/home/ivan/.ssh/config`, protocol `Ssh`, and name `git`, the three strings are fixed:

- label `ssh--7373681f2f686f6d652f6976616e2f2e7373682f636f6e6669671f676974`
- env `SSH__7373681F2F686F6D652F6976616E2F2E7373682F636F6E6669671F676974`
- pair stem `ssh-13786934f8941a5f07bb7b5b084cc9e8`

`require_distinct` trims the host and stores the ASCII lowercase form. An empty host after trimming is `WireHostEmpty`. Brackets stay on the host. The port is the caller's port, with no default substituted. The group key is that host, that port, and the SHA-256 of the decoy bytes, including the hash of an empty slice. The same identity repeated is success. The same identity on two destinations is success. Two different identities on one key sort by source display, name, and tag, then return `AmbiguousContexts` with every name. The message omits the decoy bytes and the seed. Two different refs that share a label or a pair stem return `ContextCollision` naming both. With this encoding that shared value does not arise from real paths. The check still runs inside `identities`, so a caller cannot skip it.

## Kubernetes

#62 calls `identities` once per distinct user with `KubernetesUser`, and once per distinct cluster with `KubernetesCluster`. Contexts that share a user share that user identity. Contexts that share a cluster share that cluster's `pair_stem()` for the CA file. One user is one rule. The allow list is every server that user talks to. The same server and the same user are one grant. `current-context` is not an input.

The proxy reads the destination host and port through `Grant::matches`. It then reads the client certificate bytes when the user has a pair, and then the bearer bytes. `client_auth_policy` admits a certificate signed by the arkham CA. The decoy the guest presented chooses the grant. #62 stops using the first `Grant::endpoint` in `crates/arkham-proxy/src/transports/http/mod.rs` as the credential choice. The selected grant supplies `client_cert`, `client_key`, `root_cert`, and `guest_tls_mode`. `eligible_pairs` for that connection is that grant alone.

A server that needs both `guest_tls_mode = tls` and `guest_tls_mode = mtls` cannot be told apart during the handshake. #62 calls `require_distinct` with those two contexts, that host and port, and a decoy mark that is the mode. The error names both contexts. #62 writes no grant for that server.

In `/home/ivan/.kube/config`, contexts `prod` and `staging` both use user `ivan` and server `k8s.example` on port 6443. That is one `KubernetesUser` named `ivan`. A request that presents that user's `secret()` selects that grant.

When `prod` and `staging` both name user `ivan` and the token strings in the file differ, #62 calls `require_distinct` and writes no grant. The error names `prod` and `staging`.

`KUBECONFIG` is read only when the value contains no colon. A list warns and the adapter uses `~/.kube/config`. This design leaves the list unexpanded. The variable chooses a file. Context selection stays on the wire. A single path still overrides the default. Host `kubectl --context` is left unread.

## Talos

The Talos adapter calls `identities` once per context, with protocol `Talos`. One grant per context. Each context gets its own guest pair at `pair_stem()`. The proxy reads the endpoint host and port, then the client certificate on the handshake `transports/http/mod.rs` already performs. Selection happens before the upstream client certificate is chosen. `relay_guarded` pumps after that selection. There is no new buffer. The Talos `context` key is left unread.

In `/home/ivan/.talos/config`, contexts `prod` and `prod!` both dial host `talos.example` on port 50000. Those are two identities and two certificates. The certificate selects one.

When both contexts carry the same certificate bytes, `require_distinct` names `prod` and `prod!` at host `talos.example` port 50000.

`TALOSCONFIG` follows the same colon rule as `KUBECONFIG`. This design leaves that list unexpanded.

## NATS

One call per `context/<name>.json`, with protocol `Nats` and the name taken once. The source is the json path. The label does not end in `{name}-{name}`. Password and token are `secret()`. Nkey and creds use `key_seed()`. The proxy reads the url host and port, then CONNECT fields inside `Policy::swap`, still capped by `MAX_COMMAND` at 16 KiB. #64 collects every grant whose decoy fields match, including a match that is later in label order. No match forwards the line. `context.txt` is left unread. `relay_guarded` pumps bytes after the grant is chosen. There is no new buffer.

`Error::NatsSharedEndpoint` stays the dial and TLS clash. `AmbiguousContexts` is the separate case of two decoys that present the same bytes.

A cleartext `nats` upstream uses `Policy::Forward` and writes no real credential. Two cleartext contexts on one host and port cannot be told apart on the upstream leg. #64 calls `require_distinct` with an empty decoy mark for those contexts and writes neither grant. One cleartext context on that endpoint stays forward.

In `/home/eng/.config/nats`, contexts `demo` and `Demo` both use tls on host `nats.example` port 4222. The passwords differ because the identities differ. A CONNECT that carries one password selects that context.

When both contexts were given the same decoy CONNECT bytes, `require_distinct` names both.

`NATS_CONTEXT` and `XDG_CONFIG_HOME` are left unread. The directory stays `{host_home}/.config/nats`.

## SSH

One call per host block the existing adapter already grants. The name is `HostName` or `patterns[0]`. This change leaves `*`, `?`, `!`, `Include`, and `Match` unparsed. The decoy key is seeded from `key_seed()`. #65 adds `SshKey::from_seed`. The proxy reads the destination host and port, then the offered public key in `auth_publickey`. The username is forwarded. Nothing compares it with a grant field. Password auth stays rejected. SSH does not use `relay_guarded`. This design adds no buffer in front of SSH.

`RewriteCollector::twin` mounts `decoy_files` from the first entry only. #65 puts every host's decoy private key on that first entry. This change leaves `twin` as it is.

In `/home/ivan/.ssh/config`, blocks `git` and `git.example` both resolve to host `github.com` port 22. The label for `git` is the literal above. The offered public key selects the block.

When both blocks present the same decoy public key, `require_distinct` names `git` and `git.example` at host `github.com` port 22.

## Guest material and old files

Real credentials stay in the grant fragment. The guest file receives `secret()`, the certificate at `pair_stem()`, or the public half of the seeded key. The proxy terminates the guest session and opens its own upstream session. A destination with no matching grant splices.

Adopting the helper changes the label, the env, and the pem file name. Nothing copies the old pair onto the new name. The old pair was shared across contexts. `load_or_generate_client_pair` mints a new pair on the first adapt after the switch and leaves the old files in place. `write_state` prunes only names that start with `kube-`, `talos-`, `ssh-`, `git-`, or `nats-`. The old `{label}.client.crt` blobs do not start with those prefixes, so they remain until the sibling deletes them in the same adapt. NATS nkeys and SSH keys become stable on the first adapt that uses `key_seed()`. Each of those keys replaces the previous random key.

`registry = false` leaves `Registry::template` running. This helper accepts an env that contains a bundled needle. Siblings inherit that until it is fixed on its own.

## Outside this change

The following stay out of this change:

- Adapter edits
- Proxy edits
- `twin`
- Wildcard SSH
- `SshKey::from_seed`
- New config keys
- New buffers
- A Tokio test
- A new crate
