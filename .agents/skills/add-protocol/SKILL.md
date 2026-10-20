---
name: add-protocol
description: >
  Checklist for adding a credential-rewriting protocol to arkham. Use when
  adding a wire protocol or connection-string grant (Redis, Postgres, MySQL,
  MQTT, AMQP, and the like), capture for a new port, or an integration
  end-to-end scenario.
---

# Add a credential-rewriting protocol

Grant matching stays in `arkham-config`. Substitution stays in `arkham-proxy` (`transports/`). Capture backends hand the stream to `serve_transparent_stream`.

`PROTO` is the transport directory (`redis`). `VARIANT` is the `Scheme` variant you write out (`Redis`, `Rediss`); do not derive it by capitalizing `PROTO`. Redis, as one finished protocol, is [reference/redis.md](reference/redis.md).

## Checklist

1. **Transport.** Add `crates/arkham-proxy/src/transports/$PROTO/` and `pub(crate) mod` it from `crates/arkham-proxy/src/transports/mod.rs`. `engine` is the shared substitution machine, not a protocol. Add the field and build it in `ProxyState::new` (`crates/arkham-proxy/src/lib.rs`). Add an `Expect::$VARIANT` arm in `Expect::serve` (`crates/arkham-proxy/src/identity.rs`). Reuse `relay_guarded` and the existing streaming path. The only protocol-specific buffer is the per-command credential line, capped like Redis `MAX_COMMAND`. Do not add a session loop or a payload buffer.

2. **Scheme.** Add `VARIANT`. `Scheme::as_str` is an exhaustive match. `Scheme::all` is `strum::EnumIter`, so `arkham schemes` lists the variant without a second array. When a URL omits a port, add an arm in `EndpointScope`'s port match (`crates/arkham-config/src/grants/mod.rs`). `tcp` stays explicit.

3. **Grant.** Add the URL prefix in `RuleCfg::value_scheme` (`crates/arkham-config/src/config.rs`). Without that prefix the rule is never a connection string. `GrantCollector::connection_string` (`crates/arkham-config/src/grants/mod.rs`) then dispatches it to the parser in `crates/arkham-config/src/grants/$PROTO.rs`. A connection-string rule has no `allow` entries; the string is the grant. A missing secret fails startup (`IfMissing::Error`): an undeclared secret makes arkham exit at boot. Require the real value in `integration/gen-secrets.sh`, `integration/.env.example`, and a `${VAR:?}` in `integration/compose.yaml`.

4. **Decoy.** The decoy is format-valid. A raw TCP swap is equal-length only, so a `tcp://` grant whose shaped decoy has a different length uses the length-matched render from `decoy_for_rule`. A protocol that reframes may change length.

5. **`expect`.** Add the grant lookup in `expect` (`crates/arkham-proxy/src/identity.rs`). That order is the tie-break: one port matching more than one family is ambiguous until bytes arrive, the first arm wins, and an arm whose framing does not arrive closes instead of trying another. Protocols that cannot share a port use different ports. Add the `Expect` `PartialEq` arm in the same file. `Expect::serve` is not the only match. A scope arm compares by pointer; a unit arm compares by kind.

6. **Transparent host.** Capture has a destination address and a port, not a URL host, and some clients send no SNI. Mint the leaf and key the swap on the host of the scope `expect` already selected, not on the captured address.

7. **Mid-stream TLS.** A protocol that upgrades after a cleartext greeting keeps the same framing machines across the upgrade. Handle only that cleartext opening lockstep (the greeting, the client command, and the server's acceptance). Then terminate guest TLS, handshake upstream on the same sockets, and hand both sockets to `relay_guarded`. Do not read past the acceptance line: the next bytes are a handshake. Acceptance is whatever the protocol defines (an SMTP `220`, an LDAP StartTLS extended-response success). Implicit TLS stays a separate scheme, settles both legs before the machines run, and goes straight to `relay_guarded`. A session that never upgrades also goes to `relay_guarded` with swapping off. Never swap onto a cleartext upstream; the decoy passes through. A later protocol with the same upgrade folds into this step.

8. **Client certificates.** Support an upstream client certificate, or document in `integration/README.md` why the compose demo disables client auth. A CA file on the server can make it demand one.

9. **Registry.** A connection-string protocol does not get a `[providers.*]` host list. Add a provider only for an HTTP API with allow-list hosts.

10. **Capture.** nft, tun, and eBPF do not special-case a protocol port. The only special case is UDP/443 (QUIC). Leave this protocol's port out of those crates.

11. **Tests.** Unit tests sit next to the machine and the grant parser. In-process tests go in `crates/arkham-proxy/src/e2e/`, including a no-SNI case, as `redis_tls_without_sni_mints_for_the_grant_host` does. Property tests for a new protocol live in that protocol's `props.rs` (`#[cfg(test)]`), driven by the shared harness in `crates/arkham-proxy/src/transports/engine/harness.rs` (`block_on`, `run_split_parts`, and the empty `feed(&[])` EOF flush). Keep 256 cases: chunking invariance through `run_split`, no real secret in guest-bound output across any split, and reply cuts at any offset. HTTP, SMTP, and LDAP still live in `crates/arkham-proxy/src/transports/engine/fuzz_props.rs` until #56. Its LDAP examples are `prop_ldap_split_output_is_identical` (any cut, including one byte, matches one shot), `prop_ldap_guest_output_hides_the_real_password`, `prop_ldap_wide_id_starttls_and_password_prefix` (a fragmented StartTLS reply, a held password prefix, and wide message ids), and `prop_ldap_arbitrary_no_panic`. The NATS examples in `crates/arkham-proxy/src/transports/nats/props.rs` are `prop_nats_split_output_is_identical`, `prop_nats_guest_output_hides_the_real_password`, `prop_nats_info_cut_leaves_the_rest_unread`, `prop_nats_truncated_prefix_at_eof`, `prop_nats_oversize_connect_is_forwarded`, and `prop_nats_arbitrary_no_panic`. The compose scenario uses the official server image and a maintained client. `retry`'s first argument is the scheme; a scenario that covers none passes `""` and is not recorded. Gate the scenario on its env var so `integration/client/run.ts` still runs when that service is absent. `integration/bwrap/run.sh` does not run `run.ts`.

12. **Docs.** Add a row to the protocol table in `README.md` and the scenario list in `integration/README.md`. Document the rule in `docs/user/reference/configuration.md` and add a fake rule to `integration/arkham.toml`. The existing `rust` jobs already run `mise run test:ssh` on x86_64 and ARM. Do not add a job per protocol.

13. **Pull request.** The PR body says `Closes #N`, or `Refs #N` when the issue title starts with `Tracking:`.

## Done

From the repo root. The last arguments are the new schemes, one word each (`redis rediss` when both variants exist). `pipefail` is required: `| tee` would otherwise hide `test:ssh`'s status, and `&&` then stops the chain.

```bash
set -o pipefail
mise run test:rust \
  && mise run test:ssh 2>&1 | tee /tmp/arkham-test-ssh.log \
  && .agents/skills/add-protocol/scripts/covered.sh /tmp/arkham-test-ssh.log redis rediss
```

`mise run test:rust` runs the unit and property tests. `covered.sh` fails when `test:ssh` skipped (no docker daemon still exits 0), when the log contains `FAILED (exit`, when a backend that started has no `passed` line, or when `integration/out/results/covered.json` lacks a scheme.

Confirm the new protocol has an in-process test showing the credential before the upgrade is the decoy and the credential after the upgrade is the real secret, and a reader test showing the acceptance reply leaves the handshake bytes unread. SMTP examples: `smtp_auth_before_starttls_stays_the_decoy_and_swaps_after` and `acceptance_line_leaves_the_handshake_bytes`. LDAP examples: `ldap_cleartext_bind_forwards_the_decoy` and `ldap_starttls_then_bind_swaps_the_password`.
