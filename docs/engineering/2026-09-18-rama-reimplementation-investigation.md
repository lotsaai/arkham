# Can `arkham-proxy` be reimplemented on `rama`

This investigation records the repository state at the time it was written. The Linux TPROXY and TUN backends have since been removed.

Date: 2026-09-18

## Question

Whether `crates/arkham-proxy` can be rebuilt on `~/github/plabayo/rama` (`rama` 0.5.0), and what such a rewrite would actually delete.

Short answer: the transport around the substitution engine can move to `rama`. The substitution engine is the product and stays hand written. A full replacement would cost the byte-for-byte splice guarantee and the fail-closed latch, which are the two properties the credential swap rests on.

## Where the logic lives

Line census over `crates/arkham-proxy/src`, implementation lines only, excluding `#[cfg(test)]` blocks:

| File | Impl | Test |
| --- | --- | --- |
| `substitute/h1.rs` | 955 | 463 |
| `substitute/h2.rs` | 535 | 239 |
| `substitute/mod.rs` | 254 | 0 |
| `lib.rs` | 718 | 734 |
| `relay.rs` | 112 | 0 |
| `sniff.rs` | 67 | 0 |
| **Total** | **2641** | **1436** |

The three `substitute` files are 1744 lines, 66 percent of the implementation. `lib.rs` is the ingress, sniff, and TLS skeleton at 718 lines. `relay.rs` and `sniff.rs` together are 179.

So the replaceable half is the smaller half. That framing matters more than any individual API match below.

## What `rama` genuinely replaces

### Transparent and explicit ingress

`serve` (`crates/arkham-proxy/src/lib.rs:204`), `handle_conn` (`:216`), `handle_connect` (`:235`), `handle_forward` (`:598`), `read_head` (`:635`), and `parse_authority` (`:665`) are head parsing plus CONNECT plus absolute-form forwarding. `rama` covers this with `HttpServer::auto`, `UpgradeLayer` with `MethodMatcher::CONNECT`, and `EagerHttpProxyConnector`. See `examples/src/http_connect_proxy.rs` and the stack assembly in `examples/src/http_mitm_proxy_boring.rs:93-151`.

`IP_TRANSPARENT` capture and original-destination recovery map to `rama-net/src/socket/linux/tproxy.rs`, where `ConnectorTargetFromGetSocketnameLayer` reads the socket name into a `ConnectorTarget`. `examples/src/linux_tproxy_tcp.rs` walks the full setup, including a dual-stack listener. This is a direct match for the `tproxy` backend's `stream.local_addr()` use at `crates/arkham-tproxy/src/tproxy.rs:201`.

The upstream `SO_MARK` path maps to `SocketOptions::mark` (`rama-net/src/socket/opts.rs:908`) wired through `TcpConnector::with_connector` with a `TcpStreamConnector` built from `Arc<SocketOptions>` (`rama-tcp/src/client/connect.rs:79`, `:121`). That replaces `dial_one` (`crates/arkham-proxy/src/lib.rs:493`) and its `socket2` socket, while the DNS and total-budget logic in `dial_marked` (`:467`) stays.

What does not move: the TUN userspace stack, the eBPF programs and their map ABI, the nft and policy-route netlink code, and the UDP handling in each backend. `rama` supplies TPROXY ingress and nothing else here.

### ClientHello sniffing and protocol peek

`sniff_stream` (`crates/arkham-proxy/src/sniff.rs:24`) and `peek_mode` (`crates/arkham-proxy/src/lib.rs:529`) are hand rolled. `rama` has `PeekTlsClientHelloService` and `InputWithClientHello` (`rama-tls/src/server/peek_client_hello.rs:42`, `:281`), plus `TlsPeekRouter` and `HttpPeekRouter`. The policy decision on the peeked SNI has an existing shape at `rama-cli/src/cmd/serve/proxy/mod.rs:713-770`, where `TlsHelloMitmPolicyService` chooses inspect or passthrough from `MitmPolicy`.

That maps onto arkham's gate well. `intercept_candidate` and `https_eligible` (`crates/arkham-config/src/grants.rs:232`, `:242`) become a policy predicate over the SNI, and `MitmPolicy` already models allow, deny, wildcard, and leading-dot rules (`rama-http/src/inspect/mitm_policy.rs:152`, tests at `:272-375`).

This is a real win. It deletes a hand written ClientHello parser and its size and timeout edge cases.

### Certificate issuance

Leaf minting has two `rama` routes.

The rustls route is `RustlsServerConfigExt::modify_rustls_config` (`rama-tls-rustls/src/server/config.rs:49`), used to install a `rustls::server::ResolvesServerCert` resolver, exactly as `examples/src/tls_rustls_dynamic_certs.rs:117-120` does. There is also `dynamic_config` (`:57`) for an async per-ClientHello `rustls::ServerConfig`, backed by the `ServerConfig::Stored`/`ServerConfig::Async` split in `rama-tls-rustls/src/server/acceptor_data.rs:29`.

The boring route is `TlsMitmRelay` (`rama-tls-boring/src/proxy/mitm/mod.rs:106`) with a `DynamicCertIssuer` (`rama-tls/src/server/config.rs:245`) and a moka-backed issued-cert cache (`rama-tls-boring/src/server/cert_issuer.rs:23`, `:91`).

Either way, `crates/arkham-pki/src/ca.rs` keeps the CA. `generate_domain_cert` (`:304`) and the PEM load path (`:84`) are `rcgen` plus `rustls` types and port cleanly. The cache semantics do not port for free. arkham's `CertCache` (`:344`) is a `DashMap` with lazy expiry rotation on lookup (`get`, `:367`), pre-generated exact-host and wildcard leaves at `ProxyState::new` (`crates/arkham-proxy/src/lib.rs:62-77`), and a mint budget of `MINT_BURST 20` per `MINT_WINDOW_SECS 10` with `CACHE_CAPACITY 1000` (`crates/arkham-pki/src/ca.rs:16-24`). `rama`'s cache has no TTL by default and rejects expired leaves by reissuing (`rama-tls-boring/README.md:117`). The pre-generation and the rate limit would have to be re-implemented on top, so this slice moves partially.

### TLS termination relay

`mitm_tls_stream` (`crates/arkham-proxy/src/lib.rs:385`) plus `relay_guarded` (`crates/arkham-proxy/src/relay.rs:12`) is one guest TLS session paired with one upstream TLS session, pumped per direction. `rama`'s `HttpMitmRelay` implements `Service<BridgeIo<Ingress, Egress>>` (`rama-http-backend/src/proxy/mitm.rs:237`) and takes HTTP middleware via `with_http_middleware` (`:189`). The boring path is the paired one that keeps a single upstream connection across the CONNECT handshake.

## What cannot be replaced

### The substitution engine is the product

`SubMachine` (`crates/arkham-proxy/src/substitute/mod.rs:152`) is a synchronous, byte-slice, per-direction machine:

```rust
fn substitute<'b>(&mut self, chunk: &'b [u8]) -> (Cow<'b, [u8]>, Vec<Hit>);
```

On that interface sit four behaviours `rama` has no equivalent for.

Zero-copy pass-through. A chunk with no needle match returns `Cow::Borrowed`, so the bytes are never copied, let alone re-framed. Pinned by `unchanged_chunk_borrows_zero_copy` (`substitute/h1.rs:1249`).

Fail-closed. A scan-only path that sees a needle it cannot rewrite sets `must_close`, and the relay drops the connection rather than let the real value through (`substitute/h1.rs:99`, consumed at `relay.rs:91`). That latch only exists because the machine knows which framings it can rewrite.

HEAD semantics. `take_head_requests` and `suppress_next_bodies` (`substitute/mod.rs:154`, `:158`) carry the request side's HEAD count to the response side so a HEAD reply's headers are substituted without a body being invented. Also implemented in the H2 machine (`substitute/h2.rs:99-101`).

Protocol-aware framing states. `SecretsMachine` (`substitute/h1.rs:74`) runs a `State` machine of `Head`, `Fixed`, `Chunked`, `Scan`, `Drain`, `Opaque`, `CloseDelimited`, and `Raw` (`:26`), with bounds of 64 KiB per head block and 16 MiB per body (`:18`, `:20`). It rewrites `Content-Length` only on a size change, re-encodes chunked bodies, and degrades to scan-only on anything unframable. `H2Machine` (`substitute/h2.rs:85`) walks HPACK, decodes HEADERS and CONTINUATION blocks, substitutes, re-encodes, scans DATA with a per-stream held-back tail so a needle split across frames still matches, and falls to opaque scan-only on any framing violation.

Cross-chunk matching. `scan_with_tail` (`substitute/mod.rs:208`) and `find_crossing` (`:246`) carry an overlap window of longest-needle-minus-one between chunks, so a credential split across two TCP reads is still found exactly once.

### The verbatim guarantee breaks under typed middleware

The specific reason the H1 machine cannot simply become `rama` middleware is the pass-through contract. `HttpMitmRelay`'s middleware is bounded by `Layer<HttpClientService<Body>>` (`rama-http-backend/src/proxy/mitm.rs:241`), so a middleware receives a decoded `Request` or `Response` and returns one. That value is re-serialised by the HTTP codec on the way out.

arkham's contract is the opposite. Non-granted traffic and granted-but-secretless traffic must be byte-identical. The suite pins this in `mitm_terminates_both_ends_verbatim` (`crates/arkham-proxy/src/lib.rs:964`), `absolute_form_forwards_head_verbatim` (`:917`), `connect_splices_bytes_verbatim` (`:880`), `absolute_form_ungranted_chunked_splices_byte_identical` (`:1245`), and `tls_through_splice_leaves_fake_untouched` (`:1141`). A chunked body that rama re-frames is not byte-identical, even when no secret is present.

So middleware is not a superset of the machine. It is a different guarantee, and a strictly weaker one for this use.

### Where rama's own reference code disagrees

`examples/src/http_mitm_proxy_boring.rs:234-266` mutates decoded `WebSocketRelayMessage::Text` and maps `Binary` to an empty vector, which drops it. arkham's rule is forward unchanged and scan, never drop silently. Any port has to supply a passthrough fallback service rather than take the stock relay's default handling.

`rama-proxy` itself is not inbound MITM. Its crate docs (`rama-proxy/src/lib.rs:1-9`) describe an outbound proxy database used by connection pools. Wrong crate for this job.

## Correction to an intermediate conclusion

An earlier pass concluded that rustls has zero MITM support in `rama`. That was wrong, and the record should say so.

`rama-tls-rustls` does expose per-Connection certificate resolution through `modify_rustls_config` and `dynamic_config` (`rama-tls-rustls/src/server/config.rs:49`, `:57`), and it does expose `TlsAcceptorLayer` for termination. What it lacks is the paired ingress and egress TLS relay in one connection: `TlsMitmRelay` lives in `rama-tls-boring` only (`rama-cli/src/cmd/serve/proxy/mod.rs:115`), and the rustls example says so directly (`examples/src/http_mitm_proxy_rustls.rs:5-16`). On the rustls path the proxy terminates TLS and then dials per request.

That is the only remaining technical reason to pull in the boring backend. Certificate issuance alone does not require it.

## Options

Three forks, with the trade each carries.

TLS backend. Keep `rustls` plus `aws_lc_rs` and stay off the boring C dependency, at the cost of writing the ingress-to-egress pairing by hand from `TlsAcceptorLayer`, `TlsConnector`, and `BridgeIo`. Or take boring and get `TlsMitmRelay`. Or keep the current `tokio-rustls` handling and skip this slice entirely.

Scope. Ingress, sniff, and TLS only, leaving the relay and machines untouched. Or ingress and sniff only, which touches no dependency and no trust model. Or stop, and keep the hand written core.

Machine port. Port the H1 HTTP framing states to middleware and accept the loss of the verbatim guarantee, which no arkham test currently allows. Or keep the machines and treat `rama` as ingress only. The second is the only version that preserves the existing test suite without weakening it.

## Method and evidence

All repository paths and symbols in this document were read in this session: `crates/arkham-proxy`, `crates/arkham-pki`, `crates/arkham-config/src/grants.rs`, `crates/arkham-tproxy/src/tproxy.rs`, `crates/arkham-tun/src/tun.rs`, and `crates/arkham-ebpf/src/tcp.rs` on the arkham side; `rama-net`, `rama-tcp`, `rama-tls`, `rama-tls-rustls`, `rama-tls-boring`, `rama-http`, `rama-http-backend`, `rama-proxy`, `rama-cli`, and `examples/src` on the rama side.

Both repositories are indexed in the codebase memory graph with clean coverage for the arkham-side files cited (`index_status` ready, `check_index_coverage` reporting `no_recorded_issue` for all thirteen). The rama index reports 43 partial-parse files and 4 unusable ones, none of them cited here.

Line counts come from `wc -l` plus the first `#[cfg(test)]` line in each file. The test split counts the `mod tests` block from its attribute line, so a file with tests above the attribute would be miscounted; none of these six have any.

No code was changed for this investigation. No build or test run was needed, since nothing was modified.
