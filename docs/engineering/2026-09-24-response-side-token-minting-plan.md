# Response-side OAuth token minting plan

Issue: #20 (tracking: OAuth tokens minted at runtime). Scope decided here: full OIDC/OAuth2 flow coverage through response-side decoy minting, machine legs and browser legs alike, because agents legitimately drive headless browsers whose traffic traverses the proxy. Proxy-performed refresh is rejected: arkham translates tokens on the wire and never acts as a protocol participant. It does not initiate refreshes, hold expiry timers, or schedule token acquisition. Whatever the agent does, the proxy observes and translates; nothing more.

## Problem

A granted token host's `POST /oauth/token` response carries a freshly issued `access_token` (and often a rotated `refresh_token`) the proxy has never seen. Three consequences today.

1. The agent receives and holds a live real access token, which is the outcome arkham exists to prevent.
2. Requests made with that token are not decoys, so nothing substitutes. If a rule also issued a decoy for the same env name, the real token shadows it.
3. With rotating refresh tokens, the fnox copy goes stale after the first refresh.

## Current state, from source

- Substitution pairs are built once per machine from static config: `Pair { needle, replacement, label }` in `crates/arkham-proxy/src/substitute/mod.rs:120-151`. Request direction swaps decoy to real, response direction swaps real to decoy. No runtime-added pair exists anywhere.
- `ProxyState` is write-once: plain `Arc<ResolvedConfig>`, documented no-reload, no lock (`crates/arkham-proxy/src/lib.rs:51-60`). The one interior-mutable field is `MintBucket` (`policy.rs:189-218`, `Mutex<VecDeque<Instant>>`), the burst guard for cert issuance.
- Response fail-closed latch exists: a response-direction hit in a scan-only path sets `must_close` (`h1.rs:159-165`), the relay drops the connection before writing to the guest (`relay.rs:79-92`).
- Fixed-length bodies forbid length drift entirely: the head is emitted with its original `Content-Length`, so a swap that changes length latches `must_close` (`h1.rs:238-255`). Minting must rewrite the head before emission, which no code path does today.
- Compressed bodies are scan-only, never rewritten (`h1.rs:949-959`, `enter_framing_state`).
- Registry schema is `deny_unknown_fields` with exactly `env`, `hosts`, `pattern`, `contains`, `replace` on `ProviderEntry` (`registry.rs:60-78`); `NameEntry` has `hosts`, `pattern`, `replace` (`registry.rs:81-93`). No field describes auth or token endpoints. `UriGrant` is authority-only, rejects paths (`grants.rs:90-155`).
- Decoy generator `fake_for(env, pattern)` (`config.rs:280-284`) seeds on the env name alone: deterministic across restarts, one decoy per env. A per-token mint needs a per-occurrence seed. `render_template`/`fill_verb` (`config.rs:347-406`) take any seed and are reusable as-is.
- No runtime-written state on disk exists today besides the CA (startup-time, 0600).

## Design basis: the OAuth flow, per OpenAPI and RFC 6749

The unit of configuration is the OAuth flow, not a list of response field names. OpenAPI's `components.securitySchemes` with `type: oauth2` names the flow's endpoints per flow type: `tokenUrl` on `clientCredentials` and every non-implicit flow, optional `refreshUrl` on `authorizationCode`. RFC 6749 §5.1 fixes the token response field names: `access_token` (required), `token_type` (required), `expires_in` (recommended), `refresh_token` (optional), `scope` (optional). Field names are spec-fixed; the flow is what changes per vendor.

Consequences for the design:

- The registry declares the flow. Token endpoint authorities come from the vendor's own spec, unioned into the rule's `allow` exactly like registry hosts are today, so the existing `UriGrant` authority matching grants the mint endpoint with no new machinery.
- Field names need no per-host config for standard vendors. They default to the RFC 6749 set. An override survives only for deviant envelopes (e.g. wrapped `{"data": {"access_token": ...}}` bodies).
- The flow tells the proxy what to expect. `client_credentials` responses carry `access_token` only. A flow that can refresh and declares `rotates_refresh = true` tells the proxy to mint both fields and to expect a new real value on each refresh, so rotation becomes a consequence of the declared flow rather than separate configuration.

## Design decisions

**Registry entries carry an `oauth2` flow block.**

```toml
[providers.example]
env = ["EXAMPLE_TOKEN"]
hosts = ["https://api.example.com"]
pattern = "..."

[providers.example.oauth2]
flow = "client_credentials"                      # client_credentials | authorization_code | refresh
token_url = "https://auth.example.com/oauth/token"
authorize_url = "https://auth.example.com/authorize"  # authorization_code only
refresh_url = "https://auth.example.com/refresh"  # optional
rotates_refresh = false                          # optional, default false
token_fields = ["access_token"]                   # optional, default = RFC 6749 set
```

`token_url`, `authorize_url`, and `refresh_url` are authorities, parsed as `UriGrant`, unioned into the rule's `allow` by the existing host-union path in `arkham_fnox::resolve` (`lib.rs:283-295`). `token_fields` defaults to `["access_token", "token_type", "expires_in", "refresh_token"]` filtered by flow shape: `client_credentials` defaults to the no-`refresh_token` set unless `rotates_refresh` is set. This answers issue open question 1 with the spec answer instead of per-host guesswork.

**Minted pairs live in process memory.** A `MintStore` (`Mutex<BTreeMap<String, MintedPair>>` keyed on real value) on `ProxyState` beside `MintBucket`, threaded into `MachineParams`. The store outlives connections because agents reuse tokens across connections; per-connection state dies with the relay task. It does not survive a restart: a restarted proxy orphans decoys the agent still holds, the next request sends an unknown decoy, nothing substitutes, the upstream rejects it, the agent re-authenticates. That ceiling is accepted and documented, marked in code with a `ponytail:` comment naming disk persistence as the upgrade path. Disk persistence is rejected for now because it writes real tokens at rest beside the CA, a new secret-at-rest surface with permissions and expiry-cleanup problems. This answers open questions 2 and 3.

**Decoy shape comes from the registry pattern, seed comes from the real token.** New `fake_for_seed(env, pattern, seed)` in arkham-config: `render_template`/`fill_verb` with `seed = hex(Sha256(real_value))`. Same shape as every other decoy, stable per token value, so rotation works naturally: each rotated refresh token mints its own decoy keyed on its own real value, and the old pair stays valid until the old real token expires upstream. `expires_in` from the flow response is stored on `MintedPair` for lifetime logging.

**Minting runs on complete response bodies, not on chunks.** The response machine, when the connection's host is a granted token endpoint from a flow block and the body parses as a flat JSON object, scans the flow's field names, mints decoys, rewrites the JSON, rewrites `Content-Length` before the head is emitted (chunked stays chunked, sizes re-encoded by the existing chunk re-framing). Body buffering is bounded by the existing limits; an oversize or streaming-framed body with a token-field hit fails closed instead.

**Trigger is grant + flow, not shape alone.** Minting activates only on an authority the flow block granted. A JSON body on an ungranted host that happens to contain `access_token` is untouched. This keeps the issue's non-goal intact: no rewriting by shape on arbitrary hosts. The residual risk on a granted host, minting a decoy for a value that is not really a token, fails harmless: the minted pair simply never matches anything real.

**Fail closed, reusing the existing latch.** Compressed, non-JSON, unparseable, or unknown-framing token responses with a value in a named field set `must_close` on the response machine; the guest never receives the real token. No partial rewrite ever. This answers open question 5.

**Request-side swap consults the mint store first.** The request machine adds minted pairs (decoy needle, real replacement) on every connection to any granted host, so a decoy minted on connection one substitutes on connection two. Scanning stays the existing cross-chunk-safe byte engine.

**H2 gets parity.** `H2Machine` DATA payload minting with frame length rewritten, same store, same fail-closed. Code mintage in H2 works through the existing HPACK header rewriting (`h2.rs:450-471`): `Location` is an ordinary header value, so the redirect leg needs no new H2 capability. Minting in bodies split across DATA frames uses the existing per-stream overlap window.

**Scope (open question 4) is full flow coverage, not partial.** The browser leg is in scope because agents legitimately drive headless browsers: Playwright, Puppeteer, CDP-driven Chrome. Their traffic traverses the proxy like any other guest, so the authorize leg's responses are wire-visible to arkham. The interactive human case remains outside the threat model (a human logging in on their own machine is not an agent holding a credential), but the headless case makes the authorize leg a real capture surface. Both legs reduce to the same mechanism, response-side minting, because a headless browser is just another guest connection. The proxy stays a byte translator, never a protocol actor: it does not initiate refreshes, hold expiry timers, or schedule token acquisition.

**Authorization codes mint like tokens.** The authorize endpoint answers with an authorization `code` in a `Location` header (302 redirect) or in a response body (form_post response mode). A `code` is a short-lived single-use credential and an agent-driven browser holds it just as it would a token, so it gets the same treatment: mint a decoy for the code value in the redirect `Location` (or body), record the pair, and swap the decoy back to the real code when the agent posts it to `token_url`. Machines already rewrite response headers (`h1.rs:989-1060`, `h2.rs:450-471`) and `Location` is an ordinary header, so the code leg needs no new rewrite capability, only a new mintage trigger on the flow's authorize surface. This closes the loop: every credential the flow hands the guest, access token, refresh token, and authorization code, reaches the guest only as a decoy. The `code`'s single-use semantics mean the minted pair is consumed on first swap; the store entry is simply never matched again, no expiry machinery needed.

**Discovery documents are a curation-time import, never a runtime fetch.** OIDC discovery (`.well-known/openid-configuration`) is the primary machine source, ahead of OpenAPI: its `token_endpoint` and `grant_types_supported` are standardized where OpenAPI `securitySchemes` are frequently missing or stale. A one-off generator subcommand, `arkham registry from-oidc <issuer-base-url>` (and `from-openapi <url-or-file>` for spec-only vendors), fetches or reads once, maps the document onto the `oauth2` block, and writes a `rules.d/*.toml` fragment. A human reviews and places the fragment; the registry stays the single runtime source. No fetch ever happens on `serve`, so a vendor-controlled document can never become a grant authority at runtime and a moved discovery document is a curation inconvenience, not a startup failure. This answers the remaining half of open question 1: where `token_url` values come from.

**Open question 6 (#19 interaction) stays open.** Vendors that both issue tokens and sign requests need the mint path and the re-sign path to agree on held credentials. Recorded as a dependency, nothing designed here.

## Phases

Four stacked PRs, in order. Each lands green before the next starts.

### PR1: declare OAuth flows in the registry

- `ProviderEntry`/`NameEntry` gain an optional `oauth2: Option<OAuthFlow>` sub-table (`#[serde(default)]`): `flow` (`client_credentials` | `authorization_code` | `refresh`), `token_url`, optional `authorize_url` (required for `authorization_code`), optional `refresh_url`, optional `rotates_refresh`, optional `token_fields`. Merged in `apply_provider`/`apply_name` (`registry.rs:144-203`): authorities union, scalars overwritten, `replace = true` clears the block. Carried out via `KnownHosts` and `Registry::lookup`.
- `RuleCfg` gains the same optional `oauth2` block (`config.rs:100-121`) as the per-rule override for hosts not in the registry; `arkham_fnox::resolve` unions `token_url`, `authorize_url`, and `refresh_url` into `allow` and passes the flow to `Grant`.
- Validation in `AppConfig::validate`: `flow` is a known value, `token_url` parses as authority-only `UriGrant`, no empty or duplicate `token_fields`.
- Bundled registry entries gain `oauth2` blocks for known token issuers, `token_url` values taken from the vendors' own OIDC discovery documents during curation.
- Docs: `docs/user/reference/registry.md` field table.
- Tests (arkham-config): flow block parses, default field set derives from flow shape, union across layers, `replace` clears, rule-level override, validation failures, authorities unioned into `allow`.

### PR1b: `arkham registry from-oidc` and `from-openapi` generator subcommands

- New `registry from-oidc <issuer-base-url>` and `registry from-openapi <url-or-file>` subcommands in the root binary (`src/main.rs`, clap types in `arkham-config/cli.rs`).
- `from-oidc` fetches `<issuer-base-url>/.well-known/openid-configuration` once (or reads a local file), maps `token_endpoint`, `authorization_endpoint`, `refresh_endpoint` (draft), `grant_types_supported` onto the `oauth2` block, and prints a complete `[providers.<slug>.oauth2]` TOML fragment to stdout for review and placement in `rules.d`.
- `from-openapi` parses `components.securitySchemes` for `type: oauth2` and `openIdConnect` entries; for `openIdConnect` it follows the `openIdConnectUrl` to the discovery document and reuses the OIDC mapping.
- Both refuse to write into the bundled registry and never touch runtime config; output is stdout only. Unknown fields in the discovery document are ignored, missing `token_endpoint` is an error naming the field.
- Tests: discovery JSON fixture to TOML fragment mapping, openapi fixture mapping, missing-`token_endpoint` error, `grant_types_supported` to `flow` inference.

### PR2: mint decoys from token responses

- New `crates/arkham-proxy/src/mint.rs`: `MintedPair { real: SecretString, decoy: String, label: String, fields: Vec<String>, expires_in: Option<u64> }` and `MintStore`.
- `ProxyState.mint_store`, threaded into `MachineParams` at all six machine construction sites (`lib.rs:203-277,458-519`).
- Response-side minting pass in the H1 machine (complete body, flat JSON, flow field names, head rewrite before emission). Code mintage on `authorize_url` responses: `Location` header and body (form_post response mode). H2 parity in the DATA path.
- Request-side store consultation before `eligible_pairs`.
- Fail-closed on compressed, non-JSON, unparseable, unknown-framing token bodies.
- `fake_for_seed` in arkham-config.
- Tests (arkham-proxy, `MitmFixture` pattern): mint and length rewrite, cross-connection swap, rotation with `rotates_refresh`, fail-closed compressed, fail-closed non-JSON, flow host not granted for API traffic untouched, ungranted host with token-shaped JSON untouched, code minting on redirect `Location`, code decoy swapped at token exchange, H2 parity.

### PR3: document the minting path

- Registry reference: `oauth2` block semantics, layering, `replace`, default field derivation.
- How-to: enable minting on a custom OAuth host, rule example with a flow block, the `arkham registry from-oidc` / `from-openapi` curation commands, expected log lines, fail-closed behavior.
- Security model: process-lifetime decoys, restart orphaning forces re-auth, store is memory-only, headless-browser authorization-code leg covered (codes mint as decoys), the proxy translates and never participates in the protocol, trigger is grant + flow never shape alone.
- `how-it-works` explanation gains the minting step in the per-connection flow.
- README registry section and CHANGELOG.

## Verification

Per repo conventions, no raw cargo.

- `mise run format` green on every PR.
- `mise run test` green on every PR; the new unit tests above ride the existing per-file `#[cfg(test)]` style, `snake_case` behavior-descriptive names.
- PR2 additionally: run the closest end-to-end proof against the live eBPF backend with `mise run test:ebpf`, and one manual scenario: stub token endpoint returns a real token, client holds a decoy, next request substitutes it back to real upstream. If the live backend is not available, the `MitmFixture` suite is the evidence and the limitation is stated.

## Risks

- JSON scan false positives: bounded to flow-granted token endpoints; a wrong match mints a decoy for a value that never matches anything real, harmless failure direction.
- Decoy collision with an existing grant fake: SHA256 seed over the real value, astronomically unlikely, unit-tested.
- Store growth over process lifetime: bounded by refresh volume, acceptable for a session-scoped proxy.
- Restart orphaning: accepted ceiling, documented in the security model.
- Vendor spec drift (token endpoint moved, envelope wrapped): registry is overridable per entry and per rule; a wrong `token_url` simply mints nothing, fail direction is no-coverage not leak.
- #19 interaction: open dependency, no design here.

## Known gap (separate issue)

The registry scout found that `docs/user/reference/registry.md` and `crates/arkham-compose/src/stack.rs` claim a project-tier `<workspace-root>/.config/arkham/rules.d/` override, but `Registry::load` (`registry.rs:102-119`) wires only one override dir. Not this plan's work; should be filed separately.