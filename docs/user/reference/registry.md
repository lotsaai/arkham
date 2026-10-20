# Registry reference

The bundled known-host registry: environment names, API hosts, and token shapes for the services arkham knows out of the box. The table lives in [`rules/registry.toml`](https://raw.githubusercontent.com/casualjim/arkham/main/rules/registry.toml) in the repository; this page documents the format, which is the same for the bundled table and for overrides.

## Tables

### `[providers.<name>]`

One service entry.

```toml
[providers.github]
env      = ["GITHUB_TOKEN"]
hosts    = ["https://api.github.com", "https://ghe.corp.example"]
pattern  = "ghp_ghe_{hex:32}"
contains = ["gh_"]
replace  = false
```

| Field | Meaning |
| --- | --- |
| `env` | Env var names this provider owns. |
| `hosts` | `scheme://host[:port]` allow entries granted to every listed name. Stable API endpoints only; a per-tenant endpoint uses the host family its docs state (`https://*.example.com`). |
| `pattern` | Decoy shape for these names. Keeps the prefix a platform documents; where no format is documented, the shape approximates that platform's tokens. |
| `contains` | Substrings matched against lowercased env names. Selects a decoy shape only, never hosts. |
| `replace` | `true` discards what earlier layers declared for these names, then applies this entry's fields. |
| `send` | Where the value travels: one placement, or a list. See below. |
| `signing` | Set when every claimed name is a signing secret. See below. |

### `[providers.<name>.oauth2]`

Declares that this provider's token issuer runs a known OAuth2 flow. When a rule for one of the provider's names is in effect, the proxy watches the flow's token endpoint, mints a fresh decoy for every `access_token` (and `refresh_token`) the issuer returns, and swaps the decoy back to the real value on later requests. The agent never holds a real freshly issued token.

```toml
[providers.example]
env = ["EXAMPLE_TOKEN"]
hosts = ["https://api.example.com"]

[providers.example.oauth2]
flow = "client_credentials"                      # client_credentials | authorization_code | refresh
token_url = "https://auth.example.com/oauth/token"
authorize_url = "https://auth.example.com/authorize"  # authorization_code only
refresh_url = "https://auth.example.com/refresh"    # optional
rotates_refresh = false                            # optional, default false
token_fields = []
```

| Field | Meaning |
| --- | --- |
| `flow` | Which flow the issuer runs. Decides the expected response fields: `authorization_code` (and any flow with `rotates_refresh = true`) also mints `refresh_token`. |
| `token_url` | Token endpoint. Its authority is granted like `hosts`, so the endpoint is MITM'd. |
| `authorize_url` | Authorize endpoint (`authorization_code` only; required there). Its authority is granted like `hosts`. |
| `refresh_url` | Refresh endpoint when it differs from `token_url`. |
| `rotates_refresh` | `true` when the issuer issues a new `refresh_token` on every refresh (RFC 6749 §6). Each rotated value mints its own decoy. |
| `token_fields` | Top-level JSON field names to mint. An empty list uses the flow default. |

The flow block overrides across layers like the other fields: `replace = true` discards an earlier layer's flow, and a later file's flow wins. A rule's own `oauth2` block (in `arkham.toml`) overrides the registry's.

### `send`

Where the claimed values travel on a request. One inline table, or a list when the entry covers more than one header, query parameter, or JSON field. Omit it when the location is not known. Each placement names exactly one of `header`, `query`, or `json`. `claim` is set only beside `header`, when that header carries a token and the value is a claim inside it rather than the raw bytes.

```toml
send = { header = "X-MBX-APIKEY" }
send = [{ header = "OK-ACCESS-KEY" }, { header = "OK-ACCESS-PASSPHRASE" }]
send = { header = "Authorization", claim = "sub" }
send = { query = "AccessKeyId" }
send = { json = "api_key" }
```

An entry that sets `send` must grant at least one host. Substitution is still by value once a host matches; `send` records the placement so a new vendor is a registry edit.

### `signing`

Set when every claimed name is a signing secret: an algorithm input that is not itself sent. `scheme` is one name or a list of names. Exactly one of `header`, `query`, or `json` names where the signature, not the secret, is placed. Scheme names are open strings, so a vendor whose scheme is new to the table needs no code change.

```toml
signing = { scheme = "hmac-sha256", header = "X-BAPI-SIGN" }
signing = { scheme = "hmac-sha256", query = "signature" }
signing = { scheme = ["es256", "ed25519"], header = "Authorization" }
```

A signing secret grants no hosts and no `send`. The decoy shape still comes from `pattern`, or `{hex:32}` when `pattern` is omitted. The field records the scheme; it does not sign requests.

Both fields are optional. A file written before they existed still loads. On `[names.<ENV>]` they mean the same thing for that one name.

### `[names.<ENV>]`

Hosts and pattern for a single env var, without inventing a provider. Useful for a one-off override:

```toml
[names.GH_ENTERPRISE_TOKEN]
hosts = ["https://ghe.corp.example"]
```

## Override locations

Two override directories, both loaded in filename order; project entries override global ones, which override the bundled table:

- Global: `<config-dir>/arkham/rules.d/*.toml`
- Project: `<workspace-root>/.config/arkham/rules.d/*.toml`

## Resolution rules

The pattern for a name resolves: rule `pattern`, then `[names.<ENV>]`, then the claiming `[providers.*]` entry, then `contains`, then `{hex:32}`. Across files, a later load's pattern wins regardless of tier. `contains` is the exception: earliest-loaded file wins, and `replace = true` is the way a later file takes a provider's needles back.

Hosts union across layers unless `replace = true` discards the earlier layers' hosts for those names.

`send` and `signing` overlay like `oauth2`: a later file wins when it sets them, and `replace = true` clears both. After the layers merge, a signing secret that still grants hosts or declares `send` is a load error, and so is `send` on a name that grants no host.

`arkham fake <ENV>` uses the same table, so overrides preview without running a proxy. See [how to extend the registry](../how-to/extend-the-registry.md) for the workflow.
