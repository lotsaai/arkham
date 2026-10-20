# Allow entry reference

An allow entry names the one authority a rule's real value may travel to. Grammar and semantics, as `EndpointScope` parses them in `crates/arkham-config/src/grants/mod.rs`.

## Form

```text
scheme://host[:port]
```

- **Schemes**: `http`, `https`, `tcp`, and `ssh`.
- **Default ports**: 80 for `http`, 443 for `https`, and 22 for `ssh`. A `tcp` entry requires an explicit port.
- **Hosts**: an exact name, a `*.`-prefixed suffix, or `*`.
- The entry is authority only. A path, a query, or userinfo is rejected.
- An IPv6 address goes in brackets and matches the bare form.
- Matching is ASCII case-insensitive.

```toml
allow = [
  "https://api.github.com",
  "https://*.githubusercontent.com",
  "http://127.0.0.1:8000",
  "tcp://10.0.0.8:5432",
  "ssh://bastion.example",
]
```

## Host forms

| Form | Matches |
| --- | --- |
| `api.example.com` | That host only. |
| `*.example.com` | Subdomains of `example.com` only, never the apex. |
| `*` | Any host. arkham warns at startup: the secret is at risk of exfiltration. |

## How entries gate interception

Two checks run at different layers:

- The pre-TLS interception check looks at host and port, ignoring scheme, and decides MITM versus splice.
- Request matching then needs scheme, port, and host to agree for the substitution to happen.

Consequences worth knowing:

- Only an `https://` entry makes a host TLS-eligible. A `tcp://host:443` entry alone captures the connection but never terminates its TLS.
- arkham matches the request authority, not the path. A grant to `https://api.example.com` also permits `https://api.example.com/admin`.
- Under transparent capture, a raw TCP connection has no SNI: the destination address is the identity, so a `tcp://` entry must name the literal dialled address.
