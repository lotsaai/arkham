# Tutorial: your first credential swap

This tutorial walks you through one full round trip with arkham. You will start a proxy, send a request carrying a decoy token, and prove two things: the upstream received the real value, and the client only ever saw the decoy. You will then repeat it over HTTPS so you exercise the CA trust step every real deployment needs.

Time needed: about ten minutes. You need a shell, `curl`, `python3`, and a arkham binary. If you do not have one yet, follow [the install steps in the README](../../README.md#install) first.

## What you will build

```text
  curl (holds the decoy) ---> arkham :8080 ---> upstream :8000 (receives the real value)
```

arkham sits between a client and an upstream. The client holds a fake but format-valid token. When the destination matches a rule's allow entry, arkham swaps the fake for the real value on the way out, and swaps it back on the way in.

## 1. Write the config

Create an empty directory and save this as `arkham.toml`:

```toml
[proxy]
listen = "127.0.0.1:8080"
ca_file = "ca.pem"

[rules.demo]
env = "DEMO_TOKEN"
value = "real-secret-value-xyz"
allow = ["http://127.0.0.1:8000"]
```

The rule says: the token seeded from `DEMO_TOKEN` may be swapped in only for `http://127.0.0.1:8000`. Anywhere else, the decoy travels as-is and the upstream rejects it. That is the whole idea.

## 2. Get the decoy

```sh
arkham fake DEMO_TOKEN
```

```
f92b2afa339693227aa209aac3eb48f9
```

A decoy is deterministic for its env name, so the same name always yields the same value. Keep this one handy; you will paste it into a request in a moment.

## 3. Start an upstream

Save this as `upstream.py`. It records the `Authorization` header it receives and echoes it back in the response body.

```python
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
  def do_GET(self):
    seen = self.headers.get("Authorization", "<none>")
    with open("seen.txt", "w") as f:
      f.write(seen)
    body = ("upstream saw: " + seen).encode()
    self.send_response(200)
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

  def log_message(self, *args):
    pass


HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
```

Start it in one terminal:

```sh
python3 upstream.py
```

## 4. Start the proxy

In a second terminal, from the directory holding `arkham.toml`:

```sh
arkham serve --config arkham.toml
```

arkham logs the listen address and the grant count:

```
serving, listen: 127.0.0.1:8080, grants: 1
```

## 5. Send the decoy

In a third terminal:

```sh
curl -x http://127.0.0.1:8080 http://127.0.0.1:8000/ \
  -H 'Authorization: Bearer f92b2afa339693227aa209aac3eb48f9'
```

The response body is what the client saw:

```
upstream saw: Bearer f92b2afa339693227aa209aac3eb48f9
```

Now check what the upstream actually received:

```sh
cat seen.txt
```

```
Bearer real-secret-value-xyz
```

The client sent the decoy. The upstream received the real value. The response carried the decoy back. Both sides of the wire saw only what they were meant to see.

## 6. Prove the grant is what gates the swap

Send the same request to a different port, one no allow entry covers:

```sh
python3 -m http.server 8001 &
curl -x http://127.0.0.1:8080 http://127.0.0.1:8001/ \
  -H 'Authorization: Bearer f92b2afa339693227aa209aac3eb48f9'
```

The proxy log records a splice, not a substitution, and the request carries the decoy untouched. A token exfiltrated this way is the decoy, useless outside the granted host.

## 7. Do it over HTTPS

Real secrets go to real hosts over TLS. To intercept a granted HTTPS connection, arkham terminates TLS with a certificate signed by its own CA, and the client must trust that CA.

Generate the CA and print the certificate:

```sh
arkham ca --config arkham.toml
```

One run writes three files beside the config's `ca_file`: `ca.pem` (certificate plus key, what arkham reads), `ca.crt` (certificate alone, what clients trust), and `ca.key` (key alone).

Add an HTTPS-capable upstream. Simplest check that needs no server certificate of its own: any public HTTPS host will do for observing the trust failure and success. First, try the swap against a granted HTTPS host without trusting the CA:

```toml
[rules.demo]
env = "DEMO_TOKEN"
value = "real-secret-value-xyz"
allow = ["http://127.0.0.1:8000", "https://example.com"]
```

Restart `arkham serve`, then:

```sh
curl -x http://127.0.0.1:8080 https://example.com/ \
  -H 'Authorization: Bearer f92b2afa339693227aa209aac3eb48f9'
```

curl reports a certificate verification failure: the client does not yet trust arkham's CA. Retry with the CA trusted for this one command:

```sh
curl --cacert ca.crt -x http://127.0.0.1:8080 https://example.com/ \
  -H 'Authorization: Bearer f92b2afa339693227aa209aac3eb48f9'
```

The request now completes. arkham terminated the TLS connection, substituted the header, and redacted any occurrence of the real value in the response back to the decoy.

## Where to go next

- [Secure your workspace](how-to/confine-a-workspace.md) to run a coding agent with decoys only.
- [Capture traffic transparently](how-to/capture-traffic-transparently.md) so clients need no proxy setting.
- [The configuration reference](reference/configuration.md) for every key.
- [How arkham works](explanation/how-it-works.md) when you want the machinery behind the swap.
