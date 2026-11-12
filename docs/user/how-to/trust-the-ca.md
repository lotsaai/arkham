# How to trust the arkham CA

This guide shows you how to make a client or container trust arkham's certificate authority, which is required for any granted HTTPS connection to be intercepted. You need `arkham ca` to have run at least once.

Without trust, arkham still captures and splices the connection, but TLS termination on a granted host fails the handshake. With trust, arkham terminates TLS with a per-domain leaf certificate signed by the CA, substitutes, and re-encrypts.

## 1. Generate the CA

```sh
arkham ca
```

prints the certificate PEM to stdout and writes three files beside the configured `ca_file` (default `<config-dir>/arkham/ca.pem`):

| File | Contents | Who gets it |
| --- | --- | --- |
| `ca.pem` | Certificate followed by private key | arkham itself |
| `ca.crt` | Certificate alone | Every client that must trust arkham |
| `ca.key` | Private key alone | Nobody. Keep it where `ca.pem` lives |

A client holding `ca.key` could mint its own leaf certificates and intercept its own traffic. Distribute `ca.crt` only.

## 2. Single curl invocation

```sh
curl --cacert ~/.config/arkham/ca.crt https://granted-host.example.com/
```

## 3. One toolchain

The common variables cover most clients without touching the system:

```sh
export NODE_EXTRA_CA_CERTS=/path/to/ca.crt    # Node
export REQUESTS_CA_BUNDLE=/path/to/ca.crt     # Python requests
export SSL_CERT_FILE=/path/to/ca.crt          # OpenSSL-based tools generally
export CURL_CA_BUNDLE=/path/to/ca.crt         # curl
export GIT_SSL_CAINFO=/path/to/ca.crt         # git
```

`SSL_CERT_FILE` replaces the default bundle, so a bundle that already chains to arkham's CA (next section) is the better value there.

## 4. A container's system store

Mount the certificate into the system CA location and refresh the store once:

```dockerfile
# Debian-style images
COPY ca.crt /usr/local/share/ca-certificates/arkham-ca.crt
RUN update-ca-certificates
```

For a running container, mount instead of bake:

```yaml
volumes:
  - ~/.config/arkham/ca.crt:/usr/local/share/ca-certificates/arkham-ca.crt:ro
```

and run `update-ca-certificates` from the entrypoint when it exists.

## 5. Rotate

Delete the CA files, run `arkham ca` again, redistribute `ca.crt`, and restart clients holding the old certificate. Leaf certificates are minted per domain from the CA and cached; an expired leaf rotates on next lookup, but a changed CA invalidates trust everywhere it was installed.
