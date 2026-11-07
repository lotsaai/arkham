# bwrap demo (transparent capture without docker)

The [docker demo](../README.md) also has a docker-free version. A network
namespace connects to the host over a veth, and arkham captures the
[bubblewrap] client with eBPF. The client shares the network namespace,
holds a fake token, and does not configure a proxy.

[bubblewrap]: https://github.com/containers/bubblewrap

| # | Client (under bwrap) | Grant | Passes when |
|---|----------------------|-------|-------------|
| 1 | HTTPS GET `api:8443` with the fake bearer | `https://api:8443` | response body is `token:<fake>`; api log saw the real bearer only |
| 2 | Cleartext line protocol to `10.99.0.20:9000` | `tcp://10.99.0.20:9000` | `AUTH <fake>` became `AUTH real` upstream, reply is `OK <fake>` |

The API server is the docker demo's `integration/api/server.ts`. The CA and
API leaf come from `integration/gen-certs.sh`. The fake is the deterministic
`arkham fake GH_TOKEN`. The host has a masquerade table for the veth, which
the script removes on exit.

## Run

```sh
mise run demo:bwrap
```

The task builds the release binary as you and escalates only the demo
script (netns, veth, host NAT) via sudo, with a confirmation prompt;
`--use-sudo` skips the prompt.

The script needs a cgroup v2 hierarchy. It creates
`/sys/fs/cgroup/arkham-bwrap`, starts arkham outside it, and moves the client
into it before the client runs. Capture installs no nft rules.

Requirements: sudo (for the netns, veth, and host NAT), `iproute2`, `nft`, `openssl`, `bun`, `curl`, `bwrap`.
Everything (netns, veth, host NAT table, temp certs, the eBPF cgroup) is cleaned up on exit.
