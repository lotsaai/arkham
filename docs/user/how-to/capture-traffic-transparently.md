# How to capture traffic transparently

This guide shows you how to capture a workload's connections without configuring a proxy in the workload. You need Linux, kernel 5.15 or newer, `CAP_BPF`, `CAP_NET_ADMIN`, and a cgroup v2 directory for the workload.

Explicit-proxy mode (point `HTTPS_PROXY` at arkham) needs none of this. Transparent capture has exclusions, including unconnected UDP and traffic outside the selected cgroup.

## 1. Start arkham

Create a cgroup for the workload and start arkham outside it:

```sh
sudo mkdir -p /sys/fs/cgroup/arkham
sudo arkham serve --proxy-backend ebpf --ebpf-cgroup /sys/fs/cgroup/arkham --config arkham.toml
```

arkham attaches eBPF programs to the selected cgroup without changing netfilter or routing tables. Move the workload into that cgroup. arkham normally stays outside it so its upstream connections are not redirected.

`--ebpf-cgroup enclosing` attaches to the parent of arkham's own cgroup. This supports runtimes that place arkham and the workload under one parent cgroup. A PID check excludes arkham's own sockets.

```sh
echo $$ | sudo tee /sys/fs/cgroup/arkham/cgroup.procs
```

`ARKHAM_PROXY_BACKEND`, plus `ARKHAM_EBPF_CGROUP` for the cgroup path, are the environment equivalents.

Destinations the loader's network namespace cannot reach must not be captured. A redirected connection would otherwise complete its local handshake and then hang until the upstream dial budget runs out. The loader bypasses its own non-loopback IPv4 addresses. `--ebpf-bypass` (`ARKHAM_EBPF_BYPASS`, repeat or comma-separate) adds IPv4 CIDRs. Bypassed connections use their normal routes instead of transiting the proxy.

Podman networks need a runtime channel: they are created inside the agent long after arkham starts, so no startup flag can name them. The generated stack mounts a shared bypass file into both services (`ARKHAM_EBPF_BYPASS_FILE`, or `--ebpf-bypass-file` by hand): the agent entrypoint rewrites it from `podman network inspect`, and arkham reloads it live within seconds, no restart. One CIDR per line, `#` comments allowed.

## 2. Grant raw TCP by destination address

A captured TLS connection is identified by SNI, so HTTPS grants work as usual:

```toml
allow = ["https://api.anthropic.com"]
```

A raw TCP connection has no SNI. The destination address is the only identity, so a `tcp://` grant must name the literal address the workload dials:

```toml
allow = ["tcp://10.202.0.20:9000"]
```

A `tcp://` entry requires an explicit port. Plain HTTP capture identifies the connection by its `Host` header, so `http://api.internal:8000` grants cleartext HTTP with no address guessing.

## 3. Know what passes through

Only connected UDP is captured. These datagrams are relayed unchanged, without substitution. Unconnected `sendto` traffic, including typical DNS, is not captured.

Connections with no matching grant are spliced byte for byte. The client sees the real upstream certificate and the decoy travels untouched.

## 4. Tear down

Stop arkham with Ctrl-C. Its eBPF programs and maps belong to the process and detach on exit. Capture does not write netfilter rules or routes.

## Check it works

The runnable proof is the integration demo in the repository:

```sh
git clone https://github.com/casualjim/arkham
cd arkham
mise run demo
```

It runs the container image, a client sharing arkham's netns, and an upstream on an RFC1918 subnet, and it asserts four substitution scenarios and one splice scenario. See [integration/README.md](../../../integration/README.md) for the scenario table.

The same scenarios run without docker over the eBPF backend:

```sh
mise run demo:bwrap
```
