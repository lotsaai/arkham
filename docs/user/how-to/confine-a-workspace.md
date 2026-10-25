# How to secure your workspace

This guide shows you how to run a coding agent inside a container that holds only decoy credentials, with arkham as its only egress path. Your agent works as before while arkham protects your secrets. You need arkham installed, docker with compose, and a workspace directory with secrets declared to fnox.

The flow has three parts: see which rules derive from the secrets your workspace can already reach, describe the container layout in config, then let `arkham init` generate the compose project and `arkham up` drive it.

## 1. See what derives from fnox

Rules derive at serve time: every name fnox declares that the bundled registry knows becomes a rule, allowed hosts and decoy shape included. From your workspace root:

```sh
arkham rules
```

This prints the `[rules.<label>]` blocks the proxy will substitute, with comments at the end for names the registry knows but states no hosts for and fnox declarations no registry entry covers. The report is a preview, not a file to keep: nothing here needs writing.

State a block in your workspace's `.config/arkham/config.toml` only to override derivation for that name:

```toml
[rules.github_token]
env = "GITHUB_TOKEN"
if_missing = "warn"
```

A rule with no `value` resolves its real value from fnox at serve time. See [how to get values from fnox](get-values-from-fnox.md) if a name is missing.

## 2. Describe the container layout

`[workspace]` in the same config file controls the generated stack. Most workspaces only name extra mounts. Container home defaults to `/home/eng`, the shell to `sh`.

```toml
[workspace]
include = ["~/.config/mise:ro", "../sibling-project"]
```

| Key | Purpose |
| --- | --- |
| `home` | `$HOME` inside the agent container. Defaults to `/home/eng`. Host paths under your home directory translate into this prefix; other paths mount at their own location. |
| `shell` | Shell `arkham agent` runs in the container when no command is given. Defaults to `sh`. |
| `include` | Extra host paths the agent service mounts. `~` expands; relative paths resolve against the workspace root. A trailing `:ro` or `:rw` sets the mount mode, `rw` by default. Every path must exist: generation stops rather than let docker mount an empty directory in its place. |
| `name` | Compose project name. Defaults to a slug of the workspace path. |
| `profile` | Isolated tool-config namespace in `profiles/`. Unset mounts `__shared__`. |

The workspace root itself is always mounted, at its translated path.

### Expose a dev-server port

Static `[workspace] ports` are symmetric (`127.0.0.1:<port>` to the same
container port) and fixed at container create. For a port you need now, or one
another workspace already publishes, run:

```sh
arkham expose 3000             # 127.0.0.1:3000 -> agent :3000
arkham expose 3000 --host 3001 # second workspace: same server, distinct host port
arkham expose --list           # this workspace's publishings plus every workspace's claims
```

The command claims the host port in a registry shared across workspaces (a
taken port fails naming the owning workspace), appends the
`[[workspace.expose]]` mapping to the project config, regenerates, and `up`s.
Publishing is create-time state, so the arkham service (and the agent riding
its netns) recreates and exec sessions drop. `arkham down` releases the
workspace's claims.

### Reach the host and sidecar networks

Unmatched traffic splices through the capture byte-identical, so the agent can
reach anything arkham can route — it only needs the name to resolve.
`host.docker.internal` always points at the host gateway on both the arkham
and agent services (`/etc/hosts` is per container: the agent resolves the
name, arkham dials the upstream), so host-bound dev servers just work. Further
entries go in `[workspace] extra_hosts`, and existing compose networks in
`[workspace] networks` — both rendered on the arkham service, both inherited
by the agent through the shared netns:

```toml
[workspace]
extra_hosts = ["devbox:192.168.1.20"]
networks = ["headroom_default"]
```

A sidecar like `headroom` on a joined network resolves by name from the
agent. Joining any network moves arkham off the default project network.

## 3. Mount tool profiles

Every `<tool>/` directory inside the selected profile mounts into the agent container at the location that tool reads its own configuration from by default. Profiles live under `<config-dir>/arkham/profiles/<name>/` globally, or `<workspace root>/.config/arkham/profiles/<name>/` per workspace. `__shared__` is the base every profile inherits off and arkham always creates. Create the directory for each tool you use:

```sh
mkdir -p ~/.config/arkham/profiles/__shared__/pi ~/.config/arkham/profiles/__shared__/gh
```

A second identity is a second profile. Give the workspace a `profile.toml` cookie naming its parent, then fill in only the tools that differ:

```sh
mkdir -p ~/.config/arkham/profiles/work/gh
printf '[profile]\nparent = "__shared__"\n' > ~/.config/arkham/profiles/work/profile.toml
```

```toml
[workspace]
profile = "work"
```

The `work` profile mounts its own `gh` plus everything `__shared__` names. The built-in table covers `amazon-q`, `amp`, `auggie`, `claude`, `cline`, `codebuddy`, `codebuff`, `codex`, `continue`, `copilot`, `crush`, `cursor`, `deepagents`, `droid`, `dsh`, `forge`, `gemini`, `gh`, `goose`, `gptme`, `grok`, `hermes`, `iflow`, `junie`, `kilo`, `kimi`, `kimi-code`, `kiro`, `mimo-code`, `muse-code`, `omp`, `open-interpreter`, `openclaw`, `openhands`, `opencode`, `pi`, `qoder`, `qwen`, `roo`, `trae`, `vibe`, and `warp`, plus their common CLI-name spellings.

A tool the table does not carry gets its path from config:

```toml
[tools.my-tool]
config_dir = "{home}/.my-tool"
```

The mounts are writable. Whatever the tool writes lands beside the profile on the host.

## 4. The entrypoint and the CA

`init` writes both files the generated stack mounts, when they are missing:

| File | What it is |
| --- | --- |
| `~/.config/arkham/ca.pem` | arkham's CA, with `ca.crt` and `ca.key` written beside it. Delete the three to rotate; `init` and `up` create them again. |
| `~/.config/arkham/agent-entrypoint.sh` | The agent's entrypoint. It installs the mounted `ca.crt` into the container's system store with `update-ca-certificates`, then chains to the image's own init: `[workspace] init` names it (`ARKHAM_INIT` in the generated stack — like `shell`, it lives in the workspace config), the common entrypoint script names are tried when unset, and the command runs directly otherwise. Installing the CA needs root, directly or through passwordless `sudo`; without either it prints a warning and the container's tools do not trust arkham. `init` regenerates the file whenever it differs from the generated script, so stale or edited copies cannot linger — a custom script belongs in a compose layer overriding `entrypoint:`. |

The CA is yours after that: an existing one is never overwritten, so rotating means deleting the three files and letting `init` make a fresh CA. The entrypoint is the other way around — it is generated output, regenerated whenever it differs from the script above, because a stale copy is exactly how a stack silently stops trusting arkham. See [how to trust the CA](trust-the-ca.md) for the full range of trust options. Every mount the stack adds is conditional on the host path existing, because a bind mount of a missing path makes docker create a directory in its place.

Node and Python's `requests` read their own bundle instead of the system store, so the generated stack also points `NODE_EXTRA_CA_CERTS` and `REQUESTS_CA_BUNDLE` at the system bundle the entrypoint refreshes.

## 5. Generate, start, enter, stop

```sh
arkham init             # CA, entrypoint, and the stack (--backend picks the capture backend; ebpf by default)
arkham up               # start it
arkham logs -f          # the stack's logs (--tail N, --no-log-prefix, --workspace PATH, service names as for docker compose)
arkham agent            # init, up, and the shell in one idempotent command
arkham agent --rm       # the same, stopping the stack when the shell exits
arkham down             # stop it
```

`init` never writes workspace config: rules derive at serve time from fnox and the registry, and a workspace with no config file works. A config you wrote is yours and is never touched. `<state-dir>/arkham/ws/<slug>/compose.yml` is generated state. `init` rewrites it when the rendered file would change and leaves it untouched when the render matches. `arkham agent` runs the same generation before it starts the stack. Compose merges these files in order:

1. `<config-dir>/arkham/compose.yaml` (or `compose.yml`), for additions shared by every workspace.
2. The generated per-workspace `compose.yml`.
3. The workspace's `.config/arkham/compose.yaml` (or `.yml`; the older `.config/arkham.compose.yaml` and `.yml` names still apply), for additions local to this workspace.

`arkham agent [workspace] [--rm] [-- <command>...]` execs the configured shell as your uid at the translated workspace path, after generating what is missing and starting the stack, with `<command>` in place of the shell when you pass one. It leaves the stack running when that exits, or stops it when `--rm` is set. `logs` reads the stack's logs: `-f` to follow, `--no-log-prefix` for bare lines, `--tail <N|all>` (default `all`), service names to narrow it down, and `--workspace <PATH>` when the workspace is not the current directory.

## What the generated stack does

The arkham service runs `serve --proxy-backend <backend>`, `ebpf` unless `arkham init --backend` picked another, so the agent container, which shares arkham's network namespace, has every outbound connection captured with no proxy setting and no way around the proxy. Under `ebpf` both services carry the same `cgroup_parent`, and arkham attaches with `--ebpf-cgroup enclosing` — the cgroup its own cgroup lives under, resolved from `/proc/self/cgroup`, because the daemon places that parent relative to its own cgroup root; it also carries `cgroup: host` and the `BPF`/`PERFMON` capabilities, and the agent's inner containers land in the same cgroup. Under `tun` both services need `/dev/net/tun`. It holds the CA (`ARKHAM_CA_FILE=/certs/ca.pem`) and resolves the real values itself: your fnox config directory is mounted read-only at `/root/.config/fnox`, arkham's own fnox files at `/root/.config/arkham`, and every provider credential — including an age-encrypted secret, decrypted with the key inside the mounted fnox config — resolves from fnox inside the container, the way `fnox exec` would. The environment that started the stack is never a credential source.

The agent service holds only decoys, one environment variable per rule, and runs behind your entrypoint. It mounts the same workspace paths plus the profile mounts from step 3. It runs a container runtime of its own, so it carries what that needs: unconfined seccomp, systempaths and apparmor, `SYS_CHROOT`/`AUDIT_WRITE`/`NET_ADMIN`/`SETUID`/`SETGID`/`SYS_ADMIN`, and `/dev/net/tun`. Its storage is a directory under this workspace's state, made at generation time and mounted at `{home}/.local/share/containers`. `systempaths=unconfined` is a podman option — under docker, drop it from `security_opt`.

The generated file is fully baked: image names, the agent's uid, and every mount path are concrete values chosen at generation time from your config and machine, so the stack reads as the simple thing it is. Nothing in it is env-var configurable. To differ from the generated file, use the compose layers (`~/.config/arkham/compose.yaml` globally, the workspace's `.config/arkham/compose.yaml` locally), or change the config and let `init` regenerate.

## When it breaks

- `no compose layers for ...` — run `arkham init` first, or create one of the layer files.
- `[workspace] include ... does not exist` — fix or drop the entry. Docker would mount an empty directory in its place, so generation stops instead.
- `warning: could not prepare …ca.pem` — `[proxy] ca_file` points at a container path. That is fine when you mount the CA yourself in one of the compose layers instead.
- `arkham: not root and no passwordless sudo` — the entrypoint could not refresh the system store, so nothing in the agent trusts arkham. Run the agent service as root (`user: "0"` in one of your compose layers), give that user passwordless sudo, or bake the certificate into the image — see [how to trust the CA](trust-the-ca.md).
- An inner container will not start, or podman inside the agent exits with nothing on stderr — its storage directory is not writable by the uid the agent runs as. That is why generation makes `<state-dir>/arkham/ws/<slug>/containers`; if a layer points the volume at your own directory or a named volume, `chown` it to that uid once. On Ubuntu, an inner container that dies on mount or networking also needs `apparmor=unconfined` in `security_opt`, which the generated file already sets.
- A decoy does not get swapped — the decoy was generated with a different pattern than the rule's. `arkham init` derives each decoy from its rule's `pattern` for exactly this reason; if you hand-edit the compose file, regenerate decoys with `arkham fake <ENV>` after changing a pattern.
- DNS stops resolving in the agent after recreating only the arkham service — the agent shares arkham's network namespace, so recreate both: `arkham up` again.
- `grants: 0` in arkham's startup log, or a provider answering 401 while the agent holds credentials — no rule derived, so the decoy went out as-is. Run `arkham rules`: empty output means fnox declares nothing the registry knows (see [how to get values from fnox](get-values-from-fnox.md)); otherwise state an override block in `<workspace>/.config/arkham/config.toml` and regenerate.
