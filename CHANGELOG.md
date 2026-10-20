## [0.3.26] - 2026-10-20

### 🐛 Bug Fixes

- *(amqp)* Hold a split secret until the body completes (#69)

### 🚜 Refactor

- *(nats)* Stop merging the real seed and jwt into .env (#97)

### 🧪 Testing

- *(integration)* Use @nats-io/transport-node for NATS (#82)
- *(client)* Use Bun fetch for the HTTP compose legs (#84)
- *(proxy)* Drive sslmode=allow guests with tokio-postgres (#85)
- *(proxy)* Drive SMTP e2e guests with lettre (#87)
- *(proxy)* Drive redis e2e AUTH and PING with the redis crate (#90)
## [0.3.25] - 2026-10-20

### 🐛 Bug Fixes

- *(ldap)* Upgrade StartTLS after a bind or a search (#67)

### 🧪 Testing

- *(amqp)* Prove a grantless flow splices byte-identical (#70)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.25 [ci skip]
- Release
## [0.3.24] - 2026-10-19

### 🚀 Features

- *(config)* Name each context by path, protocol, and spelling (#68)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.24 [ci skip]
- Release
## [0.3.23] - 2026-10-19

### 🚀 Features

- *(proxy)* Rewrite NATS nkey and user-JWT CONNECT (#60)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.23 [ci skip]
- Release
## [0.3.22] - 2026-10-17

### 🚀 Features

- *(amqp)* Swap SASL PLAIN on amqp and amqps (#52)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.22 [ci skip]
- Release
## [0.3.21] - 2026-10-16

### 🚀 Features

- *(proxy)* Rewrite NATS CONNECT credentials after TLS (#53)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.21 [ci skip]
- Release
## [0.3.20] - 2026-10-16

### 🐛 Bug Fixes

- *(mtls)* Enforce client certificates for redis, smtp, ldap, and postgres (#55)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.20 [ci skip]
- Release
## [0.3.19] - 2026-10-15

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.19 [ci skip]
- Release
## [0.3.18] - 2026-10-15

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.18 [ci skip]
- Release
## [0.3.17] - 2026-10-14

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.17 [ci skip]
- Release
## [0.3.16] - 2026-10-13

### 🐛 Bug Fixes

- *(test)* Wait longer for the k3d apiserver and clear capture leftovers (#48)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.16 [ci skip]
- Release
## [0.3.15] - 2026-10-13

### 🐛 Bug Fixes

- Record per-vendor signing decisions for exchange and cloud keys (#46)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.15 [ci skip]
- Release
## [0.3.14] - 2026-10-12

### 🐛 Bug Fixes

- *(proxy)* MITM transparent TLS without SNI using captured IP (#45)
- Split signing-only secrets from substitutable credentials (#43)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.13 [ci skip]
- Release
- *(release)* Push release tag with a GitHub App token
- Update changelog for v0.3.14 [ci skip]
- Release
## [0.3.12] - 2026-10-11

### 🐛 Bug Fixes

- Convert out of rama TcpStream via From

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.12 [ci skip]
- Release
## [0.3.11] - 2026-10-11

### 🐛 Bug Fixes

- *(ci)* Commit member bumps pre-release
- *(ci)* Refresh and commit lockfile in cut-release

### 🚜 Refactor

- [**breaking**] Rename hodor to arkham

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.10 [ci skip]
- Release
- Unify crate versions at 0.3.10
- Release all workspace crates in lockstep
- Update changelog for v0.3.11 [ci skip]
- Release
## [0.3.9] - 2026-10-10

### 🚜 Refactor

- *(compose)* Split stack.rs by concern

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.9 [ci skip]
- Release
## [0.3.8] - 2026-10-10

### 🐛 Bug Fixes

- *(compose)* Correct stack yaml, stop tool mounts in repo

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.8 [ci skip]
- Release
## [0.3.7] - 2026-10-10

### 🚀 Features

- *(compose)* Workspace networking, expose, stack builder
- *(proxy)* Redis transport, protocol verticals, lock-free state

### 🐛 Bug Fixes

- *(compose)* Mount missing builtin tool configs

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.7 [ci skip]
- Release
## [0.3.6] - 2026-10-08

### 🚀 Features

- Default home, CA path, and derived rules
- *(ebpf)* Reload bypass CIDRs from a shared file

### 🐛 Bug Fixes

- *(ebpf)* Satisfy clippy 1.99 and cargo metadata lints

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.6 [ci skip]
- Release
## [0.3.5] - 2026-10-07

### 🚀 Features

- Build agent image on demand, stop demanding absent client certs

### 🐛 Bug Fixes

- *(compose)* Round-trip kube/talos twins and git credentials

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.5 [ci skip]
- Release
## [0.3.4] - 2026-10-07

### 🐛 Bug Fixes

- *(compose)* Print derived rules as TOML blocks

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.4 [ci skip]
- Release
## [0.3.3] - 2026-10-07

### 🚀 Features

- *(config)* Agent devices and cap_add

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.3 [ci skip]
- Release
## [0.3.2] - 2026-10-06

### 🐛 Bug Fixes

- *(jj)* Map the jj config directory into the agent container

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.2 [ci skip]
- Release
## [0.3.1] - 2026-10-06

### 🐛 Bug Fixes

- *(fnox)* Make merge_configs infallible

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.1 [ci skip]
- Release
## [0.3.0] - 2026-10-06

### 🚀 Features

- Ssh decoy sessions, ambient source twins, review hardening (#42)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.0 [ci skip]
- Release
## [0.2.5] - 2026-10-02

### 🚀 Features

- *(compose)* [**breaking**] Known config file formats derive grants (kubeconfig, talosconfig) (#41)

### ⚙️ Miscellaneous Tasks

- *(ci)* Drop vendored skills from lychee
- Update changelog for v0.2.5 [ci skip]
- Release
## [0.2.4] - 2026-09-29

### 🚀 Features

- *(config)* Mount tool configs from inheritable profiles (#39)
- Upstream rama plus per-entry egress trust bump:minor (#40)

### 🐛 Bug Fixes

- Sync Cargo.lock with 0.2.3 manifest

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.3.0 [ci skip]
- Release
- Update changelog for v0.4.0 [ci skip]
- Release
- Release hodor version 0.2.3
- Update changelog for v0.2.4 [ci skip]
- Release
## [0.2.2] - 2026-09-27

### ⚙️ Miscellaneous Tasks

- Refresh mise tool lock, add jj bookmark cleanup to worktrunk
- Update changelog for v0.2.2 [ci skip]
- Release
## [0.2.1] - 2026-09-26

### 🚀 Features

- *(compose)* Netns-scoped capture, agent port exposure (#38)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.2.1 [ci skip]
- Release
## [0.2.0] - 2026-09-26

### 🚀 Features

- Response-side OAuth2 token minting

### ⚙️ Miscellaneous Tasks

- *(vcs)* Add worktrunk confg
- Update changelog for v0.2.0 [ci skip]
- Release
## [0.1.23] - 2026-09-25

### 🚀 Features

- *(proxy)* Tcp, mTLS, and postgres wire substitution (#36)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.23 [ci skip]
- Release
## [0.1.22] - 2026-09-20

### 🚀 Features

- Flatten the workspace CLI, add agent --rm, fix eBPF self-exclusion in containers (#35)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.22 [ci skip]
- Release
## [0.1.21] - 2026-09-19

### 🚀 Features

- *(proxy)* Add wasm rewrite plugin system + proptest fuzz suite (#34)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.21 [ci skip]
- Release
## [0.1.20] - 2026-09-18

### 🚜 Refactor

- *(proxy)* [**breaking**] Replace hand-rolled TLS stack with rama + boring (#33)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.20 [ci skip]
- Release
## [0.1.19] - 2026-09-18

### ⚙️ Miscellaneous Tasks

- *(container)* Assert on markers that exist in the binary
- Update changelog for v0.1.19 [ci skip]
- Release
## [0.1.18] - 2026-09-18

### ⚙️ Miscellaneous Tasks

- *(dist)* Build only the root package in releases
- *(ci)* Update the nightly version
- *(mise)* Pin the nightly toolchain to a dated specifier
- Update changelog for v0.1.18 [ci skip]
- Release
## [0.1.17] - 2026-09-18

### 🚀 Features

- *(capture)* [**breaking**] Add ebpf transparent backend (#32)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.17 [ci skip]
- Release
## [0.1.16] - 2026-09-16

### 🚀 Features

- *(capture)* [**breaking**] Restore tun backend beside tproxy via --proxy-backend (#31)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.16 [ci skip]
- Release hodor version 0.1.16
## [0.1.15] - 2026-09-16

### 🚀 Features

- Workspace-scoped fnox decoy credential injection
- Cover crypto infra APIs, fix dead hosts
- *(confine)* Make init produce a runnable stack
- *(confine)* Wire the agent container runtime

### 📚 Documentation

- Add user docs, rewrite README

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.15 [ci skip]
- Release hodor version 0.1.15
## [0.1.14] - 2026-09-14

### 🚀 Features

- *(confine)* Compose-based workspace lifecycle

### 🐛 Bug Fixes

- Recover bwrap demo, docs, and image base lost in rebase

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.14 [ci skip]
- Release hodor version 0.1.14
## [0.1.13] - 2026-09-13

### 🚀 Features

- *(tproxy)* Kernel TPROXY capture replacing tun, with demo and guard

### ⚙️ Miscellaneous Tasks

- *(mise)* Restructure task files into namespaced dirs
- Update changelog for v0.1.13 [ci skip]
- Release hodor version 0.1.13
## [0.1.12] - 2026-09-12

### 🐛 Bug Fixes

- *(dist)* Install libudev-dev in the dist build setup

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.12 [ci skip]
- Release hodor version 0.1.12
## [0.1.11] - 2026-09-12

### 🚀 Features

- *(secrets)* Add the bundled host registry and rules.d overrides
- *(secrets)* Resolve rule hosts, patterns, and if_missing
- *(secrets)* Resolve rule values from fnox
- *(registry)* Seed known hosts for the first provider tranche

### 🐛 Bug Fixes

- *(secrets)* Distinguish missing, absent and empty fnox values
- *(ci)* Install libudev-dev for the fnox-core dep tree

### 📚 Documentation

- Add the rules and registry spec and plan
- Fix the dead Azure source link in the plan
- Document rules, the registry, and fnox values
- Correct the registry layer precedence
- Apply markdown formatting to AGENTS.md
- *(registry)* Mark the undocumented environment names

### 🚜 Refactor

- *(config)* Rename [secrets] to [rules] and open the schema
- *(secrets)* Chain errors and drop needless clones
- *(config)* Chain the rule-merge errors

### ⚙️ Miscellaneous Tasks

- *(mise)* Pin node lts in the toolchain
- Update changelog for v0.1.11 [ci skip]
- Release hodor version 0.1.11
## [0.1.10] - 2026-09-11

### 🐛 Bug Fixes

- *(dist)* Build the released binaries with the tun feature

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.10 [ci skip]
- Release hodor version 0.1.10
## [0.1.9] - 2026-09-11

### 🚀 Features

- *(ca)* Write the certificate and key beside the CA file

### ⚙️ Miscellaneous Tasks

- *(heimdall)* Point the policy messages at the format task
- Update changelog for v0.1.9 [ci skip]
- Release hodor version 0.1.9
## [0.1.8] - 2026-09-11

### ⚙️ Miscellaneous Tasks

- *(ci)* Use current action majors in the hand-written workflows
- Update changelog for v0.1.8 [ci skip]
- Release hodor version 0.1.8
## [0.1.7] - 2026-09-11

### 🐛 Bug Fixes

- *(container)* Check out the repo so buildx can find the Dockerfile

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.7 [ci skip]
- Release hodor version 0.1.7
## [0.1.6] - 2026-09-11

### 🐛 Bug Fixes

- *(container)* Download and extract the release asset correctly

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.6 [ci skip]
- Release hodor version 0.1.6
## [0.1.5] - 2026-09-11

### 🐛 Bug Fixes

- *(dist)* Add the profile cargo-dist builds with

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.5 [ci skip]
- Release hodor version 0.1.5
## [0.1.4] - 2026-09-11

### 🐛 Bug Fixes

- *(ci)* Grant the container job the permissions it requests

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.4 [ci skip]
- Release hodor version 0.1.4
## [0.1.3] - 2026-09-11

### 🐛 Bug Fixes

- *(proxy)* Treat missing TLS close_notify as clean EOF

### 📚 Documentation

- Add an agentic devenv example
- Rewrite the README for users

### ⚙️ Miscellaneous Tasks

- *(mise)* Split tun test task into user build + root exec
- Initial import
- Update changelog for v0.1.1 [ci skip]
- Release hodor version 0.1.1
- Update changelog for v0.1.2 [ci skip]
- Release hodor version 0.1.2
- Publish the image on main and use it in the example
- Build the image from the repo root with an explicit Dockerfile
- Update changelog for v0.1.3 [ci skip]
- Release hodor version 0.1.3
