---
name: formal-verify-grant-host
description: Formally diffs arkham HostPat and Token grant endpoint matching against an independent Python oracle. Use when changing grants/scope.rs, grants/resolve.rs endpoint matching, allow-entry parsing for http/https/tcp hosts, or any code that decides whether a decoy may become a real secret.
---

# Formal verify: grant host matching

## Property (plain words)

A request identity (scheme, host, port) matches a Token allow entry if and only if the scheme equals, the port equals, and the host matches the entry's HostPat. Wildcards match subdomains only — never the apex. A break here leaks real secrets off-grant or blocks a granted swap.

Harm if false: the proxy substitutes on the wrong hosts (secret exfiltration) or fails to substitute on allowed hosts (agent breakage).

## Why this tool

Host matching is a pure predicate over a finite pattern language. Java/TLC is not available in this environment. An independent Python oracle plus exhaustive enumeration over a fixed host/pattern/scheme/port grid diffs against the real Rust types (`HostPat::matches`, `EndpointScope` parse, scheme+port+host). That answers “does the code agree with the documented rule for every case in scope?” without hand-modeling the relay.

## Coverage (keep in sync)

| Code | Role |
| --- | --- |
| `crates/arkham-config/src/grants/scope.rs` — `HostPat`, `HostPat::matches`, `FromStr` | host patterns |
| `crates/arkham-config/src/grants/scope.rs` — `EndpointScope::from_str` (http/https/tcp) | allow entry parse used by the grid |
| `crates/arkham-config/src/grants/resolve.rs` — `endpoint_match` / `host_port_match` | Token grant match predicate (harness inlines the same boolean) |

Last sync commit: `3c20783559d84f7b155d8e4778094d679589f266` (confirm before trusting after grant-matching edits; move this forward only after re-running `run.sh` and confirming the oracle still describes the code).

Proven able to fail: a scratch edit that let `*.example.com` match apex `example.com` produced 13 oracle mismatches; restoring `scope.rs` returned PASS.

## Bounds and assumptions

- Enumerated patterns/hosts/schemes/ports in `crates/arkham-config/tests/formal_grant_host.rs` only — not every Unicode hostname.
- Token grants only (not Postgres/Redis/SMTP/LDAP/NATS/AMQP/SSH scope matchers).
- Does not model TLS, capture backends, or substitution engines.
- Oracle: `.cursor/skills/formal-verify-grant-host/oracle.py` (must stay independent of the Rust source).

## When a change touches coverage

If the diff edits any coverage file above, run this skill before claiming the change is safe. If the intentional behavior of matching changed, update `oracle.py` and the grid together, re-run, then advance the sync commit in this file.

## Run

From the repo root:

```sh
.cursor/skills/formal-verify-grant-host/run.sh
```

Requires `python3` and a workspace-capable `cargo` (same toolchain as the repo). Exit 0 prints `PASS` and the case count. Exit 1 prints mismatches in code terms (`host-N` / `token-N` with rust vs oracle).

Read counterexamples with `/statechart` only when you replace this check with a TLA+ model; this differential check already prints shortest-form case ids.

## Tell a real bug from modeling error

- Oracle and docs agree, Rust differs → product bug (or intentional change needing oracle update).
- Rust matches docs, oracle differs → fix `oracle.py`, do not weaken Rust.
- Parse failure on an allow string in the grid → harness/grid bug, not a HostPat match bug.

## Able to fail

A broken variant that lets `*.example.com` match the apex `example.com` must make `run.sh` exit non-zero. Re-check that after editing the oracle or grid.
