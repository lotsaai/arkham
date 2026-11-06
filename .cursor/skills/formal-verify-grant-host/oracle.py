#!/usr/bin/env python3
"""Independent reference for HostPat + token endpoint matching.

This is not a copy of crates/arkham-config/src/grants/scope.rs. It restates
the documented rules from HostPat's doc comments and Grant::matches for
Token allows (scheme + port + host). The Rust harness diffs against it.
"""

from __future__ import annotations

import json
import sys


def ascii_eq_ignore_case(a: str, b: str) -> bool:
  if len(a) != len(b):
    return False
  return all(x.lower() == y.lower() for x, y in zip(a, b))


def host_matches(pattern: str, hostname: str) -> bool:
  """Exact / *.wildcard (subdomains only, never apex) / *."""
  if pattern == "*":
    return True
  if pattern.startswith("*."):
    suffix = pattern[2:]
    # Need "<label>." + suffix, so hostname longer than suffix+1 and the
    # byte just before the suffix is '.'.
    if len(hostname) <= len(suffix) + 1:
      return False
    cut = len(hostname) - len(suffix)
    if hostname[cut - 1] != ".":
      return False
    return ascii_eq_ignore_case(hostname[cut:], suffix)
  return ascii_eq_ignore_case(hostname, pattern)


def token_endpoint_matches(
  allow_scheme: str, allow_host_pat: str, allow_port: int, scheme: str, host: str, port: int
) -> bool:
  return allow_scheme == scheme and allow_port == port and host_matches(allow_host_pat, host)


def main() -> int:
  cases = json.load(sys.stdin)
  out = []
  for case in cases:
    kind = case["kind"]
    if kind == "host":
      out.append(
        {
          "id": case["id"],
          "expected": host_matches(case["pattern"], case["hostname"]),
        }
      )
    elif kind == "token":
      out.append(
        {
          "id": case["id"],
          "expected": token_endpoint_matches(
            case["allow_scheme"],
            case["allow_host_pat"],
            case["allow_port"],
            case["scheme"],
            case["host"],
            case["port"],
          ),
        }
      )
    else:
      raise SystemExit(f"unknown kind {kind}")
  json.dump(out, sys.stdout)
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
