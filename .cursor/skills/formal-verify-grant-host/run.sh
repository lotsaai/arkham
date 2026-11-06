#!/usr/bin/env bash
# One-command formal check for grant host / token endpoint matching.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
# Intentionally cargo test: this is the skill's proof command, not a substitute
# for `mise run test`. Filter keeps the run on the differential only.
cargo test -p arkham-config --test formal_grant_host -- --nocapture
