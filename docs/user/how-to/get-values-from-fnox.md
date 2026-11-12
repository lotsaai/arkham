# How to get values from fnox

This guide shows you how to leave the real secret out of arkham's config entirely and resolve it from fnox at serve time. You need a rule with no inline `value`, and the secret declared somewhere fnox can find it.

arkham embeds `fnox-core`, so no fnox binary or daemon is needed. fnox reaches age, 1Password, AWS Secrets Manager, Vault, Bitwarden, the OS keychain, and the rest of its provider catalog.

## 1. Write a value-less rule

```toml
[rules.github_token]
env = "GITHUB_TOKEN"
if_missing = "warn"
```

That is the whole rule. The real value resolves from fnox under the key `GITHUB_TOKEN` at startup. Set `fnox_key` when the fnox name differs:

```toml
[rules.ci]
env = "GITHUB_TOKEN"
fnox_key = "work/ci/github"
```

An inline `value` always wins over fnox, which makes temporary overrides a one-line change.

## 2. Declare the secret to fnox

arkham reads fnox's own discovery chain, plus one level of its own. From least to most specific:

1. fnox's global config, `$FNOX_CONFIG_DIR/config.toml` (or fnox's default global location).
2. `<config-dir>/arkham/fnox.toml`, arkham's own middle level. Secrets that are global for arkham but not global for fnox live here.
3. The upward `fnox.toml` walk from the working directory, per workspace.

Each level follows fnox's profile convention: `fnox.local.toml` when no profile is active, `fnox.<profile>.toml` otherwise, so `$FNOX_PROFILE` picks the file standing in for the local slot.

```toml
# <config-dir>/arkham/fnox.toml
[secrets.GITHUB_TOKEN]
provider = "age"
# ... provider-specific fields as fnox documents them
```

The declared key then flows to arkham: `arkham rules` lists it, and the rule that references it resolves.

## 3. Control missing-value behaviour

`if_missing` decides what a gap means:

- `error` (default): startup fails.
- `warn`: arkham serves without the rule's substitutions.
- `ignore`: same as `warn`, without the log line.

Two different gaps behave differently:

- A key fnox does not declare at all follows `if_missing`. This is the normal "not every machine has every secret" case.
- A key fnox declares but cannot resolve (provider unreachable, decryption failure) is always a startup error, whatever `if_missing` says. The secret exists; failing closed is correct.

## 4. Provider credentials

The host daemon resolves secrets using the fnox configuration and provider credentials available to its user.

## Check it works

```sh
arkham rules
```

lists every fnox-declared name the registry knows, and names the declarations no registry entry covers. Then start the proxy and watch the substitution log line:

```text
substituted label=github_token location=Header
```

The line carries the rule label and where the swap happened, never a value.
