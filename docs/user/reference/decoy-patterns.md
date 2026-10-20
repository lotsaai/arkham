# Decoy pattern reference

How decoy shapes are written and chosen. A decoy is deterministic for its env name: the same name always yields the same value, across restarts and machines.

## Verbs

| Verb | Expands to |
| --- | --- |
| `{hex:N}` | N lowercase hexadecimal characters. |
| `{d:N}` | N decimal digits. |
| `{base62:N}` | N characters from `[0-9a-zA-Z]`. |

N is greater than zero. Literal text passes through, so a pattern can carry any prefix. Any other verb is rejected at startup or, for `arkham fake --pattern`, at invocation.

The default pattern, when neither the rule nor the registry supplies one, is `{hex:32}`.

## Selection order

Within one registry file, the pattern for a name resolves in this order:

1. An explicit `pattern` on the rule.
2. A `[names.<ENV>]` registry entry for the name.
3. A `[providers.*]` entry that claims the env name.
4. A `contains` substring match against the lowercased env name.
5. `{hex:32}`.

Across files, a later load's pattern overrides an earlier one regardless of tier: the bundled table loads first, then `rules.d` files in filename order.

`contains` is the one exception to later-wins. Matches are tried in load order, so the earliest-loaded file wins, and within one file the first provider name in sort order wins. A bundled `contains` entry therefore beats a `rules.d` entry under a different provider name; a same-name `rules.d` provider entry loses too unless it sets `replace = true`, which discards that provider's earlier `contains` needles.

`contains` selects a decoy shape only, never hosts. A name like `ACME_ANTHROPIC_KEY` gets an Anthropic-shaped decoy without reaching Anthropic.

## Previewing

```sh
arkham fake DEMO_TOKEN
# f92b2afa339693227aa209aac3eb48f9

arkham fake GH_TOKEN
# ghp_27ac12868ee51ad4e09a0a53b61ac927d0319142

arkham fake GH_TOKEN --pattern 'acme_{base62:24}'
# acme_7iJkET9b91ka42q9RKzEH6co
```

`--pattern` overrides the registry for that invocation only.

## Two properties to rely on

- **Stability**: the decoy follows the env name. Renaming an env var changes its decoy, so regenerate any decoy held in a container environment (the secure stack does this for you) or substitution stops matching.
- **Shape validity**: a decoy mimics the real token's format, which is why tools that validate token shape accept it. Corollary: a secret scanner can flag a decoy; that is expected.
