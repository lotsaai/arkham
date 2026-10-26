use std::borrow::Cow;

use secrecy::ExposeSecret as _;

use arkham_config::grants::{Grant, Scheme};

use super::wire::{CredentialPair, Direction, Hit, Location};

/// Eligible pairs for one connection endpoint. The scheme picks the grants;
/// framed formats re-encode freely, unframed bytes need equal lengths.
pub(crate) fn eligible_pairs(grants: &[Grant], scheme: Scheme, host: &str, port: u16, dir: Direction) -> Vec<CredentialPair> {
  let mut pairs = Vec::new();
  for grant in grants {
    if !grant.matches(scheme, host, port) {
      continue;
    }
    let Some(credential) = grant.credential() else {
      continue;
    };
    let (needle, replacement) = match dir {
      Direction::Downstream => (credential.fake.as_bytes(), credential.value.expose_secret().as_bytes()),
      Direction::Upstream => (credential.value.expose_secret().as_bytes(), credential.fake.as_bytes()),
    };
    if needle.is_empty() || replacement.is_empty() {
      continue;
    }
    pairs.push(CredentialPair {
      needle: needle.to_vec(),
      replacement: replacement.to_vec(),
      label: credential.label.clone(),
    });
  }
  pairs
}

/// Cap on buffered token-response bodies. A token response larger than
/// this fails closed rather than buffering unbounded attacker data.
pub(crate) const MAX_MINT_BODY: usize = 1024 * 1024;

/// What a minting response machine expects: the flow's field names, the
/// grant label, and the decoy template.
#[derive(Debug, Clone)]
pub(crate) struct MintPlan {
  /// Grant label owning the flow (log identifier, never the value).
  pub(crate) label: String,
  /// Decoy template minted decoys render from.
  pub(crate) pattern: Option<String>,
  /// Response body fields to mint.
  pub(crate) fields: Vec<String>,
}

/// Derive the mint plan for a response machine from its grants, when a
/// flow-granted grant matches this endpoint.
pub(crate) fn mint_plan_for(grants: &[Grant], scheme: Scheme, host: &str, port: u16) -> Option<MintPlan> {
  grants.iter().find_map(|grant| match grant {
    Grant::Token {
      credential,
      oauth2: Some(flow),
      ..
    } if grant.matches(scheme, host, port) => {
      let fields = if flow.token_fields.is_empty() {
        flow.fields().into_iter().map(str::to_string).collect()
      } else {
        flow.token_fields.clone()
      };
      Some(MintPlan {
        label: credential.label.clone(),
        pattern: grant_pattern(grant),
        fields,
      })
    }
    _ => None,
  })
}

/// Decoy template of a flow-granted token grant.
fn grant_pattern(grant: &Grant) -> Option<String> {
  match grant {
    Grant::Token { pattern, .. } => pattern.clone(),
    Grant::Postgres { .. }
    | Grant::Redis { .. }
    | Grant::Smtp { .. }
    | Grant::Ldap { .. }
    | Grant::Nats { .. }
    | Grant::Amqp { .. }
    | Grant::Ssh { .. } => None,
  }
}

/// Minted pairs as needle→replacement pairs for one direction: downstream
/// swaps minted decoys back to real values, upstream redacts real minted
/// values back to their decoys.
pub(crate) fn minted_pairs(mint: &crate::mint::MintStore, dir: Direction) -> Vec<CredentialPair> {
  mint
    .snapshot_pairs()
    .into_iter()
    .filter_map(|(decoy, real, label)| {
      let real = real.expose_secret();
      if decoy.is_empty() || real.is_empty() {
        return None;
      }
      let (needle, replacement) = match dir {
        Direction::Downstream => (decoy.as_bytes(), real.as_bytes()),
        Direction::Upstream => (real.as_bytes(), decoy.as_bytes()),
      };
      Some(CredentialPair {
        needle: needle.to_vec(),
        replacement: replacement.to_vec(),
        label,
      })
    })
    .collect()
}

/// Mint a token-response body, then apply the pair redaction. A body that
/// does not parse as a flat JSON object passes through with only the pair
/// redaction: minting fires only on what it can positively identify.
pub(crate) fn mint_and_redact(
  plan: &MintPlan,
  mint: &crate::mint::MintStore,
  body: &[u8],
  pairs: &[CredentialPair],
) -> (Vec<u8>, Vec<Hit>) {
  let mut hits = Vec::new();
  let minted = 'body: {
    let Ok(text) = std::str::from_utf8(body) else {
      break 'body body.to_vec();
    };
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(text) else {
      break 'body body.to_vec();
    };
    let Some(obj) = value.as_object_mut() else {
      break 'body body.to_vec();
    };
    let expires_in = obj.get("expires_in").and_then(serde_json::Value::as_u64);
    for field in &plan.fields {
      let Some(real) = obj.get(field.as_str()).and_then(serde_json::Value::as_str) else {
        continue;
      };
      let decoy = match mint.mint(&plan.label, plan.pattern.as_deref(), field, real, expires_in) {
        Ok(decoy) => decoy,
        Err(err) => {
          tracing::warn!(label = %plan.label, field, error = %err, "mint failed; passing through");
          continue;
        }
      };
      obj.insert(field.clone(), serde_json::Value::String(decoy));
      hits.push(Hit {
        label: plan.label.clone(),
        location: Location::Body,
      });
    }
    serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
  };
  let (redacted, static_hits) = replace_in(&minted, pairs, Location::Body);
  hits.extend(static_hits);
  (redacted.into_owned(), hits)
}

/// Cross-chunk overlap window: longest needle minus one.
pub(crate) fn max_tail_size(pairs: &[CredentialPair]) -> usize {
  pairs.iter().map(|pair| pair.needle.len()).max().unwrap_or(1).saturating_sub(1)
}

/// True for a match ending past `tail_len`: not wholly inside the tail the
/// previous chunk already reported.
pub(crate) fn find_new_match(combined: &[u8], needle: &[u8], tail_len: usize) -> bool {
  if needle.is_empty() || combined.len() < needle.len() {
    return false;
  }
  combined
    .windows(needle.len())
    .enumerate()
    .any(|(i, w)| w == needle && i + needle.len() > tail_len)
}

/// True when needle matches in window starting before `old_tail_len`
/// (straddling the previous tail boundary).
pub(crate) fn find_crossing(window: &[u8], needle: &[u8], old_tail_len: usize) -> bool {
  if needle.is_empty() || window.len() < needle.len() {
    return false;
  }
  window
    .windows(needle.len())
    .enumerate()
    .any(|(i, w)| i < old_tail_len && w == needle)
}

/// Scan-only hit detection with a rolling tail window. One hit per pair per
/// chunk: a chunk containing repeated needles reports one hit, not one per
/// occurrence.
pub(crate) fn scan_with_tail(pairs: &[CredentialPair], tail: &mut Vec<u8>, tail_size: usize, data: &[u8], location: Location) -> Vec<Hit> {
  let mut hits = Vec::new();
  if tail.is_empty() {
    for pair in pairs {
      if find_new_match(data, &pair.needle, 0) {
        hits.push(Hit {
          label: pair.label.clone(),
          location,
        });
      }
    }
  } else {
    let old_tail_len = tail.len();
    let bound = tail_size.min(data.len());
    let mut window = std::mem::take(tail);
    window.extend_from_slice(&data[..bound]);
    for pair in pairs {
      let inside = find_new_match(data, &pair.needle, 0);
      let crossing = find_crossing(&window, &pair.needle, old_tail_len);
      if inside || crossing {
        hits.push(Hit {
          label: pair.label.clone(),
          location,
        });
      }
    }
  }
  let keep = tail_size.min(data.len());
  *tail = data[data.len() - keep..].to_vec();
  hits
}

/// Replace all non-overlapping occurrences; `None` when nothing matched.
/// Allocates only on first match; copies runs, never byte-at-a-time.
pub(crate) fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Option<Vec<u8>> {
  if needle.is_empty() || haystack.len() < needle.len() {
    return None;
  }
  let mut out: Option<Vec<u8>> = None;
  let mut run_start = 0;
  let mut cursor = 0;
  while cursor + needle.len() <= haystack.len() {
    if haystack[cursor..].starts_with(needle) {
      let buf = out.get_or_insert_with(|| Vec::with_capacity(haystack.len()));
      buf.extend_from_slice(&haystack[run_start..cursor]);
      buf.extend_from_slice(replacement);
      cursor += needle.len();
      run_start = cursor;
    } else {
      cursor += 1;
    }
  }
  out.map(|mut buf| {
    buf.extend_from_slice(&haystack[run_start..]);
    buf
  })
}

pub(crate) fn replace_in<'a>(data: &'a [u8], pairs: &[CredentialPair], location: Location) -> (Cow<'a, [u8]>, Vec<Hit>) {
  let mut current = Cow::Borrowed(data);
  let mut hits = Vec::new();
  for pair in pairs {
    let hay: &[u8] = match &current {
      Cow::Borrowed(bytes) => bytes,
      Cow::Owned(buf) => buf,
    };
    if let Some(next) = replace_bytes(hay, &pair.needle, &pair.replacement) {
      current = Cow::Owned(next);
      hits.push(Hit {
        label: pair.label.clone(),
        location,
      });
    }
  }
  (current, hits)
}

/// True for response statuses that never carry a body (1xx, 204, 304).
pub(crate) fn response_has_no_body(status: Option<u16>) -> bool {
  let Some(code) = status else {
    return false;
  };
  (100..200).contains(&code) || code == 204 || code == 205 || code == 304
}

/// Hold back a needle suffix and close when a full needle is already present.
///
/// # Errors
///
/// Returns `Err(())` when `pairs` contains a complete needle in `held` plus `data`.
pub(crate) fn scan_close_hold(
  held: &mut Vec<u8>,
  data: &[u8],
  out: &mut Vec<u8>,
  pairs: &[CredentialPair],
  bound: usize,
) -> Result<(), ()> {
  let mut combined = std::mem::take(held);
  combined.extend_from_slice(data);
  if pairs.iter().any(|pair| find_new_match(&combined, &pair.needle, 0)) {
    return Err(());
  }
  let keep = needle_prefix_suffix_len(&combined, pairs, bound);
  let emit = combined.len().saturating_sub(keep);
  let tail = combined.split_off(emit);
  out.extend_from_slice(&combined);
  *held = tail;
  Ok(())
}

/// Longest suffix of `data` (bounded by `bound`) that is a proper prefix of
/// some needle: exactly the bytes that might still grow into a match.
pub(crate) fn needle_prefix_suffix_len(data: &[u8], pairs: &[CredentialPair], bound: usize) -> usize {
  let max = bound.min(data.len());
  for keep in (1..=max).rev() {
    let suffix = &data[data.len() - keep..];
    if pairs.iter().any(|pair| pair.needle.len() > keep && pair.needle.starts_with(suffix)) {
      return keep;
    }
  }
  0
}

/// How many bytes of `data` may be emitted (and substituted) now without
/// cutting a needle: past the end of every complete match, and short of any
/// trailing partial match that stays held until more bytes arrive.
pub(crate) fn needle_safe_emit_len(data: &[u8], pairs: &[CredentialPair], tail_bound: usize) -> usize {
  let mut emit = data.len() - needle_prefix_suffix_len(data, pairs, tail_bound);
  for pair in pairs {
    let needle = &pair.needle;
    if needle.is_empty() || data.len() < needle.len() {
      continue;
    }
    let mut cursor = 0;
    while cursor + needle.len() <= data.len() {
      if data[cursor..].starts_with(needle) {
        emit = emit.max(cursor + needle.len());
        cursor += needle.len();
      } else {
        cursor += 1;
      }
    }
  }
  emit
}
