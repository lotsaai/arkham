//! Grant eligibility and mint plans. The scan, the hold-back, and [`Raw`]
//! live in `arkham-wire`. Protocol framing machines live in their own crates.

#[cfg(test)]
pub(crate) mod harness;

#[cfg(test)]
mod fuzz_props;

pub(crate) use super::amqp::machine::Amqp;
pub(crate) use super::http::h2::H2;
pub(crate) use super::http::machine::Http;
pub(crate) use super::ldap::machine::Ldap;
pub(crate) use super::postgres::machine::{GuestOpening, Postgres, read_guest_opening, request_upstream_tls};
pub(crate) use super::redis::machine::Redis;
pub(crate) use super::ssh::legs::{LegKeys, SshLegs, SshLegsFiles, Upstream};
pub(crate) use arkham_wire::engine::{
  CredentialPair, Direction, Hit, LocalUpgrade, Location, PeerFact, Rewritten, UpgradeNote, Wire, find_new_match, max_tail_size,
  needle_prefix_suffix_len, needle_safe_emit_len, replace_bytes, replace_in, response_has_no_body, scan_with_tail,
};
pub(crate) use arkham_wire::raw::Raw;

use secrecy::ExposeSecret as _;

use arkham_config::grants::{Grant, Scheme};

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
pub(crate) fn minted_pairs(mint: &crate::mint::MintHandle, dir: Direction) -> Vec<CredentialPair> {
  use secrecy::ExposeSecret as _;
  mint
    .pairs()
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
  mint: &crate::mint::MintHandle,
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

/// Equal-length pairs for an unframed stream. A grant whose replacement
/// differs in length is omitted so the stream is never reframed.
pub(crate) fn raw_new(grants: &[Grant], scheme: Scheme, host: &str, port: u16, dir: Direction) -> Raw {
  let pairs = eligible_pairs(grants, scheme, host, port, dir)
    .into_iter()
    .filter(|pair| pair.needle.len() == pair.replacement.len())
    .collect();
  Raw::from_pairs(pairs)
}
