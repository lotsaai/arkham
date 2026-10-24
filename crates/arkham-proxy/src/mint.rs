//! Runtime token minting: freshly issued tokens never reach the guest as
//! real values.
//!
//! A flow-granted token endpoint's response is scanned for the flow's field
//! names; each real value found is paired with a freshly minted decoy and
//! recorded here. The decoy is what the guest holds. Later requests swap
//! the decoy back to the real value through the ordinary substitution path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use secrecy::SecretString;

use crate::Error;

/// One minted pair: the real freshly issued value and the decoy standing in
/// for it on the guest side. Keyed on the real value so rotation mints a new
/// pair per value without invalidating the old one.
#[derive(Debug, Clone)]
pub struct MintedPair {
  /// Grant label owning the flow (log identifier, never the value).
  pub label: String,
  /// The decoy the guest sees and re-sends.
  pub decoy: String,
}

/// Process-lifetime minted-pair store, shared across connections because
/// agents reuse tokens across connections.
// ponytail: process-memory only; restart orphans decoys the agent still
// holds and forces re-auth. Persist beside the CA if that ceiling bites.
#[derive(Clone, Default)]
pub struct MintStore {
  pairs: Arc<DashMap<String, MintedPair>>,
}

impl std::fmt::Debug for MintStore {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let labels: Vec<String> = self.pairs.iter().map(|entry| entry.label.clone()).collect();
    f.debug_struct("MintStore")
      .field("len", &self.pairs.len())
      .field("labels", &labels)
      .finish()
  }
}

impl MintStore {
  /// Mint a decoy for one real value and record the pair. Returns the
  /// existing decoy when the value was minted before, so repeated responses
  /// are idempotent.
  ///
  /// Minted decoys are not length-matched: they only ever ride HTTP legs
  /// (the mint path is reached from head processing, which raw machines
  /// never do), where length drift is rewritten by framing.
  ///
  /// # Errors
  ///
  /// Returns an error when the value is empty.
  pub fn mint(&self, label: &str, pattern: Option<&str>, field: &str, value: &str, expires_in: Option<u64>) -> Result<String, Error> {
    if value.is_empty() {
      return Err(Error::MintEmpty);
    }
    if let Some(pair) = self.pairs.get(value) {
      return Ok(pair.decoy.clone());
    }
    let decoy = arkham_config::config::fake_for(value, pattern);
    // A racing mint of the same value computes the same seed-stable decoy,
    // so last-writer-wins is idempotent, not a conflict.
    self.pairs.insert(
      value.to_string(),
      MintedPair {
        label: label.to_string(),
        decoy: decoy.clone(),
      },
    );
    tracing::debug!(label, field, expires_in = ?expires_in, "minted decoy for freshly issued token");
    Ok(decoy)
  }

  /// Every minted pair as (decoy, real, label), for request machines to
  /// union into their pair set at construction time.
  #[must_use]
  pub fn snapshot_pairs(&self) -> Vec<(String, SecretString, String)> {
    self
      .pairs
      .iter()
      .map(|entry| {
        let (real, pair) = entry.pair();
        (pair.decoy.clone(), SecretString::from(real.clone()), pair.label.clone())
      })
      .collect()
  }
}

/// On-demand issuance burst guard: at most this many fresh leaves per
/// window. Bounds remote-triggered issuance (Any-host grants, SNI rotation).
/// Two atomics, no lock: the window rolls by compare-exchange, the count by
/// fetch-add. A lost rollover race undercounts by a hair (fail-open); the
/// count never overshoots past in-flight increments (fail-closed).
const MINT_BURST: usize = 20;
const MINT_WINDOW_SECS: u64 = 10;

#[derive(Debug)]
pub(crate) struct MintBucket {
  /// Epoch seconds the current window started.
  window: AtomicU64,
  /// Leaves minted in the current window.
  count: AtomicUsize,
}

impl MintBucket {
  #[must_use]
  pub(crate) fn new() -> Self {
    Self {
      window: AtomicU64::new(epoch_secs()),
      count: AtomicUsize::new(0),
    }
  }

  /// Check and record one issuance in a single call: every `true` already
  /// spent the budget it approved, so the old allow-then-record split (and
  /// its double-spend race) is gone.
  pub(crate) fn allow(&self) -> bool {
    let now = epoch_secs();
    loop {
      let start = self.window.load(Ordering::Acquire);
      if now.saturating_sub(start) >= MINT_WINDOW_SECS {
        if self
          .window
          .compare_exchange(start, now, Ordering::AcqRel, Ordering::Acquire)
          .is_ok()
        {
          self.count.store(1, Ordering::Release);
          return true;
        }
        continue;
      }
      if self.count.fetch_add(1, Ordering::AcqRel) < MINT_BURST {
        return true;
      }
      self.count.fetch_sub(1, Ordering::AcqRel);
      return false;
    }
  }
}

/// Wall-clock epoch seconds for the burst window. Skew backwards saturates
/// the age to zero, which only keeps counting the current window.
fn epoch_secs() -> u64 {
  SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |age| age.as_secs())
}

#[cfg(test)]
mod tests {
  use super::*;
  use secrecy::ExposeSecret as _;

  #[test]
  fn minted_decoy_is_seed_stable_and_pattern_shaped() {
    let store = MintStore::default();
    let one = store
      .mint("t", Some("tok_{hex:16}"), "access_token", "real-value-one", None)
      .unwrap();
    let again = store
      .mint("t", Some("tok_{hex:16}"), "access_token", "real-value-one", None)
      .unwrap();
    assert_eq!(one, again, "repeated mint is idempotent");
    assert!(one.starts_with("tok_"), "{one}");
    let other = store
      .mint("t", Some("tok_{hex:16}"), "access_token", "real-value-two", None)
      .unwrap();
    assert_ne!(one, other, "distinct values mint distinct decoys");
  }

  #[test]
  fn snapshot_pairs_map_decoy_back_to_real() {
    let store = MintStore::default();
    let decoy = store.mint("t", None, "refresh_token", "real-refresh", Some(3600)).unwrap();
    let pairs = store.snapshot_pairs();
    let Some((_, real, label)) = pairs.iter().find(|(d, _, _)| d == &decoy) else {
      panic!("pair recorded");
    };
    assert_eq!(real.expose_secret(), "real-refresh");
    assert_eq!(label, "t");
  }

  #[test]
  fn store_rejects_empty_values() {
    let store = MintStore::default();
    let err = store.mint("t", None, "access_token", "", None).unwrap_err();
    assert!(err.to_string().contains("empty value"), "{err:?}");
  }

  #[test]
  fn mint_records_the_label() {
    let store = MintStore::default();
    store.mint("my-rule", None, "access_token", "v", Some(900)).unwrap();
    let pair = store.pairs.get("v").expect("pair recorded");
    assert_eq!(pair.label, "my-rule");
  }

  #[test]
  fn debug_lists_labels_without_the_issued_token() {
    let store = MintStore::default();
    let token = "issued-token-9f3c1a";
    store.mint("my-rule", None, "access_token", token, None).unwrap();
    let rendered = format!("{store:?}");
    assert!(!rendered.contains(token), "{rendered}");
    assert!(rendered.contains("my-rule"), "{rendered}");
    assert!(rendered.contains("len: 1"), "{rendered}");
  }

  #[test]
  fn clone_shares_the_minted_pair() {
    let store = MintStore::default();
    let cloned = store.clone();
    let decoy = cloned.mint("rule", Some("d_{d:8}"), "access_token", "value", None).unwrap();
    assert!(decoy.starts_with("d_"), "{decoy}");
    assert!(decoy[2..].bytes().all(|b| b.is_ascii_digit()), "{decoy}");
    assert_eq!(store.snapshot_pairs().len(), 1);
  }
}
