//! Raw wire: no format.

use std::borrow::Cow;

use crate::engine::{
  CredentialPair, Hit, Location, Rewritten, Wire, find_crossing, find_new_match, max_tail_size, needle_prefix_suffix_len,
  needle_safe_emit_len, replace_in,
};

/// Byte substitution over one direction. The hold-back is the longest needle minus one.
pub struct Raw {
  pairs: Vec<CredentialPair>,
  tail_size: usize,
  held: Vec<u8>,
}

impl Raw {
  /// Build from pairs the caller already chose. The hold-back is the longest needle minus one.
  #[must_use]
  pub fn from_pairs(pairs: Vec<CredentialPair>) -> Self {
    let tail_size = max_tail_size(&pairs);
    Self {
      pairs,
      tail_size,
      held: Vec::new(),
    }
  }
}

impl Wire for Raw {
  fn feed<'a>(&mut self, chunk: &'a [u8]) -> impl Future<Output = (Rewritten<'a>, Vec<Hit>)> {
    if chunk.is_empty() {
      let flushed = std::mem::take(&mut self.held);
      return std::future::ready((Rewritten::Emit(Cow::Owned(flushed)), Vec::new()));
    }
    let hit = self.pairs.iter().any(|pair| {
      find_new_match(chunk, &pair.needle, 0)
        || (!self.held.is_empty() && {
          let old_len = self.held.len();
          let bound = self.tail_size.min(chunk.len());
          let mut window = self.held.clone();
          window.extend_from_slice(&chunk[..bound]);
          find_crossing(&window, &pair.needle, old_len)
        })
    });
    if !hit {
      if self.held.is_empty() {
        let hold = needle_prefix_suffix_len(chunk, &self.pairs, self.tail_size);
        let emit_len = chunk.len().saturating_sub(hold);
        if hold > 0 {
          self.held = chunk[emit_len..].to_vec();
        }
        let out = Cow::Borrowed(&chunk[..emit_len]);
        return std::future::ready((Rewritten::Emit(out), Vec::new()));
      }
      let mut combined = std::mem::take(&mut self.held);
      combined.extend_from_slice(chunk);
      let hold = needle_prefix_suffix_len(&combined, &self.pairs, self.tail_size);
      let emit_len = combined.len().saturating_sub(hold);
      self.held = combined.split_off(emit_len);
      return std::future::ready((Rewritten::Emit(Cow::Owned(combined)), Vec::new()));
    }
    let mut combined = std::mem::take(&mut self.held);
    combined.extend_from_slice(chunk);
    let emit_len = needle_safe_emit_len(&combined, &self.pairs, self.tail_size);
    self.held = combined.split_off(emit_len);
    let (new_emit, hits) = replace_in(&combined, &self.pairs, Location::Body);
    std::future::ready((Rewritten::Emit(Cow::Owned(new_emit.into_owned())), hits))
  }
}

impl std::fmt::Debug for Raw {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Raw")
      .field("pairs", &self.pairs)
      .field("tail_size", &self.tail_size)
      .field("held", &self.held.len())
      .finish()
  }
}
