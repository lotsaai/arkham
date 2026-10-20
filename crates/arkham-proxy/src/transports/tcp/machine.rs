//! Raw wire: no format. [`Raw::new`] keeps equal-length pairs so a TCP
//! stream is never reframed. [`Raw::length_changing`] keeps every pair;
//! SMTP replies use it, because a reply is a CRLF line and a shorter
//! decoy does not shift a length prefix. Both hold back the longest
//! needle minus one so a match split across chunks is substituted whole.

use std::borrow::Cow;

use arkham_config::grants::{Grant, Scheme};

use crate::transports::engine::{
  CredentialPair, Direction, Hit, Location, Rewritten, Wire, eligible_pairs, find_crossing, find_new_match, max_tail_size,
  needle_prefix_suffix_len, needle_safe_emit_len, replace_in,
};

/// Equal-length byte substitution over one direction.
pub(crate) struct Raw {
  pairs: Vec<CredentialPair>,
  tail_size: usize,
  held: Vec<u8>,
}

impl Raw {
  /// Build from the grants a `tcp://` or `postgres://` rule matched. Only
  /// equal-length pairs apply: this machine rewrites a chunk in place, so a
  /// grant whose replacement differs in length is skipped rather than
  /// corrupting the stream.
  pub(crate) fn new(grants: &[Grant], scheme: Scheme, host: &str, port: u16, dir: Direction) -> Self {
    let pairs = eligible_pairs(grants, scheme, host, port, dir)
      .into_iter()
      .filter(|pair| pair.needle.len() == pair.replacement.len())
      .collect();
    Self::from_pairs(pairs)
  }

  /// Like [`Self::new`], including pairs whose replacement differs in
  /// length. The hold-back is still the longest needle minus one. The
  /// emitted prefix carries the shorter or longer replacement.
  pub(crate) fn length_changing(grants: &[Grant], scheme: Scheme, host: &str, port: u16, dir: Direction) -> Self {
    Self::from_pairs(eligible_pairs(grants, scheme, host, port, dir))
  }

  pub(crate) fn extend_redaction(&mut self, extra: &[CredentialPair]) {
    let before = self.pairs.len();
    self
      .pairs
      .extend(extra.iter().filter(|pair| pair.needle.len() == pair.replacement.len()).cloned());
    if self.pairs.len() == before {
      return;
    }
    self.tail_size = max_tail_size(&self.pairs);
  }

  /// Build from pairs the caller already chose. The hold-back is the longest needle minus one.
  pub(crate) fn from_pairs(pairs: Vec<CredentialPair>) -> Self {
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
    // Probe for a hit without copying the whole chunk: fully-inside matches
    // scan the chunk in place; boundary matches scan a tiny tail window. On
    // a hit, fall back to the full held+chunk replace.
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
      // The previous chunk ended on a needle prefix. This chunk does not
      // finish it, so those bytes are emitted ahead of the chunk. The new
      // hold-back is a suffix of the combined bytes, at most the longest
      // needle minus one.
      let mut combined = std::mem::take(&mut self.held);
      combined.extend_from_slice(chunk);
      let hold = needle_prefix_suffix_len(&combined, &self.pairs, self.tail_size);
      let emit_len = combined.len().saturating_sub(hold);
      self.held = combined.split_off(emit_len);
      return std::future::ready((Rewritten::Emit(Cow::Owned(combined)), Vec::new()));
    }
    let mut combined = std::mem::take(&mut self.held);
    combined.extend_from_slice(chunk);
    // Emit past every complete match so none is sliced by the hold-back.
    let emit_len = needle_safe_emit_len(&combined, &self.pairs, self.tail_size);
    self.held = combined.split_off(emit_len);
    let (new_emit, hits) = replace_in(&combined, &self.pairs, Location::Body);
    std::future::ready((Rewritten::Emit(Cow::Owned(new_emit.into_owned())), hits))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::grants::Credential;

  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  #[tokio::test]
  async fn raw_mode_replaces_equal_length_across_writes() {
    let grants = vec![Grant::Token {
      credential: Credential {
        label: "db".into(),
        fake: "FAKE1234".into(),
        value: secrecy::SecretString::from("REAL5678"),
      },
      allow: vec!["tcp://10.0.0.8:5432".parse().unwrap()],
      pattern: None,
      oauth2: None,
    }];
    let mut raw = Raw::new(&grants, Scheme::Tcp, "10.0.0.8", 5432, Direction::Downstream);
    let (out1, _) = {
      match raw.feed(b"xxFAKE").await {
        (Rewritten::Emit(bytes), hits) => (bytes, hits),
        _ => unreachable!("expected emit"),
      }
    };
    let out1 = out1.into_owned();
    let (out2, _) = {
      match raw.feed(b"1234yy").await {
        (Rewritten::Emit(bytes), hits) => (bytes, hits),
        _ => unreachable!("expected emit"),
      }
    };
    let out2 = out2.into_owned();
    let (flush, _) = {
      match raw.feed(&[]).await {
        (Rewritten::Emit(bytes), hits) => (bytes, hits),
        _ => unreachable!("expected emit"),
      }
    };
    let flush = flush.into_owned();
    let mut full = out1;
    full.extend_from_slice(&out2);
    full.extend_from_slice(&flush);
    assert_eq!(full, b"xxREAL5678yy");
  }

  #[tokio::test]
  async fn raw_needle_ending_in_hold_window_not_sliced() {
    // The needle ends flush with the chunk end and its last byte is also a
    // needle prefix: a prefix-only hold-back would emit the needle minus
    // its last byte raw. It must be substituted whole, now.
    let grants = vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      allow: vec!["tcp://10.0.0.8:5432".parse().unwrap()],
      pattern: None,
      oauth2: None,
    }];
    let mut raw = Raw::new(&grants, Scheme::Tcp, "10.0.0.8", 5432, Direction::Downstream);
    let chunk = format!("x{FAKE}");
    let (out, _) = {
      match raw.feed(chunk.as_bytes()).await {
        (Rewritten::Emit(bytes), hits) => (bytes, hits),
        _ => unreachable!("expected emit"),
      }
    };
    let out = out.into_owned();
    let (flush, _) = {
      match raw.feed(b"z").await {
        (Rewritten::Emit(bytes), hits) => (bytes, hits),
        _ => unreachable!("expected emit"),
      }
    };
    let mut full = out;
    full.extend_from_slice(&flush);
    let text = String::from_utf8(full).unwrap();
    assert!(text.contains(&format!("x{VALUE}z")), "{text}");
    assert!(!text.contains(&FAKE[..FAKE.len() - 1]), "{text}");
  }
  #[tokio::test]
  async fn raw_mode_skips_unequal_length() {
    let grants = vec![Grant::Token {
      credential: Credential {
        label: "u".into(),
        fake: "SHORT".into(),
        value: secrecy::SecretString::from("A-MUCH-LONGER-VALUE"),
      },
      allow: vec!["tcp://10.0.0.8:5432".parse().unwrap()],
      pattern: None,
      oauth2: None,
    }];
    let mut raw = Raw::new(&grants, Scheme::Tcp, "10.0.0.8", 5432, Direction::Downstream);
    let (out, hits) = {
      match raw.feed(b"xxSHORTyy").await {
        (Rewritten::Emit(bytes), hits) => (bytes, hits),
        _ => unreachable!("expected emit"),
      }
    };
    let out = out.into_owned();
    let (flush, _) = {
      match raw.feed(&[]).await {
        (Rewritten::Emit(bytes), hits) => (bytes, hits),
        _ => unreachable!("expected emit"),
      }
    };
    let flush = flush.into_owned();
    let mut full = out;
    full.extend_from_slice(&flush);
    assert_eq!(full, b"xxSHORTyy");
    assert_eq!(hits, [] as [Hit; 0]);
  }

  #[tokio::test]
  async fn raw_mode_flushes_complete_line_without_more_input() {
    // Lockstep protocols send one line and wait for the reply: the fully
    // substituted line must leave the machine before any further chunk.
    let grants = vec![Grant::Token {
      credential: Credential {
        label: "db".into(),
        fake: "FAKE1234".into(),
        value: secrecy::SecretString::from("REAL5678"),
      },
      allow: vec!["tcp://10.0.0.8:5432".parse().unwrap()],
      pattern: None,
      oauth2: None,
    }];
    let mut raw = Raw::new(&grants, Scheme::Tcp, "10.0.0.8", 5432, Direction::Downstream);
    let (out, hits) = {
      match raw.feed(b"auth FAKE1234\n").await {
        (Rewritten::Emit(bytes), hits) => (bytes, hits),
        _ => unreachable!("expected emit"),
      }
    };
    assert_eq!(out.as_ref(), b"auth REAL5678\n");
    assert_eq!(hits.len(), 1);
  }

  #[tokio::test]
  async fn raw_tls_mode_matches_https_grants() {
    // PlainMode::Raw behind terminated TLS: the endpoint identity is an
    // `https://` grant, so the raw machine must match it, not `tcp://`.
    let grants = vec![Grant::Token {
      credential: Credential {
        label: "api".into(),
        fake: "FAKE1234".into(),
        value: secrecy::SecretString::from("REAL5678"),
      },
      allow: vec!["https://api:9443".parse().unwrap()],
      pattern: None,
      oauth2: None,
    }];
    let mut req = Raw::new(&grants, Scheme::Https, "api", 9443, Direction::Downstream);
    let (out, hits) = {
      match req.feed(b"auth FAKE1234\n").await {
        (Rewritten::Emit(bytes), hits) => (bytes, hits),
        _ => unreachable!("expected emit"),
      }
    };
    assert_eq!(out.as_ref(), b"auth REAL5678\n");
    assert_eq!(hits.len(), 1);
    let mut resp = Raw::new(&grants, Scheme::Https, "api", 9443, Direction::Upstream);
    let (out, hits) = {
      match resp.feed(b"ok REAL5678\n").await {
        (Rewritten::Emit(bytes), hits) => (bytes, hits),
        _ => unreachable!("expected emit"),
      }
    };
    assert_eq!(out.as_ref(), b"ok FAKE1234\n");
    assert_eq!(hits.len(), 1);
  }

  /// A chunk that ends on a needle prefix holds those bytes. The next
  /// chunk, which does not complete the needle, must emit them. The
  /// hold-back stays a suffix no longer than the needle minus one.
  #[tokio::test]
  async fn held_prefix_is_emitted_when_the_next_chunk_misses() {
    const NEEDLE: &str = "real-smtp-pass-extended"; // betterleaks:allow
    const REPLACEMENT: &str = "fake-smtp-pass"; // betterleaks:allow
    let grants = vec![Grant::Token {
      credential: Credential {
        label: "smtp".into(),
        fake: REPLACEMENT.into(),
        value: secrecy::SecretString::from(NEEDLE),
      },
      allow: vec!["tcp://10.0.0.8:5432".parse().unwrap()],
      pattern: None,
      oauth2: None,
    }];
    let mut raw = Raw::length_changing(&grants, Scheme::Tcp, "10.0.0.8", 5432, Direction::Upstream);
    let first = format!("535 {}", &NEEDLE[..5]);
    let second = format!(" missed {}", &NEEDLE[..2]);
    let (head, head_hits) = match raw.feed(first.as_bytes()).await {
      (Rewritten::Emit(bytes), hits) => (bytes.into_owned(), hits),
      _ => unreachable!("expected emit"),
    };
    let (tail, tail_hits) = match raw.feed(second.as_bytes()).await {
      (Rewritten::Emit(bytes), hits) => (bytes.into_owned(), hits),
      _ => unreachable!("expected emit"),
    };
    let (flush, _) = match raw.feed(&[]).await {
      (Rewritten::Emit(bytes), hits) => (bytes.into_owned(), hits),
      _ => unreachable!("expected emit"),
    };
    assert_eq!(head, b"535 ");
    assert_eq!(tail, b"real- missed ");
    assert_eq!(flush, b"re");
    assert!(head_hits.is_empty(), "an unfinished prefix is not a hit");
    assert!(tail_hits.is_empty(), "a miss must not consume the held prefix");
    assert!(flush.len() <= NEEDLE.len().saturating_sub(1));
  }
}
