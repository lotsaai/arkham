//! Tests for the raw byte machine. The machine lives in `arkham-wire`.
//! [`raw_new`](crate::transports::engine::raw_new) keeps equal-length pairs.
//! A length-changing pair is passed through [`Raw::from_pairs`](arkham_wire::raw::Raw::from_pairs).

#[cfg(test)]
mod tests {
  use arkham_config::grants::{Credential, Grant, Scheme};
  use arkham_wire::engine::{Direction, Hit, Rewritten, Wire};
  use arkham_wire::raw::Raw;

  use crate::transports::engine::{eligible_pairs, raw_new};

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
    let mut raw = raw_new(&grants, Scheme::Tcp, "10.0.0.8", 5432, Direction::Downstream);
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
    let mut raw = raw_new(&grants, Scheme::Tcp, "10.0.0.8", 5432, Direction::Downstream);
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
    let mut raw = raw_new(&grants, Scheme::Tcp, "10.0.0.8", 5432, Direction::Downstream);
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
    let mut raw = raw_new(&grants, Scheme::Tcp, "10.0.0.8", 5432, Direction::Downstream);
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
    let mut req = raw_new(&grants, Scheme::Https, "api", 9443, Direction::Downstream);
    let (out, hits) = {
      match req.feed(b"auth FAKE1234\n").await {
        (Rewritten::Emit(bytes), hits) => (bytes, hits),
        _ => unreachable!("expected emit"),
      }
    };
    assert_eq!(out.as_ref(), b"auth REAL5678\n");
    assert_eq!(hits.len(), 1);
    let mut resp = raw_new(&grants, Scheme::Https, "api", 9443, Direction::Upstream);
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
    let mut raw = Raw::from_pairs(eligible_pairs(&grants, Scheme::Tcp, "10.0.0.8", 5432, Direction::Upstream));
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
