//! HTTP/1-family wire format: framing plus credential rewrite.

use std::borrow::Cow;

use base64::Engine as _;

use arkham_config::grants::{Grant, Scheme};
use arkham_plugin::{Head as PluginHead, Header as PluginHeader, RewriteHook, Verdict};

use crate::transports::engine::{
  CredentialPair, Direction, Hit, Location, MAX_MINT_BODY, MintPlan, PeerFact, Rewritten, Wire, eligible_pairs, max_tail_size,
  mint_and_redact, mint_plan_for, minted_pairs, needle_safe_emit_len, replace_bytes, replace_in, response_has_no_body, scan_with_tail,
};

/// Max buffered header block before degrading to opaque scan-only.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Max header fields per head block for httparse scratch space.
const MAX_HEADERS: usize = 128;
/// Per-state data lives in struct fields so the dispatch loop can match
/// by value and mutate freely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
  /// Accumulating a header block.
  Head,
  /// Streaming a fixed-length body through the hold-back window.
  Fixed,
  /// Streaming a chunked body; framing parsed incrementally.
  Chunked,
  /// Forwarding a known-length body unchanged, scanning for hits.
  Scan,
  /// Oversize head: forward + scan until the head boundary, then opaque.
  Drain,
  /// Forward + scan forever; framing unknowable.
  Opaque,
  /// Close-delimited response body: streams like Raw, flushes at EOF.
  CloseDelimited,
  /// Flow-granted token response: buffering the body whole to mint decoys;
  /// the head is held so `Content-Length` can be rewritten to the decoyed
  /// body's true length.
  MintBody,
}

/// Incremental chunked-framing parse phase (resumes across arrivals). No
/// body bytes are ever buffered: payload streams through the substitution
/// hold-back window as it arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkPhase {
  /// Reading a chunk-size line into `line_buf`.
  SizeLine,
  /// Inside chunk data, `data_remaining` bytes left (then CRLF).
  Data,
  /// Expecting the CRLF that terminates one chunk's data.
  AfterData,
  /// Reading the trailer block into `trailer_buf` until the empty line.
  Trailers,
  /// Definite framing violation: latch until the parser resets.
  Broken,
}

/// What to do with one framed body, decided at head time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyMode {
  /// Swap and run plugin hooks; lengths rewritten as needed.
  Substitute,
  /// Non-identity content-encoding: the bytes are opaque to us, scan only.
  ScanOnly,
}

/// One state step's outcome: remaining borrowed input, or spilled owned
/// bytes to re-loop on (message remainder following a completed message).
enum Step<'r> {
  Rest(&'r [u8]),
  Spill(Vec<u8>),
}

/// Per-connection, per-direction substitution machine.
///
/// Request direction substitutes eligible fakes→values; response direction
/// substitutes values→fakes for the same eligible set (redaction). Anything
/// unframable is forwarded unchanged with hits logged — never blocked.
/// Call [`Http::substitute`] with an empty chunk at stream EOF to
/// flush held bytes.
pub(crate) struct Http {
  pairs: Vec<CredentialPair>,
  dir: Direction,
  state: State,
  head_buf: Vec<u8>,
  /// Cross-arrival needle hold-back window, shared by the mutually
  /// exclusive Fixed / Chunked / `CloseDelimited` / Raw body states.
  raw_held: Vec<u8>,
  /// Partial chunk-size line (chunked framing).
  line_buf: Vec<u8>,
  /// Accumulated trailer block (chunked framing).
  trailer_buf: Vec<u8>,
  /// Incremental chunked framing: parse phase, validated prefix, violation.
  chunk_phase: ChunkPhase,
  /// Bytes left in the chunk-data region being consumed.
  data_remaining: usize,
  scan_tail: Vec<u8>,
  tail_size: usize,
  fixed_remaining: usize,
  /// Body treatment for the message in progress, set at head time.
  body_mode: BodyMode,
  scan_remaining: usize,
  /// Request side: HEAD heads seen, pending pickup by the relay.
  head_requests: usize,
  /// Response side: next N responses carry no body (HEAD requests).
  suppress_body: usize,
  /// Fail-closed latch: a scan-only path hit a needle it could not rewrite
  /// (compressed/oversize/opaque). The relay drops the connection.
  must_close: bool,
  /// Stage-1 plugin hook; `None` keeps today's value-swap-only behavior.
  hook: Option<Box<dyn RewriteHook>>,
  /// Static grant pairs from construction; `pairs` rebuilds from these
  /// whenever minted pairs refresh.
  static_pairs: Vec<CredentialPair>,
  /// Runtime mint store; `None` keeps value-swap-only behavior.
  mint: Option<crate::mint::MintStore>,
  /// Response side: the flow-granted grant's expectations, when this
  /// endpoint is a token issuer and this machine mints.
  mint_plan: Option<MintPlan>,
  /// Held head awaiting a minted body (`State::MintBody`).
  mint_head: Vec<u8>,
  /// Accumulated token-response body (`State::MintBody`).
  mint_body: Vec<u8>,
  /// Bytes still expected into `mint_body` (fixed framing); `None` for
  /// chunked accumulation.
  mint_remaining: Option<usize>,
}

impl Http {
  /// Build from the grants an `http://` or `https://` rule matched. The
  /// scheme only picks pairs; framing always starts at a head.
  #[must_use]
  pub fn new(
    grants: &[Grant],
    scheme: Scheme,
    host: &str,
    port: u16,
    dir: Direction,
    hook: Option<Box<dyn RewriteHook>>,
    mint: Option<crate::mint::MintStore>,
  ) -> Self {
    let static_pairs = eligible_pairs(grants, scheme, host, port, dir);
    let tail_size = max_tail_size(&static_pairs);
    // Response machines mint when a flow-granted grant matches this endpoint.
    let mint_plan = (dir == Direction::Upstream)
      .then(|| mint_plan_for(grants, scheme, host, port))
      .flatten();
    let mut wire = Self {
      pairs: static_pairs.clone(),
      dir,
      state: State::Head,
      head_buf: Vec::new(),
      raw_held: Vec::new(),
      line_buf: Vec::new(),
      trailer_buf: Vec::new(),
      chunk_phase: ChunkPhase::SizeLine,
      data_remaining: 0,
      scan_tail: Vec::new(),
      tail_size,
      fixed_remaining: 0,
      body_mode: BodyMode::Substitute,
      scan_remaining: 0,
      head_requests: 0,
      suppress_body: 0,
      must_close: false,
      hook,
      static_pairs,
      mint,
      mint_plan,
      mint_head: Vec::new(),
      mint_body: Vec::new(),
      mint_remaining: None,
    };
    // Both directions union the minted decoys at construction, so a decoy
    // minted on any connection substitutes or redacts on this one too.
    wire.refresh_minted_pairs();
    wire
  }

  /// Rebuild the active pair set: static grants plus every minted decoy.
  /// Called at construction and at each message head, so pairs minted
  /// mid-connection go live immediately.
  fn refresh_minted_pairs(&mut self) {
    if self.mint.is_none() {
      return;
    }
    let mut pairs = self.static_pairs.clone();
    if let Some(mint) = &self.mint {
      pairs.extend(minted_pairs(mint, self.dir));
    }
    self.tail_size = max_tail_size(&pairs);
    self.pairs = pairs;
  }

  /// Scan-only variant for tests: framing unknowable from the start.
  #[cfg(test)]
  #[must_use]
  pub fn opaque(grants: &[Grant], scheme: Scheme, host: &str, port: u16, dir: Direction) -> Self {
    let mut wire = Self::new(grants, scheme, host, port, dir, None, None);
    wire.state = State::Opaque;
    wire
  }
  pub async fn substitute<'a>(&mut self, chunk: &'a [u8]) -> (Cow<'a, [u8]>, Vec<Hit>) {
    if chunk.is_empty() {
      let (flushed, hits) = self.flush_held().await;
      return (Cow::Owned(flushed), hits);
    }
    // Opaque is pure passthrough: scan + forward unchanged, zero-copy.
    // Most close-delimited response bodies live here for their whole life.
    if self.state == State::Opaque {
      let hits = self.scan_chunk(chunk, Location::Body);
      if self.dir == Direction::Upstream && !hits.is_empty() {
        self.must_close = true;
      }
      self.fail_closed_on_degrade();
      return (Cow::Borrowed(chunk), hits);
    }
    let mut out = Vec::with_capacity(chunk.len());
    let mut hits = Vec::new();
    // Owned spillover for head/body leftovers: re-loop, never recurse —
    // pipelined messages per chunk are attacker-controlled.
    let mut owned: Vec<u8>;
    let mut rest = chunk;
    while !rest.is_empty() {
      let step = match self.state {
        State::Head => self.step_head(rest, &mut out, &mut hits).await,
        State::Fixed => self.step_fixed(rest, &mut out, &mut hits).await,
        State::Chunked => self.step_chunked(rest, &mut out, &mut hits).await,
        State::Scan => self.step_scan(rest, &mut out, &mut hits),
        State::Drain => self.step_drain(rest, &mut out, &mut hits),
        State::Opaque => {
          let scan_hits = self.scan_chunk(rest, Location::Body);
          if self.dir == Direction::Upstream && !scan_hits.is_empty() {
            self.must_close = true;
          }
          self.fail_closed_on_degrade();
          hits.extend(scan_hits);
          out.extend_from_slice(rest);
          Step::Rest(&[])
        }
        State::CloseDelimited => self.step_close(rest, &mut out, &mut hits).await,
        State::MintBody => self.step_mint(rest, &mut out, &mut hits),
      };
      match step {
        Step::Rest(remaining) => rest = remaining,
        Step::Spill(spill) => {
          if spill.is_empty() {
            break;
          }
          owned = spill;
          rest = &owned;
        }
      }
    }
    if out.as_slice() == chunk {
      (Cow::Borrowed(chunk), hits)
    } else {
      (Cow::Owned(out), hits)
    }
  }

  /// Head state: buffer until the `\r\n\r\n` boundary, then hand the head
  /// to `process_head` and re-loop on the remainder.
  async fn step_head<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let need = MAX_HEAD_BYTES.saturating_add(4).saturating_sub(self.head_buf.len());
    let take = need.min(rest.len());
    self.head_buf.extend_from_slice(&rest[..take]);
    let rest = &rest[take..];
    if let Some(end) = find_header_boundary(&self.head_buf) {
      // A new message starts: pairs minted since the last message (on this
      // or any connection) go live now.
      if self.mint.is_some() {
        self.refresh_minted_pairs();
      }
      let mut owned = std::mem::take(&mut self.head_buf);
      let mut combined = owned.split_off(end);
      let (head_out, head_hits) = self.process_head(owned).await;
      out.extend_from_slice(&head_out);
      hits.extend(head_hits);
      combined.extend_from_slice(rest);
      return Step::Spill(combined);
    }
    if self.head_buf.len() > MAX_HEAD_BYTES {
      // Oversize head: emit buffered bytes unchanged, drain to boundary.
      let buffered = std::mem::take(&mut self.head_buf);
      hits.extend(self.scan_chunk(&buffered, Location::Header));
      out.extend_from_slice(&buffered);
      self.state = State::Drain;
      self.fail_closed_on_degrade();
    }
    Step::Rest(rest)
  }

  /// Fixed-length body state: stream through the substitution hold-back
  /// window. The head was already emitted with its original
  /// `Content-Length`, so every emitted region must preserve length — a
  /// swap or hook that changes it latches `must_close` rather than
  /// desynchronizing the peer's framing.
  async fn step_fixed<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let take = self.fixed_remaining.min(rest.len());
    let (data, rest) = rest.split_at(take);
    self.fixed_remaining -= take;
    let eof = self.fixed_remaining == 0;
    match self.swap_region(data, eof, hits).await {
      None => Step::Rest(&[]),
      Some((emit_len, region)) => {
        if region.len() != emit_len {
          // Content-Length framing forbids any drift.
          self.must_close = true;
          return Step::Rest(&[]);
        }
        out.extend_from_slice(&region);
        if eof {
          self.state = State::Head;
        }
        Step::Rest(rest)
      }
    }
  }

  /// Chunked body state: incremental framing parser. Payload streams
  /// through the hold-back window and is re-chunked as it is emitted; the
  /// trailer block (bounded by `MAX_HEAD_BYTES`) is swapped and hooked at
  /// the terminal chunk. No body bytes are ever buffered whole.
  async fn step_chunked<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let mut rest = rest;
    loop {
      match self.chunk_phase {
        ChunkPhase::Broken => {
          self.forward_scanned(rest, out, hits);
          self.state = State::Opaque;
          self.fail_closed_on_degrade();
          return Step::Rest(&[]);
        }
        ChunkPhase::SizeLine | ChunkPhase::Trailers => {
          let Some((line, tail)) = self.take_line(rest) else {
            self.line_buf.extend_from_slice(rest);
            if self.line_buf.len() > MAX_HEAD_BYTES
              || (self.chunk_phase == ChunkPhase::Trailers && self.trailer_buf.len() + self.line_buf.len() > MAX_HEAD_BYTES)
            {
              // An unbounded size or trailer line is malformed framing.
              let buffered = std::mem::take(&mut self.line_buf);
              self.forward_scanned(&buffered, out, hits);
              self.chunk_phase = ChunkPhase::Broken;
              continue;
            }
            return Step::Rest(&[]);
          };
          rest = tail;
          match self.chunk_phase {
            ChunkPhase::SizeLine => {
              match parse_chunk_size(&line) {
                Some(0) => {
                  if self.body_mode == BodyMode::ScanOnly {
                    out.extend_from_slice(&line);
                    out.extend_from_slice(b"\r\n");
                    out.extend_from_slice(b"\r\n"); // empty trailer line
                    self.finish_chunked_message();
                    return Step::Rest(rest);
                  }
                  // Terminal chunk: flush the held window (eof region),
                  // then the terminator.
                  match self.swap_region(&[], true, hits).await {
                    None => return Step::Rest(&[]),
                    Some((_, region)) => {
                      Self::emit_data_chunk(out, &region);
                      out.extend_from_slice(b"0\r\n");
                      self.chunk_phase = ChunkPhase::Trailers;
                    }
                  }
                }
                Some(size) => {
                  if self.body_mode == BodyMode::ScanOnly {
                    out.extend_from_slice(&line);
                    out.extend_from_slice(b"\r\n");
                  }
                  self.data_remaining = size;
                  self.chunk_phase = ChunkPhase::Data;
                }
                None => {
                  self.forward_scanned(&line, out, hits);
                  out.extend_from_slice(b"\r\n");
                  self.chunk_phase = ChunkPhase::Broken;
                }
              }
            }
            ChunkPhase::Trailers => {
              if line.is_empty() {
                if self.body_mode == BodyMode::ScanOnly {
                  out.extend_from_slice(b"\r\n");
                } else {
                  let mut block = std::mem::take(&mut self.trailer_buf);
                  if let Some(trailers) = self.rewrite_trailer_block(&mut block, hits).await {
                    out.extend_from_slice(&trailers);
                  } else {
                    return Step::Rest(&[]);
                  }
                }
                self.finish_chunked_message();
                return Step::Rest(rest);
              }
              self.trailer_buf.extend_from_slice(&line);
              self.trailer_buf.extend_from_slice(b"\r\n");
            }
            // The outer arm guards these phases; a future refactor that
            // breaks that guard must degrade, not panic, on the wire.
            ChunkPhase::Data | ChunkPhase::AfterData | ChunkPhase::Broken => {
              self.chunk_phase = ChunkPhase::Broken;
            }
          }
        }
        ChunkPhase::Data => match self.step_chunked_data(rest, out, hits).await {
          Some(remaining) => rest = remaining,
          None => return Step::Rest(&[]),
        },
        ChunkPhase::AfterData => match self.step_chunked_after_data(rest, out, hits) {
          Some(remaining) => rest = remaining,
          None => return Step::Rest(&[]),
        },
      }
    }
  }

  /// `ChunkPhase::Data`: consume up to `data_remaining` bytes of payload
  /// through the substitution window. `None` parks the parser for the next
  /// arrival.
  async fn step_chunked_data<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Option<&'r [u8]> {
    if rest.is_empty() && self.data_remaining > 0 {
      // Nothing to consume this iteration: wait for the next arrival
      // (never spin re-emitting the held window).
      return None;
    }
    let take = self.data_remaining.min(rest.len());
    let (payload, tail) = rest.split_at(take);
    self.data_remaining -= take;
    match self.body_mode {
      BodyMode::Substitute => match self.swap_region(payload, false, hits).await {
        None => return None,
        Some((_, region)) => Self::emit_data_chunk(out, &region),
      },
      BodyMode::ScanOnly => self.forward_scanned(payload, out, hits),
    }
    if self.data_remaining == 0 {
      self.chunk_phase = ChunkPhase::AfterData;
    }
    Some(tail)
  }

  /// `ChunkPhase::AfterData`: consume the CRLF that terminates one chunk's
  /// data region (a lone `\r` may straddle arrivals). `None` parks.
  fn step_chunked_after_data<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Option<&'r [u8]> {
    if !self.line_buf.is_empty() {
      // A lone `\r` stashed from the previous arrival.
      if rest.is_empty() {
        return None;
      }
      let pending = std::mem::take(&mut self.line_buf);
      if rest[0] == b'\n' {
        if self.body_mode == BodyMode::ScanOnly {
          out.extend_from_slice(b"\r\n");
        }
        self.chunk_phase = ChunkPhase::SizeLine;
        return Some(&rest[1..]);
      }
      self.forward_scanned(&pending, out, hits);
      self.chunk_phase = ChunkPhase::Broken;
      return Some(&rest[1..]);
    }
    if rest.is_empty() {
      return None;
    }
    if rest.len() >= 2 {
      if &rest[..2] == b"\r\n" {
        // Substitute mode's re-chunk already closed its chunk; only
        // the verbatim scan-only path must forward the delimiter.
        if self.body_mode == BodyMode::ScanOnly {
          out.extend_from_slice(b"\r\n");
        }
        self.chunk_phase = ChunkPhase::SizeLine;
        Some(&rest[2..])
      } else {
        self.forward_scanned(&rest[..2], out, hits);
        self.chunk_phase = ChunkPhase::Broken;
        Some(&rest[2..])
      }
    } else if rest[0] == b'\r' {
      // Half a delimiter: hold for the next arrival.
      self.line_buf.push(b'\r');
      None
    } else {
      self.forward_scanned(&rest[..1], out, hits);
      self.chunk_phase = ChunkPhase::Broken;
      Some(&rest[1..])
    }
  }
  /// Reset the incremental chunked parser for the next message.
  fn finish_chunked_message(&mut self) {
    self.line_buf.clear();
    self.trailer_buf.clear();
    self.data_remaining = 0;
    self.chunk_phase = ChunkPhase::SizeLine;
    self.state = State::Head;
  }

  /// Pull one CRLF-terminated line from `rest`, prepending any partial
  /// bytes buffered in `line_buf`. Returns `None` (with the fragment left
  /// buffered by the caller) when no complete line has arrived; a CRLF
  /// straddling the buffer boundary is still found.
  fn take_line<'r>(&mut self, rest: &'r [u8]) -> Option<(Vec<u8>, &'r [u8])> {
    if self.line_buf.last() == Some(&b'\r') && rest.first() == Some(&b'\n') {
      let mut line = std::mem::take(&mut self.line_buf);
      line.pop();
      return Some((line, &rest[1..]));
    }
    let rel = find_crlf(rest)?;
    let mut line = std::mem::take(&mut self.line_buf);
    line.extend_from_slice(&rest[..rel]);
    Some((line, &rest[rel + 2..]))
  }

  /// Substitute (stage 0) and hook (stage 1) one body region, carrying the
  /// needle hold-back window across arrivals. Returns the consumed input
  /// length and the region to emit, or `None` when the hook voted `Close`
  /// (latched). At `eof` the window flushes and the hook always gets its
  /// final call, even with an empty region, so plugins holding guest
  /// memory release it.
  async fn swap_region(&mut self, data: &[u8], eof: bool, hits: &mut Vec<Hit>) -> Option<(usize, Vec<u8>)> {
    let mut combined = std::mem::take(&mut self.raw_held);
    combined.extend_from_slice(data);
    let emit_len = if eof {
      combined.len()
    } else {
      needle_safe_emit_len(&combined, &self.pairs, self.tail_size)
    };
    let (region, mut region_hits) = replace_in(&combined[..emit_len], &self.pairs, Location::Body);
    let mut region = region.into_owned();
    hits.append(&mut region_hits);
    self.raw_held = combined.split_off(emit_len);
    if region.is_empty() && !eof {
      return Some((emit_len, region));
    }
    if let Some(hook) = self.hook.as_mut()
      && hook.rewrite_chunk(&mut region, eof).await == Verdict::Close
    {
      self.must_close = true;
      return None;
    }
    Some((emit_len, region))
  }

  /// Wrap one emitted payload region in chunked framing. Empty regions
  /// emit nothing: a zero-length chunk is the terminator, never data.
  fn emit_data_chunk(out: &mut Vec<u8>, region: &[u8]) {
    if region.is_empty() {
      return;
    }
    out.extend_from_slice(format!("{:X}\r\n", region.len()).as_bytes());
    out.extend_from_slice(region);
    out.extend_from_slice(b"\r\n");
  }

  /// Swap and hook one complete trailer block (without its final CRLF).
  /// Returns the serialized block (final CRLF included) or `None` when
  /// the hook voted `Close`.
  async fn rewrite_trailer_block(&mut self, block: &mut [u8], hits: &mut Vec<Hit>) -> Option<Vec<u8>> {
    let (swapped, trailer_hits) = replace_in(block, &self.pairs, Location::Body);
    hits.extend(trailer_hits);
    let mut headers = parse_trailer_block(&swapped);
    if !headers.is_empty()
      && let Some(hook) = self.hook.as_mut()
      && hook.rewrite_trailers(&mut headers).await == Verdict::Close
    {
      self.must_close = true;
      return None;
    }
    Some(serialize_trailer_block(&headers))
  }

  /// Scan-only forward: hits logged, response-direction hits latch close.
  fn forward_scanned(&mut self, data: &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) {
    let scan_hits = self.scan_chunk(data, Location::Body);
    if self.dir == Direction::Upstream && !scan_hits.is_empty() {
      self.must_close = true;
    }
    hits.extend(scan_hits);
    out.extend_from_slice(data);
  }

  /// Scan state: forward a body of known length unchanged, scanning for
  /// hits (compressed or otherwise opaque to substitution).
  fn step_scan<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let take = self.scan_remaining.min(rest.len());
    let (data, rest) = rest.split_at(take);
    self.forward_scanned(data, out, hits);
    self.scan_remaining -= take;
    if self.scan_remaining == 0 {
      self.state = State::Head;
    }
    Step::Rest(rest)
  }

  /// Drain state: resync at the next boundary instead of swallowing opaque.
  fn step_drain<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let Some(end) = find_header_boundary(rest) else {
      self.forward_scanned(rest, out, hits);
      self.state = State::Opaque;
      self.fail_closed_on_degrade();
      return Step::Rest(&[]);
    };
    let (head, tail) = rest.split_at(end);
    self.forward_scanned(head, out, hits);
    self.state = State::Head;
    if tail.is_empty() {
      Step::Rest(&[])
    } else {
      // `tail` is a suffix of the borrowed chunk — return it borrowed
      // instead of copying through an owned spill.
      Step::Rest(tail)
    }
  }

  /// Close-delimited response body: stream through the hold-back window.
  /// No framing means no length constraint; EOF flushes the window.
  async fn step_close<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    if let Some((_, region)) = self.swap_region(rest, false, hits).await {
      out.extend_from_slice(&region);
    }
    Step::Rest(&[])
  }

  /// Mint-body state: accumulate the token response, then mint. The head is
  /// held in `mint_head`; both emit together once the body is complete so
  /// `Content-Length` can tell the truth about the decoyed body.
  fn step_mint<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let Some(remaining) = self.mint_remaining else {
      // Chunked: accumulate raw framing bytes until the terminator.
      self.mint_body.extend_from_slice(rest);
      if self.mint_body.len() > MAX_MINT_BODY + 4096 {
        self.must_close = true;
        return Step::Rest(&[]);
      }
      if find_chunked_terminator(&self.mint_body) {
        let head = std::mem::take(&mut self.mint_head);
        let body = std::mem::take(&mut self.mint_body);
        let (emitted, mint_hits) = self.finish_mint_chunked(&head, &body);
        hits.extend(mint_hits);
        out.extend_from_slice(&emitted);
        self.state = State::Head;
      }
      return Step::Rest(&[]);
    };
    let take = remaining.min(rest.len());
    self.mint_body.extend_from_slice(&rest[..take]);
    self.mint_remaining = Some(remaining - take);
    let rest = &rest[take..];
    if self.mint_remaining == Some(0) {
      self.mint_remaining = None;
      let head = std::mem::take(&mut self.mint_head);
      let body = std::mem::take(&mut self.mint_body);
      let (emitted, mint_hits) = self.finish_mint_fixed(&head, &body);
      hits.extend(mint_hits);
      out.extend_from_slice(&emitted);
      self.state = State::Head;
    }
    Step::Rest(rest)
  }

  /// Mint the buffered fixed-length body, rewrite the head's
  /// `Content-Length`, and emit head + body.
  fn finish_mint_fixed(&mut self, head: &[u8], body: &[u8]) -> (Vec<u8>, Vec<Hit>) {
    let (body, hits) = self.mint_and_redact(body);
    let mut out = rewrite_content_length(head, body.len());
    out.extend_from_slice(&body);
    (out, hits)
  }

  /// De-chunk the buffered body, mint, re-emit as a single chunk plus the
  /// terminator. The terminator was validated by [`find_chunked_terminator`].
  fn finish_mint_chunked(&mut self, head: &[u8], body: &[u8]) -> (Vec<u8>, Vec<Hit>) {
    let Some(payload) = dechunk(body) else {
      // Framing violated after all: fail closed rather than emit a lie.
      self.must_close = true;
      return (Vec::new(), Vec::new());
    };
    let (payload, hits) = self.mint_and_redact(&payload);
    let mut out = head.to_vec();
    out.extend_from_slice(format!("{:X}\r\n", payload.len()).as_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(b"\r\n0\r\n\r\n");
    (out, hits)
  }

  /// Mint + redact through the shared body walk; when the plan or handle
  /// went missing mid-stream the pair redaction still applies.
  fn mint_and_redact(&mut self, body: &[u8]) -> (Vec<u8>, Vec<Hit>) {
    if let (Some(plan), Some(mint)) = (&self.mint_plan, &self.mint) {
      mint_and_redact(plan, mint, body, &self.pairs)
    } else {
      let (redacted, hits) = replace_in(body, &self.pairs, Location::Body);
      (redacted.into_owned(), hits)
    }
  }

  /// Substitute a complete head block (ending exactly at the boundary) and
  /// set the body state. Returns the head bytes to emit plus hits.
  /// Stage order: value swap first (stage 0), then the plugin hook on the
  /// swapped head (stage 1). Without a hook the swapped bytes flow through
  /// the same arms as before.
  async fn process_head(&mut self, head: Vec<u8>) -> (Vec<u8>, Vec<Hit>) {
    let Ok(head_str) = std::str::from_utf8(&head) else {
      let hits = self.scan_chunk(&head, Location::Header);
      self.state = State::Opaque;
      self.fail_closed_on_degrade();
      return (head, hits);
    };
    if parse_head_fields(&head, self.dir).is_err() {
      // Unparseable head: still substitute header lines (fully buffered),
      // then opaque — the body boundary is unknowable.
      let (new_head, hits) = substitute_head(head_str, &self.pairs);
      self.state = State::Opaque;
      self.fail_closed_on_degrade();
      return (new_head, hits);
    }
    // Stage 0: the value swap, computed once and reused in every arm.
    let (mut new_head, hits) = substitute_head(head_str, &self.pairs);
    if self.hook.is_some() {
      // Stage 1: on `Close` the swapped bytes are returned unchanged; the
      // latched relay drops the connection before they reach the wire.
      if !self.rewrite_head_hooked(&mut new_head).await {
        return (new_head, hits);
      }
    }
    // Framing classification on the final (possibly hooked) head.
    let Ok(final_head) = parse_head_fields(&new_head, self.dir) else {
      // Only a hook can make a parsed head unparseable: fail closed.
      self.must_close = true;
      self.state = State::Opaque;
      return (new_head, hits);
    };
    let framing = parse_framing(&final_head.headers);
    let content_swapped = has_non_identity_content_encoding(&final_head.headers);
    let status = final_head.status;
    let is_head_request = final_head.method.is_some_and(|m| m.eq_ignore_ascii_case("head"));
    // HEAD is counted only on framable messages so the response side never
    // suppresses wrongly; the response no-body handling likewise runs only
    // on framable messages (Broken substitutes headers then goes opaque).
    let framable = !matches!(framing, Framing::Broken);
    if framable && self.dir == Direction::Downstream && is_head_request {
      self.head_requests += 1;
    }
    if framable && self.dir == Direction::Upstream {
      // 1xx/204/304 never carry a body, whatever the framing claims.
      // HEAD responses never carry a body either (signalled per-request).
      let interim = matches!(status, Some(100..200));
      if response_has_no_body(status) {
        // Interim 1xx keeps a pending HEAD suppression for the final response.
        if !interim && self.suppress_body > 0 {
          self.suppress_body -= 1;
        }
        self.state = State::Head;
        return (new_head, hits);
      }
      if self.suppress_body > 0 {
        self.suppress_body -= 1;
        self.state = State::Head;
        return (new_head, hits);
      }
    }
    self.enter_framing_state(new_head, hits, framing, content_swapped, status)
  }

  /// Set the body state from the (possibly hooked) head's framing class.
  /// The head is always emitted immediately: every body state streams, so
  /// nothing is ever parked waiting for a length rewrite.
  fn enter_framing_state(
    &mut self,
    new_head: Vec<u8>,
    hits: Vec<Hit>,
    framing: Framing,
    content_swapped: bool,
    status: Option<u16>,
  ) -> (Vec<u8>, Vec<Hit>) {
    // Flow-granted token responses buffer whole for minting, on the
    // framings that carry a decodable body. Compressed bodies are opaque
    // to us: fall through to today's scan-only behavior. This is the one
    // deliberate exception to "the head is always emitted immediately":
    // minting rewrites `Content-Length`, so head and body emit together.
    let mint_fixed = matches!(framing, Framing::Fixed { len } if len <= MAX_MINT_BODY);
    let mint_chunked = matches!(framing, Framing::Chunked);
    if self.dir == Direction::Upstream
      && self.mint.is_some()
      && self.mint_plan.is_some()
      && !content_swapped
      && (mint_fixed || mint_chunked)
    {
      if let Framing::Fixed { len } = framing {
        self.mint_remaining = Some(len);
      } else {
        self.mint_remaining = None;
      }
      self.mint_head = new_head;
      self.mint_body.clear();
      self.state = State::MintBody;
      return (Vec::new(), hits);
    }
    match framing {
      Framing::Broken => {
        self.state = State::Opaque;
        self.fail_closed_on_degrade();
        (new_head, hits)
      }
      Framing::Chunked => {
        self.body_mode = if content_swapped {
          BodyMode::ScanOnly
        } else {
          BodyMode::Substitute
        };
        if self.body_mode == BodyMode::ScanOnly {
          self.fail_closed_on_degrade();
        }
        self.line_buf.clear();
        self.trailer_buf.clear();
        self.data_remaining = 0;
        self.chunk_phase = ChunkPhase::SizeLine;
        self.state = State::Chunked;
        (new_head, hits)
      }
      Framing::Fixed { len } => {
        if len == 0 {
          // Empty body: nothing left to wait for.
          self.state = State::Head;
        } else if content_swapped {
          // Compressed (or otherwise opaque) body: scan-only forward of
          // the declared length; substitution cannot apply.
          self.scan_remaining = len;
          self.state = State::Scan;
          self.fail_closed_on_degrade();
        } else {
          self.fixed_remaining = len;
          self.state = State::Fixed;
        }
        (new_head, hits)
      }
      Framing::None => {
        if self.dir == Direction::Upstream && !response_has_no_body(status) {
          // Close-delimited response body: framing unknowable. With pairs,
          // stream through the hold-back window and flush at EOF; without
          // pairs, zero-copy opaque passthrough stays byte-identical.
          if self.pairs.is_empty() {
            self.state = State::Opaque;
            self.fail_closed_on_degrade();
          } else {
            self.state = State::CloseDelimited;
          }
        } else {
          self.state = State::Head;
        }
        (new_head, hits)
      }
    }
  }

  /// Stage-1 head hook: `head_bytes` holds the swapped head. Re-parse it so
  /// the plugin sees post-swap values, run the hook, rebuild on change.
  /// Returns `false` on `Close` (latched; emit the swapped bytes unchanged).
  async fn rewrite_head_hooked(&mut self, head_bytes: &mut Vec<u8>) -> bool {
    let dir = self.dir;
    let Ok(swapped) = parse_head_fields(head_bytes, dir) else {
      // Swap output always parses; nothing to hook, keep going.
      return true;
    };
    let mut plugin_head = plugin_head_from_parsed(&swapped, dir);
    let Some(hook) = self.hook.as_mut() else {
      return true;
    };
    if hook.rewrite_head(&mut plugin_head).await == Verdict::Close {
      self.must_close = true;
      return false;
    }
    let rebuilt = rebuild_head_if_changed(&plugin_head, &swapped, head_bytes, dir);
    if let Some(rebuilt) = rebuilt {
      *head_bytes = rebuilt;
    }
    true
  }

  /// Emit everything held (partial message) unchanged. The raw tail is
  /// substituted: at EOF the data is complete.
  async fn flush_held(&mut self) -> (Vec<u8>, Vec<Hit>) {
    let mut out = Vec::new();

    let mut hits = Vec::new();
    out.extend_from_slice(std::mem::take(&mut self.head_buf).as_slice());
    match self.state {
      State::Fixed | State::CloseDelimited => {
        // EOF mid-message: the held window is complete data now. The eof
        // hook call runs even when the region is empty so plugins holding
        // guest memory release it.
        if let Some((emit_len, region)) = self.swap_region(&[], true, &mut hits).await {
          if self.state == State::Fixed && region.len() != emit_len {
            // Truncated fixed body whose swap changed length: framing is
            // already broken; drop rather than emit a lie.
            self.must_close = true;
          } else {
            out.extend_from_slice(&region);
          }
        }
      }
      State::Chunked => {
        // EOF mid-message: forward the framing fragments verbatim, then
        // the held (substituted) payload remainder, unframed — the
        // message was truncated; the connection is closing anyway.
        out.extend_from_slice(std::mem::take(&mut self.line_buf).as_slice());
        out.extend_from_slice(std::mem::take(&mut self.trailer_buf).as_slice());
        if let Some((_, region)) = self.swap_region(&[], true, &mut hits).await {
          out.extend_from_slice(&region);
        }
      }
      State::MintBody => {
        // EOF mid-token-response: mint what arrived. A truncated body
        // emits with its true rewritten length; the connection is
        // closing, so the framing lie does not outlive it.
        let head = std::mem::take(&mut self.mint_head);
        let body = std::mem::take(&mut self.mint_body);
        if self.mint_remaining.is_some() {
          self.must_close = true;
          let (emitted, mint_hits) = self.mint_and_redact(&body);
          hits.extend(mint_hits);
          let mut all = rewrite_content_length(&head, emitted.len());
          all.extend_from_slice(&emitted);
          out.extend_from_slice(&all);
        } else if let Some(payload) = dechunk(&body) {
          let (emitted, mint_hits) = self.mint_and_redact(&payload);
          hits.extend(mint_hits);
          let mut all = head;
          all.extend_from_slice(format!("{:X}\r\n", emitted.len()).as_bytes());
          all.extend_from_slice(&emitted);
          out.extend_from_slice(&all);
        } else {
          self.must_close = true;
          out.extend_from_slice(&body);
        }
      }
      _ => {}
    }
    self.state = State::Opaque;
    (out, hits)
  }

  /// Latch fail-closed when a plugin-active connection degrades to an
  /// unframable path: an unsigned body must not silently pass.
  fn fail_closed_on_degrade(&mut self) {
    if self.hook.is_some() {
      self.must_close = true;
    }
  }

  /// Scan `data` (plus overlap tail) for needles; updates the tail.
  fn scan_chunk(&mut self, data: &[u8], location: Location) -> Vec<Hit> {
    scan_with_tail(&self.pairs, &mut self.scan_tail, self.tail_size, data, location)
  }
}

#[derive(Clone, Copy)]
enum Framing {
  Broken,
  Chunked,
  Fixed { len: usize },
  None,
}
/// A parsed head block: fields plus direction-specific extras.
struct ParsedHead<'h> {
  headers: Vec<httparse::Header<'h>>,
  /// Response status code (`None` for requests).
  status: Option<u16>,
  /// Request method (`None` for responses).
  method: Option<&'h str>,
  /// Request target (`None` for responses).
  path: Option<&'h str>,
  /// HTTP version (0 = 1.0, 1 = 1.1).
  version: Option<u8>,
  /// Response reason phrase (`None` for requests).
  reason: Option<&'h str>,
}

/// Parse a complete head block with httparse (request or response per `dir`).
/// Err on any parse failure or header overflow — the caller degrades to
/// opaque scan-only forwarding.
fn parse_head_fields(head: &[u8], dir: Direction) -> Result<ParsedHead<'_>, ()> {
  let mut scratch = [httparse::EMPTY_HEADER; MAX_HEADERS];
  match dir {
    Direction::Downstream => {
      let mut req = httparse::Request::new(&mut scratch);
      match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => Ok(ParsedHead {
          headers: req.headers.to_vec(),
          status: None,
          method: req.method,
          path: req.path,
          version: req.version,
          reason: None,
        }),
        _ => Err(()),
      }
    }
    Direction::Upstream => {
      let mut resp = httparse::Response::new(&mut scratch);
      match resp.parse(head) {
        Ok(httparse::Status::Complete(_)) => Ok(ParsedHead {
          headers: resp.headers.to_vec(),
          status: resp.code,
          method: None,
          path: None,
          version: resp.version,
          reason: resp.reason,
        }),
        _ => Err(()),
      }
    }
  }
}

/// Framing classification from parsed header fields.
fn parse_framing(headers: &[httparse::Header<'_>]) -> Framing {
  match (parse_transfer_encoding(headers), parse_content_length(headers)) {
    (Err(()), _) | (_, Err(())) | (Ok(true), Ok(Some(_))) => Framing::Broken, // TE + CL: ambiguous
    (Ok(true), Ok(None)) => Framing::Chunked,
    (Ok(false), Ok(Some(len))) => Framing::Fixed { len },
    (Ok(false), Ok(None)) => Framing::None,
  }
}

/// Read `Transfer-Encoding` fields: Ok(true) = chunked, Ok(false) = absent.
/// Err on any other coding or a repeated chunked.
fn parse_transfer_encoding(headers: &[httparse::Header<'_>]) -> Result<bool, ()> {
  let mut saw_chunked = false;
  for header in headers {
    if !header.name.eq_ignore_ascii_case("transfer-encoding") {
      continue;
    }
    let Ok(value) = std::str::from_utf8(header.value) else {
      return Err(());
    };
    for coding in value.split(',') {
      let coding = coding.trim();
      let coding_name = coding.split_once(';').map_or(coding, |(name, _)| name).trim();
      if coding_name.is_empty() || !coding_name.eq_ignore_ascii_case("chunked") {
        return Err(());
      }
      if saw_chunked {
        return Err(());
      }
      saw_chunked = true;
    }
  }
  Ok(saw_chunked)
}

/// Read `Content-Length` fields: Err on malformed or conflicting values.
fn parse_content_length(headers: &[httparse::Header<'_>]) -> Result<Option<usize>, ()> {
  let mut content_length = None;
  for header in headers {
    if !header.name.eq_ignore_ascii_case("content-length") {
      continue;
    }
    let Ok(value) = std::str::from_utf8(header.value) else {
      return Err(());
    };
    let Ok(parsed) = value.trim().parse::<usize>() else {
      return Err(());
    };
    if content_length.is_some_and(|existing| existing != parsed) {
      return Err(());
    }
    content_length = Some(parsed);
  }
  Ok(content_length)
}

fn has_non_identity_content_encoding(headers: &[httparse::Header<'_>]) -> bool {
  headers
    .iter()
    .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
    .any(|header| {
      let Ok(value) = std::str::from_utf8(header.value) else {
        return true;
      };
      value.split(',').any(|encoding| !encoding.trim().eq_ignore_ascii_case("identity"))
    })
}

/// Substitute all pairs in a head block: Basic-auth lines first (decoded),
/// then raw byte replace on every line except `Host` (routing safety,
/// mirroring the H2 `:authority` skip). Returns the new head + hits.
fn substitute_head(head_str: &str, pairs: &[CredentialPair]) -> (Vec<u8>, Vec<Hit>) {
  let mut current = head_str.to_string();
  let mut hits = Vec::new();
  for pair in pairs {
    let Ok(needle) = std::str::from_utf8(&pair.needle) else {
      continue;
    };
    let Ok(replacement) = std::str::from_utf8(&pair.replacement) else {
      continue;
    };
    if substitute_basic_lines(&mut current, needle, replacement) {
      hits.push(Hit {
        label: pair.label.clone(),
        location: Location::BasicAuth,
      });
    }
  }
  // `current` derives from `&str`, so per-line buffers stay UTF-8: needles
  // and replacements are config strings, never arbitrary bytes.
  let mut replaced = vec![false; pairs.len()];
  let mut out = String::with_capacity(current.len());
  for (i, line) in current.split("\r\n").enumerate() {
    if i > 0 {
      out.push_str("\r\n");
    }
    if line.split_once(':').is_some_and(|(name, _)| name.eq_ignore_ascii_case("host")) {
      out.push_str(line);
      continue;
    }
    let mut buf = line.as_bytes().to_vec();
    for (pi, pair) in pairs.iter().enumerate() {
      if let Some(next) = replace_bytes(&buf, &pair.needle, &pair.replacement) {
        buf = next;
        replaced[pi] = true;
      }
    }
    out.push_str(&String::from_utf8_lossy(&buf));
  }
  for (pi, pair) in pairs.iter().enumerate() {
    if replaced[pi] {
      hits.push(Hit {
        label: pair.label.clone(),
        location: Location::Header,
      });
    }
  }
  (out.into_bytes(), hits)
}

/// Substitute inside `Authorization: Basic` lines (decode → replace →
/// re-encode). Returns true when any line changed.
fn substitute_basic_lines(head: &mut String, needle: &str, replacement: &str) -> bool {
  let mut changed = false;
  let mut out = String::with_capacity(head.len());
  for (i, line) in head.split("\r\n").enumerate() {
    if i > 0 {
      out.push_str("\r\n");
    }
    let Some((name, value)) = line.split_once(':') else {
      out.push_str(line);
      continue;
    };
    if !name.eq_ignore_ascii_case("authorization") {
      out.push_str(line);
      continue;
    }
    let value = value.trim_start();
    let Some(split_at) = value.find(char::is_whitespace) else {
      out.push_str(line);
      continue;
    };
    let (scheme, encoded) = value.split_at(split_at);
    if !scheme.eq_ignore_ascii_case("basic") {
      out.push_str(line);
      continue;
    }
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
      out.push_str(line);
      continue;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
      out.push_str(line);
      continue;
    };
    if !decoded.contains(needle) {
      out.push_str(line);
      continue;
    }
    let replaced = decoded.replace(needle, replacement);
    out.push_str(name);
    out.push_str(": Basic ");
    out.push_str(&base64::engine::general_purpose::STANDARD.encode(replaced.as_bytes()));
    changed = true;
  }
  *head = out;
  changed
}

fn find_header_boundary(data: &[u8]) -> Option<usize> {
  data.windows(4).position(|w| w == b"\r\n\r\n").map(|pos| pos + 4)
}

/// Rewrite (or append) `Content-Length` in a response head to the minted
/// body's true length. The head ends exactly at the `\r\n\r\n` boundary.
fn rewrite_content_length(head: &[u8], len: usize) -> Vec<u8> {
  use std::fmt::Write as _;

  let boundary = find_header_boundary(head).unwrap_or(head.len());
  let (head_end, _) = head.split_at(boundary);
  let text = String::from_utf8_lossy(head_end);
  let mut replaced = false;
  let mut out = String::with_capacity(head_end.len());
  for (i, line) in text.split("\r\n").enumerate() {
    if i > 0 {
      out.push_str("\r\n");
    }
    if line
      .split_once(':')
      .is_some_and(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
      let _ = write!(out, "Content-Length: {len}");
      replaced = true;
    } else {
      out.push_str(line);
    }
  }
  if !replaced {
    // No Content-Length to rewrite: the mint path is only entered from a
    // Fixed framing, which requires one. Defensive: re-add it.
    let insert = out.len() - 2;
    let line = format!("Content-Length: {len}\r\n");
    out.insert_str(insert, &line);
  }
  out.into_bytes()
}

/// True when a buffered chunked body reaches its terminator (`0\r\n\r\n`).
/// A payload byte sequence that mimics the terminator makes `dechunk`
/// fail validation and fail closed, so an early match is safe.
fn find_chunked_terminator(data: &[u8]) -> bool {
  const NEEDLE_A: &[u8] = b"\r\n0\r\n\r\n";
  const NEEDLE_B: &[u8] = b"0\r\n\r\n";
  data.windows(NEEDLE_A.len()).any(|w| w == NEEDLE_A) || data.starts_with(NEEDLE_B)
}

/// Decode a complete buffered chunked body to its payload.
/// Returns `None` on any framing violation.
fn dechunk(data: &[u8]) -> Option<Vec<u8>> {
  let mut out = Vec::new();
  let mut rest = data;
  loop {
    let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
    let size_line = &rest[..line_end];
    let size = parse_chunk_size(size_line)?;
    rest = &rest[line_end + 2..];
    if size == 0 {
      return Some(out);
    }
    if rest.len() < size + 2 {
      return None;
    }
    out.extend_from_slice(&rest[..size]);
    rest = &rest[size + 2..];
  }
}

/// Build the owned plugin head from a swapped parse: request carries method
/// plus the request-target token, responses carry the status code.
fn plugin_head_from_parsed(parsed: &ParsedHead<'_>, dir: Direction) -> PluginHead {
  let headers = parsed
    .headers
    .iter()
    .map(|header| PluginHeader {
      name: header.name.to_string(),
      value: header.value.to_vec(),
    })
    .collect();
  match dir {
    Direction::Downstream => PluginHead::Request {
      method: parsed.method.unwrap_or_default().to_string(),
      path_with_query: parsed.path.unwrap_or_default().to_string(),
      headers,
    },
    Direction::Upstream => PluginHead::Response {
      status: parsed.status.unwrap_or_default(),
      headers,
    },
  }
}

/// True when the hooked headers match the swapped parse byte-for-byte.
fn headers_unchanged(hooked: &[PluginHeader], swapped: &[httparse::Header<'_>]) -> bool {
  hooked.len() == swapped.len()
    && hooked
      .iter()
      .zip(swapped)
      .all(|(hooked, swapped)| hooked.name.as_bytes() == swapped.name.as_bytes() && hooked.value == swapped.value)
}

/// Offset of the first `\r\n` in `data`, if present.
fn find_crlf(data: &[u8]) -> Option<usize> {
  if data.len() < 2 {
    return None;
  }
  data.windows(2).position(|w| w == b"\r\n")
}

fn parse_chunk_size(line: &[u8]) -> Option<usize> {
  let size = line.split(|byte| *byte == b';').next().unwrap_or_default();
  let size = size.trim_ascii();
  if size.is_empty() {
    return None;
  }
  let size = std::str::from_utf8(size).ok()?;
  let size = usize::from_str_radix(size, 16).ok()?;
  // No size cap: payloads stream, so any declared length is carried as a
  // countdown. Overflow fails the parse (Broken) rather than panicking.
  Some(size)
}

/// Rebuild the head block when the hook changed method, path, status, or
/// headers; `None` keeps the swapped bytes byte-identical. An edited first
/// line is reconstructed with the original version (and reason phrase);
/// otherwise the original first line is preserved verbatim.
fn rebuild_head_if_changed(hooked: &PluginHead, swapped: &ParsedHead<'_>, swapped_bytes: &[u8], dir: Direction) -> Option<Vec<u8>> {
  let first_len = find_crlf(swapped_bytes).unwrap_or(swapped_bytes.len());
  let first_line = &swapped_bytes[..first_len];
  let version = match swapped.version {
    Some(0) => "HTTP/1.0",
    _ => "HTTP/1.1",
  };
  match (hooked, dir) {
    (
      PluginHead::Request {
        method,
        path_with_query,
        headers,
      },
      Direction::Downstream,
    ) => {
      let same_start = Some(method.as_str()) == swapped.method && Some(path_with_query.as_str()) == swapped.path;
      if same_start && headers_unchanged(headers, &swapped.headers) {
        return None;
      }
      let mut out = Vec::with_capacity(swapped_bytes.len() + 64);
      if same_start {
        out.extend_from_slice(first_line);
      } else {
        out.extend_from_slice(format!("{method} {path_with_query} {version}").as_bytes());
      }
      out.extend_from_slice(b"\r\n");
      append_plugin_headers(&mut out, headers);
      out.extend_from_slice(b"\r\n");
      Some(out)
    }
    (PluginHead::Response { status, headers }, Direction::Upstream) => {
      let same_start = Some(*status) == swapped.status;
      if same_start && headers_unchanged(headers, &swapped.headers) {
        return None;
      }
      let mut out = Vec::with_capacity(swapped_bytes.len() + 64);
      if same_start {
        out.extend_from_slice(first_line);
      } else {
        let reason = swapped.reason.unwrap_or("");
        if reason.is_empty() {
          out.extend_from_slice(format!("{version} {status}").as_bytes());
        } else {
          out.extend_from_slice(format!("{version} {status} {reason}").as_bytes());
        }
      }
      out.extend_from_slice(b"\r\n");
      append_plugin_headers(&mut out, headers);
      out.extend_from_slice(b"\r\n");
      Some(out)
    }
    // Hook changed the head shape across directions: ignore, keep bytes.
    _ => None,
  }
}

/// Append one `Name: value` line per header, raw value bytes preserved.
fn append_plugin_headers(out: &mut Vec<u8>, headers: &[PluginHeader]) {
  for header in headers {
    out.extend_from_slice(header.name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(&header.value);
    out.extend_from_slice(b"\r\n");
  }
}

/// Parse a trailer block into headers, one per `Name: value` line. Operates
/// on bytes so non-UTF8 values survive; only leading OWS is stripped.
fn parse_trailer_block(block: &[u8]) -> Vec<PluginHeader> {
  let mut headers = Vec::new();
  for line in block.split(|byte| *byte == b'\n') {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() {
      continue;
    }
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
      continue;
    };
    let name = String::from_utf8_lossy(&line[..colon]).trim().to_string();
    let mut value = &line[colon + 1..];
    while value.first().is_some_and(|byte| *byte == b' ' || *byte == b'\t') {
      value = &value[1..];
    }
    headers.push(PluginHeader {
      name,
      value: value.to_vec(),
    });
  }
  headers
}

/// Serialize headers as a trailer block: one `Name: value` line each plus
/// the terminal empty line.
fn serialize_trailer_block(headers: &[PluginHeader]) -> Vec<u8> {
  let mut out = Vec::new();
  append_plugin_headers(&mut out, headers);
  out.extend_from_slice(b"\r\n");
  out
}

#[cfg(test)]
impl Http {
  /// Fail-closed latch state.
  pub(crate) fn must_close(&self) -> bool {
    self.must_close
  }
  /// Drain pending HEAD-request count.
  fn take_head_requests(&mut self) -> usize {
    std::mem::take(&mut self.head_requests)
  }
  /// Suppress bodies for the next n responses.
  fn suppress_next_bodies(&mut self, n: usize) {
    self.suppress_body += n;
  }
}

impl Wire for Http {
  async fn feed<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    let (out, hits) = Http::substitute(self, chunk).await;
    let rewritten = if self.must_close {
      Rewritten::Close
    } else if out.is_empty() {
      Rewritten::Hold
    } else {
      Rewritten::Emit(out)
    };
    (rewritten, hits)
  }
  fn take_peer_note(&mut self) -> Option<PeerFact> {
    let n = std::mem::take(&mut self.head_requests);
    (n > 0).then_some(PeerFact::Heads(n))
  }
  fn apply_peer_note(&mut self, fact: PeerFact) {
    if let PeerFact::Heads(n) = fact {
      self.suppress_body = self.suppress_body.saturating_add(n);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::grants::Credential;

  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  fn grants() -> Vec<Grant> {
    vec![Grant::Token {
      credential: Credential {
        label: "github".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      allow: vec!["https://api.github.com".parse().unwrap()],
      pattern: None,
      oauth2: None,
    }]
  }

  fn req_machine() -> Http {
    Http::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Downstream, None, None)
  }

  fn resp_machine() -> Http {
    Http::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Upstream, None, None)
  }

  /// A flow-granted endpoint: the grant matches `auth.example.com` and
  /// declares a client-credentials flow.
  fn flow_grants() -> Vec<Grant> {
    vec![Grant::Token {
      credential: Credential {
        label: "issuer".into(),
        fake: FAKE.into(),
        value: secrecy::SecretString::from(VALUE),
      },
      allow: vec!["https://auth.example.com".parse().unwrap()],
      pattern: None,
      oauth2: Some(arkham_config::registry::OAuthFlow {
        flow: arkham_config::registry::FlowKind::ClientCredentials,
        token_url: "https://auth.example.com/oauth/token".into(),
        authorize_url: None,
        refresh_url: None,
        rotates_refresh: false,
        token_fields: Vec::new(),
      }),
    }]
  }

  fn mint_machine(store: crate::mint::MintStore) -> Http {
    Http::new(
      &flow_grants(),
      Scheme::Https,
      "auth.example.com",
      443,
      Direction::Upstream,
      None,
      Some(store),
    )
  }

  #[tokio::test]
  async fn request_header_substituted_and_response_redacted() {
    let mut req = req_machine();
    let input = format!("GET /x HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {FAKE}\r\n\r\n");
    let (out, hits) = req.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains(VALUE), "{out}");
    assert!(!out.contains(FAKE), "{out}");
    assert_eq!(
      hits,
      vec![Hit {
        label: "github".into(),
        location: Location::Header
      }]
    );

    let mut resp = resp_machine();
    let body = format!("token={VALUE}");
    let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let (out, hits) = resp.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains(FAKE), "{out}");
    assert!(!out.contains(VALUE), "{out}");
    assert_eq!(
      hits,
      vec![Hit {
        label: "github".into(),
        location: Location::Body
      }]
    );
  }

  #[tokio::test]
  async fn host_header_preserved_while_other_headers_substituted() {
    let mut req = req_machine();
    let input = format!("GET /x HTTP/1.1\r\nHost: {FAKE}\r\nX-Token: {FAKE}\r\n\r\n");
    let (out, hits) = req.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains(&format!("Host: {FAKE}\r\n")), "{out}");
    assert!(out.contains(&format!("X-Token: {VALUE}\r\n")), "{out}");
    assert_eq!(
      hits,
      vec![Hit {
        label: "github".into(),
        location: Location::Header
      }]
    );
  }

  #[tokio::test]
  async fn basic_auth_decoded_substituted_reencoded() {
    let creds = base64::engine::general_purpose::STANDARD.encode(format!("user:{FAKE}"));
    let mut req = req_machine();
    let input = format!("GET /x HTTP/1.1\r\nAuthorization: Basic {creds}\r\n\r\n");
    let (out, hits) = req.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    let encoded = out.split("Authorization: Basic ").nth(1).unwrap().split("\r\n").next().unwrap();
    let decoded = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded.trim()).unwrap()).unwrap();
    assert_eq!(decoded, format!("user:{VALUE}"));
    assert!(hits.iter().any(|hit| hit.location == Location::BasicAuth));
  }

  #[tokio::test]
  async fn fixed_body_equal_length_swap_preserves_content_length() {
    let mut req = req_machine();
    let body = format!("x={FAKE}");
    let input = format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let (out, _) = req.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains(&format!("Content-Length: {}\r\n", body.len())), "{out}");
    assert!(out.contains(VALUE), "{out}");
    assert!(!req.must_close());
  }

  #[tokio::test]
  async fn fixed_body_token_split_across_writes() {
    // The needle straddles the arrival boundary mid-token: the hold-back
    // window must recombine it, never emit the prefix raw.
    let mut req = req_machine();
    let body = format!("pre-{FAKE}-post");
    let head = format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len());
    let (out, _) = req.substitute(head.as_bytes()).await;
    assert_eq!(out.as_ref(), head.as_bytes());
    let (a, b) = FAKE.split_at(14);
    let first = format!("pre-{a}");
    let second = format!("{b}-post");
    let (out1, _) = req.substitute(first.as_bytes()).await;
    let out1 = out1.into_owned();
    let (out2, _) = req.substitute(second.as_bytes()).await;
    let out2 = out2.into_owned();
    let mut text = String::from_utf8(out1).unwrap();
    text.push_str(&String::from_utf8(out2).unwrap());
    assert_eq!(text, format!("pre-{VALUE}-post"), "{text}");
  }
  #[tokio::test]
  async fn fixed_body_length_change_fails_closed() {
    // The head goes out with its original Content-Length before the body
    // streams, so a swap that would change the length cannot be framed
    // honestly: the connection fails closed instead.
    let short_value_grants = vec![Grant::Token {
      credential: Credential {
        label: "g".into(),
        fake: "LONGFAKEVALUE".into(),
        value: secrecy::SecretString::from("short"),
      },
      allow: vec!["https://api.github.com".parse().unwrap()],
      pattern: None,
      oauth2: None,
    }];
    let mut machine = Http::new(
      &short_value_grants,
      Scheme::Https,
      "api.github.com",
      443,
      Direction::Downstream,
      None,
      None,
    );
    let body = "x=LONGFAKEVALUE";
    let input = format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let (out, _) = machine.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains("Content-Length: 15\r\n"), "{out}");
    assert!(machine.must_close(), "unequal swap must latch close");
  }

  #[tokio::test]
  async fn fixed_body_substitutes_past_any_size_cap() {
    // 20 MiB with the needle at the very end: streaming means no size
    // exists at which substitution stops or the body is buffered whole.
    let total = 20 * 1024 * 1024;
    let tail = format!("end-{FAKE}-end");
    let prefix_len = total - tail.len();
    let mut req = req_machine();
    let head = format!("POST /x HTTP/1.1\r\nContent-Length: {total}\r\n\r\n");
    let (out_head, _) = req.substitute(head.as_bytes()).await;
    assert_eq!(out_head.as_ref(), head.as_bytes());
    let zeros = vec![b'a'; 64 * 1024];
    let mut sent = 0usize;
    let mut body_hits = 0usize;
    while sent + zeros.len() < prefix_len {
      let (out, hits) = req.substitute(&zeros).await;
      assert_eq!(out.len(), zeros.len());
      body_hits += hits.len();
      sent += zeros.len();
    }
    let mid = prefix_len - sent;
    let (out, hits) = req.substitute(&zeros[..mid]).await;
    assert_eq!(out.len(), mid);
    body_hits += hits.len();
    let (out, hits) = req.substitute(tail.as_bytes()).await;
    let out = out.into_owned();
    body_hits += hits.len();
    assert_eq!(out.len(), tail.len(), "equal-length swap");
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains(&format!("end-{VALUE}-end")), "{text}");
    assert!(!text.contains(FAKE), "{text}");
    assert_eq!(body_hits, 1);
    assert!(!req.must_close());
  }

  #[tokio::test]
  async fn chunked_split_across_writes_reencoded_valid() {
    // Two chunks: "xx" + FAKE(44 = 0x2c bytes).
    let head = "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    let chunk_a = "2\r\nxx\r\n";
    let (fake_first, fake_rest) = FAKE.split_at(20);
    let part1 = format!("{head}{chunk_a}2c\r\n{fake_first}");
    let part2 = format!("{fake_rest}\r\n0\r\n\r\n");
    let mut req = req_machine();
    // Split the first part mid-head to exercise buffering too.
    let mid = head.len() - 10;
    let (out1, _) = req.substitute(&part1.as_bytes()[..mid]).await;
    let out1 = out1.into_owned();
    assert_eq!(out1, [] as [u8; 0]);
    let (out2, _) = req.substitute(&part1.as_bytes()[mid..]).await;
    let out2 = out2.into_owned();
    let (out3, hits) = req.substitute(part2.as_bytes()).await;
    let out3 = out3.into_owned();
    let mut full = out1;
    full.extend_from_slice(&out2);
    full.extend_from_slice(&out3);
    let full_str = String::from_utf8(full).unwrap();
    assert!(full_str.contains(VALUE), "{full_str}");
    assert!(!full_str.contains(FAKE), "{full_str}");
    assert!(hits.iter().any(|hit| hit.location == Location::Body));
    // Valid chunked framing: decode the re-chunked payload and check it.
    let body_start = full_str.find("\r\n\r\n").unwrap() + 4;
    let body = &full_str[body_start..];
    assert!(body.ends_with("0\r\n\r\n"), "{body}");
    let mut payload = String::new();
    let mut cursor = 0;
    while &body[cursor..cursor + 2] != "0\r" {
      let line_end = body[cursor..].find("\r\n").unwrap() + cursor;
      let size = usize::from_str_radix(&body[cursor..line_end], 16).unwrap();
      assert!(size > 0, "no empty data chunks mid-body");
      payload.push_str(&body[line_end + 2..line_end + 2 + size]);
      cursor = line_end + 2 + size + 2;
    }
    assert_eq!(payload, format!("xx{VALUE}"));
  }

  #[tokio::test]
  async fn te_plus_cl_forwarded_unchanged_with_hit() {
    let mut req = req_machine();
    let input = format!("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n{FAKE}");
    let (out, hits) = req.substitute(input.as_bytes()).await;
    assert_eq!(out.as_ref(), input.as_bytes());
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].location, Location::Body);
  }

  #[tokio::test]
  async fn cross_write_fake_matches_in_scan_mode() {
    let mut opaque = Http::opaque(&grants(), Scheme::Https, "api.github.com", 443, Direction::Downstream);
    let (first, second) = FAKE.split_at(20);
    let (_, hits1) = opaque.substitute(first.as_bytes()).await;
    assert_eq!(hits1, [] as [Hit; 0]);
    let (out2, hits2) = opaque.substitute(second.as_bytes()).await;
    assert_eq!(out2.as_ref(), second.as_bytes());
    assert_eq!(hits2.len(), 1);
  }

  #[tokio::test]
  async fn pipelined_requests_both_substituted() {
    let mut req = req_machine();
    let input = format!("GET /a HTTP/1.1\r\nAuthorization: Bearer {FAKE}\r\n\r\nGET /b HTTP/1.1\r\nAuthorization: Bearer {FAKE}\r\n\r\n");
    let (out, hits) = req.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(!out.contains(FAKE), "{out}");
    assert_eq!(out.matches(VALUE).count(), 2);
    assert_eq!(hits.len(), 2);
  }

  #[tokio::test]
  async fn non_utf8_head_goes_opaque_unchanged() {
    let mut req = req_machine();
    let mut input = b"GET /x HTTP/1.1\r\nX-Bin: \xff\xfe\r\n\r\n".to_vec();
    input.extend_from_slice(FAKE.as_bytes());
    let (out, _) = req.substitute(&input).await;
    assert_eq!(out.as_ref(), input.as_slice());
  }

  #[tokio::test]
  async fn flush_emits_partial_head_unchanged() {
    let mut req = req_machine();
    let (out, _) = req.substitute(b"GET /x HTTP/1.1\r\nAuthorization: Bearer ").await;
    assert!(out.is_empty());
    let (flush, _) = req.substitute(&[]).await;
    assert_eq!(flush.as_ref(), b"GET /x HTTP/1.1\r\nAuthorization: Bearer ");
  }

  #[tokio::test]
  async fn unchanged_chunk_borrows_zero_copy() {
    let mut req = req_machine();
    let input = b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n";
    let (out, hits) = req.substitute(input).await;
    assert!(matches!(out, Cow::Borrowed(_)));
    assert_eq!(hits, [] as [Hit; 0]);
  }

  #[tokio::test]
  async fn empty_content_length_emits_head_immediately() {
    let mut resp = resp_machine();
    let (out, _) = resp.substitute(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    assert_eq!(out.as_ref(), b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  }

  #[tokio::test]
  async fn no_body_status_ignores_framing() {
    let mut resp = resp_machine();
    let (out, _) = resp.substitute(b"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n").await;
    assert_eq!(out.as_ref(), b"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n");
    // Next bytes are a new response head, not a swallowed body.
    let (out, _) = resp.substitute(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    assert_eq!(out.as_ref(), b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  }

  #[tokio::test]
  async fn head_response_carries_no_body() {
    let mut req = req_machine();
    let mut resp = resp_machine();
    let (out, _) = req.substitute(b"HEAD /x HTTP/1.1\r\nHost: a\r\n\r\n").await;
    assert!(!out.is_empty());
    resp.suppress_next_bodies(req.take_head_requests());
    let body = format!("token={VALUE}");
    let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
    let (out, _) = resp.substitute(input.as_bytes()).await;
    assert_eq!(out.as_ref(), input.as_bytes());
  }

  #[tokio::test]
  async fn hostile_huge_chunk_size_no_panic_no_buffer() {
    // usize::MAX-ish size: streams as a countdown, never panics on cursor
    // arithmetic and never buffers waiting for the declared bytes.
    let mut req = req_machine();
    let input = b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff;\r\n";
    let (out, _) = req.substitute(input).await;
    assert_eq!(out.as_ref(), &input[..input.len() - 19]);
    assert!(!req.must_close());
  }

  #[tokio::test]
  async fn chunked_drip_fed_byte_by_byte_reencoded() {
    // One byte per substitute() call: exercises the incremental chunk
    // parser's resume logic (CRLF straddling arrivals, partial sizes).
    let mut req = req_machine();
    let fake_first = &FAKE[..3];
    let fake_rest = &FAKE[3..];
    let input = format!(
      "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nxx{fake_first}\r\n{:X}\r\n",
      fake_rest.len()
    );
    let tail = format!("{fake_rest}\r\n0\r\n\r\n");
    let full = format!("{input}{tail}");
    let mut collected = Vec::new();
    for byte in full.as_bytes() {
      let (out, _) = req.substitute(std::slice::from_ref(byte)).await;
      collected.extend_from_slice(&out);
    }
    let (flush, _) = req.substitute(&[]).await;
    collected.extend_from_slice(&flush);
    let text = String::from_utf8(collected).unwrap();
    assert!(text.contains(VALUE), "{text}");
    assert!(!text.contains(FAKE), "{text}");
    // Valid re-encoded framing: decode every data chunk and check the
    // concatenated payload (drip-fed input re-chunks per emitted region).
    let body_start = text.find("\r\n\r\n").unwrap() + 4;
    let body = &text[body_start..];
    assert!(body.ends_with("0\r\n\r\n"), "{body}");
    let mut payload = String::new();
    let mut cursor = 0;
    while &body[cursor..cursor + 2] != "0\r" {
      let line_end = body[cursor..].find("\r\n").unwrap() + cursor;
      let size = usize::from_str_radix(&body[cursor..line_end], 16).unwrap();
      assert!(size > 0, "no empty data chunks mid-body");
      payload.push_str(&body[line_end + 2..line_end + 2 + size]);
      cursor = line_end + 2 + size + 2;
    }
    assert_eq!(payload, format!("xx{VALUE}"));
  }

  #[tokio::test]
  async fn opaque_state_passes_through_borrowed() {
    let mut req = req_machine();
    // Close-delimited response head → Opaque body streaming.
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    let _ = req.substitute(head).await;
    let body = b"plain body bytes without secrets";
    let (out, hits) = req.substitute(body).await;
    assert!(matches!(out, Cow::Borrowed(_)));
    assert!(matches!(req.state, State::Opaque));
    assert_eq!(hits, [] as [Hit; 0]);
  }

  #[tokio::test]
  async fn close_delimited_token_split_across_writes() {
    let mut resp = resp_machine();
    let _ = resp.substitute(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n").await;
    let (a, b) = VALUE.split_at(14);
    let first = format!("tok-{a}");
    let (out1, _) = resp.substitute(first.as_bytes()).await;
    let out1 = out1.into_owned();
    let second = format!("{b}-end");
    let (out2, body_hits) = resp.substitute(second.as_bytes()).await;
    let out2 = out2.into_owned();
    let (flush, _) = resp.substitute(&[]).await;
    let flush = flush.into_owned();
    let mut text = String::from_utf8(out1).unwrap();
    text.push_str(&String::from_utf8(out2).unwrap());
    text.push_str(&String::from_utf8_lossy(&flush));
    assert_eq!(text, format!("tok-{FAKE}-end"), "{text}");
    assert_eq!(body_hits.len(), 1);
  }
  #[tokio::test]
  async fn close_delimited_response_redacts_at_eof() {
    let mut resp = resp_machine();
    let (head_out, _) = resp.substitute(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n").await;
    let head_out = head_out.into_owned();
    assert!(head_out.starts_with(b"HTTP/1.1 200 OK"));
    assert!(matches!(resp.state, State::CloseDelimited), "{:?}", resp.state);
    // Streaming: the body redacts as it flows, not buffered until EOF.
    let body = format!("tok-{VALUE}-end");
    let (body_out, hits) = resp.substitute(body.as_bytes()).await;
    let body_out = body_out.into_owned();
    let body_str = String::from_utf8_lossy(&body_out);
    assert!(body_str.contains(FAKE), "{body_str}");
    assert!(!body_str.contains(VALUE), "{body_str}");
    assert_eq!(hits.len(), 1);
    let (flush, flush_hits) = resp.substitute(&[]).await;
    assert!(flush.is_empty());
    assert_eq!(flush_hits, [] as [Hit; 0]);
    assert!(!resp.must_close());
  }

  #[tokio::test]
  async fn close_delimited_without_pairs_streams_zero_copy() {
    let mut resp = Http::new(&[], Scheme::Https, "api.github.com", 443, Direction::Upstream, None, None);
    let _ = resp.substitute(b"HTTP/1.1 200 OK\r\n\r\n").await;
    assert!(matches!(resp.state, State::Opaque), "{:?}", resp.state);
    let (out, hits) = resp.substitute(b"body-bytes").await;
    assert!(matches!(out, Cow::Borrowed(_)));
    assert_eq!(hits, [] as [Hit; 0]);
  }

  #[tokio::test]
  async fn compressed_response_hit_fails_closed() {
    let mut resp = resp_machine();
    let body = format!("blob-{VALUE}-blob");
    let head = format!(
      "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
      body.len()
    );
    let (out, hits) = resp.substitute(head.as_bytes()).await;
    let out = out.into_owned();
    assert!(out.ends_with(b"\r\n\r\n"));
    assert_eq!(hits, [] as [Hit; 0]);
    let (_out, hits) = resp.substitute(body.as_bytes()).await;
    assert_eq!(hits.len(), 1);
    assert!(resp.must_close(), "compressed body hit must fail closed");
    // Request direction never fails closed on scan-only hits.
    let mut req = req_machine();
    let body = format!("blob-{FAKE}-blob");
    let head = format!(
      "POST /x HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
      body.len()
    );
    let _ = req.substitute(head.as_bytes()).await;
    let (_out, hits) = req.substitute(body.as_bytes()).await;
    assert_eq!(hits.len(), 1);
    assert!(!req.must_close());
  }

  #[tokio::test]
  async fn chunked_trailers_redacted() {
    let mut resp = resp_machine();
    let input = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-Tok: {VALUE}\r\n\r\n");
    let (out, hits) = resp.substitute(input.as_bytes()).await;
    let out = out.into_owned();
    let out_str = String::from_utf8_lossy(&out);
    assert!(out_str.contains(&format!("X-Tok: {FAKE}")), "{out_str}");
    assert!(!out_str.contains(VALUE), "{out_str}");
    assert!(hits.iter().any(|hit| hit.location == Location::Body));
    assert!(!resp.must_close());
  }

  #[test]
  fn no_body_status_includes_205() {
    assert!(response_has_no_body(Some(205)));
  }

  /// Stage-1 hook double: appends markers, adds headers/trailers, or votes
  /// `Close`. Wire-observable only; the machine owns the boxed hook.
  #[derive(Default)]
  struct MockHook {
    add_header: Option<(String, Vec<u8>)>,
    append_body: Vec<u8>,
    eof_marker: Vec<u8>,
    add_trailer: Option<(String, Vec<u8>)>,
    close_head: bool,
    close_chunk: bool,
    close_trailers: bool,
  }

  impl RewriteHook for MockHook {
    fn rewrite_head<'a>(&'a mut self, head: &'a mut PluginHead) -> arkham_plugin::BoxFuture<'a, Verdict> {
      Box::pin(async move {
        if self.close_head {
          return Verdict::Close;
        }
        if let Some((name, value)) = self.add_header.clone() {
          let header = PluginHeader { name, value };
          match head {
            PluginHead::Request { headers, .. } | PluginHead::Response { headers, .. } => headers.push(header),
          }
        }
        Verdict::Continue
      })
    }

    fn rewrite_trailers<'a>(&'a mut self, headers: &'a mut Vec<PluginHeader>) -> arkham_plugin::BoxFuture<'a, Verdict> {
      Box::pin(async move {
        if self.close_trailers {
          return Verdict::Close;
        }
        if let Some((name, value)) = self.add_trailer.clone() {
          headers.push(PluginHeader { name, value });
        }
        Verdict::Continue
      })
    }

    fn rewrite_chunk<'a>(&'a mut self, data: &'a mut Vec<u8>, eof: bool) -> arkham_plugin::BoxFuture<'a, Verdict> {
      Box::pin(async move {
        if self.close_chunk {
          return Verdict::Close;
        }
        // Mirrors the example guests: never rewrite an empty region —
        // the eof release call may carry zero bytes.
        if !data.is_empty() {
          data.extend_from_slice(&self.append_body);
          if eof {
            data.extend_from_slice(&self.eof_marker);
          }
        }
        Verdict::Continue
      })
    }
  }

  fn req_hooked(hook: MockHook) -> Http {
    Http::new(
      &grants(),
      Scheme::Https,
      "api.github.com",
      443,
      Direction::Downstream,
      Some(Box::new(hook)),
      None,
    )
  }

  #[tokio::test]
  async fn mock_hook_rewrites_h1_request_head() {
    let mut req = req_hooked(MockHook {
      add_header: Some(("x-hook".to_string(), b"1".to_vec())),
      ..Default::default()
    });
    let input = format!("GET /x HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {FAKE}\r\n\r\n");
    let (out, _) = req.substitute(input.as_bytes()).await;
    let out_str = String::from_utf8(out.into_owned()).unwrap();
    assert!(out_str.contains(VALUE), "{out_str}");
    assert!(out_str.contains("x-hook: 1\r\n"), "{out_str}");
    assert!(!req.must_close());
  }

  #[tokio::test]
  async fn mock_hook_fixed_body_length_change_fails_closed() {
    // Fixed framing emits its Content-Length before the body streams, so
    // a hook that grows a region cannot be honored: latch close.
    let mut req = req_hooked(MockHook {
      append_body: b"-hooked".to_vec(),
      ..Default::default()
    });
    let body = format!("x={FAKE}");
    let input = format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let (out, _) = req.substitute(input.as_bytes()).await;
    let out_str = String::from_utf8(out.into_owned()).unwrap();
    assert!(out_str.contains(&format!("Content-Length: {}\r\n", body.len())), "{out_str}");
    assert!(!out_str.contains("x="), "{out_str}");
    assert!(req.must_close());
  }

  #[tokio::test]
  async fn mock_hook_rewrites_h1_chunked_body() {
    let mut req = req_hooked(MockHook {
      append_body: b"-hooked".to_vec(),
      ..Default::default()
    });
    let body = format!("data-{FAKE}-tail");
    let input = format!(
      "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{body}\r\n0\r\n\r\n",
      body.len()
    );
    let (out, _) = req.substitute(input.as_bytes()).await;
    let out_str = String::from_utf8(out.into_owned()).unwrap();
    let expect_body = format!("data-{VALUE}-tail-hooked");
    assert!(
      out_str.contains(&format!("{:X}\r\n{expect_body}\r\n0\r\n\r\n", expect_body.len())),
      "{out_str}"
    );
    assert!(!req.must_close());
  }

  #[tokio::test]
  async fn mock_hook_rewrites_h1_trailer_block() {
    let mut req = req_hooked(MockHook {
      add_trailer: Some(("x-hooked-trailer".to_string(), b"1".to_vec())),
      ..Default::default()
    });
    let input = "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-T: abc\r\n\r\n";
    let (out, _) = req.substitute(input.as_bytes()).await;
    let out_str = String::from_utf8(out.into_owned()).unwrap();
    assert!(out_str.contains("X-T: abc\r\n"), "{out_str}");
    assert!(out_str.contains("x-hooked-trailer: 1\r\n"), "{out_str}");
    assert!(!req.must_close());
  }

  #[tokio::test]
  async fn mock_hook_close_verdict_latches_h1() {
    let mut req = req_hooked(MockHook {
      close_head: true,
      ..Default::default()
    });
    let input = "GET /x HTTP/1.1\r\nHost: a\r\n\r\n";
    let _ = req.substitute(input.as_bytes()).await;
    assert!(req.must_close());
  }

  #[tokio::test]
  async fn mock_hook_eof_flag_on_terminal_flush() {
    // Trailing needle-prefix bytes stay held through the last data
    // region; the terminal-chunk flush is the eof call that carries them.
    let mut req = req_hooked(MockHook {
      append_body: b"-chunk".to_vec(),
      eof_marker: b"-eof".to_vec(),
      ..Default::default()
    });
    let partial = &FAKE[..6];
    let body = format!("x={FAKE}z{partial}");
    let input = format!(
      "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{body}\r\n0\r\n\r\n",
      body.len()
    );
    let (out, _) = req.substitute(input.as_bytes()).await;
    let out_str = String::from_utf8(out.into_owned()).unwrap();
    assert!(out_str.contains(&format!("x={VALUE}z-chunk")), "{out_str}");
    assert!(out_str.contains(&format!("{partial}-chunk-eof")), "{out_str}");
    assert!(out_str.ends_with("0\r\n\r\n"), "{out_str}");
    assert!(!req.must_close());
  }

  #[tokio::test]
  async fn plugin_active_connection_fails_closed_on_opaque() {
    let mut opaque = Http::opaque(&grants(), Scheme::Https, "api.github.com", 443, Direction::Downstream);
    opaque.hook = Some(Box::new(MockHook::default()));
    let (out, _) = opaque.substitute(b"unframable-bytes").await;
    assert_eq!(out.as_ref(), b"unframable-bytes");
    assert!(opaque.must_close());
  }

  #[tokio::test]
  async fn token_response_mints_decoy_and_rewrites_length() {
    let store = crate::mint::MintStore::default();
    let mut resp = mint_machine(store.clone());
    let body = r#"{"access_token":"real-token-value","token_type":"Bearer","expires_in":3600}"#;
    let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let (out, hits) = resp.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(!out.contains("real-token-value"), "{out}");
    assert!(out.contains("access_token"), "{out}");
    let decoy = store.snapshot_pairs()[0].0.clone();
    assert!(out.contains(&decoy), "{out}");
    // Content-Length rewritten to the decoyed body's true length.
    let minted_body = out.split("\r\n\r\n").nth(1).unwrap();
    assert!(out.contains(&format!("Content-Length: {}", minted_body.len())), "{out}");
    assert_eq!(
      hits,
      vec![Hit {
        label: "issuer".into(),
        location: Location::Body
      }]
    );
  }

  #[tokio::test]
  async fn minted_decoy_substitutes_on_a_later_connection() {
    let store = crate::mint::MintStore::default();
    let mut resp = mint_machine(store.clone());
    let body = r#"{"access_token":"real-token-value","token_type":"Bearer"}"#;
    let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    resp.substitute(input.as_bytes()).await;
    let decoy = store.snapshot_pairs()[0].0.clone();
    // A fresh request machine on a new connection unions the minted pair.
    let mut req = Http::new(
      &flow_grants(),
      Scheme::Https,
      "auth.example.com",
      443,
      Direction::Downstream,
      None,
      Some(store.clone()),
    );
    let input = format!("GET /x HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {decoy}\r\n\r\n");
    let (out, hits) = req.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains("real-token-value"), "{out}");
    assert!(!out.contains(&decoy), "{out}");
    assert_eq!(
      hits,
      vec![Hit {
        label: "issuer".into(),
        location: Location::Header
      }]
    );
  }

  #[tokio::test]
  async fn keepalive_request_sees_fresh_mint_at_next_head() {
    // The request machine is constructed before anything mints; the decoy
    // minted on the response leg must go live at the next request head.
    let store = crate::mint::MintStore::default();
    let mut resp = mint_machine(store.clone());
    let body = r#"{"access_token":"real-token-value"}"#;
    let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    resp.substitute(input.as_bytes()).await;
    let decoy = store.snapshot_pairs()[0].0.clone();
    let mut req = Http::new(
      &flow_grants(),
      Scheme::Https,
      "auth.example.com",
      443,
      Direction::Downstream,
      None,
      Some(store.clone()),
    );
    let first = "GET /a HTTP/1.1\r\nHost: a\r\n\r\n";
    let _ = req.substitute(first.as_bytes()).await;
    let second = format!("GET /b HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {decoy}\r\n\r\n");
    let (out, hits) = req.substitute(second.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains("real-token-value"), "{out}");
    assert!(!out.contains(&decoy), "{out}");
    assert!(hits.iter().any(|hit| hit.location == Location::Header));
  }

  #[tokio::test]
  async fn chunked_token_response_mints_and_rechunks() {
    let store = crate::mint::MintStore::default();
    let mut resp = mint_machine(store.clone());
    let input = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n23\r\n{\"access_token\":\"real-token-value\"}\r\n0\r\n\r\n";
    let (out, _hits) = resp.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(!out.contains("real-token-value"), "{out}");
    let decoy = store.snapshot_pairs()[0].0.clone();
    assert!(out.contains(&decoy), "{out}");
    assert!(out.contains("0\r\n\r\n"), "{out}");
  }

  #[tokio::test]
  async fn non_json_token_response_passes_through() {
    let store = crate::mint::MintStore::default();
    let mut resp = mint_machine(store.clone());
    let body = "not json at all";
    let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let (out, hits) = resp.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert_eq!(out, input, "unparseable body is untouched");
    assert_eq!(hits, [] as [Hit; 0]);
    assert!(store.snapshot_pairs().is_empty());
  }

  #[tokio::test]
  async fn rotation_mints_a_pair_per_value() {
    let store = crate::mint::MintStore::default();
    let mut grants = flow_grants();
    let Grant::Token { oauth2: Some(flow), .. } = &mut grants[0] else {
      panic!("a flow grant");
    };
    flow.rotates_refresh = true;
    let mut resp = Http::new(
      &grants,
      Scheme::Https,
      "auth.example.com",
      443,
      Direction::Upstream,
      None,
      Some(store.clone()),
    );
    let first = r#"{"access_token":"token-one","refresh_token":"refresh-one"}"#;
    let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{first}", first.len());
    resp.substitute(input.as_bytes()).await;
    let second = r#"{"access_token":"token-two","refresh_token":"refresh-two"}"#;
    let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{second}", second.len());
    let (out, _hits) = resp.substitute(input.as_bytes()).await;
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(!out.contains("token-two"), "{out}");
    assert!(!out.contains("refresh-two"), "{out}");
    assert_eq!(store.snapshot_pairs().len(), 4, "one pair per minted value");
  }
}
