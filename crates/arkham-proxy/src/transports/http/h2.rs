//! HTTP/2 wire format: HPACK head rewriting, DATA-frame scanning.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use base64::Engine as _;
use httlib_hpack::{Decoder, Encoder};

use arkham_config::grants::{Grant, Scheme};
use arkham_plugin::{Head as PluginHead, Header as PluginHeader, RewriteHook, Verdict};

use crate::transports::engine::{
  CredentialPair, Direction, Hit, Location, MAX_MINT_BODY, MintPlan, PeerFact, Rewritten, Wire, eligible_pairs, max_tail_size,
  mint_and_redact, mint_plan_for, minted_pairs, needle_safe_emit_len, replace_bytes, replace_in, response_has_no_body, scan_with_tail,
};

/// HTTP/2 connection preface.
pub const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_MAX_BLOCK: usize = 64 * 1024;
const H2_MAX_FIELDS: usize = 1024;
const H2_MAX_STREAMS: usize = 1024;
const H2_OUTBOUND_PAYLOAD: usize = 16 * 1024;
const F_DATA: u8 = 0x0;
const F_HEADERS: u8 = 0x1;
const F_RST_STREAM: u8 = 0x3;
const F_PUSH_PROMISE: u8 = 0x5;
const F_CONTINUATION: u8 = 0x9;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// True when decoded H2 headers carry `:method: HEAD`.
fn is_head_method(headers: &[(Vec<u8>, Vec<u8>, u8)]) -> bool {
  headers
    .iter()
    .any(|(name, value, _)| name.eq_ignore_ascii_case(b":method") && value.eq_ignore_ascii_case(b"head"))
}

/// True when decoded H2 response headers carry a no-body `:status`.
fn response_status_no_body(headers: &[(Vec<u8>, Vec<u8>, u8)]) -> bool {
  let status = headers.iter().find_map(|(name, value, _)| {
    name
      .eq_ignore_ascii_case(b":status")
      .then(|| std::str::from_utf8(value).ok()?.trim().parse::<u16>().ok())?
  });
  response_has_no_body(status)
}

/// Substitute inside a decoded H2 authorization value (scheme + base64).
/// Returns the re-encoded value when a replacement happened.
fn substitute_basic_value(value: &str, needle: &str, replacement: &str) -> Option<String> {
  let (scheme, encoded) = value.split_once(char::is_whitespace)?;
  if !scheme.eq_ignore_ascii_case("basic") {
    return None;
  }
  let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded.trim()) {
    Ok(bytes) => match String::from_utf8(bytes) {
      Ok(text) => text,
      Err(_) => return None,
    },
    Err(_) => return None,
  };
  if !decoded.contains(needle) {
    return None;
  }
  let replaced = decoded.replace(needle, replacement);
  Some(format!(
    "Basic {}",
    base64::engine::general_purpose::STANDARD.encode(replaced.as_bytes())
  ))
}

struct H2Block {
  stream_id: u32,
  end_stream: bool,
  fragments: Vec<u8>,
  raw: Vec<u8>,
}

/// Connection lifecycle: preface consumption, frame walking, or degraded
/// scan-only passthrough (one-way).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H2Phase {
  /// Waiting for the client connection preface (request leg only).
  Preface,
  /// Walking frames.
  Framing,
  /// Framing violation: scan-only passthrough for the rest of the stream.
  Opaque,
}

/// Per-connection, per-direction HTTP/2 machine. HEADERS/CONTINUATION blocks
/// are HPACK-decoded, substituted, and re-encoded; DATA payloads are
/// substituted with the frame length rewritten (a per-stream overlap window
/// is held back so cross-frame split secrets substitute whole). Any framing
/// violation degrades to opaque scan-only forwarding.
pub(crate) struct H2 {
  pairs: Vec<CredentialPair>,
  dir: Direction,
  hook: Option<Box<dyn RewriteHook>>,
  decoder: Decoder<'static>,
  encoder: Encoder<'static>,
  buffer: Vec<u8>,
  /// Connection lifecycle phase.
  phase: H2Phase,
  block: Option<H2Block>,
  open_streams: HashSet<u32>,
  data_tails: HashMap<u32, Vec<u8>>,
  scan_tail: Vec<u8>,
  tail_size: usize,
  /// Request side: HEAD methods seen, pending pickup by the relay.
  head_requests: usize,
  /// Response side: next N response HEADERS carry no DATA (HEAD replies).
  suppress_body: usize,
  /// Fail-closed latch: a scan-only path hit a needle it could not rewrite.
  must_close: bool,
  /// Static grant pairs from construction; `pairs` rebuilds from these
  /// whenever minted pairs refresh.
  static_pairs: Vec<CredentialPair>,
  /// Runtime mint store; `None` keeps value-swap-only behavior.
  mint: Option<crate::mint::MintStore>,
  /// Response side: the flow-granted grant's expectations, when this
  /// endpoint is a token issuer and this machine mints.
  mint_plan: Option<MintPlan>,
  /// Response side: streams buffering a whole token-response body.
  mint_streams: HashMap<u32, Vec<u8>>,
}

impl H2 {
  /// Build from the grants an `https://` rule matched. The downstream
  /// direction consumes the H2 connection preface; upstream starts at
  /// frames.
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
    let mint_plan = (dir == Direction::Upstream)
      .then(|| mint_plan_for(grants, scheme, host, port))
      .flatten();
    let mut wire = Self {
      pairs: static_pairs.clone(),
      dir,
      hook,
      decoder: Decoder::default(),
      encoder: Encoder::default(),
      buffer: Vec::new(),
      phase: if dir == Direction::Downstream {
        H2Phase::Preface
      } else {
        H2Phase::Framing
      },
      block: None,
      open_streams: HashSet::new(),
      data_tails: HashMap::new(),
      scan_tail: Vec::new(),
      tail_size,
      head_requests: 0,
      suppress_body: 0,
      must_close: false,
      static_pairs,
      mint,
      mint_plan,
      mint_streams: HashMap::new(),
    };
    // Both directions union the minted decoys at construction, so a decoy
    // minted on any connection substitutes or redacts on this one too.
    wire.refresh_minted_pairs();
    wire
  }

  /// Rebuild the active pair set: static grants plus every minted decoy.
  /// Called at construction and at each finished HEADERS block, so pairs
  /// minted mid-connection go live immediately.
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

  /// True when response DATA on this connection buffers whole for minting.
  fn mint_active(&self) -> bool {
    self.dir == Direction::Upstream && self.mint.is_some() && self.mint_plan.is_some()
  }

  /// Process one chunk. Inherent implementation of the [`Wire`] protocol;
  /// the trait impl below forwards here so concrete and dynamic callers share
  /// one code path.
  #[must_use]
  pub async fn substitute<'a>(&mut self, chunk: &'a [u8]) -> (Cow<'a, [u8]>, Vec<Hit>) {
    if chunk.is_empty() {
      let mut out = std::mem::take(&mut self.buffer);
      if let Some(block) = self.block.take() {
        out.extend_from_slice(&block.raw);
      }
      // Flush per-stream DATA hold-backs: substitute and emit (stream order
      // across streams is already lost at EOF; dropping would lose bytes).
      let mut held_hits = Vec::new();
      for (stream_id, held) in std::mem::take(&mut self.data_tails) {
        if held.is_empty() {
          continue;
        }
        let (new_held, mut hh) = replace_in(&held, &self.pairs, Location::Body);
        held_hits.append(&mut hh);
        // A held window can exceed the 24-bit length only with a >16 MiB
        // needle; split rather than emit a lying length field.
        let mut offset = 0;
        while offset < new_held.len() {
          let take = (new_held.len() - offset).min(0xff_ffff);
          append_frame(&mut out, F_DATA, 0, stream_id, &new_held[offset..offset + take]);
          offset += take;
        }
      }
      // Flush mint-buffered streams the same way: mint what arrived, emit
      // as DATA frames. The connection is closing; unframed remainder is
      // already the EOF convention above.
      for (stream_id, body) in std::mem::take(&mut self.mint_streams) {
        let (new_body, mut mh) = self.mint_body(&body);
        held_hits.append(&mut mh);
        let mut offset = 0;
        while offset < new_body.len() {
          let take = (new_body.len() - offset).min(0xff_ffff);
          append_frame(&mut out, F_DATA, 0, stream_id, &new_body[offset..offset + take]);
          offset += take;
        }
      }
      return (Cow::Owned(out), held_hits);
    }
    if self.phase == H2Phase::Opaque {
      let hits = scan_with_tail(&self.pairs, &mut self.scan_tail, self.tail_size, chunk, Location::Body);
      if self.dir == Direction::Upstream && !hits.is_empty() {
        self.must_close = true;
      }
      return (Cow::Borrowed(chunk), hits);
    }
    self.buffer.extend_from_slice(chunk);
    let mut out = Vec::new();
    let mut hits = Vec::new();
    if self.phase == H2Phase::Preface {
      if self.buffer.len() < H2_PREFACE.len() {
        return (Cow::Owned(Vec::new()), hits);
      }
      if !self.buffer.starts_with(H2_PREFACE) {
        self.go_opaque(&mut out, &mut hits);
        return finalize_borrow(chunk, out, hits);
      }
      out.extend_from_slice(H2_PREFACE);
      self.buffer.drain(..H2_PREFACE.len());
      self.phase = H2Phase::Framing;
    }
    // Take the buffer out of `self` so frame slices borrow the local vec
    // while `process_frame` mutates machine state; one compaction per
    // chunk instead of a memmove per frame.
    let mut buf = std::mem::take(&mut self.buffer);
    let mut cursor = 0;
    while buf.len() - cursor >= 9 {
      let len = ((buf[cursor] as usize) << 16) | ((buf[cursor + 1] as usize) << 8) | buf[cursor + 2] as usize;
      let full = 9 + len;
      if buf.len() - cursor < full {
        break;
      }
      let violation = match self.process_frame(&buf[cursor..cursor + full], &mut hits).await {
        Ok(emit) => {
          out.extend_from_slice(&emit);
          cursor += full;
          continue;
        }
        Err(emit) => emit,
      };
      // Violation: emit held + current bytes, go opaque, drain the rest.
      hits.extend(scan_with_tail(
        &self.pairs,
        &mut self.scan_tail,
        self.tail_size,
        &violation,
        Location::Body,
      ));
      out.extend_from_slice(&violation);
      self.buffer = buf.split_off(cursor + full);
      self.go_opaque(&mut out, &mut hits);
      return finalize_borrow(chunk, out, hits);
    }
    buf.drain(..cursor);
    self.buffer = buf;
    finalize_borrow(chunk, out, hits)
  }

  /// Process one complete frame. Ok = bytes to emit (borrowed when the
  /// frame passes through untouched, empty while holding a block); Err =
  /// bytes to emit before going opaque. `raw` borrows the caller's local
  /// frame buffer, never `self`.
  async fn process_frame<'f>(&mut self, raw: &'f [u8], hits: &mut Vec<Hit>) -> Result<Cow<'f, [u8]>, Vec<u8>> {
    let kind = raw[3];
    let flags = raw[4];
    let stream_id = u32::from_be_bytes([raw[5], raw[6], raw[7], raw[8]]) & 0x7fff_ffff;
    let payload = &raw[9..];
    if self.block.is_some() && kind != F_CONTINUATION {
      let mut emit = self.block.take().map(|block| block.raw).unwrap_or_default();
      emit.extend_from_slice(raw);
      return Err(emit);
    }
    match kind {
      F_HEADERS => self.headers_frame(stream_id, flags, payload, raw, hits).await.map(Cow::Owned),
      F_CONTINUATION => self.continuation_frame(stream_id, flags, payload, raw, hits).await.map(Cow::Owned),
      F_DATA => self.data_frame(stream_id, flags, payload, raw, hits).await.map(Cow::Owned),
      F_RST_STREAM => {
        if stream_id == 0 {
          return Err(raw.to_vec());
        }
        self.open_streams.remove(&stream_id);
        self.data_tails.remove(&stream_id);
        self.mint_streams.remove(&stream_id);
        Ok(Cow::Borrowed(raw))
      }
      // PUSH_PROMISE carries an HPACK block that mutates the dynamic table;
      // forwarding without decoding would corrupt later HEADERS decoding.
      F_PUSH_PROMISE => Err(raw.to_vec()),
      _ => Ok(Cow::Borrowed(raw)),
    }
  }

  async fn headers_frame(
    &mut self,
    stream_id: u32,
    flags: u8,
    payload: &[u8],
    raw: &[u8],
    hits: &mut Vec<Hit>,
  ) -> Result<Vec<u8>, Vec<u8>> {
    if stream_id == 0 {
      return Err(raw.to_vec());
    }
    let fragment = headers_fragment(flags, payload).ok_or_else(|| raw.to_vec())?;
    if fragment.len() > H2_MAX_BLOCK {
      return Err(raw.to_vec());
    }
    let block = H2Block {
      stream_id,
      end_stream: flags & FLAG_END_STREAM != 0,
      fragments: fragment.to_vec(),
      raw: raw.to_vec(),
    };
    if flags & FLAG_END_HEADERS != 0 {
      self.finish_block(block, hits).await
    } else {
      self.block = Some(block);
      Ok(Vec::new())
    }
  }

  async fn continuation_frame(
    &mut self,
    stream_id: u32,
    flags: u8,
    payload: &[u8],
    raw: &[u8],
    hits: &mut Vec<Hit>,
  ) -> Result<Vec<u8>, Vec<u8>> {
    let Some(mut block) = self.block.take() else {
      return Err(raw.to_vec());
    };
    if stream_id == 0 || stream_id != block.stream_id {
      block.raw.extend_from_slice(raw);
      return Err(block.raw);
    }
    block.fragments.extend_from_slice(payload);
    block.raw.extend_from_slice(raw);
    if block.fragments.len() > H2_MAX_BLOCK {
      return Err(block.raw);
    }
    if flags & FLAG_END_HEADERS != 0 {
      self.finish_block(block, hits).await
    } else {
      self.block = Some(block);
      Ok(Vec::new())
    }
  }

  async fn data_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8], raw: &[u8], hits: &mut Vec<Hit>) -> Result<Vec<u8>, Vec<u8>> {
    if stream_id == 0 || !self.open_streams.contains(&stream_id) {
      return Err(raw.to_vec());
    }
    let data = data_payload(flags, payload).ok_or_else(|| raw.to_vec())?;
    if self.mint_active() {
      return Ok(self.mint_data_frame(stream_id, flags, data, hits));
    }
    let end_stream = flags & FLAG_END_STREAM != 0;
    // Prepend the hold-back so cross-frame split secrets substitute whole;
    // hold the overlap window for the next frame (bounded by tail_size).
    // Padding is dropped and the length rewritten — always legal framing.
    let held_tail = self.data_tails.get_mut(&stream_id).map(std::mem::take).unwrap_or_default();
    let mut combined = held_tail;
    combined.extend_from_slice(data);
    let hold = if end_stream {
      0
    } else {
      // Never slice a needle: emit past complete matches, hold any trailing
      // partial. A fixed window could cut a needle ending inside it.
      combined.len() - needle_safe_emit_len(&combined, &self.pairs, self.tail_size)
    };
    let emit_len = combined.len() - hold;
    let (new_emit, mut data_hits) = replace_in(&combined[..emit_len], &self.pairs, Location::Body);
    let mut new_emit = new_emit.into_owned();
    hits.append(&mut data_hits);
    if let Some(hook) = self.hook.as_mut()
      && hook.rewrite_chunk(&mut new_emit, end_stream).await == Verdict::Close
    {
      self.must_close = true;
      return Ok(Vec::new());
    }
    if end_stream {
      // Release the stream slot: otherwise long-lived H2 connections leak
      // one open_streams entry per DATA-terminated stream until the 1024
      // cap degrades the whole connection to opaque.
      self.data_tails.remove(&stream_id);
      self.open_streams.remove(&stream_id);
    } else if hold > 0 {
      self.data_tails.insert(stream_id, combined[emit_len..].to_vec());
    }
    let mut out_flags = flags & !(FLAG_PADDED | FLAG_END_STREAM);
    if end_stream {
      out_flags |= FLAG_END_STREAM;
    }
    if new_emit.len() > 0xff_ffff {
      // Substitution grew the payload past the 24-bit length field: the
      // frame cannot be legally re-framed, so degrade rather than lie.
      // With a hook active the growth may hide an unsigned body: fail closed.
      if self.hook.is_some() {
        self.must_close = true;
        return Ok(Vec::new());
      }
      return Err(raw.to_vec());
    }
    let mut frame = Vec::with_capacity(9 + new_emit.len());
    append_frame(&mut frame, F_DATA, out_flags, stream_id, &new_emit);
    Ok(frame)
  }

  /// Mint-active response DATA: buffer the stream's payload whole, then
  /// mint and re-emit as one frame at `END_STREAM`. The JSON rewrite needs
  /// the complete body, and H2 re-frames freely, so nothing streams.
  fn mint_data_frame(&mut self, stream_id: u32, flags: u8, data: &[u8], hits: &mut Vec<Hit>) -> Vec<u8> {
    let end_stream = flags & FLAG_END_STREAM != 0;
    let buf = self.mint_streams.entry(stream_id).or_default();
    buf.extend_from_slice(data);
    if buf.len() > MAX_MINT_BODY {
      self.must_close = true;
      self.mint_streams.remove(&stream_id);
      self.open_streams.remove(&stream_id);
      return Vec::new();
    }
    if !end_stream {
      return Vec::new();
    }
    let body = self.mint_streams.remove(&stream_id).unwrap_or_default();
    self.open_streams.remove(&stream_id);
    let (new_body, mut body_hits) = self.mint_body(&body);
    hits.append(&mut body_hits);
    if new_body.len() > 0xff_ffff {
      // The minted body cannot fit one 24-bit length field: fail closed
      // rather than split what the JSON rewrite produced.
      self.must_close = true;
      return Vec::new();
    }
    let mut frame = Vec::with_capacity(9 + new_body.len());
    append_frame(&mut frame, F_DATA, FLAG_END_STREAM, stream_id, &new_body);
    frame
  }

  /// Mint + redact through the shared body walk; when the plan or handle
  /// went missing mid-stream the pair redaction still applies.
  fn mint_body(&mut self, body: &[u8]) -> (Vec<u8>, Vec<Hit>) {
    if let (Some(plan), Some(mint)) = (&self.mint_plan, &self.mint) {
      mint_and_redact(plan, mint, body, &self.pairs)
    } else {
      let (redacted, hits) = replace_in(body, &self.pairs, Location::Body);
      (redacted.into_owned(), hits)
    }
  }

  async fn finish_block(&mut self, block: H2Block, hits: &mut Vec<Hit>) -> Result<Vec<u8>, Vec<u8>> {
    let mut frag = block.fragments;
    let mut headers: Vec<(Vec<u8>, Vec<u8>, u8)> = Vec::new();
    if self.decoder.decode(&mut frag, &mut headers).is_err() {
      return Err(block.raw);
    }
    if headers.len() > H2_MAX_FIELDS {
      return Err(block.raw);
    }
    // A finished HEADERS block starts a message: pairs minted since the
    // last block (on this or any connection) go live now.
    if self.mint.is_some() {
      self.refresh_minted_pairs();
    }
    substitute_h2_values(&mut headers, &self.pairs, hits);
    if let Some(hook) = self.hook.as_mut() {
      let has_method = headers.iter().any(|(name, _, _)| name.eq_ignore_ascii_case(b":method"));
      let has_status = headers.iter().any(|(name, _, _)| name.eq_ignore_ascii_case(b":status"));
      if has_method || has_status {
        if !rewrite_h2_head(hook, &mut headers).await {
          self.must_close = true;
          return Err(block.raw);
        }
      } else {
        let mut trailers: Vec<PluginHeader> = headers
          .iter()
          .map(|(name, value, _)| PluginHeader {
            name: String::from_utf8_lossy(name).into_owned(),
            value: value.clone(),
          })
          .collect();
        if hook.rewrite_trailers(&mut trailers).await == Verdict::Close {
          self.must_close = true;
          return Err(block.raw);
        }
        headers = trailers
          .into_iter()
          .map(|header| (header.name.into_bytes(), header.value, 0))
          .collect();
      }
    }
    if self.dir == Direction::Downstream && is_head_method(&headers) {
      self.head_requests += 1;
    }
    // HEADERS without opening the stream, so stray DATA frames fail the
    // `open_streams` check and degrade to opaque instead of substituting
    let no_body = self.dir == Direction::Upstream && (self.suppress_body > 0 || response_status_no_body(&headers));
    // Trailer HEADERS (no `:status`) must not consume a pending HEAD
    // suppression — only real response heads decrement. Interim 1xx heads
    // (e.g. 103 Early Hints) keep the suppression for the final response.
    let status: Option<u16> = headers.iter().find_map(|(name, value, _)| {
      if !name.eq_ignore_ascii_case(b":status") {
        return None;
      }
      match std::str::from_utf8(value) {
        Ok(value) => {
          let parsed: Result<u16, _> = value.trim().parse();
          parsed.ok()
        }
        Err(_) => None,
      }
    });
    let has_status = status.is_some();
    let interim = status.is_some_and(|code| (100..200).contains(&code));
    if has_status && !interim && self.suppress_body > 0 && self.dir == Direction::Upstream {
      self.suppress_body -= 1;
    }
    let mut encoded = Vec::new();
    for (name, value, _) in &mut headers {
      if self
        .encoder
        .encode((std::mem::take(name), std::mem::take(value), Encoder::NEVER_INDEXED), &mut encoded)
        .is_err()
      {
        return Err(block.raw);
      }
    }
    if !no_body && !self.open_streams.contains(&block.stream_id) {
      if self.open_streams.len() >= H2_MAX_STREAMS {
        return Err(block.raw);
      }
      self.open_streams.insert(block.stream_id);
    }
    let mut out = Vec::new();
    if block.end_stream {
      // A mint-buffered stream ended by trailers: mint and emit the whole
      // body as a final DATA frame before the trailer block.
      if let Some(body) = self.mint_streams.remove(&block.stream_id) {
        let (new_body, mut body_hits) = self.mint_body(&body);
        hits.append(&mut body_hits);
        if new_body.len() > 0xff_ffff {
          self.must_close = true;
          return Ok(Vec::new());
        }
        if !new_body.is_empty() {
          append_frame(&mut out, F_DATA, 0, block.stream_id, &new_body);
        }
      }
      self.flush_trailer_held(block.stream_id, &mut out, hits).await;
      self.open_streams.remove(&block.stream_id);
    }
    append_header_frames(&mut out, block.stream_id, block.end_stream, &encoded);
    Ok(out)
  }

  /// Trailer-terminated stream: the DATA hold-back window still parks body
  /// bytes (no DATA `END_STREAM` released them). Flush them as a final DATA
  /// frame before the trailer block, or they are lost — split secrets
  /// included.
  async fn flush_trailer_held(&mut self, stream_id: u32, out: &mut Vec<u8>, hits: &mut Vec<Hit>) {
    if let Some(held) = self.data_tails.remove(&stream_id)
      && !held.is_empty()
    {
      let (new_held, mut held_hits) = replace_in(&held, &self.pairs, Location::Body);
      let mut new_held = new_held.into_owned();
      hits.append(&mut held_hits);
      let mut closed = false;
      if let Some(hook) = self.hook.as_mut()
        && hook.rewrite_chunk(&mut new_held, true).await == Verdict::Close
      {
        self.must_close = true;
        closed = true;
      }
      if !closed {
        let mut offset = 0;
        while offset < new_held.len() {
          let take = (new_held.len() - offset).min(0xff_ffff);
          append_frame(out, F_DATA, 0, stream_id, &new_held[offset..offset + take]);
          offset += take;
        }
      }
    }
  }

  fn go_opaque(&mut self, out: &mut Vec<u8>, hits: &mut Vec<Hit>) {
    self.phase = H2Phase::Opaque;
    self.block = None;
    if self.hook.is_some() {
      self.must_close = true;
    }
    // Mint-buffered bodies hold unminted real tokens: emitting them raw on
    // the opaque path would leak. Drop and fail closed instead.
    if !self.mint_streams.is_empty() {
      self.mint_streams.clear();
      self.must_close = true;
    }
    let rest = std::mem::take(&mut self.buffer);
    hits.extend(scan_with_tail(
      &self.pairs,
      &mut self.scan_tail,
      self.tail_size,
      &rest,
      Location::Body,
    ));
    out.extend_from_slice(&rest);
  }
}

#[cfg(test)]
impl H2 {
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

impl Wire for H2 {
  async fn feed<'a>(&mut self, chunk: &'a [u8]) -> (Rewritten<'a>, Vec<Hit>) {
    let (out, hits) = H2::substitute(self, chunk).await;
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
fn finalize_borrow(chunk: &[u8], out: Vec<u8>, hits: Vec<Hit>) -> (Cow<'_, [u8]>, Vec<Hit>) {
  if out.as_slice() == chunk {
    (Cow::Borrowed(chunk), hits)
  } else {
    (Cow::Owned(out), hits)
  }
}

/// Substitute all pairs in decoded header values. `:authority` is skipped
/// (routing safety); `authorization: Basic` is decoded first like HTTP/1.
fn substitute_h2_values(headers: &mut [(Vec<u8>, Vec<u8>, u8)], pairs: &[CredentialPair], hits: &mut Vec<Hit>) {
  for pair in pairs {
    let mut header_hit = false;
    let mut basic_hit = false;
    let needle_str = std::str::from_utf8(&pair.needle).ok();
    let repl_str = std::str::from_utf8(&pair.replacement).ok();
    for (name, value, _) in headers.iter_mut() {
      if name.eq_ignore_ascii_case(b":authority") {
        continue;
      }
      if name.eq_ignore_ascii_case(b"authorization")
        && let (Some(needle), Some(repl)) = (needle_str, repl_str)
        && let Ok(val_str) = std::str::from_utf8(value)
        && let Some(new_val) = substitute_basic_value(val_str, needle, repl)
      {
        *value = new_val.into_bytes();
        basic_hit = true;
        continue;
      }
      if let Some(next) = replace_bytes(value, &pair.needle, &pair.replacement) {
        *value = next;
        header_hit = true;
      }
    }
    if basic_hit {
      hits.push(Hit {
        label: pair.label.clone(),
        location: Location::BasicAuth,
      });
    }
    if header_hit {
      hits.push(Hit {
        label: pair.label.clone(),
        location: Location::Header,
      });
    }
  }
}

/// Regular (non-pseudo) decoded H2 fields as hook-visible headers.
fn regular_h2_headers(headers: &[(Vec<u8>, Vec<u8>, u8)]) -> Vec<PluginHeader> {
  headers
    .iter()
    .filter(|(name, _, _)| name.first() != Some(&b':'))
    .map(|(name, value, _)| PluginHeader {
      name: String::from_utf8_lossy(name).into_owned(),
      value: value.clone(),
    })
    .collect()
}

/// Find a pseudo-header value, lossy-decoded.
fn pseudo_value(headers: &[(Vec<u8>, Vec<u8>, u8)], name: &[u8]) -> Option<String> {
  headers
    .iter()
    .find(|(field, _, _)| field.eq_ignore_ascii_case(name))
    .map(|(_, value, _)| String::from_utf8_lossy(value).into_owned())
}
/// Rebuilt pseudo-headers plus hook-returned regular headers.
type HookedHead = (Vec<(Vec<u8>, Vec<u8>)>, Vec<PluginHeader>);

/// Run the head hook over decoded headers: swap is stage 0, the plugin is
/// stage 1. Pseudo-headers ride outside the hook-visible list (routing
/// safety); the hook's regular headers replace the block's wholesale while
/// the extracted `:method`/`:path`/`:status` are re-injected at the front.
/// Returns false on `Verdict::Close`. An unparseable `:status` or a head the
/// hook retypes to the other variant keeps legacy pseudos: only the regular
/// headers are applied.
async fn rewrite_h2_head(hook: &mut Box<dyn RewriteHook>, headers: &mut Vec<(Vec<u8>, Vec<u8>, u8)>) -> bool {
  let is_response = headers.iter().any(|(name, _, _)| name.eq_ignore_ascii_case(b":status"));
  let mut head = if is_response {
    let Some(status) = pseudo_value(headers, b":status").and_then(|value| value.trim().parse::<u16>().ok()) else {
      return true;
    };
    PluginHead::Response {
      status,
      headers: regular_h2_headers(headers),
    }
  } else {
    PluginHead::Request {
      method: pseudo_value(headers, b":method").unwrap_or_default(),
      path_with_query: pseudo_value(headers, b":path").unwrap_or_default(),
      headers: regular_h2_headers(headers),
    }
  };
  if hook.rewrite_head(&mut head).await == Verdict::Close {
    return false;
  }
  let (pseudos, hooked): HookedHead = match head {
    PluginHead::Request {
      method,
      path_with_query,
      headers,
    } if !is_response => (
      vec![
        (b":method".to_vec(), method.into_bytes()),
        (b":path".to_vec(), path_with_query.into_bytes()),
      ],
      headers,
    ),
    PluginHead::Response { status, headers } if is_response => (vec![(b":status".to_vec(), status.to_string().into_bytes())], headers),
    PluginHead::Request { headers, .. } | PluginHead::Response { headers, .. } => (Vec::new(), headers),
  };
  let mut others: Vec<(Vec<u8>, Vec<u8>, u8)> = Vec::new();
  for (name, value, flag) in std::mem::take(headers) {
    if name.first() != Some(&b':') {
      continue;
    }
    if pseudos.iter().any(|(fresh, _)| fresh.eq_ignore_ascii_case(&name)) {
      continue;
    }
    others.push((name, value, flag));
  }
  let mut rebuilt: Vec<(Vec<u8>, Vec<u8>, u8)> = pseudos
    .into_iter()
    .map(|(name, value)| (name, value, Encoder::NEVER_INDEXED))
    .collect();
  rebuilt.append(&mut others);
  for header in hooked {
    rebuilt.push((header.name.into_bytes(), header.value, Encoder::NEVER_INDEXED));
  }
  *headers = rebuilt;
  true
}

fn headers_fragment(flags: u8, payload: &[u8]) -> Option<&[u8]> {
  let mut start = 0;
  let pad_len = if flags & FLAG_PADDED != 0 {
    start = 1;
    *payload.first()? as usize
  } else {
    0
  };
  if flags & FLAG_PRIORITY != 0 {
    start += 5;
  }
  if payload.len() < start + pad_len {
    return None;
  }
  Some(&payload[start..payload.len() - pad_len])
}

fn data_payload(flags: u8, payload: &[u8]) -> Option<&[u8]> {
  if flags & FLAG_PADDED == 0 {
    return Some(payload);
  }
  let pad_len = *payload.first()? as usize;
  if payload.len() < 1 + pad_len {
    return None;
  }
  Some(&payload[1..payload.len() - pad_len])
}

/// Emit a header block as HEADERS + CONTINUATION* capped at 16 KiB payloads.
fn append_header_frames(out: &mut Vec<u8>, stream_id: u32, end_stream: bool, block: &[u8]) {
  let mut first = true;
  let mut offset = 0;
  while first || offset < block.len() {
    let take = (block.len() - offset).min(H2_OUTBOUND_PAYLOAD);
    let payload = &block[offset..offset + take];
    offset += take;
    let kind = if first { F_HEADERS } else { F_CONTINUATION };
    let mut flags = 0;
    if offset == block.len() {
      flags |= FLAG_END_HEADERS;
    }
    if first && end_stream {
      flags |= FLAG_END_STREAM;
    }
    append_frame(out, kind, flags, stream_id, payload);
    first = false;
  }
}

/// Append one H2 frame header + payload. `payload` must fit the 24-bit
/// length field; callers cap at `H2_OUTBOUND_PAYLOAD` or reject on parse.
fn append_frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
  let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
  out.extend_from_slice(&len.to_be_bytes()[1..]);
  out.push(kind);
  out.push(flags);
  out.extend_from_slice(&stream_id.to_be_bytes());
  out.extend_from_slice(payload);
}

#[cfg(test)]
mod h2_tests {
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

  fn req_machine() -> H2 {
    H2::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Downstream, None, None)
  }

  fn resp_machine() -> H2 {
    H2::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Upstream, None, None)
  }

  fn mint_resp_machine(store: crate::mint::MintStore) -> H2 {
    H2::new(
      &flow_grants(),
      Scheme::Https,
      "auth.example.com",
      443,
      Direction::Upstream,
      None,
      Some(store),
    )
  }

  fn encode_headers(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut encoder = Encoder::default();
    let mut out = Vec::new();
    for (name, value) in fields {
      encoder
        .encode(
          (name.as_bytes().to_vec(), value.as_bytes().to_vec(), Encoder::NEVER_INDEXED),
          &mut out,
        )
        .unwrap();
    }
    out
  }

  fn decode_headers(block: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut decoder = Decoder::default();
    let mut buf = block.to_vec();
    let mut headers = Vec::new();
    decoder.decode(&mut buf, &mut headers).unwrap();
    headers.into_iter().map(|(name, value, _)| (name, value)).collect()
  }

  fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    append_frame(&mut out, kind, flags, stream, payload);
    out
  }

  fn first_frame_payload(out: &[u8]) -> (u8, u8, u32, Vec<u8>) {
    let len = ((out[0] as usize) << 16) | ((out[1] as usize) << 8) | out[2] as usize;
    let kind = out[3];
    let flags = out[4];
    let stream = u32::from_be_bytes([out[5], out[6], out[7], out[8]]) & 0x7fff_ffff;
    (kind, flags, stream, out[9..9 + len].to_vec())
  }

  #[tokio::test]
  async fn h2_request_headers_substituted() {
    let mut machine = req_machine();
    // Preface split across writes is held, not emitted.
    let (out1, _) = machine.substitute(&H2_PREFACE[..10]).await;
    assert_eq!(out1.into_owned(), [] as [u8; 0]);

    let block = encode_headers(&[
      (":method", "GET"),
      (":scheme", "https"),
      (":path", "/"),
      (":authority", "api.github.com"),
      ("authorization", &format!("Bearer {FAKE}")),
    ]);
    let mut input = H2_PREFACE[10..].to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block));
    let (out, hits) = machine.substitute(&input).await;
    let out = out.into_owned();
    assert!(out.starts_with(H2_PREFACE), "preface must pass through first");
    let (kind, flags, stream, payload) = first_frame_payload(&out[H2_PREFACE.len()..]);
    assert_eq!(kind, F_HEADERS);
    assert_eq!(stream, 1);
    assert_ne!(flags & FLAG_END_HEADERS, 0);
    assert_ne!(flags & FLAG_END_STREAM, 0);
    let headers = decode_headers(&payload);
    let auth = headers.iter().find(|(name, _)| name == b"authorization").unwrap();
    assert_eq!(auth.1, format!("Bearer {VALUE}").as_bytes());
    assert!(headers.iter().any(|(name, _)| name == b":authority"));
    assert!(hits.iter().any(|hit| hit.location == Location::Header));
  }

  #[tokio::test]
  async fn h2_continuation_block_substituted() {
    let mut machine = req_machine();
    let block = encode_headers(&[(":method", "POST"), ("authorization", &format!("Bearer {FAKE}"))]);
    let mid = block.len() / 2;
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, 0, 1, &block[..mid]));
    input.extend_from_slice(&frame(F_CONTINUATION, FLAG_END_HEADERS, 1, &block[mid..]));
    let (out, _) = machine.substitute(&input).await;
    let out = out.into_owned();
    let (_, _, _, payload) = first_frame_payload(&out[H2_PREFACE.len()..]);
    let headers = decode_headers(&payload);
    let auth = headers.iter().find(|(name, _)| name == b"authorization").unwrap();
    assert_eq!(auth.1, format!("Bearer {VALUE}").as_bytes());
  }

  #[tokio::test]
  async fn h2_data_substituted_with_hit() {
    let mut machine = req_machine();
    let block = encode_headers(&[(":method", "POST"), (":path", "/upload")]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS, 1, &block));
    let payload = format!("blob-{FAKE}-blob");
    input.extend_from_slice(&frame(F_DATA, FLAG_END_STREAM, 1, payload.as_bytes()));
    let (out, hits) = machine.substitute(&input).await;
    let out = out.into_owned();
    // Skip the re-encoded HEADERS frame; DATA carries the real value now.
    let mut rest = &out[H2_PREFACE.len()..];
    let hlen = ((rest[0] as usize) << 16) | ((rest[1] as usize) << 8) | rest[2] as usize;
    rest = &rest[9 + hlen..];
    let (kind, _, _, data) = first_frame_payload(rest);
    assert_eq!(kind, F_DATA);
    assert_eq!(data, format!("blob-{VALUE}-blob").as_bytes());
    assert_eq!(
      hits,
      vec![Hit {
        label: "github".into(),
        location: Location::Body
      }]
    );
  }

  #[tokio::test]
  async fn h2_data_response_redacted() {
    let mut machine = resp_machine();
    let block = encode_headers(&[(":status", "200")]);
    let mut input = frame(F_HEADERS, FLAG_END_HEADERS, 1, &block);
    let payload = format!("tok-{VALUE}-end");
    input.extend_from_slice(&frame(F_DATA, FLAG_END_STREAM, 1, payload.as_bytes()));
    let (out, hits) = machine.substitute(&input).await;
    let out = out.into_owned();
    let hlen = ((out[0] as usize) << 16) | ((out[1] as usize) << 8) | out[2] as usize;
    let (kind, _, _, data) = first_frame_payload(&out[9 + hlen..]);
    assert_eq!(kind, F_DATA);
    assert_eq!(data, format!("tok-{FAKE}-end").as_bytes());
    assert!(hits.iter().any(|hit| hit.location == Location::Body));
  }

  #[tokio::test]
  async fn h2_response_redacts_values() {
    let mut machine = resp_machine();
    let block = encode_headers(&[(":status", "200"), ("x-echo", VALUE)]);
    let input = frame(F_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block);
    let (out, _) = machine.substitute(&input).await;
    let (_, _, _, payload) = first_frame_payload(&out);
    let headers = decode_headers(&payload);
    let echo = headers.iter().find(|(name, _)| name == b"x-echo").unwrap();
    assert_eq!(echo.1, FAKE.as_bytes());
  }

  #[tokio::test]
  async fn h2_head_request_suppresses_response_data() {
    let mut req = req_machine();
    let block = encode_headers(&[(":method", "HEAD"), (":path", "/"), (":authority", "api.github.com")]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block));
    let (_, _) = req.substitute(&input).await;
    assert_eq!(req.take_head_requests(), 1);

    let mut resp = resp_machine();
    resp.suppress_next_bodies(1);
    let rblock = encode_headers(&[(":status", "200"), ("x-echo", VALUE)]);
    let input = frame(F_HEADERS, FLAG_END_HEADERS, 1, &rblock);
    let (out, _) = resp.substitute(&input).await;
    let (_, _, _, payload) = first_frame_payload(&out);
    let headers = decode_headers(&payload);
    let echo = headers.iter().find(|(name, _)| name == b"x-echo").unwrap();
    assert_eq!(echo.1, FAKE.as_bytes());
    // Stream never opened: stray DATA is not substituted, just forwarded.
    let data = frame(F_DATA, FLAG_END_STREAM, 1, format!("tok-{VALUE}-end").as_bytes());
    let (out, _) = resp.substitute(&data).await;
    assert!(
      out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()),
      "stray DATA must pass through"
    );
  }

  #[tokio::test]
  async fn h2_garbage_goes_opaque_unchanged() {
    let mut machine = req_machine();
    let input = b"GARBAGE-NOT-A-PREFACE-AT-ALL-!!!!";
    assert!(input.len() >= H2_PREFACE.len());
    let (out, _) = machine.substitute(input).await;
    assert_eq!(out.as_ref(), input.as_slice());
    // Stays opaque: later chunks borrowed.
    let (out, _) = machine.substitute(b"more-bytes").await;
    assert!(matches!(out, Cow::Borrowed(_)));
  }

  #[tokio::test]
  async fn h2_push_promise_forwarded_unchanged() {
    let mut machine = req_machine();
    let mut input = H2_PREFACE.to_vec();
    let promise = frame(0x5, FLAG_END_HEADERS, 1, b"promised-payload");
    input.extend_from_slice(&promise);
    let (out, hits) = machine.substitute(&input).await;
    assert_eq!(out.into_owned(), input);
    assert_eq!(hits, [] as [Hit; 0]);
  }

  #[tokio::test]
  async fn h2_data_end_stream_releases_stream_id() {
    let mut machine = req_machine();
    let block = encode_headers(&[(":method", "POST"), (":path", "/upload")]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS, 1, &block));
    let (_, _) = machine.substitute(&input).await;
    assert!(machine.open_streams.contains(&1), "POST stream opens");
    let data = frame(F_DATA, FLAG_END_STREAM, 1, b"payload");
    let (_, _) = machine.substitute(&data).await;
    assert!(!machine.open_streams.contains(&1), "DATA END_STREAM must release the stream");
    assert!(machine.data_tails.is_empty());
  }

  #[tokio::test]
  async fn h2_interim_103_keeps_head_suppression() {
    let mut resp = resp_machine();
    resp.suppress_next_bodies(1);
    let interim = encode_headers(&[(":status", "103")]);
    let input = frame(F_HEADERS, FLAG_END_HEADERS, 1, &interim);
    let (_, _) = resp.substitute(&input).await;
    assert_eq!(resp.suppress_body, 1, "interim 1xx must not consume HEAD suppression");
    let final_head = encode_headers(&[(":status", "200")]);
    let input = frame(F_HEADERS, FLAG_END_HEADERS, 1, &final_head);
    let (_, _) = resp.substitute(&input).await;
    assert_eq!(resp.suppress_body, 0);
  }

  /// Stage-1 hook double: appends markers, adds headers/trailers, or votes
  /// `Close`. Wire-observable only; the machine owns the boxed hook.
  #[derive(Default)]
  struct MockHook {
    add_header: Option<(String, Vec<u8>)>,
    append_body: Vec<u8>,
    add_trailer: Option<(String, Vec<u8>)>,
    close_head: bool,
    close_chunk: bool,
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
        if let Some((name, value)) = self.add_trailer.clone() {
          headers.push(PluginHeader { name, value });
        }
        Verdict::Continue
      })
    }

    fn rewrite_chunk<'a>(&'a mut self, data: &'a mut Vec<u8>, _eof: bool) -> arkham_plugin::BoxFuture<'a, Verdict> {
      Box::pin(async move {
        if self.close_chunk {
          return Verdict::Close;
        }
        data.extend_from_slice(&self.append_body);
        Verdict::Continue
      })
    }
  }

  fn req_hooked(hook: MockHook) -> H2 {
    H2::new(
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
  async fn mock_hook_rewrites_h2_head() {
    let mut machine = req_hooked(MockHook {
      add_header: Some(("x-hook".to_string(), b"1".to_vec())),
      ..Default::default()
    });
    let block = encode_headers(&[
      (":method", "GET"),
      (":scheme", "https"),
      (":path", "/"),
      (":authority", "api.github.com"),
      ("x-echo", FAKE),
    ]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block));
    let (out, _) = machine.substitute(&input).await;
    let out = out.into_owned();
    let (_, _, _, payload) = first_frame_payload(&out[H2_PREFACE.len()..]);
    let headers = decode_headers(&payload);
    let echo = headers.iter().find(|(name, _)| name == b"x-echo").unwrap();
    assert_eq!(echo.1, VALUE.as_bytes(), "swap is stage 0");
    assert!(
      headers.iter().any(|(name, value)| name == b"x-hook" && value == b"1"),
      "hook header present"
    );
    assert!(!machine.must_close());
  }

  #[tokio::test]
  async fn mock_hook_rewrites_h2_data_frame() {
    let mut machine = req_hooked(MockHook {
      append_body: b"-hooked".to_vec(),
      ..Default::default()
    });
    let block = encode_headers(&[
      (":method", "POST"),
      (":scheme", "https"),
      (":path", "/x"),
      (":authority", "api.github.com"),
    ]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS, 1, &block));
    let payload = format!("tok-{FAKE}-end").into_bytes();
    input.extend_from_slice(&frame(F_DATA, FLAG_END_STREAM, 1, &payload));
    let (out, _) = machine.substitute(&input).await;
    let out = out.into_owned();
    let expect = format!("tok-{VALUE}-end-hooked");
    assert!(
      out.windows(expect.len()).any(|w| w == expect.as_bytes()),
      "swapped + hooked DATA on the wire"
    );
    assert!(!machine.must_close());
  }

  #[tokio::test]
  async fn mock_hook_rewrites_h2_trailer_block() {
    let mut machine = req_hooked(MockHook {
      add_trailer: Some(("x-hooked-trailer".to_string(), b"1".to_vec())),
      ..Default::default()
    });
    let block = encode_headers(&[
      (":method", "POST"),
      (":scheme", "https"),
      (":path", "/x"),
      (":authority", "api.github.com"),
    ]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS, 1, &block));
    let trailers = encode_headers(&[("x-t", "abc")]);
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &trailers));
    let (out, _) = machine.substitute(&input).await;
    let out = out.into_owned();
    let needle = b"x-hooked-trailer";
    assert!(out.windows(needle.len()).any(|w| w == needle), "hooked trailer on the wire");
    assert!(!machine.must_close());
  }

  #[tokio::test]
  async fn h2_trailer_flushes_held_data_tail() {
    // DATA without END_STREAM parks the overlap window; the trailer
    // HEADERS ends the stream and must flush those bytes — substituted —
    // before the trailer block, not drop them.
    let mut machine = req_machine();
    let block = encode_headers(&[(":method", "POST"), (":path", "/x")]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS, 1, &block));
    let payload = format!("x{FAKE}y").into_bytes();
    input.extend_from_slice(&frame(F_DATA, 0, 1, &payload));
    let trailers = encode_headers(&[("x-t", "abc")]);
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &trailers));
    let (out, hits) = machine.substitute(&input).await;
    let out = out.into_owned();
    assert!(
      out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()),
      "held tail flushed substituted"
    );
    assert!(hits.iter().any(|hit| hit.location == Location::Body));
    assert!(machine.data_tails.is_empty(), "stream tail released");
    assert!(!machine.must_close());
  }

  #[tokio::test]
  async fn h2_needle_ending_in_hold_window_not_sliced() {
    // The needle ends inside the (former fixed-size) hold-back window but
    // starts before it: a window cut would emit its prefix raw and the
    // match would never recombine. It must be substituted in frame one.
    let mut machine = req_machine();
    let block = encode_headers(&[(":method", "POST"), (":path", "/x")]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS, 1, &block));
    let payload = format!("x{FAKE}y").into_bytes();
    input.extend_from_slice(&frame(F_DATA, 0, 1, &payload));
    input.extend_from_slice(&frame(F_DATA, FLAG_END_STREAM, 1, b"zz"));
    let (out, hits) = machine.substitute(&input).await;
    let out = out.into_owned();
    assert!(
      out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()),
      "needle inside one frame substituted whole"
    );
    assert!(hits.iter().any(|hit| hit.location == Location::Body));
    assert!(machine.data_tails.is_empty());
    assert!(!machine.must_close());
  }

  #[tokio::test]
  async fn h2_needle_split_across_data_frames() {
    // The needle straddles two DATA frames mid-token: the per-stream
    // hold-back window must recombine it, never emit the prefix raw.
    let mut machine = req_machine();
    let block = encode_headers(&[(":method", "POST"), (":path", "/x")]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS, 1, &block));
    let (a, b) = FAKE.split_at(15);
    input.extend_from_slice(&frame(F_DATA, 0, 1, format!("pre-{a}").as_bytes()));
    input.extend_from_slice(&frame(F_DATA, FLAG_END_STREAM, 1, format!("{b}-post").as_bytes()));
    let (out, hits) = machine.substitute(&input).await;
    let out = out.into_owned();
    assert!(
      out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()),
      "split needle recombined and substituted"
    );
    assert!(!out.windows(FAKE.len() - 1).any(|w| w == &FAKE.as_bytes()[..FAKE.len() - 1]));
    assert!(hits.iter().any(|hit| hit.location == Location::Body));
    assert!(machine.data_tails.is_empty());
    assert!(!machine.must_close());
  }

  #[tokio::test]
  async fn h2_token_response_mints_and_reframes() {
    let store = crate::mint::MintStore::default();
    let mut resp = mint_resp_machine(store.clone());
    let block = encode_headers(&[(":status", "200")]);
    let mut input = frame(F_HEADERS, FLAG_END_HEADERS, 1, &block);
    let body = r#"{"access_token":"real-token-value","token_type":"Bearer"}"#;
    input.extend_from_slice(&frame(F_DATA, FLAG_END_STREAM, 1, body.as_bytes()));
    let (out, hits) = resp.substitute(&input).await;
    let out = out.into_owned();
    let decoy = store.snapshot_pairs()[0].0.clone();
    assert!(!out.windows(16).any(|w| w == b"real-token-value"), "real token never emitted");
    assert!(out.windows(decoy.len()).any(|w| w == decoy.as_bytes()), "decoy emitted");
    assert!(hits.iter().any(|hit| hit.location == Location::Body));
    assert!(!resp.must_close());
  }

  #[tokio::test]
  async fn h2_split_data_frames_mint_at_end_stream() {
    let store = crate::mint::MintStore::default();
    let mut resp = mint_resp_machine(store.clone());
    let block = encode_headers(&[(":status", "200")]);
    let mut input = frame(F_HEADERS, FLAG_END_HEADERS, 1, &block);
    let (a, b) = r#"{"access_token":"real-token-value"}"#.split_at(20);
    input.extend_from_slice(&frame(F_DATA, 0, 1, a.as_bytes()));
    input.extend_from_slice(&frame(F_DATA, FLAG_END_STREAM, 1, b.as_bytes()));
    let (out, _) = resp.substitute(&input).await;
    let out = out.into_owned();
    assert!(!out.windows(16).any(|w| w == b"real-token-value"), "real token never emitted");
    let decoy = store.snapshot_pairs()[0].0.clone();
    assert!(out.windows(decoy.len()).any(|w| w == decoy.as_bytes()), "whole-body decoy emitted");
    assert!(resp.mint_streams.is_empty());
    assert!(!resp.must_close());
  }

  #[tokio::test]
  async fn h2_minted_decoy_substitutes_on_a_later_request_connection() {
    let store = crate::mint::MintStore::default();
    let mut resp = mint_resp_machine(store.clone());
    let block = encode_headers(&[(":status", "200")]);
    let mut input = frame(F_HEADERS, FLAG_END_HEADERS, 1, &block);
    let body = r#"{"access_token":"real-token-value"}"#;
    input.extend_from_slice(&frame(F_DATA, FLAG_END_STREAM, 1, body.as_bytes()));
    let _ = resp.substitute(&input).await;
    let decoy = store.snapshot_pairs()[0].0.clone();
    // A fresh request machine on a new connection unions the minted pair.
    let mut req = H2::new(
      &flow_grants(),
      Scheme::Https,
      "auth.example.com",
      443,
      Direction::Downstream,
      None,
      Some(store.clone()),
    );
    let block = encode_headers(&[
      (":method", "GET"),
      (":path", "/x"),
      (":authority", "auth.example.com"),
      ("authorization", &format!("Bearer {decoy}")),
    ]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block));
    let (out, hits) = req.substitute(&input).await;
    let out = out.into_owned();
    assert!(out.windows(16).any(|w| w == b"real-token-value"), "real value upstream: {out:?}");
    assert!(!out.windows(decoy.len()).any(|w| w == decoy.as_bytes()), "decoy swapped out");
    assert!(hits.iter().any(|hit| hit.location == Location::Header));
  }
}
