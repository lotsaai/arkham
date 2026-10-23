//! Shared property-test harness.
//!
//! [`block_on`] runs one feed on a current-thread runtime for the synchronous
//! HTTP, SMTP, and LDAP properties. [`feed_parts`] awaits the same cuts,
//! including the empty EOF flush `feed(&[])`, on the caller's runtime. NATS
//! properties call [`feed_parts`] from `#[tokio::test]` and do not build a
//! runtime.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

use super::{Rewritten, Wire};

pub(crate) fn emit_bytes(rewritten: Rewritten<'_>) -> Vec<u8> {
  match rewritten {
    Rewritten::Emit(bytes) => bytes.into_owned(),
    Rewritten::Hold | Rewritten::Close => Vec::new(),
  }
}

pub(crate) fn block_on<F>(fut: F) -> F::Output
where
  F: std::future::Future,
{
  thread_local! {
    static RT: tokio::runtime::Runtime =
      tokio::runtime::Builder::new_current_thread().build().expect("test runtime");
  }
  RT.with(|rt| rt.block_on(fut))
}

/// Drain a machine over `splits` (ascending cuts into `data`, implied
/// final cut at `data.len()`), then one empty EOF flush. Concatenated
/// output, total hit count.
pub(crate) fn run_split<M: Wire>(m: &mut M, data: &[u8], splits: &[usize]) -> (Vec<u8>, usize) {
  let (out, hits, _) = run_split_parts(m, data, splits);
  (out, hits)
}

/// [`run_split`] plus whether any feed returned [`Rewritten::Close`].
pub(crate) fn run_split_parts<M: Wire>(m: &mut M, data: &[u8], splits: &[usize]) -> (Vec<u8>, usize, bool) {
  block_on(feed_parts(m, data, splits))
}

/// [`run_split_parts`] on the caller's runtime. The last feed is `feed(&[])`.
pub(crate) async fn feed_parts<M: Wire>(m: &mut M, data: &[u8], splits: &[usize]) -> (Vec<u8>, usize, bool) {
  let mut out = Vec::new();
  let mut hits = 0;
  let mut prev = 0;
  let mut closed = false;
  for &cut in splits.iter().chain(std::iter::once(&data.len())) {
    // A relay only calls with non-empty chunks; an empty call is the
    // EOF flush. Skip cuts that would produce an interior empty call.
    if cut > prev {
      let (rewritten, chunk_hits) = m.feed(&data[prev..cut]).await;
      closed |= matches!(rewritten, Rewritten::Close);
      out.extend_from_slice(&emit_bytes(rewritten));
      hits += chunk_hits.len();
      prev = cut;
    }
  }
  if prev < data.len() {
    let (rewritten, chunk_hits) = m.feed(&data[prev..]).await;
    closed |= matches!(rewritten, Rewritten::Close);
    out.extend_from_slice(&emit_bytes(rewritten));
    hits += chunk_hits.len();
  }
  let (rewritten, chunk_hits) = m.feed(&[]).await;
  closed |= matches!(rewritten, Rewritten::Close);
  out.extend_from_slice(&emit_bytes(rewritten));
  hits += chunk_hits.len();
  (out, hits, closed)
}

/// Drain an H2 machine the same way.
pub(crate) fn run_split_h2<M: Wire>(m: &mut M, data: &[u8], splits: &[usize]) -> (Vec<u8>, usize) {
  run_split(m, data, splits)
}

/// One reply stream. Each poll yields bytes up to the next cut, then
/// pends once before the following poll. The waker is woken so the
/// runtime resumes.
pub(crate) struct CutPend {
  pub(crate) data: Vec<u8>,
  pub(crate) cuts: Vec<usize>,
  pub(crate) at: usize,
  pub(crate) reads: usize,
  pub(crate) pends: usize,
  arm_pend: bool,
}

impl CutPend {
  pub(crate) fn new(data: Vec<u8>, cuts: &[usize]) -> Self {
    let mut cuts: Vec<usize> = cuts.iter().copied().filter(|cut| *cut > 0 && *cut < data.len()).collect();
    cuts.sort_unstable();
    cuts.dedup();
    Self {
      data,
      cuts,
      at: 0,
      reads: 0,
      pends: 0,
      arm_pend: false,
    }
  }
}

impl AsyncRead for CutPend {
  fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    if self.arm_pend {
      self.arm_pend = false;
      self.pends = self.pends.saturating_add(1);
      cx.waker().wake_by_ref();
      return Poll::Pending;
    }
    if buf.remaining() == 0 {
      return Poll::Ready(Ok(()));
    }
    let Some(rest) = self.data.get(self.at..) else {
      return Poll::Ready(Ok(()));
    };
    if rest.is_empty() {
      return Poll::Ready(Ok(()));
    }
    let end = self.cuts.iter().copied().find(|cut| *cut > self.at).unwrap_or(self.data.len());
    let n = end.saturating_sub(self.at).min(buf.remaining());
    if n == 0 {
      return Poll::Ready(Err(std::io::Error::other("reply cut produced an empty read")));
    }
    let Some(chunk) = rest.get(..n) else {
      return Poll::Ready(Ok(()));
    };
    buf.put_slice(chunk);
    self.at = self.at.saturating_add(n);
    self.reads = self.reads.saturating_add(1);
    self.arm_pend = self.at < self.data.len();
    Poll::Ready(Ok(()))
  }
}
