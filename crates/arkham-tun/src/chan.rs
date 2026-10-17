//! Channel-backed guest stream for connection tasks: AsyncRead/Write over
//! the tracker's mpsc channels. RX close = guest FIN (EOF).

use std::pin::Pin;
use std::task::{Context, Poll};

use std::sync::Arc;

use futures_sink::Sink as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

use crate::tracker::TaskMsg;

/// Guest-facing stream half: writes go to the task, a closed RX reads as
/// the guest's FIN (EOF).
pub(crate) struct ChanStream {
  rx: mpsc::Receiver<Vec<u8>>,
  tx: Option<tokio_util::sync::PollSender<TaskMsg>>,
  pending: Option<(Vec<u8>, usize)>,
  /// The capture loop sleeps while the guest is quiet. A task write does
  /// not arrive as a TUN packet, so the write wakes that sleep.
  wake: Arc<Notify>,
}

impl ChanStream {
  pub(super) fn new(rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::Sender<TaskMsg>, wake: Arc<Notify>) -> Self {
    Self {
      rx,
      tx: Some(tokio_util::sync::PollSender::new(tx)),
      pending: None,
      wake,
    }
  }
}

impl Drop for ChanStream {
  fn drop(&mut self) {
    self.wake.notify_one();
  }
}

impl AsyncRead for ChanStream {
  fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    loop {
      if let Some((data, pos)) = &mut self.pending {
        let n = (data.len() - *pos).min(buf.remaining());
        buf.put_slice(&data[*pos..*pos + n]);
        *pos += n;
        if *pos >= data.len() {
          self.pending = None;
        }
        return Poll::Ready(Ok(()));
      }
      match self.rx.poll_recv(cx) {
        Poll::Ready(Some(data)) => {
          self.pending = Some((data, 0));
        }
        Poll::Ready(None) => return Poll::Ready(Ok(())),
        Poll::Pending => return Poll::Pending,
      }
    }
  }
}

fn broken_pipe(msg: &str) -> std::io::Error {
  std::io::Error::new(std::io::ErrorKind::BrokenPipe, msg)
}

impl AsyncWrite for ChanStream {
  fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
    let Some(tx) = self.tx.as_mut() else {
      return Poll::Ready(Err(broken_pipe("guest stream shut down")));
    };
    match Pin::new(tx).poll_ready(cx) {
      Poll::Ready(Ok(())) => {}
      Poll::Ready(Err(_)) => return Poll::Ready(Err(broken_pipe("guest relay gone"))),
      Poll::Pending => return Poll::Pending,
    }
    let Some(tx) = self.tx.as_mut() else {
      return Poll::Ready(Err(broken_pipe("guest stream shut down")));
    };
    match Pin::new(tx).start_send(TaskMsg::Data(buf.to_vec())) {
      Ok(()) => {
        self.wake.notify_one();
        Poll::Ready(Ok(buf.len()))
      }
      Err(_) => Poll::Ready(Err(broken_pipe("guest relay gone"))),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    self.tx = None;
    self.wake.notify_one();
    Poll::Ready(Ok(()))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn chan_stream_read_write_eof() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let (guest_tx, task_rx) = mpsc::channel::<Vec<u8>>(8);
    let (task_tx, loop_rx) = mpsc::channel::<TaskMsg>(8);
    let mut loop_rx = loop_rx;
    let mut stream = ChanStream::new(task_rx, task_tx, Arc::new(Notify::new()));
    // Task → guest direction.
    stream.write_all(b"hello").await.unwrap();
    match loop_rx.recv().await.unwrap() {
      TaskMsg::Data(data) => assert_eq!(data, b"hello"),
      TaskMsg::Abort => panic!("unexpected abort"),
    }
    // Guest → task direction.
    guest_tx.send(b"world".to_vec()).await.unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"world");
    // Guest FIN → EOF.
    drop(guest_tx);
    assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    // Shutdown → writes fail.
    stream.shutdown().await.unwrap();
    assert!(stream.write_all(b"x").await.is_err());
  }

  #[tokio::test]
  async fn shutdown_wakes_the_capture_loop() {
    use tokio::io::AsyncWriteExt as _;
    let (_guest_tx, task_rx) = mpsc::channel::<Vec<u8>>(8);
    let (task_tx, _loop_rx) = mpsc::channel::<TaskMsg>(8);
    let wake = Arc::new(Notify::new());
    let mut stream = ChanStream::new(task_rx, task_tx, Arc::clone(&wake));
    let notified = wake.notified();
    stream.shutdown().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_millis(50), notified)
      .await
      .expect("shutdown wakes the capture loop");
  }

  #[tokio::test]
  async fn drop_wakes_the_capture_loop() {
    let (_guest_tx, task_rx) = mpsc::channel::<Vec<u8>>(8);
    let (task_tx, _loop_rx) = mpsc::channel::<TaskMsg>(8);
    let wake = Arc::new(Notify::new());
    let stream = ChanStream::new(task_rx, task_tx, Arc::clone(&wake));
    let notified = wake.notified();
    drop(stream);
    tokio::time::timeout(std::time::Duration::from_millis(50), notified)
      .await
      .expect("drop wakes the capture loop");
  }
}
