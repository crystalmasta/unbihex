pub mod socket;

pub use socket::{InterfaceBinding, ProtectFn, SocketFactory};

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream that first yields `prefix` and then reads from `inner`.
/// Used to hand already-buffered bytes (e.g. after an HTTP head) to a relay.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// Yields `prefix` before reading from `inner`.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        PrefixedStream {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            if self.pos == self.prefix.len() {
                self.prefix = Vec::new();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Bytes that were accepted by `poll_write` but not yet written to the inner stream.
#[derive(Default)]
pub(crate) struct PendingOut {
    buf: Vec<u8>,
    pos: usize,
}

impl PendingOut {
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn extend(&mut self, data: &[u8]) {
        if self.is_empty() {
            self.buf.clear();
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    pub fn buf_mut(&mut self) -> &mut Vec<u8> {
        if self.is_empty() {
            self.buf.clear();
            self.pos = 0;
        }
        &mut self.buf
    }

    /// Writes everything pending into `inner`.
    pub fn poll_drain<W: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        while self.pos < self.buf.len() {
            let n = std::task::ready!(Pin::new(&mut *inner).poll_write(cx, &self.buf[self.pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            self.pos += n;
        }
        self.buf.clear();
        self.pos = 0;
        Poll::Ready(Ok(()))
    }
}
