//! A stream with bytes pushed back in front of it.
//!
//! Reading the request head leaves a buffered reader holding whatever arrived after it. When
//! the connection is then handed to a TLS acceptor, those bytes have to come first or the
//! handshake sees a truncated ClientHello. In practice a client waits for `200 Connection
//! Established` before speaking TLS, so the buffer is usually empty — which is exactly why
//! this needs to be explicit rather than assumed. A pipelining client would otherwise fail
//! rarely and unreproducibly.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub struct Rewind<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Rewind<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self { prefix, pos: 0, inner }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            // Free the buffer once drained; a pipelined head can be large and this object
            // lives as long as the connection.
            if self.pos == self.prefix.len() {
                self.prefix = Vec::new();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn prefix_is_delivered_before_the_stream() {
        let (mut a, b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = a.write_all(b"world").await;
        });

        let mut r = Rewind::new(b, b"hello ".to_vec());
        let mut out = String::new();
        r.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "hello world");
    }

    #[tokio::test]
    async fn a_short_read_buffer_does_not_lose_prefix_bytes() {
        let (a, b) = tokio::io::duplex(64);
        drop(a);
        let mut r = Rewind::new(b, b"abcdef".to_vec());

        let mut out = Vec::new();
        let mut two = [0u8; 2];
        while let Ok(n) = r.read(&mut two).await {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&two[..n]);
        }
        assert_eq!(out, b"abcdef");
    }
}
