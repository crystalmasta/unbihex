//! XTLS Vision flow (`xtls-rprx-vision`), client side.
//!
//! Vision hides the length pattern of TLS-in-TLS: the first packets of each
//! direction are wrapped in padded blocks
//!
//! ```text
//! [user UUID, first block only] | command | content_len(be16) | padding_len(be16) | content | padding
//! ```
//!
//! with `command` 0 = more padded blocks follow, 1 = padding ends, 2 = padding ends
//! and the sender stops using the outer TLS ("direct copy"). After a 2 from the
//! server, the inner traffic arrives on the bare TCP connection.
//!
//! The client never switches its own direction to direct copy: it ends its padding
//! with command 1 and keeps writing through TLS, which servers accept.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

use super::tls_stream::TlsRecordStream;
use super::vless::VlessStream;
use crate::net::PendingOut;

/// More padded blocks follow.
pub const CMD_CONTINUE: u8 = 0x00;
/// Padding ends; the stream continues inside TLS.
pub const CMD_END: u8 = 0x01;
/// Padding ends; the sender continues on the raw connection.
pub const CMD_DIRECT: u8 = 0x02;

/// Largest content per padded block (Xray buffers are 8 KiB including the 21-byte header).
const MAX_CONTENT: usize = 8192 - 21;
/// Wait this long for client data before sending a padding-only first block.
const FIRST_PACKET_WAIT: Duration = Duration::from_millis(5);
/// Stop padding after this many uplink blocks at the latest.
const MAX_PADDED_PACKETS: u32 = 8;

/// Streams that can stop reading through TLS (see [`TlsRecordStream::switch_to_raw_read`]).
pub trait RawSwitch {
    /// Switches reads to the raw socket; returns already decrypted bytes.
    fn switch_to_raw_read(&mut self) -> io::Result<Vec<u8>>;
}

impl RawSwitch for TlsRecordStream {
    fn switch_to_raw_read(&mut self) -> io::Result<Vec<u8>> {
        TlsRecordStream::switch_to_raw_read(self)
    }
}

impl<S: RawSwitch> RawSwitch for VlessStream<S> {
    fn switch_to_raw_read(&mut self) -> io::Result<Vec<u8>> {
        self.get_mut().switch_to_raw_read()
    }
}

/// One padded block.
pub fn pad_block(uuid: Option<&[u8; 16]>, command: u8, content: &[u8], long: bool) -> Vec<u8> {
    let len = content.len().min(MAX_CONTENT);
    let content = &content[..len];
    let mut rng = rand::thread_rng();
    let mut padding = if long && len < 900 {
        rng.gen_range(0..500) + 900 - len
    } else {
        rng.gen_range(0..256)
    };
    padding = padding.min(MAX_CONTENT - len);
    let mut out = Vec::with_capacity(16 + 5 + len + padding);
    if let Some(u) = uuid {
        out.extend_from_slice(u);
    }
    out.push(command);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&(padding as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding, 0);
    out
}

/// Downlink unpadding state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unpad {
    /// Waiting for 21 bytes to see whether the server pads at all.
    Initial(Vec<u8>),
    /// Inside a block: header bytes still to read, then content and padding.
    Block {
        header_left: u8,
        command: u8,
        content: usize,
        padding: usize,
    },
    /// No more padding: bytes pass through.
    Plain,
}

/// What a chunk of downlink bytes turned into.
#[derive(Debug, Default, PartialEq, Eq)]
struct Unpadded {
    data: Vec<u8>,
    /// The server switched to direct copy.
    direct: bool,
}

/// Downlink parser, independent of I/O for testing.
#[derive(Debug)]
struct Unpadder {
    uuid: [u8; 16],
    state: Unpad,
}

impl Unpadder {
    fn new(uuid: [u8; 16]) -> Self {
        Unpadder {
            uuid,
            state: Unpad::Initial(Vec::new()),
        }
    }

    fn is_plain(&self) -> bool {
        self.state == Unpad::Plain
    }

    /// Feeds bytes; `eof` flushes an incomplete initial check.
    fn feed(&mut self, mut input: &[u8], eof: bool) -> Unpadded {
        let mut out = Unpadded::default();
        loop {
            match &mut self.state {
                Unpad::Plain => {
                    out.data.extend_from_slice(input);
                    return out;
                }
                Unpad::Initial(acc) => {
                    acc.extend_from_slice(input);
                    if acc.len() < 21 && !eof {
                        return out;
                    }
                    let acc = std::mem::take(acc);
                    if acc.len() >= 21 && acc[..16] == self.uuid {
                        self.state = Unpad::Block {
                            header_left: 5,
                            command: 0,
                            content: 0,
                            padding: 0,
                        };
                        // Re-run with the bytes after the UUID.
                        let rest = acc[16..].to_vec();
                        let more = self.feed(&rest, eof);
                        out.data.extend(more.data);
                        out.direct |= more.direct;
                        return out;
                    }
                    // The server does not pad: everything is data.
                    self.state = Unpad::Plain;
                    out.data.extend_from_slice(&acc);
                    return out;
                }
                Unpad::Block {
                    header_left,
                    command,
                    content,
                    padding,
                } => {
                    if *header_left > 0 {
                        let Some((&b, rest)) = input.split_first() else {
                            return out;
                        };
                        input = rest;
                        match *header_left {
                            5 => *command = b,
                            4 => *content = usize::from(b) << 8,
                            3 => *content |= usize::from(b),
                            2 => *padding = usize::from(b) << 8,
                            _ => *padding |= usize::from(b),
                        }
                        *header_left -= 1;
                    } else if *content > 0 {
                        if input.is_empty() {
                            return out;
                        }
                        let n = (*content).min(input.len());
                        out.data.extend_from_slice(&input[..n]);
                        input = &input[n..];
                        *content -= n;
                    } else if *padding > 0 {
                        if input.is_empty() {
                            return out;
                        }
                        let n = (*padding).min(input.len());
                        input = &input[n..];
                        *padding -= n;
                    }
                    if let Unpad::Block {
                        header_left: 0,
                        command,
                        content: 0,
                        padding: 0,
                    } = self.state
                    {
                        if command == CMD_CONTINUE {
                            self.state = Unpad::Block {
                                header_left: 5,
                                command: 0,
                                content: 0,
                                padding: 0,
                            };
                        } else {
                            self.state = Unpad::Plain;
                            out.direct = command == CMD_DIRECT;
                            // Anything after the last block is ordinary data.
                            out.data.extend_from_slice(input);
                            return out;
                        }
                    }
                }
            }
        }
    }
}

/// Vision over a VLESS stream.
pub struct VisionStream<S> {
    inner: S,
    uuid: [u8; 16],
    // Uplink.
    uuid_pending: bool,
    padding: bool,
    packets: u32,
    is_tls: bool,
    out: PendingOut,
    first_wait: Option<Pin<Box<Sleep>>>,
    /// The padding-only first block is queued but not flushed yet; reads push it out.
    first_unsent: bool,
    // Downlink.
    unpad: Unpadder,
    ready: Vec<u8>,
    ready_pos: usize,
    eof: bool,
}

impl<S> VisionStream<S> {
    /// Wraps a VLESS stream opened with `flow = xtls-rprx-vision`.
    pub fn new(inner: S, uuid: [u8; 16]) -> Self {
        VisionStream {
            inner,
            uuid,
            uuid_pending: true,
            padding: true,
            packets: 0,
            is_tls: false,
            out: PendingOut::default(),
            first_wait: Some(Box::pin(tokio::time::sleep(FIRST_PACKET_WAIT))),
            first_unsent: false,
            unpad: Unpadder::new(uuid),
            ready: Vec::new(),
            ready_pos: 0,
            eof: false,
        }
    }

    fn take_uuid(&mut self) -> Option<[u8; 16]> {
        if self.uuid_pending {
            self.uuid_pending = false;
            Some(self.uuid)
        } else {
            None
        }
    }

    /// Pads one uplink chunk and queues it; returns how many bytes were taken.
    fn queue_padded(&mut self, data: &[u8]) -> usize {
        let chunk = &data[..data.len().min(MAX_CONTENT)];
        if self.packets == 0
            && chunk.len() >= 6
            && chunk[0] == 0x16
            && chunk[1] == 0x03
            && chunk[5] == 0x01
        {
            self.is_tls = true;
        }
        let app_data = chunk.len() >= 6 && chunk[..3] == [0x17, 0x03, 0x03];
        let (command, long) = if self.is_tls && app_data {
            (CMD_END, true)
        } else if !self.is_tls || self.packets + 1 >= MAX_PADDED_PACKETS {
            (CMD_END, self.is_tls)
        } else {
            (CMD_CONTINUE, true)
        };
        if command != CMD_CONTINUE {
            self.padding = false;
        }
        self.packets += 1;
        let uuid = self.take_uuid();
        self.out.extend(&pad_block(uuid.as_ref(), command, chunk, long));
        chunk.len()
    }
}

impl<S: AsyncRead + AsyncWrite + RawSwitch + Unpin> VisionStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.out.is_empty() {
            ready!(self.out.poll_drain(&mut self.inner, cx))?;
        }
        Poll::Ready(Ok(()))
    }

    /// Sends a padding-only first block if the client stays silent (server-first protocols).
    ///
    /// Never waits on the uplink otherwise: a read parked behind a full socket stalls the
    /// download during an upload, and deadlocks with a server that waits for the client to
    /// read before it reads again. Uplink data the app wrote is pushed by the write side.
    fn poll_first_packet(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(wait) = self.first_wait.as_mut() {
            if self.packets > 0 || !self.uuid_pending {
                self.first_wait = None;
            } else {
                ready!(wait.as_mut().poll(cx));
                self.first_wait = None;
                let uuid = self.take_uuid();
                self.out
                    .extend(&pad_block(uuid.as_ref(), CMD_CONTINUE, &[], true));
                self.first_unsent = true;
            }
        }
        if self.first_unsent {
            // Pending keeps the writability wakeup registered; the read goes on meanwhile.
            if let Poll::Ready(r) = self.poll_drain(cx) {
                r?;
                if let Poll::Ready(r) = Pin::new(&mut self.inner).poll_flush(cx) {
                    r?;
                    self.first_unsent = false;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + RawSwitch + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_first_packet(cx))?;
        loop {
            if this.ready_pos < this.ready.len() {
                let n = (this.ready.len() - this.ready_pos).min(buf.remaining());
                buf.put_slice(&this.ready[this.ready_pos..this.ready_pos + n]);
                this.ready_pos += n;
                if this.ready_pos == this.ready.len() {
                    this.ready.clear();
                    this.ready_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.unpad.is_plain() {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            let eof = n == 0;
            let res = this.unpad.feed(&tmp[..n], eof);
            this.ready.extend_from_slice(&res.data);
            if res.direct {
                let left = this.inner.switch_to_raw_read()?;
                this.ready.extend_from_slice(&left);
                tracing::trace!("vision: server switched to direct copy");
            }
            if eof {
                this.eof = true;
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + RawSwitch + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if !this.padding {
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Keep `first_wait`: poll_read may be parked on it, and dropping it would lose that
        // wakeup. When it fires, poll_first_packet sees `packets > 0` and sends nothing.
        let n = this.queue_padded(data);
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [0xab; 16];

    #[test]
    fn padding_layout() {
        let b = pad_block(Some(&UUID), CMD_CONTINUE, b"hello", true);
        assert_eq!(&b[..16], &UUID);
        assert_eq!(b[16], CMD_CONTINUE);
        assert_eq!(u16::from_be_bytes([b[17], b[18]]), 5);
        let pad = usize::from(u16::from_be_bytes([b[19], b[20]]));
        assert!((895..1395).contains(&pad), "{pad}");
        assert_eq!(&b[21..26], b"hello");
        assert_eq!(b.len(), 26 + pad);
        let b = pad_block(None, CMD_END, &[1u8; 2000], false);
        assert!(usize::from(u16::from_be_bytes([b[3], b[4]])) < 256);
        let big = pad_block(None, CMD_END, &[1u8; 8171], true);
        assert_eq!(u16::from_be_bytes([big[3], big[4]]), 0);
    }

    #[test]
    fn unpadding_across_chunks() {
        let mut stream = pad_block(Some(&UUID), CMD_CONTINUE, b"abc", true);
        stream.extend(pad_block(None, CMD_CONTINUE, b"defg", false));
        stream.extend(pad_block(None, CMD_DIRECT, b"hi", false));
        stream.extend_from_slice(b"raw-after");
        for split in [1usize, 2, 7, 20, 21, 100, 5000] {
            let mut u = Unpadder::new(UUID);
            let mut got = Vec::new();
            let mut direct = false;
            for c in stream.chunks(split) {
                let r = u.feed(c, false);
                got.extend(r.data);
                direct |= r.direct;
            }
            assert_eq!(got, b"abcdefghiraw-after", "split {split}");
            assert!(direct && u.is_plain());
        }
    }

    #[test]
    fn unpadded_server_and_end_command() {
        let mut u = Unpadder::new(UUID);
        let r = u.feed(b"plain response that is long enough", false);
        assert_eq!(r.data, b"plain response that is long enough");
        let mut u = Unpadder::new(UUID);
        assert_eq!(u.feed(b"short", true).data, b"short");
        let mut u = Unpadder::new(UUID);
        let mut s = pad_block(Some(&UUID), CMD_END, b"x", true);
        s.extend_from_slice(b"tls-data");
        let r = u.feed(&s, false);
        assert_eq!(r.data, b"xtls-data");
        assert!(!r.direct);
    }

    #[tokio::test]
    async fn uplink_policy() {
        let mut v = VisionStream::new((), UUID);
        let mut hello = vec![0x16, 0x03, 0x01, 0x02, 0x00, 0x01];
        hello.resize(517, 0);
        v.queue_padded(&hello);
        assert!(v.is_tls && v.padding);
        v.queue_padded(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        assert!(v.padding);
        v.queue_padded(&[0x17, 0x03, 0x03, 0x00, 0x10, 0x00]);
        assert!(!v.padding);
        let mut v = VisionStream::new((), UUID);
        v.queue_padded(b"GET / HTTP/1.1\r\n\r\n");
        assert!(!v.padding);
    }

    impl RawSwitch for tokio::io::DuplexStream {
        fn switch_to_raw_read(&mut self) -> io::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    // A full uplink must not hold back the downlink: a server that waits for the client
    // to read before it reads again would otherwise deadlock with it.
    #[tokio::test]
    async fn read_is_not_blocked_by_full_uplink() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(1024);
        let mut v = VisionStream::new(client, UUID);
        let n = v.write(&[0x42; 4096]).await.unwrap();
        assert!(n > 0 && !v.out.is_empty(), "uplink should be backed up");
        let reply = b"plain response that is long enough";
        server.write_all(reply).await.unwrap();
        let mut buf = [0u8; 64];
        let got = tokio::time::timeout(Duration::from_secs(1), v.read(&mut buf))
            .await
            .expect("read blocked by the uplink")
            .unwrap();
        assert_eq!(&buf[..got], reply);
    }
}
