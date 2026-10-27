//! A rustls stream (client or server) that reads exactly one TLS record at a time.
//!
//! XTLS Vision may tell the reader that the peer stopped wrapping data in TLS
//! (`CommandPaddingDirect`). From that point the bytes on the socket are the inner
//! traffic itself, so the reader must not have buffered them inside the TLS layer.
//! Feeding rustls record by record guarantees that: after the record with the
//! command is decrypted, nothing more has been read from the socket.

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::{ClientConnection, Connection, ServerConnection};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::error::{Error, Result};

/// Where the record reader is inside the current record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Collecting the 5-byte record header.
    Header { got: usize },
    /// Handing the collected header to rustls.
    HeaderOut { sent: usize, body: usize },
    /// Passing the record body through.
    Body { left: usize },
}

struct RecordReader {
    hdr: [u8; 5],
    phase: Phase,
}

impl RecordReader {
    fn new() -> Self {
        RecordReader {
            hdr: [0; 5],
            phase: Phase::Header { got: 0 },
        }
    }

    fn at_boundary(&self) -> bool {
        self.phase == Phase::Header { got: 0 }
    }
}

/// `io::Read` over the socket that never returns bytes past the current record.
struct Feed<'a, 'b> {
    tcp: &'a mut TcpStream,
    rec: &'a mut RecordReader,
    cx: &'a mut Context<'b>,
}

fn poll_tcp_read(tcp: &mut TcpStream, cx: &mut Context<'_>, out: &mut [u8]) -> io::Result<usize> {
    let mut rb = ReadBuf::new(out);
    match Pin::new(tcp).poll_read(cx, &mut rb) {
        Poll::Ready(Ok(())) => Ok(rb.filled().len()),
        Poll::Ready(Err(e)) => Err(e),
        Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
    }
}

impl Read for Feed<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            match self.rec.phase {
                Phase::Header { got } => {
                    let n = poll_tcp_read(self.tcp, self.cx, &mut self.rec.hdr[got..])?;
                    if n == 0 {
                        return if got == 0 {
                            Ok(0)
                        } else {
                            Err(io::ErrorKind::UnexpectedEof.into())
                        };
                    }
                    let got = got + n;
                    self.rec.phase = if got == 5 {
                        let body = usize::from(u16::from_be_bytes([self.rec.hdr[3], self.rec.hdr[4]]));
                        Phase::HeaderOut { sent: 0, body }
                    } else {
                        Phase::Header { got }
                    };
                }
                Phase::HeaderOut { sent, body } => {
                    let n = (5 - sent).min(out.len());
                    out[..n].copy_from_slice(&self.rec.hdr[sent..sent + n]);
                    let sent = sent + n;
                    self.rec.phase = if sent < 5 {
                        Phase::HeaderOut { sent, body }
                    } else if body == 0 {
                        Phase::Header { got: 0 }
                    } else {
                        Phase::Body { left: body }
                    };
                    return Ok(n);
                }
                Phase::Body { left } => {
                    let want = left.min(out.len());
                    let n = poll_tcp_read(self.tcp, self.cx, &mut out[..want])?;
                    if n == 0 {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                    let left = left - n;
                    self.rec.phase = if left == 0 {
                        Phase::Header { got: 0 }
                    } else {
                        Phase::Body { left }
                    };
                    return Ok(n);
                }
            }
        }
    }
}

/// `io::Write` over the socket for rustls' `write_tls`.
struct Sink<'a, 'b> {
    tcp: &'a mut TcpStream,
    cx: &'a mut Context<'b>,
}

impl Write for Sink<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.tcp).poll_write(self.cx, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut *self.tcp).poll_flush(self.cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

fn tls_err(e: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// A TLS stream with record-exact reads and a switch to raw reads.
pub struct TlsRecordStream {
    tcp: TcpStream,
    conn: Connection,
    rec: RecordReader,
    /// Reads bypass TLS (Vision direct copy).
    raw_read: bool,
    /// The peer closed the TLS stream.
    eof: bool,
    /// close_notify was queued.
    closing: bool,
}

impl std::fmt::Debug for TlsRecordStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsRecordStream")
            .field("raw_read", &self.raw_read)
            .finish()
    }
}

impl TlsRecordStream {
    /// Wraps a connection whose handshake has not started on the wire yet.
    pub fn new(tcp: TcpStream, conn: impl Into<Connection>) -> Self {
        TlsRecordStream {
            tcp,
            conn: conn.into(),
            rec: RecordReader::new(),
            raw_read: false,
            eof: false,
            closing: false,
        }
    }

    /// Starts a TLS handshake with `config` for `name` and completes it; the
    /// ClientHello is fragmented when `fragment` is set.
    pub async fn connect(
        mut tcp: TcpStream,
        config: Arc<rustls::ClientConfig>,
        name: ServerName<'static>,
        fragment: Option<&super::fragment::FragmentConfig>,
    ) -> Result<Self> {
        let mut conn =
            ClientConnection::new(config, name).map_err(|e| Error::Tls(e.to_string()))?;
        if let Some(f) = fragment {
            let mut hello = Vec::new();
            while conn.wants_write() {
                conn.write_tls(&mut hello)?;
            }
            f.send(&mut tcp, &hello).await?;
        }
        let mut s = TlsRecordStream::new(tcp, conn);
        s.handshake().await?;
        Ok(s)
    }

    /// Server side: answers the ClientHello arriving on `tcp` and completes the handshake.
    pub async fn accept(tcp: TcpStream, config: Arc<rustls::ServerConfig>) -> Result<Self> {
        let conn = ServerConnection::new(config).map_err(|e| Error::Tls(e.to_string()))?;
        let mut s = TlsRecordStream::new(tcp, conn);
        s.handshake().await?;
        Ok(s)
    }

    /// Server side, when the first records were read already (REALITY reads the
    /// ClientHello itself to check the client); `prefix` ends at a record boundary.
    pub async fn accept_prefixed(
        tcp: TcpStream,
        mut conn: ServerConnection,
        prefix: &[u8],
    ) -> Result<Self> {
        let mut rest = prefix;
        while !rest.is_empty() {
            if conn.read_tls(&mut rest)? == 0 {
                break;
            }
            conn.process_new_packets()
                .map_err(|e| Error::Tls(e.to_string()))?;
        }
        let mut s = TlsRecordStream::new(tcp, conn);
        s.handshake().await?;
        Ok(s)
    }

    /// The peer's address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.tcp.peer_addr()
    }

    /// Drives the handshake to completion.
    pub async fn handshake(&mut self) -> Result<()> {
        std::future::poll_fn(|cx| self.poll_handshake(cx))
            .await
            .map_err(|e| Error::Tls(e.to_string()))
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            // Send everything rustls has queued (ClientHello, Finished…).
            while self.conn.wants_write() {
                match self.conn.write_tls(&mut Sink { tcp: &mut self.tcp, cx }) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
            if !self.conn.is_handshaking() {
                return Poll::Ready(Ok(()));
            }
            let mut feed = Feed {
                tcp: &mut self.tcp,
                rec: &mut self.rec,
                cx,
            };
            match self.conn.read_tls(&mut feed) {
                Ok(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed during the TLS handshake",
                    )));
                }
                Ok(_) => {
                    if let Err(e) = self.conn.process_new_packets() {
                        // Let the peer see the alert, then fail.
                        let _ = self.conn.write_tls(&mut Sink { tcp: &mut self.tcp, cx });
                        return Poll::Ready(Err(tls_err(e)));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    /// The negotiated TLS version.
    pub fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        self.conn.protocol_version()
    }

    /// Stops reading through TLS: returns plaintext that was already decrypted
    /// (to be delivered before anything else) and reads the socket directly from now on.
    pub fn switch_to_raw_read(&mut self) -> io::Result<Vec<u8>> {
        let mut left = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            match self.conn.reader().read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => left.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }
        if !self.rec.at_boundary() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vision: the peer switched to direct copy in the middle of a TLS record",
            ));
        }
        self.raw_read = true;
        Ok(left)
    }

    /// Writes queued ciphertext; `Pending` while the socket is full.
    fn poll_flush_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut Sink { tcp: &mut self.tcp, cx }) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for TlsRecordStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.raw_read {
            return Pin::new(&mut this.tcp).poll_read(cx, buf);
        }
        loop {
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.conn.reader().read(buf.initialize_unfilled()) {
                Ok(n) => {
                    if n == 0 {
                        // close_notify received.
                        this.eof = true;
                    }
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                // Closed without close_notify: treat as a normal end of stream.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
            let mut feed = Feed {
                tcp: &mut this.tcp,
                rec: &mut this.rec,
                cx,
            };
            match this.conn.read_tls(&mut feed) {
                Ok(0) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => {
                    // A post-handshake answer (a KeyUpdate) goes out with the next write
                    // or flush. Writing here would register this task's waker for socket
                    // writability and lose the writer's wakeup when the halves are polled
                    // from different tasks (tokio::io::split).
                    this.conn.process_new_packets().map_err(tls_err)?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for TlsRecordStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        std::task::ready!(this.poll_flush_tls(cx))?;
        let n = this.conn.writer().write(data)?;
        // Push it out now if the socket allows; poll_flush finishes the rest.
        if let Poll::Ready(Err(e)) = this.poll_flush_tls(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        std::task::ready!(this.poll_flush_tls(cx))?;
        Pin::new(&mut this.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.closing {
            this.closing = true;
            this.conn.send_close_notify();
        }
        std::task::ready!(this.poll_flush_tls(cx))?;
        Pin::new(&mut this.tcp).poll_shutdown(cx)
    }
}
