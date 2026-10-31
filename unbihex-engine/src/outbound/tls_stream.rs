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

// By Pavel Shakhmin (github.com/pshakhmin), PR #25.
/// How much of the socket a [`TlsRecordStream`] read asks for in bulk mode once
/// it is moving data.
const BULK_READ: usize = 64 * 1024;
/// The first bulk reads ask for one record only: an idle connection should not
/// hold 64 KB of scratch for a transfer that may never happen.
const BULK_READ_MIN: usize = 16 * 1024;

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
    // By Pavel Shakhmin (github.com/pshakhmin), PR #25.
    /// rustls hands `write_tls` a header chunk and a payload chunk and writes them
    /// with `write_vectored`. The default `Write::write_vectored` only writes the
    /// first chunk, so without this every record costs two `write` syscalls and
    /// arrives as a 5-byte segment followed by the payload.
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match Pin::new(&mut *self.tcp).poll_write_vectored(self.cx, bufs) {
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

// By Pavel Shakhmin (github.com/pshakhmin), PR #25.
/// What [`feed_wire`] managed to hand over.
struct Fed {
    /// Bytes of the slice rustls accepted.
    consumed: usize,
    /// The peer ended the TLS stream.
    eof: bool,
}

/// Hands wire bytes to rustls, draining decrypted plaintext into `buf` as it goes
/// so rustls' plaintext buffer never fills up mid-buffer.
///
/// Stops when `buf` is full; the caller keeps the rest for the next read.
fn feed_wire(conn: &mut Connection, wire: &[u8], buf: &mut ReadBuf<'_>) -> io::Result<Fed> {
    let mut rest = wire;
    let mut eof = false;
    while !rest.is_empty() {
        match conn.read_tls(&mut rest) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
        conn.process_new_packets().map_err(tls_err)?;
        match conn.reader().read(buf.initialize_unfilled()) {
            // read() returns 0 only at the end of the TLS stream.
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(n) => {
                buf.advance(n);
                if buf.remaining() == 0 {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                eof = true;
                break;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(Fed {
        consumed: wire.len() - rest.len(),
        eof,
    })
}

/// A TLS stream with record-exact reads and a switch to raw reads.
pub struct TlsRecordStream {
    tcp: TcpStream,
    conn: Connection,
    rec: RecordReader,
    /// Reads bypass TLS (Vision direct copy).
    raw_read: bool,
    /// Reads no longer stop at TLS record boundaries (Vision is not in use).
    bulk: bool,
    /// One socket read while `bulk`; fed to rustls from memory.
    scratch: Vec<u8>,
    /// Wire bytes read from the socket but not yet handed to rustls.
    carry: Vec<u8>,
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
            bulk: false,
            scratch: Vec::new(),
            carry: Vec::new(),
            eof: false,
            closing: false,
        }
    }

    // By Pavel Shakhmin (github.com/pshakhmin), PR #25.
    /// Stops reading one record at a time.
    ///
    /// The record-exact feed exists for XTLS Vision, which may switch to a raw
    /// copy in the middle of the connection and therefore must not have read past
    /// the record carrying the command. Without Vision that guarantee costs two
    /// socket reads per record — a 5-byte header read and a body read — and pins
    /// reads to the first record, so a `read` can never return more than 16 KB.
    /// Bulk mode reads the socket once into a scratch buffer and lets rustls
    /// deframe from memory instead.
    pub fn set_bulk(&mut self) {
        if self.bulk {
            return;
        }
        debug_assert!(self.rec.at_boundary(), "bulk read mid-record");
        self.bulk = true;
        if self.scratch.is_empty() {
            self.scratch = vec![0u8; BULK_READ_MIN];
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

    // By Pavel Shakhmin (github.com/pshakhmin), PR #25.
    /// Reads as much as the socket has, up to `buf.len()`, without stopping at a
    /// record boundary: the socket is read once into `scratch` and rustls deframes
    /// it from memory. Keeps decrypting while the caller has room, so a 64 KB read
    /// can come back in one call instead of four 16 KB ones.
    fn poll_read_bulk(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        loop {
            // Anything already decrypted goes out first.
            match self.conn.reader().read(buf.initialize_unfilled()) {
                Ok(0) => {
                    if buf.filled().len() == before {
                        // close_notify: the peer ended the TLS stream cleanly.
                        self.eof = true;
                    }
                    return Poll::Ready(Ok(()));
                }
                Ok(n) => {
                    buf.advance(n);
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                // Closed without close_notify: treat as a normal end of stream.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
            // Never block once bytes were delivered; the next poll drains the rest.
            if buf.filled().len() > before {
                return Poll::Ready(Ok(()));
            }

            // Wire bytes rustls did not take last time go first.
            if !self.carry.is_empty() {
                let wire = std::mem::take(&mut self.carry);
                match feed_wire(&mut self.conn, &wire, buf) {
                    Ok(fed) => {
                        if fed.consumed < wire.len() {
                            self.carry = wire[fed.consumed..].to_vec();
                        }
                        if fed.eof {
                            self.eof = true;
                        }
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
                if buf.remaining() == 0 || self.eof {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            let n = {
                let mut rb = ReadBuf::new(&mut self.scratch);
                match Pin::new(&mut self.tcp).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => rb.filled().len(),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            };
            if n == 0 {
                self.eof = true;
                return Poll::Ready(Ok(()));
            }
            if n == self.scratch.len() && self.scratch.len() < BULK_READ {
                // A full read means a bulk transfer: ask for more next time.
                let next = (self.scratch.len() * 2).min(BULK_READ);
                self.scratch.resize(next, 0);
            }
            match feed_wire(&mut self.conn, &self.scratch[..n], buf) {
                Ok(fed) => {
                    if fed.consumed < n {
                        self.carry = self.scratch[fed.consumed..n].to_vec();
                    }
                    if fed.eof || fed.consumed == 0 {
                        self.eof = true;
                    }
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
            if buf.remaining() == 0 || self.eof {
                return Poll::Ready(Ok(()));
            }
        }
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
        if this.bulk {
            return this.poll_read_bulk(cx, buf);
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn feed(conn: &mut Connection, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            conn.read_tls(&mut bytes).unwrap();
            conn.process_new_packets().unwrap();
        }
    }

    fn drain(conn: &mut Connection) -> Vec<u8> {
        let mut out = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut out).unwrap();
        }
        out
    }

    /// Client and server configs for `example.com` with a fresh self-signed certificate.
    fn configs() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
        let cert = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (Arc::new(client_cfg), Arc::new(server_cfg))
    }

    /// A client and a server connection with the handshake done in memory.
    fn connected_pair() -> (Connection, Connection) {
        let (client_cfg, server_cfg) = configs();
        let name = ServerName::try_from("example.com").unwrap();
        let mut c: Connection = ClientConnection::new(client_cfg, name).unwrap().into();
        let mut s: Connection = ServerConnection::new(server_cfg).unwrap().into();
        for _ in 0..10 {
            let to_server = drain(&mut c);
            feed(&mut s, &to_server);
            let to_client = drain(&mut s);
            feed(&mut c, &to_client);
            if !c.is_handshaking() && !s.is_handshaking() {
                return (c, s);
            }
        }
        panic!("handshake did not finish");
    }

    /// The TLS records carrying `plain`.
    fn sealed(s: &mut Connection, plain: &[u8]) -> Vec<u8> {
        // rustls buffers at most 64 KB of plaintext: seal it piece by piece.
        let mut out = Vec::new();
        for piece in plain.chunks(16 * 1024) {
            s.writer().write_all(piece).unwrap();
            out.extend(drain(s));
        }
        out
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ours = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (peer, _) = l.accept().await.unwrap();
        (ours, peer)
    }

    /// Vision: the peer's last TLS record and the raw bytes after it arrive in one
    /// read; after the switch the raw bytes still come out, in order.
    #[tokio::test]
    async fn raw_bytes_after_the_last_record_survive_the_switch() {
        let (c, mut s) = connected_pair();
        let mut wire = sealed(&mut s, b"last record");
        wire.extend_from_slice(b"raw bytes after the switch");
        let (ours, mut peer) = tcp_pair().await;
        peer.write_all(&wire).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut tls = TlsRecordStream::new(ours, c);
        let mut got = [0u8; 11];
        tls.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"last record");
        assert!(tls.switch_to_raw_read().unwrap().is_empty());
        let mut raw = Vec::new();
        tls.read_to_end(&mut raw).await.unwrap();
        assert_eq!(raw, b"raw bytes after the switch");
    }

    /// Records cut at any byte (inside headers, across several records) come out whole.
    #[tokio::test]
    async fn records_split_anywhere_arrive_whole() {
        let (c, mut s) = connected_pair();
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        let wire = sealed(&mut s, &data);
        let (ours, mut peer) = tcp_pair().await;
        peer.set_nodelay(true).unwrap();
        tokio::spawn(async move {
            let sizes = [1usize, 4, 2, 7000, 3, 16_389, 70_000];
            let mut rest = &wire[..];
            for n in sizes.iter().cycle() {
                if rest.is_empty() {
                    break;
                }
                let n = (*n).min(rest.len());
                peer.write_all(&rest[..n]).await.unwrap();
                rest = &rest[n..];
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            peer.shutdown().await.unwrap();
        });
        let mut tls = TlsRecordStream::new(ours, c);
        let mut got = Vec::new();
        tls.read_to_end(&mut got).await.unwrap();
        assert_eq!(got.len(), data.len());
        assert!(got == data);
    }

    // By Pavel Shakhmin (github.com/pshakhmin), PR #25.
    /// Bulk mode: a single read crosses record boundaries, and the stream still
    /// ends where it should.
    #[tokio::test]
    async fn bulk_read_crosses_record_boundaries() {
        let (c, mut s) = connected_pair();
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let wire = sealed(&mut s, &data);
        let (ours, mut peer) = tcp_pair().await;
        peer.set_nodelay(true).unwrap();
        tokio::spawn(async move {
            peer.write_all(&wire).await.unwrap();
            peer.shutdown().await.unwrap();
        });
        let mut tls = TlsRecordStream::new(ours, c);
        tls.set_bulk();
        let mut buf = vec![0u8; BULK_READ];
        let first = tls.read(&mut buf).await.unwrap();
        assert!(
            first > 16 * 1024,
            "a bulk read returned {first} bytes: still stopping at one record"
        );
        let mut got = buf[..first].to_vec();
        tls.read_to_end(&mut got).await.unwrap();
        assert_eq!(got.len(), data.len());
        assert!(got == data);
    }

    /// One TLS stream over loopback, ours against tokio-rustls on either side:
    /// `cargo test --release --features server --lib tls_throughput -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "a measurement, not a check"]
    async fn tls_throughput() {
        use crate::outbound::AsyncStream;
        const TOTAL: usize = 1 << 30;
        let (client_cfg, server_cfg) = configs();
        for (writer_ours, reader_ours, bulk) in [
            (true, true, false),
            (true, true, true),
            (false, false, false),
            (false, true, false),
            (false, true, true),
            (true, false, false),
        ] {
            let (ours, peer) = tcp_pair().await;
            let scfg = server_cfg.clone();
            let writer = tokio::spawn(async move {
                let mut w: Box<dyn AsyncStream> = if writer_ours {
                    Box::new(TlsRecordStream::accept(peer, scfg).await.unwrap())
                } else {
                    Box::new(tokio_rustls::TlsAcceptor::from(scfg).accept(peer).await.unwrap())
                };
                let chunk = vec![7u8; 64 * 1024];
                let mut sent = 0;
                while sent < TOTAL {
                    w.write_all(&chunk).await.unwrap();
                    sent += chunk.len();
                }
                w.shutdown().await.unwrap();
            });
            let name = ServerName::try_from("example.com").unwrap();
            let mut r: Box<dyn AsyncStream> = if reader_ours {
                let mut r = TlsRecordStream::connect(ours, client_cfg.clone(), name, None).await.unwrap();
                if bulk {
                    r.set_bulk();
                }
                Box::new(r)
            } else {
                Box::new(tokio_rustls::TlsConnector::from(client_cfg.clone()).connect(name, ours).await.unwrap())
            };
            let start = std::time::Instant::now();
            let mut buf = vec![0u8; 64 * 1024];
            let mut got = 0;
            loop {
                let n = r.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got += n;
            }
            let secs = start.elapsed().as_secs_f64();
            writer.await.unwrap();
            let side = |o: bool| if o { "ours" } else { "tokio-rustls" };
            let how = if reader_ours && !bulk { "exact" } else if bulk { "bulk" } else { "" };
            println!(
                "writer {:12} reader {:12} {:5} {:6.2} Gbit/s",
                side(writer_ours),
                side(reader_ours),
                how,
                got as f64 * 8.0 / secs / 1e9
            );
        }
    }
}
