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

    /// One TLS stream over loopback, ours against tokio-rustls on either side:
    /// `cargo test --release --features server --lib tls_throughput -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "a measurement, not a check"]
    async fn tls_throughput() {
        use crate::outbound::AsyncStream;
        const TOTAL: usize = 1 << 30;
        let (client_cfg, server_cfg) = configs();
        for (writer_ours, reader_ours) in [(true, true), (false, false), (false, true), (true, false)] {
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
                Box::new(TlsRecordStream::connect(ours, client_cfg.clone(), name, None).await.unwrap())
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
            println!(
                "writer {:12} reader {:12} {:6.2} Gbit/s",
                side(writer_ours),
                side(reader_ours),
                got as f64 * 8.0 / secs / 1e9
            );
        }
    }
}
