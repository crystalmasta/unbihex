//! Trojan client (SPEC §11.12), wire format as Xray and sing-box speak it, over TLS or
//! REALITY, optionally inside WebSocket or HTTPUpgrade.
//!
//! Request:  hex(SHA-224(password)) (56) | CRLF | cmd | atyp | addr | port | CRLF | payload…
//!           (cmd 1 = TCP, 3 = UDP; the address is SOCKS5-encoded). No response header.
//! UDP:      every packet, both ways: atyp | addr | port | len(be16) | CRLF | payload.

use std::sync::Arc;

use bytes::{Buf, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use super::fragment::FragmentConfig;
use super::reality::RealityClient;
use super::tls::TlsClient;
use super::vless::VlessStream;
use super::ws::WsConfig;
use super::{BoxStream, Outbound, PacketStream, ServerEndpoint};
use crate::address::{TargetAddr, parse_socks_addr, write_socks_addr};
use crate::config::TrojanConfig;
use crate::error::{Error, Result};
use crate::net::SocketFactory;
use crate::session::Session;

/// Trojan command: TCP stream.
pub const CMD_TCP: u8 = 0x01;
/// Trojan command: UDP packets.
pub const CMD_UDP: u8 = 0x03;
/// Largest UDP payload in one packet (Xray refuses bigger ones).
pub const MAX_UDP_PAYLOAD: usize = 8192;

/// The 56 hex digits of SHA-224 that stand for the password on the wire.
pub fn password_hash(password: &str) -> [u8; 56] {
    let digest = Sha224::digest(password.as_bytes());
    let mut out = [0u8; 56];
    // hex::encode_to_slice cannot fail: 28 bytes fit 56 digits exactly.
    let _ = hex::encode_to_slice(digest, &mut out);
    out
}

/// Encodes a Trojan request header.
pub fn encode_request(hash: &[u8; 56], cmd: u8, target: &TargetAddr) -> Result<Vec<u8>> {
    let mut h = Vec::with_capacity(56 + 2 + 1 + 1 + 256 + 2 + 2);
    h.extend_from_slice(hash);
    h.extend_from_slice(b"\r\n");
    h.push(cmd);
    write_socks_addr(target, &mut h)?;
    h.extend_from_slice(b"\r\n");
    Ok(h)
}

/// Appends one UDP packet for `target`.
pub fn encode_udp(target: &TargetAddr, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(Error::protocol(
            "trojan: UDP payload larger than 8192 bytes",
        ));
    }
    write_socks_addr(target, out)?;
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(payload);
    Ok(())
}

/// Takes one UDP packet off the front of `src`: `Ok(None)` until it is complete.
pub fn decode_udp(src: &mut BytesMut) -> Result<Option<(TargetAddr, BytesMut)>> {
    let (from, at) = match parse_socks_addr(src) {
        Ok(v) => v,
        // Only a short buffer is worth waiting on; a bad address type is not.
        Err(_) if udp_addr_incomplete(src) => return Ok(None),
        Err(e) => return Err(e),
    };
    let Some(head) = src.get(at..at + 4) else {
        return Ok(None);
    };
    if &head[2..] != b"\r\n" {
        return Err(Error::protocol("trojan: bad UDP packet header"));
    }
    let len = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if len > MAX_UDP_PAYLOAD {
        return Err(Error::protocol("trojan: oversize UDP packet"));
    }
    if src.len() < at + 4 + len {
        src.reserve(at + 4 + len - src.len());
        return Ok(None);
    }
    src.advance(at + 4);
    Ok(Some((from, src.split_to(len))))
}

/// Whether `buf` is a known address type cut short (more bytes may complete it).
fn udp_addr_incomplete(buf: &[u8]) -> bool {
    use crate::address::{SOCKS_ATYP_DOMAIN, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6};
    let need = match buf.first() {
        None => return true,
        Some(&SOCKS_ATYP_IPV4) => 1 + 4 + 2,
        Some(&SOCKS_ATYP_IPV6) => 1 + 16 + 2,
        Some(&SOCKS_ATYP_DOMAIN) => match buf.get(1) {
            None => return true,
            Some(0) => return false,
            Some(&n) => 2 + usize::from(n) + 2,
        },
        Some(_) => return false,
    };
    buf.len() < need
}

/// UDP to one destination over a Trojan stream opened with [`CMD_UDP`]; the header
/// goes out with the first packet.
pub struct TrojanUdp {
    r: Mutex<(ReadHalf<BoxStream>, BytesMut)>,
    w: Mutex<(WriteHalf<BoxStream>, Option<Vec<u8>>)>,
    target: TargetAddr,
}

impl TrojanUdp {
    /// Wraps `stream`; `header` is the request header for `target`.
    pub fn new(stream: BoxStream, header: Vec<u8>, target: TargetAddr) -> Self {
        let (r, w) = tokio::io::split(stream);
        TrojanUdp {
            r: Mutex::new((r, BytesMut::new())),
            w: Mutex::new((w, Some(header))),
            target,
        }
    }
}

#[async_trait::async_trait]
impl PacketStream for TrojanUdp {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        let mut w = self.w.lock().await;
        let (half, header) = &mut *w;
        let mut out = header.take().unwrap_or_default();
        encode_udp(&self.target, payload, &mut out)?;
        half.write_all(&out).await?;
        half.flush().await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut r = self.r.lock().await;
        let (half, rbuf) = &mut *r;
        loop {
            // The packet's source is not checked: the flow has one destination, and
            // Xray reports the address it sent to (a resolved domain shows as an IP).
            if let Some((_, data)) = decode_udp(rbuf)? {
                if data.len() > buf.len() {
                    return Err(Error::protocol("UDP packet larger than buffer"));
                }
                buf[..data.len()].copy_from_slice(&data);
                return Ok(data.len());
            }
            rbuf.reserve(16 * 1024);
            if half.read_buf(rbuf).await? == 0 {
                return Err(Error::protocol("trojan: UDP flow closed"));
            }
        }
    }
}

/// Trojan outbound.
pub struct TrojanOutbound {
    tag: String,
    hash: [u8; 56],
    server: ServerEndpoint,
    tls: Option<TlsClient>,
    reality: Option<RealityClient>,
    fragment: Option<FragmentConfig>,
    ws: Option<WsConfig>,
    /// `Host` of the WebSocket request when the config names none.
    ws_host: String,
    grpc: Option<Arc<super::grpc::GrpcClient>>,
    sockets: Arc<SocketFactory>,
}

impl TrojanOutbound {
    /// Creates the outbound for an already resolved server.
    pub fn new(
        cfg: &TrojanConfig,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
    ) -> Result<Self> {
        cfg.validate()?;
        let reality = cfg.reality.as_ref().map(RealityClient::new).transpose()?;
        let tls = match &cfg.tls {
            Some(t) if t.enabled => Some(TlsClient::new(
                &super::grpc::transport_tls(t, cfg.ws.is_some(), cfg.grpc.is_some()),
                &cfg.server,
            )?),
            _ => None,
        };
        let mut ob = TrojanOutbound {
            tag: cfg.tag.clone(),
            hash: password_hash(cfg.password.expose()),
            server,
            tls,
            reality,
            fragment: cfg.fragment.clone(),
            ws: cfg.ws.clone(),
            ws_host: super::ws::default_host(cfg.tls.as_ref(), &cfg.server),
            grpc: None,
            sockets,
        };
        ob.build_grpc(cfg)?;
        Ok(ob)
    }

    fn build_grpc(&mut self, cfg: &TrojanConfig) -> Result<()> {
        self.grpc = super::grpc::GrpcClient::for_outbound(
            cfg.grpc.as_ref(),
            &self.server,
            &self.sockets,
            self.tls.as_ref(),
            cfg.tls.as_ref(),
            self.reality.as_ref(),
            self.fragment.as_ref(),
        )?;
        Ok(())
    }

    /// Test only: trust extra roots (a self-signed test CA) for plain TLS.
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_extra_roots(
        mut self,
        cfg: &TrojanConfig,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<Self> {
        if let Some(t) = cfg.tls.as_ref().filter(|t| t.enabled) {
            let t = super::grpc::transport_tls(t, cfg.ws.is_some(), cfg.grpc.is_some());
            self.tls = Some(TlsClient::with_extra_roots(&t, &cfg.server, roots)?);
            self.build_grpc(cfg)?;
        }
        Ok(self)
    }

    /// TCP, then REALITY or TLS, then the WebSocket/HTTPUpgrade handshake.
    async fn transport(&self) -> Result<BoxStream> {
        if let Some(g) = &self.grpc {
            return g.open().await;
        }
        let tcp = self.server.connect(&self.sockets).await?;
        if let Some(r) = &self.reality {
            let mut s = r.connect(tcp, self.fragment.as_ref()).await?;
            s.set_bulk();
            return Ok(Box::new(s));
        }
        super::ws::dial(
            tcp,
            self.tls.as_ref(),
            self.fragment.as_ref(),
            self.ws.as_ref(),
            &self.ws_host,
        )
        .await
    }
}

#[async_trait::async_trait]
impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn server(&self) -> Option<&ServerEndpoint> {
        Some(&self.server)
    }

    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream> {
        let header = encode_request(&self.hash, CMD_TCP, &sess.target)?;
        Ok(Box::new(VlessStream::request_only(
            self.transport().await?,
            header,
        )))
    }

    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>> {
        let header = encode_request(&self.hash, CMD_UDP, &sess.target)?;
        Ok(Box::new(TrojanUdp::new(
            self.transport().await?,
            header,
            sess.target.clone(),
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn password_is_hex_sha224() {
        // SHA-224 test vectors ("" and "abc", FIPS 180-2), as lowercase hex.
        assert_eq!(
            &password_hash(""),
            b"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            &password_hash("abc"),
            b"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    #[test]
    fn request_layout() {
        let hash = password_hash("pw");
        let h = encode_request(&hash, CMD_TCP, &"example.com:443".parse().unwrap()).unwrap();
        let mut want = hash.to_vec();
        want.extend_from_slice(b"\r\n\x01\x03\x0bexample.com\x01\xbb\r\n");
        assert_eq!(h, want);
        let h = encode_request(&hash, CMD_UDP, &"1.2.3.4:53".parse().unwrap()).unwrap();
        assert_eq!(&h[56..], b"\r\n\x03\x01\x01\x02\x03\x04\x00\x35\r\n");
        let h = encode_request(&hash, CMD_TCP, &"[::1]:80".parse().unwrap()).unwrap();
        assert_eq!(h[59], 0x04);
        assert_eq!(h.len(), 56 + 2 + 1 + 1 + 16 + 2 + 2);
    }

    #[test]
    fn udp_packets_round_trip_in_pieces() {
        let a: TargetAddr = "1.2.3.4:53".parse().unwrap();
        let b: TargetAddr = "dns.example:5353".parse().unwrap();
        let mut wire = Vec::new();
        encode_udp(&a, b"first", &mut wire).unwrap();
        encode_udp(&b, b"", &mut wire).unwrap();
        encode_udp(&a, &[7u8; 300], &mut wire).unwrap();
        assert_eq!(&wire[..12], b"\x01\x01\x02\x03\x04\x00\x35\x00\x05\r\nf");
        // Fed one byte at a time, every packet comes out whole and in order.
        let mut src = BytesMut::new();
        let mut got = Vec::new();
        for byte in &wire {
            src.extend_from_slice(&[*byte]);
            while let Some(p) = decode_udp(&mut src).unwrap() {
                got.push(p);
            }
        }
        assert!(src.is_empty());
        assert_eq!(got.len(), 3);
        assert_eq!(
            (got[0].0.clone(), &got[0].1[..]),
            (a.clone(), &b"first"[..])
        );
        assert_eq!((got[1].0.clone(), got[1].1.len()), (b, 0));
        assert_eq!(&got[2].1[..], &[7u8; 300][..]);
    }

    #[test]
    fn bad_udp_packets_are_refused() {
        assert!(encode_udp(&"1.2.3.4:1".parse().unwrap(), &[0; 8193], &mut Vec::new()).is_err());
        for wire in [
            &b"\x09\x01\x02"[..],                             // unknown address type
            &b"\x01\x01\x02\x03\x04\x00\x35\x00\x01xx1"[..],  // no CRLF
            &b"\x01\x01\x02\x03\x04\x00\x35\x20\x01\r\n"[..], // longer than 8192
            &b"\x03\x00\x00\x35"[..],                         // empty domain
        ] {
            assert!(decode_udp(&mut BytesMut::from(wire)).is_err(), "{wire:?}");
        }
    }

    #[tokio::test]
    async fn header_rides_with_the_first_write_and_nothing_is_stripped() {
        let (client, mut server) = tokio::io::duplex(4096);
        let header =
            encode_request(&password_hash("pw"), CMD_TCP, &"a.b:1".parse().unwrap()).unwrap();
        let mut s = VlessStream::request_only(client, header.clone());
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut got = vec![0u8; header.len() + 5];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..header.len()], &header[..]);
        assert_eq!(&got[header.len()..], b"hello");
        // The server answers with bare data: the first bytes are not a header.
        server.write_all(&[0, 0, 1]).await.unwrap();
        let mut back = [0u8; 3];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(back, [0, 0, 1]);
    }

    #[tokio::test]
    async fn udp_flow_sends_the_header_once() {
        let (client, mut server) = tokio::io::duplex(4096);
        let target: TargetAddr = "1.2.3.4:53".parse().unwrap();
        let header = encode_request(&password_hash("pw"), CMD_UDP, &target).unwrap();
        let flow = TrojanUdp::new(Box::new(client), header.clone(), target.clone());
        flow.send(b"one").await.unwrap();
        flow.send(b"two").await.unwrap();
        let mut want = header;
        encode_udp(&target, b"one", &mut want).unwrap();
        encode_udp(&target, b"two", &mut want).unwrap();
        let mut got = vec![0u8; want.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, want);
        let mut reply = Vec::new();
        encode_udp(&target, b"answer", &mut reply).unwrap();
        server.write_all(&reply).await.unwrap();
        let mut buf = [0u8; 64];
        let n = flow.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"answer");
    }
}
