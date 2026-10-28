//! XUDP: UDP inside a Mux.Cool stream, as Xray sends UDP for VLESS + Vision.
//!
//! The VLESS request uses the Mux command and the target `v1.mux.cool:666`; the
//! stream then carries frames
//!
//! ```text
//! meta_len(be16) | session_id(be16)=0 | status | option | [network(2) | port(be16) | atyp | addr] [global_id(8)]
//! [data_len(be16) | data]            (when option has bit 0x01)
//! ```
//!
//! status 1 = new (first packet, with destination and global ID), 2 = keep,
//! 3 = end, 4 = keep-alive (ignored). Address types: 1 IPv4, 2 domain, 3 IPv6.
//! The 8-byte global ID identifies the client's UDP socket, so the server can keep
//! one NAT mapping for it (full-cone NAT: games, voice calls).

use std::net::{IpAddr, SocketAddr};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use super::PacketStream;
use crate::address::{Address, TargetAddr};
use crate::error::{Error, Result};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_KEEPALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const NETWORK_UDP: u8 = 2;

/// The Mux.Cool destination of an XUDP request.
pub fn mux_target() -> TargetAddr {
    TargetAddr::new(Address::Domain("v1.mux.cool".into()), 666)
}

fn process_key() -> &'static [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    KEY.get_or_init(rand::random)
}

/// A stable ID for a local UDP socket, unlinkable across app restarts.
pub fn global_id(source: Option<SocketAddr>) -> [u8; 8] {
    let Some(src) = source else {
        return [0; 8];
    };
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(process_key()) else {
        return [0; 8];
    };
    mac.update(src.to_string().as_bytes());
    let out = mac.finalize().into_bytes();
    let mut id = [0u8; 8];
    id.copy_from_slice(&out[..8]);
    id
}

pub(crate) fn write_addr(out: &mut Vec<u8>, t: &TargetAddr) -> Result<()> {
    out.extend_from_slice(&t.port.to_be_bytes());
    match &t.addr {
        Address::Ip(IpAddr::V4(v4)) => {
            out.push(1);
            out.extend_from_slice(&v4.octets());
        }
        Address::Domain(d) => {
            let len = u8::try_from(d.len()).map_err(|_| Error::protocol("domain too long"))?;
            out.push(2);
            out.push(len);
            out.extend_from_slice(d.as_bytes());
        }
        Address::Ip(IpAddr::V6(v6)) => {
            out.push(3);
            out.extend_from_slice(&v6.octets());
        }
    }
    Ok(())
}

/// Encodes one client → server packet.
pub fn encode_packet(first: bool, dest: &TargetAddr, gid: &[u8; 8], payload: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(payload.len()).map_err(|_| Error::protocol("UDP payload too large"))?;
    let mut meta = vec![0, 0, if first { STATUS_NEW } else { STATUS_KEEP }, OPTION_DATA, NETWORK_UDP];
    write_addr(&mut meta, dest)?;
    if first {
        meta.extend_from_slice(gid);
    }
    let mut out = Vec::with_capacity(4 + meta.len() + payload.len());
    out.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// UDP flow to one destination over an XUDP stream.
pub struct XudpStream<S> {
    dest: TargetAddr,
    gid: [u8; 8],
    w: Mutex<(WriteHalf<S>, bool)>,
    r: Mutex<ReadHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite> XudpStream<S> {
    /// Wraps a VLESS (Mux command) stream.
    pub fn new(stream: S, dest: TargetAddr, source: Option<SocketAddr>) -> Self {
        let (r, w) = tokio::io::split(stream);
        XudpStream {
            dest,
            gid: global_id(source),
            w: Mutex::new((w, true)),
            r: Mutex::new(r),
        }
    }
}

#[async_trait::async_trait]
impl<S: AsyncRead + AsyncWrite + Send + 'static> PacketStream for XudpStream<S> {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        let mut w = self.w.lock().await;
        let frame = encode_packet(w.1, &self.dest, &self.gid, payload)?;
        w.1 = false;
        w.0.write_all(&frame).await?;
        w.0.flush().await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut r = self.r.lock().await;
        loop {
            let meta_len = usize::from(r.read_u16().await?);
            if meta_len < 4 {
                return Err(Error::protocol("xudp: stream closed"));
            }
            if meta_len > 512 {
                return Err(Error::protocol("xudp: bad frame"));
            }
            let mut meta = vec![0u8; meta_len];
            r.read_exact(&mut meta).await?;
            let discard = match meta[2] {
                STATUS_KEEP | STATUS_NEW => false,
                STATUS_KEEPALIVE => true,
                _ => return Err(Error::protocol("xudp: session ended")),
            };
            if meta[3] & OPTION_DATA == 0 {
                continue;
            }
            let len = usize::from(r.read_u16().await?);
            if discard || len > buf.len() {
                let mut sink = vec![0u8; len];
                r.read_exact(&mut sink).await?;
                if discard {
                    continue;
                }
                return Err(Error::protocol("UDP packet larger than buffer"));
            }
            r.read_exact(&mut buf[..len]).await?;
            if len > 0 {
                return Ok(len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_layout() {
        let dest: TargetAddr = "1.2.3.4:53".parse().unwrap();
        let f = encode_packet(true, &dest, &[9; 8], b"q").unwrap();
        // meta: 0 0 | 1 1 2 | 0 53 | 1 1 2 3 4 | gid(8) = 20
        assert_eq!(&f[..2], &20u16.to_be_bytes());
        assert_eq!(&f[2..7], &[0, 0, STATUS_NEW, OPTION_DATA, NETWORK_UDP]);
        assert_eq!(&f[7..9], &53u16.to_be_bytes());
        assert_eq!(&f[9..14], &[1, 1, 2, 3, 4]);
        assert_eq!(&f[14..22], &[9; 8]);
        assert_eq!(&f[22..], &[0, 1, b'q']);
        let f = encode_packet(false, &"[::1]:5".parse().unwrap(), &[0; 8], b"zz").unwrap();
        assert_eq!(f[4], STATUS_KEEP);
        assert_eq!(f[9], 3);
        assert_eq!(global_id(None), [0; 8]);
        let a = global_id(Some("10.0.0.1:5000".parse().unwrap()));
        assert_eq!(a, global_id(Some("10.0.0.1:5000".parse().unwrap())));
        assert_ne!(a, global_id(Some("10.0.0.1:5001".parse().unwrap())));
    }

    #[tokio::test]
    async fn reads_frames_and_skips_keepalives() {
        let (client, mut server) = tokio::io::duplex(4096);
        let x = XudpStream::new(client, "1.1.1.1:53".parse().unwrap(), None);
        let mut frames = Vec::new();
        frames.extend_from_slice(&[0, 4, 0, 0, STATUS_KEEPALIVE, 0]);
        frames.extend_from_slice(&[0, 4, 0, 0, STATUS_KEEPALIVE, OPTION_DATA, 0, 2, 7, 7]);
        frames.extend_from_slice(&[0, 12, 0, 0, STATUS_KEEP, OPTION_DATA, NETWORK_UDP, 0, 53, 1, 1, 1, 1, 1]);
        frames.extend_from_slice(&[0, 3, b'a', b'b', b'c']);
        frames.extend_from_slice(&[0, 4, 0, 0, 3, 0]);
        server.write_all(&frames).await.unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(x.recv(&mut buf).await.unwrap(), 3);
        assert_eq!(&buf[..3], b"abc");
        assert!(x.recv(&mut buf).await.is_err());
    }
}
