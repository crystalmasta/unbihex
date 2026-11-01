//! Hysteria 2 wire framing (public protocol: QUIC varints, TCP 0x401, UDP messages).

// By dubr1k (github.com/dubr1k), PR #33.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};

pub(super) const MAX_ADDRESS: usize = 2048;
pub(super) const MAX_UDP: usize = 65_507;

pub(super) fn put_varint(out: &mut Vec<u8>, value: u64) -> Result<()> {
    let (width, tag) = match value {
        0..=63 => (1, 0),
        64..=16_383 => (2, 0x40),
        16_384..=1_073_741_823 => (4, 0x80),
        1_073_741_824..=4_611_686_018_427_387_903 => (8, 0xc0),
        _ => return Err(Error::protocol("hysteria2: varint overflow")),
    };
    let bytes = value.to_be_bytes();
    let start = out.len();
    out.extend_from_slice(&bytes[8 - width..]);
    out[start] |= tag;
    Ok(())
}

fn take_varint(input: &mut &[u8]) -> Result<u64> {
    let first = *input
        .first()
        .ok_or_else(|| Error::protocol("hysteria2: truncated varint"))?;
    let width = 1usize << (first >> 6);
    if input.len() < width {
        return Err(Error::protocol("hysteria2: truncated varint"));
    }
    let mut value = u64::from(first & 0x3f);
    for &b in &input[1..width] {
        value = (value << 8) | u64::from(b);
    }
    *input = &input[width..];
    Ok(value)
}

async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> Result<u64> {
    let first = r.read_u8().await?;
    let width = 1usize << (first >> 6);
    let mut bytes = [0u8; 8];
    bytes[0] = first;
    r.read_exact(&mut bytes[1..width]).await?;
    take_varint(&mut &bytes[..width])
}

pub(super) fn random_padding(from: usize, to: usize) -> String {
    use rand::distributions::{Alphanumeric, DistString};
    let mut rng = rand::thread_rng();
    let n = rng.gen_range(from..=to);
    Alphanumeric.sample_string(&mut rng, n)
}

pub(super) fn tcp_request(address: &str) -> Result<Vec<u8>> {
    if address.is_empty() || address.len() > MAX_ADDRESS {
        return Err(Error::protocol("hysteria2: invalid target length"));
    }
    let padding = random_padding(64, 512);
    let mut out = Vec::with_capacity(address.len() + padding.len() + 24);
    put_varint(&mut out, 0x401)?;
    put_varint(&mut out, address.len() as u64)?;
    out.extend_from_slice(address.as_bytes());
    put_varint(&mut out, padding.len() as u64)?;
    out.extend_from_slice(padding.as_bytes());
    Ok(out)
}

pub(super) async fn read_tcp_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<()> {
    let status = r.read_u8().await?;
    let length = read_varint(r).await?;
    if length > 2048 {
        return Err(Error::protocol("hysteria2: oversized TCP message"));
    }
    let mut message = vec![0; length as usize];
    r.read_exact(&mut message).await?;
    let length = read_varint(r).await?;
    if length > 4096 {
        return Err(Error::protocol("hysteria2: oversized TCP padding"));
    }
    let mut padding = vec![0; length as usize];
    r.read_exact(&mut padding).await?;
    if status != 0 {
        // Peer-provided text is not forwarded into application logs.
        return Err(Error::protocol("hysteria2: server refused TCP request"));
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct UdpMessage {
    pub session: u32,
    pub packet: u16,
    pub fragment: u8,
    pub count: u8,
    pub address: String,
    pub data: Bytes,
}

impl UdpMessage {
    pub fn parse(bytes: Bytes) -> Result<Self> {
        if bytes.len() < 9 {
            return Err(Error::protocol("hysteria2: short UDP message"));
        }
        let mut input = &bytes[8..];
        let len = take_varint(&mut input)?;
        if len == 0 || len > MAX_ADDRESS as u64 || len as usize >= input.len() {
            return Err(Error::protocol("hysteria2: invalid UDP address length"));
        }
        let address = std::str::from_utf8(&input[..len as usize])
            .map_err(|_| Error::protocol("hysteria2: invalid UDP address"))?
            .to_string();
        let offset = bytes.len() - input.len() + len as usize;
        let count = bytes[7];
        if count == 0 || bytes[6] >= count || bytes.len() - offset > MAX_UDP {
            return Err(Error::protocol("hysteria2: invalid UDP fragments"));
        }
        Ok(Self {
            session: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            packet: u16::from_be_bytes([bytes[4], bytes[5]]),
            fragment: bytes[6],
            count,
            address,
            data: bytes.slice(offset..),
        })
    }
}

pub(super) fn udp_header(
    session: u32,
    packet: u16,
    fragment: u8,
    count: u8,
    address: &str,
) -> Result<Vec<u8>> {
    if address.is_empty() || address.len() > MAX_ADDRESS || count == 0 || fragment >= count {
        return Err(Error::protocol("hysteria2: invalid UDP header"));
    }
    let mut out = Vec::with_capacity(address.len() + 16);
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(&packet.to_be_bytes());
    out.extend_from_slice(&[fragment, count]);
    put_varint(&mut out, address.len() as u64)?;
    out.extend_from_slice(address.as_bytes());
    Ok(out)
}

struct Partial {
    started: Instant,
    address: String,
    parts: Vec<Option<Bytes>>,
    size: usize,
}

/// Per-flow bounded reassembly. Incomplete packets expire; duplicate fragments
/// never count twice, and conflicting fragments cannot splice different packets.
#[derive(Default)]
pub(super) struct Reassembler {
    packets: HashMap<u16, Partial>,
}

impl Reassembler {
    pub fn push(&mut self, message: UdpMessage) -> Result<Option<Bytes>> {
        self.packets
            .retain(|_, p| p.started.elapsed() < Duration::from_secs(5));
        if message.count == 1 {
            self.packets.remove(&message.packet);
            return Ok(Some(message.data));
        }
        if !self.packets.contains_key(&message.packet)
            && self.packets.len() >= 8
            && let Some(id) = self
                .packets
                .iter()
                .min_by_key(|(_, p)| p.started)
                .map(|(k, _)| *k)
        {
            self.packets.remove(&id);
        }
        if self.packets.values().map(|p| p.size).sum::<usize>() + message.data.len() > 128 * 1024 {
            self.packets.remove(&message.packet);
            return Err(Error::protocol("hysteria2: UDP reassembly budget exceeded"));
        }
        let p = self
            .packets
            .entry(message.packet)
            .or_insert_with(|| Partial {
                started: Instant::now(),
                address: message.address.clone(),
                parts: vec![None; message.count as usize],
                size: 0,
            });
        if p.address != message.address || p.parts.len() != message.count as usize {
            self.packets.remove(&message.packet);
            return Err(Error::protocol("hysteria2: conflicting UDP fragments"));
        }
        let index = usize::from(message.fragment);
        if let Some(old) = &p.parts[index] {
            if old != &message.data {
                self.packets.remove(&message.packet);
                return Err(Error::protocol("hysteria2: conflicting UDP duplicate"));
            }
            return Ok(None);
        }
        p.size += message.data.len();
        if p.size > MAX_UDP {
            self.packets.remove(&message.packet);
            return Err(Error::protocol("hysteria2: oversized UDP packet"));
        }
        p.parts[index] = Some(message.data);
        if p.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let mut data = BytesMut::with_capacity(p.size);
        for part in p.parts.iter().flatten() {
            data.extend_from_slice(part);
        }
        self.packets.remove(&message.packet);
        Ok(Some(data.freeze()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_varints_and_udp_golden_frame() {
        for n in [
            0,
            63,
            64,
            16383,
            16384,
            1_073_741_823,
            1_073_741_824,
            4_611_686_018_427_387_903,
        ] {
            let mut out = Vec::new();
            put_varint(&mut out, n).unwrap();
            assert_eq!(take_varint(&mut out.as_slice()).unwrap(), n);
        }
        let mut header = udp_header(0x01020304, 0x0506, 0, 1, "a:9").unwrap();
        assert_eq!(header, [1, 2, 3, 4, 5, 6, 0, 1, 3, b'a', b':', b'9']);
        header.extend_from_slice(b"payload");
        let parsed = UdpMessage::parse(Bytes::from(header)).unwrap();
        assert_eq!(parsed.session, 0x01020304);
        assert_eq!(parsed.packet, 0x0506);
        assert_eq!(parsed.data, &b"payload"[..]);
        assert!(take_varint(&mut &[0x80, 0][..]).is_err());
        assert!(put_varint(&mut Vec::new(), u64::MAX).is_err());
    }

    fn fragment(id: u8, count: u8, data: &'static [u8]) -> UdpMessage {
        UdpMessage {
            session: 1,
            packet: 2,
            fragment: id,
            count,
            address: "a:9".into(),
            data: Bytes::from_static(data),
        }
    }

    #[test]
    fn reassembles_out_of_order_without_duplicate_or_cross_packet_splicing() {
        let mut r = Reassembler::default();
        assert!(r.push(fragment(1, 2, b"world")).unwrap().is_none());
        assert!(r.push(fragment(1, 2, b"world")).unwrap().is_none());
        assert_eq!(
            r.push(fragment(0, 2, b"hello ")).unwrap().unwrap(),
            &b"hello world"[..]
        );
        r.push(fragment(0, 2, b"a")).unwrap();
        assert!(r.push(fragment(1, 3, b"b")).is_err());
        r.push(fragment(0, 2, b"a")).unwrap();
        assert!(r.push(fragment(0, 2, b"different")).is_err());
        assert!(r.packets.is_empty());
    }

    #[tokio::test]
    async fn tcp_framing_and_response_limits() {
        let request = tcp_request("example.test:443").unwrap();
        let mut r = request.as_slice();
        assert_eq!(read_varint(&mut r).await.unwrap(), 0x401);
        let len = read_varint(&mut r).await.unwrap();
        assert_eq!(&r[..len as usize], b"example.test:443");
        let mut ok = &[0, 0, 0, b'x'][..];
        read_tcp_response(&mut ok).await.unwrap();
        assert_eq!(ok, b"x");
        let mut rejected = &[1, 0, 0][..];
        assert!(read_tcp_response(&mut rejected).await.is_err());
        let mut oversized = vec![0];
        put_varint(&mut oversized, 2049).unwrap();
        assert!(read_tcp_response(&mut oversized.as_slice()).await.is_err());
        let mut pad = vec![0, 0];
        put_varint(&mut pad, 4097).unwrap();
        assert!(read_tcp_response(&mut pad.as_slice()).await.is_err());
    }
}
