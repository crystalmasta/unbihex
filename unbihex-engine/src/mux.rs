//! Mux.Cool frames, shared by the server (`inbound::mux`) and the client
//! (`outbound::mux`).
//!
//! ```text
//! meta_len(be16) | id(be16) | status | option | [network | port(be16) | atyp | addr | [global_id(8)]]
//! [data_len(be16) | data]            (when option has bit 0x01)
//! ```
//!
//! The address is present on `new` frames and on UDP `keep` frames that name
//! their destination; replies name the source they came from, which is what
//! lets a client keep several UDP destinations on one stream.

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::address::{Address, TargetAddr, normalize_domain};
use crate::error::{Error, Result};
use crate::outbound::xudp::write_addr;

pub(crate) const STATUS_NEW: u8 = 1;
pub(crate) const STATUS_KEEP: u8 = 2;
pub(crate) const STATUS_END: u8 = 3;
pub(crate) const STATUS_KEEPALIVE: u8 = 4;
pub(crate) const OPTION_DATA: u8 = 1;
pub(crate) const NETWORK_TCP: u8 = 1;
pub(crate) const NETWORK_UDP: u8 = 2;
/// Xray refuses longer metadata as well.
const MAX_META: usize = 512;

/// One parsed frame.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) id: u16,
    pub(crate) status: u8,
    pub(crate) target: Option<(u8, TargetAddr)>,
    pub(crate) data: Option<Vec<u8>>,
}

/// A `keep` frame with data; UDP frames name their destination or source.
pub(crate) fn data_frame(id: u16, udp_source: Option<&TargetAddr>, data: &[u8]) -> Vec<u8> {
    let mut meta = Vec::with_capacity(32);
    meta.extend_from_slice(&id.to_be_bytes());
    meta.extend_from_slice(&[STATUS_KEEP, OPTION_DATA]);
    if let Some(src) = udp_source {
        let mut addr = Vec::with_capacity(24);
        // A domain over 255 bytes cannot come in, so it cannot go out either.
        if write_addr(&mut addr, src).is_ok() {
            meta.push(NETWORK_UDP);
            meta.extend_from_slice(&addr);
        }
    }
    // Callers keep data within u16 (TCP chunks, UDP datagrams).
    let len = u16::try_from(data.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(4 + meta.len() + data.len());
    out.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&data[..usize::from(len)]);
    out
}

/// A `new` UDP frame carrying the first datagram and the global ID, as Xray
/// expects when a client asks for full-cone UDP: its server reads the datagram
/// in the same frame and dispatches it to the destination.
pub(crate) fn new_udp_frame(
    id: u16,
    target: &TargetAddr,
    gid: &[u8; 8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let len = u16::try_from(data.len()).map_err(|_| Error::protocol("mux: datagram too large"))?;
    let mut meta = Vec::with_capacity(32);
    meta.extend_from_slice(&id.to_be_bytes());
    meta.extend_from_slice(&[STATUS_NEW, OPTION_DATA, NETWORK_UDP]);
    write_addr(&mut meta, target)?;
    meta.extend_from_slice(gid);
    let mut out = Vec::with_capacity(4 + meta.len() + data.len());
    out.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(out)
}

pub(crate) fn end_frame(id: u16) -> Vec<u8> {
    let mut out = vec![0, 4];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[STATUS_END, 0]);
    out
}

pub(crate) fn keepalive_frame(id: u16) -> Vec<u8> {
    let mut out = vec![0, 4];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[STATUS_KEEPALIVE, 0]);
    out
}

/// Reads one frame; None at a clean end of the stream.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let meta_len = usize::from(u16::from_be_bytes(len));
    if !(4..=MAX_META).contains(&meta_len) {
        return Err(Error::protocol(format!("mux: metadata length {meta_len}")));
    }
    let mut meta = vec![0u8; meta_len];
    r.read_exact(&mut meta).await?;
    let mut f = parse_meta(&meta)?;
    if meta[3] & OPTION_DATA != 0 {
        let len = usize::from(r.read_u16().await?);
        let mut data = vec![0u8; len];
        r.read_exact(&mut data).await?;
        f.data = Some(data);
    }
    Ok(Some(f))
}

fn parse_meta(meta: &[u8]) -> Result<Frame> {
    let bad = || Error::protocol("mux: malformed frame");
    let id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    if !(STATUS_NEW..=STATUS_KEEPALIVE).contains(&status) {
        return Err(Error::protocol(format!("mux: frame status {status}")));
    }
    let mut target = None;
    // Xray reads an address only when it is there and the network says UDP
    // (`UnmarshalFromBuffer`); any other tail on a `keep` is padding to ignore.
    if status == STATUS_NEW
        || (status == STATUS_KEEP && meta.get(4).is_some_and(|n| *n == NETWORK_UDP))
    {
        let network = *meta.get(4).ok_or_else(bad)?;
        if network != NETWORK_TCP && network != NETWORK_UDP {
            return Err(Error::protocol(format!("mux: network {network}")));
        }
        // The global ID that may follow a UDP destination is not used yet.
        let (addr, _rest) = parse_addr(meta.get(5..).ok_or_else(bad)?)?;
        target = Some((network, addr));
    }
    Ok(Frame {
        id,
        status,
        target,
        data: None,
    })
}

/// `port(be16) | atyp | addr`, returning what follows it.
fn parse_addr(b: &[u8]) -> Result<(TargetAddr, &[u8])> {
    let bad = || Error::protocol("mux: malformed address");
    let (head, rest) = b.split_at_checked(3).ok_or_else(bad)?;
    let port = u16::from_be_bytes([head[0], head[1]]);
    let (addr, rest) = match head[2] {
        1 => {
            let (a, rest) = rest.split_first_chunk::<4>().ok_or_else(bad)?;
            (Address::Ip(Ipv4Addr::from(*a).into()), rest)
        }
        2 => {
            let (&n, rest) = rest.split_first().ok_or_else(bad)?;
            let (name, rest) = rest.split_at_checked(usize::from(n)).ok_or_else(bad)?;
            let name = std::str::from_utf8(name).map_err(|_| bad())?;
            (
                Address::Domain(normalize_domain(name).map_err(|_| bad())?),
                rest,
            )
        }
        3 => {
            let (a, rest) = rest.split_first_chunk::<16>().ok_or_else(bad)?;
            (Address::Ip(Ipv6Addr::from(*a).into()), rest)
        }
        t => return Err(Error::protocol(format!("mux: address type {t}"))),
    };
    Ok((TargetAddr::new(addr, port), rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::xudp::encode_packet;

    #[tokio::test]
    async fn reads_xudp_frames() {
        let dest: TargetAddr = "1.2.3.4:53".parse().unwrap();
        let mut wire = encode_packet(true, &dest, &[7; 8], b"q").unwrap();
        let other: TargetAddr = "Example.com:443".parse().unwrap();
        wire.extend(encode_packet(false, &other, &[7; 8], b"zz").unwrap());
        wire.extend(end_frame(0));
        let mut r = &wire[..];
        let f = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(
            f,
            Frame {
                id: 0,
                status: STATUS_NEW,
                target: Some((NETWORK_UDP, dest)),
                data: Some(b"q".to_vec()),
            }
        );
        let f = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(f.status, STATUS_KEEP);
        assert_eq!(
            f.target,
            Some((NETWORK_UDP, "example.com:443".parse().unwrap()))
        );
        assert_eq!(f.data.as_deref(), Some(&b"zz"[..]));
        let f = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!((f.status, f.target, f.data), (STATUS_END, None, None));
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn refuses_malformed_frames() {
        for wire in [
            &[0, 3, 0, 0, 2][..],                             // metadata too short
            &[0, 6, 0, 1, STATUS_NEW, 0, 9, 0][..],           // unknown network
            &[0, 8, 0, 1, STATUS_NEW, 0, 1, 0, 80, 4][..],    // unknown address type
            &[0, 9, 0, 1, STATUS_NEW, 0, 1, 0, 80, 1, 1][..], // truncated IPv4
            &[0, 4, 0, 1, 9, 0][..],                          // unknown status
        ] {
            let mut r = wire;
            assert!(read_frame(&mut r).await.is_err(), "{wire:?}");
        }
    }

    #[tokio::test]
    async fn a_keep_with_a_padding_tail_is_not_an_error() {
        // Xray parses an address on a keep frame only when byte 4 says UDP;
        // any other tail is padding, and treating it as an address would kill
        // the stream along with every session on it.
        let wire = [0, 7, 0, 1, STATUS_KEEP, 0, 9, 0, 0, 0, 0];
        let mut r = &wire[..];
        let f = read_frame(&mut r)
            .await
            .expect("a padded keep is a valid frame")
            .expect("a frame, not the end of the stream");
        assert_eq!((f.id, f.status, f.target, f.data), (1, STATUS_KEEP, None, None));
    }

    /// A hostile peer sends arbitrary bytes: the codec must reject them, never
    /// panic. Deterministic, so a failure is reproducible.
    #[tokio::test]
    async fn arbitrary_bytes_are_rejected_without_panicking() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..2000 {
            let len = (next() % 600) as usize;
            let wire: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = parse_addr(&wire);
            let _ = read_frame(&mut &wire[..]).await;
        }
    }

    #[test]
    fn reply_frames() {
        let src: TargetAddr = "[::1]:5353".parse().unwrap();
        let f = data_frame(3, Some(&src), b"ok");
        // meta: id 0 3 | keep | data | udp | port | atyp 3 | 16 bytes = 24
        assert_eq!(&f[..2], &24u16.to_be_bytes());
        assert_eq!(&f[2..7], &[0, 3, STATUS_KEEP, OPTION_DATA, NETWORK_UDP]);
        assert_eq!(&f[7..10], &[0x14, 0xe9, 3]);
        assert_eq!(&f[26..], &[0, 2, b'o', b'k']);
        assert_eq!(
            data_frame(1, None, b"x"),
            vec![0, 4, 0, 1, STATUS_KEEP, OPTION_DATA, 0, 1, b'x']
        );
        assert_eq!(end_frame(258), vec![0, 4, 1, 2, STATUS_END, 0]);
    }

    #[tokio::test]
    async fn new_udp_frame_names_destination_and_id() {
        let target: TargetAddr = "1.2.3.4:9001".parse().unwrap();
        let f = new_udp_frame(7, &target, &[9; 8], b"hi").unwrap();
        let meta_len = usize::from(u16::from_be_bytes([f[0], f[1]]));
        // id, status+option, network, port+atyp+ipv4, global id
        assert_eq!(meta_len, 2 + 2 + 1 + 7 + 8);
        assert_eq!(&f[2..5], &[0, 7, STATUS_NEW]);
        assert_eq!(f[5], OPTION_DATA);
        assert_eq!(f[6], NETWORK_UDP);
        assert_eq!(&f[14..22], &[9; 8]);
        assert_eq!(&f[22..24], &2u16.to_be_bytes());
        assert_eq!(&f[24..], b"hi");
        let mut r = &f[..];
        let parsed = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(parsed.target, Some((NETWORK_UDP, target)));
        assert_eq!(parsed.data.as_deref(), Some(&b"hi"[..]));
    }
}
