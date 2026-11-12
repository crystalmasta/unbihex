//! The server name of a QUIC connection (SPEC §10.3): the client's Initial packets
//! are encrypted with keys anyone can derive from their destination connection ID
//! (RFC 9001 §5.2, RFC 9369 §3.3.1), so the ClientHello inside them, and its SNI,
//! can be read the way Xray's `quic` sniffer does. QUIC v1 and v2. The ClientHello
//! may span several Initial packets and datagrams (Chrome with a post-quantum key
//! share), and its CRYPTO frames may come in any order, split and mixed with PING
//! and PADDING (Chrome's "chaos protection").

use std::collections::VecDeque;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aes::Aes128;
use aes_gcm::aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use super::{SNIFF_TIMEOUT, Sniff, client_hello_name};
use crate::error::{Error, Result};
use crate::outbound::PacketStream;

const V1: u32 = 0x0000_0001;
const V2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// The port whose UDP flows are sniffed (HTTP/3).
pub const PORT: u16 = 443;

/// The most datagrams read while looking for the name: a ClientHello with a
/// post-quantum key share takes two.
const MAX_DATAGRAMS: usize = 4;

/// The longest CRYPTO stream put together; a ClientHello is far shorter.
const MAX_CRYPTO: u64 = 64 * 1024;

/// Client Initial packet protection keys.
#[derive(Debug, PartialEq, Eq)]
struct Keys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

/// HKDF-Expand-Label from TLS 1.3 with an empty context.
fn expand_label(prk: &Hkdf<Sha256>, label: &[u8], out: &mut [u8]) -> Option<()> {
    let mut info = Vec::with_capacity(10 + label.len());
    info.extend_from_slice(&u16::try_from(out.len()).ok()?.to_be_bytes());
    info.push(u8::try_from(6 + label.len()).ok()?);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    prk.expand(&info, out).ok()
}

/// The client's Initial keys for a destination connection ID.
fn client_keys(version: u32, dcid: &[u8]) -> Option<Keys> {
    let (salt, key_label, iv_label, hp_label): (&[u8], &[u8], &[u8], &[u8]) = match version {
        V1 => (&SALT_V1, b"quic key", b"quic iv", b"quic hp"),
        V2 => (&SALT_V2, b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
        _ => return None,
    };
    let initial = Hkdf::<Sha256>::new(Some(salt), dcid);
    let mut secret = [0u8; 32];
    expand_label(&initial, b"client in", &mut secret)?;
    let client = Hkdf::<Sha256>::from_prk(&secret).ok()?;
    let mut keys = Keys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    expand_label(&client, key_label, &mut keys.key)?;
    expand_label(&client, iv_label, &mut keys.iv)?;
    expand_label(&client, hp_label, &mut keys.hp)?;
    Some(keys)
}

/// The header protection mask for a 16-byte ciphertext sample.
fn hp_mask(hp: &[u8; 16], sample: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(hp));
    let mut block = GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// A QUIC variable-length integer.
fn varint(buf: &mut &[u8]) -> Option<u64> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        v = (v << 8) | u64::from(b);
    }
    *buf = &buf[len..];
    Some(v)
}

fn take<'a>(buf: &mut &'a [u8], n: u64) -> Option<&'a [u8]> {
    let n = usize::try_from(n).ok()?;
    if buf.len() < n {
        return None;
    }
    let (head, rest) = buf.split_at(n);
    *buf = rest;
    Some(head)
}

/// Skips an ACK frame (its type already read).
fn skip_ack(p: &mut &[u8], ecn: bool) -> Option<()> {
    varint(p)?; // largest acknowledged
    varint(p)?; // delay
    let ranges = varint(p)?;
    varint(p)?; // first range
    for _ in 0..ranges {
        varint(p)?;
        varint(p)?;
    }
    if ecn {
        for _ in 0..3 {
            varint(p)?;
        }
    }
    Some(())
}

/// Collects the CRYPTO frames of a decrypted Initial payload; `None` on a frame a
/// client's first flight does not carry.
fn crypto_frames(mut p: &[u8], out: &mut Vec<(u64, Vec<u8>)>) -> Option<()> {
    while !p.is_empty() {
        match varint(&mut p)? {
            0x00 | 0x01 => {} // PADDING, PING
            kind @ (0x02 | 0x03) => skip_ack(&mut p, kind == 0x03)?,
            0x06 => {
                let offset = varint(&mut p)?;
                let len = varint(&mut p)?;
                let data = take(&mut p, len)?;
                if offset.checked_add(len)? > MAX_CRYPTO {
                    return None;
                }
                out.push((offset, data.to_vec()));
            }
            _ => return None,
        }
    }
    Some(())
}

/// Decrypts the client Initial packets of one datagram (coalesced packets
/// included) and collects their CRYPTO frames. False when the datagram holds no
/// client Initial that decrypts.
fn initial_crypto(mut d: &[u8], out: &mut Vec<(u64, Vec<u8>)>) -> bool {
    let mut any = false;
    // Long headers only: a short header has no length, nothing follows it.
    while d.len() >= 7 && d[0] & 0x80 != 0 {
        let version = u32::from_be_bytes([d[1], d[2], d[3], d[4]]);
        // The Initial and Retry type bits differ between v1 and v2.
        let (initial, retry) = match version {
            V1 => (0, 3),
            V2 => (1, 0),
            _ => break,
        };
        let packet_type = (d[0] >> 4) & 0x03;
        if packet_type == retry {
            break;
        }
        let dcid_len = usize::from(d[5]);
        if dcid_len > 20 {
            break;
        }
        let Some(dcid) = d.get(6..6 + dcid_len) else {
            break;
        };
        let mut pos = 6 + dcid_len;
        let Some(&scid_len) = d.get(pos) else { break };
        pos += 1 + usize::from(scid_len);
        let Some(mut rest) = d.get(pos..) else { break };
        let before = rest.len();
        if packet_type == initial {
            let Some(token_len) = varint(&mut rest) else {
                break;
            };
            if take(&mut rest, token_len).is_none() {
                break;
            }
        }
        let Some(length) = varint(&mut rest) else {
            break;
        };
        let pn_offset = pos + (before - rest.len());
        let Some(end) = usize::try_from(length)
            .ok()
            .and_then(|l| pn_offset.checked_add(l))
        else {
            break;
        };
        if end > d.len() {
            break;
        }
        if packet_type == initial {
            if decrypt_initial(&d[..end], version, dcid, pn_offset, out).is_none() {
                break;
            }
            any = true;
        }
        d = &d[end..];
    }
    any
}

/// Removes header protection from one Initial packet and decrypts its payload.
fn decrypt_initial(
    packet: &[u8],
    version: u32,
    dcid: &[u8],
    pn_offset: usize,
    out: &mut Vec<(u64, Vec<u8>)>,
) -> Option<()> {
    let keys = client_keys(version, dcid)?;
    let sample: &[u8; 16] = packet.get(pn_offset + 4..pn_offset + 20)?.try_into().ok()?;
    let mask = hp_mask(&keys.hp, sample);
    let first = packet[0] ^ (mask[0] & 0x0f);
    let pn_len = usize::from(first & 0x03) + 1;
    let mut header = packet.get(..pn_offset + pn_len)?.to_vec();
    header[0] = first;
    let mut pn = 0u64;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | u64::from(header[pn_offset + i]);
    }
    // The client's first packets: the truncated number is the full one.
    let mut nonce = keys.iv;
    for (n, p) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
        *n ^= p;
    }
    let cipher = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    let payload = Payload {
        msg: &packet[pn_offset + pn_len..],
        aad: &header,
    };
    let plain = cipher.decrypt(Nonce::from_slice(&nonce), payload).ok()?;
    crypto_frames(&plain, out)
}

/// Looks for the server name in the first datagrams a QUIC client sent. The first
/// must be a client Initial; later ones that are not (0-RTT, a short header) are
/// skipped.
pub fn server_name(datagrams: &[Vec<u8>]) -> Sniff {
    let mut frames = Vec::new();
    for (i, d) in datagrams.iter().enumerate() {
        if !initial_crypto(d, &mut frames) && i == 0 {
            return Sniff::NotFound;
        }
    }
    // Put the CRYPTO stream together from offset 0; frames may come in any order
    // and overlap.
    frames.sort_by_key(|(offset, _)| *offset);
    let mut stream: Vec<u8> = Vec::new();
    for (offset, data) in &frames {
        let Ok(offset) = usize::try_from(*offset) else {
            break;
        };
        if offset > stream.len() {
            break;
        }
        if offset + data.len() > stream.len() {
            stream.extend_from_slice(&data[stream.len() - offset..]);
        }
    }
    if stream.len() < 4 {
        return Sniff::Incomplete;
    }
    if stream[0] != 1 {
        return Sniff::NotFound;
    }
    let len =
        (usize::from(stream[1]) << 16) | (usize::from(stream[2]) << 8) | usize::from(stream[3]);
    if stream.len() < 4 + len {
        return Sniff::Incomplete;
    }
    client_hello_name(&stream[4..4 + len]).map_or(Sniff::NotFound, Sniff::Name)
}

/// Reads the first datagrams of a UDP flow (at most [`MAX_DATAGRAMS`], for at most
/// [`SNIFF_TIMEOUT`]) and returns the QUIC server name found together with a flow
/// that yields those datagrams again.
pub async fn peek(inbound: Box<dyn PacketStream>) -> (Option<String>, Box<dyn PacketStream>) {
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    let mut got = Vec::new();
    let mut failed = None;
    let mut name = None;
    let mut buf = vec![0u8; 65_535];
    while got.len() < MAX_DATAGRAMS {
        match tokio::time::timeout_at(deadline, inbound.recv(&mut buf)).await {
            Ok(Ok(n)) => got.push(buf[..n].to_vec()),
            Ok(Err(e)) => {
                failed = Some(e);
                break;
            }
            Err(_) => break,
        }
        match server_name(&got) {
            Sniff::Name(n) => {
                name = Some(n);
                break;
            }
            Sniff::NotFound => break,
            Sniff::Incomplete => {}
        }
    }
    if got.is_empty() && failed.is_none() {
        return (name, inbound);
    }
    let replay = Replay {
        queued: parking_lot::Mutex::new((got.into(), failed)),
        inner: inbound,
    };
    (name, Box::new(replay))
}

/// A flow that first yields the datagrams read while sniffing (and the error that
/// ended the reading, if any), then reads on.
struct Replay {
    queued: parking_lot::Mutex<(VecDeque<Vec<u8>>, Option<Error>)>,
    inner: Box<dyn PacketStream>,
}

#[async_trait::async_trait]
impl PacketStream for Replay {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        self.inner.send(payload).await
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        {
            let mut q = self.queued.lock();
            if let Some(d) = q.0.pop_front() {
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                return Ok(n);
            }
            if let Some(e) = q.1.take() {
                return Err(e);
            }
        }
        self.inner.recv(buf).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use std::sync::Arc;

    use rand::Rng;
    use rand::seq::SliceRandom;
    use rustls::Side;
    use rustls::quic::{Keys as RustlsKeys, Version};

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn rustls_keys(version: Version, dcid: &[u8]) -> RustlsKeys {
        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap();
        suite.keys(dcid, Side::Client, version)
    }

    /// RFC 9001 A.1 and A.2: keys from the example connection ID and the mask.
    #[test]
    fn rfc9001_initial_keys_and_mask() {
        let k = client_keys(V1, &hex("8394c8f03e515708")).unwrap();
        assert_eq!(k.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(k.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(k.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
        let sample: [u8; 16] = hex("d1b1c98dd7689fb8ec11d242b123dc9b").try_into().unwrap();
        assert_eq!(hp_mask(&k.hp, &sample)[..5], hex("437b9aec36"));
    }

    /// RFC 9369 A.1: the same for QUIC v2; the masks of both agree with rustls.
    #[test]
    fn rfc9369_initial_keys() {
        let dcid = hex("8394c8f03e515708");
        let k = client_keys(V2, &dcid).unwrap();
        assert_eq!(k.key.to_vec(), hex("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(k.iv.to_vec(), hex("91f73e2351d8fa91660e909f"));
        assert_eq!(k.hp.to_vec(), hex("45b95e15235d6f45a6b19cbcb0294ba9"));
        for (ours, theirs) in [(V1, Version::V1), (V2, Version::V2)] {
            let k = client_keys(ours, &dcid).unwrap();
            let sample = [0x5au8; 16];
            // A long header with a four-byte packet number.
            let (mut first, mut pn) = (0xc3u8, [0u8; 4]);
            rustls_keys(theirs, &dcid)
                .local
                .header
                .encrypt_in_place(&sample, &mut first, &mut pn)
                .unwrap();
            let mask = hp_mask(&k.hp, &sample);
            assert_eq!(
                (first, pn.to_vec()),
                (0xc3 ^ (mask[0] & 0x0f), mask[1..5].to_vec())
            );
        }
        assert!(client_keys(0xff00_001d, &dcid).is_none());
    }

    fn put_varint(out: &mut Vec<u8>, v: u64) {
        match v {
            0..=0x3f => out.push(v as u8),
            0x40..=0x3fff => out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes()),
            _ => out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes()),
        }
    }

    /// A CRYPTO frame.
    pub(crate) fn crypto(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06];
        put_varint(&mut f, offset as u64);
        put_varint(&mut f, data.len() as u64);
        f.extend_from_slice(data);
        f
    }

    /// A client Initial packet carrying `frames`, padded to `min_len`, protected
    /// with rustls's QUIC keys (an implementation independent of ours).
    pub(crate) fn initial_packet(
        version: Version,
        dcid: &[u8],
        pn: u32,
        frames: &[u8],
        min_len: usize,
    ) -> Vec<u8> {
        let (v, packet_type) = match version {
            Version::V2 => (V2, 1u8),
            _ => (V1, 0u8),
        };
        let keys = rustls_keys(version, dcid);
        let mut header = vec![0xc0 | (packet_type << 4) | 0x03];
        header.extend_from_slice(&v.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(4);
        header.extend_from_slice(&[1, 2, 3, 4]); // source connection ID
        header.push(0); // no token
        let fixed = header.len() + 2 + 4 + 16;
        let mut payload = frames.to_vec();
        if fixed + payload.len() < min_len {
            payload.resize(min_len - fixed, 0); // PADDING
        }
        // The length, always in the two-byte form.
        let length = (4 + payload.len() + 16) as u16;
        header.extend_from_slice(&(0x4000 | length).to_be_bytes());
        let pn_offset = header.len();
        header.extend_from_slice(&pn.to_be_bytes());
        let tag = keys
            .local
            .packet
            .encrypt_in_place(u64::from(pn), &header, &mut payload)
            .unwrap();
        let mut packet = header;
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(tag.as_ref());
        let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
        let (first, rest) = packet.split_at_mut(1);
        keys.local
            .header
            .encrypt_in_place(
                &sample,
                &mut first[0],
                &mut rest[pn_offset - 1..pn_offset + 3],
            )
            .unwrap();
        packet
    }

    /// A real QUIC ClientHello from rustls for `name`; `extra` bytes of transport
    /// parameters make it as long as Chrome's with a post-quantum key share.
    pub(crate) fn quic_client_hello(version: Version, name: &str, extra: usize) -> Vec<u8> {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let mut params = vec![0x40, 0x5a]; // a reserved parameter id
        put_varint(&mut params, extra as u64);
        params.resize(params.len() + extra, 0x61);
        let mut conn = rustls::quic::ClientConnection::new(
            Arc::new(config),
            version,
            rustls::pki_types::ServerName::try_from(name.to_string()).unwrap(),
            params,
        )
        .unwrap();
        let mut hello = Vec::new();
        conn.write_hs(&mut hello);
        assert_eq!(hello[0], 1, "a ClientHello");
        hello
    }

    #[test]
    fn a_single_initial_gives_the_name() {
        for version in [Version::V1, Version::V2] {
            let hello = quic_client_hello(version, "www.YouTube.com", 0);
            let dcid = [7u8; 8];
            let d = initial_packet(version, &dcid, 0, &crypto(0, &hello), 1200);
            assert_eq!(d.len(), 1200);
            let want = Sniff::Name("www.youtube.com".into());
            assert_eq!(server_name(std::slice::from_ref(&d)), want);
            // Damaged: nothing decrypts.
            let mut bad = d.clone();
            bad[100] ^= 1;
            assert_eq!(server_name(&[bad]), Sniff::NotFound);
            // Bytes after it (a short-header packet) do not matter.
            let mut coalesced = d;
            coalesced.extend_from_slice(&[0x40, 1, 2, 3]);
            assert_eq!(server_name(&[coalesced]), want);
        }
        let tls = b"\x16\x03\x01 not quic at all".to_vec();
        assert_eq!(server_name(&[tls]), Sniff::NotFound);
        assert_eq!(
            server_name(&[vec![0x40; 1200]]),
            Sniff::NotFound,
            "a short header"
        );
    }

    /// Chrome: a ClientHello over 1200 bytes in two datagrams, its CRYPTO frames
    /// cut into pieces and shuffled among PING and PADDING frames.
    #[test]
    fn a_hello_over_two_datagrams_in_shuffled_frames() {
        let mut rng = rand::thread_rng();
        let name = "rr3---sn-example.googlevideo.com";
        let want = Sniff::Name(name.into());
        for version in [Version::V1, Version::V2] {
            let hello = quic_client_hello(version, name, 1300);
            assert!(hello.len() > 1400);
            let dcid: [u8; 8] = rand::random();
            // Plain split: the first datagram alone is not enough; the order of
            // the datagrams does not matter.
            let half = hello.len() / 2;
            let d1 = initial_packet(version, &dcid, 0, &crypto(0, &hello[..half]), 1200);
            let d2 = initial_packet(version, &dcid, 1, &crypto(half, &hello[half..]), 1200);
            assert_eq!(server_name(std::slice::from_ref(&d1)), Sniff::Incomplete);
            assert_eq!(server_name(&[d1.clone(), d2.clone()]), want);
            assert_eq!(server_name(&[d2, d1]), want);
            // Chaos: pieces of 1-80 bytes, some sent twice, in any order.
            for _ in 0..20 {
                let mut pieces = Vec::new();
                let mut at = 0;
                while at < hello.len() {
                    let n = rng.gen_range(1..=80).min(hello.len() - at);
                    pieces.push(crypto(at, &hello[at..at + n]));
                    if rng.gen_bool(0.1) {
                        pieces.push(crypto(at, &hello[at..at + n]));
                    }
                    pieces.push(vec![0x01]); // PING
                    pieces.push(vec![0x00; 3]); // PADDING
                    at += n;
                }
                pieces.shuffle(&mut rng);
                let mid = pieces.len() / 2;
                let datagrams: Vec<Vec<u8>> = [&pieces[..mid], &pieces[mid..]]
                    .iter()
                    .enumerate()
                    .map(|(pn, frames)| {
                        initial_packet(version, &dcid, pn as u32, &frames.concat(), 1200)
                    })
                    .collect();
                assert_eq!(server_name(&datagrams), want);
            }
        }
    }

    /// A flow to sniff: datagrams the app sent, then nothing.
    pub(crate) struct Script {
        incoming: tokio::sync::Mutex<VecDeque<Vec<u8>>>,
    }

    impl Script {
        pub(crate) fn new(datagrams: Vec<Vec<u8>>) -> Script {
            Script {
                incoming: tokio::sync::Mutex::new(datagrams.into()),
            }
        }
    }

    #[async_trait::async_trait]
    impl PacketStream for Script {
        async fn send(&self, _payload: &[u8]) -> Result<()> {
            Ok(())
        }

        async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
            let next = self.incoming.lock().await.pop_front();
            match next {
                Some(d) => {
                    buf[..d.len()].copy_from_slice(&d);
                    Ok(d.len())
                }
                None => std::future::pending().await,
            }
        }
    }

    #[tokio::test]
    async fn peeked_datagrams_are_replayed() {
        let hello = quic_client_hello(Version::V1, "blocked.example", 1300);
        let dcid = [3u8; 8];
        let half = hello.len() / 2;
        let d1 = initial_packet(Version::V1, &dcid, 0, &crypto(half, &hello[half..]), 1200);
        let d2 = initial_packet(Version::V1, &dcid, 1, &crypto(0, &hello[..half]), 1200);
        let script = Script::new(vec![d1.clone(), d2.clone(), b"later".to_vec()]);
        let (name, flow) = peek(Box::new(script)).await;
        assert_eq!(name.as_deref(), Some("blocked.example"));
        let mut buf = vec![0u8; 2048];
        for want in [&d1[..], &d2[..], b"later"] {
            let n = flow.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], want);
        }
        // Not QUIC: one datagram read, given back.
        let (name, flow) = peek(Box::new(Script::new(vec![b"hello".to_vec()]))).await;
        assert!(name.is_none());
        let n = flow.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_flow_costs_only_the_timeout() {
        let start = tokio::time::Instant::now();
        let (name, _) = peek(Box::new(Script::new(Vec::new()))).await;
        assert!(name.is_none());
        assert_eq!(start.elapsed(), SNIFF_TIMEOUT);
    }

    /// A real QUIC client (quinn, the stack of Hysteria 2) dialing an IP with a name.
    #[tokio::test]
    async fn quinn_initial_gives_the_name() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(config)).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
        let _connecting = endpoint
            .connect(server.local_addr().unwrap(), "h3.quinn.example")
            .unwrap();
        let mut buf = vec![0u8; 65_535];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            server_name(&[buf[..n].to_vec()]),
            Sniff::Name("h3.quinn.example".into())
        );
    }
}
