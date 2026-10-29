//! REALITY: handshake records shaped like `dest`'s.
//!
//! A passive observer sees the SNI of `dest` and the lengths of the server's handshake
//! records. rustls sends EncryptedExtensions, Certificate, CertificateVerify and
//! Finished in one small record; a real site sends kilobytes of certificate chain in
//! several. So, as Xray does, the server sends our client's ClientHello to `dest`, reads
//! its answer ([`probe`]), and then:
//! - answers with `dest`'s key exchange group and cipher suite, so the ServerHello has
//!   the same length;
//! - re-frames its encrypted handshake ([`reshape`]) into records of `dest`'s lengths,
//!   filled with TLS 1.3 record padding (RFC 8446 §5.4). It decrypts rustls's flight
//!   with the server handshake traffic secret (from [`SecretLog`]) and encrypts it again.
//!   rustls never uses that key again: after Finished the server writes with the
//!   application keys.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONNECT: Duration = Duration::from_secs(3);
/// How long `dest` may take to start answering.
const ANSWER: Duration = Duration::from_secs(3);
/// `dest`'s flight ends when, after an encrypted record, the data stops at a record
/// boundary for a quarter of the TCP connect time (about the RTT to `dest`), within
/// these bounds. A record still arriving is always waited for. A flight is sent at
/// once and fits the initial congestion window, so its segments arrive back to back;
/// a long pause would show as an extra delay before our ServerHello.
const MIN_GAP: Duration = Duration::from_millis(2);
const MAX_GAP: Duration = Duration::from_millis(15);
const MAX_RECORDS: usize = 16;
const MAX_READ: usize = 64 * 1024;
/// AEAD tag of every TLS 1.3 suite.
const TAG: usize = 16;
/// Largest TLSInnerPlaintext (content + type + padding).
const MAX_INNER: usize = 16_384 + 1;

/// What `dest` answered to the same ClientHello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestShape {
    /// Key exchange group of its ServerHello.
    pub group: u16,
    /// Cipher suite of its ServerHello.
    pub suite: u16,
    /// Lengths of its encrypted records after the ServerHello (record payloads).
    pub records: Vec<usize>,
}

/// Sends `hello` (whole TLS records) to `addr` and reads its first flight; None when
/// it cannot be reached, asks for a retry or does not answer in time.
pub async fn probe(addr: std::net::SocketAddr, hello: &[u8]) -> Option<DestShape> {
    let dialed = Instant::now();
    let mut tcp = tokio::time::timeout(CONNECT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let gap = (dialed.elapsed() / 4).clamp(MIN_GAP, MAX_GAP);
    let _ = tcp.set_nodelay(true);
    tcp.write_all(hello).await.ok()?;
    let start = Instant::now();
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut hello_info = None;
    let mut records = Vec::new();
    let mut pos = 0;
    loop {
        while let Some(h) = buf.get(pos..pos + 5) {
            let len = usize::from(u16::from_be_bytes([h[3], h[4]]));
            let Some(body) = buf.get(pos + 5..pos + 5 + len) else {
                break;
            };
            match h[0] {
                0x16 if hello_info.is_none() => hello_info = Some(server_hello(body)?),
                0x14 => {}
                0x17 if hello_info.is_some() => records.push(len),
                _ => return None,
            }
            pos += 5 + len;
        }
        if records.len() >= MAX_RECORDS || buf.len() >= MAX_READ {
            break;
        }
        let left = ANSWER.checked_sub(start.elapsed());
        let wait = if records.is_empty() {
            left?
        } else if pos == buf.len() {
            gap
        } else {
            // In the middle of a record: the rest is on its way.
            left.unwrap_or_default()
        };
        match tokio::time::timeout(wait, tcp.read_buf(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {}
            _ => break,
        }
    }
    let (group, suite) = hello_info?;
    (!records.is_empty()).then_some(DestShape {
        group,
        suite,
        records,
    })
}

/// SHA-256 of "HelloRetryRequest": the random of a retry request.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Group and cipher suite of a TLS 1.3 ServerHello record body.
fn server_hello(body: &[u8]) -> Option<(u16, u16)> {
    let u16_at = |b: &[u8], i: usize| Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]));
    if *body.first()? != 2 {
        return None;
    }
    let random = body.get(6..38)?;
    if random == HRR_RANDOM {
        return None;
    }
    let sid = usize::from(*body.get(38)?);
    let at = 39 + sid;
    let suite = u16_at(body, at)?;
    let ext_len = usize::from(u16_at(body, at + 3)?);
    let mut ext = body.get(at + 5..at + 5 + ext_len)?;
    let mut group = None;
    let mut tls13 = false;
    while ext.len() >= 4 {
        let kind = u16_at(ext, 0)?;
        let n = usize::from(u16_at(ext, 2)?);
        let data = ext.get(4..4 + n)?;
        match kind {
            0x0033 => group = u16_at(data, 0),
            0x002b => tls13 = data == [3, 4],
            _ => {}
        }
        ext = &ext[4 + n..];
    }
    tls13.then_some((group?, suite))
}

/// Keeps the server handshake traffic secret of one connection.
#[derive(Debug, Default)]
pub struct SecretLog(Mutex<Option<Vec<u8>>>);

impl SecretLog {
    /// The secret, once rustls has derived it.
    pub fn secret(&self) -> Option<Vec<u8>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl rustls::KeyLog for SecretLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
            *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(secret.to_vec());
        }
    }
}

/// The record key and IV of a TLS 1.3 traffic secret (RFC 8446 §7.3).
struct Keys {
    suite: u16,
    key: Vec<u8>,
    iv: [u8; 12],
}

fn expand_label(secret: &[u8], label: &str, len: usize, sha384: bool) -> Option<Vec<u8>> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&u16::try_from(len).ok()?.to_be_bytes());
    info.push(u8::try_from(full.len()).ok()?);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    let mut out = vec![0u8; len];
    if sha384 {
        Hkdf::<Sha384>::from_prk(secret)
            .ok()?
            .expand(&info, &mut out)
            .ok()?;
    } else {
        Hkdf::<Sha256>::from_prk(secret)
            .ok()?
            .expand(&info, &mut out)
            .ok()?;
    }
    Some(out)
}

impl Keys {
    fn new(suite: u16, secret: &[u8]) -> Option<Self> {
        let (key_len, sha384) = match suite {
            0x1301 => (16, false),
            0x1302 => (32, true),
            0x1303 => (32, false),
            _ => return None,
        };
        Some(Keys {
            suite,
            key: expand_label(secret, "key", key_len, sha384)?,
            iv: expand_label(secret, "iv", 12, sha384)?.try_into().ok()?,
        })
    }

    fn nonce(&self, seq: u64) -> [u8; 12] {
        let mut n = self.iv;
        for (b, s) in n[4..].iter_mut().zip(seq.to_be_bytes()) {
            *b ^= s;
        }
        n
    }

    fn seal(&self, seq: u64, aad: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.nonce(seq);
        let p = Payload { msg, aad };
        match self.suite {
            0x1301 => Aes128Gcm::new_from_slice(&self.key)
                .ok()?
                .encrypt(GenericArray::from_slice(&nonce), p),
            0x1302 => Aes256Gcm::new_from_slice(&self.key)
                .ok()?
                .encrypt(GenericArray::from_slice(&nonce), p),
            _ => ChaCha20Poly1305::new_from_slice(&self.key)
                .ok()?
                .encrypt(GenericArray::from_slice(&nonce), p),
        }
        .ok()
    }

    fn open(&self, seq: u64, aad: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.nonce(seq);
        let p = Payload { msg, aad };
        match self.suite {
            0x1301 => Aes128Gcm::new_from_slice(&self.key)
                .ok()?
                .decrypt(GenericArray::from_slice(&nonce), p),
            0x1302 => Aes256Gcm::new_from_slice(&self.key)
                .ok()?
                .decrypt(GenericArray::from_slice(&nonce), p),
            _ => ChaCha20Poly1305::new_from_slice(&self.key)
                .ok()?
                .decrypt(GenericArray::from_slice(&nonce), p),
        }
        .ok()
    }
}

fn header(typ: u8, len: usize) -> [u8; 5] {
    let l = (len as u16).to_be_bytes();
    [typ, 3, 3, l[0], l[1]]
}

/// rustls's first flight (`flight`: ServerHello, ChangeCipherSpec, encrypted records)
/// with the encrypted handshake re-framed into records of `sizes` (record payload
/// lengths). Handshake bytes that do not fit go into extra records after them. None
/// when the flight is not what we expect; the caller then sends it unchanged.
pub fn reshape(flight: &[u8], suite: u16, secret: &[u8], sizes: &[usize]) -> Option<Vec<u8>> {
    let keys = Keys::new(suite, secret)?;
    let mut out = Vec::with_capacity(flight.len() + sizes.iter().sum::<usize>() + 64);
    let mut handshake = Vec::new();
    let mut seq = 0;
    let mut rest = flight;
    while !rest.is_empty() {
        let h = rest.get(..5)?;
        let len = usize::from(u16::from_be_bytes([h[3], h[4]]));
        let record = rest.get(..5 + len)?;
        match h[0] {
            0x16 | 0x14 if seq == 0 => out.extend_from_slice(record),
            0x17 => {
                let mut inner = keys.open(seq, h, &record[5..])?;
                seq += 1;
                while inner.last() == Some(&0) {
                    inner.pop();
                }
                if inner.pop()? != 0x16 {
                    return None;
                }
                handshake.extend_from_slice(&inner);
            }
            _ => return None,
        }
        rest = &rest[5 + len..];
    }
    if handshake.is_empty() {
        return None;
    }
    let mut chunks = plan(handshake.len(), sizes).into_iter();
    let mut left = &handshake[..];
    let mut seq = 0;
    while !left.is_empty() {
        let (take, record_len) = chunks.next().unwrap_or((
            left.len().min(MAX_INNER - 1),
            left.len().min(MAX_INNER - 1) + 1 + TAG,
        ));
        let (now, later) = left.split_at(take);
        let mut inner = Vec::with_capacity(record_len - TAG);
        inner.extend_from_slice(now);
        inner.push(0x16);
        inner.resize(record_len - TAG, 0);
        let h = header(0x17, record_len);
        let sealed = keys.seal(seq, &h, &inner)?;
        out.extend_from_slice(&h);
        out.extend_from_slice(&sealed);
        seq += 1;
        left = later;
    }
    Some(out)
}

/// How many handshake bytes go into each record of `sizes`: every record carries at
/// least one (TLS forbids empty handshake records), the rest is padding. Returns
/// (bytes, record payload length) pairs for the records used.
fn plan(total: usize, sizes: &[usize]) -> Vec<(usize, usize)> {
    let usable: Vec<usize> = sizes
        .iter()
        .copied()
        .filter(|&s| s > 1 + TAG && s - TAG <= MAX_INNER)
        .collect();
    let mut out = Vec::new();
    let mut left = total;
    for (i, &size) in usable.iter().enumerate() {
        if left == 0 {
            break;
        }
        let cap = size - TAG - 1;
        // Leave one byte for each later record while there are bytes to spare.
        let later = (usable.len() - i - 1).min(left - 1);
        let take = cap.min(left - later);
        out.push((take, size));
        left -= take;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_fills_dest_sizes() {
        // Observed for www.microsoft.com: 36, 8268, 281, 69.
        let p = plan(300, &[36, 8268, 281, 69]);
        assert_eq!(
            p.iter().map(|&(_, s)| s).collect::<Vec<_>>(),
            [36, 8268, 281, 69]
        );
        assert_eq!(p.iter().map(|&(t, _)| t).sum::<usize>(), 300);
        assert!(p.iter().all(|&(t, s)| t >= 1 && t + 1 + TAG <= s));
        // Fewer bytes than records: only as many records as bytes.
        assert_eq!(plan(2, &[36, 8268, 281, 69]).len(), 2);
        // More bytes than fit: the plan covers what it can, the rest goes elsewhere.
        assert_eq!(plan(100, &[30]).iter().map(|&(t, _)| t).sum::<usize>(), 13);
    }

    #[test]
    fn reshape_round_trips() {
        let secret = [7u8; 32];
        let keys = Keys::new(0x1301, &secret).unwrap();
        // A fake flight: ServerHello, CCS, one encrypted record of 300 handshake bytes.
        let handshake: Vec<u8> = (0..300u32).map(|i| i as u8 | 1).collect();
        let mut inner = handshake.clone();
        inner.push(0x16);
        let h = header(0x17, inner.len() + TAG);
        let mut flight = vec![0x16, 3, 3, 0, 2, 2, 0, 0x14, 3, 3, 0, 1, 1];
        flight.extend_from_slice(&h);
        flight.extend(keys.seal(0, &h, &inner).unwrap());

        let sizes = [36, 8268, 281, 69];
        let out = reshape(&flight, 0x1301, &secret, &sizes).unwrap();
        assert_eq!(&out[..13], &flight[..13]);
        let (mut rest, mut seq, mut got, mut lens) = (&out[13..], 0, Vec::new(), Vec::new());
        while !rest.is_empty() {
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            lens.push(len);
            let mut p = keys.open(seq, &rest[..5], &rest[5..5 + len]).unwrap();
            while p.last() == Some(&0) {
                p.pop();
            }
            assert_eq!(p.pop(), Some(0x16));
            got.extend(p);
            seq += 1;
            rest = &rest[5 + len..];
        }
        assert_eq!(lens, sizes);
        assert_eq!(got, handshake);
    }

    #[test]
    fn server_hello_fields() {
        // type, len(3), version, random, sid len 32, sid, suite, compression, extensions
        let mut b = vec![2, 0, 0, 0, 3, 3];
        b.extend([0x11; 32]);
        b.push(32);
        b.extend([0x22; 32]);
        b.extend([0x13, 0x02, 0]);
        let ext = [0x00, 0x2b, 0, 2, 3, 4, 0x00, 0x33, 0, 4, 0x11, 0xec, 0, 0];
        b.extend((ext.len() as u16).to_be_bytes());
        b.extend(ext);
        assert_eq!(server_hello(&b), Some((0x11ec, 0x1302)));
        b[6..38].copy_from_slice(&HRR_RANDOM);
        assert_eq!(server_hello(&b), None);
    }
}
