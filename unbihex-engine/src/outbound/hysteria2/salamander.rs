//! Salamander packet envelope: salt[8] followed by QUIC bytes XORed with
//! BLAKE2b-256(password || salt). QUIC/TLS still provides authentication.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use blake2::{Blake2b, Digest, digest::consts::U32};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::RngCore;

use crate::config::Secret;

fn mask(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hash = Blake2b::<U32>::new();
    hash.update(password.as_bytes());
    hash.update(salt);
    hash.finalize().into()
}

fn seal(password: &str, salt: [u8; 8], payload: &[u8]) -> Vec<u8> {
    let key = mask(password, &salt);
    let mut out = Vec::with_capacity(payload.len() + 8);
    out.extend_from_slice(&salt);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 32]));
    out
}

fn open(password: &str, bytes: &mut [u8]) -> usize {
    if bytes.len() <= 8 {
        return 0;
    }
    let key = mask(password, &bytes[..8]);
    for (i, b) in bytes[8..].iter_mut().enumerate() {
        *b ^= key[i % 32];
    }
    bytes.copy_within(8.., 0);
    bytes.len() - 8
}

#[derive(Debug)]
pub(super) struct SalamanderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Secret,
}

impl SalamanderSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, password: Secret) -> Self {
        Self { inner, password }
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit
            .segment_size
            .is_some_and(|size| size < transmit.contents.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Salamander: unexpected GSO batch",
            ));
        }
        let mut salt = [0; 8];
        rand::thread_rng().fill_bytes(&mut salt);
        let bytes = seal(self.password.expose(), salt, transmit.contents);
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &bytes,
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        for i in 0..count {
            let length = meta[i].len;
            let stride = meta[i].stride;
            if stride <= 8 || length > bufs[i].len() {
                meta[i].len = 0;
                continue;
            }
            // GRO may place several wire datagrams in one buffer. Decrypt each
            // with its OWN salt and compact the strides, including a short tail.
            let mut read = 0;
            let mut written = 0;
            while read < length {
                let end = (read + stride).min(length);
                let n = open(self.password.expose(), &mut bufs[i][read..end]);
                if n == 0 {
                    written = 0;
                    break;
                }
                bufs[i].copy_within(read..read + n, written);
                written += n;
                read = end;
            }
            meta[i].len = written;
            meta[i].stride = stride - 8;
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_salamander_envelope_and_short_packet() {
        // Independently calculated with hashlib.blake2b(digest_size=32).
        let bytes = seal("test-password", [0, 1, 2, 3, 4, 5, 6, 7], b"QUIC payload");
        assert_eq!(
            hex::encode(&bytes),
            "000102030405060788f4431a951c286972f89b86"
        );
        let mut bytes = bytes;
        let n = open("test-password", &mut bytes);
        assert_eq!(&bytes[..n], b"QUIC payload");
        assert_eq!(open("test-password", &mut [0; 8]), 0);
    }
}
