//! REALITY server (the `server` feature): TLS 1.3 that looks like `dest` to everyone
//! without the key.
//!
//! The ClientHello is read first. When its session_id opens with
//! `auth_key = HKDF-SHA256(X25519(private key, client X25519 share), salt = random[..20], info = "REALITY")`
//! (AES-256-GCM, nonce `random[20..]`, aad = the ClientHello with a zeroed session_id)
//! and names an allowed short ID, we finish the TLS 1.3 handshake ourselves with a
//! throw-away Ed25519 certificate whose signature field is
//! `HMAC-SHA512(auth_key, public key)`: the proof the client checks. Everyone else
//! (scanners, browsers, a censor's probes) is spliced to `dest` together with the
//! bytes read so far, and talks to the real site.
//!
//! Not done yet: Xray also dials `dest` for authenticated clients to copy the sizes of
//! its handshake records; ours have rustls's sizes.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rustls::crypto::ring::sign::any_eddsa_type;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{ServerConfig, ServerConnection, SignatureAlgorithm, SignatureScheme};
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{ServerRealityConfig, parse_short_id, parse_x25519_key};
use crate::error::{Error, Result};
use crate::outbound::pq::X25519_MLKEM768;
use crate::outbound::tls_stream::TlsRecordStream;

/// ClientHello offset of the session_id: handshake header 4 + version 2 + random 32 + length 1.
const SID_OFFSET: usize = 39;
/// More than any real ClientHello (post-quantum ones are about 2 KB).
const MAX_HELLO: usize = 64 * 1024;
const DEST_CONNECT: Duration = Duration::from_secs(5);
const FALLBACK_IDLE: Duration = Duration::from_secs(300);

/// A configured REALITY server.
pub struct RealityServer {
    private: StaticSecret,
    server_names: HashSet<String>,
    short_ids: HashSet<[u8; 8]>,
    max_time_diff: Option<Duration>,
    dest: String,
    key: Arc<dyn SigningKey>,
    public: [u8; 32],
    /// The certificate with a zero signature; the last 64 bytes get the HMAC.
    cert: Vec<u8>,
    base: ServerConfig,
}

/// The outcome of reading a ClientHello.
pub enum Handshake {
    /// Our client: the TLS stream is ready.
    Done(Box<TlsRecordStream>),
    /// Anyone else: forward to `dest`, starting with these bytes.
    Fallback(TcpStream, Vec<u8>),
}

impl RealityServer {
    /// Checks the settings and makes the Ed25519 key of this run.
    pub fn new(cfg: &ServerRealityConfig) -> Result<Self> {
        let private =
            StaticSecret::from(parse_x25519_key(cfg.private_key.expose(), "private_key")?);
        let short_ids = cfg
            .short_ids
            .iter()
            .map(|s| parse_short_id(s))
            .collect::<Result<_>>()?;
        // PKCS#8 v1 around a random Ed25519 seed.
        let mut pkcs8 = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        pkcs8.extend_from_slice(&seed);
        let key = any_eddsa_type(&PrivatePkcs8KeyDer::from(pkcs8))
            .map_err(|e| Error::config(format!("reality: ed25519 key: {e}")))?;
        let spki = key
            .public_key()
            .ok_or_else(|| Error::config("reality: ed25519 key without a public key"))?;
        let public: [u8; 32] = spki
            .as_ref()
            .get(spki.as_ref().len().saturating_sub(32)..)
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| Error::config("reality: ed25519 public key"))?;

        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups.insert(0, &X25519_MLKEM768);
        let mut base = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::config(format!("reality: {e}")))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(OneCert(None)));
        // As Xray's REALITY: no tickets, no ALPN, an uncompressed certificate.
        base.send_tls13_tickets = 0;
        base.cert_compressors = Vec::new();
        Ok(RealityServer {
            private,
            server_names: cfg
                .server_names
                .iter()
                .map(|n| n.trim().to_ascii_lowercase())
                .filter(|n| !n.is_empty())
                .collect(),
            short_ids,
            max_time_diff: (cfg.max_time_diff_ms > 0)
                .then(|| Duration::from_millis(cfg.max_time_diff_ms)),
            dest: cfg.dest.clone(),
            cert: template_cert(&public),
            key: Arc::new(Ed25519Always(key)),
            public,
            base,
        })
    }

    /// Reads the ClientHello (waiting at most `hello_wait`) and either completes the
    /// handshake or hands the connection back for [`RealityServer::forward`].
    pub async fn accept(&self, mut tcp: TcpStream, hello_wait: Duration) -> Result<Handshake> {
        let mut prefix = Vec::with_capacity(2048);
        // A slow or partial hello goes to the real site as it is.
        let hello = tokio::time::timeout(hello_wait, read_hello(&mut tcp, &mut prefix))
            .await
            .unwrap_or(Ok(None))?;
        let auth_key = match hello.as_deref().map(|h| self.authenticate(h)) {
            Some(Ok(k)) => k,
            Some(Err(why)) => {
                tracing::debug!("reality: {why}, forwarding to {}", self.dest);
                return Ok(Handshake::Fallback(tcp, prefix));
            }
            None => return Ok(Handshake::Fallback(tcp, prefix)),
        };
        let conn = ServerConnection::new(self.config_for(&auth_key))
            .map_err(|e| Error::Tls(e.to_string()))?;
        let tls = TlsRecordStream::accept_prefixed(tcp, conn, &prefix).await?;
        Ok(Handshake::Done(Box::new(tls)))
    }

    /// Splices a client that is not ours to `dest`.
    pub async fn forward(&self, tcp: TcpStream, prefix: Vec<u8>) {
        let connect = tokio::time::timeout(DEST_CONNECT, TcpStream::connect(&self.dest));
        let mut dest = match connect.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return tracing::debug!("reality dest {}: {e}", self.dest),
            Err(_) => return tracing::debug!("reality dest {}: connect timed out", self.dest),
        };
        let _ = dest.set_nodelay(true);
        if dest.write_all(&prefix).await.is_err() {
            return;
        }
        let (up, down) = (AtomicU64::new(0), AtomicU64::new(0));
        if let Err(e) = crate::relay::relay_tcp(tcp, dest, FALLBACK_IDLE, &up, &down).await {
            tracing::trace!("reality forward: {e}");
        }
    }

    /// The auth key of a ClientHello from our client, or why it is not one.
    fn authenticate(&self, hs: &[u8]) -> std::result::Result<[u8; 32], &'static str> {
        let h = parse_hello(hs).ok_or("not a TLS 1.3 ClientHello with a 32-byte session_id")?;
        if !h.tls13 {
            return Err("no TLS 1.3 in the ClientHello");
        }
        let name = h.server_name.unwrap_or_default().to_ascii_lowercase();
        if !self.server_names.contains(&name) {
            return Err("server name not in server_names");
        }
        let share = h.x25519.ok_or("no X25519 key share")?;
        let shared = self.private.diffie_hellman(&PublicKey::from(share));
        if !shared.was_contributory() {
            return Err("weak X25519 key share");
        }
        let mut auth_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&h.random[..20]), shared.as_bytes())
            .expand(b"REALITY", &mut auth_key)
            .map_err(|_| "hkdf")?;
        let mut aad = hs.to_vec();
        aad[SID_OFFSET..SID_OFFSET + 32].fill(0);
        let plain = Aes256Gcm::new_from_slice(&auth_key)
            .map_err(|_| "aes key")?
            .decrypt(
                Nonce::from_slice(&h.random[20..]),
                Payload {
                    msg: &h.session_id,
                    aad: &aad,
                },
            )
            .map_err(|_| "session_id does not open with our key")?;
        let plain: [u8; 16] = plain.try_into().map_err(|_| "bad session_id")?;
        let short_id: [u8; 8] = plain[8..].try_into().map_err(|_| "bad session_id")?;
        if !self.short_ids.contains(&short_id) {
            return Err("short ID not in short_ids");
        }
        if let Some(max) = self.max_time_diff {
            let theirs = u64::from(u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]));
            let ours = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if Duration::from_secs(ours.abs_diff(theirs)) > max {
                return Err("client clock out of max_time_diff_ms");
            }
        }
        Ok(auth_key)
    }

    /// A TLS config whose certificate proves `auth_key`.
    fn config_for(&self, auth_key: &[u8; 32]) -> Arc<ServerConfig> {
        let mut cert = self.cert.clone();
        let at = cert.len() - 64;
        // HMAC accepts any key length.
        if let Ok(mut mac) = <Hmac<Sha512> as Mac>::new_from_slice(auth_key) {
            mac.update(&self.public);
            cert[at..].copy_from_slice(&mac.finalize().into_bytes());
        }
        let mut cfg = self.base.clone();
        cfg.cert_resolver = Arc::new(OneCert(Some(Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(cert)],
            self.key.clone(),
        )))));
        Arc::new(cfg)
    }
}

#[derive(Debug)]
struct OneCert(Option<Arc<CertifiedKey>>);

impl ResolvesServerCert for OneCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.clone()
    }
}

/// Signs with Ed25519 whatever the client lists: browsers (and their fingerprints)
/// do not offer it, but REALITY clients check this certificate their own way.
#[derive(Debug)]
struct Ed25519Always(Arc<dyn SigningKey>);

impl SigningKey for Ed25519Always {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.0.choose_scheme(&[SignatureScheme::ED25519])
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}

/// DER: tag, length, content.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let n = content.len();
    let mut out = vec![tag];
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

/// The certificate Xray's REALITY makes: v3, serial 0, empty names, zero validity
/// times, an Ed25519 key, and a signature field that is overwritten per connection.
fn template_cert(public: &[u8; 32]) -> Vec<u8> {
    let ed25519 = der(0x30, &der(0x06, &[0x2b, 0x65, 0x70]));
    let time = der(0x18, b"00010101000000Z");
    let spki = der(
        0x30,
        &[ed25519.clone(), der(0x03, &[&[0u8][..], public].concat())].concat(),
    );
    let tbs = der(
        0x30,
        &[
            der(0xa0, &der(0x02, &[2])),
            der(0x02, &[0]),
            ed25519.clone(),
            der(0x30, &[]),
            der(0x30, &[time.clone(), time].concat()),
            der(0x30, &[]),
            spki,
        ]
        .concat(),
    );
    der(0x30, &[tbs, ed25519, der(0x03, &[0u8; 65])].concat())
}

enum Scan {
    Hello(Vec<u8>),
    More,
    NotHello,
}

/// Reads until a whole ClientHello is in `buf` (Some), the bytes cannot be one, or
/// the client stops sending (None). Everything read stays in `buf`.
async fn read_hello(tcp: &mut TcpStream, buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    loop {
        match scan(buf) {
            Scan::Hello(h) => return Ok(Some(h)),
            Scan::NotHello => return Ok(None),
            Scan::More if buf.len() >= MAX_HELLO => return Ok(None),
            Scan::More => {}
        }
        if tcp.read_buf(buf).await? == 0 {
            return Ok(None);
        }
    }
}

/// The ClientHello handshake message from the records in `buf`, once it and any
/// record after it are complete (TLS reading then resumes at a record boundary).
fn scan(buf: &[u8]) -> Scan {
    if buf.first().is_some_and(|&t| t != 0x16) {
        return Scan::NotHello;
    }
    let mut hs = Vec::new();
    let mut need = None;
    let mut pos = 0;
    while let Some(h) = buf.get(pos..pos + 5) {
        let len = usize::from(u16::from_be_bytes([h[3], h[4]]));
        if need.is_none_or(|n| hs.len() < n)
            && (h[0] != 0x16 || h[1] != 3 || len == 0 || len > 16_384)
        {
            return Scan::NotHello;
        }
        let Some(body) = buf.get(pos + 5..pos + 5 + len) else {
            return Scan::More;
        };
        if need.is_none_or(|n| hs.len() < n) {
            hs.extend_from_slice(body);
        }
        pos += 5 + len;
        if need.is_none() && hs.len() >= 4 {
            if hs[0] != 0x01 {
                return Scan::NotHello;
            }
            let n = 4 + (usize::from(hs[1]) << 16 | usize::from(hs[2]) << 8 | usize::from(hs[3]));
            if n > MAX_HELLO {
                return Scan::NotHello;
            }
            need = Some(n);
        }
    }
    match need {
        Some(n) if hs.len() >= n && pos == buf.len() => {
            hs.truncate(n);
            Scan::Hello(hs)
        }
        _ => Scan::More,
    }
}

/// What REALITY needs from a ClientHello.
struct Hello {
    random: [u8; 32],
    session_id: [u8; 32],
    server_name: Option<String>,
    x25519: Option<[u8; 32]>,
    tls13: bool,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n)?;
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<usize> {
        let b = self.take(2)?;
        Some(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
}

fn parse_hello(hs: &[u8]) -> Option<Hello> {
    let mut r = Reader(hs.get(4..)?);
    r.take(2)?; // legacy_version
    let random = r.take(32)?.try_into().ok()?;
    if r.u8()? != 32 {
        return None;
    }
    let session_id = r.take(32)?.try_into().ok()?;
    let n = r.u16()?;
    r.take(n)?; // cipher suites
    let n = usize::from(r.u8()?);
    r.take(n)?; // compression methods
    let n = r.u16()?;
    let mut ext = Reader(r.take(n)?);
    let mut hello = Hello {
        random,
        session_id,
        server_name: None,
        x25519: None,
        tls13: false,
    };
    while !ext.0.is_empty() {
        let kind = ext.u16()?;
        let n = ext.u16()?;
        let mut d = Reader(ext.take(n)?);
        match kind {
            0x0000 => {
                d.u16()?;
                if d.u8()? == 0 {
                    let n = d.u16()?;
                    hello.server_name = std::str::from_utf8(d.take(n)?).ok().map(String::from);
                }
            }
            0x002b => {
                let n = usize::from(d.u8()?);
                hello.tls13 = d.take(n)?.chunks(2).any(|v| v == [3, 4]);
            }
            0x0033 => {
                let n = d.u16()?;
                let mut shares = Reader(d.take(n)?);
                while !shares.0.is_empty() {
                    let group = shares.u16()?;
                    let n = shares.u16()?;
                    let key = shares.take(n)?;
                    if group == 0x001d && n == 32 {
                        hello.x25519 = key.try_into().ok();
                    }
                }
            }
            _ => {}
        }
    }
    Some(hello)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(body: &[u8]) -> Vec<u8> {
        let mut r = vec![0x16, 3, 1];
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    #[test]
    fn scan_reassembles_split_hellos() {
        let mut hs = vec![1, 0, 0, 6];
        hs.extend_from_slice(b"abcdef");
        let mut wire = record(&hs[..3]);
        wire.extend(record(&hs[3..]));
        assert!(matches!(scan(&wire[..4]), Scan::More));
        assert!(matches!(scan(&wire[..wire.len() - 1]), Scan::More));
        assert!(matches!(scan(&wire), Scan::Hello(h) if h == hs));
        // A complete record after the hello is fine; half of one is not yet.
        let mut more = wire.clone();
        more.extend_from_slice(&[0x14, 3, 3, 0, 1, 1]);
        assert!(matches!(scan(&more), Scan::Hello(_)));
        assert!(matches!(scan(&more[..more.len() - 1]), Scan::More));
        assert!(matches!(scan(b"GET / HTTP/1.1\r\n"), Scan::NotHello));
        assert!(matches!(scan(&record(&[2, 0, 0, 0])), Scan::NotHello));
        assert!(matches!(scan(&[0x16, 3, 1, 0, 0]), Scan::NotHello));
    }

    #[test]
    fn certificate_layout() {
        let cert = template_cert(&[7; 32]);
        // What REALITY clients look for: the key after its AlgorithmIdentifier, and
        // the signature as the last 64 bytes of a 65-byte BIT STRING.
        let key_at = cert
            .windows(10)
            .position(|w| w == [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
            .unwrap();
        assert_eq!(&cert[key_at + 10..key_at + 42], &[7; 32]);
        assert_eq!(&cert[cert.len() - 67..cert.len() - 64], &[0x03, 0x41, 0x00]);
        assert_eq!(&cert[..2], &[0x30, 0x81]);
        assert_eq!(usize::from(cert[2]), cert.len() - 3);
    }
}
