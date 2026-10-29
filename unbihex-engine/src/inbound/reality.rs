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
//! A ClientHello is accepted once: the client's clock must be within `max_time_diff`
//! of ours (2 minutes unless set), and the randoms seen in that window are remembered,
//! so a recorded hello replayed by a prober is spliced to `dest` like any stranger.
//!
//! For our clients the server also asks `dest` how it answers the same hello and
//! copies its key exchange group, cipher suite and handshake record sizes
//! (`reality_shape.rs`), so the handshake looks like `dest`'s on the wire.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

use super::reality_shape::{self, DestShape, SecretLog};
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
/// The clock window when the config gives none (Xray's 0 means no check; ours does not,
/// since without it a recorded hello could be replayed forever).
const DEFAULT_TIME_DIFF: Duration = Duration::from_secs(120);
/// At most this many remembered randoms; only authenticated hellos are remembered.
const REPLAY_CAP: usize = 1 << 20;
/// How long a `dest` answer stays usable for hellos with the same stable shape.
const SHAPE_TTL: Duration = Duration::from_secs(600);
/// How long the resolved `dest` addresses are reused.
const DEST_TTL: Duration = Duration::from_secs(300);
/// At most this many cached shapes; the oldest insertion is evicted.
const SHAPE_CAP: usize = 8;
/// Timeout of the `dest` host lookup.
const DEST_LOOKUP: Duration = Duration::from_secs(3);

/// A configured REALITY server.
pub struct RealityServer {
    private: StaticSecret,
    server_names: HashSet<String>,
    short_ids: HashSet<[u8; 8]>,
    max_time_diff: Duration,
    seen: Mutex<Seen>,
    dest: String,
    /// Answers of `dest` to hello shapes, and the resolved `dest` addresses.
    shapes: tokio::sync::Mutex<ShapeCache>,
    key: Arc<dyn SigningKey>,
    public: [u8; 32],
    /// The certificate with a zero signature; the last 64 bytes get the HMAC.
    cert: Vec<u8>,
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

        tls_config(None, None)?;
        Ok(RealityServer {
            private,
            server_names: cfg
                .server_names
                .iter()
                .map(|n| n.trim().to_ascii_lowercase())
                .filter(|n| !n.is_empty())
                .collect(),
            short_ids,
            max_time_diff: match cfg.max_time_diff_ms {
                0 => DEFAULT_TIME_DIFF,
                ms => Duration::from_millis(ms),
            },
            seen: Mutex::new(Seen::default()),
            dest: cfg.dest.clone(),
            shapes: tokio::sync::Mutex::new(ShapeCache::default()),
            cert: template_cert(&public),
            key: Arc::new(Ed25519Always(key)),
            public,
        })
    }

    /// Reads the ClientHello (waiting at most `hello_wait`) and either completes the
    /// handshake or hands the connection back for [`RealityServer::forward`].
    pub async fn accept(&self, mut tcp: TcpStream, hello_wait: Duration) -> Result<Handshake> {
        crate::net::socket::tune_tcp(&tcp);
        let mut prefix = Vec::with_capacity(2048);
        // A slow or partial hello goes to the real site as it is.
        let hello = tokio::time::timeout(hello_wait, read_hello(&mut tcp, &mut prefix))
            .await
            .unwrap_or(Ok(None))?;
        let (auth_key, shape_key) = match hello.as_deref().map(|h| self.authenticate(h)) {
            Some(Ok(k)) => k,
            Some(Err(why)) => {
                tracing::debug!("reality: {why}, forwarding to {}", self.dest);
                return Ok(Handshake::Fallback(tcp, prefix));
            }
            None => return Ok(Handshake::Fallback(tcp, prefix)),
        };
        let shape = self.shape_for(shape_key, &prefix).await;
        if shape.is_none() {
            tracing::debug!(
                "reality: no answer from {}, handshake sizes are ours",
                self.dest
            );
        }
        let log = Arc::new(SecretLog::default());
        let config = self.config_for(&auth_key, shape.as_deref(), log.clone())?;
        let mut conn = ServerConnection::new(config).map_err(|e| Error::Tls(e.to_string()))?;
        let mut rest = &prefix[..];
        while !rest.is_empty() && conn.read_tls(&mut rest)? > 0 {
            conn.process_new_packets()
                .map_err(|e| Error::Tls(e.to_string()))?;
        }
        // rustls's first flight, re-framed like dest's when we know its sizes.
        let mut flight = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut flight)?;
        }
        let shaped = match (&shape, log.secret(), conn.negotiated_cipher_suite()) {
            (Some(s), Some(secret), Some(cs)) => {
                reality_shape::reshape(&flight, u16::from(cs.suite()), &secret, &s.records)
            }
            _ => None,
        };
        tcp.write_all(shaped.as_deref().unwrap_or(&flight)).await?;
        let mut tls = TlsRecordStream::new(tcp, conn);
        tls.handshake().await?;
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

    /// The auth key of a ClientHello from our client and its stable shape key, or why
    /// it is not one.
    fn authenticate(&self, hs: &[u8]) -> std::result::Result<([u8; 32], [u8; 32]), &'static str> {
        let h = parse_hello(hs).ok_or("not a TLS 1.3 ClientHello with a 32-byte session_id")?;
        if !h.tls13 {
            return Err("no TLS 1.3 in the ClientHello");
        }
        let name = h
            .server_name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
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
        let theirs = u64::from(u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]));
        let ours = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if Duration::from_secs(ours.abs_diff(theirs)) > self.max_time_diff {
            // The key and short ID were right: our client with a wrong clock, or a
            // replay of an old hello. Say so above debug, or it looks like a dead server.
            tracing::info!(
                "reality: a client's clock is {} s off ours (allowed {} s); sending it to dest",
                ours.abs_diff(theirs),
                self.max_time_diff.as_secs()
            );
            return Err("client clock out of max_time_diff_ms");
        }
        // A hello stays acceptable while its time is within the window on either side,
        // so it is remembered for twice the window (plus a second of rounding).
        let keep = self.max_time_diff * 2 + Duration::from_secs(1);
        if !self
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .first_time(h.random, keep)
        {
            tracing::info!("reality: a replayed ClientHello; sending it to dest");
            return Err("replayed ClientHello");
        }
        Ok((auth_key, shape_key(&h)))
    }

    /// The answer of `dest` to this hello shape, from the cache or from a fresh probe.
    async fn shape_for(&self, key: [u8; 32], hello: &[u8]) -> Option<Arc<DestShape>> {
        // Fast path and cached address under a short lock.
        let cached_addr = {
            let cache = self.shapes.lock().await;
            if let Some(shape) = cache.get(&key) {
                return Some(shape);
            }
            cache.fresh_dest_addr()
        };
        let addr = match cached_addr {
            Some(addr) => addr,
            None => self.resolve_dest().await?,
        };
        // The probe runs without the lock: on a dead dest concurrent misses may probe
        // in parallel, which is cheaper than serializing every handshake behind one.
        let probed = reality_shape::probe(addr, hello).await;
        let shape = match probed {
            Some(shape) => Arc::new(shape),
            None => {
                // A failed probe is not cached; a stale address is the likely reason,
                // so make the next handshake resolve `dest` again.
                self.shapes.lock().await.clear_dest_addrs();
                return None;
            }
        };
        // Last writer wins; entries for the same key are equivalent.
        self.shapes.lock().await.insert(key, shape.clone());
        Some(shape)
    }

    /// Resolves `dest` and remembers the addresses for [`DEST_TTL`].
    async fn resolve_dest(&self) -> Option<SocketAddr> {
        let found = tokio::time::timeout(DEST_LOOKUP, tokio::net::lookup_host(&self.dest))
            .await
            .ok()?
            .ok()?
            .collect::<Vec<_>>();
        let addr = *found.first()?;
        self.shapes.lock().await.set_dest_addrs(found);
        Some(addr)
    }

    /// A TLS config whose certificate proves `auth_key`, answering with `dest`'s
    /// group and cipher suite when known; `log` receives the handshake secret.
    fn config_for(
        &self,
        auth_key: &[u8; 32],
        shape: Option<&DestShape>,
        log: Arc<SecretLog>,
    ) -> Result<Arc<ServerConfig>> {
        let mut cert = self.cert.clone();
        let at = cert.len() - 64;
        // HMAC accepts any key length.
        if let Ok(mut mac) = <Hmac<Sha512> as Mac>::new_from_slice(auth_key) {
            mac.update(&self.public);
            cert[at..].copy_from_slice(&mac.finalize().into_bytes());
        }
        let mut cfg = tls_config(shape.map(|s| s.group), shape.map(|s| s.suite))?;
        cfg.cert_resolver = Arc::new(OneCert(Some(Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(cert)],
            self.key.clone(),
        )))));
        cfg.key_log = log;
        Ok(Arc::new(cfg))
    }
}

/// TLS 1.3 server settings, limited to `group` and `suite` when we support them.
fn tls_config(group: Option<u16>, suite: Option<u16>) -> Result<ServerConfig> {
    let mut cfg = ServerConfig::builder_with_provider(provider(group, suite))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::config(format!("reality: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(OneCert(None)));
    // As Xray's REALITY: no tickets, no ALPN, an uncompressed certificate.
    cfg.send_tls13_tickets = 0;
    cfg.cert_compressors = Vec::new();
    Ok(cfg)
}

/// Crypto providers by `(group, suite)`, where `u16::MAX` means None.
type ProviderCache = Mutex<HashMap<(u16, u16), Arc<rustls::crypto::CryptoProvider>>>;

/// The crypto provider for `group` and `suite`, built once per combination.
fn provider(group: Option<u16>, suite: Option<u16>) -> Arc<rustls::crypto::CryptoProvider> {
    static CACHE: OnceLock<ProviderCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (group.unwrap_or(u16::MAX), suite.unwrap_or(u16::MAX));
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(provider) = cache.get(&key) {
        return provider.clone();
    }
    let built = Arc::new(build_provider(group, suite));
    cache.insert(key, built.clone());
    built
}

/// Builds a provider like Xray's REALITY: our groups and suites, narrowed to `dest`'s.
fn build_provider(group: Option<u16>, suite: Option<u16>) -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups.insert(0, &X25519_MLKEM768);
    if let Some(g) = group.filter(|&g| provider.kx_groups.iter().any(|k| u16::from(k.name()) == g))
    {
        provider.kx_groups.retain(|k| u16::from(k.name()) == g);
    }
    provider.cipher_suites.retain(|cs| cs.tls13().is_some());
    if let Some(s) = suite.filter(|&s| {
        provider
            .cipher_suites
            .iter()
            .any(|cs| u16::from(cs.suite()) == s)
    }) {
        provider
            .cipher_suites
            .retain(|cs| u16::from(cs.suite()) == s);
    }
    provider
}

/// Client randoms of accepted hellos, oldest first.
#[derive(Default)]
struct Seen {
    set: HashSet<[u8; 32]>,
    order: VecDeque<(Instant, [u8; 32])>,
}

impl Seen {
    /// Remembers `random` for `keep`; false if it is already remembered.
    fn first_time(&mut self, random: [u8; 32], keep: Duration) -> bool {
        let now = Instant::now();
        while let Some(&(at, r)) = self.order.front() {
            if now.duration_since(at) < keep && self.order.len() < REPLAY_CAP {
                break;
            }
            self.order.pop_front();
            self.set.remove(&r);
        }
        if !self.set.insert(random) {
            return false;
        }
        self.order.push_back((now, random));
        true
    }
}

/// Cached answers of `dest` per stable ClientHello shape, and its resolved addresses.
#[derive(Default)]
struct ShapeCache {
    shapes: HashMap<[u8; 32], (Instant, Arc<DestShape>)>,
    dest_addrs: Option<(Instant, Vec<SocketAddr>)>,
}

impl ShapeCache {
    /// The cached shape for `key`, if it is still fresh.
    fn get(&self, key: &[u8; 32]) -> Option<Arc<DestShape>> {
        let (at, shape) = self.shapes.get(key)?;
        (at.elapsed() < SHAPE_TTL).then(|| shape.clone())
    }

    /// The first cached `dest` address, while it is younger than [`DEST_TTL`].
    fn fresh_dest_addr(&self) -> Option<SocketAddr> {
        let (at, addrs) = self.dest_addrs.as_ref()?;
        if at.elapsed() >= DEST_TTL {
            return None;
        }
        addrs.first().copied()
    }

    /// Remembers resolved `dest` addresses from now.
    fn set_dest_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.set_dest_addrs_at(Instant::now(), addrs);
    }

    fn set_dest_addrs_at(&mut self, at: Instant, addrs: Vec<SocketAddr>) {
        self.dest_addrs = Some((at, addrs));
    }

    /// Forgets the resolved addresses; the next handshake resolves `dest` again.
    fn clear_dest_addrs(&mut self) {
        self.dest_addrs = None;
    }

    /// Stores `shape`, evicting the oldest insertion when the cache is full.
    fn insert(&mut self, key: [u8; 32], shape: Arc<DestShape>) {
        self.insert_at(key, Instant::now(), shape);
    }

    fn insert_at(&mut self, key: [u8; 32], at: Instant, shape: Arc<DestShape>) {
        if !self.shapes.contains_key(&key) && self.shapes.len() >= SHAPE_CAP {
            let oldest = self
                .shapes
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(k, _)| *k);
            if let Some(oldest) = oldest {
                self.shapes.remove(&oldest);
            }
        }
        self.shapes.insert(key, (at, shape));
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
    /// Offered cipher suites, as sent (2 bytes each).
    suites: Vec<u8>,
    /// Payload of `supported_groups` (0x000a).
    groups: Vec<u8>,
    /// Payload of `ALPN` (0x0010).
    alpn: Vec<u8>,
    /// Group ids in `key_share` (0x0033), in order.
    share_groups: Vec<u16>,
}

/// A key over the stable fields of a ClientHello: the ones that decide how `dest`
/// answers. Volatile bytes (random, session id, key shares) are not part of it.
fn shape_key(h: &Hello) -> [u8; 32] {
    fn feed(hash: &mut Sha256, bytes: &[u8]) {
        sha2::Digest::update(hash, (bytes.len() as u16).to_be_bytes());
        sha2::Digest::update(hash, bytes);
    }
    /// Feeds a list of u16 codes (cipher suites, groups) without its GREASE entries.
    fn feed_pairs(hash: &mut Sha256, bytes: &[u8]) {
        let kept: Vec<u8> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .filter(|c| !is_grease(u16::from_be_bytes(**c)))
            .flatten()
            .copied()
            .collect();
        feed(hash, &kept);
    }
    let mut hash = Sha256::default();
    let name = h
        .server_name
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    feed(&mut hash, name.as_bytes());
    sha2::Digest::update(&mut hash, [u8::from(h.tls13)]);
    feed_pairs(&mut hash, &h.suites);
    feed_pairs(&mut hash, &h.groups);
    feed(&mut hash, &h.alpn);
    let mut shares = Vec::with_capacity(h.share_groups.len() * 2);
    for group in &h.share_groups {
        shares.extend_from_slice(&group.to_be_bytes());
    }
    feed_pairs(&mut hash, &shares);
    sha2::Digest::finalize(hash).into()
}

/// RFC 8701 GREASE values (`0x?a?a`): a browser sends one at random in every
/// ClientHello and peers ignore it, so it must not change the cache key.
fn is_grease(v: u16) -> bool {
    let (hi, lo) = ((v >> 8) as u8, v as u8);
    hi == lo && (hi & 0x0f) == 0x0a
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
    let suites = r.take(n)?.to_vec(); // cipher suites
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
        suites,
        groups: Vec::new(),
        alpn: Vec::new(),
        share_groups: Vec::new(),
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
            0x000a => hello.groups = d.take(n)?.to_vec(),
            0x0010 => hello.alpn = d.take(n)?.to_vec(),
            0x002b => {
                let n = usize::from(d.u8()?);
                hello.tls13 = d.take(n)?.chunks(2).any(|v| v == [3, 4]);
            }
            0x0033 => {
                let n = d.u16()?;
                let mut shares = Reader(d.take(n)?);
                while !shares.0.is_empty() {
                    let group = u16::try_from(shares.u16()?).ok()?;
                    let n = shares.u16()?;
                    let key = shares.take(n)?;
                    hello.share_groups.push(group);
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

    /// A TLS 1.3 ClientHello handshake message with the fields REALITY reads.
    fn client_hello(
        name: &str,
        suites: &[u8],
        random: [u8; 32],
        session_id: [u8; 32],
        share: [u8; 32],
    ) -> Vec<u8> {
        let name = name.as_bytes();
        let entry_len = name.len() + 3;
        let mut ext = Vec::new();
        // server_name
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&((entry_len + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(entry_len as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        // supported_groups: x25519
        ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
        // ALPN: h2
        ext.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']);
        // supported_versions: TLS 1.3
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        // key_share: x25519
        ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
        ext.extend_from_slice(&share);

        let mut hs = vec![0x01, 0, 0, 0, 0x03, 0x03];
        hs.extend_from_slice(&random);
        hs.push(32);
        hs.extend_from_slice(&session_id);
        hs.extend_from_slice(&(suites.len() as u16).to_be_bytes());
        hs.extend_from_slice(suites);
        hs.extend_from_slice(&[1, 0]);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);
        let body_len = hs.len() - 4;
        hs[1..4].copy_from_slice(&(body_len as u32).to_be_bytes()[1..]);
        hs
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn shape_key_ignores_volatile_bytes() {
        let suites = [0x13, 0x01, 0x13, 0x02];
        let a = client_hello("Example.COM", &suites, [1; 32], [2; 32], [3; 32]);
        let b = client_hello("example.com", &suites, [9; 32], [8; 32], [7; 32]);
        let a = shape_key(&parse_hello(&a).unwrap());
        let b = shape_key(&parse_hello(&b).unwrap());
        // Client random, session id and key share bytes do not matter; the SNI is
        // compared case-insensitively.
        assert_eq!(a, b);

        // A different stable field does change the key.
        let order = [0x13, 0x02, 0x13, 0x01];
        let c = client_hello("example.com", &order, [1; 32], [2; 32], [3; 32]);
        assert_ne!(a, shape_key(&parse_hello(&c).unwrap()));
        let sni = client_hello("other.example", &suites, [1; 32], [2; 32], [3; 32]);
        assert_ne!(a, shape_key(&parse_hello(&sni).unwrap()));

        // A browser sends a random GREASE code in every hello; peers ignore it, so
        // it must not invalidate the cache (measured: Xray/uTLS sends 0xFAFA, 0x5A5A…).
        let grease = |g: [u8; 2]| {
            let suites = [g[0], g[1], 0x13, 0x01, 0x13, 0x02];
            shape_key(&parse_hello(&client_hello("example.com", &suites, [1; 32], [2; 32], [3; 32])).unwrap())
        };
        assert_eq!(grease([0xfa, 0xfa]), grease([0x0a, 0x0a]));
        assert_eq!(grease([0xfa, 0xfa]), a);
    }

    #[test]
    fn grease_values() {
        for g in [0x0a0a, 0x1a1a, 0x2a2a, 0x5a5a, 0xfafa] {
            assert!(is_grease(g), "{g:#06x}");
        }
        for v in [0x1301, 0x001d, 0x11ec, 0x1d1d, 0x0a1a] {
            assert!(!is_grease(v), "{v:#06x}");
        }
    }

    #[test]
    fn shape_cache_ttl_and_cap() {
        let shape = || {
            Arc::new(DestShape {
                group: 0x001d,
                suite: 0x1301,
                records: vec![42],
            })
        };

        let mut cache = ShapeCache::default();
        cache.insert_at([1; 32], Instant::now(), shape());
        assert!(cache.get(&[1; 32]).is_some());
        // An entry older than the TTL is not fresh.
        cache.insert_at(
            [2; 32],
            Instant::now() - SHAPE_TTL - Duration::from_secs(1),
            shape(),
        );
        assert!(cache.get(&[2; 32]).is_none());

        let mut cache = ShapeCache::default();
        let base = Instant::now() - Duration::from_secs(100);
        for i in 0..SHAPE_CAP as u8 {
            cache.insert_at([i; 32], base + Duration::from_secs(u64::from(i)), shape());
        }
        assert_eq!(cache.shapes.len(), SHAPE_CAP);
        let newest = [SHAPE_CAP as u8; 32];
        cache.insert_at(newest, base + Duration::from_secs(100), shape());
        assert_eq!(cache.shapes.len(), SHAPE_CAP);
        // The oldest insertion went, the new one stayed.
        assert!(!cache.shapes.contains_key(&[0; 32]));
        assert!(cache.shapes.contains_key(&newest));
    }

    #[test]
    fn dest_addr_ttl() {
        let mut cache = ShapeCache::default();
        assert!(cache.fresh_dest_addr().is_none());

        let addr = SocketAddr::from(([127, 0, 0, 1], 443));
        cache.set_dest_addrs_at(Instant::now(), vec![addr]);
        assert_eq!(cache.fresh_dest_addr(), Some(addr));

        // Older than the TTL: not used, the next handshake resolves again.
        cache.set_dest_addrs_at(
            Instant::now() - DEST_TTL - Duration::from_secs(1),
            vec![addr],
        );
        assert!(cache.fresh_dest_addr().is_none());

        cache.set_dest_addrs(vec![addr]);
        assert_eq!(cache.fresh_dest_addr(), Some(addr));
        cache.clear_dest_addrs();
        assert!(cache.fresh_dest_addr().is_none());
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
    fn replayed_randoms_are_refused() {
        let mut seen = Seen::default();
        let keep = Duration::from_secs(60);
        assert!(seen.first_time([1; 32], keep));
        assert!(seen.first_time([2; 32], keep));
        assert!(!seen.first_time([1; 32], keep));
        // Past `keep` a random is forgotten (the clock check refuses it by then).
        assert!(seen.first_time([3; 32], Duration::ZERO));
        assert!(seen.first_time([1; 32], keep));
        assert_eq!(seen.order.len(), seen.set.len());
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
