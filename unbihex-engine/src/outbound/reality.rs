//! REALITY client handshake.
//!
//! REALITY is TLS 1.3 where the client proves knowledge of the server's X25519
//! public key inside the ClientHello `session_id`:
//!
//! * `auth_key = HKDF-SHA256(ikm = X25519(client key share secret, server public key),
//!   salt = client_random[..20], info = "REALITY")`, 32 bytes;
//! * `session_id = AES-256-GCM(auth_key, nonce = client_random[20..],
//!   plaintext = ver(3) | 0 | unix_time(be32) | short_id(8),
//!   aad = the ClientHello handshake message with a zeroed session_id)`.
//!
//! The server answers with a throw-away Ed25519 certificate whose signature field is
//! `HMAC-SHA512(auth_key, public key)`; anything else means we reached the real site
//! the server impersonates, and the connection is refused.
//!
//! rustls builds the ClientHello itself, so the hello is built twice with the same
//! randomness and key share: once to learn its bytes, once more with the computed
//! session_id. The provider hooks below are fed through a thread-local because
//! rustls requires `'static` key-exchange and random sources, and the ClientHello is
//! produced synchronously inside `ClientConnection::new`.

use std::cell::RefCell;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
    SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, NamedGroup, SignatureScheme};
use sha2::{Sha256, Sha512};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

use super::tls_stream::TlsRecordStream;
use crate::config::RealityConfig;
use crate::error::{Error, Result};

/// Client version reported inside the session_id (Xray 26.3.27).
const VERSION: [u8; 3] = [26, 3, 27];
/// ClientHello offset of the session_id: handshake header 4 + version 2 + random 32 + length 1.
const SID_OFFSET: usize = 39;

/// A REALITY client for one server.
#[derive(Clone)]
pub struct RealityClient {
    server_public: [u8; 32],
    short_id: [u8; 8],
    server_name: ServerName<'static>,
    alpn: Vec<Vec<u8>>,
}

impl std::fmt::Debug for RealityClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityClient")
            .field("server_name", &self.server_name)
            .finish()
    }
}

/// What the provider hooks use while one ClientHello is being built.
#[derive(Default)]
struct HelloState {
    /// Our X25519 secret (TLS key share and REALITY auth key).
    secret: Option<[u8; 32]>,
    /// Randomness handed out so far (first pass) or to hand out (second pass).
    fills: Vec<Vec<u8>>,
    /// Second pass: next fill to replay.
    replay_pos: Option<usize>,
}

thread_local! {
    static HELLO: RefCell<HelloState> = RefCell::new(HelloState::default());
}

#[derive(Debug)]
struct HookedRandom;

static HOOKED_RANDOM: HookedRandom = HookedRandom;

impl SecureRandom for HookedRandom {
    fn fill(&self, buf: &mut [u8]) -> std::result::Result<(), GetRandomFailed> {
        HELLO.with(|h| {
            let mut h = h.borrow_mut();
            if let Some(pos) = h.replay_pos {
                if let Some(prev) = h.fills.get(pos)
                    && prev.len() == buf.len()
                {
                    buf.copy_from_slice(prev);
                    h.replay_pos = Some(pos + 1);
                    return Ok(());
                }
                h.replay_pos = None;
            } else if h.secret.is_some() {
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, buf);
                h.fills.push(buf.to_vec());
                return Ok(());
            }
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, buf);
            Ok(())
        })
    }
}

#[derive(Debug)]
struct HookedX25519;

static HOOKED_X25519: HookedX25519 = HookedX25519;

struct X25519Exchange {
    secret: StaticSecret,
    public: [u8; 32],
}

impl SupportedKxGroup for HookedX25519 {
    fn start(&self) -> std::result::Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let bytes = HELLO
            .with(|h| h.borrow().secret)
            .ok_or_else(|| rustls::Error::General("reality: no key share prepared".into()))?;
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Box::new(X25519Exchange { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for X25519Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> std::result::Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::General("reality: bad server key share".into()))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(rustls::Error::General("reality: weak server key share".into()));
        }
        Ok(SharedSecret::from(shared.as_bytes().to_vec()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// Accepts only the REALITY temporary certificate signed for our auth key.
#[derive(Debug)]
struct RealityVerifier {
    auth_key: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

/// Finds the Ed25519 public key (SubjectPublicKeyInfo) and the signature value in a
/// DER certificate.
fn ed25519_key_and_signature(der: &[u8]) -> Option<([u8; 32], [u8; 64])> {
    // AlgorithmIdentifier { 1.3.101.112 } followed by BIT STRING (33 bytes, 0 unused bits).
    const KEY_PREFIX: [u8; 12] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0, 0];
    let pos = der
        .windows(10)
        .position(|w| w == &KEY_PREFIX[..10])?;
    let key: [u8; 32] = der.get(pos + 10..pos + 42)?.try_into().ok()?;
    // The certificate ends with the signature BIT STRING: 03 41 00 + 64 bytes.
    if der.len() < 67 || der[der.len() - 67..der.len() - 64] != [0x03, 0x41, 0x00] {
        return None;
    }
    let sig: [u8; 64] = der[der.len() - 64..].try_into().ok()?;
    Some((key, sig))
}

impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fail = || {
            rustls::Error::General(
                "REALITY: the server did not prove the key (wrong pbk/sid, or the request reached the real site)"
                    .into(),
            )
        };
        let (key, sig) = ed25519_key_and_signature(end_entity.as_ref()).ok_or_else(fail)?;
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&self.auth_key).map_err(|_| fail())?;
        mac.update(&key);
        mac.verify_slice(&sig).map_err(|_| fail())?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("REALITY requires TLS 1.3".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Rejects everything; used for the first, never-sent ClientHello.
#[derive(Debug)]
struct NoVerifier(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Err(rustls::Error::General("probe connection".into()))
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("probe connection".into()))
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("probe connection".into()))
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

fn provider() -> CryptoProvider {
    let mut p = rustls::crypto::ring::default_provider();
    p.kx_groups = vec![&HOOKED_X25519];
    p.secure_random = &HOOKED_RANDOM;
    p
}

fn client_config(
    verifier: Arc<dyn ServerCertVerifier>,
    alpn: &[Vec<u8>],
) -> Result<Arc<ClientConfig>> {
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::disabled();
    cfg.alpn_protocols = alpn.to_vec();
    Ok(Arc::new(cfg))
}

/// The ClientHello handshake message (without the record header) queued in `conn`.
fn take_hello(conn: &mut ClientConnection) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out)
            .map_err(|e| Error::Tls(e.to_string()))?;
    }
    // One handshake record: 16 03 01 len(2) | ClientHello.
    if out.len() < 5 + SID_OFFSET + 32 || out[0] != 0x16 {
        return Err(Error::Tls("reality: unexpected ClientHello layout".into()));
    }
    let len = usize::from(u16::from_be_bytes([out[3], out[4]]));
    let hello = out
        .get(5..5 + len)
        .ok_or_else(|| Error::Tls("reality: ClientHello split across records".into()))?
        .to_vec();
    if hello[0] != 0x01 || hello[SID_OFFSET - 1] != 32 {
        return Err(Error::Tls("reality: ClientHello without a 32-byte session_id".into()));
    }
    Ok(hello)
}

/// Builds a ClientConnection inside a prepared thread-local state.
fn with_state<T>(state: HelloState, f: impl FnOnce() -> T) -> (T, HelloState) {
    HELLO.with(|h| *h.borrow_mut() = state);
    let r = f();
    let state = HELLO.with(|h| std::mem::take(&mut *h.borrow_mut()));
    (r, state)
}

impl RealityClient {
    /// Validates the settings.
    pub fn new(cfg: &RealityConfig) -> Result<Self> {
        let server_name = ServerName::try_from(cfg.server_name.clone())
            .map_err(|_| Error::config(format!("reality: invalid server name {:?}", cfg.server_name)))?;
        let alpn = if cfg.alpn.is_empty() {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            cfg.alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
        };
        Ok(RealityClient {
            server_public: cfg.public_key_bytes()?,
            short_id: cfg.short_id_bytes()?,
            server_name,
            alpn,
        })
    }

    /// Builds the connection and the ClientHello record (with the REALITY session_id)
    /// that must be sent first.
    fn prepare_with_bytes(&self) -> Result<PreparedHello> {
        let algs = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
        let shared = StaticSecret::from(secret).diffie_hellman(&PublicKey::from(self.server_public));
        if !shared.was_contributory() {
            return Err(Error::config("reality: invalid public key"));
        }

        // Pass 1: learn the exact ClientHello.
        let probe_cfg = client_config(Arc::new(NoVerifier(algs)), &self.alpn)?;
        let (conn, state) = with_state(
            HelloState {
                secret: Some(secret),
                ..Default::default()
            },
            || ClientConnection::new(probe_cfg, self.server_name.clone()),
        );
        let mut probe = conn.map_err(|e| Error::Tls(e.to_string()))?;
        let mut aad = take_hello(&mut probe)?;
        drop(probe);
        let random: [u8; 32] = aad[6..38]
            .try_into()
            .map_err(|_| Error::Tls("reality: bad ClientHello".into()))?;
        let probe_sid = aad[SID_OFFSET..SID_OFFSET + 32].to_vec();
        aad[SID_OFFSET..SID_OFFSET + 32].fill(0);

        // auth_key and the encrypted session_id.
        let mut auth_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&random[..20]), shared.as_bytes())
            .expand(b"REALITY", &mut auth_key)
            .map_err(|_| Error::Tls("reality: hkdf".into()))?;
        let mut plain = [0u8; 16];
        plain[..3].copy_from_slice(&VERSION);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        plain[4..8].copy_from_slice(&now.to_be_bytes());
        plain[8..16].copy_from_slice(&self.short_id);
        let sealed = Aes256Gcm::new_from_slice(&auth_key)
            .map_err(|_| Error::Tls("reality: aes key".into()))?
            .encrypt(
                Nonce::from_slice(&random[20..32]),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Tls("reality: seal".into()))?;

        // Pass 2: same randomness, but the session_id is ours.
        let mut fills = state.fills;
        let slot = fills
            .iter()
            .position(|f| f.as_slice() == probe_sid.as_slice())
            .ok_or_else(|| Error::Tls("reality: cannot locate the session_id source".into()))?;
        fills[slot] = sealed.clone();
        let verifier = Arc::new(RealityVerifier { auth_key, algs });
        let cfg = client_config(verifier, &self.alpn)?;
        let (conn, _) = with_state(
            HelloState {
                secret: Some(secret),
                fills,
                replay_pos: Some(0),
            },
            || ClientConnection::new(cfg, self.server_name.clone()),
        );
        let mut conn = conn.map_err(|e| Error::Tls(e.to_string()))?;

        // The second hello must be the first one with our session_id.
        let mut check = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut check)
                .map_err(|e| Error::Tls(e.to_string()))?;
        }
        let mut expected = aad;
        expected[SID_OFFSET..SID_OFFSET + 32].copy_from_slice(&sealed);
        if check.get(5..) != Some(expected.as_slice()) {
            return Err(Error::Tls("reality: ClientHello is not reproducible".into()));
        }
        Ok(PreparedHello { conn, hello: check })
    }

    /// Runs the REALITY handshake over `tcp`.
    pub async fn connect(
        &self,
        tcp: TcpStream,
        fragment: Option<&super::fragment::FragmentConfig>,
    ) -> Result<TlsRecordStream> {
        let prepared = self.prepare_with_bytes()?;
        let mut tcp = tcp;
        match fragment {
            Some(f) => f.send(&mut tcp, &prepared.hello).await?,
            None => tokio::io::AsyncWriteExt::write_all(&mut tcp, &prepared.hello).await?,
        }
        let mut s = TlsRecordStream::new(tcp, prepared.conn);
        s.handshake().await?;
        Ok(s)
    }
}

struct PreparedHello {
    conn: ClientConnection,
    /// The ClientHello TLS record.
    hello: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_is_reproducible_and_sealed() {
        let server = StaticSecret::from([7u8; 32]);
        let cfg = RealityConfig {
            server_name: "www.example.com".into(),
            public_key: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                PublicKey::from(&server).as_bytes(),
            ),
            short_id: "0123abcd".into(),
            alpn: Vec::new(),
        };
        let client = RealityClient::new(&cfg).unwrap();
        let prepared = client.prepare_with_bytes().unwrap();
        let hello = &prepared.hello[5..];
        let random: [u8; 32] = hello[6..38].try_into().unwrap();
        // Server side: recover the client's key share and open the session_id.
        let ks_pos = hello
            .windows(4)
            .position(|w| w == [0x00, 0x1d, 0x00, 0x20])
            .unwrap();
        let client_pub: [u8; 32] = hello[ks_pos + 4..ks_pos + 36].try_into().unwrap();
        let shared = server.diffie_hellman(&PublicKey::from(client_pub));
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&random[..20]), shared.as_bytes())
            .expand(b"REALITY", &mut key)
            .unwrap();
        let mut aad = hello.to_vec();
        aad[SID_OFFSET..SID_OFFSET + 32].fill(0);
        let plain = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&random[20..]),
                Payload {
                    msg: &hello[SID_OFFSET..SID_OFFSET + 32],
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(&plain[..3], &VERSION);
        assert_eq!(&plain[8..12], &[0x01, 0x23, 0xab, 0xcd]);
        assert_eq!(&plain[12..16], &[0, 0, 0, 0]);
    }

    #[test]
    fn certificate_check() {
        let auth_key = [3u8; 32];
        let key = [9u8; 32];
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&auth_key).unwrap();
        mac.update(&key);
        let sig = mac.finalize().into_bytes();
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
        der.extend_from_slice(&key);
        der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00]);
        der.extend_from_slice(&sig);
        let (k, s) = ed25519_key_and_signature(&der).unwrap();
        assert_eq!(k, key);
        assert_eq!(&s[..], &sig[..]);
        let v = RealityVerifier {
            auth_key,
            algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        };
        let name = ServerName::try_from("a.com").unwrap();
        assert!(
            v.verify_server_cert(&CertificateDer::from(der.clone()), &[], &name, &[], UnixTime::now())
                .is_ok()
        );
        *der.last_mut().unwrap() ^= 1;
        assert!(
            v.verify_server_cert(&CertificateDer::from(der), &[], &name, &[], UnixTime::now())
                .is_err()
        );
    }
}
