//! Browser TLS fingerprints.
//!
//! rustls's ClientHello is easy to tell from a browser's (JA3/JA4: no GREASE, its own
//! cipher, group and extension sets), and DPI can block by it. The patched rustls
//! (`vendor/rustls`) hands us its encoded ClientHello before hashing and sending it; we
//! rebuild it as Chrome's and keep everything rustls's state depends on: the random, the
//! session id (REALITY's token), SNI, ALPN, key shares, a HelloRetryRequest cookie.
//!
//! Chrome 13x (BoringSSL): GREASE cipher, group, version and extension values; its cipher
//! suites, including TLS 1.2 CBC ones (servers we talk to never pick them; one that did
//! would fail the handshake, not downgrade it); extensions shuffled per connection between
//! a leading and a trailing GREASE extension; X25519MLKEM768 and X25519 key shares;
//! GREASE ECH; ALPS. signature_algorithms as Chrome 152: a GREASE value, ML-DSA, then
//! the classical eight (rustls verifies only those, and servers with ML-DSA certificates
//! are not ones we talk to). JA4: `t13d1516h2_8daaf6152771_806a8c22fdea`, as Chromium 152.
//!
//! The per-connection randomness is derived from the ClientHello random, so a retried
//! hello and REALITY's second pass rebuild the same bytes.

use std::sync::Arc;

use rustls::client::{ClientHelloRewriter, RewrittenHello};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use sha2::{Digest, Sha256};

use super::pq::X25519_MLKEM768;

/// A browser whose ClientHello we send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fingerprint {
    /// Chrome (also Edge and other Chromium browsers).
    Chrome,
}

impl Fingerprint {
    /// From the `fp` value of a link or config. Every browser name maps to Chrome until
    /// more templates exist; `none` keeps rustls's own ClientHello.
    pub fn from_name(name: Option<&str>) -> Option<Fingerprint> {
        match name.map(|n| n.trim().to_ascii_lowercase()).as_deref() {
            Some("none") | Some("rustls") => None,
            _ => Some(Fingerprint::Chrome),
        }
    }

    /// Key exchange groups in Chrome's order, for a provider whose ClientHello will be
    /// rewritten: X25519MLKEM768 first (its X25519 half is also sent on its own), then the
    /// classic curves a HelloRetryRequest may ask for.
    pub fn kx_groups(self) -> Vec<&'static dyn SupportedKxGroup> {
        vec![
            &X25519_MLKEM768,
            rustls::crypto::ring::kx_group::X25519,
            rustls::crypto::ring::kx_group::SECP256R1,
            rustls::crypto::ring::kx_group::SECP384R1,
        ]
    }

    /// The ring provider with Chrome's groups and cipher suite order.
    pub fn provider(self) -> CryptoProvider {
        let mut p = rustls::crypto::ring::default_provider();
        p.kx_groups = self.kx_groups();
        p.cipher_suites.sort_by_key(|s| {
            let id = u16::from(s.suite());
            CHROME_SUITES.iter().position(|&c| c == id).unwrap_or(usize::MAX)
        });
        p
    }

    /// The rewriter to install as `ClientConfig::client_hello_rewriter`.
    pub fn rewriter(self) -> Arc<dyn ClientHelloRewriter> {
        Arc::new(ChromeHello)
    }
}

const CHROME_SUITES: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
const CHROME_GROUPS: [u16; 4] = [0x11ec, 0x001d, 0x0017, 0x0018];
/// After a GREASE value: ML-DSA-44/65/87, then the classical schemes.
const CHROME_SIGALGS: [u16; 11] = [
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

const SERVER_NAME: u16 = 0;
const STATUS_REQUEST: u16 = 5;
const SUPPORTED_GROUPS: u16 = 10;
const EC_POINT_FORMATS: u16 = 11;
const SIGNATURE_ALGORITHMS: u16 = 13;
const ALPN: u16 = 16;
const SCT: u16 = 18;
const PADDING: u16 = 21;
const EXTENDED_MASTER_SECRET: u16 = 23;
const COMPRESS_CERTIFICATE: u16 = 27;
const SESSION_TICKET: u16 = 35;
const PRE_SHARED_KEY: u16 = 41;
const EARLY_DATA: u16 = 42;
const SUPPORTED_VERSIONS: u16 = 43;
const PSK_KEY_EXCHANGE_MODES: u16 = 45;
const KEY_SHARE: u16 = 51;
const ALPS: u16 = 0x44cd;
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const RENEGOTIATION_INFO: u16 = 0xff01;

/// Rebuilds rustls's ClientHello as Chrome's.
#[derive(Debug)]
struct ChromeHello;

impl ClientHelloRewriter for ChromeHello {
    fn rewrite(&self, hello: &[u8]) -> Option<RewrittenHello> {
        let parsed = ParsedHello::parse(hello)?;
        let message = chrome(&parsed)?;
        let added_extensions = ParsedHello::parse(&message)?
            .extensions
            .iter()
            .map(|(t, _)| *t)
            .filter(|t| parsed.ext(*t).is_none())
            .collect();
        Some(RewrittenHello {
            message,
            added_extensions,
        })
    }
}

/// The fields of a ClientHello handshake message we need.
struct ParsedHello<'a> {
    random: &'a [u8],
    session_id: &'a [u8],
    cipher_suites: Vec<u16>,
    extensions: Vec<(u16, &'a [u8])>,
}

impl<'a> ParsedHello<'a> {
    fn parse(msg: &'a [u8]) -> Option<ParsedHello<'a>> {
        let mut r = Reader(msg);
        if r.u8()? != 1 || r.u24()? != r.0.len() {
            return None;
        }
        r.u16()?;
        let random = r.take(32)?;
        let session_id = r.vec8()?;
        let mut suites = Reader(r.vec16()?);
        let mut cipher_suites = Vec::new();
        while !suites.0.is_empty() {
            cipher_suites.push(suites.u16()?);
        }
        r.vec8()?;
        let mut exts = Reader(r.vec16()?);
        if !r.0.is_empty() {
            return None;
        }
        let mut extensions = Vec::new();
        while !exts.0.is_empty() {
            extensions.push((exts.u16()?, exts.vec16()?));
        }
        Some(ParsedHello {
            random,
            session_id,
            cipher_suites,
            extensions,
        })
    }

    fn ext(&self, typ: u16) -> Option<&'a [u8]> {
        self.extensions.iter().find(|(t, _)| *t == typ).map(|(_, d)| *d)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

/// Deterministic per-hello randomness: SHA-256 of the ClientHello random in counter mode.
struct HelloRng {
    seed: [u8; 32],
    block: [u8; 32],
    pos: usize,
    counter: u32,
}

impl HelloRng {
    fn new(random: &[u8]) -> HelloRng {
        let mut h = Sha256::new();
        h.update(b"unbihex/fingerprint/chrome");
        h.update(random);
        HelloRng {
            seed: h.finalize().into(),
            block: [0; 32],
            pos: 32,
            counter: 0,
        }
    }

    fn u8(&mut self) -> u8 {
        if self.pos == 32 {
            let mut h = Sha256::new();
            h.update(self.seed);
            h.update(self.counter.to_be_bytes());
            self.block = h.finalize().into();
            self.counter += 1;
            self.pos = 0;
        }
        self.pos += 1;
        self.block[self.pos - 1]
    }

    fn below(&mut self, n: usize) -> usize {
        let v = u32::from_be_bytes([self.u8(), self.u8(), self.u8(), self.u8()]);
        v as usize % n
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.u8();
        }
    }

    /// A GREASE value (RFC 8701): 0x?A?A.
    fn grease(&mut self) -> u16 {
        let n = (self.u8() & 0xf0) | 0x0a;
        u16::from_be_bytes([n, n])
    }
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_vec16(out: &mut Vec<u8>, data: &[u8]) {
    put_u16(out, data.len() as u16);
    out.extend_from_slice(data);
}

fn u16_list(values: &[u16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(values.len() * 2);
    for &x in values {
        put_u16(&mut v, x);
    }
    v
}

/// Whether an ALPN extension offers h2.
fn offers_h2(alpn: &[u8]) -> bool {
    let mut r = Reader(alpn);
    let Some(list) = r.vec16() else {
        return false;
    };
    let mut l = Reader(list);
    while let Some(name) = l.vec8() {
        if name == b"h2" {
            return true;
        }
    }
    false
}

/// Chrome's key_share: a one-byte GREASE share, then rustls's shares unchanged.
fn key_share(rustls_ks: &[u8], grease: u16) -> Option<Vec<u8>> {
    let entries = Reader(rustls_ks).vec16()?;
    let mut list = Vec::with_capacity(entries.len() + 5);
    put_u16(&mut list, grease);
    put_vec16(&mut list, &[0]);
    list.extend_from_slice(entries);
    let mut out = Vec::with_capacity(list.len() + 2);
    put_vec16(&mut out, &list);
    Some(out)
}

/// A GREASE ECH extension (draft-ietf-tls-esni): outer hello, HKDF-SHA256 and
/// AES-128-GCM, a random config id, a random 32-byte "encapsulated key" and payload.
fn grease_ech(rng: &mut HelloRng) -> Vec<u8> {
    let mut out = vec![0, 0x00, 0x01, 0x00, 0x01, rng.u8()];
    let mut enc = [0u8; 32];
    rng.fill(&mut enc);
    put_vec16(&mut out, &enc);
    let mut payload = vec![0u8; [144, 176, 208, 240][rng.below(4)]];
    rng.fill(&mut payload);
    put_vec16(&mut out, &payload);
    out
}

fn chrome(h: &ParsedHello<'_>) -> Option<Vec<u8>> {
    // PSK binders and early data are computed over rustls's own bytes.
    if h.ext(PRE_SHARED_KEY).is_some() || h.ext(EARLY_DATA).is_some() {
        return None;
    }
    let rustls_key_share = h.ext(KEY_SHARE)?;
    let mut rng = HelloRng::new(h.random);
    let grease_suite = rng.grease();
    let grease_group = rng.grease();
    let grease_version = rng.grease();
    let grease_first = rng.grease();
    let mut grease_last = rng.grease();
    if grease_last == grease_first {
        grease_last ^= 0x1010;
    }

    let alpn = h.ext(ALPN);
    let mut middle: Vec<(u16, Vec<u8>)> = Vec::new();
    if let Some(sni) = h.ext(SERVER_NAME) {
        middle.push((SERVER_NAME, sni.to_vec()));
    }
    middle.push((EXTENDED_MASTER_SECRET, Vec::new()));
    middle.push((RENEGOTIATION_INFO, vec![0]));
    let mut groups = vec![grease_group];
    groups.extend_from_slice(&CHROME_GROUPS);
    let mut groups_ext = Vec::new();
    put_vec16(&mut groups_ext, &u16_list(&groups));
    middle.push((SUPPORTED_GROUPS, groups_ext));
    middle.push((EC_POINT_FORMATS, vec![1, 0]));
    middle.push((SESSION_TICKET, h.ext(SESSION_TICKET).unwrap_or(&[]).to_vec()));
    if let Some(a) = alpn {
        middle.push((ALPN, a.to_vec()));
    }
    middle.push((STATUS_REQUEST, vec![1, 0, 0, 0, 0]));
    let mut sigalgs = Vec::new();
    let mut schemes = vec![rng.grease()];
    schemes.extend_from_slice(&CHROME_SIGALGS);
    put_vec16(&mut sigalgs, &u16_list(&schemes));
    middle.push((SIGNATURE_ALGORITHMS, sigalgs));
    middle.push((SCT, Vec::new()));
    middle.push((KEY_SHARE, key_share(rustls_key_share, grease_group)?));
    middle.push((PSK_KEY_EXCHANGE_MODES, vec![1, 1]));
    let versions = u16_list(&[grease_version, 0x0304, 0x0303]);
    let mut versions_ext = vec![versions.len() as u8];
    versions_ext.extend_from_slice(&versions);
    middle.push((SUPPORTED_VERSIONS, versions_ext));
    middle.push((COMPRESS_CERTIFICATE, vec![2, 0, 2]));
    if alpn.is_some_and(offers_h2) {
        middle.push((ALPS, vec![0, 3, 2, b'h', b'2']));
    }
    middle.push((ENCRYPTED_CLIENT_HELLO, grease_ech(&mut rng)));
    // rustls extensions Chrome has no slot for (a HelloRetryRequest cookie…) stay.
    for (t, d) in &h.extensions {
        if !middle.iter().any(|(m, _)| m == t) {
            middle.push((*t, d.to_vec()));
        }
    }
    for i in (1..middle.len()).rev() {
        middle.swap(i, rng.below(i + 1));
    }

    let mut exts: Vec<(u16, Vec<u8>)> = vec![(grease_first, Vec::new())];
    exts.extend(middle);
    exts.push((grease_last, vec![0]));

    let mut suites = vec![grease_suite];
    suites.extend_from_slice(&CHROME_SUITES);
    let encode = |exts: &[(u16, Vec<u8>)]| {
        let mut ext_bytes = Vec::new();
        for (t, d) in exts {
            put_u16(&mut ext_bytes, *t);
            put_vec16(&mut ext_bytes, d);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(h.random);
        body.push(h.session_id.len() as u8);
        body.extend_from_slice(h.session_id);
        put_vec16(&mut body, &u16_list(&suites));
        body.extend_from_slice(&[1, 0]);
        put_vec16(&mut body, &ext_bytes);
        body
    };
    let mut body = encode(&exts);
    // BoringSSL pads a hello of 256..511 bytes to 512 (some middleboxes choke on those sizes).
    let len = body.len() + 4;
    if (0x100..0x200).contains(&len) {
        let pad = (0x200 - len).saturating_sub(4).max(1);
        exts.push((PADDING, vec![0; pad]));
        body = encode(&exts);
    }
    let mut msg = vec![1];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    // Every suite rustls offered is still offered, so the server cannot pick one rustls
    // expects and we hid (the renegotiation SCSV is replaced by renegotiation_info).
    debug_assert!(
        h.cipher_suites
            .iter()
            .all(|c| CHROME_SUITES.contains(c) || *c == 0x00ff)
    );
    Some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

    fn is_grease(v: u16) -> bool {
        v & 0x0f0f == 0x0a0a && v >> 12 == (v >> 4) & 0xf
    }

    /// JA4 (https://github.com/FoxIO-LLC/ja4) of a ClientHello message.
    fn ja4(hello: &[u8]) -> String {
        let h = ParsedHello::parse(hello).unwrap();
        let suites: Vec<u16> = h.cipher_suites.iter().copied().filter(|c| !is_grease(*c)).collect();
        let exts: Vec<u16> = h.extensions.iter().map(|(t, _)| *t).filter(|t| !is_grease(*t)).collect();
        let alpn = h
            .ext(ALPN)
            .and_then(|a| Reader(Reader(a).vec16()?).vec8().map(|n| n.to_vec()))
            .map(|n| format!("{}{}", n[0] as char, n[n.len() - 1] as char))
            .unwrap_or_else(|| "00".into());
        let a = format!(
            "t13{}{:02}{:02}{alpn}",
            if h.ext(SERVER_NAME).is_some() { "d" } else { "i" },
            suites.len(),
            exts.len()
        );
        let hex = |v: &[u16]| v.iter().map(|x| format!("{x:04x}")).collect::<Vec<_>>().join(",");
        let short = |s: String| hex::encode(Sha256::digest(s.as_bytes()))[..12].to_string();
        let mut sorted_suites = suites.clone();
        sorted_suites.sort();
        let mut sorted_exts: Vec<u16> = exts.into_iter().filter(|t| *t != SERVER_NAME && *t != ALPN).collect();
        sorted_exts.sort();
        let sigs = Reader(h.ext(SIGNATURE_ALGORITHMS).unwrap()).vec16().unwrap();
        let sigs: Vec<u16> =
            sigs.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).filter(|s| !is_grease(*s)).collect();
        format!(
            "{a}_{}_{}",
            short(hex(&sorted_suites)),
            short(format!("{}_{}", hex(&sorted_exts), hex(&sigs)))
        )
    }

    fn client_config(fp: Fingerprint, roots: RootCertStore) -> ClientConfig {
        let mut cfg = ClientConfig::builder_with_provider(Arc::new(fp.provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        cfg.client_hello_rewriter = Some(fp.rewriter());
        cfg.resumption = rustls::client::Resumption::disabled();
        cfg
    }

    fn first_hello(cfg: ClientConfig) -> Vec<u8> {
        let mut conn = ClientConnection::new(Arc::new(cfg), ServerName::try_from("example.com").unwrap()).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        assert_eq!(out[0], 0x16);
        out[5..].to_vec()
    }

    #[test]
    fn chrome_hello_has_chrome_shape() {
        let hello = first_hello(client_config(Fingerprint::Chrome, RootCertStore::empty()));
        let print = ja4(&hello);
        // Chromium 152.0.7977.167, recorded on the wire.
        assert_eq!(print, "t13d1516h2_8daaf6152771_806a8c22fdea");
        let h = ParsedHello::parse(&hello).unwrap();
        assert!(is_grease(h.cipher_suites[0]));
        assert!(is_grease(h.extensions[0].0) && h.extensions[0].1.is_empty());
        let last = h.extensions.last().unwrap();
        assert!(is_grease(last.0) && last.1 == [0]);
        assert_eq!(h.session_id.len(), 32);
        // GREASE share, X25519MLKEM768 (1216 B), then X25519 (32 B).
        let mut ks = Reader(Reader(h.ext(KEY_SHARE).unwrap()).vec16().unwrap());
        assert!(is_grease(ks.u16().unwrap()));
        assert_eq!(ks.vec16().unwrap(), [0]);
        assert_eq!((ks.u16().unwrap(), ks.vec16().unwrap().len()), (0x11ec, 1216));
        assert_eq!((ks.u16().unwrap(), ks.vec16().unwrap().len()), (0x001d, 32));
        for t in [ALPS, ENCRYPTED_CLIENT_HELLO, SCT, RENEGOTIATION_INFO, COMPRESS_CERTIFICATE] {
            assert!(h.ext(t).is_some(), "missing {t:#x}");
        }
    }

    #[test]
    fn extensions_are_shuffled_per_connection_but_stable_per_hello() {
        let order = |hello: &[u8]| -> Vec<u16> {
            ParsedHello::parse(hello).unwrap().extensions.iter().map(|(t, _)| *t).filter(|t| !is_grease(*t)).collect()
        };
        let orders: Vec<Vec<u16>> = (0..8)
            .map(|_| order(&first_hello(client_config(Fingerprint::Chrome, RootCertStore::empty()))))
            .collect();
        assert!(orders.iter().any(|o| *o != orders[0]), "the order never changes");
        // The same rustls hello always becomes the same bytes (HelloRetryRequest, REALITY).
        let mut plain = client_config(Fingerprint::Chrome, RootCertStore::empty());
        plain.client_hello_rewriter = None;
        let rustls_hello = first_hello(plain);
        let h = ParsedHello::parse(&rustls_hello).unwrap();
        assert!(chrome(&h).is_some());
        assert_eq!(chrome(&h), chrome(&h));
    }

    #[test]
    fn none_keeps_rustls_hello() {
        assert_eq!(Fingerprint::from_name(Some("none")), None);
        assert_eq!(Fingerprint::from_name(Some("firefox")), Some(Fingerprint::Chrome));
        assert_eq!(Fingerprint::from_name(None), Some(Fingerprint::Chrome));
    }

    /// A Chrome-fingerprinted client that accepts the in-memory test server's certificate
    /// (signatures are still checked).
    fn test_client() -> ClientConfig {
        #[derive(Debug)]
        struct AnyCert(rustls::crypto::WebPkiSupportedAlgorithms);
        impl rustls::client::danger::ServerCertVerifier for AnyCert {
            fn verify_server_cert(
                &self,
                _: &CertificateDer<'_>,
                _: &[CertificateDer<'_>],
                _: &ServerName<'_>,
                _: &[u8],
                _: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                m: &[u8],
                c: &CertificateDer<'_>,
                d: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                rustls::crypto::verify_tls12_signature(m, c, d, &self.0)
            }
            fn verify_tls13_signature(
                &self,
                m: &[u8],
                c: &CertificateDer<'_>,
                d: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                rustls::crypto::verify_tls13_signature(m, c, d, &self.0)
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.0.supported_schemes()
            }
        }
        let fp = Fingerprint::Chrome;
        let provider = fp.provider();
        let algs = provider.signature_verification_algorithms;
        let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(algs)))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        cfg.client_hello_rewriter = Some(fp.rewriter());
        cfg.resumption = rustls::client::Resumption::disabled();
        cfg
    }

    /// Runs a Chrome-fingerprinted handshake against an in-memory rustls server with
    /// `server_groups`, sends data through it, and returns the group the server chose.
    fn handshake(server_groups: Vec<&'static dyn SupportedKxGroup>) -> rustls::NamedGroup {
        use std::io::{Read, Write};
        let cert = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups = server_groups;
        let mut server_cfg = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert.cert.der().to_vec())], key)
            .unwrap();
        server_cfg.alpn_protocols = vec![b"h2".to_vec()];
        let name = ServerName::try_from("example.com").unwrap();
        let mut c = ClientConnection::new(Arc::new(test_client()), name).unwrap();
        let mut s = ServerConnection::new(Arc::new(server_cfg)).unwrap();
        for _ in 0..10 {
            let mut buf = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut buf).unwrap();
            }
            s.read_tls(&mut buf.as_slice()).unwrap();
            s.process_new_packets().unwrap();
            let mut buf = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut buf).unwrap();
            }
            c.read_tls(&mut buf.as_slice()).unwrap();
            c.process_new_packets().unwrap();
            if !c.is_handshaking() && !s.is_handshaking() {
                break;
            }
        }
        assert!(!c.is_handshaking(), "client did not finish");
        assert_eq!(c.alpn_protocol(), Some(&b"h2"[..]));
        c.writer().write_all(b"ping").unwrap();
        let mut buf = Vec::new();
        c.write_tls(&mut buf).unwrap();
        s.read_tls(&mut buf.as_slice()).unwrap();
        s.process_new_packets().unwrap();
        let mut got = [0u8; 4];
        s.reader().read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");
        s.negotiated_key_exchange_group().unwrap().name()
    }

    #[test]
    fn handshake_with_the_chrome_hello() {
        let group = handshake(vec![&X25519_MLKEM768, rustls::crypto::ring::kx_group::X25519]);
        assert_eq!(group, rustls::NamedGroup::X25519MLKEM768);
        // A server without ML-KEM completes on the separate X25519 share, no retry.
        let group = handshake(vec![rustls::crypto::ring::kx_group::X25519]);
        assert_eq!(group, rustls::NamedGroup::X25519);
        // A server with P-256 only asks for it with a HelloRetryRequest.
        let group = handshake(vec![rustls::crypto::ring::kx_group::SECP256R1]);
        assert_eq!(group, rustls::NamedGroup::secp256r1);
    }
}
