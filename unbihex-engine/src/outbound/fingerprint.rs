//! Browser TLS fingerprints.
//!
//! rustls's ClientHello is easy to tell from a browser's (JA3/JA4: no GREASE, its own
//! cipher, group and extension sets), and DPI can block by it. The patched rustls
//! (`vendor/rustls`) hands us its encoded ClientHello before hashing and sending it; we
//! rebuild it as the profile's and keep everything rustls's state depends on: the
//! random, the session id (REALITY's token), SNI, ALPN, key shares, a HelloRetryRequest
//! cookie.
//!
//! Every profile is one row of [`Profile`]: cipher suites, groups, signature algorithms,
//! extension order, ALPN, key-share mode and the flags (GREASE, shuffling, padding,
//! delegated credentials, record_size_limit, ALPS) its uTLS preset sends. Chrome's
//! output is the same as before the table: GREASE cipher/group/version/extension values,
//! its 15 cipher suites, a per-connection shuffle between a leading and a trailing
//! GREASE extension, X25519MLKEM768 and X25519 key shares and ALPS. It deliberately does
//! not send Chrome's GREASE ECH: rustls treats the server's ECH ack as unsolicited and
//! drops the connection, so JA4 is `t13d1515h2_8daaf6152771_eac8ad812b09` (one extension
//! short of Chromium 152's `...1516...806a8c22fdea`). Firefox 120+ (NSS) has no GREASE,
//! its own order, an X25519-only key share and delegated_credentials; the lists follow
//! utls's `HelloFirefox_120`.
//!
//! The other rows mirror utls's presets (`u_parrots.go`): `HelloSafari_26_3`,
//! `HelloIOS_14` (`HelloIOS_Auto`), `HelloAndroid_11_OkHttp`, `HelloEdge_85`
//! (`HelloEdge_Auto`), `Hello360_11_0`, `HelloQQ_11_1`. Where a preset advertises
//! something rustls has no provider for (P-521, FFDHE, CBC suites) only the
//! advertisement is mirrored; the key shares stay on groups rustls (and REALITY) really
//! supports. `random`/`randomized` build a randomized spec on the same lists, as utls's
//! randomized parrot does: `randomized` mixes per connection from the hello random,
//! `random` uses one fixed seed so it is stable within a process (Xray picks one modern
//! preset per process for `random`).

use std::sync::Arc;

use rustls::client::{ClientHelloRewriter, RewrittenHello};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use sha2::{Digest, Sha256};

use super::pq::X25519_MLKEM768;
use crate::error::{Error, Result};

/// A browser whose ClientHello we send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fingerprint {
    /// Chrome / Chromium.
    Chrome,
    /// Desktop Firefox 120+.
    Firefox,
    /// Safari 26.3 (`HelloSafari_Auto` in utls).
    Safari,
    /// iOS 14 (`HelloIOS_Auto` in utls).
    Ios,
    /// Android 11 OkHttp (`HelloAndroid_11_OkHttp` in utls).
    Android,
    /// Edge 85 (`HelloEdge_Auto` in utls).
    Edge,
    /// 360 Browser 11.0; utls's `Hello360_Auto` is the older 7.5 preset, which has no
    /// TLS 1.3 and no h2, so we mirror the maintained 11.0 preset instead.
    Browser360,
    /// QQ Browser 11.1 (`HelloQQ_Auto` in utls).
    Qq,
    /// A fixed randomized spec (Xray picks one modern preset per process for `random`).
    Random,
    /// utls's randomized parrot with ALPN: a fresh permutation per connection.
    Randomized,
}

impl Fingerprint {
    /// From the `fp` value of a link or config. An absent value keeps the historical
    /// default (Chrome); `none` and `rustls` keep rustls's own ClientHello; any other
    /// unknown name is an error rather than a silent Chrome substitution.
    pub fn from_name(name: Option<&str>) -> Result<Option<Fingerprint>> {
        match name.map(|n| n.trim().to_ascii_lowercase()).as_deref() {
            None | Some("chrome") | Some("chromium") => Ok(Some(Fingerprint::Chrome)),
            Some("firefox") | Some("ff") | Some("firefox_120") => Ok(Some(Fingerprint::Firefox)),
            Some("safari") => Ok(Some(Fingerprint::Safari)),
            Some("ios") => Ok(Some(Fingerprint::Ios)),
            Some("android") => Ok(Some(Fingerprint::Android)),
            Some("edge") => Ok(Some(Fingerprint::Edge)),
            Some("360") => Ok(Some(Fingerprint::Browser360)),
            Some("qq") => Ok(Some(Fingerprint::Qq)),
            Some("random") => Ok(Some(Fingerprint::Random)),
            Some("randomized") => Ok(Some(Fingerprint::Randomized)),
            Some("") | Some("none") | Some("rustls") => Ok(None),
            Some(other) => Err(Error::Unsupported(format!("tls fingerprint {other:?}"))),
        }
    }

    fn profile(self) -> &'static Profile {
        match self {
            Fingerprint::Chrome => &CHROME_PROFILE,
            Fingerprint::Firefox => &FIREFOX_PROFILE,
            Fingerprint::Safari => &SAFARI_PROFILE,
            Fingerprint::Ios => &IOS_PROFILE,
            Fingerprint::Android => &ANDROID_PROFILE,
            Fingerprint::Edge => &EDGE_PROFILE,
            Fingerprint::Browser360 => &THREE60_PROFILE,
            Fingerprint::Qq => &QQ_PROFILE,
            Fingerprint::Random | Fingerprint::Randomized => &RANDOM_PROFILE,
        }
    }

    /// Whether this profile's first key share is the X25519MLKEM768 hybrid. REALITY
    /// installs its own hooked groups in the same order.
    pub fn uses_hybrid(self) -> bool {
        self.profile().kx.contains(&Kx::Mlkem)
    }

    /// Key exchange groups in the browser's order, for a provider whose ClientHello will
    /// be rewritten. Groups a preset advertises but rustls has no provider for (P-521,
    /// FFDHE) are only listed in supported_groups; they never get a key share.
    pub fn kx_groups(self) -> Vec<&'static dyn SupportedKxGroup> {
        self.profile().kx.iter().map(|k| k.group()).collect()
    }

    /// The ring provider with the browser's groups and cipher suite order.
    pub fn provider(self) -> CryptoProvider {
        let profile = self.profile();
        let mut p = rustls::crypto::ring::default_provider();
        p.kx_groups = self.kx_groups();
        p.cipher_suites.sort_by_key(|s| {
            let suite = u16::from(s.suite());
            profile.suites.iter().position(|&c| c == suite).unwrap_or(usize::MAX)
        });
        p
    }

    /// The rewriter to install as `ClientConfig::client_hello_rewriter`.
    pub fn rewriter(self) -> Arc<dyn ClientHelloRewriter> {
        match self {
            Fingerprint::Randomized => Arc::new(RandomizedHello { fixed_seed: false }),
            Fingerprint::Random => Arc::new(RandomizedHello { fixed_seed: true }),
            _ => Arc::new(TableHello(self.profile())),
        }
    }
}

/// A key exchange group the provider can actually produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kx {
    Mlkem,
    X25519,
    P256,
    P384,
}

impl Kx {
    fn group(self) -> &'static dyn SupportedKxGroup {
        use rustls::crypto::ring::kx_group::{SECP256R1, SECP384R1, X25519};
        match self {
            Kx::Mlkem => &X25519_MLKEM768,
            Kx::X25519 => X25519,
            Kx::P256 => SECP256R1,
            Kx::P384 => SECP384R1,
        }
    }
}

/// Where the ALPN extension's protocol list comes from.
#[derive(Clone, Copy, Debug)]
enum Alpn {
    /// rustls's list; omit the extension when rustls sent none (Chrome, Android).
    Hello,
    /// rustls's list, or the profile's own list when rustls sent none (Firefox,
    /// Safari, iOS, Edge, 360, QQ, randomized).
    HelloOrFixed(&'static [&'static [u8]]),
}

/// How the key_share extension is built from rustls's entries.
#[derive(Clone, Copy, Debug)]
enum KeyShareMode {
    /// A one-byte GREASE share, then rustls's shares (Chrome, Safari, iOS, Edge, 360, QQ).
    GreaseThenRustls,
    /// Only the X25519 share on the first flight (Firefox).
    X25519Only,
    /// rustls's shares unchanged; the profile has no GREASE share (randomized, Android).
    RustlsOnly,
}

/// Which supported_versions list the profile sends.
#[derive(Clone, Copy, Debug)]
enum VersionMode {
    /// A GREASE value, TLS 1.3 and TLS 1.2 (Chrome, Safari).
    Grease1312,
    /// A GREASE value, TLS 1.3 down to TLS 1.0 (iOS, Edge, 360, QQ).
    Grease13121110,
    /// rustls's own bytes (Firefox, Android; keeps a TLS 1.3-only caller honest).
    Rustls,
}

/// A logical extension in a profile's ClientHello.
#[derive(Clone, Copy, Debug)]
enum Ext {
    Sni,
    Ems,
    Reneg,
    Groups,
    Points,
    SessionTicket,
    Alpn,
    Status,
    Sigalgs,
    Sct,
    DelegatedCredentials,
    KeyShare,
    PskModes,
    Versions,
    RecordSizeLimit,
    CompressCertificate(&'static [u16]),
    Alps(u16),
    ChannelId(u16),
}

/// One table row: the lists and switches of a uTLS preset.
#[derive(Debug)]
struct Profile {
    /// uTLS preset name, also the per-profile RNG label.
    label: &'static str,
    /// Cipher suites without GREASE.
    suites: &'static [u16],
    /// supported_groups without GREASE.
    groups: &'static [u16],
    /// signature_algorithms without GREASE.
    sigalgs: &'static [u16],
    /// Extension order, minus the leading/trailing GREASE and dynamic padding.
    extensions: &'static [Ext],
    alpn: Alpn,
    key_share: KeyShareMode,
    versions: VersionMode,
    /// GREASE cipher, group, version and the two extension values.
    grease: bool,
    /// Shuffle the extension list after the first entry (Chrome 106+).
    shuffle: bool,
    /// BoringSSL padding: a hello of 256..511 bytes is padded to 512.
    pad_to_512: bool,
    /// Groups the provider really supports, in preference order.
    kx: &'static [Kx],
}

/// Chrome 155 (`HelloChrome_155` in utls; Chromium 152 on the wire).
const CHROME_SUITES: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
const CHROME_GROUPS: [u16; 4] = [0x11ec, 0x001d, 0x0017, 0x0018];
/// After a GREASE value: ML-DSA-44/65/87, then the classical schemes.
const CHROME_SIGALGS: [u16; 11] = [
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

/// Firefox 120 cipher suites, from `HelloFirefox_120` in utls (same as NSS).
const FIREFOX_SUITES: [u16; 15] = [
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
const FIREFOX_GROUPS: [u16; 6] = [0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101];
/// Firefox 120 signature schemes: the ECDSA curves, then RSA-PSS, then the PKCS#1 and
/// SHA-1 legacy tail.
const FIREFOX_SIGALGS: [u16; 11] = [
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
/// The schemes Firefox lists in delegated_credentials.
const FIREFOX_DELEGATED_SIGALGS: [u16; 4] = [0x0403, 0x0503, 0x0603, 0x0203];

// Safari 26.3 (`HelloSafari_Auto`). 3DES suites are advertised but have no rustls
// provider; a server that picked one would fail the handshake, never downgrade it.
const SAFARI_SUITES: [u16; 20] = [
    0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009, 0xc014,
    0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];
const SAFARI_GROUPS: [u16; 5] = [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019];
/// The duplicate 0x0805 is in utls's preset; keep it so the list matches byte for byte.
const SAFARI_SIGALGS: [u16; 10] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

// iOS 14 (`HelloIOS_Auto`). P-521 and the CBC/3DES suites are advertisement only.
const IOS_SUITES: [u16; 25] = [
    0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024, 0xc023, 0xc00a,
    0xc009, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0xc008,
    0xc012,
];
const IOS_GROUPS: [u16; 4] = [0x001d, 0x0017, 0x0018, 0x0019];
const IOS_SIGALGS: [u16; 11] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

// Android 11 OkHttp. utls's preset is TLS 1.2 only (no supported_versions, no key_share)
// and sends no ALPN; rustls refuses a TLS 1.2 server hello as a downgrade once it thought
// it offered 1.3, so we keep rustls's TLS 1.3 suites, versions, key share and ALPN. The
// TLS 1.2 suites, groups and extension order still follow the preset.
const ANDROID_SUITES: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
const ANDROID_GROUPS: [u16; 3] = [0x001d, 0x0017, 0x0018];
const ANDROID_SIGALGS: [u16; 9] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

// Edge 85 (`HelloEdge_Auto`), the same Chromium 85 lists as Chrome without ALPS.
const EDGE_GROUPS: [u16; 3] = [0x001d, 0x0017, 0x0018];
const EDGE_SIGALGS: [u16; 8] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

// 360 Browser 11.0 (`Hello360_11_0`): Chrome's suites plus RSA 3DES.
const THREE60_SUITES: [u16; 16] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035, 0x000a,
];
const THREE60_GROUPS: [u16; 3] = [0x001d, 0x0017, 0x0018];
const THREE60_SIGALGS: [u16; 9] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

// QQ Browser 11.1 (`HelloQQ_11_1`): Chrome's lists, an old-codepoint ALPS.
const QQ_GROUPS: [u16; 3] = [0x001d, 0x0017, 0x0018];
const QQ_SIGALGS: [u16; 8] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

/// The base lists the randomized parrots permute.
const RANDOM_SUITES: [u16; 15] = CHROME_SUITES;
const RANDOM_GROUPS: [u16; 3] = [0x001d, 0x0017, 0x0018];
const RANDOM_SIGALGS: [u16; 8] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

const ALPN_H2_HTTP1: &[&[u8]] = &[b"h2", b"http/1.1"];

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
const RECORD_SIZE_LIMIT: u16 = 28;
const DELEGATED_CREDENTIALS: u16 = 34;
const SESSION_TICKET: u16 = 35;
const PRE_SHARED_KEY: u16 = 41;
const EARLY_DATA: u16 = 42;
const SUPPORTED_VERSIONS: u16 = 43;
const PSK_KEY_EXCHANGE_MODES: u16 = 45;
const KEY_SHARE: u16 = 51;
/// Chrome's ALPS codepoint.
const ALPS: u16 = 0x44cd;
/// The older ALPS codepoint QQ and Edge 85 use.
const ALPS_OLD: u16 = 0x4469;
/// utls's `fakeExtensionChannelID` (not IANA assigned).
const CHANNEL_ID: u16 = 30032;
const RENEGOTIATION_INFO: u16 = 0xff01;

const CHROME_EXTS: &[Ext] = &[
    Ext::Sni,
    Ext::Ems,
    Ext::Reneg,
    Ext::Groups,
    Ext::Points,
    Ext::SessionTicket,
    Ext::Alpn,
    Ext::Status,
    Ext::Sigalgs,
    Ext::Sct,
    Ext::KeyShare,
    Ext::PskModes,
    Ext::Versions,
    Ext::CompressCertificate(&[2]),
    Ext::Alps(ALPS),
];

// Firefox 120's wire order; note that signature_algorithms follows supported_versions
// (unlike Chrome's, which precedes SCT and key_share). The preset also advertises an
// X25519+P-256 key share and an ECH grease extension; both are omitted because rustls
// only ever builds a share for its first group and cannot answer an ECH ack. A
// HelloRetryRequest covers P-256.
const FIREFOX_EXTS: &[Ext] = &[
    Ext::Sni,
    Ext::Ems,
    Ext::Reneg,
    Ext::Groups,
    Ext::Points,
    Ext::SessionTicket,
    Ext::Alpn,
    Ext::Status,
    Ext::DelegatedCredentials,
    Ext::KeyShare,
    Ext::Versions,
    Ext::Sigalgs,
    Ext::PskModes,
    Ext::RecordSizeLimit,
];

const SAFARI_EXTS: &[Ext] = &[
    Ext::Sni,
    Ext::Ems,
    Ext::Reneg,
    Ext::Groups,
    Ext::Points,
    Ext::Alpn,
    Ext::Status,
    Ext::Sigalgs,
    Ext::Sct,
    Ext::KeyShare,
    Ext::PskModes,
    Ext::Versions,
    Ext::CompressCertificate(&[1]),
];

const IOS_EXTS: &[Ext] = &[
    Ext::Sni,
    Ext::Ems,
    Ext::Reneg,
    Ext::Groups,
    Ext::Points,
    Ext::Alpn,
    Ext::Status,
    Ext::Sigalgs,
    Ext::Sct,
    Ext::KeyShare,
    Ext::PskModes,
    Ext::Versions,
];

const ANDROID_EXTS: &[Ext] = &[
    Ext::Sni,
    Ext::Ems,
    Ext::Reneg,
    Ext::Groups,
    Ext::Points,
    Ext::Status,
    Ext::Sigalgs,
    // Additions the TLS 1.2 preset does not have; kept after its own extensions so the
    // prefix still matches HelloAndroid_11_OkHttp.
    Ext::Alpn,
    Ext::KeyShare,
    Ext::Versions,
    Ext::PskModes,
];

const EDGE_EXTS: &[Ext] = &[
    Ext::Sni,
    Ext::Ems,
    Ext::Reneg,
    Ext::Groups,
    Ext::Points,
    Ext::SessionTicket,
    Ext::Alpn,
    Ext::Status,
    Ext::Sigalgs,
    Ext::Sct,
    Ext::KeyShare,
    Ext::PskModes,
    Ext::Versions,
    Ext::CompressCertificate(&[2]),
];

const QQ_EXTS: &[Ext] = &[
    Ext::Sni,
    Ext::Ems,
    Ext::Reneg,
    Ext::Groups,
    Ext::Points,
    Ext::SessionTicket,
    Ext::Alpn,
    Ext::Status,
    Ext::Sigalgs,
    Ext::Sct,
    Ext::KeyShare,
    Ext::PskModes,
    Ext::Versions,
    Ext::CompressCertificate(&[2]),
    Ext::Alps(ALPS_OLD),
];

const THREE60_EXTS: &[Ext] = &[
    Ext::Sni,
    Ext::Ems,
    Ext::Reneg,
    Ext::Groups,
    Ext::Points,
    Ext::SessionTicket,
    Ext::Alpn,
    Ext::Status,
    Ext::Sigalgs,
    Ext::Sct,
    Ext::ChannelId(CHANNEL_ID),
    Ext::KeyShare,
    Ext::PskModes,
    Ext::Versions,
    Ext::CompressCertificate(&[2]),
];

static CHROME_PROFILE: Profile = Profile {
    label: "chrome",
    suites: &CHROME_SUITES,
    groups: &CHROME_GROUPS,
    sigalgs: &CHROME_SIGALGS,
    extensions: CHROME_EXTS,
    alpn: Alpn::Hello,
    key_share: KeyShareMode::GreaseThenRustls,
    versions: VersionMode::Grease1312,
    grease: true,
    shuffle: true,
    pad_to_512: true,
    kx: &[Kx::Mlkem, Kx::X25519, Kx::P256, Kx::P384],
};

static FIREFOX_PROFILE: Profile = Profile {
    label: "firefox",
    suites: &FIREFOX_SUITES,
    groups: &FIREFOX_GROUPS,
    sigalgs: &FIREFOX_SIGALGS,
    extensions: FIREFOX_EXTS,
    alpn: Alpn::HelloOrFixed(ALPN_H2_HTTP1),
    key_share: KeyShareMode::X25519Only,
    versions: VersionMode::Rustls,
    grease: false,
    shuffle: false,
    pad_to_512: false,
    kx: &[Kx::X25519, Kx::P256, Kx::P384],
};

static SAFARI_PROFILE: Profile = Profile {
    label: "safari",
    suites: &SAFARI_SUITES,
    groups: &SAFARI_GROUPS,
    sigalgs: &SAFARI_SIGALGS,
    extensions: SAFARI_EXTS,
    alpn: Alpn::HelloOrFixed(ALPN_H2_HTTP1),
    key_share: KeyShareMode::GreaseThenRustls,
    versions: VersionMode::Grease1312,
    grease: true,
    shuffle: false,
    pad_to_512: false,
    kx: &[Kx::Mlkem, Kx::X25519, Kx::P256, Kx::P384],
};

static IOS_PROFILE: Profile = Profile {
    label: "ios",
    suites: &IOS_SUITES,
    groups: &IOS_GROUPS,
    sigalgs: &IOS_SIGALGS,
    extensions: IOS_EXTS,
    alpn: Alpn::HelloOrFixed(ALPN_H2_HTTP1),
    key_share: KeyShareMode::GreaseThenRustls,
    versions: VersionMode::Grease13121110,
    grease: true,
    shuffle: false,
    pad_to_512: true,
    kx: &[Kx::X25519, Kx::P256, Kx::P384],
};

static ANDROID_PROFILE: Profile = Profile {
    label: "android",
    suites: &ANDROID_SUITES,
    groups: &ANDROID_GROUPS,
    sigalgs: &ANDROID_SIGALGS,
    extensions: ANDROID_EXTS,
    alpn: Alpn::Hello,
    key_share: KeyShareMode::RustlsOnly,
    versions: VersionMode::Rustls,
    grease: false,
    shuffle: false,
    pad_to_512: false,
    kx: &[Kx::X25519, Kx::P256, Kx::P384],
};

static EDGE_PROFILE: Profile = Profile {
    label: "edge",
    suites: &CHROME_SUITES,
    groups: &EDGE_GROUPS,
    sigalgs: &EDGE_SIGALGS,
    extensions: EDGE_EXTS,
    alpn: Alpn::HelloOrFixed(ALPN_H2_HTTP1),
    key_share: KeyShareMode::GreaseThenRustls,
    versions: VersionMode::Grease13121110,
    grease: true,
    shuffle: false,
    pad_to_512: true,
    kx: &[Kx::X25519, Kx::P256, Kx::P384],
};

static THREE60_PROFILE: Profile = Profile {
    label: "360",
    suites: &THREE60_SUITES,
    groups: &THREE60_GROUPS,
    sigalgs: &THREE60_SIGALGS,
    extensions: THREE60_EXTS,
    alpn: Alpn::HelloOrFixed(ALPN_H2_HTTP1),
    key_share: KeyShareMode::GreaseThenRustls,
    versions: VersionMode::Grease13121110,
    grease: true,
    shuffle: false,
    pad_to_512: true,
    kx: &[Kx::X25519, Kx::P256, Kx::P384],
};

static QQ_PROFILE: Profile = Profile {
    label: "qq",
    suites: &CHROME_SUITES,
    groups: &QQ_GROUPS,
    sigalgs: &QQ_SIGALGS,
    extensions: QQ_EXTS,
    alpn: Alpn::HelloOrFixed(ALPN_H2_HTTP1),
    key_share: KeyShareMode::GreaseThenRustls,
    versions: VersionMode::Grease13121110,
    grease: true,
    shuffle: false,
    pad_to_512: true,
    kx: &[Kx::X25519, Kx::P256, Kx::P384],
};

/// Shared table for `random`/`randomized`; the randomized rewriter builds its own lists.
static RANDOM_PROFILE: Profile = Profile {
    label: "randomized",
    suites: &RANDOM_SUITES,
    groups: &RANDOM_GROUPS,
    sigalgs: &RANDOM_SIGALGS,
    extensions: &[],
    alpn: Alpn::HelloOrFixed(ALPN_H2_HTTP1),
    key_share: KeyShareMode::GreaseThenRustls,
    versions: VersionMode::Rustls,
    grease: false,
    shuffle: false,
    pad_to_512: true,
    kx: &[Kx::X25519, Kx::P256, Kx::P384],
};

/// Rebuilds rustls's ClientHello as a table profile's.
#[derive(Debug)]
struct TableHello(&'static Profile);

impl ClientHelloRewriter for TableHello {
    fn rewrite(&self, hello: &[u8]) -> Option<RewrittenHello> {
        rewrite_parsed(&ParsedHello::parse(hello)?, |h| rewrite_profile(self.0, h))
    }
}

/// Rebuilds rustls's ClientHello as `randomized`'s (or `random`'s fixed-seed variant).
#[derive(Debug)]
struct RandomizedHello {
    fixed_seed: bool,
}

impl ClientHelloRewriter for RandomizedHello {
    fn rewrite(&self, hello: &[u8]) -> Option<RewrittenHello> {
        let parsed = ParsedHello::parse(hello)?;
        rewrite_parsed(&parsed, |h| randomized(h, self.fixed_seed))
    }
}

/// Runs a builder over a parsed hello and records the extensions it added.
fn rewrite_parsed(
    parsed: &ParsedHello<'_>,
    build: impl FnOnce(&ParsedHello<'_>) -> Option<Vec<u8>>,
) -> Option<RewrittenHello> {
    let message = build(parsed)?;
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

/// Deterministic per-hello randomness: SHA-256 of the profile label and the ClientHello
/// random in counter mode.
struct HelloRng {
    seed: [u8; 32],
    block: [u8; 32],
    pos: usize,
    counter: u32,
}

impl HelloRng {
    fn new(label: &str, random: &[u8]) -> HelloRng {
        let mut h = Sha256::new();
        h.update(b"unbihex/fingerprint/");
        h.update(label.as_bytes());
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

/// An ALPN extension body for a protocol list.
fn alpn_bytes(protocols: &[&[u8]]) -> Vec<u8> {
    let mut list = Vec::new();
    for p in protocols {
        list.push(p.len() as u8);
        list.extend_from_slice(p);
    }
    let mut out = Vec::new();
    put_vec16(&mut out, &list);
    out
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

/// A Fisher-Yates shuffle over `values[start..]` that never moves anything before
/// `start`.
fn shuffle_tail<T>(values: &mut [T], start: usize, rng: &mut HelloRng) {
    if start >= values.len() {
        return;
    }
    for i in (start..values.len()).rev() {
        values.swap(i, start + rng.below(i + 1 - start));
    }
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

/// A serialized ClientHello body (everything after the 4-byte handshake header).
fn encode_body(h: &ParsedHello<'_>, suites: &[u16], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut ext_bytes = Vec::new();
    for (t, d) in exts {
        put_u16(&mut ext_bytes, *t);
        put_vec16(&mut ext_bytes, d);
    }
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(h.random);
    body.push(h.session_id.len() as u8);
    body.extend_from_slice(h.session_id);
    put_vec16(&mut body, &u16_list(suites));
    body.extend_from_slice(&[1, 0]);
    put_vec16(&mut body, &ext_bytes);
    body
}

/// Encodes a ClientHello, applying BoringSSL's 256..511 -> 512 byte padding first when
/// the profile asks for it.
fn encode_message(
    h: &ParsedHello<'_>,
    suites: &[u16],
    exts: &[(u16, Vec<u8>)],
    pad_to_512: bool,
) -> Vec<u8> {
    let mut body = encode_body(h, suites, exts);
    if pad_to_512 {
        let len = body.len() + 4;
        if (0x100..0x200).contains(&len) {
            let pad = (0x200 - len).saturating_sub(4).max(1);
            let mut padded = exts.to_vec();
            padded.push((PADDING, vec![0; pad]));
            body = encode_body(h, suites, &padded);
        }
    }
    let mut msg = vec![1];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    msg
}

/// Rebuilds a hello as `p`'s, reproducing the preset's extension order and flags.
fn rewrite_profile(p: &Profile, h: &ParsedHello<'_>) -> Option<Vec<u8>> {
    // PSK binders and early data are computed over rustls's own bytes.
    if h.ext(PRE_SHARED_KEY).is_some() || h.ext(EARLY_DATA).is_some() {
        return None;
    }

    let mut rng = HelloRng::new(p.label, h.random);
    let (grease_suite, grease_group, grease_version, grease_first, mut grease_last) = if p.grease {
        let suite = rng.grease();
        let group = rng.grease();
        let version = rng.grease();
        let first = rng.grease();
        let last = rng.grease();
        (suite, group, version, first, last)
    } else {
        (0, 0, 0, 0, 0)
    };
    if p.grease && grease_last == grease_first {
        grease_last ^= 0x1010;
    }

    let alpn: Option<Vec<u8>> = match p.alpn {
        Alpn::Hello => h.ext(ALPN).map(<[u8]>::to_vec),
        Alpn::HelloOrFixed(fixed) => {
            Some(h.ext(ALPN).map(<[u8]>::to_vec).unwrap_or_else(|| alpn_bytes(fixed)))
        }
    };

    let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();
    for ext in p.extensions {
        match ext {
            Ext::Sni => {
                if let Some(sni) = h.ext(SERVER_NAME) {
                    exts.push((SERVER_NAME, sni.to_vec()));
                }
            }
            Ext::Ems => exts.push((EXTENDED_MASTER_SECRET, Vec::new())),
            Ext::Reneg => exts.push((RENEGOTIATION_INFO, vec![0])),
            Ext::Groups => {
                let mut groups = Vec::with_capacity(p.groups.len() + usize::from(p.grease));
                if p.grease {
                    groups.push(grease_group);
                }
                groups.extend_from_slice(p.groups);
                let mut body = Vec::new();
                put_vec16(&mut body, &u16_list(&groups));
                exts.push((SUPPORTED_GROUPS, body));
            }
            Ext::Points => exts.push((EC_POINT_FORMATS, vec![1, 0])),
            Ext::SessionTicket => exts.push((
                SESSION_TICKET,
                h.ext(SESSION_TICKET).unwrap_or(&[]).to_vec(),
            )),
            Ext::Alpn => {
                if let Some(a) = &alpn {
                    exts.push((ALPN, a.clone()));
                }
            }
            Ext::Status => exts.push((STATUS_REQUEST, vec![1, 0, 0, 0, 0])),
            Ext::Sigalgs => {
                let mut schemes = Vec::with_capacity(p.sigalgs.len() + usize::from(p.grease));
                if p.grease {
                    schemes.push(rng.grease());
                }
                schemes.extend_from_slice(p.sigalgs);
                let mut body = Vec::new();
                put_vec16(&mut body, &u16_list(&schemes));
                exts.push((SIGNATURE_ALGORITHMS, body));
            }
            Ext::Sct => exts.push((SCT, Vec::new())),
            Ext::DelegatedCredentials => {
                let mut body = Vec::new();
                put_vec16(&mut body, &u16_list(&FIREFOX_DELEGATED_SIGALGS));
                exts.push((DELEGATED_CREDENTIALS, body));
            }
            Ext::KeyShare => match p.key_share {
                KeyShareMode::GreaseThenRustls => {
                    let ks = h.ext(KEY_SHARE)?;
                    exts.push((KEY_SHARE, key_share(ks, grease_group)?));
                }
                KeyShareMode::X25519Only => {
                    let ks = h.ext(KEY_SHARE)?;
                    exts.push((KEY_SHARE, firefox_key_share(ks)?));
                }
                KeyShareMode::RustlsOnly => {
                    exts.push((KEY_SHARE, h.ext(KEY_SHARE)?.to_vec()));
                }
            },
            Ext::PskModes => exts.push((PSK_KEY_EXCHANGE_MODES, vec![1, 1])),
            Ext::Versions => match p.versions {
                VersionMode::Grease1312 => {
                    let values = u16_list(&[grease_version, 0x0304, 0x0303]);
                    let mut body = vec![values.len() as u8];
                    body.extend_from_slice(&values);
                    exts.push((SUPPORTED_VERSIONS, body));
                }
                VersionMode::Grease13121110 => {
                    let values = u16_list(&[grease_version, 0x0304, 0x0303, 0x0302, 0x0301]);
                    let mut body = vec![values.len() as u8];
                    body.extend_from_slice(&values);
                    exts.push((SUPPORTED_VERSIONS, body));
                }
                VersionMode::Rustls => exts.push((
                    SUPPORTED_VERSIONS,
                    h.ext(SUPPORTED_VERSIONS).unwrap_or(&[]).to_vec(),
                )),
            },
            Ext::RecordSizeLimit => exts.push((RECORD_SIZE_LIMIT, vec![0x40, 0x01])),
            Ext::CompressCertificate(algs) => {
                let mut body = vec![(algs.len() * 2) as u8];
                for &a in *algs {
                    put_u16(&mut body, a);
                }
                exts.push((COMPRESS_CERTIFICATE, body));
            }
            Ext::Alps(codepoint) => {
                if alpn.as_deref().is_some_and(offers_h2) {
                    exts.push((*codepoint, vec![0, 3, 2, b'h', b'2']));
                }
            }
            Ext::ChannelId(codepoint) => {
                let mut id = [0u8; 32];
                rng.fill(&mut id);
                exts.push((*codepoint, id.to_vec()));
            }
        }
    }
    // rustls extensions the profile has no slot for (a HelloRetryRequest cookie…) stay.
    // compress_certificate is an optional offer, though: rustls enables it by default, and
    // keeping it would add an extension no Firefox, iOS or Android preset sends.
    let profile_compresses = p
        .extensions
        .iter()
        .any(|e| matches!(e, Ext::CompressCertificate(_)));
    for (t, d) in &h.extensions {
        if *t == COMPRESS_CERTIFICATE && !profile_compresses {
            continue;
        }
        if !exts.iter().any(|(m, _)| m == t) {
            exts.push((*t, d.to_vec()));
        }
    }

    if p.shuffle {
        // Chrome 106+ shuffles every extension except the GREASE wrappers and padding.
        // Both are appended after this point, so the whole table is shuffled.
        shuffle_tail(&mut exts, 0, &mut rng);
    }

    let mut suites = Vec::with_capacity(p.suites.len() + usize::from(p.grease));
    if p.grease {
        exts.insert(0, (grease_first, Vec::new()));
        exts.push((grease_last, vec![0]));
        suites.push(grease_suite);
    }
    suites.extend_from_slice(p.suites);

    // Every suite rustls offered is still offered, so the server cannot pick one rustls
    // expects and we hid (the renegotiation SCSV is replaced by renegotiation_info).
    debug_assert!(
        h.cipher_suites
            .iter()
            .all(|c| p.suites.contains(c) || *c == 0x00ff)
    );

    Some(encode_message(h, &suites, &exts, p.pad_to_512))
}

/// `random`'s fixed seed: stable across hellos and processes, still a spec no real
/// browser sends.
const RANDOM_SEED: u64 = 0x756e_6269_6865_7801;

/// utls's randomized parrot: shuffle the suites, signature algorithms and extension
/// order, optionally drop extensions by weighted coin, and keep TLS 1.3's key share and
/// supported_versions from rustls so the hello stays valid. `fixed_seed` is `random`;
/// otherwise the seed is the hello random, so each connection differs.
fn randomized(h: &ParsedHello<'_>, fixed_seed: bool) -> Option<Vec<u8>> {
    if h.ext(PRE_SHARED_KEY).is_some() || h.ext(EARLY_DATA).is_some() {
        return None;
    }
    let rustls_key_share = h.ext(KEY_SHARE)?;
    let mut rng = if fixed_seed {
        HelloRng::new("random", &RANDOM_SEED.to_be_bytes())
    } else {
        HelloRng::new("randomized", h.random)
    };

    let mut suites = RANDOM_SUITES.to_vec();
    shuffle_tail(&mut suites, 0, &mut rng);
    let mut sigalgs = RANDOM_SIGALGS.to_vec();
    shuffle_tail(&mut sigalgs, 0, &mut rng);

    let alpn = h
        .ext(ALPN)
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| alpn_bytes(ALPN_H2_HTTP1));

    let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();
    if let Some(sni) = h.ext(SERVER_NAME) {
        exts.push((SERVER_NAME, sni.to_vec()));
    }
    let mut groups = Vec::new();
    put_vec16(&mut groups, &u16_list(&RANDOM_GROUPS));
    exts.push((SUPPORTED_GROUPS, groups));
    exts.push((EC_POINT_FORMATS, vec![1, 0]));
    exts.push((ALPN, alpn));
    let mut schemes = Vec::new();
    put_vec16(&mut schemes, &u16_list(&sigalgs));
    exts.push((SIGNATURE_ALGORITHMS, schemes));
    exts.push((KEY_SHARE, rustls_key_share.to_vec()));
    exts.push((PSK_KEY_EXCHANGE_MODES, vec![1, 1]));
    exts.push((
        SUPPORTED_VERSIONS,
        h.ext(SUPPORTED_VERSIONS).unwrap_or(&[]).to_vec(),
    ));
    // The smaller optional extensions come and go with DefaultWeights-like coins.
    if rng.below(2) == 0 {
        exts.push((EXTENDED_MASTER_SECRET, Vec::new()));
    }
    if rng.below(2) == 0 {
        exts.push((RENEGOTIATION_INFO, vec![0]));
    }
    if rng.below(4) != 0 {
        exts.push((STATUS_REQUEST, vec![1, 0, 0, 0, 0]));
    }
    if rng.below(2) == 0 {
        exts.push((SCT, Vec::new()));
    }
    if rng.below(2) == 0 {
        exts.push((SESSION_TICKET, h.ext(SESSION_TICKET).unwrap_or(&[]).to_vec()));
    }
    if offers_h2(h.ext(ALPN).unwrap_or(&[])) && rng.below(3) == 0 {
        exts.push((ALPS, vec![0, 3, 2, b'h', b'2']));
    }
    shuffle_tail(&mut exts, 0, &mut rng);

    Some(encode_message(h, &suites, &exts, true))
}

/// Firefox's ALPN extension data: h2, then http/1.1 (used by the tests).
#[cfg(test)]
fn firefox_alpn() -> Vec<u8> {
    alpn_bytes(ALPN_H2_HTTP1)
}

/// Firefox's key_share: the X25519 share alone on the first flight. A HelloRetryRequest
/// can still select another advertised curve, so keep rustls's entries if X25519 is absent.
fn firefox_key_share(rustls_ks: &[u8]) -> Option<Vec<u8>> {
    let entries = Reader(rustls_ks).vec16()?;
    let mut r = Reader(entries);
    let mut list = Vec::new();
    while !r.0.is_empty() {
        let group = r.u16()?;
        let data = r.vec16()?;
        if group == 0x001d {
            put_u16(&mut list, group);
            put_vec16(&mut list, data);
        }
    }
    if list.is_empty() {
        return Some(rustls_ks.to_vec());
    }
    let mut out = Vec::new();
    put_vec16(&mut out, &list);
    Some(out)
}

/// Rebuilds a hello as Chrome's (kept as a named entry point for the tests).
#[cfg(test)]
fn chrome(h: &ParsedHello<'_>) -> Option<Vec<u8>> {
    rewrite_profile(&CHROME_PROFILE, h)
}

/// Rebuilds a hello as Firefox's (kept as a named entry point for the tests).
#[cfg(test)]
fn firefox(h: &ParsedHello<'_>) -> Option<Vec<u8>> {
    rewrite_profile(&FIREFOX_PROFILE, h)
}

/// Rebuilds a hello as any profile's; the tests use it for the whole table.
#[cfg(test)]
fn rewrite(fp: Fingerprint, h: &ParsedHello<'_>) -> Option<Vec<u8>> {
    match fp {
        Fingerprint::Randomized => randomized(h, false),
        Fingerprint::Random => randomized(h, true),
        _ => rewrite_profile(fp.profile(), h),
    }
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
        // Chromium 152.0.7977.167, recorded on the wire, minus the GREASE ECH extension
        // that rustls cannot safely send (see the module documentation).
        assert_eq!(print, "t13d1515h2_8daaf6152771_eac8ad812b09");
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
        for t in [ALPS, SCT, RENEGOTIATION_INFO, COMPRESS_CERTIFICATE] {
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
    fn from_name_maps_names_and_rejects_unknown_ones() {
        for name in ["none", "rustls"] {
            assert_eq!(Fingerprint::from_name(Some(name)).unwrap(), None, "{name}");
        }
        let names = [
            ("chrome", Fingerprint::Chrome),
            ("chromium", Fingerprint::Chrome),
            ("CHROME", Fingerprint::Chrome),
            ("firefox", Fingerprint::Firefox),
            ("ff", Fingerprint::Firefox),
            ("firefox_120", Fingerprint::Firefox),
            ("Firefox", Fingerprint::Firefox),
            ("safari", Fingerprint::Safari),
            ("ios", Fingerprint::Ios),
            ("android", Fingerprint::Android),
            ("edge", Fingerprint::Edge),
            ("360", Fingerprint::Browser360),
            ("qq", Fingerprint::Qq),
            ("random", Fingerprint::Random),
            ("randomized", Fingerprint::Randomized),
        ];
        for (name, fp) in names {
            assert_eq!(Fingerprint::from_name(Some(name)).unwrap(), Some(fp), "{name}");
        }
        assert_eq!(
            Fingerprint::from_name(None).unwrap(),
            Some(Fingerprint::Chrome)
        );
        for name in ["firefox_999", "tor", "safari_16", "chrome_155"] {
            assert!(
                matches!(Fingerprint::from_name(Some(name)), Err(Error::Unsupported(_))),
                "{name}"
            );
        }
    }

    /// Every profile with a fixed table row (all but the per-connection randomized one).
    const TABLE_PROFILES: [Fingerprint; 9] = [
        Fingerprint::Chrome,
        Fingerprint::Firefox,
        Fingerprint::Safari,
        Fingerprint::Ios,
        Fingerprint::Android,
        Fingerprint::Edge,
        Fingerprint::Browser360,
        Fingerprint::Qq,
        Fingerprint::Random,
    ];

    /// A rustls hello with the profile's provider but no rewriter.
    fn plain_hello(fp: Fingerprint) -> Vec<u8> {
        let mut cfg = client_config(fp, RootCertStore::empty());
        cfg.client_hello_rewriter = None;
        first_hello(cfg)
    }

    fn alpn_list(data: &[u8]) -> Vec<Vec<u8>> {
        let mut r = Reader(data);
        let list = r.vec16().unwrap();
        let mut l = Reader(list);
        let mut out = Vec::new();
        while let Some(name) = l.vec8() {
            out.push(name.to_vec());
        }
        out
    }

    fn u16_values(data: &[u8]) -> Vec<u16> {
        Reader(data)
            .0
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect()
    }

    fn all_grease_free(h: &ParsedHello<'_>) -> bool {
        h.cipher_suites.iter().all(|v| !is_grease(*v))
            && h.extensions.iter().all(|(t, _)| !is_grease(*t))
            && h
                .ext(SUPPORTED_GROUPS)
                .map(|d| u16_values(Reader(d).vec16().unwrap()).iter().all(|v| !is_grease(*v)))
                .unwrap_or(true)
            && h
                .ext(SIGNATURE_ALGORITHMS)
                .map(|d| u16_values(Reader(d).vec16().unwrap()).iter().all(|v| !is_grease(*v)))
                .unwrap_or(true)
    }

    #[test]
    fn every_profile_is_deterministic_and_has_its_lists() {
        for fp in TABLE_PROFILES {
            let hello = plain_hello(fp);
            let h = ParsedHello::parse(&hello).unwrap();
            let a = rewrite(fp, &h).expect("rewrite");
            let b = rewrite(fp, &h).expect("rewrite");
            assert_eq!(a, b, "{fp:?} is not deterministic");

            let parsed = ParsedHello::parse(&a).unwrap();
            let profile = fp.profile();
            let suites: Vec<u16> = parsed
                .cipher_suites
                .iter()
                .copied()
                .filter(|c| !is_grease(*c))
                .collect();
            if fp == Fingerprint::Random {
                // The fixed-seed parrot permutes the same set.
                let mut got = suites.clone();
                let mut want = profile.suites.to_vec();
                got.sort_unstable();
                want.sort_unstable();
                assert_eq!(got, want, "{fp:?} cipher suites");
            } else {
                assert_eq!(suites, profile.suites, "{fp:?} cipher suites");
            }

            // The client config asks for h2 and http/1.1, so every profile carries them.
            assert_eq!(
                alpn_list(parsed.ext(ALPN).expect("ALPN")),
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                "{fp:?} ALPN"
            );

            // GREASE is only where the preset has it; the no-GREASE profiles stay clean.
            assert_eq!(is_grease(parsed.cipher_suites[0]), profile.grease, "{fp:?} GREASE");
            if !profile.grease {
                assert!(all_grease_free(&parsed), "{fp:?} carries GREASE");
            }
        }
    }

    #[test]
    fn randomized_hello_differs_per_connection_and_parses() {
        let a = first_hello(client_config(Fingerprint::Randomized, RootCertStore::empty()));
        let b = first_hello(client_config(Fingerprint::Randomized, RootCertStore::empty()));
        assert_ne!(a, b, "every connection should get a fresh permutation");
        let ha = ParsedHello::parse(&a).expect("valid randomized hello");
        let hb = ParsedHello::parse(&b).expect("valid randomized hello");
        assert!(all_grease_free(&ha) && all_grease_free(&hb));
        // The same hello always becomes the same bytes for a given kind of seed.
        assert_eq!(randomized(&ha, false), randomized(&ha, false));
        assert_eq!(randomized(&ha, true), randomized(&ha, true));
        // `random` is the fixed-seed parrot: stable, still not a table profile.
        let random_a = first_hello(client_config(Fingerprint::Random, RootCertStore::empty()));
        let random_b = first_hello(client_config(Fingerprint::Random, RootCertStore::empty()));
        let ra = ParsedHello::parse(&random_a).unwrap();
        let rb = ParsedHello::parse(&random_b).unwrap();
        assert_eq!(randomized(&ra, true), randomized(&ra, true));
        let ext_order = |h: &ParsedHello<'_>| {
            randomized(h, true)
                .map(|m| {
                    ParsedHello::parse(&m)
                        .unwrap()
                        .extensions
                        .iter()
                        .map(|(t, _)| *t)
                        .collect::<Vec<_>>()
                })
                .unwrap()
        };
        assert_eq!(ext_order(&ra), ext_order(&rb));
        assert_eq!(alpn_list(ha.ext(ALPN).unwrap()), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn handshake_with_every_profile() {
        let x25519 = || vec![rustls::crypto::ring::kx_group::X25519];
        for fp in [
            Fingerprint::Chrome,
            Fingerprint::Firefox,
            Fingerprint::Safari,
            Fingerprint::Ios,
            Fingerprint::Android,
            Fingerprint::Edge,
            Fingerprint::Browser360,
            Fingerprint::Qq,
            Fingerprint::Random,
            Fingerprint::Randomized,
        ] {
            // handshake() asserts the negotiated ALPN is h2.
            let group = handshake(fp, x25519());
            assert_eq!(group, rustls::NamedGroup::X25519, "{fp:?}");
        }
    }

    #[test]
    fn profiles_differ_where_they_must() {
        // Safari, iOS and Android are three genuinely different TLS clients.
        assert_ne!(SAFARI_SUITES.as_slice(), IOS_SUITES.as_slice());
        assert_ne!(IOS_SUITES.as_slice(), ANDROID_SUITES.as_slice());
        assert_ne!(SAFARI_EXTS.len(), IOS_EXTS.len());
        assert_ne!(IOS_EXTS.len(), ANDROID_EXTS.len());
        assert_ne!(Fingerprint::Safari.profile().groups, Fingerprint::Ios.profile().groups);

        let safari = first_hello(client_config(Fingerprint::Safari, RootCertStore::empty()));
        let ios = first_hello(client_config(Fingerprint::Ios, RootCertStore::empty()));
        let android = first_hello(client_config(Fingerprint::Android, RootCertStore::empty()));
        let safari = ParsedHello::parse(&safari).unwrap();
        let ios = ParsedHello::parse(&ios).unwrap();
        let android = ParsedHello::parse(&android).unwrap();
        assert_ne!(safari.cipher_suites, ios.cipher_suites);
        assert_ne!(ios.cipher_suites, android.cipher_suites);
        // Safari 26.3 is the only one of the three with an ML-KEM group.
        let groups = |h: &ParsedHello<'_>| {
            u16_values(Reader(h.ext(SUPPORTED_GROUPS).unwrap()).vec16().unwrap())
        };
        assert!(groups(&safari).contains(&0x11ec));
        assert!(!groups(&ios).contains(&0x11ec));
        // Safari 26.3 has no session_ticket; iOS and Android keep different sets.
        assert!(safari.ext(SESSION_TICKET).is_none());
        // Android has no GREASE and no SCT; iOS has both.
        assert!(android.cipher_suites.iter().all(|c| !is_grease(*c)));
        assert!(android.ext(SCT).is_none());
        assert!(ios.ext(SCT).is_some());
        // Android's TLS 1.2 suites follow its preset; TLS 1.3 stays for rustls.
        assert!(android.cipher_suites.contains(&0xc02b));
        assert!(ios.ext(KEY_SHARE).is_some());
    }

    /// A browser-fingerprinted client that accepts the in-memory test server's certificate
    /// (signatures are still checked).
    fn test_client(fp: Fingerprint) -> ClientConfig {
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

    /// Runs a browser-fingerprinted handshake against an in-memory rustls server with
    /// `server_groups`, sends data through it, and returns the group the server chose.
    fn handshake(
        fp: Fingerprint,
        server_groups: Vec<&'static dyn SupportedKxGroup>,
    ) -> rustls::NamedGroup {
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
        let mut c = ClientConnection::new(Arc::new(test_client(fp)), name).unwrap();
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
        let group = handshake(
            Fingerprint::Chrome,
            vec![&X25519_MLKEM768, rustls::crypto::ring::kx_group::X25519],
        );
        assert_eq!(group, rustls::NamedGroup::X25519MLKEM768);
        // A server without ML-KEM completes on the separate X25519 share, no retry.
        let group = handshake(
            Fingerprint::Chrome,
            vec![rustls::crypto::ring::kx_group::X25519],
        );
        assert_eq!(group, rustls::NamedGroup::X25519);
        // A server with P-256 only asks for it with a HelloRetryRequest.
        let group = handshake(
            Fingerprint::Chrome,
            vec![rustls::crypto::ring::kx_group::SECP256R1],
        );
        assert_eq!(group, rustls::NamedGroup::secp256r1);
    }

    #[test]
    fn firefox_hello_has_firefox_shape() {
        let hello = first_hello(client_config(Fingerprint::Firefox, RootCertStore::empty()));
        let h = ParsedHello::parse(&hello).unwrap();
        assert_eq!(h.cipher_suites, FIREFOX_SUITES);
        let order: Vec<u16> = h.extensions.iter().map(|(t, _)| *t).collect();
        let expected = [
            SERVER_NAME,
            EXTENDED_MASTER_SECRET,
            RENEGOTIATION_INFO,
            SUPPORTED_GROUPS,
            EC_POINT_FORMATS,
            SESSION_TICKET,
            ALPN,
            STATUS_REQUEST,
            DELEGATED_CREDENTIALS,
            KEY_SHARE,
            SUPPORTED_VERSIONS,
            SIGNATURE_ALGORITHMS,
            PSK_KEY_EXCHANGE_MODES,
            RECORD_SIZE_LIMIT,
        ];
        assert_eq!(&order[..expected.len()], &expected);
        // No GREASE value anywhere, in any list.
        assert!(h.cipher_suites.iter().all(|v| !is_grease(*v)));
        assert!(order.iter().all(|v| !is_grease(*v)));
        let groups: Vec<u16> = Reader(Reader(h.ext(SUPPORTED_GROUPS).unwrap()).vec16().unwrap())
            .0
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(groups, FIREFOX_GROUPS);
        let sigalgs: Vec<u16> =
            Reader(Reader(h.ext(SIGNATURE_ALGORITHMS).unwrap()).vec16().unwrap())
                .0
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
        assert_eq!(sigalgs, FIREFOX_SIGALGS);
        assert!(groups.iter().chain(&sigalgs).all(|v| !is_grease(*v)));
        // An X25519-only key share, like Firefox's first flight.
        let mut ks = Reader(Reader(h.ext(KEY_SHARE).unwrap()).vec16().unwrap());
        assert_eq!(ks.u16().unwrap(), 0x001d);
        assert_eq!(ks.vec16().unwrap().len(), 32);
        assert!(ks.0.is_empty());
        assert_eq!(h.ext(ALPN).unwrap().to_vec(), firefox_alpn());
        assert_eq!(h.ext(RECORD_SIZE_LIMIT).unwrap().to_vec(), [0x40, 0x01]);

        // The same rustls hello always becomes the same Firefox bytes.
        let mut plain = client_config(Fingerprint::Firefox, RootCertStore::empty());
        plain.client_hello_rewriter = None;
        let rustls_hello = first_hello(plain);
        let parsed = ParsedHello::parse(&rustls_hello).unwrap();
        assert_eq!(firefox(&parsed), firefox(&parsed));
        assert!(hello.len() > rustls_hello.len());
    }

    #[test]
    fn handshake_with_the_firefox_hello() {
        let group = handshake(
            Fingerprint::Firefox,
            vec![rustls::crypto::ring::kx_group::X25519],
        );
        assert_eq!(group, rustls::NamedGroup::X25519);
        // The test server accepted our ALPN; handshake() asserts h2.
    }

    #[test]
    fn firefox_and_chrome_hellos_differ_and_both_are_accepted() {
        let chrome = first_hello(client_config(Fingerprint::Chrome, RootCertStore::empty()));
        let firefox = first_hello(client_config(Fingerprint::Firefox, RootCertStore::empty()));
        assert_ne!(chrome, firefox);
        let x25519 = || vec![rustls::crypto::ring::kx_group::X25519];
        assert_eq!(
            handshake(Fingerprint::Chrome, x25519()),
            rustls::NamedGroup::X25519
        );
        assert_eq!(
            handshake(Fingerprint::Firefox, x25519()),
            rustls::NamedGroup::X25519
        );
    }

    /// What a real server sees. Run with
    /// `FP_PROBE=firefox FP_HOST=example.com cargo test -- --ignored probe --nocapture`.
    #[test]
    #[ignore = "needs network"]
    fn external_fingerprint_probe() {
        use rustls::StreamOwned;
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let name = std::env::var("FP_PROBE").unwrap_or_else(|_| "chrome".into());
        let host = std::env::var("FP_HOST").unwrap_or_else(|_| "tls.browserleaks.com".into());
        let fp = Fingerprint::from_name(Some(&name)).unwrap().unwrap();
        let mut cfg = test_client(fp);
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server = ServerName::try_from(host.clone()).unwrap();
        let conn = ClientConnection::new(Arc::new(cfg), server).unwrap();
        let tcp = TcpStream::connect((host.as_str(), 443)).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        let mut stream = StreamOwned::new(conn, tcp);

        let path = if host == "tls.browserleaks.com" { "/json" } else { "/" };
        let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        match stream.read_to_end(&mut raw) {
            Ok(_) => {}
            Err(e) if !raw.is_empty() => println!("{name}: read ended early: {e}"),
            Err(e) => panic!("{name}: {e}"),
        }
        let text = String::from_utf8_lossy(&raw);
        let status = text.lines().next().unwrap_or("no status");
        println!("{name}@{host}: {status} ({} bytes)", raw.len());
        for key in ["\"ja3_text\"", "\"akamai_text\""] {
            if let Some(i) = text.find(key) {
                let tail = &text[i..];
                let end = tail.find(',').unwrap_or(tail.len().min(200));
                println!("{name}: {}", &tail[..end.min(200)]);
            }
        }
    }

}
