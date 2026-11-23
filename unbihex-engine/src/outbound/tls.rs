//! TLS client (SPEC §11.2): rustls + ring + webpki roots, optional leaf pinning, and a
//! browser ClientHello (`fingerprint`). Certificate verification is skipped only with
//! `allow_insecure` (a link's `allowInsecure=1`); the handshake signature is still checked.
//! `trusted_sha256` accepts exactly the listed leaf certificates without a chain or name
//! check; [`probe_leaf_sha256`] reads a server's leaf hash so the user can trust it.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::fingerprint::Fingerprint;
use super::tls_stream::TlsRecordStream;
use crate::config::TlsConfig;
use crate::error::{Error, Result};

/// A TLS client for one server name.
#[derive(Clone)]
pub struct TlsClient {
    connector: TlsConnector,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    fingerprint: Option<Fingerprint>,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient")
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl TlsClient {
    // By dubr1k (github.com/dubr1k), PR #33.
    /// QUIC uses the same roots and pinning policy, but not the TCP-only
    /// ClientHello rewriter. ALPN is fixed by the Hysteria 2 protocol.
    pub(crate) fn quic_config(
        cfg: &TlsConfig,
        default_sni: &str,
        extra_roots: Vec<CertificateDer<'static>>,
    ) -> Result<Arc<ClientConfig>> {
        let mut cfg = cfg.clone();
        cfg.fingerprint = Some("none".into());
        cfg.alpn = vec!["h3".into()];
        Ok(Self::build(&cfg, default_sni, extra_roots, &Trust::default())?.config)
    }

    /// Builds a client trusting the bundled WebPKI roots.
    pub fn new(cfg: &TlsConfig, default_sni: &str) -> Result<TlsClient> {
        Self::build(cfg, default_sni, Vec::new(), &Trust::default())
    }

    /// Trusts only `roots` when there are any (an endpoint's own certificate), and
    /// checks the certificate against `verify_name` while sending `cfg.sni`.
    pub(crate) fn with_trust(
        cfg: &TlsConfig,
        default_sni: &str,
        roots: Vec<CertificateDer<'static>>,
        verify_name: Option<&str>,
    ) -> Result<TlsClient> {
        let trust = Trust {
            only_given_roots: !roots.is_empty(),
            verify_name: verify_name
                .map(|n| {
                    ServerName::try_from(n.to_string())
                        .map_err(|_| Error::config(format!("invalid TLS server name {n:?}")))
                })
                .transpose()?,
            probe: None,
        };
        Self::build(cfg, default_sni, roots, &trust)
    }

    /// Test-only: trust additional roots (e.g. a self-signed test CA).
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_extra_roots(
        cfg: &TlsConfig,
        default_sni: &str,
        roots: Vec<CertificateDer<'static>>,
    ) -> Result<TlsClient> {
        Self::build(cfg, default_sni, roots, &Trust::default())
    }

    fn build(
        cfg: &TlsConfig,
        default_sni: &str,
        extra_roots: Vec<CertificateDer<'static>>,
        trust: &Trust,
    ) -> Result<TlsClient> {
        let fingerprint = Fingerprint::from_name(cfg.fingerprint.as_deref())?;
        let provider = Arc::new(match fingerprint {
            Some(fp) => fp.provider(),
            None => rustls::crypto::ring::default_provider(),
        });
        let mut roots = RootCertStore::empty();
        if !trust.only_given_roots {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        for r in extra_roots {
            roots.add(r).map_err(|e| Error::Tls(e.to_string()))?;
        }
        let roots = Arc::new(roots);

        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Tls(e.to_string()))?;
        let mut config = if let Some(name) = &trust.verify_name {
            let inner = WebPkiServerVerifier::builder_with_provider(roots, provider)
                .build()
                .map_err(|e| Error::Tls(e.to_string()))?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NameVerifier {
                    inner,
                    name: name.clone(),
                }))
                .with_no_client_auth()
        } else if let Some(probe) = &trust.probe {
            builder
                .dangerous()
                .with_custom_certificate_verifier(probe.clone())
                .with_no_client_auth()
        } else if cfg.pinned_sha256.is_empty()
            && cfg.trusted_sha256.is_empty()
            && !cfg.allow_insecure
        {
            builder.with_root_certificates(roots).with_no_client_auth()
        } else {
            let pins = parse_hashes("pinned_sha256", &cfg.pinned_sha256)?;
            let trusted = parse_hashes("trusted_sha256", &cfg.trusted_sha256)?;
            let inner = WebPkiServerVerifier::builder_with_provider(roots, provider)
                .build()
                .map_err(|e| Error::Tls(e.to_string()))?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinningVerifier {
                    inner,
                    pins,
                    trusted,
                    insecure: cfg.allow_insecure,
                }))
                .with_no_client_auth()
        };
        config.alpn_protocols = cfg.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        if let Some(fp) = fingerprint {
            config.client_hello_rewriter = Some(fp.rewriter());
            // A resumption PSK binder covers rustls's own hello bytes, not the rewritten ones.
            config.resumption = rustls::client::Resumption::disabled();
            if config.alpn_protocols.is_empty() {
                // Browsers always offer ALPN; this is also Xray's default.
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
        }

        let sni = cfg.sni.clone().unwrap_or_else(|| default_sni.to_string());
        let server_name = ServerName::try_from(sni.clone())
            .map_err(|_| Error::config(format!("invalid TLS server name {sni:?}")))?;
        let config = Arc::new(config);
        Ok(TlsClient {
            connector: TlsConnector::from(config.clone()),
            config,
            server_name,
            fingerprint,
        })
    }

    /// The rustls configuration (tests build a ClientHello from it).
    #[cfg(test)]
    pub(crate) fn client_config(&self) -> Arc<ClientConfig> {
        self.config.clone()
    }

    /// The browser profile whose ClientHello this client sends, if any.
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.fingerprint
    }

    /// Runs the TLS handshake over a TCP connection, returning a record-exact stream
    /// (needed by XTLS Vision).
    pub async fn connect_record(
        &self,
        tcp: tokio::net::TcpStream,
        fragment: Option<&super::fragment::FragmentConfig>,
    ) -> Result<TlsRecordStream> {
        TlsRecordStream::connect(tcp, self.config.clone(), self.server_name.clone(), fragment).await
    }

    /// Runs the TLS handshake over `stream`.
    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> Result<TlsStream<S>> {
        self.connector
            .connect(self.server_name.clone(), stream)
            .await
            .map_err(|e| Error::Tls(e.to_string()))
    }

    /// [`TlsClient::connect`] for a proxy tunnel: a server that closes the TCP
    /// connection without a close_notify ends the stream instead of failing it.
    pub async fn connect_tunnel<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> Result<CleanEof<TlsStream<S>>> {
        Ok(CleanEof(self.connect(stream).await?))
    }
}

/// A TLS stream on which a TCP close without close_notify reads as the end of the
/// stream, as Go's `crypto/tls` (Xray, sing-box) reports it. rustls calls it an
/// error, which would tear down both directions of a relay at once instead of
/// passing the end on; the tunnelled protocol has its own integrity.
pub struct CleanEof<S>(pub S);

impl<S: AsyncRead + Unpin> AsyncRead for CleanEof<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.0).poll_read(cx, buf) {
            std::task::Poll::Ready(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::trace!("tls: closed without close_notify");
                std::task::Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CleanEof<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, data)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Who is trusted and for which name, beyond the defaults (WebPKI roots, the SNI).
#[derive(Default)]
struct Trust {
    /// Trust only the roots passed in, not the bundled WebPKI ones.
    only_given_roots: bool,
    /// Check the certificate against this name instead of the SNI.
    verify_name: Option<ServerName<'static>>,
    /// Accept any certificate and record its hash ([`probe_leaf_sha256`] only).
    probe: Option<Arc<ProbeVerifier>>,
}

/// Parses hex SHA-256 values (`:` and spaces allowed) of a config field.
fn parse_hashes(field: &str, list: &[String]) -> Result<Vec<[u8; 32]>> {
    list.iter()
        .map(|h| {
            let clean: String = h.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            let bytes = hex::decode(&clean)
                .map_err(|_| Error::config(format!("{field}: invalid hex")))?;
            <[u8; 32]>::try_from(bytes)
                .map_err(|_| Error::config(format!("{field}: expected 32 bytes")))
        })
        .collect()
}

/// Standard WebPKI validation, for a name other than the SNI sent.
#[derive(Debug)]
struct NameVerifier {
    inner: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for NameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, &self.name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Standard WebPKI validation (skipped when `insecure`) AND a match against one of
/// the pinned leaf hashes (when there are any). With `trusted` the leaf must be one
/// of those and is then accepted without the chain and name check.
#[derive(Debug)]
struct PinningVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: Vec<[u8; 32]>,
    trusted: Vec<[u8; 32]>,
    insecure: bool,
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if !self.trusted.is_empty() {
            if !self.trusted.contains(&digest) {
                return Err(rustls::Error::General(
                    "certificate does not match the trusted fingerprint".into(),
                ));
            }
        } else if !self.insecure {
            self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }
        if self.pins.is_empty() || self.pins.contains(&digest) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "certificate does not match pinned_sha256".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Accepts any certificate and keeps the leaf hash once the handshake signature
/// proves the server holds that certificate's key.
#[derive(Debug)]
struct ProbeVerifier {
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
    leaf: std::sync::Mutex<Option<[u8; 32]>>,
}

impl ProbeVerifier {
    fn record(&self, cert: &CertificateDer<'_>) {
        let digest: [u8; 32] = Sha256::digest(cert.as_ref()).into();
        if let Ok(mut leaf) = self.leaf.lock() {
            *leaf = Some(digest);
        }
    }
}

impl ServerCertVerifier for ProbeVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let ok = rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)?;
        self.record(cert);
        Ok(ok)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let ok = rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)?;
        self.record(cert);
        Ok(ok)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// The longest a probe's handshake may take (a backstop; the caller sets its own timeout).
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Handshakes over `stream` and returns the SHA-256 of the server's leaf certificate
/// (DER) for the user to trust (`trusted_sha256`). Any certificate is accepted here,
/// and only here: the handshake signature must still prove the key, and no data is
/// sent. The stream is dropped on return. `fingerprint` is a `fp` name, `alpn` the
/// protocols offered.
pub async fn probe_leaf_sha256<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    server_name: &str,
    fingerprint: Option<&str>,
    alpn: &[String],
) -> Result<[u8; 32]> {
    let cfg = TlsConfig {
        enabled: true,
        sni: Some(server_name.to_string()),
        alpn: alpn.to_vec(),
        pinned_sha256: Vec::new(),
        trusted_sha256: Vec::new(),
        allow_insecure: false,
        fingerprint: fingerprint.map(String::from),
    };
    let provider = match Fingerprint::from_name(fingerprint)? {
        Some(fp) => fp.provider(),
        None => rustls::crypto::ring::default_provider(),
    };
    let verifier = Arc::new(ProbeVerifier {
        algs: provider.signature_verification_algorithms,
        leaf: std::sync::Mutex::new(None),
    });
    let trust = Trust {
        probe: Some(verifier.clone()),
        ..Trust::default()
    };
    let client = TlsClient::build(&cfg, server_name, Vec::new(), &trust)?;
    tokio::time::timeout(PROBE_TIMEOUT, client.connect(stream))
        .await
        .map_err(|_| Error::Tls("fingerprint probe timed out".into()))??;
    verifier
        .leaf
        .lock()
        .ok()
        .and_then(|leaf| *leaf)
        .ok_or_else(|| Error::Tls("the server sent no verifiable certificate".into()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A TLS server that sends "hello" and drops the TCP connection without a
    /// close_notify, as a server behind a broken middlebox or fallback can.
    async fn abrupt_server() -> (std::net::SocketAddr, CertificateDer<'static>) {
        abrupt_server_on("127.0.0.1:0").await
    }

    async fn abrupt_server_on(bind: &str) -> (std::net::SocketAddr, CertificateDer<'static>) {
        let ck = rcgen::generate_simple_self_signed(vec!["abrupt.test".into()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::try_from(ck.signing_key.serialize_der()).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind(bind).await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let Ok(mut tls) = acceptor.accept(s).await else { continue };
                // The client may have hung up already.
                let _ = tls.write_all(b"hello").await;
                let _ = tls.flush().await;
                // Close the socket itself: no close_notify.
                let (tcp, _) = tls.into_inner();
                drop(tcp);
            }
        });
        (addr, cert)
    }

    /// `allow_insecure` takes an untrusted certificate for another name; a pin still holds.
    #[tokio::test]
    async fn allow_insecure_skips_verification_but_not_pins() {
        let (addr, cert) = abrupt_server().await;
        let mut cfg = TlsConfig {
            enabled: true,
            sni: Some("127.0.0.1".into()),
            alpn: Vec::new(),
            pinned_sha256: Vec::new(),
            allow_insecure: false,
            trusted_sha256: Vec::new(),
            fingerprint: Some("chrome".into()),
        };
        let connect = |cfg: TlsConfig| async move {
            let client = TlsClient::new(&cfg, "127.0.0.1").unwrap();
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            client.connect_tunnel(tcp).await.map(|_| ())
        };
        let e = connect(cfg.clone()).await.unwrap_err().to_string();
        assert!(e.contains("certificate"), "{e}");
        cfg.allow_insecure = true;
        connect(cfg.clone()).await.unwrap();
        cfg.pinned_sha256 = vec!["00".repeat(32)];
        let e = connect(cfg.clone()).await.unwrap_err().to_string();
        assert!(e.contains("pinned"), "{e}");
        cfg.pinned_sha256 = vec![hex::encode(Sha256::digest(cert.as_ref()))];
        connect(cfg).await.unwrap();
    }

    fn trust_cfg(sni: &str, trusted: Vec<String>, pinned: Vec<String>, fp: Option<&str>) -> TlsConfig {
        TlsConfig {
            enabled: true,
            sni: Some(sni.into()),
            alpn: Vec::new(),
            pinned_sha256: pinned,
            trusted_sha256: trusted,
            allow_insecure: false,
            fingerprint: fp.map(String::from),
        }
    }

    async fn try_connect(addr: std::net::SocketAddr, cfg: &TlsConfig) -> Result<()> {
        let client = TlsClient::new(cfg, "unused.test")?;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.connect_tunnel(tcp).await.map(|_| ())
    }

    fn sha(cert: &CertificateDer<'_>) -> String {
        hex::encode(Sha256::digest(cert.as_ref()))
    }

    /// A trusted fingerprint takes a foreign certificate by IP and by name; anything
    /// else is refused, and `pinned_sha256` still has to match as well.
    #[tokio::test]
    async fn trusted_sha256_accepts_exactly_that_leaf() {
        let (addr, cert) = abrupt_server().await;
        let good = sha(&cert);
        for fp in [None, Some("firefox")] {
            for sni in ["127.0.0.1", "other.example"] {
                let e = try_connect(addr, &trust_cfg(sni, vec![], vec![], fp)).await.unwrap_err();
                assert!(e.to_string().contains("certificate"), "{e}");
                try_connect(addr, &trust_cfg(sni, vec![good.clone()], vec![], fp)).await.unwrap();
                // Colons and case are fine.
                let colons = good
                    .as_bytes()
                    .chunks(2)
                    .map(|c| std::str::from_utf8(c).unwrap().to_uppercase())
                    .collect::<Vec<_>>()
                    .join(":");
                try_connect(addr, &trust_cfg(sni, vec![colons], vec![], fp)).await.unwrap();
                let e = try_connect(addr, &trust_cfg(sni, vec!["00".repeat(32)], vec![], fp))
                    .await
                    .unwrap_err();
                assert!(e.to_string().contains("does not match the trusted fingerprint"), "{e}");
            }
        }
        // Trusted and pinned must both match.
        let e = try_connect(
            addr,
            &trust_cfg("127.0.0.1", vec![good.clone()], vec!["11".repeat(32)], None),
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("pinned"), "{e}");
        try_connect(addr, &trust_cfg("127.0.0.1", vec![good.clone()], vec![good.clone()], None))
            .await
            .unwrap();
        // Bad values are config errors.
        for bad in ["zz", "abcd"] {
            let e = TlsClient::new(&trust_cfg("a.test", vec![bad.into()], vec![], None), "a.test")
                .unwrap_err();
            assert!(e.to_string().contains("trusted_sha256"), "{e}");
        }
    }

    #[tokio::test]
    async fn trusted_sha256_over_ipv6() {
        let Ok(l) = std::net::TcpListener::bind("[::1]:0") else { return };
        drop(l);
        let (addr, cert) = abrupt_server_on("[::1]:0").await;
        let cfg = trust_cfg("::1", vec![sha(&cert)], vec![], None);
        try_connect(addr, &cfg).await.unwrap();
        let cfg = trust_cfg("::1", vec!["00".repeat(32)], vec![], None);
        try_connect(addr, &cfg).await.unwrap_err();
    }

    #[tokio::test]
    async fn probe_returns_the_leaf_sha256() {
        let (addr, cert) = abrupt_server().await;
        for fp in [None, Some("chrome")] {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let got = probe_leaf_sha256(tcp, "127.0.0.1", fp, &[]).await.unwrap();
            assert_eq!(hex::encode(got), sha(&cert));
        }
        // And what it returns is what `trusted_sha256` takes.
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let got = probe_leaf_sha256(tcp, "x.example", None, &["h2".to_string()]).await.unwrap();
        try_connect(addr, &trust_cfg("x.example", vec![hex::encode(got)], vec![], None))
            .await
            .unwrap();
        // A server that is no TLS server is an error, not a hang.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request

").await;
            }
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        probe_leaf_sha256(tcp, "127.0.0.1", None, &[]).await.unwrap_err();
    }

    #[tokio::test]
    async fn a_close_without_close_notify_ends_a_tunnel_cleanly() {
        let (addr, cert) = abrupt_server().await;
        let cfg = TlsConfig {
            enabled: true,
            sni: Some("abrupt.test".into()),
            alpn: Vec::new(),
            pinned_sha256: Vec::new(),
            allow_insecure: false,
            trusted_sha256: Vec::new(),
            fingerprint: None,
        };
        let client = TlsClient::with_extra_roots(&cfg, "abrupt.test", vec![cert]).unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut s = client.connect_tunnel(tcp).await.unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello");
        // rustls alone calls it an error.
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut s = client.connect(tcp).await.unwrap();
        let mut got = Vec::new();
        let e = s.read_to_end(&mut got).await.unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
