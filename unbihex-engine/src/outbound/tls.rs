//! TLS client (SPEC §11.2): rustls + ring + webpki roots, optional leaf pinning, and a
//! browser ClientHello (`fingerprint`). Certificate verification can never be disabled.

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
        } else if cfg.pinned_sha256.is_empty() {
            builder.with_root_certificates(roots).with_no_client_auth()
        } else {
            let pins = cfg
                .pinned_sha256
                .iter()
                .map(|h| {
                    let clean: String = h.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                    let bytes = hex::decode(&clean)
                        .map_err(|_| Error::config("pinned_sha256: invalid hex"))?;
                    <[u8; 32]>::try_from(bytes)
                        .map_err(|_| Error::config("pinned_sha256: expected 32 bytes"))
                })
                .collect::<Result<Vec<_>>>()?;
            let inner = WebPkiServerVerifier::builder_with_provider(roots, provider)
                .build()
                .map_err(|e| Error::Tls(e.to_string()))?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinningVerifier { inner, pins }))
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

/// Standard WebPKI validation AND a match against one of the pinned leaf hashes.
#[derive(Debug)]
struct PinningVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: Vec<[u8; 32]>,
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
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self.pins.contains(&digest) {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A TLS server that sends "hello" and drops the TCP connection without a
    /// close_notify, as a server behind a broken middlebox or fallback can.
    async fn abrupt_server() -> (std::net::SocketAddr, CertificateDer<'static>) {
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
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let mut tls = acceptor.accept(s).await.unwrap();
                tls.write_all(b"hello").await.unwrap();
                tls.flush().await.unwrap();
                // Close the socket itself: no close_notify.
                let (tcp, _) = tls.into_inner();
                drop(tcp);
            }
        });
        (addr, cert)
    }

    #[tokio::test]
    async fn a_close_without_close_notify_ends_a_tunnel_cleanly() {
        let (addr, cert) = abrupt_server().await;
        let cfg = TlsConfig {
            enabled: true,
            sni: Some("abrupt.test".into()),
            alpn: Vec::new(),
            pinned_sha256: Vec::new(),
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
