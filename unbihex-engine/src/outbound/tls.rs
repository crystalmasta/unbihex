//! TLS client (SPEC §11.4): rustls + ring + webpki roots, optional leaf pinning, and a
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
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient")
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl TlsClient {
    /// Builds a client trusting the bundled WebPKI roots.
    pub fn new(cfg: &TlsConfig, default_sni: &str) -> Result<TlsClient> {
        Self::build(cfg, default_sni, Vec::new())
    }

    /// Test-only: trust additional roots (e.g. a self-signed test CA).
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_extra_roots(
        cfg: &TlsConfig,
        default_sni: &str,
        roots: Vec<CertificateDer<'static>>,
    ) -> Result<TlsClient> {
        Self::build(cfg, default_sni, roots)
    }

    fn build(
        cfg: &TlsConfig,
        default_sni: &str,
        extra_roots: Vec<CertificateDer<'static>>,
    ) -> Result<TlsClient> {
        let fingerprint = Fingerprint::from_name(cfg.fingerprint.as_deref());
        let provider = Arc::new(match fingerprint {
            Some(fp) => fp.provider(),
            None => rustls::crypto::ring::default_provider(),
        });
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for r in extra_roots {
            roots.add(r).map_err(|e| Error::Tls(e.to_string()))?;
        }
        let roots = Arc::new(roots);

        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Tls(e.to_string()))?;
        let mut config = if cfg.pinned_sha256.is_empty() {
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
        })
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
