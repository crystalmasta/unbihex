use std::io;

/// Engine errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid configuration.
    #[error("config: {0}")]
    Config(String),
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// A feature the engine does not implement yet.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Refused by a block outbound.
    #[error("blocked by rule")]
    Blocked,
    /// The destination is the engine itself or a loopback address the client may not reach.
    #[error("forbidden destination: {0}")]
    Forbidden(String),
    /// The peer violated a protocol.
    #[error("protocol: {0}")]
    Protocol(String),
    /// A deadline passed.
    #[error("timed out")]
    Timeout,
    /// Name resolution failed.
    #[error("dns: {0}")]
    Dns(String),
    /// TLS handshake or verification failed.
    #[error("tls: {0}")]
    Tls(String),
    /// The platform refused to protect a socket from the VPN.
    #[error("socket protect callback rejected the socket")]
    Protect,
    /// The TUN device failed.
    #[error("tun: {0}")]
    Tun(String),
    /// An OS-level operation failed.
    #[error("platform: {0}")]
    Platform(String),
}

/// Result with [`Error`] as the default error.
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// Shorthand for [`Error::Config`].
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }
    /// Shorthand for [`Error::Protocol`].
    pub fn protocol(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }
}

impl From<tokio::time::error::Elapsed> for Error {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Error::Timeout
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            Error::Timeout => io::Error::new(io::ErrorKind::TimedOut, "timed out"),
            other => io::Error::other(other.to_string()),
        }
    }
}
