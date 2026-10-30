/// Error types for the IP stack.
///
/// This enum represents all possible errors that can occur when working with the IP stack.
#[derive(thiserror::Error, Debug)]
pub enum IpStackError {
    /// The transport protocol is not supported.
    #[error("The transport protocol is not supported")]
    UnsupportedTransportProtocol,

    /// The packet is invalid or malformed.
    #[error("The packet is invalid")]
    InvalidPacket,

    /// A value is too large to fit in a u16.
    #[error("ValueTooBigError<u16> {0}")]
    ValueTooBigErrorU16(#[from] etherparse::err::ValueTooBigError<u16>),

    /// A value is too large to fit in a usize.
    #[error("ValueTooBigError<usize> {0}")]
    ValueTooBigErrorUsize(#[from] etherparse::err::ValueTooBigError<usize>),

    /// The TCP packet is invalid.
    #[error("Invalid Tcp packet")]
    InvalidTcpPacket,

    /// An I/O error occurred.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Error accepting a new stream.
    #[error("Accept Error")]
    AcceptError,

    /// Error sending data through a channel.
    #[error("Send Error {0}")]
    SendError(#[from] Box<tokio::sync::mpsc::error::SendError<crate::stream::IpStackStream>>),

    /// Invalid MTU size. The minimum MTU is 1280 bytes to comply with IPv6 standards.
    #[error("Invalid MTU size: {0} (bytes). Minimum MTU is 1280 bytes.")]
    InvalidMtuSize(u16),
}

impl From<tokio::sync::mpsc::error::SendError<crate::stream::IpStackStream>> for IpStackError {
    fn from(e: tokio::sync::mpsc::error::SendError<crate::stream::IpStackStream>) -> Self {
        IpStackError::SendError(Box::new(e))
    }
}

// Safety: All variants of IpStackError either contain no data or wrap types that are `Send`.
// This ensures that IpStackError as a whole is safe to send between threads.
unsafe impl Send for IpStackError {}

// Safety: All variants of IpStackError either contain no data or wrap types that are `Sync`.
// This ensures that IpStackError as a whole is safe to share between threads.
unsafe impl Sync for IpStackError {}

impl From<IpStackError> for std::io::Error {
    fn from(e: IpStackError) -> Self {
        match e {
            IpStackError::IoError(e) => e,
            _ => std::io::Error::other(e),
        }
    }
}

/// A specialized [`Result`] type for IP stack operations.
///
/// This type is used throughout the IP stack for any operation which may produce an error.
///
/// [`Result`]: std::result::Result
pub type Result<T, E = IpStackError> = std::result::Result<T, E>;
