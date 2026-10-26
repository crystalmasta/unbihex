use serde::{Serialize, ser::Serializer};

/// Plugin result.
pub type Result<T> = std::result::Result<T, Error>;

/// Plugin errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The native side rejected the call (permission denied, OS error…).
    #[cfg(mobile)]
    #[error(transparent)]
    PluginInvoke(#[from] tauri::plugin::mobile::PluginInvokeError),
    /// Not available on this platform.
    #[error("{0}")]
    Unsupported(&'static str),
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.to_string().as_ref())
    }
}
