//! Client errors. Messages are shown to the user as is, so they are in Russian.

/// Everything that can go wrong in the client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The engine refused the config or failed to start.
    #[error("ядро: {0}")]
    Engine(#[from] unbihex_engine::Error),
    /// Downloading a subscription failed.
    #[error("подписка: {0}")]
    Subscription(String),
    /// Nothing usable in the user's input.
    #[error("{0}")]
    Input(String),
    /// Unknown subscription or server id.
    #[error("не найдено: {0}")]
    NotFound(String),
    /// The server cannot be used by the engine.
    #[error("сервер не поддерживается ядром: {0}")]
    Unsupported(String),
    /// An OS-level operation (routes, proxy, permissions) failed.
    #[error("система: {0}")]
    Platform(String),
    /// Reading or writing the state file failed.
    #[error("файл: {0}")]
    Io(#[from] std::io::Error),
    /// The state file is damaged.
    #[error("данные: {0}")]
    Json(#[from] serde_json::Error),
    /// Already connected / not connected.
    #[error("{0}")]
    State(String),
}

/// Result with [`ClientError`].
pub type Result<T, E = ClientError> = std::result::Result<T, E>;

impl ClientError {
    /// Shorthand for [`ClientError::Platform`].
    pub fn platform(msg: impl Into<String>) -> Self {
        ClientError::Platform(msg.into())
    }
}
