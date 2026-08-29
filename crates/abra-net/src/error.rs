#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("core: {0}")]
    Core(#[from] abra_core::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("authentication: {0}")]
    Authentication(String),
    #[error("authorization: {0}")]
    Authorization(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("timeout")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn protocol(s: impl Into<String>) -> Self {
        Self::Protocol(s.into())
    }
    pub(crate) fn authz(s: impl Into<String>) -> Self {
        Self::Authorization(s.into())
    }
}
