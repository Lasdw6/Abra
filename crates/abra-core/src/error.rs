//! The one error type for `abra-core`.

use std::path::PathBuf;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("io error: {0}")]
    BareIo(#[source] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A hex/base64 string was not the expected shape or length.
    #[error("malformed {kind}: {detail}")]
    Encoding { kind: &'static str, detail: String },

    /// A stored object is missing.
    #[error("{kind} not found: {id}")]
    NotFound { kind: &'static str, id: String },

    /// A stored object is present but does not decode.
    #[error("corrupt {kind}: {detail}")]
    Corrupt { kind: &'static str, detail: String },

    /// A manifest, cert, or path violated the spec.
    #[error("invalid: {0}")]
    Invalid(String),

    /// An unsupported `spec` version was encountered.
    #[error("unsupported spec {found:?}, this build implements {expected:?}")]
    UnsupportedSpec { found: String, expected: String },

    #[error("signature verification failed: {0}")]
    BadSignature(String),
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn encoding(kind: &'static str, detail: impl Into<String>) -> Self {
        Error::Encoding {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) fn not_found(kind: &'static str, id: impl Into<String>) -> Self {
        Error::NotFound {
            kind,
            id: id.into(),
        }
    }

    pub(crate) fn corrupt(kind: &'static str, detail: impl Into<String>) -> Self {
        Error::Corrupt {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) fn invalid(detail: impl Into<String>) -> Self {
        Error::Invalid(detail.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::BareIo(e)
    }
}
