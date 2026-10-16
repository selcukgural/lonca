use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("git: {0}")]
    Git(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("integrity: {0}")]
    Integrity(String),
    #[error("conflict: {0}")]
    Conflict(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn git<E: std::fmt::Display>(e: E) -> Error {
    Error::Git(e.to_string())
}
