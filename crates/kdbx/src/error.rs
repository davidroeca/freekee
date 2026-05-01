//! Error types for KDBX I/O.
//!
//! No variant carries plaintext passphrase, keyfile, or decrypted entry
//! material. Upstream `keepass` errors are mapped onto a fixed set of
//! categories so a future upstream `Display` change cannot leak secrets
//! into our error stream.

use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("i/o error reading or writing KDBX file")]
    Io(#[from] std::io::Error),

    #[error("malformed KDBX file")]
    Format,

    #[error("authentication failed")]
    Authentication,

    #[error("integrity check failed")]
    IntegrityCheck,

    #[error("unsupported KDBX version")]
    UnsupportedVersion,

    #[error("entry or group not found")]
    NotFound,

    #[error("entry or group already exists at the requested path")]
    AlreadyExists,

    #[error("invalid path: empty title or group segment")]
    InvalidPath,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<keepass::error::DatabaseOpenError> for Error {
    fn from(err: keepass::error::DatabaseOpenError) -> Self {
        use keepass::error::DatabaseOpenError as E;
        match err {
            E::Io(e) => Error::Io(e),
            E::UnexpectedEof => Error::Format,
            E::VersionParse(_) => Error::Format,
            E::UnsupportedVersion => Error::UnsupportedVersion,
            E::Key(_) => Error::Authentication,
            E::Cryptography(_) => Error::IntegrityCheck,
            E::Format(_) => Error::Format,
            // `DatabaseOpenError` is `#[non_exhaustive]`. New variants
            // are mapped conservatively to `Format` until we triage them.
            _ => Error::Format,
        }
    }
}

impl From<keepass::error::DatabaseSaveError> for Error {
    fn from(err: keepass::error::DatabaseSaveError) -> Self {
        use keepass::error::DatabaseSaveError as E;
        match err {
            E::Io(e) => Error::Io(e),
            E::UnsupportedVersion => Error::UnsupportedVersion,
            // Serialization, Key, Cryptography, Random - none should
            // include passphrase material, but we map without embedding
            // upstream Display strings to be safe against future churn.
            _ => Error::Format,
        }
    }
}
