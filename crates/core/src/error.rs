//! Error type for the `core` orchestrator.
//!
//! Wraps the underlying `kdbx::Error` so callers don't have to know
//! about the lower layer. As with `kdbx`, no variant carries
//! plaintext passphrases, derived keys, or entry values.

use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("kdbx layer error")]
    Kdbx(#[from] kdbx::Error),

    #[error("i/o error")]
    Io(#[from] std::io::Error),

    #[error("entry or group not found")]
    NotFound,

    #[error("file already exists at the destination; pass --force to overwrite")]
    FileExists,

    #[error("invalid passphrase: empty")]
    EmptyPassphrase,

    #[error(
        "rotation verification failed: post-save reopen did not decrypt with the new credentials"
    )]
    RotationVerificationFailed,

    #[error("at least one rotation target must be specified")]
    NoRotationTarget,
}

pub type Result<T> = std::result::Result<T, Error>;
