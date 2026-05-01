//! freekee orchestrator. Composes `kdbx` and `audit`. All CLI and
//! tauri-bridge code talks to this layer; only `core` knows about
//! `kdbx` and `audit` directly (per `docs/design.md` section 5).

pub mod backup;
mod error;
pub mod password;
mod vault;

pub use backup::BackupOutcome;
pub use error::{Error, Result};
pub use password::{Alphabet, PasswordPolicy};
pub use vault::{RotateOpts, Vault};

/// Defaults applied to a database created via [`Vault::create`] when
/// the caller doesn't override them. Chosen to match KeePassXC's
/// current defaults so freekee-created files round-trip cleanly with
/// the wider ecosystem:
///
/// - Outer cipher: AES-256 (hardware-accelerated on Linux x86_64 and
///   Apple Silicon; PQ-equivalent to ChaCha20 under Grover, both
///   ~128-bit effective).
/// - Inner cipher: ChaCha20.
/// - KDF: Argon2id with memory = 64 MiB, iterations = 10,
///   parallelism = 2. Per-platform auto-tuning is M2.
pub const DEFAULT_TEMPLATE: kdbx::NewDatabaseTemplate = kdbx::NewDatabaseTemplate {
    kdf: kdbx::Argon2idParams {
        memory: 64 * 1024 * 1024,
        iterations: 10,
        parallelism: 2,
    },
    outer_cipher: kdbx::OuterCipher::Aes256,
    inner_cipher: kdbx::InnerCipher::ChaCha20,
};
