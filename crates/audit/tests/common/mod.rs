// Each integration test target compiles `common` independently, so
// items used by only one of them look "dead" to the other.
#![allow(dead_code)]

use keepass::config::{DatabaseConfig, KdfConfig};

/// Build a `kdbx::Database` whose underlying `keepass::Database` has
/// `cfg` mutated by the caller. No file I/O, no Argon2 cost.
pub fn db(mutate: impl FnOnce(&mut DatabaseConfig)) -> kdbx::Database {
    let mut inner = keepass::Database::new();
    mutate(&mut inner.config);
    kdbx::Database::__from_keepass(inner)
}

/// An Argon2id KDF that satisfies all of the strict default
/// thresholds (memory ≥ 64 MiB, iterations ≥ 2, parallelism ≥ 2).
pub fn strong_kdf() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 10,
        memory: 64 * 1024 * 1024,
        parallelism: 2,
        version: argon2::Version::Version13,
    }
}

/// `keepass-rs`'s default-config KDF (Argon2 with weak parameters).
/// Useful when a test wants to leave KDF at upstream defaults.
pub fn default_kdf() -> KdfConfig {
    DatabaseConfig::default().kdf_config
}
