//! Deterministic JSON snapshot of a parsed database. Used by both the
//! `dump-expected` helper binary (to regenerate `expected.json` next
//! to each fixture) and the golden test that asserts the committed
//! snapshot still matches what the parser produces.
//!
//! Volatile fields (timestamps, randomly-generated UUIDs) are omitted
//! so the snapshot survives a lossless re-save. The deeper structural
//! equivalence is asserted by `Database`'s `PartialEq` in the round-
//! trip harness; this snapshot's job is to catch version, cipher,
//! KDF, and gross structural drift.

// `serde_json::json!` expands with `.unwrap()` on infallible branches,
// which trips our disallowed-methods lint.
#![allow(clippy::disallowed_methods)]

use crate::{Database, KdbxVersion, Kdf, OuterCipher};

/// Build the canonical snapshot for a parsed database. Output is
/// stable across runs of the same parser version.
pub fn expected_snapshot(db: &Database) -> serde_json::Value {
    serde_json::json!({
        "kdbx_version": kdbx_version_str(db),
        "outer_cipher": outer_cipher_str(db),
        "kdf": kdf_json(db),
        "root_entry_count": db.root_entry_count(),
        "root_subgroup_count": db.root_subgroup_count(),
    })
}

fn kdbx_version_str(db: &Database) -> String {
    match db.kdbx_version() {
        KdbxVersion::Kdb1 => "kdb1".to_owned(),
        KdbxVersion::Kdb2(m) => format!("kdb2.{m}"),
        KdbxVersion::Kdb3(m) => format!("kdb3.{m}"),
        KdbxVersion::Kdb4(m) => format!("kdb4.{m}"),
    }
}

fn outer_cipher_str(db: &Database) -> &'static str {
    match db.outer_cipher() {
        OuterCipher::Aes256 => "aes-256",
        OuterCipher::Twofish => "twofish",
        OuterCipher::ChaCha20 => "chacha20",
    }
}

fn kdf_json(db: &Database) -> serde_json::Value {
    match db.kdf() {
        Kdf::Aes { rounds } => serde_json::json!({ "type": "aes-kdf", "rounds": rounds }),
        Kdf::Argon2d {
            iterations,
            memory,
            parallelism,
        } => serde_json::json!({
            "type": "argon2d",
            "iterations": iterations,
            "memory_bytes": memory,
            "parallelism": parallelism,
        }),
        Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } => serde_json::json!({
            "type": "argon2id",
            "iterations": iterations,
            "memory_bytes": memory,
            "parallelism": parallelism,
        }),
    }
}
