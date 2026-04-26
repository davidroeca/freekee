// `serde_json::json!` expands to `.unwrap()` internally on infallible
// branches, which trips our disallowed-methods lint. The unwraps are
// safe because the JSON shape is static.
#![allow(clippy::disallowed_methods)]

//! Emit a deterministic JSON snapshot of a KDBX file's structural
//! properties. Used to commit `expected.json` next to each fixture in
//! `tests/roundtrip/fixtures/`.
//!
//! Volatile fields (timestamps, randomly-generated UUIDs) are omitted
//! so the snapshot survives a lossless re-save. Deeper structural
//! equivalence is asserted by `Database`'s `PartialEq` in the test
//! harness; this snapshot's job is to catch version/cipher/KDF drift
//! and gross structural changes that would otherwise be invisible.
//!
//! Usage:
//!   echo "<password>" | dump-expected <path-to-db.kdbx>

use std::io::BufRead;
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            eprintln!("usage: dump-expected <path-to-db.kdbx>");
            return ExitCode::from(2);
        }
    };

    let mut password = String::new();
    if let Err(e) = std::io::stdin().lock().read_line(&mut password) {
        eprintln!("dump-expected: read password from stdin: {e}");
        return ExitCode::from(2);
    }
    let password = password.trim_end_matches('\n').trim_end_matches('\r');

    let db = match kdbx::Database::open(&path, password) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("dump-expected: {e}");
            return ExitCode::from(1);
        }
    };

    let snapshot = serde_json::json!({
        "kdbx_version": kdbx_version_str(&db),
        "outer_cipher": outer_cipher_str(&db),
        "kdf": kdf_json(&db),
        "root_entry_count": db.root_entry_count(),
        "root_subgroup_count": db.root_subgroup_count(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&snapshot).expect("snapshot is always serializable"),
    );
    ExitCode::SUCCESS
}

fn kdbx_version_str(db: &kdbx::Database) -> String {
    use kdbx::KdbxVersion;
    match db.kdbx_version() {
        KdbxVersion::Kdb1 => "kdb1".to_owned(),
        KdbxVersion::Kdb2(m) => format!("kdb2.{m}"),
        KdbxVersion::Kdb3(m) => format!("kdb3.{m}"),
        KdbxVersion::Kdb4(m) => format!("kdb4.{m}"),
    }
}

fn outer_cipher_str(db: &kdbx::Database) -> &'static str {
    use kdbx::OuterCipher;
    match db.outer_cipher() {
        OuterCipher::Aes256 => "aes-256",
        OuterCipher::Twofish => "twofish",
        OuterCipher::ChaCha20 => "chacha20",
    }
}

fn kdf_json(db: &kdbx::Database) -> serde_json::Value {
    use kdbx::Kdf;
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
