//! KDF rules. See `docs/design.md` section 7.1.

use crate::{AuditConfig, Category, Finding, Severity};
use kdbx::Kdf;

pub fn legacy_kdf(db: &kdbx::Database) -> Option<Finding> {
    match db.kdf() {
        Kdf::Aes { .. } => Some(Finding {
            rule: "legacy-kdf",
            severity: Severity::High,
            category: Category::CipherFormat,
            message:
                "Database uses AES-KDF for key derivation. Argon2id provides better resistance \
                 to GPU/ASIC attacks and is the current KeePass recommendation."
                    .into(),
            citation: "https://keepass.info/help/kb/kdbx_4.html",
            remediation: "freekee rotate kdf <path> --to argon2id".into(),
        }),
        Kdf::Argon2d { .. } | Kdf::Argon2id { .. } => None,
    }
}

pub fn weak_argon2_params(db: &kdbx::Database, config: &AuditConfig) -> Option<Finding> {
    let (iterations, memory, parallelism) = match db.kdf() {
        Kdf::Argon2d {
            iterations,
            memory,
            parallelism,
        }
        | Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } => (iterations, memory, parallelism),
        // AES-KDF is handled by `legacy_kdf`; nothing to add here.
        Kdf::Aes { .. } => return None,
    };

    let mut reasons = Vec::new();
    if memory < config.weak_argon2_memory_bytes {
        reasons.push(format!(
            "memory={} bytes (< {} bytes)",
            memory, config.weak_argon2_memory_bytes
        ));
    }
    if iterations < config.weak_argon2_iters {
        reasons.push(format!(
            "iterations={} (< {})",
            iterations, config.weak_argon2_iters
        ));
    }
    if parallelism < config.weak_argon2_parallelism {
        reasons.push(format!(
            "parallelism={} (< {})",
            parallelism, config.weak_argon2_parallelism
        ));
    }

    if reasons.is_empty() {
        return None;
    }

    Some(Finding {
        rule: "weak-argon2-params",
        severity: Severity::Medium,
        category: Category::CipherFormat,
        message: format!(
            "Argon2 parameters below recommended floor: {}.",
            reasons.join(", ")
        ),
        citation: "https://keepass.info/help/kb/kdbx_4.html",
        remediation:
            "freekee rotate kdf-params <path> --memory 65536 --iterations 10 --parallelism 2".into(),
    })
}
