//! Audit rule tests. In-memory fixtures only (no file I/O, no Argon2
//! cost). Per `docs/design.md` §7 and milestone-0 plan §6.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use audit::{AuditConfig, Severity};
use keepass::config::{DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig};

mod common;
use common::{db, strong_kdf};

// `zxcvbn-rs` 3.1.1 saturates `guesses_log10` at ~19.27 (≈64 bits) so
// any sufficiently complex 25+ char password reads as 64.0 bits. That
// is comfortably above the 60-bit default threshold.
const STRONG_PASSPHRASE: &str = "qWk3@p9Lnv8Z2!Mrx7&fE$Bc1";
const WEAK_PASSPHRASE: &str = "password1";

#[test]
fn strong_database_yields_no_findings() {
    let database = db(|cfg| {
        cfg.outer_cipher_config = OuterCipherConfig::ChaCha20;
        cfg.kdf_config = strong_kdf();
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    assert_eq!(findings, vec![], "no findings expected; got {findings:?}");
}

// ─── A1: weak-outer-cipher ────────────────────────────────────────────────

#[test]
fn flags_twofish_outer_cipher() {
    let database = db(|cfg| {
        cfg.outer_cipher_config = OuterCipherConfig::Twofish;
        cfg.kdf_config = strong_kdf();
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    let f = findings
        .iter()
        .find(|f| f.rule == "weak-outer-cipher")
        .expect("expected weak-outer-cipher finding");
    assert_eq!(f.severity, Severity::Medium);
    assert!(!f.remediation.is_empty(), "remediation must be populated");
    assert!(!f.citation.is_empty(), "citation must be populated");
}

#[test]
fn does_not_flag_aes256_outer_cipher() {
    let database = db(|cfg| {
        cfg.outer_cipher_config = OuterCipherConfig::AES256;
        cfg.kdf_config = strong_kdf();
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    assert!(!findings.iter().any(|f| f.rule == "weak-outer-cipher"));
}

// ─── A2: legacy-stream-cipher ─────────────────────────────────────────────

#[test]
fn flags_salsa20_inner_cipher() {
    let database = db(|cfg| {
        cfg.inner_cipher_config = InnerCipherConfig::Salsa20;
        cfg.kdf_config = strong_kdf();
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    let f = findings
        .iter()
        .find(|f| f.rule == "legacy-stream-cipher")
        .expect("expected legacy-stream-cipher finding");
    assert_eq!(f.severity, Severity::Medium);
    assert!(!f.remediation.is_empty(), "remediation must be populated");
    assert!(!f.citation.is_empty(), "citation must be populated");
}

#[test]
fn does_not_flag_chacha20_inner_cipher() {
    let database = db(|cfg| {
        cfg.inner_cipher_config = InnerCipherConfig::ChaCha20;
        cfg.kdf_config = strong_kdf();
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    assert!(!findings.iter().any(|f| f.rule == "legacy-stream-cipher"));
}

// ─── A3: legacy-kdf ───────────────────────────────────────────────────────

#[test]
fn flags_aes_kdf() {
    let database = db(|cfg| {
        cfg.kdf_config = KdfConfig::Aes { rounds: 100_000 };
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    let f = findings
        .iter()
        .find(|f| f.rule == "legacy-kdf")
        .expect("expected legacy-kdf finding");
    assert_eq!(f.severity, Severity::High);
    assert!(f.remediation.contains("argon2id"));
}

#[test]
fn does_not_flag_argon2id() {
    let database = db(|cfg| {
        cfg.kdf_config = strong_kdf();
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    assert!(!findings.iter().any(|f| f.rule == "legacy-kdf"));
}

// ─── A4: weak-argon2-params ───────────────────────────────────────────────

#[test]
fn flags_weak_argon2_memory() {
    let database = db(|cfg| {
        cfg.kdf_config = KdfConfig::Argon2id {
            iterations: 10,
            memory: 1024 * 1024, // 1 MiB << 64 MiB threshold
            parallelism: 2,
            version: argon2::Version::Version13,
        };
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    let f = findings
        .iter()
        .find(|f| f.rule == "weak-argon2-params")
        .expect("expected weak-argon2-params finding");
    assert!(f.message.contains("memory"));
}

#[test]
fn flags_weak_argon2_iterations() {
    let database = db(|cfg| {
        cfg.kdf_config = KdfConfig::Argon2id {
            iterations: 1,
            memory: 64 * 1024 * 1024,
            parallelism: 2,
            version: argon2::Version::Version13,
        };
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    let f = findings
        .iter()
        .find(|f| f.rule == "weak-argon2-params")
        .expect("expected weak-argon2-params finding");
    assert!(f.message.contains("iterations"));
}

#[test]
fn flags_weak_argon2_parallelism() {
    let database = db(|cfg| {
        cfg.kdf_config = KdfConfig::Argon2id {
            iterations: 10,
            memory: 64 * 1024 * 1024,
            parallelism: 1,
            version: argon2::Version::Version13,
        };
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    let f = findings
        .iter()
        .find(|f| f.rule == "weak-argon2-params")
        .expect("expected weak-argon2-params finding");
    assert!(f.message.contains("parallelism"));
}

#[test]
fn does_not_flag_strong_argon2() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    assert!(!findings.iter().any(|f| f.rule == "weak-argon2-params"));
}

// ─── A5: legacy-kdbx-version ──────────────────────────────────────────────

#[test]
fn flags_kdbx3_version() {
    let database = db(|cfg| {
        cfg.version = DatabaseVersion::KDB3(1);
        cfg.kdf_config = strong_kdf();
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    let f = findings
        .iter()
        .find(|f| f.rule == "legacy-kdbx-version")
        .expect("expected legacy-kdbx-version finding");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn does_not_flag_kdbx4_version() {
    let database = db(|cfg| {
        cfg.version = DatabaseVersion::KDB4(1);
        cfg.kdf_config = strong_kdf();
    });
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    assert!(!findings.iter().any(|f| f.rule == "legacy-kdbx-version"));
}

// ─── A6: weak-passphrase ──────────────────────────────────────────────────

#[test]
fn flags_weak_passphrase() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    let findings = audit::run(&database, WEAK_PASSPHRASE, &AuditConfig::default());
    let f = findings
        .iter()
        .find(|f| f.rule == "weak-passphrase")
        .expect("expected weak-passphrase finding");
    assert_eq!(f.severity, Severity::High);
    // Must not embed the passphrase plaintext anywhere.
    assert!(
        !f.message.contains(WEAK_PASSPHRASE),
        "passphrase plaintext leaked into finding message: {}",
        f.message,
    );
    assert!(
        !f.remediation.contains(WEAK_PASSPHRASE),
        "passphrase plaintext leaked into remediation: {}",
        f.remediation,
    );
}

#[test]
fn does_not_flag_strong_passphrase() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    assert!(!findings.iter().any(|f| f.rule == "weak-passphrase"));
}

#[test]
fn defaults_match_committed_thresholds() {
    let cfg = AuditConfig::default();
    // `zxcvbn-rs` 3.1.1 caps at ~64 bits; thresholds sit below the cap.
    assert_eq!(cfg.weak_passphrase_bits, 60.0);
    assert_eq!(cfg.weak_entry_password_bits, 50.0);
    // Stricter than design.md (365); user-confirmed in plan §6.
    assert_eq!(cfg.stale_password_days, 180);
    assert_eq!(cfg.weak_argon2_memory_bytes, 64 * 1024 * 1024);
    assert_eq!(cfg.weak_argon2_iters, 2);
    assert_eq!(cfg.weak_argon2_parallelism, 2);
    assert_eq!(cfg.large_attachment_bytes, 5 * 1024 * 1024);
}
