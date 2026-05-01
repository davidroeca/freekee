//! Audit rule tests. In-memory fixtures only (no file I/O, no Argon2
//! cost). Per `docs/design.md` section 7 and milestone-0 plan section 6.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use audit::{AuditConfig, CompositeKeyInfo, Severity};
use keepass::config::{DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig};

mod common;
use common::{db, strong_kdf};

// `zxcvbn-rs` 3.1.1 saturates `guesses_log10` at ~19.27 (~=64 bits) so
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
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert_eq!(findings, vec![], "no findings expected; got {findings:?}");
}

// A1: weak-outer-cipher

#[test]
fn flags_twofish_outer_cipher() {
    let database = db(|cfg| {
        cfg.outer_cipher_config = OuterCipherConfig::Twofish;
        cfg.kdf_config = strong_kdf();
    });
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
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
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "weak-outer-cipher"));
}

// A2: legacy-stream-cipher

#[test]
fn flags_salsa20_inner_cipher() {
    let database = db(|cfg| {
        cfg.inner_cipher_config = InnerCipherConfig::Salsa20;
        cfg.kdf_config = strong_kdf();
    });
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
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
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "legacy-stream-cipher"));
}

// A3: legacy-kdf

#[test]
fn flags_aes_kdf() {
    let database = db(|cfg| {
        cfg.kdf_config = KdfConfig::Aes { rounds: 100_000 };
    });
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
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
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "legacy-kdf"));
}

// A4: weak-argon2-params

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
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
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
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
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
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "weak-argon2-params")
        .expect("expected weak-argon2-params finding");
    assert!(f.message.contains("parallelism"));
}

#[test]
fn does_not_flag_strong_argon2() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "weak-argon2-params"));
}

// A5: legacy-kdbx-version

#[test]
fn flags_kdbx3_version() {
    let database = db(|cfg| {
        cfg.version = DatabaseVersion::KDB3(1);
        cfg.kdf_config = strong_kdf();
    });
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
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
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "legacy-kdbx-version"));
}

// A8: weak-entry-password

#[test]
fn flags_weak_entry_password() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    let entry_password = "123456";
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Mail");
        entry.set_protected(keepass::db::fields::PASSWORD, entry_password);
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "weak-entry-password")
        .expect("expected weak-entry-password finding");
    assert_eq!(f.severity, Severity::Medium);
    assert!(
        f.message.contains("Mail"),
        "finding should reference entry by title; got: {}",
        f.message,
    );
    // Plaintext password must not leak into any user-facing field.
    assert!(
        !f.message.contains(entry_password),
        "entry password leaked into finding message: {}",
        f.message,
    );
    assert!(
        !f.remediation.contains(entry_password),
        "entry password leaked into remediation: {}",
        f.remediation,
    );
    assert!(!f.citation.is_empty(), "citation must be populated");
}

#[test]
fn does_not_flag_strong_entry_password() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Bank");
        entry.set_protected(keepass::db::fields::PASSWORD, STRONG_PASSPHRASE);
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "weak-entry-password"));
}

#[test]
fn weak_entry_password_walks_nested_groups() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    let weak = "qwerty";
    {
        let mut root = inner.root_mut();
        let mut sub = root.add_group();
        sub.name = "Web".into();
        let mut entry = sub.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Forum");
        entry.set_protected(keepass::db::fields::PASSWORD, weak);
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "weak-entry-password")
        .expect("entries inside subgroups must also be audited");
    assert!(f.message.contains("Forum"));
    assert!(!f.message.contains(weak), "password leaked: {}", f.message);
}

#[test]
fn ignores_entry_with_no_password_field() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Note-only");
        // No password set.
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "weak-entry-password"));
}

// A9: reused-password

#[test]
fn flags_reused_password_across_two_entries() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    let shared = "Shared-Password-Of-Sufficient-Strength-2026";
    {
        let mut root = inner.root_mut();
        let mut e1 = root.add_entry();
        e1.set_unprotected(keepass::db::fields::TITLE, "Mail");
        e1.set_protected(keepass::db::fields::PASSWORD, shared);
    }
    {
        let mut root = inner.root_mut();
        let mut e2 = root.add_entry();
        e2.set_unprotected(keepass::db::fields::TITLE, "Calendar");
        e2.set_protected(keepass::db::fields::PASSWORD, shared);
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "reused-password")
        .expect("expected reused-password finding");
    assert_eq!(f.severity, Severity::Medium);
    assert!(
        f.message.contains("Mail") && f.message.contains("Calendar"),
        "finding should cite both entries; got: {}",
        f.message,
    );
    assert!(
        !f.message.contains(shared),
        "reused password plaintext leaked into finding message: {}",
        f.message,
    );
    assert!(
        !f.remediation.contains(shared),
        "reused password plaintext leaked into remediation: {}",
        f.remediation,
    );
    assert!(!f.citation.is_empty(), "citation must be populated");
}

#[test]
fn does_not_flag_unique_passwords() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    {
        let mut root = inner.root_mut();
        let mut e1 = root.add_entry();
        e1.set_unprotected(keepass::db::fields::TITLE, "Mail");
        e1.set_protected(
            keepass::db::fields::PASSWORD,
            "Unique-Password-One-2026!aA9",
        );
    }
    {
        let mut root = inner.root_mut();
        let mut e2 = root.add_entry();
        e2.set_unprotected(keepass::db::fields::TITLE, "Calendar");
        e2.set_protected(
            keepass::db::fields::PASSWORD,
            "Unique-Password-Two-2026!bB8",
        );
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "reused-password"));
}

#[test]
fn reused_password_groups_three_or_more_entries_in_one_finding() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    let shared = "Triple-Reuse-Password-2026!Zz9";
    for title in ["A", "B", "C"] {
        let mut root = inner.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(keepass::db::fields::TITLE, title);
        e.set_protected(keepass::db::fields::PASSWORD, shared);
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    let reused: Vec<_> = findings
        .iter()
        .filter(|f| f.rule == "reused-password")
        .collect();
    assert_eq!(
        reused.len(),
        1,
        "expected exactly one finding for one shared password (got {})",
        reused.len(),
    );
    let msg = &reused[0].message;
    assert!(msg.contains('A') && msg.contains('B') && msg.contains('C'));
}

#[test]
fn reused_password_separates_findings_by_password() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    let pw_one = "First-Reused-Password-2026!Q1";
    let pw_two = "Second-Reused-Password-2026!Q2";
    for (title, pw) in [
        ("Mail", pw_one),
        ("Calendar", pw_one),
        ("Bank", pw_two),
        ("Broker", pw_two),
    ] {
        let mut root = inner.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(keepass::db::fields::TITLE, title);
        e.set_protected(keepass::db::fields::PASSWORD, pw);
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    let reused = findings
        .iter()
        .filter(|f| f.rule == "reused-password")
        .count();
    assert_eq!(reused, 2, "expected one finding per shared password");
}

#[test]
fn empty_passwords_are_not_treated_as_reuse() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    for title in ["Note A", "Note B"] {
        let mut root = inner.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(keepass::db::fields::TITLE, title);
        // No password set on either; an empty/missing password is not
        // a meaningful "shared secret".
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "reused-password"));
}

// A10: stale-password

#[test]
fn flags_stale_password() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    let modified = chrono::Utc::now().naive_utc() - chrono::Duration::days(400);
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Bank");
        entry.set_protected(
            keepass::db::fields::PASSWORD,
            "Strong-Stale-Password-2026!Aa9",
        );
        entry.times.last_modification = Some(modified);
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "stale-password")
        .expect("expected stale-password finding for 400-day-old entry");
    assert_eq!(f.severity, audit::Severity::Low);
    assert!(
        f.message.contains("Bank"),
        "finding should cite entry title; got: {}",
        f.message,
    );
    assert!(!f.citation.is_empty(), "citation must be populated");
}

#[test]
fn does_not_flag_recently_modified_password() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    let modified = chrono::Utc::now().naive_utc() - chrono::Duration::days(30);
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Recent");
        entry.set_protected(
            keepass::db::fields::PASSWORD,
            "Strong-Fresh-Password-2026!Aa9",
        );
        entry.times.last_modification = Some(modified);
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "stale-password"));
}

#[test]
fn does_not_flag_entry_without_last_modification() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Unknown-Age");
        entry.set_protected(keepass::db::fields::PASSWORD, "Strong-Password-2026!Aa9");
        entry.times.last_modification = None;
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "stale-password"));
}

#[test]
fn does_not_flag_old_entry_with_no_password() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    let modified = chrono::Utc::now().naive_utc() - chrono::Duration::days(400);
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Old Note");
        entry.times.last_modification = Some(modified);
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "stale-password"));
}

// A13: large-attachment

#[test]
fn flags_attachment_over_default_threshold() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Photos");
        // Default threshold is 5 MiB; 6 MiB must trip it.
        entry.add_attachment(
            "huge.bin",
            keepass::db::Value::unprotected(vec![0u8; 6 * 1024 * 1024]),
        );
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "large-attachment")
        .expect("expected large-attachment finding for 6 MiB attachment");
    assert_eq!(f.severity, audit::Severity::Info);
    assert!(
        f.message.contains("Photos"),
        "finding should cite entry title; got: {}",
        f.message,
    );
    assert!(!f.citation.is_empty(), "citation must be populated");
}

#[test]
fn does_not_flag_attachment_under_threshold() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Doc");
        entry.add_attachment(
            "small.bin",
            keepass::db::Value::unprotected(vec![0u8; 1024 * 1024]),
        );
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "large-attachment"));
}

#[test]
fn large_attachment_threshold_respects_config() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Doc");
        entry.add_attachment(
            "ish.bin",
            keepass::db::Value::unprotected(vec![0u8; 2 * 1024 * 1024]),
        );
    }
    let database = kdbx::Database::__from_keepass(inner);

    let config = AuditConfig {
        large_attachment_bytes: 1024 * 1024, // 1 MiB
        ..AuditConfig::default()
    };
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &config,
    );
    assert!(
        findings.iter().any(|f| f.rule == "large-attachment"),
        "lowering the threshold should make the 2 MiB attachment fire",
    );
}

#[test]
fn each_oversized_attachment_emits_its_own_finding() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Album");
        entry.add_attachment(
            "a.bin",
            keepass::db::Value::unprotected(vec![0u8; 6 * 1024 * 1024]),
        );
        entry.add_attachment(
            "b.bin",
            keepass::db::Value::unprotected(vec![0u8; 7 * 1024 * 1024]),
        );
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    let count = findings
        .iter()
        .filter(|f| f.rule == "large-attachment")
        .count();
    assert_eq!(count, 2, "expected one finding per oversized attachment");
}

// A11: expired-entry-overdue

#[test]
fn flags_expired_entry_overdue() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Old API Token");
        entry.set_protected(
            keepass::db::fields::PASSWORD,
            "Some-Strong-Password-2026!Aa9",
        );
        entry.times.expires = Some(true);
        entry.times.expiry = Some(
            chrono::NaiveDate::from_ymd_opt(2020, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
        );
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "expired-entry-overdue")
        .expect("expected expired-entry-overdue finding for past expiry");
    assert_eq!(f.severity, audit::Severity::Low);
    assert!(
        f.message.contains("Old API Token"),
        "finding should cite entry title; got: {}",
        f.message,
    );
    assert!(!f.citation.is_empty(), "citation must be populated");
}

#[test]
fn does_not_flag_future_expiry() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Future Token");
        entry.times.expires = Some(true);
        entry.times.expiry = Some(
            chrono::NaiveDate::from_ymd_opt(2999, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
        );
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "expired-entry-overdue"));
}

#[test]
fn does_not_flag_entry_that_does_not_expire() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "Permanent");
        entry.times.expires = Some(false);
        // expiry timestamp set but `expires == false` means the user
        // does not want this entry treated as expirable.
        entry.times.expiry = Some(
            chrono::NaiveDate::from_ymd_opt(2020, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
        );
    }
    let database = kdbx::Database::__from_keepass(inner);

    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "expired-entry-overdue"));
}

// A7: passphrase-only

#[test]
fn flags_passphrase_only_composite_key() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::PassphraseOnly,
        &AuditConfig::default(),
    );
    let f = findings
        .iter()
        .find(|f| f.rule == "passphrase-only")
        .expect("expected passphrase-only finding");
    assert_eq!(f.severity, Severity::Info);
    assert!(!f.remediation.is_empty(), "remediation must be populated");
    assert!(!f.citation.is_empty(), "citation must be populated");
}

#[test]
fn does_not_flag_passphrase_only_when_extra_factor_present() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::HasExtraFactor,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "passphrase-only"));
}

#[test]
fn does_not_flag_passphrase_only_when_composite_key_untracked() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "passphrase-only"));
}

// A6: weak-passphrase

#[test]
fn flags_weak_passphrase() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    let findings = audit::run(
        &database,
        WEAK_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
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
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(!findings.iter().any(|f| f.rule == "weak-passphrase"));
}

#[test]
fn defaults_match_committed_thresholds() {
    let cfg = AuditConfig::default();
    // `zxcvbn-rs` 3.1.1 caps at ~64 bits; thresholds sit below the cap.
    assert_eq!(cfg.weak_passphrase_bits, 60.0);
    assert_eq!(cfg.weak_entry_password_bits, 50.0);
    // Stricter than design.md (365); user-confirmed in plan section 6.
    assert_eq!(cfg.stale_password_days, 180);
    assert_eq!(cfg.weak_argon2_memory_bytes, 64 * 1024 * 1024);
    assert_eq!(cfg.weak_argon2_iters, 2);
    assert_eq!(cfg.weak_argon2_parallelism, 2);
    assert_eq!(cfg.large_attachment_bytes, 5 * 1024 * 1024);
}
