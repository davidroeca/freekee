//! KDBX format-version rule. See `docs/design.md` section 7.1.

use crate::{Category, Finding, Severity};

pub fn legacy_kdbx_version(db: &kdbx::Database) -> Option<Finding> {
    let v = db.kdbx_version();
    if v.major() >= 4 {
        return None;
    }
    Some(Finding {
        rule: "legacy-kdbx-version",
        severity: Severity::Medium,
        category: Category::CipherFormat,
        message: format!(
            "Database is KDBX {}.x. KDBX 4 supports Argon2id and HMAC-protected headers.",
            v.major(),
        ),
        citation: "https://keepass.info/help/kb/kdbx_4.html",
        remediation: "freekee rotate kdbx-version <path> --to 4".into(),
    })
}
