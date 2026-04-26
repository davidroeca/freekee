//! Per-entry rules. See `docs/design.md` §7.1.
//!
//! IMPORTANT: rules in this file see plaintext entry passwords but MUST
//! NOT embed any of them in `Finding`. Only derived metadata (entry
//! title, bit-strength estimate) is recorded.

use crate::{AuditConfig, Category, Finding, Severity, strength};

pub fn weak_entry_passwords(db: &kdbx::Database, config: &AuditConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    for entry in db.entries() {
        let Some(password) = entry.password() else {
            continue;
        };
        if password.is_empty() {
            continue;
        }
        let bits = strength::passphrase_bits(password);
        if bits >= config.weak_entry_password_bits {
            continue;
        }
        let title = entry.title().unwrap_or("(untitled)");
        findings.push(Finding {
            rule: "weak-entry-password",
            severity: Severity::Medium,
            category: Category::Entries,
            message: format!(
                "Entry `{title}` has a password estimated at {bits:.1} bits; threshold is {:.1}.",
                config.weak_entry_password_bits,
            ),
            citation: "https://csrc.nist.gov/publications/detail/sp/800-63b/final",
            remediation: format!("freekee rotate entry <path> --title {title:?}"),
        });
    }
    findings
}
