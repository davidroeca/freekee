//! Per-entry rules. See `docs/design.md` §7.1.
//!
//! IMPORTANT: rules in this file see plaintext entry passwords but MUST
//! NOT embed any of them in `Finding`. Only derived metadata (entry
//! title, bit-strength estimate, sharing relationships) is recorded.

use std::collections::BTreeMap;

use crate::{AuditConfig, Category, Finding, Severity, strength};

pub fn reused_passwords(db: &kdbx::Database) -> Vec<Finding> {
    // Group entry titles by their password value. The password string
    // is used only as a `BTreeMap` key here and never copied into a
    // `Finding`; the produced finding records only entry titles.
    let mut by_password: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in db.entries() {
        let Some(password) = entry.password() else {
            continue;
        };
        if password.is_empty() {
            continue;
        }
        let title = entry.title().unwrap_or("(untitled)").to_owned();
        by_password
            .entry(password.to_owned())
            .or_default()
            .push(title);
    }

    let mut findings = Vec::new();
    for (_password, titles) in by_password {
        if titles.len() < 2 {
            continue;
        }
        let cited = titles
            .iter()
            .map(|t| format!("`{t}`"))
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding {
            rule: "reused-password",
            severity: Severity::Medium,
            category: Category::Entries,
            message: format!("{} entries share the same password: {cited}.", titles.len(),),
            citation: "https://csrc.nist.gov/publications/detail/sp/800-63b/final",
            remediation: "freekee rotate entries <path> --reused".into(),
        });
    }
    findings
}

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
