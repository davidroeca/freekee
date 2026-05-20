//! Per-entry rules. See `docs/design.md` section 7.1.
//!
//! IMPORTANT: rules in this file see plaintext entry passwords but MUST
//! NOT embed any of them in `Finding`. Only derived metadata (entry
//! title, bit-strength estimate, sharing relationships) is recorded.

use std::collections::BTreeMap;

use crate::{AuditConfig, Category, Finding, Severity, strength};

pub fn large_attachments(db: &kdbx::Database, config: &AuditConfig) -> Vec<Finding> {
    let threshold = config.large_attachment_bytes;
    let mut findings = Vec::new();
    for entry in db.entries() {
        let title = entry.title().unwrap_or("(untitled)");
        for size in entry.attachment_sizes() {
            if (size as u64) <= threshold {
                continue;
            }
            findings.push(Finding {
                rule: "large-attachment",
                severity: Severity::Info,
                category: Category::Attachments,
                message: format!(
                    "Entry `{title}` has an attachment of {} bytes; threshold is {} bytes.",
                    size, threshold,
                ),
                citation: "https://keepass.info/help/base/entries.html",
                remediation: format!(
                    "freekee export attachment <path> --title {title:?}; then remove from the entry"
                ),
                entry_path: None,
            });
        }
    }
    findings
}

pub fn stale_passwords(db: &kdbx::Database, config: &AuditConfig) -> Vec<Finding> {
    let now = chrono::Utc::now().naive_utc();
    let threshold = chrono::Duration::days(config.stale_password_days);
    let mut findings = Vec::new();
    for entry in db.entries() {
        // Only meaningful for entries that actually hold a password.
        let Some(password) = entry.password() else {
            continue;
        };
        if password.is_empty() {
            continue;
        }
        let Some(modified) = entry.last_modified_at() else {
            continue;
        };
        let age = now.signed_duration_since(modified);
        if age <= threshold {
            continue;
        }
        let title = entry.title().unwrap_or("(untitled)");
        let entry_path = build_entry_path(&entry, title);
        findings.push(Finding {
            rule: "stale-password",
            severity: Severity::Low,
            category: Category::Entries,
            message: format!(
                "Entry `{title}` was last updated {} days ago; threshold is {} days.",
                age.num_days(),
                config.stale_password_days,
            ),
            citation: "https://csrc.nist.gov/publications/detail/sp/800-63b/final",
            remediation: format!("freekee rotate entry <path> --title {title:?}"),
            entry_path: Some(entry_path),
        });
    }
    findings
}

/// Build a `[group1, ..., groupN, title]` path vector for a per-entry
/// finding. Mirrors how `Vault::list` renders entries via slash-join.
fn build_entry_path(entry: &kdbx::Entry<'_>, title: &str) -> Vec<String> {
    let mut path = entry.group_path();
    path.push(title.to_owned());
    path
}

pub fn expired_entries(db: &kdbx::Database) -> Vec<Finding> {
    let now = chrono::Utc::now().naive_utc();
    let mut findings = Vec::new();
    for entry in db.entries() {
        let Some(expiry) = entry.expires_at() else {
            continue;
        };
        if expiry >= now {
            continue;
        }
        let title = entry.title().unwrap_or("(untitled)");
        let entry_path = build_entry_path(&entry, title);
        findings.push(Finding {
            rule: "expired-entry-overdue",
            severity: Severity::Low,
            category: Category::Entries,
            message: format!(
                "Entry `{title}` expired on {} and has not been rotated or removed.",
                expiry.format("%Y-%m-%d"),
            ),
            citation: "https://keepass.info/help/base/entries.html#expiry",
            remediation: format!("freekee rotate entry <path> --title {title:?}"),
            entry_path: Some(entry_path),
        });
    }
    findings
}

pub fn reused_passwords(db: &kdbx::Database) -> Vec<Finding> {
    // Group entries by their password value, keeping (title, full path)
    // per member so the per-finding output can name the other sharers.
    // The password string is used only as a `BTreeMap` key here and is
    // never copied into a `Finding`; produced findings record only entry
    // titles and paths.
    let mut by_password: BTreeMap<String, Vec<(String, Vec<String>)>> = BTreeMap::new();
    for entry in db.entries() {
        let Some(password) = entry.password() else {
            continue;
        };
        if password.is_empty() {
            continue;
        }
        let title = entry.title().unwrap_or("(untitled)").to_owned();
        let path = build_entry_path(&entry, &title);
        by_password
            .entry(password.to_owned())
            .or_default()
            .push((title, path));
    }

    let mut findings = Vec::new();
    for (_password, members) in by_password {
        if members.len() < 2 {
            continue;
        }
        // Emit one finding per member so the interactive fix loop in
        // `freekee fix` can iterate uniformly. The message cites the
        // *other* members so the user sees who they share with.
        for (i, (title, path)) in members.iter().enumerate() {
            let others = members
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (t, _))| format!("`{t}`"))
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(Finding {
                rule: "reused-password",
                severity: Severity::Medium,
                category: Category::Entries,
                message: format!("Entry `{title}` shares its password with {others}."),
                citation: "https://csrc.nist.gov/publications/detail/sp/800-63b/final",
                remediation: format!("freekee rotate entry <path> --title {title:?}"),
                entry_path: Some(path.clone()),
            });
        }
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
        let entry_path = build_entry_path(&entry, title);
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
            entry_path: Some(entry_path),
        });
    }
    findings
}
