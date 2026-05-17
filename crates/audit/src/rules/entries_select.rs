//! Path-keyed entry predicates for callers that need to *act on*
//! flagged entries (e.g. `freekee rotate entries`).
//!
//! These share threshold sources with the `Finding`-producing rules in
//! `rules::entries` but return owned `(group_path, title)` tuples so a
//! caller can reconstruct an `EntryPath` and mutate the entry. They are
//! deliberately not part of `audit::run` — the audit pipeline produces
//! `Finding`s; this module produces actionable targets.

use std::collections::BTreeMap;

use crate::{AuditConfig, strength};

/// Entries whose stored password is below
/// `cfg.weak_entry_password_bits`. Entries with no password (or an
/// empty one) are skipped, matching `rules::entries::weak_entry_passwords`.
pub fn weak_entry_targets(db: &kdbx::Database, cfg: &AuditConfig) -> Vec<(Vec<String>, String)> {
    let mut out = Vec::new();
    for entry in db.entries() {
        let Some(password) = entry.password() else {
            continue;
        };
        if password.is_empty() {
            continue;
        }
        if strength::passphrase_bits(password) >= cfg.weak_entry_password_bits {
            continue;
        }
        let title = entry.title().unwrap_or("(untitled)").to_owned();
        out.push((entry.group_path(), title));
    }
    out
}

/// Entries whose `last_modification` is older than
/// `cfg.stale_password_days` days. Entries without a password or
/// without a recorded modification timestamp are skipped, matching
/// `rules::entries::stale_passwords`.
pub fn stale_entry_targets(db: &kdbx::Database, cfg: &AuditConfig) -> Vec<(Vec<String>, String)> {
    let now = chrono::Utc::now().naive_utc();
    let threshold = chrono::Duration::days(cfg.stale_password_days);
    let mut out = Vec::new();
    for entry in db.entries() {
        let Some(password) = entry.password() else {
            continue;
        };
        if password.is_empty() {
            continue;
        }
        let Some(modified) = entry.last_modified_at() else {
            continue;
        };
        if now.signed_duration_since(modified) <= threshold {
            continue;
        }
        let title = entry.title().unwrap_or("(untitled)").to_owned();
        out.push((entry.group_path(), title));
    }
    out
}

/// Entries whose password is shared with at least one other entry.
/// Every member of a sharing set is returned (so a caller can rotate
/// all of them). Matches `rules::entries::reused_passwords` semantics.
pub fn reused_entry_targets(db: &kdbx::Database) -> Vec<(Vec<String>, String)> {
    // Group by password value. The plaintext is only used as a
    // `BTreeMap` key, never copied into the returned tuples.
    let mut by_password: BTreeMap<String, Vec<(Vec<String>, String)>> = BTreeMap::new();
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
            .push((entry.group_path(), title));
    }
    let mut out = Vec::new();
    for (_password, members) in by_password {
        if members.len() < 2 {
            continue;
        }
        out.extend(members);
    }
    out
}
