//! Path-keyed predicate helpers used by callers that want to *act on*
//! entries (e.g. `freekee rotate entries`). Existing `Finding`-producing
//! rules live in `rules/entries.rs`; these sibling helpers share the
//! same thresholds and walk but return owned `(group_path, title)`
//! tuples instead.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use audit::AuditConfig;

mod common;
use common::strong_kdf;

const STRONG_UNIQUE_A: &str = "qWk3@p9Lnv8Z2!Mrx7&fE$Bc1-A";
const STRONG_UNIQUE_B: &str = "qWk3@p9Lnv8Z2!Mrx7&fE$Bc1-B";
const STRONG_SHARED: &str = "Shared-Strong-Password-2026!Aa9";
const WEAK: &str = "123456";

/// Fixture: one entry per predicate plus a clean baseline.
///
/// Layout (group / title):
///   root / Weak       — weak password, fresh
///   Web  / Stale      — strong unique password, 400d old
///   root / Mail       — strong shared password, fresh
///   Web  / Calendar   — strong shared password (same as Mail), fresh
///   root / Clean      — strong unique password, fresh
///
/// Expected matches per predicate:
///   weak   -> [( [],          "Weak"    )]
///   stale  -> [( ["Web"],     "Stale"   )]
///   reused -> [( [],          "Mail"    ),
///              ( ["Web"],     "Calendar")]
///   clean entry is in none of the above.
fn build_fixture() -> kdbx::Database {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    let fresh = chrono::Utc::now().naive_utc();
    let stale = fresh - chrono::Duration::days(400);
    {
        let mut root = inner.root_mut();
        let mut weak = root.add_entry();
        weak.set_unprotected(keepass::db::fields::TITLE, "Weak");
        weak.set_protected(keepass::db::fields::PASSWORD, WEAK);
        weak.times.last_modification = Some(fresh);
    }
    {
        let mut root = inner.root_mut();
        let mut mail = root.add_entry();
        mail.set_unprotected(keepass::db::fields::TITLE, "Mail");
        mail.set_protected(keepass::db::fields::PASSWORD, STRONG_SHARED);
        mail.times.last_modification = Some(fresh);
    }
    {
        let mut root = inner.root_mut();
        let mut clean = root.add_entry();
        clean.set_unprotected(keepass::db::fields::TITLE, "Clean");
        clean.set_protected(keepass::db::fields::PASSWORD, STRONG_UNIQUE_A);
        clean.times.last_modification = Some(fresh);
    }
    {
        let mut root = inner.root_mut();
        let mut web = root.add_group();
        web.name = "Web".into();
        {
            let mut stale_e = web.add_entry();
            stale_e.set_unprotected(keepass::db::fields::TITLE, "Stale");
            stale_e.set_protected(keepass::db::fields::PASSWORD, STRONG_UNIQUE_B);
            stale_e.times.last_modification = Some(stale);
        }
        {
            let mut cal = web.add_entry();
            cal.set_unprotected(keepass::db::fields::TITLE, "Calendar");
            cal.set_protected(keepass::db::fields::PASSWORD, STRONG_SHARED);
            cal.times.last_modification = Some(fresh);
        }
    }
    kdbx::Database::__from_keepass(inner)
}

fn sorted(mut v: Vec<(Vec<String>, String)>) -> Vec<(Vec<String>, String)> {
    v.sort();
    v
}

#[test]
fn weak_entry_targets_returns_only_weak_entry() {
    let db = build_fixture();
    let targets = sorted(audit::weak_entry_targets(&db, &AuditConfig::default()));
    assert_eq!(targets, vec![(vec![], "Weak".to_owned())]);
}

#[test]
fn stale_entry_targets_returns_only_stale_entry_with_group_path() {
    let db = build_fixture();
    let targets = sorted(audit::stale_entry_targets(&db, &AuditConfig::default()));
    assert_eq!(targets, vec![(vec!["Web".to_owned()], "Stale".to_owned())]);
}

#[test]
fn reused_entry_targets_returns_both_sharing_entries() {
    let db = build_fixture();
    let targets = sorted(audit::reused_entry_targets(&db));
    assert_eq!(
        targets,
        vec![
            (vec![], "Mail".to_owned()),
            (vec!["Web".to_owned()], "Calendar".to_owned()),
        ],
    );
}

#[test]
fn clean_entry_is_in_no_target_list() {
    let db = build_fixture();
    let cfg = AuditConfig::default();
    let in_weak = audit::weak_entry_targets(&db, &cfg)
        .iter()
        .any(|(_, t)| t == "Clean");
    let in_stale = audit::stale_entry_targets(&db, &cfg)
        .iter()
        .any(|(_, t)| t == "Clean");
    let in_reused = audit::reused_entry_targets(&db)
        .iter()
        .any(|(_, t)| t == "Clean");
    assert!(!in_weak, "Clean entry must not appear in weak targets");
    assert!(!in_stale, "Clean entry must not appear in stale targets");
    assert!(!in_reused, "Clean entry must not appear in reused targets");
}

#[test]
fn empty_database_returns_no_targets() {
    let mut inner = keepass::Database::new();
    inner.config.kdf_config = strong_kdf();
    let db = kdbx::Database::__from_keepass(inner);
    let cfg = AuditConfig::default();
    assert!(audit::weak_entry_targets(&db, &cfg).is_empty());
    assert!(audit::stale_entry_targets(&db, &cfg).is_empty());
    assert!(audit::reused_entry_targets(&db).is_empty());
}
