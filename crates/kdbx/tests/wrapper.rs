//! Unit tests for the thin `kdbx` wrapper methods that aren't already
//! exercised through the file-I/O paths in `roundtrip.rs` /
//! `negative.rs`. Built in-memory via `__from_keepass` so they pay no
//! Argon2 cost and can target wrapper logic in isolation.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use chrono::NaiveDate;

fn make(db: keepass::Database) -> kdbx::Database {
    kdbx::Database::__from_keepass(db)
}

// Database::entries (recursive walk over current entries)

#[test]
fn entries_iterator_empty_database_yields_nothing() {
    let db = make(keepass::Database::new());
    assert_eq!(db.entries().count(), 0);
}

#[test]
fn entries_iterator_includes_root_entries() {
    let mut inner = keepass::Database::new();
    {
        let mut root = inner.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(keepass::db::fields::TITLE, "A");
    }
    let db = make(inner);
    let titles: Vec<_> = db
        .entries()
        .filter_map(|e| e.title().map(str::to_owned))
        .collect();
    assert_eq!(titles, vec!["A".to_owned()]);
}

#[test]
fn entries_iterator_walks_into_nested_groups() {
    let mut inner = keepass::Database::new();
    {
        let mut root = inner.root_mut();
        let mut child = root.add_group();
        child.name = "Web".into();
        let mut grandchild = child.add_group();
        grandchild.name = "Forums".into();
        let mut e = grandchild.add_entry();
        e.set_unprotected(keepass::db::fields::TITLE, "DeepEntry");
    }
    let db = make(inner);
    let titles: Vec<_> = db
        .entries()
        .filter_map(|e| e.title().map(str::to_owned))
        .collect();
    assert_eq!(titles, vec!["DeepEntry".to_owned()]);
}

#[test]
fn entries_iterator_counts_all_current_entries() {
    let mut inner = keepass::Database::new();
    {
        let mut root = inner.root_mut();
        for title in ["A", "B"] {
            let mut e = root.add_entry();
            e.set_unprotected(keepass::db::fields::TITLE, title);
        }
        let mut child = root.add_group();
        child.name = "Sub".into();
        for title in ["C", "D"] {
            let mut e = child.add_entry();
            e.set_unprotected(keepass::db::fields::TITLE, title);
        }
    }
    let db = make(inner);
    assert_eq!(db.entries().count(), 4);
}

// Entry::expires_at (Times.expires + Times.expiry semantics)

fn ts(year: i32, month: u32, day: u32) -> chrono::NaiveDateTime {
    NaiveDate::from_ymd_opt(year, month, day)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap()
}

fn entry_with_times(
    expires: Option<bool>,
    expiry: Option<chrono::NaiveDateTime>,
) -> kdbx::Database {
    let mut inner = keepass::Database::new();
    {
        let mut root = inner.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(keepass::db::fields::TITLE, "T");
        e.times.expires = expires;
        e.times.expiry = expiry;
    }
    make(inner)
}

#[test]
fn expires_at_returns_timestamp_when_expires_true_and_expiry_set() {
    let target = ts(2025, 6, 1);
    let db = entry_with_times(Some(true), Some(target));
    let entry = db.entries().next().unwrap();
    assert_eq!(entry.expires_at(), Some(target));
}

#[test]
fn expires_at_returns_none_when_expires_false_even_if_expiry_set() {
    // KeePass semantics: `Times.Expires == False` means the user has
    // turned off expiry for this entry, so the stored timestamp must
    // be ignored.
    let db = entry_with_times(Some(false), Some(ts(2020, 1, 1)));
    let entry = db.entries().next().unwrap();
    assert_eq!(entry.expires_at(), None);
}

#[test]
fn expires_at_returns_none_when_expires_unset() {
    let db = entry_with_times(None, Some(ts(2020, 1, 1)));
    let entry = db.entries().next().unwrap();
    assert_eq!(entry.expires_at(), None);
}

#[test]
fn expires_at_returns_none_when_expires_true_but_expiry_unset() {
    let db = entry_with_times(Some(true), None);
    let entry = db.entries().next().unwrap();
    assert_eq!(entry.expires_at(), None);
}

// Entry::last_modified_at

#[test]
fn last_modified_at_returns_none_when_unset() {
    let mut inner = keepass::Database::new();
    {
        let mut root = inner.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(keepass::db::fields::TITLE, "T");
        e.times.last_modification = None;
    }
    let db = make(inner);
    let entry = db.entries().next().unwrap();
    assert_eq!(entry.last_modified_at(), None);
}

#[test]
fn last_modified_at_returns_recorded_timestamp() {
    let target = ts(2024, 3, 15);
    let mut inner = keepass::Database::new();
    {
        let mut root = inner.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(keepass::db::fields::TITLE, "T");
        e.times.last_modification = Some(target);
    }
    let db = make(inner);
    let entry = db.entries().next().unwrap();
    assert_eq!(entry.last_modified_at(), Some(target));
}
