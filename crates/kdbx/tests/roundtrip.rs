//! Compatibility test harness against `tests/roundtrip/fixtures/`.
//!
//! Each test reads a KeePassXC-generated fixture and asserts a structural
//! property. Round-trip (read -> write -> read) coverage is added per the
//! milestone-0 TDD plan.

mod common;

use common::{assert_roundtrip_idempotent, assert_self_roundtrip, fixture_dir, fixture_password};

#[test]
fn read_with_keyfile_fixture_succeeds() {
    let dir = fixture_dir("with-keyfile");
    let password = fixture_password("with-keyfile");
    let keyfile = dir.join("keyfile.bin");

    let db = kdbx::Database::open(&dir.join("db.kdbx"), &password, Some(&keyfile))
        .expect("open with-keyfile fixture");

    assert!(
        db.root_entry_count() > 0,
        "with-keyfile fixture must have at least one entry"
    );
}

#[test]
fn read_empty_database_has_no_entries_or_subgroups() {
    let path = fixture_dir("empty").join("db.kdbx");
    let password = fixture_password("empty");

    let db = kdbx::Database::open(&path, &password, None).expect("open empty fixture");

    assert_eq!(
        db.root_entry_count(),
        0,
        "empty fixture must have no entries"
    );
    assert_eq!(
        db.root_subgroup_count(),
        0,
        "empty fixture must have no subgroups"
    );
}

#[test]
fn roundtrip_empty_is_lossless() {
    assert_self_roundtrip("empty");
}

#[test]
fn read_single_entry_has_one_populated_entry() {
    let path = fixture_dir("single-entry").join("db.kdbx");
    let password = fixture_password("single-entry");

    let db = kdbx::Database::open(&path, &password, None).expect("open single-entry fixture");

    assert_eq!(
        db.root_entry_count(),
        1,
        "single-entry fixture must have one entry"
    );
    let entry = db.root_entries().next().expect("entry must be enumerable");
    assert!(
        entry.title().is_some_and(|t| !t.is_empty()),
        "title must be non-empty",
    );
    assert!(
        entry.password().is_some_and(|p| !p.is_empty()),
        "password must be non-empty",
    );
}

#[test]
fn roundtrip_single_entry_preserves_fields() {
    assert_self_roundtrip("single-entry");
}

#[test]
#[ignore = "keepass-rs does not yet parse <PreviousParentGroup> (KDBX 4.1); see docs/kdbx-compat-matrix.md and upstream PR #308"]
fn roundtrip_groups_and_entries_preserves_hierarchy() {
    assert_self_roundtrip("groups-and-entries");
}

#[test]
fn roundtrip_with_history_preserves_prior_versions() {
    assert_self_roundtrip("with-history");
}

#[test]
fn roundtrip_with_attachments_preserves_binaries() {
    assert_self_roundtrip("with-attachments");
}

#[test]
fn roundtrip_with_custom_data_preserves_map() {
    assert_self_roundtrip("with-custom-data");
}

#[test]
fn roundtrip_kdbx41_features_are_preserved() {
    assert_self_roundtrip("kdbx41-features");
}

#[test]
fn roundtrip_is_idempotent_for_empty() {
    assert_roundtrip_idempotent("empty");
}

#[test]
fn roundtrip_is_idempotent_for_single_entry() {
    assert_roundtrip_idempotent("single-entry");
}

#[test]
fn roundtrip_is_idempotent_for_kdbx41_features() {
    assert_roundtrip_idempotent("kdbx41-features");
}

#[cfg(feature = "keepassxc-verify")]
#[test]
fn keepassxc_can_open_written_empty() {
    common::assert_keepassxc_can_open("empty");
}

#[cfg(feature = "keepassxc-verify")]
#[test]
fn keepassxc_can_open_written_single_entry() {
    common::assert_keepassxc_can_open("single-entry");
}

#[cfg(feature = "keepassxc-verify")]
#[test]
fn keepassxc_can_open_written_with_history() {
    common::assert_keepassxc_can_open("with-history");
}

#[cfg(feature = "keepassxc-verify")]
#[test]
fn keepassxc_can_open_written_with_attachments() {
    common::assert_keepassxc_can_open("with-attachments");
}

#[cfg(feature = "keepassxc-verify")]
#[test]
fn keepassxc_can_open_written_with_custom_data() {
    common::assert_keepassxc_can_open("with-custom-data");
}

#[cfg(feature = "keepassxc-verify")]
#[test]
fn keepassxc_can_open_written_kdbx41_features() {
    common::assert_keepassxc_can_open("kdbx41-features");
}
