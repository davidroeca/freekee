//! Golden tests: each committed `expected.json` must match the
//! snapshot produced by re-parsing its `db.kdbx`. Catches version,
//! cipher, and KDF drift that round-trip equality does not surface.
//! Regenerate with the binary noted in the failure message.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

mod common;
use common::assert_expected_snapshot_matches;

#[test]
fn empty_matches_committed_snapshot() {
    assert_expected_snapshot_matches("empty");
}

#[test]
fn single_entry_matches_committed_snapshot() {
    assert_expected_snapshot_matches("single-entry");
}

#[test]
fn with_history_matches_committed_snapshot() {
    assert_expected_snapshot_matches("with-history");
}

#[test]
fn with_attachments_matches_committed_snapshot() {
    assert_expected_snapshot_matches("with-attachments");
}

#[test]
fn with_custom_data_matches_committed_snapshot() {
    assert_expected_snapshot_matches("with-custom-data");
}

#[test]
fn with_custom_icons_matches_committed_snapshot() {
    assert_expected_snapshot_matches("with-custom-icons");
}

#[test]
fn with_tags_and_expiry_matches_committed_snapshot() {
    assert_expected_snapshot_matches("with-tags-and-expiry");
}

#[test]
fn with_autotype_matches_committed_snapshot() {
    assert_expected_snapshot_matches("with-autotype");
}

#[test]
fn kdbx41_features_matches_committed_snapshot() {
    assert_expected_snapshot_matches("kdbx41-features");
}

#[test]
fn kdbx40_legacy_matches_committed_snapshot() {
    assert_expected_snapshot_matches("kdbx40-legacy");
}

#[test]
fn kdbx3_legacy_matches_committed_snapshot() {
    assert_expected_snapshot_matches("kdbx3-legacy");
}
