//! Legacy-version handling and negative paths. Per `docs/design.md` §4
//! threat model and milestone-0 plan §5 tests #11–#15.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

mod common;

use common::{fixture_dir, fixture_password};
use std::fs;

#[test]
fn read_kdbx40_legacy_reports_v4_version() {
    let path = fixture_dir("kdbx40-legacy").join("db.kdbx");
    let password = fixture_password("kdbx40-legacy");

    let db = kdbx::Database::open(&path, &password, None).expect("open kdbx40-legacy");

    let v = db.kdbx_version();
    assert_eq!(v.major(), 4, "kdbx40-legacy must report major version 4");
    assert!(
        matches!(v, kdbx::KdbxVersion::Kdb4(0)),
        "expected Kdb4(0), got {v:?}",
    );
}

#[test]
fn read_kdbx3_legacy_reports_v3_version() {
    // We do not write KDBX 3.x (per design §3 non-goal), but reading it
    // is acceptable so the audit layer can flag it for upgrade.
    let path = fixture_dir("kdbx3-legacy").join("db.kdbx");
    let password = fixture_password("kdbx3-legacy");

    let db = kdbx::Database::open(&path, &password, None).expect("open kdbx3-legacy");

    assert_eq!(db.kdbx_version().major(), 3);
}

#[test]
fn corrupted_header_returns_format_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("truncated.kdbx");
    // Plausible KDBX magic bytes followed by garbage and a hard truncation.
    fs::write(
        &path,
        [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0x00, 0x00],
    )
    .unwrap();

    let err = kdbx::Database::open(&path, "anything", None).expect_err("must reject");
    assert!(
        matches!(err, kdbx::Error::Format),
        "expected Format, got {err:?}",
    );
}

#[test]
fn wrong_password_returns_authentication_error_without_leaking_password() {
    let path = fixture_dir("empty").join("db.kdbx");
    let attempted = "WRONG_SENTINEL_a8f3c2_DO_NOT_LEAK";

    let err = kdbx::Database::open(&path, attempted, None).expect_err("must reject");
    assert!(
        matches!(err, kdbx::Error::Authentication),
        "expected Authentication, got {err:?}",
    );

    let display = err.to_string();
    let debug = format!("{err:?}");
    assert!(
        !display.contains(attempted),
        "Display string leaked the attempted passphrase: {display}",
    );
    assert!(
        !debug.contains(attempted),
        "Debug string leaked the attempted passphrase: {debug}",
    );
}

#[test]
fn tampered_payload_returns_integrity_error() {
    let src = fixture_dir("empty").join("db.kdbx");
    let password = fixture_password("empty");
    let dir = tempfile::tempdir().expect("tempdir");
    let dst = dir.path().join("tampered.kdbx");

    let mut bytes = fs::read(&src).expect("read src");
    // Flip a byte deep into the encrypted region (well past the plaintext
    // header). The HMAC over the ciphertext should reject this.
    let len = bytes.len();
    assert!(len > 64, "fixture too small for tampering test");
    let tampered_index = len - 8;
    bytes[tampered_index] ^= 0xff;
    fs::write(&dst, &bytes).expect("write tampered");

    let err = kdbx::Database::open(&dst, &password, None).expect_err("must reject");
    assert!(
        matches!(err, kdbx::Error::IntegrityCheck | kdbx::Error::Format),
        "expected IntegrityCheck or Format, got {err:?}",
    );
}
