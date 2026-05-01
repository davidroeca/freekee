//! Tests for `core::Vault`. The orchestrator is tested via real
//! KDBX file I/O against the workspace's shared roundtrip fixtures
//! and via in-memory builds for everything that doesn't need a
//! committed file on disk.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use freekee_core::{Alphabet, PasswordPolicy, RotateOpts, Vault};
use kdbx::{
    Argon2idParams, EntryDraft, EntryField, EntryFieldValue, EntryPath, InnerCipher,
    NewDatabaseTemplate, OuterCipher,
};
use zeroize::Zeroizing;

fn tiny_template() -> NewDatabaseTemplate {
    // Smallest Argon2id config that satisfies the upstream validator,
    // for tests that need to actually save (and re-open) a database.
    NewDatabaseTemplate {
        kdf: Argon2idParams {
            memory: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        },
        outer_cipher: OuterCipher::ChaCha20,
        inner_cipher: InnerCipher::ChaCha20,
    }
}

fn fixture_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/roundtrip/fixtures")
        .join(name)
}

fn fixture_password(name: &str) -> String {
    let raw = fs::read_to_string(fixture_dir(name).join("password.txt"))
        .expect("read fixture password.txt");
    raw.trim_end_matches('\n').to_owned()
}

/// Copy a fixture's `db.kdbx` into a fresh tempdir and return both
/// the dir handle (kept alive by the caller) and the destination
/// path. Tests must never mutate the committed fixture in place.
fn copied_fixture(fixture: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("copy.kdbx");
    fs::copy(fixture_dir(fixture).join("db.kdbx"), &dest).unwrap();
    (tmp, dest)
}

#[test]
fn vault_open_then_save_reopens_unchanged() {
    let fixture = "single-entry";
    let password = fixture_password(fixture);

    // Copy the fixture out of the workspace tree so the test never
    // mutates a committed file.
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("copy.kdbx");
    fs::copy(fixture_dir(fixture).join("db.kdbx"), &dest).unwrap();

    let mut vault = Vault::open(&dest, Zeroizing::new(password.clone()), None).expect("vault open");
    vault.save().expect("vault save");

    // Original (canonical) and what core wrote should match
    // structurally. `kdbx::Database` derives `PartialEq + Eq` over
    // the upstream parsed tree, so this catches any field the
    // orchestrator silently dropped on the save round-trip.
    let original = kdbx::Database::open(&fixture_dir(fixture).join("db.kdbx"), &password, None)
        .expect("open canonical");
    let written = kdbx::Database::open(&dest, &password, None).expect("open core-written");
    assert_eq!(original, written);
}

#[test]
fn vault_set_field_then_save_then_reopen_sees_new_field() {
    let fixture = "single-entry";
    let password = fixture_password(fixture);
    let (_tmp, dest) = copied_fixture(fixture);

    let mut vault = Vault::open(&dest, Zeroizing::new(password.clone()), None).unwrap();

    // The single-entry fixture's lone entry is titled "Test Entry".
    let entry_path = EntryPath {
        groups: &[],
        title: "Test Entry",
    };
    vault
        .set_field(
            entry_path,
            EntryField::Username,
            EntryFieldValue::Plain("rotated-username"),
        )
        .unwrap();
    vault.save().unwrap();

    let reopened = kdbx::Database::open(&dest, &password, None).unwrap();
    let entry = reopened.entry_by_path(entry_path).expect("entry present");
    assert_eq!(entry.username(), Some("rotated-username"));
}

#[test]
fn vault_upsert_entry_inserts_when_missing() {
    let fixture = "single-entry";
    let password = fixture_password(fixture);
    let (_tmp, dest) = copied_fixture(fixture);

    let mut vault = Vault::open(&dest, Zeroizing::new(password.clone()), None).unwrap();

    let new_path = EntryPath {
        groups: &[],
        title: "Brand New",
    };
    vault
        .upsert_entry(
            new_path,
            EntryDraft {
                username: Some("alice"),
                password: Some("hunter2"),
                ..EntryDraft::default()
            },
        )
        .unwrap();
    vault.save().unwrap();

    let reopened = kdbx::Database::open(&dest, &password, None).unwrap();
    let entry = reopened.entry_by_path(new_path).expect("upserted entry");
    assert_eq!(entry.username(), Some("alice"));
    assert_eq!(entry.password(), Some("hunter2"));
}

#[test]
fn vault_upsert_entry_updates_when_present() {
    let fixture = "single-entry";
    let password = fixture_password(fixture);
    let (_tmp, dest) = copied_fixture(fixture);

    let mut vault = Vault::open(&dest, Zeroizing::new(password.clone()), None).unwrap();
    let entry_path = EntryPath {
        groups: &[],
        title: "Test Entry",
    };

    vault
        .upsert_entry(
            entry_path,
            EntryDraft {
                username: Some("changed"),
                ..EntryDraft::default()
            },
        )
        .unwrap();
    vault.save().unwrap();

    let reopened = kdbx::Database::open(&dest, &password, None).unwrap();
    let entry = reopened.entry_by_path(entry_path).unwrap();
    assert_eq!(entry.username(), Some("changed"));
    // Update goes through edit_tracking, so prior version lands in history.
    assert_eq!(entry.history_count(), 1);
}

#[test]
fn vault_remove_entry_clears_from_live_tree() {
    let fixture = "single-entry";
    let password = fixture_password(fixture);
    let (_tmp, dest) = copied_fixture(fixture);

    let mut vault = Vault::open(&dest, Zeroizing::new(password.clone()), None).unwrap();
    let entry_path = EntryPath {
        groups: &[],
        title: "Test Entry",
    };
    vault.remove_entry(entry_path).unwrap();
    vault.save().unwrap();

    let reopened = kdbx::Database::open(&dest, &password, None).unwrap();
    assert!(reopened.entry_by_path(entry_path).is_none());
    assert!(reopened.deleted_object_count() >= 1);
}

#[test]
fn vault_move_entry_relocates_via_orchestrator() {
    let fixture = "single-entry";
    let password = fixture_password(fixture);
    let (_tmp, dest) = copied_fixture(fixture);

    let mut vault = Vault::open(&dest, Zeroizing::new(password.clone()), None).unwrap();

    // Same-group rename. Cross-group moves are covered in
    // `kdbx::tests::mutate::move_entry_to_existing_group_relocates`;
    // here we exercise the orchestrator wiring + same-group case.
    vault
        .move_entry(
            EntryPath {
                groups: &[],
                title: "Test Entry",
            },
            EntryPath {
                groups: &[],
                title: "Test Entry Renamed",
            },
        )
        .unwrap();
    vault.save().unwrap();

    let reopened = kdbx::Database::open(&dest, &password, None).unwrap();
    assert!(
        reopened
            .entry_by_path(EntryPath {
                groups: &[],
                title: "Test Entry"
            })
            .is_none(),
        "old title should be gone"
    );
    assert!(
        reopened
            .entry_by_path(EntryPath {
                groups: &[],
                title: "Test Entry Renamed"
            })
            .is_some(),
        "new title should be present"
    );
}

#[test]
fn vault_create_init_writes_a_valid_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("brand-new.kdbx");

    let vault = Vault::create(
        &dest,
        Zeroizing::new("init-pw".to_owned()),
        tiny_template(),
        false,
    )
    .expect("create");
    drop(vault);

    // File exists and re-opens cleanly with the supplied passphrase.
    let reopened = kdbx::Database::open(&dest, "init-pw", None).expect("reopen");
    assert_eq!(reopened.root_entry_count(), 0);
    assert_eq!(reopened.root_subgroup_count(), 0);
}

#[test]
fn vault_create_refuses_existing_file_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("preexisting.kdbx");

    Vault::create(
        &dest,
        Zeroizing::new("first".to_owned()),
        tiny_template(),
        false,
    )
    .unwrap();

    // Snapshot pre-attempt bytes; second create must not modify the file.
    let before = fs::read(&dest).unwrap();
    let err = Vault::create(
        &dest,
        Zeroizing::new("second".to_owned()),
        tiny_template(),
        false,
    )
    .expect_err("must refuse without force");
    assert!(matches!(err, freekee_core::Error::FileExists));
    let after = fs::read(&dest).unwrap();
    assert_eq!(before, after, "pre-existing file must be untouched");
}

#[test]
fn vault_create_with_force_overwrites() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("overwritten.kdbx");

    Vault::create(
        &dest,
        Zeroizing::new("first".to_owned()),
        tiny_template(),
        false,
    )
    .unwrap();
    Vault::create(
        &dest,
        Zeroizing::new("second".to_owned()),
        tiny_template(),
        true,
    )
    .expect("force overwrites");

    // Old passphrase no longer works; new passphrase does.
    assert!(kdbx::Database::open(&dest, "first", None).is_err());
    assert!(kdbx::Database::open(&dest, "second", None).is_ok());
}

#[test]
fn rotate_passphrase_writes_backup_and_old_password_no_longer_works() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    Vault::create(
        &dest,
        Zeroizing::new("old-pass".to_owned()),
        tiny_template(),
        false,
    )
    .unwrap();

    let mut vault = Vault::open(&dest, Zeroizing::new("old-pass".to_owned()), None).unwrap();
    let outcome = vault
        .rotate_passphrase(
            Zeroizing::new("new-pass".to_owned()),
            RotateOpts { backup: true },
        )
        .unwrap();
    drop(vault);

    let backup = outcome.backup_path.expect("backup must be created");
    assert!(backup.exists(), "backup file must be on disk");

    // Old passphrase no longer opens.
    assert!(
        Vault::open(&dest, Zeroizing::new("old-pass".to_owned()), None).is_err(),
        "old passphrase should be rejected"
    );
    // New passphrase works.
    Vault::open(&dest, Zeroizing::new("new-pass".to_owned()), None)
        .expect("new passphrase should open");
}

#[test]
fn rotate_passphrase_with_no_backup_does_not_write_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    Vault::create(
        &dest,
        Zeroizing::new("old-pass".to_owned()),
        tiny_template(),
        false,
    )
    .unwrap();

    let mut vault = Vault::open(&dest, Zeroizing::new("old-pass".to_owned()), None).unwrap();
    let outcome = vault
        .rotate_passphrase(
            Zeroizing::new("new-pass".to_owned()),
            RotateOpts { backup: false },
        )
        .unwrap();

    assert!(outcome.backup_path.is_none(), "no backup path returned");

    // No file in the directory matches the backup naming convention.
    let has_backup = fs::read_dir(tmp.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".freekee-bak-")
    });
    assert!(!has_backup, "no backup file should be created");

    // New passphrase still works.
    Vault::open(&dest, Zeroizing::new("new-pass".to_owned()), None).expect("rotation took effect");
}

#[test]
fn rotate_kdf_params_changes_persistent_params_passphrase_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    Vault::create(
        &dest,
        Zeroizing::new("pw".to_owned()),
        tiny_template(),
        false,
    )
    .unwrap();

    let mut vault = Vault::open(&dest, Zeroizing::new("pw".to_owned()), None).unwrap();
    let new_params = Argon2idParams {
        memory: 16 * 1024,
        iterations: 3,
        parallelism: 2,
    };
    let outcome = vault
        .rotate_kdf_params(new_params, RotateOpts { backup: true })
        .expect("rotate kdf params");
    assert!(outcome.backup_path.is_some());
    drop(vault);

    // Same passphrase still opens the rotated file.
    let reopened = kdbx::Database::open(&dest, "pw", None).expect("passphrase unchanged");
    match reopened.kdf() {
        kdbx::Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } => {
            assert_eq!(iterations, 3);
            assert_eq!(memory, 16 * 1024);
            assert_eq!(parallelism, 2);
        }
        other => panic!("expected Argon2id after rotation, got {other:?}"),
    }
}

#[test]
fn rotate_entry_appends_history_and_changes_password() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    Vault::create(
        &dest,
        Zeroizing::new("pw".to_owned()),
        tiny_template(),
        false,
    )
    .unwrap();

    let mut vault = Vault::open(&dest, Zeroizing::new("pw".to_owned()), None).unwrap();
    let entry_path = EntryPath {
        groups: &[],
        title: "Bank",
    };
    vault
        .upsert_entry(
            entry_path,
            EntryDraft {
                username: Some("alice"),
                password: Some("original-pw"),
                ..EntryDraft::default()
            },
        )
        .unwrap();
    vault.save().unwrap();

    let policy = PasswordPolicy {
        length: 32,
        alphabet: Alphabet::AlphaNum,
    };
    let outcome = vault
        .rotate_entry(entry_path, &policy, RotateOpts { backup: true })
        .expect("rotate entry");
    assert!(outcome.backup_path.is_some(), "backup must be created");
    drop(vault);

    let reopened = kdbx::Database::open(&dest, "pw", None).unwrap();
    let entry = reopened.entry_by_path(entry_path).unwrap();
    let new_pw = entry.password().expect("entry must still have a password");
    assert_eq!(new_pw.len(), 32);
    assert_ne!(new_pw, "original-pw");
    assert!(new_pw.chars().all(|c| c.is_ascii_alphanumeric()));
    assert_eq!(
        entry.history_count(),
        1,
        "rotation must snapshot prior version into history"
    );
    let prior = entry.historical(0).unwrap();
    assert_eq!(prior.password(), Some("original-pw"));
}

#[test]
fn rotate_entry_returns_not_found_for_missing_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    Vault::create(
        &dest,
        Zeroizing::new("pw".to_owned()),
        tiny_template(),
        false,
    )
    .unwrap();
    let mut vault = Vault::open(&dest, Zeroizing::new("pw".to_owned()), None).unwrap();
    let err = vault
        .rotate_entry(
            EntryPath {
                groups: &[],
                title: "Nope",
            },
            &PasswordPolicy::default(),
            RotateOpts::default(),
        )
        .expect_err("missing entry must error");
    assert!(matches!(err, freekee_core::Error::NotFound));
}

#[test]
fn rotate_passphrase_rejects_empty_new_pass() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    Vault::create(
        &dest,
        Zeroizing::new("old".to_owned()),
        tiny_template(),
        false,
    )
    .unwrap();

    let mut vault = Vault::open(&dest, Zeroizing::new("old".to_owned()), None).unwrap();
    let err = vault
        .rotate_passphrase(Zeroizing::new(String::new()), RotateOpts::default())
        .expect_err("empty new pass rejected");
    assert!(matches!(err, freekee_core::Error::EmptyPassphrase));
    // Original file untouched: still opens with the old passphrase.
    drop(vault);
    Vault::open(&dest, Zeroizing::new("old".to_owned()), None).expect("untouched original");
}

#[test]
fn rotation_rollback_restores_original_when_verify_would_fail() {
    // The rotate_* methods all funnel through a save+verify+rollback
    // helper. Driving an in-place verify failure from the public API
    // requires injecting corruption between save and verify, which
    // we don't expose. Instead this test exercises the underlying
    // BackupGuard + restore machinery end-to-end - the same pieces
    // the rotation tail uses - to demonstrate that a "save lands,
    // verify fails" path leaves the original recoverable.

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    Vault::create(
        &dest,
        Zeroizing::new("pw".to_owned()),
        tiny_template(),
        false,
    )
    .unwrap();
    let original_bytes = fs::read(&dest).unwrap();

    let mut guard =
        freekee_core::backup::BackupGuard::create_for(&dest, chrono::Utc::now()).unwrap();
    // Simulate "save succeeded, file is now garbage" - exactly the
    // corruption the verify step is designed to catch.
    fs::write(&dest, b"this is not a kdbx file").unwrap();
    assert!(
        kdbx::Database::open(&dest, "pw", None).is_err(),
        "corrupted file must not open"
    );

    guard.restore(&dest).unwrap();
    assert_eq!(
        fs::read(&dest).unwrap(),
        original_bytes,
        "restore must put the original bytes back"
    );
    kdbx::Database::open(&dest, "pw", None).expect("restored file opens with original creds");
}

#[test]
fn vault_create_rejects_empty_passphrase() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("empty-pw.kdbx");
    let err = Vault::create(&dest, Zeroizing::new(String::new()), tiny_template(), false)
        .expect_err("empty passphrase rejected");
    assert!(matches!(err, freekee_core::Error::EmptyPassphrase));
    assert!(!dest.exists(), "no file should be written");
}
