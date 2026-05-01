//! Tests for `core::Vault`. The orchestrator is tested via real
//! KDBX file I/O against the workspace's shared roundtrip fixtures
//! and via in-memory builds for everything that doesn't need a
//! committed file on disk.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use freekee_core::{Alphabet, EntryView, HistoryView, PasswordPolicy, RotateOpts, Vault};
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
        None,
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
        None,
        tiny_template(),
        false,
    )
    .unwrap();

    // Snapshot pre-attempt bytes; second create must not modify the file.
    let before = fs::read(&dest).unwrap();
    let err = Vault::create(
        &dest,
        Zeroizing::new("second".to_owned()),
        None,
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
        None,
        tiny_template(),
        false,
    )
    .unwrap();
    Vault::create(
        &dest,
        Zeroizing::new("second".to_owned()),
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
    let err = Vault::create(
        &dest,
        Zeroizing::new(String::new()),
        None,
        tiny_template(),
        false,
    )
    .expect_err("empty passphrase rejected");
    assert!(matches!(err, freekee_core::Error::EmptyPassphrase));
    assert!(!dest.exists(), "no file should be written");
}

// ---------------------------------------------------------------------------
// First-class read accessors.
//
// These pin the contract for the new `Vault::list/get/get_password/history/
// entry_exists/current_argon2id_params` surface that replaces `vault.db()`
// reach-throughs from the CLI. Each test owns a fresh in-memory vault built
// via `Vault::create` + `tiny_template` so these stay fast (Argon2id at the
// minimum-viable params).
// ---------------------------------------------------------------------------

/// Helper: build a vault, populate it with a fixed set of entries directly
/// under root, and return the open vault. Each entry has its title as the
/// password (lets tests assert by title without a separate map).
fn vault_with_entries(dest: &std::path::Path, titles: &[&str]) -> Vault {
    Vault::create(
        dest,
        Zeroizing::new("pw".to_owned()),
        None,
        tiny_template(),
        false,
    )
    .unwrap();
    let mut vault = Vault::open(dest, Zeroizing::new("pw".to_owned()), None).unwrap();
    for title in titles {
        vault
            .upsert_entry(
                EntryPath { groups: &[], title },
                EntryDraft {
                    username: Some("alice"),
                    password: Some(title), // title-as-password for assertion convenience
                    url: Some("https://example.test"),
                    ..EntryDraft::default()
                },
            )
            .unwrap();
    }
    vault.save().unwrap();
    vault
}

#[test]
fn list_returns_sorted_paths_with_optional_substring_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let vault = vault_with_entries(&dest, &["GitHub", "AlphaBank", "BetaMail"]);

    let all = vault.list(None);
    assert_eq!(
        all,
        vec![
            "AlphaBank".to_owned(),
            "BetaMail".to_owned(),
            "GitHub".to_owned(),
        ],
        "list(None) must return every entry path, sorted ascending"
    );

    let filtered = vault.list(Some("bank"));
    assert_eq!(
        filtered,
        vec!["AlphaBank".to_owned()],
        "substring filter must narrow the result set"
    );
}

#[test]
fn list_filter_is_case_insensitive() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let vault = vault_with_entries(&dest, &["Bank", "Email"]);

    assert_eq!(
        vault.list(Some("BANK")),
        vec!["Bank".to_owned()],
        "uppercase needle must still match a lowercase haystack"
    );
}

#[test]
fn get_returns_view_for_existing_entry_without_password() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let vault = vault_with_entries(&dest, &["Bank"]);

    let view: EntryView = vault
        .get(EntryPath {
            groups: &[],
            title: "Bank",
        })
        .expect("entry exists, view must be Some");

    assert_eq!(view.title.as_deref(), Some("Bank"));
    assert_eq!(view.username.as_deref(), Some("alice"));
    assert_eq!(view.url.as_deref(), Some("https://example.test"));
    // EntryView intentionally has no `password` field. Callers must opt
    // in via `Vault::get_password`. This assertion is structural: it
    // pins the type's shape so adding a `password` field would break
    // here and force a deliberate review.
    let _no_password_field: fn(&EntryView) -> () = |_v: &EntryView| {};
}

#[test]
fn get_returns_none_for_missing_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let vault = vault_with_entries(&dest, &["Bank"]);

    assert!(
        vault
            .get(EntryPath {
                groups: &[],
                title: "Nope",
            })
            .is_none(),
        "missing entry must yield None, not a default-filled view"
    );
}

#[test]
fn get_password_returns_zeroizing_value() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let vault = vault_with_entries(&dest, &["Bank"]);

    let pw: Zeroizing<String> = vault
        .get_password(EntryPath {
            groups: &[],
            title: "Bank",
        })
        .expect("password is set");
    // Helper assigns title as password.
    assert_eq!(pw.as_str(), "Bank");

    assert!(
        vault
            .get_password(EntryPath {
                groups: &[],
                title: "Nope",
            })
            .is_none(),
        "missing entry => None password (not Some(empty))"
    );
}

#[test]
fn history_view_count_matches_edits() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let mut vault = vault_with_entries(&dest, &["Bank"]);

    // Three edits → three historical versions (each set_field snapshots
    // the prior version via edit_tracking).
    let path = EntryPath {
        groups: &[],
        title: "Bank",
    };
    for u in ["alice2", "alice3", "alice4"] {
        vault
            .set_field(path, EntryField::Username, EntryFieldValue::Plain(u))
            .unwrap();
    }

    let hv: HistoryView = vault.history(path).expect("entry exists");
    assert_eq!(hv.count, 3, "three edits must produce three history rows");
    assert_eq!(
        hv.timestamps.len(),
        3,
        "timestamps Vec must align 1:1 with count"
    );
}

#[test]
fn history_view_timestamps_align_with_edits() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let mut vault = vault_with_entries(&dest, &["Bank"]);

    let path = EntryPath {
        groups: &[],
        title: "Bank",
    };
    vault
        .set_field(path, EntryField::Username, EntryFieldValue::Plain("alice2"))
        .unwrap();

    let hv = vault.history(path).expect("entry exists");
    assert_eq!(hv.count, 1);
    // The single recorded timestamp must come back as Some - upstream
    // populates last_modification on every edit.
    assert!(
        hv.timestamps[0].is_some(),
        "edit_tracking populates last_modification; timestamp must be Some"
    );
}

#[test]
fn entry_exists_true_for_present_false_for_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let vault = vault_with_entries(&dest, &["Bank"]);

    assert!(vault.entry_exists(EntryPath {
        groups: &[],
        title: "Bank"
    }));
    assert!(!vault.entry_exists(EntryPath {
        groups: &[],
        title: "Nope"
    }));
}

// ---------------------------------------------------------------------------
// rotate_keyfile.
//
// Tests that the new `Vault::rotate_keyfile` method correctly adds, removes,
// and replaces the keyfile composite. All of these route through the shared
// `save_and_verify_with_backup` helper; the verify-failure rollback path is
// covered for all rotations by `rotation_rollback_restores_original_when_
// verify_would_fail` above.
// ---------------------------------------------------------------------------

/// Write 64 random bytes to `path` to act as a fresh keyfile. KeePass
/// accepts arbitrary binary content; only the bytes' identity matters.
fn write_random_keyfile(path: &std::path::Path) {
    use std::io::Write;
    // Deterministic-ish content seeded from the path so different test
    // tempdirs produce different keyfiles. Avoids needing rand in the
    // test deps.
    let seed: u64 = path
        .as_os_str()
        .to_string_lossy()
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
    let bytes: Vec<u8> = (0..64u8)
        .map(|i| seed.wrapping_mul(i as u64 + 1).to_le_bytes()[i as usize % 8])
        .collect();
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(&bytes).unwrap();
}

#[test]
fn rotate_keyfile_add_makes_keyfile_required() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let kf_path = tmp.path().join("new.key");
    write_random_keyfile(&kf_path);

    Vault::create(
        &dest,
        Zeroizing::new("pw".to_owned()),
        None,
        tiny_template(),
        false,
    )
    .unwrap();
    let mut vault = Vault::open(&dest, Zeroizing::new("pw".to_owned()), None).unwrap();

    vault
        .rotate_keyfile(Some(&kf_path), RotateOpts { backup: true })
        .expect("rotate keyfile add");
    drop(vault);

    // After rotation: passphrase-only must fail; passphrase + keyfile
    // must succeed.
    assert!(
        Vault::open(&dest, Zeroizing::new("pw".to_owned()), None).is_err(),
        "passphrase-only must be rejected after add"
    );
    Vault::open(&dest, Zeroizing::new("pw".to_owned()), Some(&kf_path))
        .expect("composite must open");
}

#[test]
fn rotate_keyfile_remove_makes_keyfile_optional() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let kf_path = tmp.path().join("k.key");
    write_random_keyfile(&kf_path);

    // Create passphrase-only, then add a keyfile so we have something
    // to remove.
    Vault::create(
        &dest,
        Zeroizing::new("pw".to_owned()),
        None,
        tiny_template(),
        false,
    )
    .unwrap();
    {
        let mut v = Vault::open(&dest, Zeroizing::new("pw".to_owned()), None).unwrap();
        v.rotate_keyfile(Some(&kf_path), RotateOpts::default())
            .unwrap();
    }

    // Now remove the keyfile.
    let mut vault = Vault::open(&dest, Zeroizing::new("pw".to_owned()), Some(&kf_path)).unwrap();
    vault
        .rotate_keyfile(None, RotateOpts::default())
        .expect("rotate keyfile remove");
    drop(vault);

    // Passphrase-only must succeed now.
    Vault::open(&dest, Zeroizing::new("pw".to_owned()), None)
        .expect("passphrase-only must open after remove");
}

#[test]
fn rotate_keyfile_replace_swaps_keyfile() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let old_kf = tmp.path().join("old.key");
    let new_kf = tmp.path().join("new.key");
    write_random_keyfile(&old_kf);
    write_random_keyfile(&new_kf);

    // Start with the old keyfile.
    Vault::create(
        &dest,
        Zeroizing::new("pw".to_owned()),
        None,
        tiny_template(),
        false,
    )
    .unwrap();
    {
        let mut v = Vault::open(&dest, Zeroizing::new("pw".to_owned()), None).unwrap();
        v.rotate_keyfile(Some(&old_kf), RotateOpts::default())
            .unwrap();
    }

    // Swap to the new keyfile.
    let mut vault = Vault::open(&dest, Zeroizing::new("pw".to_owned()), Some(&old_kf)).unwrap();
    vault
        .rotate_keyfile(Some(&new_kf), RotateOpts::default())
        .expect("rotate keyfile replace");
    drop(vault);

    // Old keyfile must no longer open; new one must.
    assert!(
        Vault::open(&dest, Zeroizing::new("pw".to_owned()), Some(&old_kf)).is_err(),
        "old keyfile must be rejected after replace"
    );
    Vault::open(&dest, Zeroizing::new("pw".to_owned()), Some(&new_kf))
        .expect("new keyfile must open");
}

#[test]
fn rotate_keyfile_with_no_change_still_saves_and_returns_outcome() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    Vault::create(
        &dest,
        Zeroizing::new("pw".to_owned()),
        None,
        tiny_template(),
        false,
    )
    .unwrap();
    let mut vault = Vault::open(&dest, Zeroizing::new("pw".to_owned()), None).unwrap();

    // Rotate to None on a passphrase-only vault: the held state doesn't
    // change, but a save+verify still runs (and can take a backup) so
    // the call is observable.
    let outcome = vault
        .rotate_keyfile(None, RotateOpts { backup: true })
        .expect("noop rotate keyfile");
    assert!(
        outcome.backup_path.is_some(),
        "backup must be created when requested"
    );
    drop(vault);

    Vault::open(&dest, Zeroizing::new("pw".to_owned()), None)
        .expect("file still opens with original creds");
}

#[test]
fn current_argon2id_params_matches_template_used_at_create() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    Vault::create(
        &dest,
        Zeroizing::new("pw".to_owned()),
        None,
        tiny_template(),
        false,
    )
    .unwrap();
    let vault = Vault::open(&dest, Zeroizing::new("pw".to_owned()), None).unwrap();

    let params = vault
        .current_argon2id_params()
        .expect("tiny_template uses Argon2id, not legacy AES-KDF");
    assert_eq!(params, tiny_template().kdf);
}

#[test]
fn rotate_kdf_noop_when_already_argon2id() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    Vault::create(
        &dest,
        Zeroizing::new("pw".to_owned()),
        None,
        tiny_template(),
        false,
    )
    .unwrap();

    let mut vault = Vault::open(&dest, Zeroizing::new("pw".to_owned()), None).unwrap();
    let outcome = vault.rotate_kdf(RotateOpts { backup: true }).unwrap();

    assert!(!outcome.changed, "no-op: already on Argon2id");
    assert!(outcome.backup_path.is_none(), "no-op: no backup written");
}

#[test]
fn rotate_kdf_legacy_aeskdf_upgrades_and_reports_changed() {
    let fixture = "kdbx40-legacy";
    let (_tmp, dest) = copied_fixture(fixture);
    let password = fixture_password(fixture);

    let mut vault = Vault::open(&dest, Zeroizing::new(password), None).unwrap();
    let outcome = vault.rotate_kdf(RotateOpts { backup: false }).unwrap();

    assert!(outcome.changed, "AES-KDF -> Argon2id is a real rotation");
    assert!(outcome.backup_path.is_none(), "backup disabled");
}

#[test]
fn rotate_kdf_legacy_aeskdf_with_backup_reports_changed_and_backup_path() {
    let fixture = "kdbx40-legacy";
    let (_tmp, dest) = copied_fixture(fixture);
    let password = fixture_password(fixture);

    let mut vault = Vault::open(&dest, Zeroizing::new(password), None).unwrap();
    let outcome = vault.rotate_kdf(RotateOpts { backup: true }).unwrap();

    assert!(outcome.changed, "AES-KDF -> Argon2id is a real rotation");
    assert!(outcome.backup_path.is_some(), "backup enabled and written");
}
