//! Mutation primitives on `kdbx::Database`. Each test builds a small
//! in-memory database, mutates it, saves to a tempfile, reopens, and
//! asserts the change persisted. Tiny Argon2 params keep wall-clock
//! tolerable; production defaults live in `core::Vault::create`.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use kdbx::{
    Argon2idParams, Database, EntryDraft, EntryField, EntryFieldValue, EntryPath, GroupPath,
    InnerCipher, Kdf, NewDatabaseTemplate, OuterCipher,
};

/// Smallest Argon2id config that still satisfies the upstream
/// validator (memory >= 8 KiB per parallel lane). Tests must not use
/// these for anything but speed.
fn tiny_template() -> NewDatabaseTemplate {
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

#[test]
fn add_entry_persists_after_save_and_reopen() {
    let mut db = Database::new_empty(tiny_template());
    db.add_entry(
        EntryPath {
            groups: &[],
            title: "Bank",
        },
        EntryDraft {
            username: Some("alice"),
            password: Some("hunter2"),
            url: Some("https://bank.example"),
            notes: None,
        },
    )
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("new.kdbx");
    db.save(&path, "test-passphrase", None).unwrap();

    let reopened = Database::open(&path, "test-passphrase", None).unwrap();
    let entry = reopened
        .entry_by_path(EntryPath {
            groups: &[],
            title: "Bank",
        })
        .expect("entry should be found after reopen");

    assert_eq!(entry.title(), Some("Bank"));
    assert_eq!(entry.username(), Some("alice"));
    assert_eq!(entry.password(), Some("hunter2"));
    assert_eq!(entry.url(), Some("https://bank.example"));
}

#[test]
fn set_entry_field_password_lands_in_history() {
    let mut db = Database::new_empty(tiny_template());
    db.add_entry(
        EntryPath {
            groups: &[],
            title: "Bank",
        },
        EntryDraft {
            password: Some("first-password"),
            ..EntryDraft::default()
        },
    )
    .unwrap();

    db.set_entry_field(
        EntryPath {
            groups: &[],
            title: "Bank",
        },
        EntryField::Password,
        EntryFieldValue::Protected("second-password"),
    )
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("set-history.kdbx");
    db.save(&path, "test-passphrase", None).unwrap();

    let reopened = Database::open(&path, "test-passphrase", None).unwrap();
    let entry = reopened
        .entry_by_path(EntryPath {
            groups: &[],
            title: "Bank",
        })
        .expect("entry should be found");

    assert_eq!(entry.password(), Some("second-password"));
    assert_eq!(
        entry.history_count(),
        1,
        "edit_tracking must snapshot the prior version into history"
    );
    let prior = entry.historical(0).expect("history index 0");
    assert_eq!(prior.password(), Some("first-password"));
}

#[test]
fn remove_entry_adds_uuid_to_deleted_objects() {
    let mut db = Database::new_empty(tiny_template());
    db.add_entry(
        EntryPath {
            groups: &[],
            title: "Bank",
        },
        EntryDraft::default(),
    )
    .unwrap();

    let before = db.deleted_object_count();
    db.remove_entry(EntryPath {
        groups: &[],
        title: "Bank",
    })
    .unwrap();
    let after = db.deleted_object_count();

    assert!(
        db.entry_by_path(EntryPath {
            groups: &[],
            title: "Bank",
        })
        .is_none(),
        "removed entry must be gone from the live tree"
    );
    assert_eq!(
        after,
        before + 1,
        "EntryTrack::remove must register the UUID in deleted_objects \
         so KeePassXC sync respects the deletion"
    );

    // Survives save/reopen.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("removed.kdbx");
    db.save(&path, "test-passphrase", None).unwrap();
    let reopened = Database::open(&path, "test-passphrase", None).unwrap();
    assert_eq!(reopened.deleted_object_count(), after);
}

#[test]
fn move_entry_to_existing_group_relocates() {
    let mut db = Database::new_empty(tiny_template());
    db.ensure_group(GroupPath {
        segments: &["Personal"],
    })
    .unwrap();
    db.ensure_group(GroupPath {
        segments: &["Work"],
    })
    .unwrap();
    db.add_entry(
        EntryPath {
            groups: &["Personal"],
            title: "Email",
        },
        EntryDraft {
            password: Some("hunter2"),
            ..EntryDraft::default()
        },
    )
    .unwrap();

    db.move_entry(
        EntryPath {
            groups: &["Personal"],
            title: "Email",
        },
        EntryPath {
            groups: &["Work"],
            title: "Email",
        },
    )
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("moved.kdbx");
    db.save(&path, "test-passphrase", None).unwrap();
    let reopened = Database::open(&path, "test-passphrase", None).unwrap();

    assert!(
        reopened
            .entry_by_path(EntryPath {
                groups: &["Personal"],
                title: "Email"
            })
            .is_none(),
        "entry should no longer live in the source group"
    );
    let moved = reopened
        .entry_by_path(EntryPath {
            groups: &["Work"],
            title: "Email",
        })
        .expect("entry should be in destination group");
    assert_eq!(moved.password(), Some("hunter2"));
}

#[test]
fn ensure_group_creates_intermediate_groups() {
    let mut db = Database::new_empty(tiny_template());
    db.ensure_group(GroupPath {
        segments: &["A", "B", "C"],
    })
    .unwrap();
    // Idempotent: re-running with the same path adds nothing.
    db.ensure_group(GroupPath {
        segments: &["A", "B", "C"],
    })
    .unwrap();

    db.add_entry(
        EntryPath {
            groups: &["A", "B", "C"],
            title: "Deep",
        },
        EntryDraft::default(),
    )
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("deep.kdbx");
    db.save(&path, "test-passphrase", None).unwrap();
    let reopened = Database::open(&path, "test-passphrase", None).unwrap();
    let entry = reopened
        .entry_by_path(EntryPath {
            groups: &["A", "B", "C"],
            title: "Deep",
        })
        .expect("entry should be reachable through nested groups");
    assert_eq!(entry.title(), Some("Deep"));
}

#[test]
fn set_kdf_params_then_save_persists_new_params() {
    let mut db = Database::new_empty(tiny_template());
    db.set_kdf_params(Argon2idParams {
        memory: 16 * 1024,
        iterations: 3,
        parallelism: 2,
    })
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("kdf.kdbx");
    db.save(&path, "test-passphrase", None).unwrap();

    let reopened = Database::open(&path, "test-passphrase", None).unwrap();
    match reopened.kdf() {
        Kdf::Argon2id {
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

// ---------------------------------------------------------------------------
// Keyfile-on-save.
//
// `save` accepts an optional keyfile and the resulting file requires the same
// composite to reopen.
// ---------------------------------------------------------------------------

fn fixture_dir(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/roundtrip/fixtures")
        .join(name)
}

#[test]
fn save_with_keyfile_round_trips_with_keyfile_required() {
    let fdir = fixture_dir("with-keyfile");
    let pass = std::fs::read_to_string(fdir.join("password.txt"))
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    let keyfile = fdir.join("keyfile.bin");

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("copy.kdbx");
    std::fs::copy(fdir.join("db.kdbx"), &dest).unwrap();

    let mut db = Database::open(&dest, &pass, Some(&keyfile)).unwrap();
    // Mutate so we can prove the save round-trip went through, not
    // just that the original bytes were left in place.
    db.add_entry(
        EntryPath {
            groups: &[],
            title: "Inserted",
        },
        EntryDraft {
            username: Some("alice"),
            password: None,
            url: None,
            notes: None,
        },
    )
    .unwrap();

    db.save(&dest, &pass, Some(&keyfile)).unwrap();

    // Reopen with the full composite: succeeds and the mutation is
    // visible.
    let reopened = Database::open(&dest, &pass, Some(&keyfile)).unwrap();
    assert!(
        reopened
            .entry_by_path(EntryPath {
                groups: &[],
                title: "Inserted"
            })
            .is_some(),
        "mutation must persist across a keyfile-preserving save"
    );

    // Reopen with passphrase only: must fail. Today's broken `save`
    // would write a passphrase-only file and this would (incorrectly)
    // succeed.
    assert!(
        Database::open(&dest, &pass, None).is_err(),
        "keyfile must remain required after save"
    );
}

#[test]
fn save_without_keyfile_remains_passphrase_only() {
    let mut db = Database::new_empty(tiny_template());
    db.add_entry(
        EntryPath {
            groups: &[],
            title: "B",
        },
        EntryDraft {
            username: Some("a"),
            password: None,
            url: None,
            notes: None,
        },
    )
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    db.save(&dest, "pw", None).unwrap();

    Database::open(&dest, "pw", None).expect("passphrase-only round trip still works");
}
