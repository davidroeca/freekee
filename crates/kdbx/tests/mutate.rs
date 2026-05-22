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

// ---------------------------------------------------------------------------
// Format rotation: bringing a parsed database to `keepass-rs`'s current
// write target (today KDBX4(0)) so it can be saved at all. Without
// this, `save` on a parsed KDBX 3 database errors with
// `UnsupportedVersion`.
// ---------------------------------------------------------------------------

#[test]
fn ensure_writable_mutates_kdbx3_to_current_kdbx4() {
    let fdir = fixture_dir("kdbx3-legacy");
    let pass = std::fs::read_to_string(fdir.join("password.txt"))
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    let mut db = Database::open(&fdir.join("db.kdbx"), &pass, None).unwrap();
    assert_eq!(db.kdbx_version().major(), 3, "fixture precondition");

    let changed = db.ensure_writable();

    assert!(changed, "KDB3 input must mutate");
    assert_eq!(
        db.kdbx_version().major(),
        4,
        "in-memory version must now be KDBX4"
    );
}

#[test]
fn ensure_writable_no_op_on_current_kdbx4() {
    let mut db = Database::new_empty(tiny_template());
    let v_before = db.kdbx_version();

    let changed = db.ensure_writable();

    assert!(!changed, "freshly-created KDBX4 must be no-op");
    assert_eq!(
        db.kdbx_version(),
        v_before,
        "version must be unchanged on no-op"
    );
}

#[test]
fn ensure_writable_kdbx3_then_save_round_trips_as_kdbx4() {
    let fdir = fixture_dir("kdbx3-legacy");
    let pass = std::fs::read_to_string(fdir.join("password.txt"))
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    let mut db = Database::open(&fdir.join("db.kdbx"), &pass, None).unwrap();
    let entries_before: Vec<String> = db
        .entries()
        .filter_map(|e| e.title().map(str::to_owned))
        .collect();
    assert!(
        !entries_before.is_empty(),
        "fixture must have at least one entry"
    );

    db.ensure_writable();

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("rotated.kdbx");
    db.save(&dest, &pass, None).unwrap();

    let reopened = Database::open(&dest, &pass, None).unwrap();
    assert_eq!(reopened.kdbx_version().major(), 4, "file on disk is KDBX4");
    let entries_after: Vec<String> = reopened
        .entries()
        .filter_map(|e| e.title().map(str::to_owned))
        .collect();
    assert_eq!(entries_before, entries_after, "entries must round-trip");
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

// ---------------------------------------------------------------------------
// keepassxc-cli compatibility.
//
// `Database::new_empty` patches Meta fields that KeePassXC expects to be
// numeric. Without these patches, `cs_opt_fromstr` serializes `None`
// as empty strings, which KeePassXC rejects with "Invalid number
// value".
// ---------------------------------------------------------------------------

#[cfg(feature = "keepassxc-verify")]
fn assert_keepassxc_db_info_accepts(path: &std::path::Path, password: &str) {
    use std::io::Write;
    let mut child = std::process::Command::new("keepassxc-cli")
        .arg("db-info")
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("keepassxc-cli must be on PATH (feature `keepassxc-verify`)");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(format!("{password}\n").as_bytes())
        .expect("write password");
    let output = child.wait_with_output().expect("wait keepassxc-cli");
    assert!(
        output.status.success(),
        "keepassxc-cli rejected {}: stderr={}",
        path.display(),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(feature = "keepassxc-verify")]
#[test]
fn keepassxc_can_open_file_with_deleted_object() {
    // Reproduces the delete-path defect surfaced by the operator smoke
    // chain: `apply_keepassxc_defaults` runs on `open` / `new_empty`,
    // but `remove_entry` (which adds a `DeletedObject` after
    // initialization) leaves its numeric fields un-normalized. The
    // resulting `<UsageCount></UsageCount>` empty element on the
    // historical-snapshot side of the deletion is what KeePassXC
    // rejects with "Invalid number value".
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("with-deleted.kdbx");
    let mut db = Database::new_empty(tiny_template());
    db.add_entry(
        EntryPath {
            groups: &[],
            title: "ToDelete",
        },
        EntryDraft {
            username: Some("alice"),
            password: Some("secret"),
            ..EntryDraft::default()
        },
    )
    .unwrap();
    db.remove_entry(EntryPath {
        groups: &[],
        title: "ToDelete",
    })
    .unwrap();
    assert!(
        db.deleted_object_count() >= 1,
        "remove_entry should populate deleted_objects"
    );
    db.save(&dest, "del-test-pw", None).unwrap();

    // Round-trip via our own code still works.
    Database::open(&dest, "del-test-pw", None).expect("our parser must reopen the file");

    // KeePassXC must accept it.
    assert_keepassxc_db_info_accepts(&dest, "del-test-pw");
}

#[cfg(feature = "keepassxc-verify")]
#[test]
fn keepassxc_can_open_file_after_set_entry_field() {
    // Hypothesis: `set_entry_field` -> `edit_tracking` snapshots the
    // prior entry into history. If the history clone introduces any
    // `Option<numeric>` set to `None`, KeePassXC will reject it.
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("hist.kdbx");
    let mut db = Database::new_empty(tiny_template());
    db.add_entry(
        EntryPath {
            groups: &[],
            title: "github",
        },
        EntryDraft {
            username: Some("alice"),
            password: Some("first"),
            ..EntryDraft::default()
        },
    )
    .unwrap();
    db.set_entry_field(
        EntryPath {
            groups: &[],
            title: "github",
        },
        EntryField::Password,
        EntryFieldValue::Protected("second"),
    )
    .unwrap();
    db.save(&dest, "hist-pw", None).unwrap();

    assert_keepassxc_db_info_accepts(&dest, "hist-pw");
}

#[cfg(feature = "keepassxc-verify")]
#[test]
fn keepassxc_can_open_file_created_by_new_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("init.kdbx");
    let mut db = Database::new_empty(tiny_template());
    db.add_entry(
        EntryPath {
            groups: &[],
            title: "Test",
        },
        EntryDraft {
            username: Some("alice"),
            password: Some("secret123"),
            ..EntryDraft::default()
        },
    )
    .unwrap();
    db.save(&dest, "init-test-pw", None).unwrap();

    // Verify our own code can round-trip the database.
    let reopened = Database::open(&dest, "init-test-pw", None).unwrap();
    assert_eq!(
        reopened.root_entry_count(),
        1,
        "should have 1 entry after round-trip"
    );

    let mut child = std::process::Command::new("keepassxc-cli")
        .arg("db-info")
        .arg(&dest)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("keepassxc-cli must be on PATH (feature `keepassxc-verify`)");
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"init-test-pw\n")
        .expect("write password");
    let output = child.wait_with_output().expect("wait keepassxc-cli");
    assert!(
        output.status.success(),
        "keepassxc-cli rejected init-created file: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(feature = "keepassxc-verify")]
#[test]
fn keepassxc_can_open_kdbx3_after_format_rotation() {
    // Round-trip the legacy KDBX 3 fixture through `ensure_writable`
    // + `save`, then assert `keepassxc-cli db-info` accepts the
    // rotated file. Locks in the KDB3 -> current upgrade path as a
    // KeePassXC-compat operation.
    let fdir = fixture_dir("kdbx3-legacy");
    let pass = std::fs::read_to_string(fdir.join("password.txt"))
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("rotated.kdbx");
    let mut db = Database::open(&fdir.join("db.kdbx"), &pass, None).unwrap();
    assert!(db.ensure_writable(), "fixture is KDB3, mutation expected");
    db.save(&dest, &pass, None).unwrap();

    assert_keepassxc_db_info_accepts(&dest, &pass);
}

// ---------------------------------------------------------------------------
// `set_entry_expiry` primitive: write both `times.expires` and
// `times.expiry` together, snapshot history, persist through reopen.
// Powers the upcoming `freekee fix --extend-expiry-days N` flow.
// ---------------------------------------------------------------------------

#[test]
fn set_entry_expiry_some_persists_after_save_and_reopen() {
    let mut db = Database::new_empty(tiny_template());
    db.add_entry(
        EntryPath {
            groups: &[],
            title: "Token",
        },
        EntryDraft {
            password: Some("hunter2"),
            ..EntryDraft::default()
        },
    )
    .unwrap();

    let target = chrono::NaiveDate::from_ymd_opt(2027, 1, 15)
        .unwrap()
        .and_hms_opt(12, 0, 0)
        .unwrap();
    db.set_entry_expiry(
        EntryPath {
            groups: &[],
            title: "Token",
        },
        Some(target),
    )
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("expiry.kdbx");
    db.save(&path, "test-passphrase", None).unwrap();

    let reopened = Database::open(&path, "test-passphrase", None).unwrap();
    let entry = reopened
        .entry_by_path(EntryPath {
            groups: &[],
            title: "Token",
        })
        .expect("entry survives save+reopen");
    assert_eq!(
        entry.expires_at(),
        Some(target),
        "expires_at must reflect the value set via set_entry_expiry"
    );
}

#[test]
fn set_entry_expiry_none_clears_expires_flag() {
    let mut db = Database::new_empty(tiny_template());
    db.add_entry(
        EntryPath {
            groups: &[],
            title: "Token",
        },
        EntryDraft::default(),
    )
    .unwrap();
    let target = chrono::NaiveDate::from_ymd_opt(2027, 1, 15)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    // First set an expiry, then clear it.
    db.set_entry_expiry(
        EntryPath {
            groups: &[],
            title: "Token",
        },
        Some(target),
    )
    .unwrap();
    db.set_entry_expiry(
        EntryPath {
            groups: &[],
            title: "Token",
        },
        None,
    )
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("cleared.kdbx");
    db.save(&path, "test-passphrase", None).unwrap();
    let reopened = Database::open(&path, "test-passphrase", None).unwrap();
    let entry = reopened
        .entry_by_path(EntryPath {
            groups: &[],
            title: "Token",
        })
        .unwrap();
    assert_eq!(
        entry.expires_at(),
        None,
        "expires_at must read None after set_entry_expiry(None) (the \
         expires flag flipped to false; entry is not expirable)"
    );
}

#[test]
fn set_entry_expiry_snapshots_history() {
    let mut db = Database::new_empty(tiny_template());
    db.add_entry(
        EntryPath {
            groups: &[],
            title: "Token",
        },
        EntryDraft::default(),
    )
    .unwrap();
    // Baseline: a freshly-added entry has zero history versions.
    let baseline = db
        .entry_by_path(EntryPath {
            groups: &[],
            title: "Token",
        })
        .unwrap()
        .history_count();

    let target = chrono::NaiveDate::from_ymd_opt(2027, 1, 15)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    db.set_entry_expiry(
        EntryPath {
            groups: &[],
            title: "Token",
        },
        Some(target),
    )
    .unwrap();

    let entry = db
        .entry_by_path(EntryPath {
            groups: &[],
            title: "Token",
        })
        .unwrap();
    assert_eq!(
        entry.history_count(),
        baseline + 1,
        "edit_tracking must snapshot the prior entry state into history"
    );
}

#[test]
fn set_entry_expiry_not_found_returns_error() {
    let mut db = Database::new_empty(tiny_template());
    let target = chrono::NaiveDate::from_ymd_opt(2027, 1, 15)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    let err = db
        .set_entry_expiry(
            EntryPath {
                groups: &[],
                title: "Nonexistent",
            },
            Some(target),
        )
        .expect_err("set_entry_expiry on a missing entry must fail");
    assert!(
        matches!(err, kdbx::Error::NotFound),
        "expected Error::NotFound, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Header fingerprint.
//
// `Database::read_header_fingerprint` returns a stable hash of the file's
// unencrypted prefix (master seed, KDF salt, transform seed, encryption IV
// region — all regenerated by every save). Used by `core::Vault` to detect
// concurrent edits between open and save. Implementation is filesystem-only:
// no decrypt, no credentials.
// ---------------------------------------------------------------------------

#[test]
fn read_header_fingerprint_stable_for_unchanged_file() {
    let db = Database::new_empty(tiny_template());
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("fp.kdbx");
    db.save(&path, "test-passphrase", None).unwrap();

    let fp1 = Database::read_header_fingerprint(&path).unwrap();
    let fp2 = Database::read_header_fingerprint(&path).unwrap();
    assert_eq!(
        fp1, fp2,
        "fingerprint of an unchanged file must be byte-stable"
    );
}

#[test]
fn read_header_fingerprint_changes_after_save() {
    let db = Database::new_empty(tiny_template());
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("fp.kdbx");
    db.save(&path, "test-passphrase", None).unwrap();
    let fp1 = Database::read_header_fingerprint(&path).unwrap();

    // Save the same in-memory database again. The on-disk header must
    // change because the upstream serializer regenerates master_seed,
    // KDF salt, transform seed, and IV from getrandom on every call.
    db.save(&path, "test-passphrase", None).unwrap();
    let fp2 = Database::read_header_fingerprint(&path).unwrap();

    assert_ne!(
        fp1, fp2,
        "every save regenerates the header; the fingerprint must change"
    );
}

#[test]
fn read_header_fingerprint_errors_for_missing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("does-not-exist.kdbx");
    Database::read_header_fingerprint(&missing)
        .expect_err("fingerprint of a missing file must error");
}

// ---------------------------------------------------------------------------
// Atomic save.
//
// `Database::save` writes to a sibling `<path>.freekee-tmp` first, then
// `fs::rename`s into place. On a successful save the tempfile is gone; on
// a rename failure the tempfile remains on disk and the target is
// untouched. Closes the truncate-window crash hole of the previous
// `File::create(path)` shape.
// ---------------------------------------------------------------------------

fn freekee_tmp_for(path: &std::path::Path) -> std::path::PathBuf {
    let mut buf = path.as_os_str().to_owned();
    buf.push(".freekee-tmp");
    std::path::PathBuf::from(buf)
}

#[test]
fn save_renames_tempfile_into_place_no_orphan_on_success() {
    let db = Database::new_empty(tiny_template());
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("v.kdbx");
    let tmpfile = freekee_tmp_for(&path);

    db.save(&path, "test-passphrase", None).unwrap();

    assert!(path.exists(), "target file must exist after save");
    assert!(
        !tmpfile.exists(),
        "atomic save must rename the tempfile into place \
         (no `<path>.freekee-tmp` orphan should remain on success)"
    );
}

#[test]
fn save_leaves_tempfile_when_rename_fails_and_preserves_target() {
    // Force the rename step to fail by occupying `path` with a non-empty
    // directory. The atomic-save contract: the tempfile remains on disk
    // as evidence of the failed write; the existing target is untouched.
    let db = Database::new_empty(tiny_template());
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("v.kdbx");
    std::fs::create_dir(&path).unwrap();
    let sentinel = path.join("sentinel.txt");
    std::fs::write(&sentinel, b"do-not-clobber").unwrap();
    let tmpfile = freekee_tmp_for(&path);

    let err = db.save(&path, "test-passphrase", None);
    assert!(err.is_err(), "save into a directory must fail");

    assert!(
        path.is_dir(),
        "target directory must remain a directory after failed save"
    );
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"do-not-clobber",
        "pre-existing files inside the target directory must be untouched"
    );
    assert!(
        tmpfile.is_file(),
        "atomic save: tempfile remains as evidence when the rename fails"
    );
}
