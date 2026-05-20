//! CLI tests for `freekee fix`. Drives the interactive prompt loop via
//! stdin: line 1 = passphrase, lines 2..N = `y` / `n` / `q` responses
//! to per-finding prompts and the final confirm.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use assert_cmd::Command;
use freekee_core::Vault;
use kdbx::{Argon2idParams, EntryDraft, EntryPath, InnerCipher, NewDatabaseTemplate, OuterCipher};
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use std::path::Path;
use zeroize::Zeroizing;

fn freekee() -> Command {
    Command::cargo_bin("freekee").expect("cargo bin freekee")
}

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

/// Build a tiny vault with a single weak-password entry; audit will
/// flag both `weak-argon2-params` (db-level) and `weak-entry-password`.
fn seed_vault_with_weak_entry(path: &Path, password: &str, entry_password: &str) {
    let mut vault = Vault::create(
        path,
        Zeroizing::new(password.to_owned()),
        None,
        tiny_template(),
        false,
    )
    .unwrap();
    vault
        .upsert_entry(
            EntryPath {
                groups: &[],
                title: "Forum",
            },
            EntryDraft {
                password: Some(entry_password),
                ..EntryDraft::default()
            },
        )
        .unwrap();
    vault.save().unwrap();
}

#[test]
fn fix_help_lists_expected_flags() {
    freekee()
        .arg("fix")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("--extend-expiry-days"))
        .stdout(contains("--length"))
        .stdout(contains("--no-backup"))
        .stdout(contains("--pass-stdin"));
}

/// Accepting a weak-entry-password finding regenerates that entry's
/// password, produces exactly ONE backup file, and the entry's
/// post-fix password is not the pre-fix value.
#[test]
fn fix_accept_weak_entry_rotates_with_single_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("accept.kdbx");
    // Strong-enough master passphrase so `weak-passphrase` doesn't fire
    // (we want a deterministic in-scope finding count).
    let master = "FixTestMaster-PassphraseStrong-2026-XYZ!aA9";
    seed_vault_with_weak_entry(&dest, master, "weak-pre-fix-123");

    // Stdin: passphrase, then n (skip weak-argon2-params — DB-level,
    // first in audit order), y (accept weak-entry-password), y (confirm
    // applying 1 fix).
    let stdin = format!("{master}\nn\ny\ny\n");

    freekee()
        .arg("fix")
        .arg("--db")
        .arg(&dest)
        .arg("--pass-stdin")
        .write_stdin(stdin)
        .assert()
        .success();

    // Exactly one backup file in the working dir despite multiple
    // findings; the batch save is the whole point of apply_fix_batch.
    let parent = dest.parent().unwrap();
    let backups: Vec<_> = std::fs::read_dir(parent)
        .unwrap()
        .filter_map(|e| {
            let e = e.ok()?;
            e.file_name()
                .to_string_lossy()
                .contains("freekee-bak")
                .then(|| e.path())
        })
        .collect();
    assert_eq!(
        backups.len(),
        1,
        "exactly one backup file expected; got {backups:?}"
    );

    // The Forum entry's password is no longer the seeded value.
    let vault = Vault::open(&dest, Zeroizing::new(master.to_owned()), None).unwrap();
    let pw = vault
        .get_password(EntryPath {
            groups: &[],
            title: "Forum",
        })
        .expect("password should be present");
    assert_ne!(
        pw.as_str(),
        "weak-pre-fix-123",
        "weak-entry-password fix must regenerate the password"
    );
}

/// Accepting an `expired-entry-overdue` finding extends the entry's
/// expiry forward by --extend-expiry-days.
#[test]
fn fix_accept_expired_extends_expiry_by_days() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("expired.kdbx");
    let master = "FixTestMaster-PassphraseStrong-2026-XYZ!aA9";

    // Build a vault with one entry whose expiry is in the past.
    let mut vault = Vault::create(
        &dest,
        Zeroizing::new(master.to_owned()),
        None,
        tiny_template(),
        false,
    )
    .unwrap();
    vault
        .upsert_entry(
            EntryPath {
                groups: &[],
                title: "OldToken",
            },
            EntryDraft {
                password: Some("StrongEnoughPasswordForEntry-2026-Z9"),
                ..EntryDraft::default()
            },
        )
        .unwrap();
    vault
        .extend_entry_expiry(
            EntryPath {
                groups: &[],
                title: "OldToken",
            },
            chrono::NaiveDate::from_ymd_opt(2020, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
        )
        .unwrap();
    vault.save().unwrap();
    drop(vault);

    // In-scope findings: weak-argon2-params (skip), expired-entry-overdue (accept).
    let stdin = format!("{master}\nn\ny\ny\n");
    let extend_days = 30_i64;

    let before_call = chrono::Utc::now().naive_utc();
    freekee()
        .arg("fix")
        .arg("--db")
        .arg(&dest)
        .arg("--extend-expiry-days")
        .arg(extend_days.to_string())
        .arg("--pass-stdin")
        .write_stdin(stdin)
        .assert()
        .success();
    let after_call = chrono::Utc::now().naive_utc();

    let reopened = kdbx::Database::open(&dest, master, None).unwrap();
    let entry = reopened
        .entry_by_path(EntryPath {
            groups: &[],
            title: "OldToken",
        })
        .unwrap();
    let expiry = entry.expires_at().expect("entry must still expire");
    // The new expiry sits inside the window [before_call + days, after_call + days].
    let min_expected =
        before_call + chrono::Duration::days(extend_days) - chrono::Duration::seconds(2);
    let max_expected =
        after_call + chrono::Duration::days(extend_days) + chrono::Duration::seconds(2);
    assert!(
        expiry >= min_expected && expiry <= max_expected,
        "new expiry {expiry} not within [{min_expected}, {max_expected}]",
    );
}

/// `q` mid-loop applies the fixes accepted so far and skips the rest.
#[test]
fn fix_quit_mid_loop_applies_accepted_so_far() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("quit.kdbx");
    let master = "FixTestMaster-PassphraseStrong-2026-XYZ!aA9";
    seed_vault_with_weak_entry(&dest, master, "weak-pre-fix-123");

    // In-scope findings (in audit order): weak-argon2-params,
    // weak-entry-password. Accept the first, quit before the second.
    // Then 'y' to confirm applying the 1 accepted fix.
    let stdin = format!("{master}\ny\nq\ny\n");

    freekee()
        .arg("fix")
        .arg("--db")
        .arg(&dest)
        .arg("--pass-stdin")
        .write_stdin(stdin)
        .assert()
        .success()
        .stdout(contains("Stopping prompt phase").or(contains("applying 1")));

    // weak-argon2-params fix applied: kdf params should now match
    // freekee_core::DEFAULT_TEMPLATE (64 MiB / 10 / 2).
    let reopened = kdbx::Database::open(&dest, master, None).unwrap();
    match reopened.kdf() {
        kdbx::Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } => {
            assert_eq!(iterations, 10);
            assert_eq!(memory, 64 * 1024 * 1024);
            assert_eq!(parallelism, 2);
        }
        other => panic!("expected Argon2id with default params, got {other:?}"),
    }
    // weak-entry-password fix skipped (we quit before reaching it):
    // entry's password is still the seeded weak value.
    let entry = reopened
        .entry_by_path(EntryPath {
            groups: &[],
            title: "Forum",
        })
        .unwrap();
    assert_eq!(
        entry.password(),
        Some("weak-pre-fix-123"),
        "quitting must skip findings that haven't been prompted yet"
    );
}

/// `--json` is rejected (interactive command). Users wanting machine-
/// readable findings should use `freekee audit --json`.
#[test]
fn fix_rejects_json_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("nojson.kdbx");
    seed_vault_with_weak_entry(&dest, "pw", "weak");

    freekee()
        .arg("fix")
        .arg("--db")
        .arg(&dest)
        .arg("--json")
        .arg("--pass-stdin")
        .write_stdin("pw\n")
        .assert()
        .failure()
        .stderr(contains("--json"));
}

/// Skipping every prompt must leave the file untouched (no save, no
/// backup file written).
#[test]
fn fix_skip_all_does_not_save() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("skip.kdbx");
    seed_vault_with_weak_entry(&dest, "vault-pw", "weak123");
    let mtime_before = std::fs::metadata(&dest).unwrap().modified().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // Many `n` responses cover every prompt regardless of finding count
    // (extra inputs after EOF behavior would be a different test).
    let stdin = format!("vault-pw\n{}", "n\n".repeat(20));

    freekee()
        .arg("fix")
        .arg("--db")
        .arg(&dest)
        .arg("--pass-stdin")
        .write_stdin(stdin)
        .assert()
        .success()
        .stdout(contains("nothing to apply").or(contains("No fixes accepted")));

    let mtime_after = std::fs::metadata(&dest).unwrap().modified().unwrap();
    assert_eq!(
        mtime_before, mtime_after,
        "skip-all must not save: file mtime should not change"
    );
    let parent = dest.parent().unwrap();
    let backups: Vec<_> = std::fs::read_dir(parent)
        .unwrap()
        .filter_map(|e| {
            let e = e.ok()?;
            e.file_name()
                .to_string_lossy()
                .contains("freekee-bak")
                .then(|| e.path())
        })
        .collect();
    assert!(
        backups.is_empty(),
        "skip-all must not produce a backup; got {backups:?}"
    );
}
