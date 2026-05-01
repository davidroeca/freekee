//! Smoke tests for the mutating CLI surface added in milestone 1.
//! Each subcommand gets at least one happy-path test that runs the
//! binary via `assert_cmd` and asserts an observable on-disk effect.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use assert_cmd::Command;
use freekee_core::Vault;
use kdbx::{Argon2idParams, EntryDraft, EntryPath, InnerCipher, NewDatabaseTemplate, OuterCipher};
use predicates::prelude::*;
use predicates::str::contains;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

fn freekee() -> Command {
    Command::cargo_bin("freekee").expect("cargo bin freekee")
}

/// Tiny Argon2id parameters that satisfy the upstream validator while
/// keeping CLI tests cheap. Used for fixtures built in-process before
/// shelling out to the binary.
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

/// Build a fresh KDBX at `path` with a couple of entries - one under
/// root, one under `Personal/`. Used by ls/get/history tests so the
/// binary can be exercised against a known state. `Vault` does not yet
/// expose `ensure_group`, so the test driver reaches one layer down to
/// `kdbx` to seed the nested group; this is fixture-construction
/// scaffolding, not production wiring.
fn seed_vault(path: &Path, password: &str) {
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
                title: "github",
            },
            EntryDraft {
                username: Some("alice"),
                password: Some("gh-secret"),
                url: Some("https://github.com"),
                ..EntryDraft::default()
            },
        )
        .unwrap();
    vault.save().unwrap();
    drop(vault);

    let mut db =
        kdbx::Database::open(path, password, None).expect("reopen for nested-group seeding");
    db.ensure_group(kdbx::GroupPath {
        segments: &["Personal"],
    })
    .unwrap();
    db.add_entry(
        EntryPath {
            groups: &["Personal"],
            title: "email",
        },
        EntryDraft {
            username: Some("alice@example.com"),
            password: Some("em-secret"),
            ..EntryDraft::default()
        },
    )
    .unwrap();
    db.save(path, password, None).unwrap();
}

#[test]
fn init_creates_a_kdbx_that_reopens_with_the_supplied_passphrase() {
    let tmp = tempfile::tempdir().unwrap();
    let dest: PathBuf = tmp.path().join("brand-new.kdbx");

    freekee()
        .arg("init")
        .arg(&dest)
        // Tiny Argon2 params so the test runs in well under a second.
        .arg("--memory")
        .arg("8")
        .arg("--iterations")
        .arg("1")
        .arg("--parallelism")
        .arg("1")
        .arg("--pass-stdin")
        .write_stdin("init-test-pw\n")
        .assert()
        .success();

    assert!(dest.exists(), "init must produce a file at the path");

    // File round-trips through `kdbx::Database::open` with the
    // supplied passphrase, proving init wrote a valid KDBX.
    let db = kdbx::Database::open(&dest, "init-test-pw", None).expect("init output reopens");
    assert_eq!(db.root_entry_count(), 0);
    assert_eq!(db.root_subgroup_count(), 0);
    // Defaults from `core::DEFAULT_TEMPLATE`'s overridden inner cipher.
    assert!(matches!(db.inner_cipher(), kdbx::InnerCipher::ChaCha20));
}

#[test]
fn init_refuses_existing_file_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("existing.kdbx");
    std::fs::write(&dest, b"placeholder").unwrap();
    let before = std::fs::read(&dest).unwrap();

    freekee()
        .arg("init")
        .arg(&dest)
        .arg("--memory")
        .arg("8")
        .arg("--iterations")
        .arg("1")
        .arg("--parallelism")
        .arg("1")
        .arg("--pass-stdin")
        .write_stdin("nope\n")
        .assert()
        .failure()
        .stderr(contains("exists").or(contains("force")));

    assert_eq!(
        std::fs::read(&dest).unwrap(),
        before,
        "existing file must be left untouched without --force"
    );
}

#[test]
fn init_with_force_overwrites_existing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("clobber.kdbx");
    std::fs::write(&dest, b"placeholder").unwrap();

    freekee()
        .arg("init")
        .arg(&dest)
        .arg("--force")
        .arg("--memory")
        .arg("8")
        .arg("--iterations")
        .arg("1")
        .arg("--parallelism")
        .arg("1")
        .arg("--pass-stdin")
        .write_stdin("force-pw\n")
        .assert()
        .success();

    kdbx::Database::open(&dest, "force-pw", None).expect("force-overwritten file is a valid kdbx");
}

#[test]
fn ls_lists_entries_with_group_path_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "ls-pw");

    freekee()
        .arg("ls")
        .arg(&dest)
        .arg("--pass-stdin")
        .write_stdin("ls-pw\n")
        .assert()
        .success()
        .stdout(contains("github"))
        .stdout(contains("Personal/email"));
}

#[test]
fn get_default_does_not_show_password() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "get-pw");

    freekee()
        .arg("get")
        .arg(&dest)
        .arg("github")
        .arg("--pass-stdin")
        .write_stdin("get-pw\n")
        .assert()
        .success()
        .stdout(contains("alice"))
        .stdout(contains("https://github.com"))
        .stdout(predicates::str::contains("gh-secret").not());
}

#[test]
fn get_with_show_surfaces_password_in_stdout() {
    // The carve-out: `get --show` is the one CLI path allowed to
    // print an entry password. The secret-leakage meta-test relaxes
    // its no-leak rule specifically for this command.
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "show-pw");

    freekee()
        .arg("get")
        .arg(&dest)
        .arg("github")
        .arg("--show")
        .arg("--pass-stdin")
        .write_stdin("show-pw\n")
        .assert()
        .success()
        .stdout(contains("gh-secret"));
}

#[test]
fn get_returns_error_for_missing_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "missing-pw");

    freekee()
        .arg("get")
        .arg(&dest)
        .arg("does-not-exist")
        .arg("--pass-stdin")
        .write_stdin("missing-pw\n")
        .assert()
        .failure();
}

#[test]
fn history_reports_zero_for_freshly_seeded_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "hist-pw");

    freekee()
        .arg("history")
        .arg(&dest)
        .arg("github")
        .arg("--pass-stdin")
        .write_stdin("hist-pw\n")
        .assert()
        .success()
        .stdout(contains("0"));
}

#[test]
fn set_creates_a_new_entry_with_field_assignments() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "set-pw");

    freekee()
        .arg("set")
        .arg(&dest)
        .arg("Personal/email")
        .arg("username=alice@example.com")
        .arg("url=https://mail.example.com")
        .arg("--pass-stdin")
        .write_stdin("set-pw\n")
        .assert()
        .success();

    let db = kdbx::Database::open(&dest, "set-pw", None).unwrap();
    let entry = db
        .entry_by_path(EntryPath {
            groups: &["Personal"],
            title: "email",
        })
        .expect("upserted entry");
    assert_eq!(entry.url(), Some("https://mail.example.com"));
}

#[test]
fn set_gen_password_does_not_echo_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "gen-pw");

    let assert = freekee()
        .arg("set")
        .arg(&dest)
        .arg("github")
        .arg("--gen-password")
        .arg("--length")
        .arg("16")
        .arg("--pass-stdin")
        .write_stdin("gen-pw\n")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();

    let db = kdbx::Database::open(&dest, "gen-pw", None).unwrap();
    let entry = db
        .entry_by_path(EntryPath {
            groups: &[],
            title: "github",
        })
        .unwrap();
    let pw = entry.password().expect("entry has a password");
    assert_eq!(pw.len(), 16, "generated password length must be 16");
    assert!(
        !stdout.contains(pw),
        "generated password must not appear in stdout without --print-generated; \
         stdout was: {stdout}"
    );
}

#[test]
fn set_gen_password_with_print_flag_echoes_generated_value() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "gen-print-pw");

    let assert = freekee()
        .arg("set")
        .arg(&dest)
        .arg("github")
        .arg("--gen-password")
        .arg("--length")
        .arg("12")
        .arg("--print-generated")
        .arg("--pass-stdin")
        .write_stdin("gen-print-pw\n")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();

    let db = kdbx::Database::open(&dest, "gen-print-pw", None).unwrap();
    let pw = db
        .entry_by_path(EntryPath {
            groups: &[],
            title: "github",
        })
        .unwrap()
        .password()
        .unwrap()
        .to_owned();
    assert!(
        stdout.contains(&pw),
        "generated password must appear in stdout when --print-generated is set"
    );
}

#[test]
fn rm_removes_entry_and_writes_deleted_object() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "rm-pw");

    freekee()
        .arg("rm")
        .arg(&dest)
        .arg("github")
        .arg("--pass-stdin")
        .write_stdin("rm-pw\n")
        .assert()
        .success();

    let db = kdbx::Database::open(&dest, "rm-pw", None).unwrap();
    assert!(
        db.entry_by_path(EntryPath {
            groups: &[],
            title: "github"
        })
        .is_none()
    );
    assert!(db.deleted_object_count() >= 1);
}

#[test]
fn mv_renames_an_entry_in_place() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "mv-pw");

    freekee()
        .arg("mv")
        .arg(&dest)
        .arg("github")
        .arg("github-renamed")
        .arg("--pass-stdin")
        .write_stdin("mv-pw\n")
        .assert()
        .success();

    let db = kdbx::Database::open(&dest, "mv-pw", None).unwrap();
    assert!(
        db.entry_by_path(EntryPath {
            groups: &[],
            title: "github"
        })
        .is_none()
    );
    assert!(
        db.entry_by_path(EntryPath {
            groups: &[],
            title: "github-renamed"
        })
        .is_some()
    );
}

#[test]
fn rotate_passphrase_changes_credentials_and_writes_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "old-pass");

    freekee()
        .arg("rotate")
        .arg("passphrase")
        .arg(&dest)
        .arg("--pass-stdin")
        .arg("--new-pass-stdin")
        .write_stdin("old-pass\nnew-pass\n")
        .assert()
        .success();

    // New pass works.
    kdbx::Database::open(&dest, "new-pass", None).expect("new pass opens rotated file");
    // Old pass does not.
    assert!(kdbx::Database::open(&dest, "old-pass", None).is_err());
    // Backup landed.
    let has_backup = std::fs::read_dir(tmp.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".freekee-bak-")
    });
    assert!(has_backup, "rotate passphrase must leave a backup file");
}

#[test]
fn rotate_passphrase_no_backup_skips_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "old");

    freekee()
        .arg("rotate")
        .arg("passphrase")
        .arg(&dest)
        .arg("--no-backup")
        .arg("--pass-stdin")
        .arg("--new-pass-stdin")
        .write_stdin("old\nnewer\n")
        .assert()
        .success();

    let has_backup = std::fs::read_dir(tmp.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".freekee-bak-")
    });
    assert!(!has_backup, "--no-backup must suppress backup creation");
}

#[test]
fn rotate_kdf_params_changes_argon2_settings() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "kdf-pw");

    freekee()
        .arg("rotate")
        .arg("kdf-params")
        .arg(&dest)
        .arg("--memory")
        .arg("16")
        .arg("--iterations")
        .arg("3")
        .arg("--parallelism")
        .arg("2")
        .arg("--pass-stdin")
        .write_stdin("kdf-pw\n")
        .assert()
        .success();

    let db = kdbx::Database::open(&dest, "kdf-pw", None).unwrap();
    match db.kdf() {
        kdbx::Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } => {
            assert_eq!(iterations, 3);
            assert_eq!(memory, 16 * 1024 * 1024);
            assert_eq!(parallelism, 2);
        }
        other => panic!("expected Argon2id, got {other:?}"),
    }
}

#[test]
fn rotate_entry_replaces_password_silently_unless_print_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "rot-ent-pw");

    let original_pw = "gh-secret"; // from seed_vault
    let assert = freekee()
        .arg("rotate")
        .arg("entry")
        .arg(&dest)
        .arg("github")
        .arg("--length")
        .arg("20")
        .arg("--pass-stdin")
        .write_stdin("rot-ent-pw\n")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();

    let db = kdbx::Database::open(&dest, "rot-ent-pw", None).unwrap();
    let entry = db
        .entry_by_path(EntryPath {
            groups: &[],
            title: "github",
        })
        .unwrap();
    let new_pw = entry.password().expect("entry has a password").to_owned();
    assert_eq!(new_pw.len(), 20);
    assert_ne!(new_pw, original_pw);
    assert_eq!(entry.history_count(), 1);
    assert!(
        !stdout.contains(&new_pw),
        "rotate entry must not echo the new password without --print-generated"
    );
    assert!(
        !stdout.contains(original_pw),
        "rotate entry must not echo the prior password"
    );
}

#[test]
fn rotate_entry_print_generated_flag_echoes_new_password() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "rot-print-pw");

    let assert = freekee()
        .arg("rotate")
        .arg("entry")
        .arg(&dest)
        .arg("github")
        .arg("--length")
        .arg("18")
        .arg("--print-generated")
        .arg("--pass-stdin")
        .write_stdin("rot-print-pw\n")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();

    let db = kdbx::Database::open(&dest, "rot-print-pw", None).unwrap();
    let new_pw = db
        .entry_by_path(EntryPath {
            groups: &[],
            title: "github",
        })
        .unwrap()
        .password()
        .unwrap()
        .to_owned();
    assert!(
        stdout.contains(&new_pw),
        "--print-generated must echo the new password to stdout"
    );
}

// ---------------------------------------------------------------------------
// `set field=-` stdin sentinel.
//
// The sentinel reads the value from stdin instead of the command line,
// so secrets don't leak into shell history or `ps` output.
// Stdin order: passphrase first (existing `--pass-stdin`), then one
// line per `field=-` assignment in command-line order.
// ---------------------------------------------------------------------------

#[test]
fn set_field_sentinel_reads_password_from_stdin() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "sent-pw");

    let secret = "stdin-only-secret-7c3";
    freekee()
        .arg("set")
        .arg(&dest)
        .arg("github")
        .arg("password=-")
        .arg("--pass-stdin")
        .write_stdin(format!("sent-pw\n{secret}\n"))
        .assert()
        .success();

    let db = kdbx::Database::open(&dest, "sent-pw", None).unwrap();
    let entry = db
        .entry_by_path(EntryPath {
            groups: &[],
            title: "github",
        })
        .unwrap();
    assert_eq!(entry.password(), Some(secret));
}

#[test]
fn set_field_sentinel_supports_multiple_fields_in_order() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "multi-pw");

    freekee()
        .arg("set")
        .arg(&dest)
        .arg("github")
        .arg("username=-")
        .arg("password=-")
        .arg("--pass-stdin")
        .write_stdin("multi-pw\nstdin-user\nstdin-pass\n")
        .assert()
        .success();

    let db = kdbx::Database::open(&dest, "multi-pw", None).unwrap();
    let entry = db
        .entry_by_path(EntryPath {
            groups: &[],
            title: "github",
        })
        .unwrap();
    assert_eq!(entry.username(), Some("stdin-user"));
    assert_eq!(entry.password(), Some("stdin-pass"));
}

#[test]
fn set_field_sentinel_does_not_consume_extra_lines() {
    // Single sentinel reads exactly one line. Any extra lines on
    // stdin must be ignored (not silently consumed and stored). We
    // verify by piping passphrase + value + a line that would cause
    // a wrong-credentials error if it were treated as the value.
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    seed_vault(&dest, "extra-pw");

    let intended = "the-real-value";
    freekee()
        .arg("set")
        .arg(&dest)
        .arg("github")
        .arg("password=-")
        .arg("--pass-stdin")
        .write_stdin(format!(
            "extra-pw\n{intended}\nthis-extra-line-must-be-ignored\n"
        ))
        .assert()
        .success();

    let db = kdbx::Database::open(&dest, "extra-pw", None).unwrap();
    let entry = db
        .entry_by_path(EntryPath {
            groups: &[],
            title: "github",
        })
        .unwrap();
    assert_eq!(entry.password(), Some(intended));
}

// ---------------------------------------------------------------------------
// init --keyfile + rotate keyfile.
//
// Each test writes a fresh random keyfile to the tempdir and shells out to
// the binary, then asserts the resulting file requires the expected
// composite to reopen.
// ---------------------------------------------------------------------------

fn write_random_keyfile(path: &Path) {
    use std::io::Write;
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
fn init_with_keyfile_creates_a_kdbx_that_requires_keyfile() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("kf.kdbx");
    let kf = tmp.path().join("init.key");
    write_random_keyfile(&kf);

    freekee()
        .arg("init")
        .arg(&dest)
        .arg("--keyfile")
        .arg(&kf)
        .arg("--memory")
        .arg("8")
        .arg("--iterations")
        .arg("1")
        .arg("--parallelism")
        .arg("1")
        .arg("--pass-stdin")
        .write_stdin("init-kf-pw\n")
        .assert()
        .success();

    // Reopen with the full composite: works.
    kdbx::Database::open(&dest, "init-kf-pw", Some(&kf))
        .expect("init --keyfile must produce a file that reopens with the same composite");
    // Reopen without the keyfile: must fail.
    assert!(
        kdbx::Database::open(&dest, "init-kf-pw", None).is_err(),
        "init --keyfile must NOT write a passphrase-only file"
    );
}

#[test]
fn rotate_keyfile_add_via_cli_makes_keyfile_required() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let new_kf = tmp.path().join("new.key");
    write_random_keyfile(&new_kf);
    seed_vault(&dest, "rotkf-pw");

    freekee()
        .arg("rotate")
        .arg("keyfile")
        .arg(&dest)
        .arg("--new-keyfile")
        .arg(&new_kf)
        .arg("--pass-stdin")
        .write_stdin("rotkf-pw\n")
        .assert()
        .success();

    kdbx::Database::open(&dest, "rotkf-pw", Some(&new_kf))
        .expect("rotated file must require the new keyfile composite");
    assert!(
        kdbx::Database::open(&dest, "rotkf-pw", None).is_err(),
        "passphrase-only must be rejected after rotate keyfile add"
    );
}

#[test]
fn rotate_keyfile_remove_via_cli_makes_keyfile_optional() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let kf = tmp.path().join("k.key");
    write_random_keyfile(&kf);

    // Seed: passphrase-only vault, then add keyfile via CLI.
    seed_vault(&dest, "rm-pw");
    freekee()
        .arg("rotate")
        .arg("keyfile")
        .arg(&dest)
        .arg("--new-keyfile")
        .arg(&kf)
        .arg("--pass-stdin")
        .write_stdin("rm-pw\n")
        .assert()
        .success();

    // Remove the keyfile.
    freekee()
        .arg("rotate")
        .arg("keyfile")
        .arg(&dest)
        .arg("--keyfile")
        .arg(&kf)
        .arg("--remove")
        .arg("--pass-stdin")
        .write_stdin("rm-pw\n")
        .assert()
        .success();

    kdbx::Database::open(&dest, "rm-pw", None)
        .expect("file must reopen passphrase-only after --remove");
}

#[test]
fn rotate_keyfile_with_wrong_current_keyfile_errors_out() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("v.kdbx");
    let real_kf = tmp.path().join("real.key");
    let wrong_kf = tmp.path().join("wrong.key");
    let new_kf = tmp.path().join("new.key");
    write_random_keyfile(&real_kf);
    write_random_keyfile(&wrong_kf);
    write_random_keyfile(&new_kf);

    // Set up a vault that requires `real_kf`.
    seed_vault(&dest, "wrong-pw");
    freekee()
        .arg("rotate")
        .arg("keyfile")
        .arg(&dest)
        .arg("--new-keyfile")
        .arg(&real_kf)
        .arg("--pass-stdin")
        .write_stdin("wrong-pw\n")
        .assert()
        .success();

    // Attempt to rotate using the wrong current keyfile.
    freekee()
        .arg("rotate")
        .arg("keyfile")
        .arg(&dest)
        .arg("--keyfile")
        .arg(&wrong_kf)
        .arg("--new-keyfile")
        .arg(&new_kf)
        .arg("--pass-stdin")
        .write_stdin("wrong-pw\n")
        .assert()
        .failure();

    // Real composite still works.
    kdbx::Database::open(&dest, "wrong-pw", Some(&real_kf))
        .expect("file must remain openable with the real composite");
}

#[test]
fn init_chacha20_cipher_flag_is_respected() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("cc20.kdbx");

    freekee()
        .arg("init")
        .arg(&dest)
        .arg("--cipher")
        .arg("chacha20")
        .arg("--memory")
        .arg("8")
        .arg("--iterations")
        .arg("1")
        .arg("--parallelism")
        .arg("1")
        .arg("--pass-stdin")
        .write_stdin("cc20-pw\n")
        .assert()
        .success();

    let db = kdbx::Database::open(&dest, "cc20-pw", None).unwrap();
    assert!(matches!(db.outer_cipher(), kdbx::OuterCipher::ChaCha20));
}
