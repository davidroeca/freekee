//! End-to-end operator smoke chain.
//!
//! Drives every mutating subcommand against a single freshly-`init`-ed
//! vault, in the order an operator would use them, plus a sibling
//! `init --keyfile` vault to cover that init path. Asserts the file
//! still reopens cleanly between rotations. The final
//! `keepassxc-cli db-info` step (under the `keepassxc-verify` feature)
//! confirms a file produced by the full chain is still accepted by
//! KeePassXC.
//!
//! Granular per-command behaviours are covered by `cli_mutate.rs`;
//! this file is the regression guard for the chain as a whole. Run
//! cost is dominated by the rotations (each does an Argon2id pass);
//! keeping it to a single chain (rather than one per command) keeps
//! that cost paid once.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use assert_cmd::Command;
use kdbx::EntryPath;
use predicates::prelude::*;
use predicates::str::contains;
use std::path::Path;

fn freekee() -> Command {
    Command::cargo_bin("freekee").expect("cargo bin freekee")
}

/// Deterministic 64-byte keyfile. Same construction as
/// `cli_mutate.rs::write_random_keyfile`.
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

#[cfg(feature = "keepassxc-verify")]
fn assert_keepassxc_db_info_accepts(path: &Path, password: &str, keyfile: Option<&Path>) {
    use std::io::Write;
    let mut cmd = std::process::Command::new("keepassxc-cli");
    cmd.arg("db-info").arg(path);
    if let Some(kf) = keyfile {
        cmd.arg("--key-file").arg(kf);
    }
    let mut child = cmd
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

#[test]
fn full_operator_smoke_chain() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("m2.kdbx");
    let init_kf_db = tmp.path().join("init-kf.kdbx");
    let init_kf = tmp.path().join("init.key");
    let later_kf = tmp.path().join("later.key");
    write_random_keyfile(&init_kf);
    write_random_keyfile(&later_kf);

    // 1. init (passphrase-only). Tiny Argon2 params so the test runs
    //    in well under a second.
    freekee()
        .arg("init")
        .arg(&db)
        .args(["--memory", "8", "--iterations", "1", "--parallelism", "1"])
        .arg("--pass-stdin")
        .write_stdin("pw0\n")
        .assert()
        .success();
    assert!(db.exists(), "init must produce the file");

    // 2. init --keyfile on a sibling path. The chain proper continues
    //    against `db`; this just covers the init-with-keyfile entry
    //    point so it can't regress silently.
    freekee()
        .arg("init")
        .arg(&init_kf_db)
        .arg("--keyfile")
        .arg(&init_kf)
        .args(["--memory", "8", "--iterations", "1", "--parallelism", "1"])
        .arg("--pass-stdin")
        .write_stdin("kf-pw\n")
        .assert()
        .success();
    kdbx::Database::open(&init_kf_db, "kf-pw", Some(&init_kf))
        .expect("init --keyfile output must reopen with the same composite");
    assert!(
        kdbx::Database::open(&init_kf_db, "kf-pw", None).is_err(),
        "init --keyfile must NOT write a passphrase-only file"
    );

    // 3. set "email" with plaintext fields on the command line.
    freekee()
        .arg("set")
        .arg("--db")
        .arg(&db)
        .arg("email")
        .arg("username=alice@example.com")
        .arg("url=https://mail.example.com")
        .arg("password=plain-pw")
        .arg("--pass-stdin")
        .write_stdin("pw0\n")
        .assert()
        .success();

    // 4. set "github" so we have a second entry to rotate / move.
    freekee()
        .arg("set")
        .arg("--db")
        .arg(&db)
        .arg("github")
        .arg("username=alice")
        .arg("url=https://github.com")
        .arg("password=initial-gh-pw")
        .arg("--pass-stdin")
        .write_stdin("pw0\n")
        .assert()
        .success();

    // 5. set field=- reads the github password from stdin.
    let stdin_secret = "stdin-only-pw";
    freekee()
        .arg("set")
        .arg("--db")
        .arg(&db)
        .arg("github")
        .arg("password=-")
        .arg("--pass-stdin")
        .write_stdin(format!("pw0\n{stdin_secret}\n"))
        .assert()
        .success();

    // 6. ls lists both entries.
    freekee()
        .arg("ls")
        .arg("--db")
        .arg(&db)
        .arg("--pass-stdin")
        .write_stdin("pw0\n")
        .assert()
        .success()
        .stdout(contains("email"))
        .stdout(contains("github"));

    // 7. get hides the password by default and reveals neither plain
    //    nor stdin-sourced passwords in stdout.
    freekee()
        .arg("get")
        .arg("--db")
        .arg(&db)
        .arg("email")
        .arg("--pass-stdin")
        .write_stdin("pw0\n")
        .assert()
        .success()
        .stdout(contains("<hidden"))
        .stdout(predicates::str::contains("plain-pw").not());

    // 8. get --show is the lone carve-out that prints the password.
    freekee()
        .arg("get")
        .arg("--db")
        .arg(&db)
        .arg("email")
        .arg("--show")
        .arg("--pass-stdin")
        .write_stdin("pw0\n")
        .assert()
        .success()
        .stdout(contains("plain-pw"));

    // 9. history reports the snapshot taken by `set field=-` above.
    freekee()
        .arg("history")
        .arg("--db")
        .arg(&db)
        .arg("github")
        .arg("--pass-stdin")
        .write_stdin("pw0\n")
        .assert()
        .success();
    {
        let opened = kdbx::Database::open(&db, "pw0", None).unwrap();
        let entry = opened
            .entry_by_path(EntryPath {
                groups: &[],
                title: "github",
            })
            .expect("github entry");
        assert!(
            entry.history_count() >= 1,
            "the `set field=-` step should have left at least one history snapshot, got {}",
            entry.history_count(),
        );
    }

    // 10. mv (same-group rename).
    freekee()
        .arg("mv")
        .arg("--db")
        .arg(&db)
        .arg("github")
        .arg("gh-renamed")
        .arg("--pass-stdin")
        .write_stdin("pw0\n")
        .assert()
        .success();

    // 11. rm "email".
    freekee()
        .arg("rm")
        .arg("--db")
        .arg(&db)
        .arg("email")
        .arg("--pass-stdin")
        .write_stdin("pw0\n")
        .assert()
        .success();
    {
        let opened = kdbx::Database::open(&db, "pw0", None).unwrap();
        assert!(
            opened
                .entry_by_path(EntryPath {
                    groups: &[],
                    title: "email",
                })
                .is_none(),
            "email entry should be deleted",
        );
        assert!(
            opened
                .entry_by_path(EntryPath {
                    groups: &[],
                    title: "gh-renamed",
                })
                .is_some(),
            "gh-renamed entry should exist",
        );
        // Deletion lands in `deleted_objects` so KeePassXC sync respects it.
        assert!(
            opened.deleted_object_count() >= 1,
            "rm should populate deleted_objects"
        );
    }

    // 12. rotate passphrase pw0 -> pw1.
    freekee()
        .arg("rotate")
        .arg("passphrase")
        .arg("--db")
        .arg(&db)
        .arg("--pass-stdin")
        .arg("--new-pass-stdin")
        .write_stdin("pw0\npw1\n")
        .assert()
        .success();
    assert!(
        kdbx::Database::open(&db, "pw0", None).is_err(),
        "old passphrase must be rejected after rotate passphrase",
    );
    kdbx::Database::open(&db, "pw1", None).expect("new passphrase must work");

    // 13. rotate kdf-params (bump Argon2 above tiny defaults).
    freekee()
        .arg("rotate")
        .arg("kdf-params")
        .arg("--db")
        .arg(&db)
        .args(["--memory", "16", "--iterations", "2", "--parallelism", "2"])
        .arg("--pass-stdin")
        .write_stdin("pw1\n")
        .assert()
        .success();
    {
        let opened = kdbx::Database::open(&db, "pw1", None).unwrap();
        match opened.kdf() {
            kdbx::Kdf::Argon2id {
                iterations,
                memory,
                parallelism,
            } => {
                assert_eq!(iterations, 2);
                assert_eq!(memory, 16 * 1024 * 1024);
                assert_eq!(parallelism, 2);
            }
            other => panic!("expected Argon2id after rotate kdf-params, got {other:?}"),
        }
    }

    // 14. rotate entry regenerates the password on gh-renamed. The new
    //     password is silent by default; we just confirm a value still
    //     exists and is different from `stdin_secret`.
    freekee()
        .arg("rotate")
        .arg("entry")
        .arg("--db")
        .arg(&db)
        .arg("gh-renamed")
        .arg("--length")
        .arg("20")
        .arg("--pass-stdin")
        .write_stdin("pw1\n")
        .assert()
        .success();
    {
        let opened = kdbx::Database::open(&db, "pw1", None).unwrap();
        let pw = opened
            .entry_by_path(EntryPath {
                groups: &[],
                title: "gh-renamed",
            })
            .expect("gh-renamed entry")
            .password()
            .expect("password should be set")
            .to_owned();
        assert_ne!(
            pw, stdin_secret,
            "rotate entry must replace the prior password"
        );
        assert_eq!(pw.len(), 20, "--length 20 should produce 20 chars");
    }

    // 15. rotate keyfile --new-keyfile adds a keyfile composite.
    freekee()
        .arg("rotate")
        .arg("keyfile")
        .arg("--db")
        .arg(&db)
        .arg("--new-keyfile")
        .arg(&later_kf)
        .arg("--pass-stdin")
        .write_stdin("pw1\n")
        .assert()
        .success();
    kdbx::Database::open(&db, "pw1", Some(&later_kf))
        .expect("must reopen with the new keyfile composite");
    assert!(
        kdbx::Database::open(&db, "pw1", None).is_err(),
        "passphrase-only must be rejected after rotate keyfile add",
    );

    // 16. rotate keyfile --remove returns to passphrase-only.
    freekee()
        .arg("rotate")
        .arg("keyfile")
        .arg("--db")
        .arg(&db)
        .arg("--keyfile")
        .arg(&later_kf)
        .arg("--remove")
        .arg("--pass-stdin")
        .write_stdin("pw1\n")
        .assert()
        .success();
    kdbx::Database::open(&db, "pw1", None)
        .expect("must reopen passphrase-only after rotate keyfile --remove");

    // 17. KeePassXC must accept the result. Only runs under the
    //     `keepassxc-verify` feature (see Cargo.toml).
    #[cfg(feature = "keepassxc-verify")]
    {
        assert_keepassxc_db_info_accepts(&db, "pw1", None);
        assert_keepassxc_db_info_accepts(&init_kf_db, "kf-pw", Some(&init_kf));
    }
}
