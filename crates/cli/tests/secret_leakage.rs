//! Secret-leakage meta-test. Per `AGENTS.md` and milestone-0 plan section 8.
//!
//! Builds a canary KDBX with two known sentinel strings (the master
//! passphrase and one entry's password). Runs every read-only CLI
//! command against it (correct + wrong passphrase) and asserts that
//! neither sentinel substring appears in any captured stdout or
//! stderr - including error output from the wrong-password paths.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use assert_cmd::Command;
use std::fs::File;

const CANARY_PASSPHRASE: &str = "CANARY_PASSPHRASE_d3f1a8e7_DO_NOT_LEAK";
const CANARY_ENTRY_PASSWORD: &str = "SENTINEL_LEAK_CANARY_8e3b1f4d";
const WRONG_PASSPHRASE: &str = "ATTEMPTED_WRONG_PASSPHRASE_4c9b2a05";

fn freekee() -> Command {
    Command::cargo_bin("freekee").expect("cargo bin freekee")
}

fn build_canary(path: &std::path::Path) {
    let mut inner = keepass::Database::new();
    {
        let mut root = inner.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, "canary");
        entry.set_protected(keepass::db::fields::PASSWORD, CANARY_ENTRY_PASSWORD);
    }
    let mut file = File::create(path).expect("create canary file");
    let key = keepass::DatabaseKey::new().with_password(CANARY_PASSPHRASE);
    inner.save(&mut file, key).expect("save canary");
}

fn assert_no_canary_in(label: &str, stdout: &[u8], stderr: &[u8]) {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    for (canary, kind) in [
        (CANARY_PASSPHRASE, "passphrase"),
        (CANARY_ENTRY_PASSWORD, "entry-password"),
        (WRONG_PASSPHRASE, "wrong-passphrase-attempt"),
    ] {
        assert!(
            !stdout.contains(canary),
            "{label}: {kind} canary leaked into stdout: {stdout}",
        );
        assert!(
            !stderr.contains(canary),
            "{label}: {kind} canary leaked into stderr: {stderr}",
        );
    }
}

#[test]
fn no_canary_substrings_in_any_command_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let canary = dir.path().join("canary.kdbx");
    build_canary(&canary);

    // Every read-only invocation, with the correct passphrase.
    for argv in [
        vec!["info"],
        vec!["verify"],
        vec!["audit"],
        vec!["audit", "--json"],
        vec!["audit", "--strict"],
    ] {
        let mut cmd = freekee();
        cmd.args(&argv).arg("--db").arg(&canary).arg("--pass-stdin");
        let out = cmd
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("run freekee");
        assert_no_canary_in(&format!("{argv:?} (correct pw)"), &out.stdout, &out.stderr);
    }

    // Wrong-passphrase paths. These should fail; assert no canary leaks
    // in the error output AND that the attempted wrong passphrase is
    // also not echoed (it should never be reflected to the user).
    for sub in ["info", "verify", "audit"] {
        let mut cmd = freekee();
        cmd.arg(sub).arg("--db").arg(&canary).arg("--pass-stdin");
        let out = cmd
            .write_stdin(format!("{WRONG_PASSPHRASE}\n"))
            .output()
            .expect("run freekee with wrong pw");
        assert!(
            !out.status.success(),
            "{sub} with wrong passphrase must fail, got {:?}",
            out.status,
        );
        assert_no_canary_in(&format!("{sub} (wrong pw)"), &out.stdout, &out.stderr);
    }

    // No-passphrase paths. These cannot leak anything; sanity check.
    for argv in [vec!["--help"], vec!["--version"]] {
        let out = freekee().args(&argv).output().expect("run");
        assert_no_canary_in(&format!("{argv:?}"), &out.stdout, &out.stderr);
    }

    // Mutating + read-extra commands. Each runs against a *fresh* canary so
    // a leak in one command can't contaminate the next test's assertion.
    for argv in [
        vec!["ls"],
        vec!["history", "canary"],
        vec!["get", "canary"], // no --show: must still hide the password
        vec!["get", "--clip", "canary"], // --clip: no stdout print; clipboard may fail on CI
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let canary = dir.path().join("canary.kdbx");
        build_canary(&canary);
        let mut cmd = freekee();
        cmd.args(&argv).arg("--db").arg(&canary).arg("--pass-stdin");
        let out = cmd
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("run freekee");
        assert_no_canary_in(&format!("{argv:?} (correct pw)"), &out.stdout, &out.stderr);
    }

    // `get --show` carve-out: it IS allowed to surface the entry
    // password in stdout (sanity-check it actually does), but the
    // master passphrase, the wrong-passphrase canary, and stderr must
    // still be canary-free.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let canary = dir.path().join("canary.kdbx");
        build_canary(&canary);
        let out = freekee()
            .arg("get")
            .arg("--db")
            .arg(&canary)
            .arg("canary")
            .arg("--show")
            .arg("--pass-stdin")
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("run get --show");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stdout.contains(CANARY_ENTRY_PASSWORD),
            "get --show must surface the entry password in stdout (carve-out check); \
             stdout was: {stdout}"
        );
        assert!(
            !stdout.contains(CANARY_PASSPHRASE),
            "get --show must not surface the master passphrase: stdout was: {stdout}"
        );
        assert!(
            !stderr.contains(CANARY_ENTRY_PASSWORD),
            "get --show must not echo the entry password into stderr: stderr was: {stderr}"
        );
        assert!(
            !stderr.contains(CANARY_PASSPHRASE),
            "get --show must not echo the master passphrase into stderr: stderr was: {stderr}"
        );
    }

    // Mutating commands. Each runs on its own canary, then the canary
    // strings (master passphrase, prior entry password) must not
    // appear anywhere in captured output. The new entry password, set
    // here as a third sentinel, must also be invisible unless the
    // command explicitly opted in via --print-generated.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let canary = dir.path().join("canary.kdbx");
        build_canary(&canary);
        let new_canary = "NEWLY_SET_CANARY_VALUE_27a9f1c4";
        let out = freekee()
            .arg("set")
            .arg("--db")
            .arg(&canary)
            .arg("canary")
            .arg(format!("password={new_canary}"))
            .arg("--pass-stdin")
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("run set");
        assert_no_canary_in("set", &out.stdout, &out.stderr);
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains(new_canary),
            "set must not echo the assigned password value"
        );
        assert!(
            !String::from_utf8_lossy(&out.stderr).contains(new_canary),
            "set must not echo the assigned password value to stderr"
        );
    }

    // `set --gen-password` (no --print-generated): the generated
    // password must not appear in any stream. We can't predict the
    // generated value, so the assertion has to be the standard
    // canary check plus a tighter "the entry's actual password isn't
    // in stdout" check after reading it back.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let canary = dir.path().join("canary.kdbx");
        build_canary(&canary);
        let out = freekee()
            .arg("set")
            .arg("--db")
            .arg(&canary)
            .arg("canary")
            .arg("--gen-password")
            .arg("--length")
            .arg("16")
            .arg("--pass-stdin")
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("run set --gen-password");
        assert_no_canary_in("set --gen-password", &out.stdout, &out.stderr);
        let actual_pw = kdbx::Database::open(&canary, CANARY_PASSPHRASE, None)
            .expect("reopen canary")
            .entry_by_path(kdbx::EntryPath {
                groups: &[],
                title: "canary",
            })
            .expect("entry present")
            .password()
            .expect("password set")
            .to_owned();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stdout.contains(&actual_pw),
            "generated password must not be echoed without --print-generated: stdout was: {stdout}"
        );
        assert!(
            !stderr.contains(&actual_pw),
            "generated password must not be echoed to stderr: stderr was: {stderr}"
        );
    }

    // `rm` and `mv`: standard canary-free assertion.
    for argv in [vec!["rm", "canary"], vec!["mv", "canary", "canary-renamed"]] {
        let dir = tempfile::tempdir().expect("tempdir");
        let canary = dir.path().join("canary.kdbx");
        build_canary(&canary);
        let mut cmd = freekee();
        cmd.args(&argv[..1])
            .arg("--db")
            .arg(&canary)
            .args(&argv[1..])
            .arg("--pass-stdin");
        let out = cmd
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("run freekee");
        assert_no_canary_in(&format!("{argv:?}"), &out.stdout, &out.stderr);
    }

    // `rotate passphrase`: BOTH the old master canary and the new
    // canary value must stay out of every captured stream. Old and
    // new are distinct sentinels so a leak in either direction is
    // unambiguous.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let canary = dir.path().join("canary.kdbx");
        build_canary(&canary);
        let new_master = "ROTATED_NEW_MASTER_CANARY_a4b7e2c1";
        let out = freekee()
            .arg("rotate")
            .arg("passphrase")
            .arg("--db")
            .arg(&canary)
            .arg("--pass-stdin")
            .arg("--new-pass-stdin")
            .write_stdin(format!("{CANARY_PASSPHRASE}\n{new_master}\n"))
            .output()
            .expect("run rotate passphrase");
        assert!(
            out.status.success(),
            "rotate passphrase must succeed; status: {:?}, stderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        );
        assert_no_canary_in("rotate passphrase", &out.stdout, &out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stdout.contains(new_master),
            "rotate passphrase must not echo the new master passphrase: stdout was: {stdout}"
        );
        assert!(
            !stderr.contains(new_master),
            "rotate passphrase must not echo the new master passphrase to stderr: stderr was: {stderr}"
        );
    }

    // `rotate entry` without `--print-generated`: generated password
    // must not leak. The actual generated value is unknown, so we
    // read it back after rotation and assert it's absent from every
    // captured stream.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let canary = dir.path().join("canary.kdbx");
        build_canary(&canary);
        let out = freekee()
            .arg("rotate")
            .arg("entry")
            .arg("--db")
            .arg(&canary)
            .arg("canary")
            .arg("--length")
            .arg("16")
            .arg("--pass-stdin")
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("run rotate entry");
        assert!(out.status.success(), "rotate entry must succeed");
        assert_no_canary_in("rotate entry", &out.stdout, &out.stderr);
        let new_pw = kdbx::Database::open(&canary, CANARY_PASSPHRASE, None)
            .unwrap()
            .entry_by_path(kdbx::EntryPath {
                groups: &[],
                title: "canary",
            })
            .unwrap()
            .password()
            .unwrap()
            .to_owned();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stdout.contains(&new_pw),
            "rotate entry must not echo the new password without --print-generated: \
             stdout was: {stdout}"
        );
        assert!(
            !stderr.contains(&new_pw),
            "rotate entry must not echo the new password to stderr: stderr was: {stderr}"
        );
    }

    // `rotate entry --print-generated`: the new password IS allowed
    // in stdout (carve-out parallel to `get --show`), but never in
    // stderr, and the master/wrong-pass canaries still must not leak.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let canary = dir.path().join("canary.kdbx");
        build_canary(&canary);
        let out = freekee()
            .arg("rotate")
            .arg("entry")
            .arg("--db")
            .arg(&canary)
            .arg("canary")
            .arg("--length")
            .arg("16")
            .arg("--print-generated")
            .arg("--pass-stdin")
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("run rotate entry --print-generated");
        assert!(out.status.success(), "rotate entry must succeed");
        let new_pw = kdbx::Database::open(&canary, CANARY_PASSPHRASE, None)
            .unwrap()
            .entry_by_path(kdbx::EntryPath {
                groups: &[],
                title: "canary",
            })
            .unwrap()
            .password()
            .unwrap()
            .to_owned();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stdout.contains(&new_pw),
            "rotate entry --print-generated must echo the new password to stdout"
        );
        assert!(
            !stderr.contains(&new_pw),
            "rotate entry --print-generated must keep stderr canary-free"
        );
        assert!(
            !stdout.contains(CANARY_PASSPHRASE) && !stderr.contains(CANARY_PASSPHRASE),
            "master passphrase must not leak even with --print-generated"
        );
    }

    // `set field=-` stdin sentinel: the assigned value is read from
    // stdin instead of argv, but the same no-leak rule applies. Both
    // the master passphrase canary and the new value canary must be
    // absent from stdout/stderr.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let canary = dir.path().join("canary.kdbx");
        build_canary(&canary);
        let stdin_canary = "STDIN_SENTINEL_CANARY_4f8e3b21";
        let out = freekee()
            .arg("set")
            .arg("--db")
            .arg(&canary)
            .arg("canary")
            .arg("password=-")
            .arg("--pass-stdin")
            .write_stdin(format!("{CANARY_PASSPHRASE}\n{stdin_canary}\n"))
            .output()
            .expect("run set password=-");
        assert!(
            out.status.success(),
            "set password=- must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_no_canary_in("set password=- (stdin)", &out.stdout, &out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stdout.contains(stdin_canary),
            "set password=- must not echo the stdin-supplied value: stdout was: {stdout}"
        );
        assert!(
            !stderr.contains(stdin_canary),
            "set password=- must not echo the stdin-supplied value to stderr: stderr was: {stderr}"
        );
    }

    // `init --keyfile`: the master passphrase must not appear anywhere
    // in stdout/stderr, and the keyfile path itself is fine to surface
    // (it's a filesystem path, not a secret). Init writes a brand-new
    // file, so we use the standard CANARY_PASSPHRASE as the new
    // master.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("init-kf.kdbx");
        let kf = dir.path().join("init.key");
        write_random_canary_keyfile(&kf);
        let out = freekee()
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
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("run init --keyfile");
        assert!(
            out.status.success(),
            "init --keyfile must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_no_canary_in("init --keyfile", &out.stdout, &out.stderr);
    }

    // `rotate keyfile --new-keyfile`: master passphrase canary must
    // stay out of all output.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let canary = dir.path().join("canary.kdbx");
        build_canary(&canary);
        let kf = dir.path().join("k.key");
        write_random_canary_keyfile(&kf);
        let out = freekee()
            .arg("rotate")
            .arg("keyfile")
            .arg("--db")
            .arg(&canary)
            .arg("--new-keyfile")
            .arg(&kf)
            .arg("--pass-stdin")
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("run rotate keyfile --new-keyfile");
        assert!(
            out.status.success(),
            "rotate keyfile add must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_no_canary_in("rotate keyfile add", &out.stdout, &out.stderr);
    }

    // `rotate keyfile --remove`: master passphrase canary must stay
    // out of all output. Setup adds a keyfile first via the same
    // command, then removes it.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let canary = dir.path().join("canary.kdbx");
        build_canary(&canary);
        let kf = dir.path().join("k.key");
        write_random_canary_keyfile(&kf);
        // Setup: bind a keyfile.
        freekee()
            .arg("rotate")
            .arg("keyfile")
            .arg("--db")
            .arg(&canary)
            .arg("--new-keyfile")
            .arg(&kf)
            .arg("--pass-stdin")
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("setup add");
        // Now remove it.
        let out = freekee()
            .arg("rotate")
            .arg("keyfile")
            .arg("--db")
            .arg(&canary)
            .arg("--keyfile")
            .arg(&kf)
            .arg("--remove")
            .arg("--pass-stdin")
            .write_stdin(format!("{CANARY_PASSPHRASE}\n"))
            .output()
            .expect("run rotate keyfile --remove");
        assert!(
            out.status.success(),
            "rotate keyfile remove must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_no_canary_in("rotate keyfile remove", &out.stdout, &out.stderr);
    }
}

/// Write 64 deterministic-pseudo-random bytes to act as a keyfile in
/// secret-leakage tests. Path-derived seed so different tempdirs get
/// distinct content. (Keyfile bytes themselves aren't a meta-test
/// canary: the master passphrase canary is what these tests guard.)
fn write_random_canary_keyfile(path: &std::path::Path) {
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
