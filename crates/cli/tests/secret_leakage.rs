//! Secret-leakage meta-test. Per `AGENTS.md` and milestone-0 plan §8.
//!
//! Builds a canary KDBX with two known sentinel strings (the master
//! passphrase and one entry's password). Runs every read-only CLI
//! command against it (correct + wrong passphrase) and asserts that
//! neither sentinel substring appears in any captured stdout or
//! stderr — including error output from the wrong-password paths.

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
        cmd.args(&argv).arg(&canary).arg("--pass-stdin");
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
        cmd.arg(sub).arg(&canary).arg("--pass-stdin");
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
}
