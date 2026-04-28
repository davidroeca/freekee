//! Smoke tests for the read-only CLI surface. Per milestone-0 plan §7.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use std::path::PathBuf;

const FIXTURE_PASSWORD: &str = "correct horse battery staple";

fn fixtures(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/roundtrip/fixtures")
        .join(name)
}

fn freekee() -> Command {
    Command::cargo_bin("freekee").expect("cargo bin freekee")
}

#[test]
fn version_flag_prints_workspace_version() {
    freekee()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_lists_all_three_subcommands() {
    freekee()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("info"))
        .stdout(contains("verify"))
        .stdout(contains("audit"));
}

#[test]
fn info_on_empty_fixture_prints_metadata_no_secrets() {
    let path = fixtures("empty").join("db.kdbx");
    freekee()
        .arg("info")
        .arg(&path)
        .arg("--pass-stdin")
        .write_stdin(format!("{FIXTURE_PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("KDBX 4"))
        .stdout(contains("AES-256").or(contains("ChaCha20")))
        .stdout(predicates::str::contains(FIXTURE_PASSWORD).not());
}

#[test]
fn verify_on_clean_fixture_exits_zero() {
    let path = fixtures("empty").join("db.kdbx");
    freekee()
        .arg("verify")
        .arg(&path)
        .arg("--pass-stdin")
        .write_stdin(format!("{FIXTURE_PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("OK"));
}

#[test]
fn audit_on_empty_fixture_surfaces_only_passphrase_only_info() {
    // The CLI opens databases with a passphrase only today, so A7
    // (passphrase-only) always fires INFO. A clean fixture must not
    // surface anything else.
    let path = fixtures("empty").join("db.kdbx");
    freekee()
        .arg("audit")
        .arg(&path)
        .arg("--pass-stdin")
        .write_stdin(format!("{FIXTURE_PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("passphrase-only"))
        .stdout(contains("1 finding"));
}

#[test]
fn audit_on_kdbx3_legacy_succeeds_without_strict() {
    let path = fixtures("kdbx3-legacy").join("db.kdbx");
    freekee()
        .arg("audit")
        .arg(&path)
        .arg("--pass-stdin")
        .write_stdin(format!("{FIXTURE_PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("legacy-kdf").or(contains("legacy-kdbx-version")));
}

#[test]
fn audit_on_kdbx3_legacy_with_strict_exits_nonzero() {
    let path = fixtures("kdbx3-legacy").join("db.kdbx");
    freekee()
        .arg("audit")
        .arg(&path)
        .arg("--strict")
        .arg("--pass-stdin")
        .write_stdin(format!("{FIXTURE_PASSWORD}\n"))
        .assert()
        .failure()
        .stdout(contains("legacy-kdf").or(contains("legacy-kdbx-version")));
}

#[test]
fn audit_with_json_outputs_machine_readable() {
    let path = fixtures("empty").join("db.kdbx");
    freekee()
        .arg("audit")
        .arg(&path)
        .arg("--json")
        .arg("--pass-stdin")
        .write_stdin(format!("{FIXTURE_PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("[").and(contains("]")));
}
