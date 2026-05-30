//! `freekee audit --hibp` (A12 breached-password). The HIBP range API is
//! stubbed by a localhost TCP server pointed at via `FREEKEE_HIBP_BASE_URL`,
//! so these tests are fully offline and deterministic.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread;

use assert_cmd::Command;
use freekee_core::Vault;
use kdbx::{Argon2idParams, EntryDraft, EntryPath, InnerCipher, NewDatabaseTemplate, OuterCipher};
use predicates::prelude::*;
use predicates::str::contains;
use zeroize::Zeroizing;

const PASSPHRASE: &str = "correct horse battery staple unique vault";
// SHA1("password") suffix; the canned range body marks it breached.
const BREACHED_RANGE_BODY: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n";

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

fn seed_vault(path: &Path) {
    let mut vault = Vault::create(
        path,
        Zeroizing::new(PASSPHRASE.to_owned()),
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
                password: Some("password"),
                ..EntryDraft::default()
            },
        )
        .unwrap();
    vault.save().unwrap();
}

/// Spawn a localhost stub that answers every request with the same canned
/// range body. Returns the `http://127.0.0.1:PORT` base URL.
fn spawn_stub() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                BREACHED_RANGE_BODY.len(),
                BREACHED_RANGE_BODY,
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    base
}

#[test]
fn hibp_flag_reports_breached_entry() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("v.kdbx");
    seed_vault(&db);
    let base = spawn_stub();

    freekee()
        .args(["audit", "--db"])
        .arg(&db)
        .args(["--hibp", "--pass-stdin"])
        .env("FREEKEE_HIBP_BASE_URL", &base)
        .write_stdin(format!("{PASSPHRASE}\n"))
        .assert()
        .success()
        .stdout(contains("breached-password"));
}

#[test]
fn hibp_flag_json_includes_rule() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("v.kdbx");
    seed_vault(&db);
    let base = spawn_stub();

    freekee()
        .args(["audit", "--db"])
        .arg(&db)
        .args(["--hibp", "--json", "--pass-stdin"])
        .env("FREEKEE_HIBP_BASE_URL", &base)
        .write_stdin(format!("{PASSPHRASE}\n"))
        .assert()
        .success()
        .stdout(contains("\"breached-password\""));
}

#[test]
fn without_hibp_flag_no_breached_finding() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("v.kdbx");
    seed_vault(&db);
    // No stub, no env override: a network attempt would error, proving
    // the default path makes no request.
    freekee()
        .args(["audit", "--db"])
        .arg(&db)
        .arg("--pass-stdin")
        .write_stdin(format!("{PASSPHRASE}\n"))
        .assert()
        .success()
        .stdout(contains("breached-password").not());
}
