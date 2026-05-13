//! End-to-end tests for `~/.config/freekee/config.toml`. Precedence
//! contract: an explicit `--db` arg wins over `$FREEKEE_DB`, which
//! wins over the config file's `default_db`.
//!
//! Each test isolates from the host user's config by overriding
//! `$XDG_CONFIG_HOME` on the spawned `freekee` subprocess.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use assert_cmd::Command;
use freekee_core::Vault;
use kdbx::{Argon2idParams, InnerCipher, NewDatabaseTemplate, OuterCipher};
use predicates::str::contains;
use std::fs;
use std::path::{Path, PathBuf};
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

/// Build an empty kdbx at `dest` so `freekee info` has something to open.
fn make_kdbx(dest: &Path, password: &str) {
    let _ = Vault::create(
        dest,
        Zeroizing::new(password.to_owned()),
        None,
        tiny_template(),
        false,
    )
    .unwrap();
}

/// Write a `config.toml` in `xdg_dir`'s freekee subdir.
fn write_config(xdg_dir: &Path, default_db: &Path) {
    let dir = xdg_dir.join("freekee");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("config.toml"),
        format!(
            "default_db = {}\n",
            // Quote with `"` and escape backslashes for cross-platform safety.
            toml_string(default_db),
        ),
    )
    .unwrap();
}

fn toml_string(p: &Path) -> String {
    let s = p
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{s}\"")
}

#[test]
fn config_default_db_is_used_when_no_arg_or_env() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg");
    let db = tmp.path().join("from-config.kdbx");
    make_kdbx(&db, "cfg-pw");
    write_config(&xdg, &db);

    // No --db, no FREEKEE_DB; config provides the path.
    freekee()
        .env("XDG_CONFIG_HOME", &xdg)
        .env_remove("FREEKEE_DB")
        .arg("info")
        .arg("--pass-stdin")
        .write_stdin("cfg-pw\n")
        .assert()
        .success()
        .stdout(contains("KDBX 4"));
}

#[test]
fn freekee_db_env_wins_over_config() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg");
    let from_cfg = tmp.path().join("from-config.kdbx");
    let from_env = tmp.path().join("from-env.kdbx");
    make_kdbx(&from_cfg, "cfg-pw");
    make_kdbx(&from_env, "env-pw");
    write_config(&xdg, &from_cfg);

    // FREEKEE_DB points to from-env.kdbx; env must win, so the
    // env-pw passphrase decrypts cleanly and the cfg-pw one wouldn't.
    freekee()
        .env("XDG_CONFIG_HOME", &xdg)
        .env("FREEKEE_DB", &from_env)
        .arg("info")
        .arg("--pass-stdin")
        .write_stdin("env-pw\n")
        .assert()
        .success();

    // Sanity-check the reverse: the from-config password must fail
    // because the file actually opened was from-env.
    freekee()
        .env("XDG_CONFIG_HOME", &xdg)
        .env("FREEKEE_DB", &from_env)
        .arg("info")
        .arg("--pass-stdin")
        .write_stdin("cfg-pw\n")
        .assert()
        .failure();
}

#[test]
fn explicit_db_arg_wins_over_env_and_config() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg");
    let from_cfg = tmp.path().join("from-config.kdbx");
    let from_env: PathBuf = tmp.path().join("from-env.kdbx");
    let from_arg = tmp.path().join("from-arg.kdbx");
    make_kdbx(&from_cfg, "cfg-pw");
    make_kdbx(&from_env, "env-pw");
    make_kdbx(&from_arg, "arg-pw");
    write_config(&xdg, &from_cfg);

    freekee()
        .env("XDG_CONFIG_HOME", &xdg)
        .env("FREEKEE_DB", &from_env)
        .arg("info")
        .arg("--db")
        .arg(&from_arg)
        .arg("--pass-stdin")
        .write_stdin("arg-pw\n")
        .assert()
        .success();
}

#[test]
fn missing_config_file_falls_back_to_arg_or_env_normally() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg"); // intentionally never populated
    let db = tmp.path().join("only-arg.kdbx");
    make_kdbx(&db, "only-pw");

    // No config file exists under $XDG_CONFIG_HOME/freekee. No
    // FREEKEE_DB. Without --db this would error, but with --db it
    // works normally.
    freekee()
        .env("XDG_CONFIG_HOME", &xdg)
        .env_remove("FREEKEE_DB")
        .arg("info")
        .arg("--db")
        .arg(&db)
        .arg("--pass-stdin")
        .write_stdin("only-pw\n")
        .assert()
        .success();
}

#[test]
fn malformed_config_surfaces_clear_error() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg");
    fs::create_dir_all(xdg.join("freekee")).unwrap();
    fs::write(
        xdg.join("freekee").join("config.toml"),
        "this is = not [[[[ valid toml",
    )
    .unwrap();

    freekee()
        .env("XDG_CONFIG_HOME", &xdg)
        .env_remove("FREEKEE_DB")
        .arg("info")
        .arg("--pass-stdin")
        .write_stdin("whatever\n")
        .assert()
        .failure()
        .stderr(contains("config"));
}
