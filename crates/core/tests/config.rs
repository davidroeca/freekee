//! Config-file loading. Pins the contract for
//! `Config::load(&path)` and `Config::default_path()`.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use freekee_core::Config;

#[test]
fn load_returns_default_when_file_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("nope.toml");
    let cfg = Config::load(&path).expect("missing file must not be an error");
    assert!(
        cfg.default_db.is_none(),
        "missing file => no default_db, got {:?}",
        cfg.default_db,
    );
}

#[test]
fn load_parses_default_db_from_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.toml");
    fs::write(&path, r#"default_db = "/home/test/vault.kdbx""#).unwrap();
    let cfg = Config::load(&path).expect("well-formed toml must parse");
    assert_eq!(cfg.default_db, Some(PathBuf::from("/home/test/vault.kdbx")));
}

#[test]
fn load_returns_default_for_empty_file() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("empty.toml");
    fs::write(&path, "").unwrap();
    let cfg = Config::load(&path).expect("empty file is valid toml");
    assert!(cfg.default_db.is_none());
}

#[test]
fn load_errors_on_malformed_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("broken.toml");
    fs::write(&path, "this is = not valid [[[[ toml").unwrap();
    let err = Config::load(&path).expect_err("malformed toml must surface as an error");
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("config"),
        "error message should mention 'config' for context, got {msg:?}",
    );
}

#[test]
fn load_ignores_unknown_keys() {
    // Forward compatibility: a config file that mentions keys this
    // version doesn't know about should still load cleanly, with the
    // known keys taking effect.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("forward.toml");
    fs::write(
        &path,
        r#"
default_db = "/path/x.kdbx"
future_key = "something we don't know about yet"
"#,
    )
    .unwrap();
    let cfg = Config::load(&path).expect("unknown keys must not break loading");
    assert_eq!(cfg.default_db, Some(PathBuf::from("/path/x.kdbx")));
}

#[test]
fn default_path_lives_under_freekee_subdir() {
    // We don't assert the platform-specific prefix (XDG on Linux,
    // ~/Library/Application Support on macOS, %APPDATA% on Windows);
    // only that *if* one is reachable, it ends with `freekee/config.toml`.
    if let Some(p) = Config::default_path() {
        let s = p.to_string_lossy();
        assert!(
            s.ends_with("freekee/config.toml") || s.ends_with("freekee\\config.toml"),
            "default config path should end with freekee/config.toml, got {s:?}",
        );
    }
}
