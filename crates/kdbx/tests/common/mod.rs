// Each integration test target compiles `common` independently, so
// items used by only one of them look "dead" to the other.
#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

pub fn fixture_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/roundtrip/fixtures")
        .join(name)
}

pub fn fixture_password(name: &str) -> String {
    let raw = fs::read_to_string(fixture_dir(name).join("password.txt"))
        .expect("read fixture password.txt");
    raw.trim_end_matches('\n').to_owned()
}

/// Shared helper: read → write → read, assert structural equivalence.
///
/// `Database` derives `PartialEq + Eq` via the upstream `keepass`
/// library, so equality covers every parsed field (groups, entries,
/// history, attachments, custom data, KDF/cipher config). Any field
/// that the upstream parser drops on write would appear here as a
/// structural mismatch.
pub fn assert_self_roundtrip(fixture: &str) {
    let path = fixture_dir(fixture).join("db.kdbx");
    let password = fixture_password(fixture);

    let original =
        kdbx::Database::open(&path, &password, None).unwrap_or_else(|e| panic!("open {fixture}: {e}"));
    let tempdir = tempfile::tempdir().expect("tempdir");
    let out_path = tempdir.path().join(format!("{fixture}-roundtrip.kdbx"));
    original
        .save(&out_path, &password)
        .unwrap_or_else(|e| panic!("save {fixture}: {e}"));
    let reopened = kdbx::Database::open(&out_path, &password, None)
        .unwrap_or_else(|e| panic!("reopen {fixture}: {e}"));

    assert_eq!(original, reopened, "round-trip must preserve {fixture}");
}

/// Read → write → read → write → read; assert the second-round result
/// equals the first-round result. Locks in the idempotency invariant
/// from `docs/design.md` §10 (testing strategy, property tests).
pub fn assert_roundtrip_idempotent(fixture: &str) {
    let path = fixture_dir(fixture).join("db.kdbx");
    let password = fixture_password(fixture);
    let tempdir = tempfile::tempdir().expect("tempdir");

    let original =
        kdbx::Database::open(&path, &password, None).unwrap_or_else(|e| panic!("open {fixture}: {e}"));

    let once_path = tempdir.path().join(format!("{fixture}-rt1.kdbx"));
    original
        .save(&once_path, &password)
        .unwrap_or_else(|e| panic!("save1 {fixture}: {e}"));
    let once = kdbx::Database::open(&once_path, &password, None)
        .unwrap_or_else(|e| panic!("reopen1 {fixture}: {e}"));

    let twice_path = tempdir.path().join(format!("{fixture}-rt2.kdbx"));
    once.save(&twice_path, &password)
        .unwrap_or_else(|e| panic!("save2 {fixture}: {e}"));
    let twice = kdbx::Database::open(&twice_path, &password, None)
        .unwrap_or_else(|e| panic!("reopen2 {fixture}: {e}"));

    assert_eq!(
        once, twice,
        "second round-trip must equal first for {fixture}"
    );
}

/// Compare the committed `expected.json` next to a fixture against a
/// freshly-computed snapshot. Catches version, cipher, and KDF drift
/// that the structural-equality round-trip does not surface.
pub fn assert_expected_snapshot_matches(fixture: &str) {
    let dir = fixture_dir(fixture);
    let kdbx_path = dir.join("db.kdbx");
    let expected_path = dir.join("expected.json");
    let password = fixture_password(fixture);

    let db = kdbx::Database::open(&kdbx_path, &password, None)
        .unwrap_or_else(|e| panic!("open {fixture}: {e}"));
    let actual = kdbx::snapshot::expected_snapshot(&db);

    let raw = fs::read_to_string(&expected_path)
        .unwrap_or_else(|e| panic!("read expected.json for {fixture}: {e}"));
    let expected: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("parse expected.json for {fixture}: {e}"));

    assert_eq!(
        actual,
        expected,
        "snapshot drift for fixture `{fixture}`: regenerate with `cargo run -p kdbx --features dump-expected --bin dump-expected -- {} < {}`",
        kdbx_path.display(),
        dir.join("password.txt").display(),
    );
}

/// Shell out to `keepassxc-cli db-info` to verify a file we wrote can be
/// re-opened by the canonical KeePass implementation. Gated on the
/// `keepassxc-verify` feature; requires `keepassxc-cli` 2.7+ on PATH.
#[cfg(feature = "keepassxc-verify")]
pub fn assert_keepassxc_can_open(fixture: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let src = fixture_dir(fixture).join("db.kdbx");
    let password = fixture_password(fixture);
    let tempdir = tempfile::tempdir().expect("tempdir");
    let out_path = tempdir.path().join(format!("{fixture}-for-keepassxc.kdbx"));

    let original =
        kdbx::Database::open(&src, &password, None).unwrap_or_else(|e| panic!("open {fixture}: {e}"));
    original
        .save(&out_path, &password)
        .unwrap_or_else(|e| panic!("save {fixture}: {e}"));

    let mut child = Command::new("keepassxc-cli")
        .arg("db-info")
        .arg(&out_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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
        "keepassxc-cli rejected our file `{fixture}`: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
}
