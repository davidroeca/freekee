//! Tests for v0.1 audit rules deferred past milestone-0.
//!
//! Each test is `#[ignore]` with a pointer to the rule it locks in. Un-
//! ignoring is the start of the TDD loop for that rule's implementation
//! in milestone 0.5 / v0.1 prep. Per the milestone-0 plan §6.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use audit::AuditConfig;

mod common;
use common::{db, strong_kdf};

const STRONG_PASSPHRASE: &str = "qWk3@p9Lnv8Z2!Mrx7&fE$Bc1";

// A2 (legacy-stream-cipher) is now implemented; tests live in rules.rs.

// ─── A7: passphrase-only (informational) ──────────────────────────────────

#[test]
#[ignore = "M1: A7 passphrase-only — DB unlocked with passphrase only → INFO"]
fn flags_passphrase_only_composite_key() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    // Future: audit::run signature evolves to accept composite-key info
    // (passphrase + keyfile presence). For now, the assertion is enough
    // to fail until the rule and the API extension land.
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    assert!(
        findings.iter().any(|f| f.rule == "passphrase-only"),
        "expected passphrase-only finding when no keyfile is present",
    );
}

// A8 (weak-entry-password) is now implemented; tests live in rules.rs.

// A9 (reused-password) is now implemented; tests live in rules.rs.

// A10 (stale-password) is now implemented; tests live in rules.rs.

// A11 (expired-entry-overdue) is now implemented; tests live in rules.rs.

// ─── A13: large-attachment (informational) ────────────────────────────────

#[test]
#[ignore = "M1: A13 large-attachment (> large_attachment_bytes → INFO)"]
fn flags_large_attachment() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    assert!(
        findings.iter().any(|f| f.rule == "large-attachment"),
        "expected large-attachment finding for attachment > 5 MiB",
    );
}

// ─── A12: breached-password (HIBP) — DEFERRED beyond v0.1 ─────────────────

#[test]
#[ignore = "DEFERRED past v0.1: A12 breached-password requires network (HIBP k-anonymity)"]
fn flags_breached_password() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    let findings = audit::run(&database, STRONG_PASSPHRASE, &AuditConfig::default());
    assert!(
        findings.iter().any(|f| f.rule == "breached-password"),
        "expected breached-password finding for known-breached password",
    );
}
