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

// A12: breached-password (HIBP), DEFERRED beyond v0.1

#[test]
#[ignore = "DEFERRED past v0.1: breached-password requires network (HIBP k-anonymity)"]
fn flags_breached_password() {
    let database = db(|cfg| cfg.kdf_config = strong_kdf());
    let findings = audit::run(
        &database,
        STRONG_PASSPHRASE,
        audit::CompositeKeyInfo::Untracked,
        &AuditConfig::default(),
    );
    assert!(
        findings.iter().any(|f| f.rule == "breached-password"),
        "expected breached-password finding for known-breached password",
    );
}
