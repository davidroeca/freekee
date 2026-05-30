//! Pure k-anonymity helpers for the A12 breached-password rule.
//!
//! These exercise the offline pieces only: SHA-1 range split, suffix
//! match against a fetched range body, and `Finding` shape. The network
//! lives in `core` (see `crates/core/tests/hibp.rs`); `audit` stays pure.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use audit::{Category, Severity};

// SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
const PASSWORD_SHA1_PREFIX: &str = "5BAA6";
const PASSWORD_SHA1_SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

#[test]
fn range_split_matches_known_sha1_vector() {
    let (prefix, suffix) = audit::hibp_range_split("password");
    assert_eq!(prefix, PASSWORD_SHA1_PREFIX);
    assert_eq!(suffix, PASSWORD_SHA1_SUFFIX);
    assert_eq!(prefix.len(), 5);
    assert_eq!(suffix.len(), 35);
}

#[test]
fn breach_count_returns_count_for_matching_suffix() {
    // Range API body shape: `SUFFIX:COUNT`, CRLF-separated, suffix uppercase.
    let body = format!(
        "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
         {PASSWORD_SHA1_SUFFIX}:9659365\r\n\
         00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n"
    );
    assert_eq!(audit::breach_count(PASSWORD_SHA1_SUFFIX, &body), 9659365);
}

#[test]
fn breach_count_is_zero_when_suffix_absent() {
    let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n";
    assert_eq!(audit::breach_count(PASSWORD_SHA1_SUFFIX, body), 0);
}

#[test]
fn breach_count_matches_suffix_case_insensitively() {
    let body = format!("{}:42\r\n", PASSWORD_SHA1_SUFFIX.to_lowercase());
    assert_eq!(audit::breach_count(PASSWORD_SHA1_SUFFIX, &body), 42);
}

#[test]
fn finding_shape_cites_count_not_password() {
    let path = vec!["root".to_owned(), "github".to_owned()];
    let finding = audit::breached_password_finding("github", path.clone(), 9659365);
    assert_eq!(finding.rule, "breached-password");
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.category, Category::Entries);
    assert_eq!(finding.entry_path, Some(path));
    assert!(finding.message.contains("9659365"));
    // The helper never receives the password, so it cannot leak it; the
    // count and title are the only entry-derived data in the message.
    assert!(finding.message.contains("github"));
}
