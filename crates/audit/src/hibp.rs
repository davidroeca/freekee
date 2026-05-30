//! Pure k-anonymity helpers for the A12 `breached-password` rule.
//!
//! This module performs **no network I/O**. The network range query lives in
//! `core`. Here we only:
//!
//! 1. split a password's SHA-1 into the 5-char range prefix (the *only*
//!    thing that may ever leave the machine) and the 35-char suffix kept
//!    locally for comparison, and
//! 2. count breach occurrences by matching that suffix against a range
//!    response body the caller already fetched.
//!
//! Per the file-wide rule in `rules/entries.rs`, no `Finding` produced
//! here embeds a password: only the entry title, path, and breach count.

use sha1::{Digest, Sha1};

use crate::{Category, Finding, Severity};

/// Split a password's SHA-1 hash into the HIBP range query `(prefix,
/// suffix)`: the uppercase-hex digest's first 5 chars and remaining 35.
///
/// Only `prefix` is ever transmitted (k-anonymity); `suffix` stays local
/// and is compared against the range response with [`breach_count`].
pub fn hibp_range_split(password: &str) -> (String, String) {
    let digest = Sha1::digest(password.as_bytes());
    let hex = format!("{digest:X}");
    let (prefix, suffix) = hex.split_at(5);
    (prefix.to_owned(), suffix.to_owned())
}

/// Count how many times `suffix` appears in a HIBP range response body.
///
/// The body is `SUFFIX:COUNT` lines (CRLF- or LF-separated). The match is
/// case-insensitive because the API returns uppercase suffixes while a
/// caller may pass either case. Returns `0` when the suffix is absent.
pub fn breach_count(suffix: &str, response_body: &str) -> u64 {
    for line in response_body.lines() {
        let Some((line_suffix, count)) = line.trim().split_once(':') else {
            continue;
        };
        if line_suffix.eq_ignore_ascii_case(suffix) {
            return count.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Build the `breached-password` finding for an entry whose password
/// appeared `count` times in the HIBP corpus. The password is never an
/// input here, so it cannot leak into the finding.
pub fn breached_password_finding(title: &str, entry_path: Vec<String>, count: u64) -> Finding {
    Finding {
        rule: "breached-password",
        severity: Severity::Critical,
        category: Category::Entries,
        message: format!(
            "Entry `{title}` uses a password found {count} time(s) in the \
             Have I Been Pwned breach corpus.",
        ),
        citation: "https://haveibeenpwned.com/API/v3#PwnedPasswords",
        remediation: format!("freekee rotate entry <path> --title {title:?}"),
        entry_path: Some(entry_path),
    }
}
