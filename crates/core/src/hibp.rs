//! HIBP breached-password walk (A12). This module owns the network I/O
//! that the `audit` crate deliberately does not: it fetches the k-anonymity
//! range responses and feeds them to `audit`'s pure helpers.
//!
//! Privacy invariant: only the 5-char SHA-1 prefix from
//! [`audit::hibp_range_split`] is ever sent over the network. The full
//! hash, the suffix, and the password itself never leave the machine.

use std::collections::HashMap;

use audit::{Finding, breach_count, breached_password_finding, hibp_range_split};

use crate::error::{Error, Result};

/// Source of HIBP range responses, keyed by the 5-char hash prefix.
///
/// The seam between the breach walk and the HTTP transport: tests inject
/// a fake so they run offline, and the transport can be swapped (e.g. for
/// async reqwest when the Tauri/sync layer lands) without touching the
/// walk or the pure `audit` helpers.
pub trait RangeClient {
    /// Fetch the range response body for `prefix` (the `SUFFIX:COUNT`
    /// lines for every breached hash sharing that prefix).
    fn fetch(&self, prefix: &str) -> Result<String>;
}

/// A [`RangeClient`] backed by a blocking HTTPS request to a HIBP-compatible
/// `range/{prefix}` endpoint. `base_url` is configurable so callers can
/// point tests at a local stub; production uses `https://api.pwnedpasswords.com`.
pub struct HttpRangeClient {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl HttpRangeClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::blocking::Client::new(),
        }
    }
}

impl RangeClient for HttpRangeClient {
    fn fetch(&self, prefix: &str) -> Result<String> {
        let url = format!("{}/range/{prefix}", self.base_url.trim_end_matches('/'));
        // `reqwest::Error`'s Display carries only the URL (which contains
        // just the public 5-char prefix) and status. Never a password.
        let resp = self
            .client
            .get(&url)
            .send()
            .map_err(|e| Error::Hibp(e.to_string()))?
            .error_for_status()
            .map_err(|e| Error::Hibp(e.to_string()))?;
        resp.text().map_err(|e| Error::Hibp(e.to_string()))
    }
}

/// Walk every entry with a password and return a `breached-password`
/// finding for each whose password appears in the HIBP corpus.
///
/// Requests are deduplicated by prefix (k-anonymity batching): entries
/// sharing a 5-char prefix trigger a single fetch. Passwords and full
/// hashes are never stored, logged, or transmitted.
pub fn breached_passwords(db: &kdbx::Database, client: &dyn RangeClient) -> Result<Vec<Finding>> {
    let mut cache: HashMap<String, String> = HashMap::new();
    let mut findings = Vec::new();

    for entry in db.entries() {
        let Some(password) = entry.password() else {
            continue;
        };
        if password.is_empty() {
            continue;
        }
        let (prefix, suffix) = hibp_range_split(password);
        let body = match cache.get(&prefix) {
            Some(body) => body,
            None => {
                let fetched = client.fetch(&prefix)?;
                cache.entry(prefix).or_insert(fetched)
            }
        };
        let count = breach_count(&suffix, body);
        if count == 0 {
            continue;
        }
        let title = entry.title().unwrap_or("(untitled)");
        let mut path = entry.group_path();
        path.push(title.to_owned());
        findings.push(breached_password_finding(title, path, count));
    }

    Ok(findings)
}
