//! Tests for the HIBP breached-password walk in `core`. The network is
//! stubbed by a `FakeRangeClient` so these run fully offline; the only
//! live-network path is `HttpRangeClient`, exercised via the CLI's
//! localhost-stub tests, not here.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use std::cell::RefCell;

use freekee_core::{RangeClient, breached_passwords};
use kdbx::{
    Argon2idParams, Database, EntryDraft, EntryPath, InnerCipher, NewDatabaseTemplate, OuterCipher,
};

// SHA1("password") prefix/suffix.
const BREACHED_PREFIX: &str = "5BAA6";
const BREACHED_SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

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

/// Records every prefix it is asked for and answers from a canned map.
/// Unknown prefixes return an empty body (no breach match).
struct FakeRangeClient {
    body_for_breached_prefix: String,
    requested: RefCell<Vec<String>>,
}

impl FakeRangeClient {
    fn new() -> Self {
        Self {
            body_for_breached_prefix: format!("{BREACHED_SUFFIX}:9659365\r\n"),
            requested: RefCell::new(Vec::new()),
        }
    }
}

impl RangeClient for FakeRangeClient {
    fn fetch(&self, prefix: &str) -> freekee_core::Result<String> {
        self.requested.borrow_mut().push(prefix.to_owned());
        if prefix == BREACHED_PREFIX {
            Ok(self.body_for_breached_prefix.clone())
        } else {
            Ok(String::new())
        }
    }
}

fn add(db: &mut Database, title: &str, password: &str) {
    db.add_entry(
        EntryPath { groups: &[], title },
        EntryDraft {
            password: Some(password),
            ..Default::default()
        },
    )
    .unwrap();
}

#[test]
fn flags_only_the_breached_entry() {
    let mut db = Database::new_empty(tiny_template());
    add(&mut db, "github", "password"); // breached
    add(&mut db, "bank", "S0me-l0ng-uniqu3-passphrase-9x!"); // safe

    let client = FakeRangeClient::new();
    let findings = breached_passwords(&db, &client).unwrap();

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.rule, "breached-password");
    assert_eq!(f.entry_path, Some(vec!["github".to_owned()]));
    assert!(f.message.contains("9659365"));
}

#[test]
fn never_transmits_more_than_the_five_char_prefix() {
    let mut db = Database::new_empty(tiny_template());
    add(&mut db, "github", "password");
    add(&mut db, "bank", "S0me-l0ng-uniqu3-passphrase-9x!");

    let client = FakeRangeClient::new();
    breached_passwords(&db, &client).unwrap();

    for prefix in client.requested.borrow().iter() {
        assert_eq!(prefix.len(), 5, "transmitted prefix must be 5 chars");
        assert!(
            prefix
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_lowercase()),
            "prefix must be uppercase hex, got {prefix:?}",
        );
    }
}

#[test]
fn dedupes_requests_by_prefix() {
    let mut db = Database::new_empty(tiny_template());
    // Two entries share the same password (hence the same prefix).
    add(&mut db, "github", "password");
    add(&mut db, "github-alt", "password");

    let client = FakeRangeClient::new();
    let findings = breached_passwords(&db, &client).unwrap();

    // Both entries are flagged, but the prefix is fetched only once.
    assert_eq!(findings.len(), 2);
    let reqs = client.requested.borrow();
    let mut unique = reqs.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        reqs.len(),
        unique.len(),
        "a prefix was fetched more than once"
    );
}
