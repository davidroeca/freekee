//! Passphrase strength rule. See `docs/design.md` section 7.1.
//!
//! IMPORTANT: this rule receives the passphrase plaintext but MUST NOT
//! embed any of it in `Finding`. Only the bit-strength estimate is
//! recorded.

use crate::{AuditConfig, Category, CompositeKeyInfo, Finding, Severity, strength};

pub fn passphrase_only(composite_key: CompositeKeyInfo) -> Option<Finding> {
    if composite_key != CompositeKeyInfo::PassphraseOnly {
        return None;
    }
    Some(Finding {
        rule: "passphrase-only",
        severity: Severity::Info,
        category: Category::CompositeKey,
        message: "Database is unlocked with a passphrase only. Adding a keyfile or hardware token \
                  raises the cost of an offline attack against the master key."
            .into(),
        citation: "https://keepass.info/help/base/keys.html",
        remediation: "freekee rotate keyfile <path> --add".into(),
    })
}

pub fn weak_passphrase(passphrase: &str, config: &AuditConfig) -> Option<Finding> {
    let bits = strength::passphrase_bits(passphrase);
    if bits >= config.weak_passphrase_bits {
        return None;
    }
    Some(Finding {
        rule: "weak-passphrase",
        severity: Severity::High,
        category: Category::CompositeKey,
        message: format!(
            "Master passphrase strength is {bits:.1} bits; threshold is {:.1}.",
            config.weak_passphrase_bits,
        ),
        citation: "https://csrc.nist.gov/publications/detail/sp/800-63b/final",
        remediation: "freekee rotate passphrase <path>".into(),
    })
}
