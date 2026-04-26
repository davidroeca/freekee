//! Passphrase strength rule. See `docs/design.md` §7.1.
//!
//! IMPORTANT: this rule receives the passphrase plaintext but MUST NOT
//! embed any of it in `Finding`. Only the bit-strength estimate is
//! recorded.

use crate::{AuditConfig, Category, Finding, Severity, strength};

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
