//! Outer/inner cipher rules. See `docs/design.md` §7.1.
//!
//! KDBX4 only allows AES-256, ChaCha20, and Twofish as outer ciphers
//! (per `keepass::config::OuterCipherConfig`); AES-128 is not a valid
//! KDBX4 option, contrary to design.md §7.1's example phrasing. The
//! `weak-outer-cipher` rule therefore flags Twofish (legacy, not on
//! KeePass's recommended list) at MEDIUM. The design.md phrasing is
//! tracked for update in the doc-fixup PR.

use crate::{Category, Finding, Severity};
use kdbx::OuterCipher;

pub fn weak_outer_cipher(db: &kdbx::Database) -> Option<Finding> {
    match db.outer_cipher() {
        OuterCipher::Aes256 | OuterCipher::ChaCha20 => None,
        OuterCipher::Twofish => Some(Finding {
            rule: "weak-outer-cipher",
            severity: Severity::Medium,
            category: Category::CipherFormat,
            message:
                "Outer cipher is Twofish, which is not on KeePass's current recommended list. \
                 Use AES-256 or ChaCha20."
                    .into(),
            citation: "https://keepass.info/help/kb/kdbx_4.html",
            remediation: "freekee rotate cipher <path> --to chacha20".into(),
        }),
    }
}
