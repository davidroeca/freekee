//! Outer/inner cipher rules. See `docs/design.md` section 7.1.
//!
//! KDBX4 only allows AES-256, ChaCha20, and Twofish as outer ciphers
//! (per `keepass::config::OuterCipherConfig`); AES-128 is not a valid
//! KDBX4 option, contrary to design.md section 7.1's example phrasing. The
//! `weak-outer-cipher` rule therefore flags Twofish (legacy, not on
//! KeePass's recommended list) at MEDIUM. The design.md phrasing is
//! tracked for update in the doc-fixup PR.

use crate::{Category, Finding, Severity};
use kdbx::{InnerCipher, OuterCipher};

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

pub fn legacy_stream_cipher(db: &kdbx::Database) -> Option<Finding> {
    match db.inner_cipher() {
        InnerCipher::ChaCha20 => None,
        InnerCipher::Salsa20 => Some(Finding {
            rule: "legacy-stream-cipher",
            severity: Severity::Medium,
            category: Category::CipherFormat,
            message: "Inner stream cipher is Salsa20, the legacy KDBX 3 default. KDBX 4 selects \
                 ChaCha20 for new databases; Salsa20 is retained only for backward compatibility."
                .into(),
            citation: "https://keepass.info/help/kb/kdbx_4.html",
            remediation: "freekee rotate cipher <path> --inner chacha20".into(),
        }),
        InnerCipher::Plain => None,
    }
}
