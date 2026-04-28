//! Configuration audit for parsed KDBX4 databases.
//!
//! Pure analysis: takes a parsed database, returns findings. No I/O,
//! no mutation. See `docs/design.md` §7. Rules live under `rules/`.

mod rules;
mod strength;

pub use strength::passphrase_bits;

use serde::Serialize;

/// Severity ordering: Info < Low < Medium < High < Critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    CipherFormat,
    CompositeKey,
    Entries,
    Attachments,
}

/// A single audit observation. `remediation` is the exact CLI command
/// the user can run to address the finding (per design.md §7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub category: Category,
    pub message: String,
    pub citation: &'static str,
    pub remediation: String,
}

/// User-tunable thresholds.
///
/// `zxcvbn` caveat: `zxcvbn-rs` 3.1.1 saturates `guesses_log10` at
/// `log10(u64::MAX) ≈ 19.27`, which is ~64.0 bits. **No password can
/// score above 64 bits with this library**, so any threshold ≥ 64
/// would flag every passphrase regardless of strength. The
/// passphrase/entry bit thresholds below intentionally sit below that
/// cap to remain meaningful. The user-confirmed "stricter" intent
/// from milestone-0 plan §6 is honored where it can be (`stale_*`)
/// and noted as unachievable for the bit thresholds.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Minimum acceptable passphrase strength in bits (zxcvbn).
    /// Must be < 64 to be expressible; see struct docs.
    pub weak_passphrase_bits: f64,
    /// Minimum acceptable per-entry password strength in bits.
    /// Must be < 64; see struct docs.
    pub weak_entry_password_bits: f64,
    /// Maximum age in days before a password is flagged stale.
    pub stale_password_days: i64,
    /// Argon2 memory floor (bytes).
    pub weak_argon2_memory_bytes: u64,
    /// Argon2 iterations floor.
    pub weak_argon2_iters: u64,
    /// Argon2 parallelism floor.
    pub weak_argon2_parallelism: u32,
    /// Attachment size ceiling for the informational `large-attachment`
    /// finding (bytes).
    pub large_attachment_bytes: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            // Below the 64-bit zxcvbn cap; matches design.md §4.4/§7.1.
            weak_passphrase_bits: 60.0,
            weak_entry_password_bits: 50.0,
            // User's stricter value (design.md says 365).
            stale_password_days: 180,
            weak_argon2_memory_bytes: 64 * 1024 * 1024,
            weak_argon2_iters: 2,
            weak_argon2_parallelism: 2,
            large_attachment_bytes: 5 * 1024 * 1024,
        }
    }
}

/// What the caller can tell us about the composite key used to unlock
/// the database. Some rules (currently A7 `passphrase-only`) need this
/// information because it is not stored in the parsed `Database`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CompositeKeyInfo {
    /// The caller did not track which factors made up the composite
    /// key. A7 stays silent.
    #[default]
    Untracked,
    /// The caller knows the composite key contained no extra factor
    /// beyond the passphrase: no keyfile, no challenge-response, etc.
    /// A7 fires INFO.
    PassphraseOnly,
    /// At least one factor beyond the passphrase was present (keyfile,
    /// challenge-response, ...). A7 stays silent.
    HasExtraFactor,
}

/// Run every enabled rule against the database and return findings in
/// rule order.
pub fn run(
    db: &kdbx::Database,
    passphrase: &str,
    composite_key: CompositeKeyInfo,
    config: &AuditConfig,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(f) = rules::cipher::weak_outer_cipher(db) {
        findings.push(f);
    }
    if let Some(f) = rules::cipher::legacy_stream_cipher(db) {
        findings.push(f);
    }
    if let Some(f) = rules::kdf::legacy_kdf(db) {
        findings.push(f);
    }
    if let Some(f) = rules::kdf::weak_argon2_params(db, config) {
        findings.push(f);
    }
    if let Some(f) = rules::format::legacy_kdbx_version(db) {
        findings.push(f);
    }
    if let Some(f) = rules::passphrase::weak_passphrase(passphrase, config) {
        findings.push(f);
    }
    if let Some(f) = rules::passphrase::passphrase_only(composite_key) {
        findings.push(f);
    }
    findings.extend(rules::entries::weak_entry_passwords(db, config));
    findings.extend(rules::entries::reused_passwords(db));
    findings.extend(rules::entries::stale_passwords(db, config));
    findings.extend(rules::entries::expired_entries(db));
    findings.extend(rules::entries::large_attachments(db, config));

    findings
}
