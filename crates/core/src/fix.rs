//! `freekee fix` orchestrator types.
//!
//! [`FixIntent`] enumerates the remediations the interactive CLI can
//! collect from the user. [`Vault::apply_fix_batch`] validates the
//! collected intents, applies them all in-memory, then runs ONE
//! `save_and_verify_with_backup` at the tail — same pattern as
//! [`Vault::rotate_entries`]. A single fix loop therefore produces at
//! most one backup file and pays the Argon2 verify cost only once.
//!
//! Composite-key fixes (passphrase, keyfile) and informational findings
//! (large attachments) are deliberately not modeled here; they need
//! interactive input that the loop does not collect, and the existing
//! `rotate {passphrase, keyfile}` subcommands cover them.

use crate::BackupOutcome;
use crate::password::PasswordPolicy;

/// One remediation step in a `freekee fix` batch.
///
/// Paths are owned `Vec<String>` (group chain followed by the entry
/// title) so callers can accumulate intents across prompt iterations
/// without lifetime gymnastics.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum FixIntent {
    /// Generate a fresh password for the entry at `path` and write it
    /// in place. Mirrors [`Vault::rotate_entry`] mutation but defers
    /// persistence to the batch tail.
    RegenerateEntryPassword {
        path: Vec<String>,
        policy: PasswordPolicy,
    },
    /// Set the entry at `path` to expire at `until` (and mark
    /// `times.expires = true`). Mirrors [`Vault::extend_entry_expiry`].
    ExtendEntryExpiry {
        path: Vec<String>,
        until: chrono::NaiveDateTime,
    },
    /// Replace the outer (file-level) cipher.
    SetOuterCipher(kdbx::OuterCipher),
    /// Replace the inner (protected-field) stream cipher.
    SetInnerCipher(kdbx::InnerCipher),
    /// Switch the KDF to Argon2id using `DEFAULT_TEMPLATE`'s parameters.
    SetKdfArgon2id,
    /// Replace the Argon2id parameters.
    SetArgon2idParams(kdbx::Argon2idParams),
    /// Bring the KDBX format up to the current write target. No-op if
    /// already at the target.
    UpgradeFormat,
}

/// Outcome of a batched fix run. `applied` is a human-readable list,
/// one line per applied intent, never containing plaintext secrets.
#[derive(Debug, Default)]
pub struct FixReport {
    pub applied: Vec<String>,
    pub outcome: BackupOutcome,
}
