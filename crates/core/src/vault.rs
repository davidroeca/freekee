//! `Vault` — the orchestrator above `kdbx::Database`. Owns a parsed
//! database, the file path, and the credentials used to unlock it.
//! All CLI and tauri-bridge code goes through this type rather than
//! reaching into `kdbx` directly (per `docs/design.md` §5).

use std::path::{Path, PathBuf};

use chrono::Utc;
use zeroize::Zeroizing;

use kdbx::{EntryDraft, EntryField, EntryFieldValue, EntryPath};

use crate::backup::{BackupGuard, BackupOutcome};
use crate::error::{Error, Result};
use crate::password::PasswordPolicy;

/// Options shared by all rotation methods on [`Vault`].
#[derive(Debug, Clone, Copy)]
pub struct RotateOpts {
    /// When `true`, copy the existing file to a timestamped backup
    /// before writing the rotated file. The post-save verify always
    /// runs regardless of this flag.
    pub backup: bool,
}

impl Default for RotateOpts {
    fn default() -> Self {
        Self { backup: true }
    }
}

pub struct Vault {
    db: kdbx::Database,
    path: PathBuf,
    password: Zeroizing<String>,
    keyfile: Option<PathBuf>,
}

impl std::fmt::Debug for Vault {
    /// Manual `Debug` so the held passphrase never appears in any
    /// formatter output, panic message, or `expect_err` rendering.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("keyfile", &self.keyfile)
            .field("password", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Open an existing KDBX file. The passphrase is held in a
    /// `Zeroizing<String>` for the lifetime of the `Vault`.
    pub fn open(path: &Path, password: Zeroizing<String>, keyfile: Option<&Path>) -> Result<Self> {
        let db = kdbx::Database::open(path, password.as_str(), keyfile)?;
        Ok(Self {
            db,
            path: path.to_path_buf(),
            password,
            keyfile: keyfile.map(Path::to_path_buf),
        })
    }

    /// Create a new KDBX file at `path` with the given template and
    /// passphrase. Refuses to overwrite an existing file unless
    /// `force` is true. The new file is written and fsynced before
    /// returning the open `Vault`.
    pub fn create(
        path: &Path,
        password: Zeroizing<String>,
        template: kdbx::NewDatabaseTemplate,
        force: bool,
    ) -> Result<Self> {
        if password.is_empty() {
            return Err(crate::error::Error::EmptyPassphrase);
        }
        if path.exists() && !force {
            return Err(crate::error::Error::FileExists);
        }
        let db = kdbx::Database::new_empty(template);
        db.save(path, password.as_str())?;
        Ok(Self {
            db,
            path: path.to_path_buf(),
            password,
            keyfile: None,
        })
    }

    /// Write the in-memory database back to its original path with
    /// the held credentials. No backup; rotation paths use
    /// `save_with_backup` (Phase 2.4).
    pub fn save(&mut self) -> Result<()> {
        self.db.save(&self.path, self.password.as_str())?;
        Ok(())
    }

    /// Path on disk this vault was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Optional keyfile path used to unlock this vault.
    pub fn keyfile(&self) -> Option<&Path> {
        self.keyfile.as_deref()
    }

    /// Edit a single field on an existing entry. The prior version
    /// of the entry lands in its history (see `kdbx::Database::set_entry_field`).
    pub fn set_field(
        &mut self,
        path: EntryPath<'_>,
        field: EntryField<'_>,
        value: EntryFieldValue<'_>,
    ) -> Result<()> {
        self.db.set_entry_field(path, field, value)?;
        Ok(())
    }

    /// Insert an entry at `path` if missing, or update the supplied
    /// fields on the existing entry. Field updates route through
    /// `set_field` so each one snapshots into history.
    pub fn upsert_entry(&mut self, path: EntryPath<'_>, draft: EntryDraft<'_>) -> Result<()> {
        if self.db.entry_by_path(path).is_none() {
            self.db.add_entry(path, draft)?;
            return Ok(());
        }
        if let Some(u) = draft.username {
            self.db
                .set_entry_field(path, EntryField::Username, EntryFieldValue::Plain(u))?;
        }
        if let Some(p) = draft.password {
            self.db
                .set_entry_field(path, EntryField::Password, EntryFieldValue::Protected(p))?;
        }
        if let Some(u) = draft.url {
            self.db
                .set_entry_field(path, EntryField::Url, EntryFieldValue::Plain(u))?;
        }
        if let Some(n) = draft.notes {
            self.db
                .set_entry_field(path, EntryField::Notes, EntryFieldValue::Plain(n))?;
        }
        Ok(())
    }

    /// Remove the entry at `path`. The UUID is registered in the
    /// database's `deleted_objects` (see `kdbx::Database::remove_entry`)
    /// so KeePassXC sync respects the deletion.
    pub fn remove_entry(&mut self, path: EntryPath<'_>) -> Result<()> {
        self.db.remove_entry(path)?;
        Ok(())
    }

    /// Relocate (and optionally rename) an entry. The change is
    /// recorded in the entry's history.
    pub fn move_entry(&mut self, src: EntryPath<'_>, dst: EntryPath<'_>) -> Result<()> {
        self.db.move_entry(src, dst)?;
        Ok(())
    }

    /// Borrow the underlying `kdbx::Database` for read-only inspection.
    /// Callers needing more granular access (history, attachments,
    /// etc.) use this until first-class `core` accessors arrive.
    pub fn db(&self) -> &kdbx::Database {
        &self.db
    }

    /// Generate a fresh password for the entry at `path` using
    /// `policy`, then save with the existing passphrase. The prior
    /// password lands in entry history (via `set_field` →
    /// `edit_tracking`). The new password is **not** returned in
    /// the outcome — fetch it via the underlying database accessor
    /// when the caller has explicitly opted in to seeing it.
    pub fn rotate_entry(
        &mut self,
        path: EntryPath<'_>,
        policy: &PasswordPolicy,
        opts: RotateOpts,
    ) -> Result<BackupOutcome> {
        if self.db.entry_by_path(path).is_none() {
            return Err(Error::NotFound);
        }
        let new_pw = policy.generate();
        self.db.set_entry_field(
            path,
            EntryField::Password,
            EntryFieldValue::Protected(new_pw.as_str()),
        )?;
        let pw = self.password.clone();
        self.save_and_verify_with_backup(opts.backup, &pw)
    }

    /// Replace the database's KDF parameters (Argon2id) and re-save.
    /// The passphrase is unchanged. Optionally takes a backup; always
    /// verifies the rotated file decrypts before declaring success.
    pub fn rotate_kdf_params(
        &mut self,
        params: kdbx::Argon2idParams,
        opts: RotateOpts,
    ) -> Result<BackupOutcome> {
        self.db.set_kdf_params(params)?;
        let pw = self.password.clone();
        self.save_and_verify_with_backup(opts.backup, &pw)
    }

    /// Re-encrypt the file under a new passphrase. Optionally takes a
    /// timestamped backup first; always verifies the rotated file by
    /// reopening it with the new passphrase before declaring success.
    /// On verify failure, restores from the backup (if any) and
    /// surfaces [`Error::RotationVerificationFailed`].
    pub fn rotate_passphrase(
        &mut self,
        new: Zeroizing<String>,
        opts: RotateOpts,
    ) -> Result<BackupOutcome> {
        if new.is_empty() {
            return Err(Error::EmptyPassphrase);
        }
        let outcome = self.save_and_verify_with_backup(opts.backup, new.as_str())?;
        // Only update the held passphrase after the new file has
        // verified — on rollback, `self.password` still matches the
        // restored on-disk state.
        self.password = new;
        Ok(outcome)
    }

    /// Shared rotation tail: take a backup, save with `password`,
    /// reopen to confirm the file decrypts, roll back on failure.
    /// `password` is the credential used both to write the file and
    /// to verify it (always equal — `kdbx::Database::save` is
    /// passphrase-only today; keyfile-on-save lands in M2).
    fn save_and_verify_with_backup(
        &mut self,
        backup: bool,
        password: &str,
    ) -> Result<BackupOutcome> {
        let mut guard = if backup {
            BackupGuard::create_for(&self.path, Utc::now())?
        } else {
            BackupGuard::skip()
        };
        self.db.save(&self.path, password)?;
        // `keyfile: None` deliberately. `kdbx::Database::save` writes
        // a passphrase-only file regardless of how the vault was
        // opened (keyfile-on-save is a pending M2 follow-up); so the
        // verify must use the same composition the save produced.
        if kdbx::Database::open(&self.path, password, None).is_err() {
            let _ = guard.restore(&self.path);
            return Err(Error::RotationVerificationFailed);
        }
        let backup_path = guard.path().map(Path::to_path_buf);
        guard.commit();
        Ok(BackupOutcome { backup_path })
    }
}
