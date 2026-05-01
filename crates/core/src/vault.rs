//! `Vault` - the orchestrator above `kdbx::Database`. Owns a parsed
//! database, the file path, and the credentials used to unlock it.
//! All CLI and tauri-bridge code goes through this type rather than
//! reaching into `kdbx` directly (per `docs/design.md` section 5).

use std::path::{Path, PathBuf};

use chrono::Utc;
use zeroize::Zeroizing;

use kdbx::{EntryDraft, EntryField, EntryFieldValue, EntryPath};

use crate::backup::{BackupGuard, BackupOutcome};
use crate::error::{Error, Result};
use crate::password::PasswordPolicy;

/// Read-only view of an entry's printable fields, returned by
/// [`Vault::get`]. The password is intentionally absent — callers must
/// opt into seeing it via [`Vault::get_password`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryView {
    pub title: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
}

/// Summary of an entry's history, returned by [`Vault::history`].
/// `timestamps[i]` is the modification time recorded for the historical
/// entry at index `i`; `count` and `timestamps.len()` are equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryView {
    pub count: usize,
    pub timestamps: Vec<Option<chrono::NaiveDateTime>>,
}

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

    /// Create a new KDBX file at `path` with the given template,
    /// passphrase, and optional keyfile. Refuses to overwrite an
    /// existing file unless `force` is true. The new file is written
    /// and fsynced before returning the open `Vault`.
    pub fn create(
        path: &Path,
        password: Zeroizing<String>,
        keyfile: Option<&Path>,
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
        db.save(path, password.as_str(), keyfile)?;
        Ok(Self {
            db,
            path: path.to_path_buf(),
            password,
            keyfile: keyfile.map(Path::to_path_buf),
        })
    }

    /// Write the in-memory database back to its original path with
    /// the held credentials. No backup; rotation paths use
    /// `save_with_backup` (Phase 2.4).
    pub fn save(&mut self) -> Result<()> {
        self.db
            .save(&self.path, self.password.as_str(), self.keyfile.as_deref())?;
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

    /// Sorted list of every entry's full `<group>/<title>` path.
    /// `needle` is an optional case-insensitive substring filter
    /// applied against the rendered path.
    pub fn list(&self, needle: Option<&str>) -> Vec<String> {
        let lc_needle = needle.map(str::to_lowercase);
        let mut lines: Vec<String> = self
            .db
            .entries()
            .map(|e| {
                let title = e.title().unwrap_or("").to_owned();
                let mut full = e.group_path();
                full.push(title);
                full.join("/")
            })
            .filter(|full| {
                lc_needle
                    .as_ref()
                    .is_none_or(|n| full.to_lowercase().contains(n))
            })
            .collect();
        lines.sort();
        lines
    }

    /// Read-only view of an entry's printable fields. Returns `None`
    /// when no entry exists at `path`. The password is deliberately
    /// excluded; callers must opt in via [`Vault::get_password`].
    pub fn get(&self, path: EntryPath<'_>) -> Option<EntryView> {
        self.db.entry_by_path(path).map(|e| EntryView {
            title: e.title().map(str::to_owned),
            username: e.username().map(str::to_owned),
            url: e.url().map(str::to_owned),
        })
    }

    /// Stored password for the entry at `path`, wrapped in
    /// [`Zeroizing`] so it's wiped from memory when dropped. Separate
    /// accessor (rather than a field on [`EntryView`]) so password
    /// surfacing is always an explicit caller decision.
    pub fn get_password(&self, path: EntryPath<'_>) -> Option<Zeroizing<String>> {
        self.db
            .entry_by_path(path)
            .and_then(|e| e.password().map(|p| Zeroizing::new(p.to_owned())))
    }

    /// History summary for the entry at `path`: count of prior versions
    /// plus the modification timestamp recorded on each. Index 0 is the
    /// most recent prior version. Returns `None` when no entry exists.
    pub fn history(&self, path: EntryPath<'_>) -> Option<HistoryView> {
        let entry = self.db.entry_by_path(path)?;
        let count = entry.history_count();
        let timestamps: Vec<Option<chrono::NaiveDateTime>> = (0..count)
            .map(|i| entry.historical(i).and_then(|h| h.last_modified_at()))
            .collect();
        Some(HistoryView { count, timestamps })
    }

    /// Whether an entry exists at `path`. Cheaper to call than
    /// [`Vault::get`] when only existence matters.
    pub fn entry_exists(&self, path: EntryPath<'_>) -> bool {
        self.db.entry_by_path(path).is_some()
    }

    /// Current Argon2id parameters for this database, or `None` when
    /// the file is using a different KDF (legacy AES-KDF, Argon2d).
    /// Lets callers inherit the file's existing values when only some
    /// of the Argon2id knobs are being changed.
    pub fn current_argon2id_params(&self) -> Option<kdbx::Argon2idParams> {
        match self.db.kdf() {
            kdbx::Kdf::Argon2id {
                iterations,
                memory,
                parallelism,
            } => Some(kdbx::Argon2idParams {
                iterations,
                memory,
                parallelism,
            }),
            _ => None,
        }
    }

    /// Generate a fresh password for the entry at `path` using
    /// `policy`, then save with the existing passphrase. The prior
    /// password lands in entry history (via `set_field` ->
    /// `edit_tracking`). The new password is **not** returned in
    /// the outcome - fetch it via the underlying database accessor
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

    /// Add, replace, or remove the keyfile composite for this database.
    /// Pass `Some(path)` to bind a (new) keyfile, `None` to drop any
    /// existing one. The passphrase is unchanged; the verify step
    /// reopens the saved file using the *new* keyfile composition. On
    /// verify failure, restores from the backup (if any), reverts the
    /// held keyfile state to match, and surfaces
    /// [`Error::RotationVerificationFailed`].
    pub fn rotate_keyfile(
        &mut self,
        new_keyfile: Option<&Path>,
        opts: RotateOpts,
    ) -> Result<BackupOutcome> {
        // Snapshot prior state so the held keyfile stays consistent
        // with whatever's on disk on rollback.
        let prev = self.keyfile.clone();
        self.keyfile = new_keyfile.map(Path::to_path_buf);
        let pw = self.password.clone();
        match self.save_and_verify_with_backup(opts.backup, &pw) {
            Ok(outcome) => Ok(outcome),
            Err(e) => {
                self.keyfile = prev;
                Err(e)
            }
        }
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
        // verified - on rollback, `self.password` still matches the
        // restored on-disk state.
        self.password = new;
        Ok(outcome)
    }

    /// Shared rotation tail: take a backup, save with `password` plus
    /// the vault's currently-held keyfile, reopen to confirm the file
    /// decrypts under the same composite, roll back on failure.
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
        let keyfile = self.keyfile.as_deref();
        self.db.save(&self.path, password, keyfile)?;
        // Verify must use the same composite the save produced -
        // i.e., the same keyfile (or absence thereof). Rotations that
        // change the keyfile must update `self.keyfile` before
        // entering this helper so the post-save verify sees the new
        // composition.
        if kdbx::Database::open(&self.path, password, keyfile).is_err() {
            let _ = guard.restore(&self.path);
            return Err(Error::RotationVerificationFailed);
        }
        let backup_path = guard.path().map(Path::to_path_buf);
        guard.commit();
        Ok(BackupOutcome { backup_path })
    }
}
