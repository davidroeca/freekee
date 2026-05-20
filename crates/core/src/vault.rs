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

/// Predicate selector for [`Vault::rotate_entries`]. Each `true` field
/// enables the corresponding audit predicate; the union of all enabled
/// predicates (OR-combined and deduplicated by entry path) is what
/// rotates. All-`false` is legal at the type level but the CLI requires
/// at least one to be set.
#[derive(Debug, Default, Clone, Copy)]
pub struct BulkRotateFilter {
    /// Entries flagged by `audit::reused_entry_targets`.
    pub reused: bool,
    /// Entries flagged by `audit::stale_entry_targets`.
    pub stale: bool,
    /// Entries flagged by `audit::weak_entry_targets`.
    pub weak: bool,
}

/// Filter passed to [`Vault::list`]. Each field is an optional
/// case-insensitive substring; multiple fields are AND-combined. An
/// empty filter (the default) matches every entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct ListFilter<'a> {
    /// Match against the rendered `<group>/<title>` path.
    pub path: Option<&'a str>,
    /// Match against the entry's username field.
    pub username: Option<&'a str>,
    /// Match against the entry's url field.
    pub url: Option<&'a str>,
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

    /// Extend (or set) the entry's expiry to `until`. In-memory only;
    /// the caller is responsible for persistence via `save`, a rotation
    /// method, or `apply_fix_batch`. Routes through
    /// [`kdbx::Database::set_entry_expiry`], which snapshots the prior
    /// version into history and stamps `times.last_modification`.
    ///
    /// Intended primarily for use inside `apply_fix_batch` so the
    /// expiry-extension fix and other intents can share a single
    /// save+verify+backup tail.
    pub fn extend_entry_expiry(
        &mut self,
        path: EntryPath<'_>,
        until: chrono::NaiveDateTime,
    ) -> Result<()> {
        self.db.set_entry_expiry(path, Some(until))?;
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

    /// Sorted list of every entry's full `<group>/<title>` path,
    /// optionally narrowed by [`ListFilter`]. All filter fields are
    /// case-insensitive substring matches; multiple fields are
    /// AND-combined.
    pub fn list(&self, filter: &ListFilter<'_>) -> Vec<String> {
        let lc_path = filter.path.map(str::to_lowercase);
        let lc_username = filter.username.map(str::to_lowercase);
        let lc_url = filter.url.map(str::to_lowercase);
        let mut lines: Vec<String> = self
            .db
            .entries()
            .filter(|e| {
                lc_username
                    .as_ref()
                    .is_none_or(|n| e.username().is_some_and(|u| u.to_lowercase().contains(n)))
                    && lc_url
                        .as_ref()
                        .is_none_or(|n| e.url().is_some_and(|u| u.to_lowercase().contains(n)))
            })
            .map(|e| {
                let title = e.title().unwrap_or("").to_owned();
                let mut full = e.group_path();
                full.push(title);
                full.join("/")
            })
            .filter(|full| {
                lc_path
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

    /// Whether the database's KDF is already Argon2id.
    pub fn kdf_is_argon2id(&self) -> bool {
        matches!(self.db.kdf(), kdbx::Kdf::Argon2id { .. })
    }

    /// Current outer cipher used by this database.
    pub fn outer_cipher(&self) -> kdbx::OuterCipher {
        self.db.outer_cipher()
    }

    /// Current inner cipher used by this database.
    pub fn inner_cipher(&self) -> kdbx::InnerCipher {
        self.db.inner_cipher()
    }

    /// Rotate the outer and/or inner cipher. Pass `None` for either
    /// argument to leave it unchanged. At least one must be `Some`.
    /// Routes through the shared backup / save / verify / rollback tail.
    pub fn rotate_cipher(
        &mut self,
        outer: Option<kdbx::OuterCipher>,
        inner: Option<kdbx::InnerCipher>,
        opts: RotateOpts,
    ) -> Result<BackupOutcome> {
        if outer.is_none() && inner.is_none() {
            return Err(Error::NoRotationTarget);
        }
        if let Some(c) = outer {
            self.db.set_outer_cipher(c);
        }
        if let Some(c) = inner {
            self.db.set_inner_cipher(c);
        }
        let pw = self.password.clone();
        self.save_and_verify_with_backup(opts.backup, &pw)
    }

    /// Bring the database's in-memory format version up to whatever
    /// `keepass-rs` currently writes (today: KDBX4 minor 0; tracks the
    /// upstream constant when the pin moves). No-op when already at
    /// the current write target. The legacy KDF and inner cipher are
    /// preserved as-is — chain `rotate_kdf` / `rotate_cipher`
    /// afterward if full modernization is desired.
    pub fn rotate_format(&mut self, opts: RotateOpts) -> Result<BackupOutcome> {
        if !self.db.ensure_writable() {
            return Ok(BackupOutcome {
                changed: false,
                backup_path: None,
            });
        }
        let pw = self.password.clone();
        self.save_and_verify_with_backup(opts.backup, &pw)
    }

    /// Rotate the KDF type to Argon2id. If the database already uses
    /// Argon2id, this is a no-op (returns `BackupOutcome { backup_path:
    /// None }`). For legacy AES-KDF databases, the KDF is replaced with
    /// Argon2id using the workspace-default parameters from
    /// `DEFAULT_TEMPLATE`. Routes through the shared backup / save /
    /// verify / rollback tail.
    pub fn rotate_kdf(&mut self, opts: RotateOpts) -> Result<BackupOutcome> {
        if self.kdf_is_argon2id() {
            return Ok(BackupOutcome {
                changed: false,
                backup_path: None,
            });
        }
        self.db.set_kdf_params(crate::DEFAULT_TEMPLATE.kdf)?;
        let pw = self.password.clone();
        self.save_and_verify_with_backup(opts.backup, &pw)
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

    /// Bulk-regenerate passwords for every entry that matches at least
    /// one selected audit predicate (weak / stale / reused). All matched
    /// entries are mutated in memory, then a **single**
    /// `save_and_verify_with_backup` runs at the end — do not "fix" this
    /// to save per-entry; that would multiply the Argon2 verify cost by
    /// the match count and slow large vaults by orders of magnitude.
    ///
    /// Predicate sources are `audit::weak_entry_targets`,
    /// `audit::stale_entry_targets`, and `audit::reused_entry_targets`,
    /// all using `AuditConfig::default()` thresholds. CLI threshold
    /// override flags are out of scope for v1.
    ///
    /// Returns the rotation outcome and the sorted list of rotated
    /// entry paths (`<group>/<title>` strings). New passwords are never
    /// surfaced — fetch via [`Vault::get_password`] when explicit opt-in
    /// is required.
    ///
    /// Empty-match path: returns `(BackupOutcome { changed: false,
    /// backup_path: None }, vec![])` without invoking save, so no file
    /// mtime change and no backup is written.
    pub fn rotate_entries(
        &mut self,
        filter: &BulkRotateFilter,
        policy: &PasswordPolicy,
        opts: RotateOpts,
    ) -> Result<(BackupOutcome, Vec<String>)> {
        let matches = self.bulk_rotate_targets(filter);

        if matches.is_empty() {
            return Ok((
                BackupOutcome {
                    changed: false,
                    backup_path: None,
                },
                Vec::new(),
            ));
        }

        let mut rotated_paths = Vec::with_capacity(matches.len());
        for (group_path, title) in &matches {
            let groups: Vec<&str> = group_path.iter().map(String::as_str).collect();
            let path = EntryPath {
                groups: &groups,
                title,
            };
            let new_pw = policy.generate();
            self.db.set_entry_field(
                path,
                EntryField::Password,
                EntryFieldValue::Protected(new_pw.as_str()),
            )?;
            let mut joined = group_path.clone();
            joined.push(title.clone());
            rotated_paths.push(joined.join("/"));
        }

        let pw = self.password.clone();
        let outcome = self.save_and_verify_with_backup(opts.backup, &pw)?;
        Ok((outcome, rotated_paths))
    }

    /// Sorted `<group>/<title>` paths for every entry the matching
    /// `BulkRotateFilter` would rotate. Read-only; used by the CLI's
    /// `--dry-run` to preview `rotate_entries`. The implementation is
    /// the same predicate union + dedup logic that `rotate_entries`
    /// uses, so a dry-run is a faithful preview.
    pub fn bulk_rotate_preview(&self, filter: &BulkRotateFilter) -> Vec<String> {
        self.bulk_rotate_targets(filter)
            .into_iter()
            .map(|(group_path, title)| {
                let mut joined = group_path;
                joined.push(title);
                joined.join("/")
            })
            .collect()
    }

    fn bulk_rotate_targets(&self, filter: &BulkRotateFilter) -> Vec<(Vec<String>, String)> {
        let cfg = audit::AuditConfig::default();
        let mut matches: Vec<(Vec<String>, String)> = Vec::new();
        if filter.weak {
            matches.extend(audit::weak_entry_targets(&self.db, &cfg));
        }
        if filter.stale {
            matches.extend(audit::stale_entry_targets(&self.db, &cfg));
        }
        if filter.reused {
            matches.extend(audit::reused_entry_targets(&self.db));
        }
        matches.sort();
        matches.dedup();
        matches
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
        Ok(BackupOutcome {
            changed: true,
            backup_path,
        })
    }
}
