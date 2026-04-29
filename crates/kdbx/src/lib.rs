//! KDBX4 file I/O wrapper around the `keepass` crate.
//!
//! Insulates the rest of the workspace from upstream churn per
//! `docs/design.md` §6. The surface here grows test-by-test under the
//! milestone-0 TDD plan.

mod error;
pub mod path;
pub mod snapshot;

pub use error::{Error, Result};
pub use path::{
    Argon2idParams, EntryDraft, EntryField, EntryFieldValue, EntryPath, GroupPath,
    NewDatabaseTemplate,
};

use std::fs::File;
use std::path::Path;

use keepass::DatabaseKey;
use keepass::db::fields;

/// KDBX file format version, mirroring the four upstream variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbxVersion {
    Kdb1,
    Kdb2(u16),
    Kdb3(u16),
    Kdb4(u16),
}

/// Outer (file-level) symmetric cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuterCipher {
    Aes256,
    Twofish,
    ChaCha20,
}

/// Inner (protected-field) cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerCipher {
    Plain,
    Salsa20,
    ChaCha20,
}

/// Key derivation function recorded in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// Legacy: iterated AES. Discouraged.
    Aes { rounds: u64 },
    /// Argon2d.
    Argon2d {
        iterations: u64,
        memory: u64,
        parallelism: u32,
    },
    /// Argon2id (current KeePass recommendation).
    Argon2id {
        iterations: u64,
        memory: u64,
        parallelism: u32,
    },
}

impl KdbxVersion {
    /// Major version (1..=4). Useful for audit rules that flag pre-4.x.
    pub fn major(&self) -> u8 {
        match self {
            KdbxVersion::Kdb1 => 1,
            KdbxVersion::Kdb2(_) => 2,
            KdbxVersion::Kdb3(_) => 3,
            KdbxVersion::Kdb4(_) => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Database {
    inner: keepass::Database,
}

impl Database {
    /// Open a KDBX file with a passphrase and an optional keyfile.
    ///
    /// Pass `keyfile = None` for passphrase-only databases.
    pub fn open(path: &Path, password: &str, keyfile: Option<&Path>) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut key = DatabaseKey::new().with_password(password);
        if let Some(kf_path) = keyfile {
            let mut kf = File::open(kf_path)?;
            key = key.with_keyfile(&mut kf)?;
        }
        let inner = keepass::Database::open(&mut file, key)?;
        Ok(Self { inner })
    }

    /// Write this database to `path` with a passphrase. KDBX4 only.
    pub fn save(&self, path: &Path, password: &str) -> Result<()> {
        let mut file = File::create(path)?;
        let key = DatabaseKey::new().with_password(password);
        self.inner.save(&mut file, key)?;
        Ok(())
    }

    /// Number of entries directly under the root group (does not recurse).
    pub fn root_entry_count(&self) -> usize {
        self.inner.root().entries().count()
    }

    /// Number of subgroups directly under the root group.
    pub fn root_subgroup_count(&self) -> usize {
        self.inner.root().groups().count()
    }

    /// File format version recorded in the database header.
    pub fn kdbx_version(&self) -> KdbxVersion {
        use keepass::config::DatabaseVersion as V;
        match self.inner.config.version {
            V::KDB(_) => KdbxVersion::Kdb1,
            V::KDB2(m) => KdbxVersion::Kdb2(m),
            V::KDB3(m) => KdbxVersion::Kdb3(m),
            V::KDB4(m) => KdbxVersion::Kdb4(m),
        }
    }

    /// Iterator over entries directly under the root group.
    pub fn root_entries(&self) -> impl Iterator<Item = Entry<'_>> + '_ {
        // `iter_all_entries` borrows `&self.inner` directly, sidestepping
        // the temp-GroupRef lifetime trap that `root().entries()` hits.
        let root_id = self.inner.root().id();
        self.inner
            .iter_all_entries()
            .filter(move |e| e.parent().id() == root_id)
            .map(|inner| Entry { inner })
    }

    /// Iterator over every current entry in the database, recursively
    /// across all groups. Historical (prior-version) entries are not
    /// included; access them via [`Entry::history`] when added.
    pub fn entries(&self) -> impl Iterator<Item = Entry<'_>> + '_ {
        self.inner.iter_all_entries().map(|inner| Entry { inner })
    }

    /// Outer cipher recorded in the file header.
    pub fn outer_cipher(&self) -> OuterCipher {
        use keepass::config::OuterCipherConfig as C;
        match self.inner.config.outer_cipher_config {
            C::AES256 => OuterCipher::Aes256,
            C::Twofish => OuterCipher::Twofish,
            C::ChaCha20 => OuterCipher::ChaCha20,
            // `OuterCipherConfig` is `#[non_exhaustive]`. Map unknown
            // variants conservatively to AES-256 (a recognized value).
            _ => OuterCipher::Aes256,
        }
    }

    /// Inner stream cipher used for protected field values.
    pub fn inner_cipher(&self) -> InnerCipher {
        use keepass::config::InnerCipherConfig as C;
        match self.inner.config.inner_cipher_config {
            C::Plain => InnerCipher::Plain,
            C::Salsa20 => InnerCipher::Salsa20,
            C::ChaCha20 => InnerCipher::ChaCha20,
            _ => InnerCipher::ChaCha20,
        }
    }

    /// Look up an entry by its [`EntryPath`]. Group segments and the
    /// title are matched case-insensitively (matching upstream
    /// `keepass-rs`). Returns `None` if any group along the path or
    /// the entry itself is missing.
    pub fn entry_by_path(&self, path: EntryPath<'_>) -> Option<Entry<'_>> {
        let group_id = self.resolve_group_id(path.groups).ok()?;
        let title = path.title;
        // Iterate from `Database` directly to keep the returned
        // `EntryRef` bound to `&self.inner`, not to a temp `GroupRef`.
        self.inner
            .iter_all_entries()
            .find(|e| {
                e.parent().id() == group_id
                    && e.get(fields::TITLE)
                        .is_some_and(|t| t.eq_ignore_ascii_case(title))
            })
            .map(|inner| Entry { inner })
    }

    /// Create an empty database with the supplied configuration. The
    /// caller chooses cipher/KDF defaults; freekee's user-facing
    /// defaults live in `core::Vault::create`, not here.
    pub fn new_empty(template: NewDatabaseTemplate) -> Self {
        use keepass::config::{DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig};
        // `DatabaseConfig` is `#[non_exhaustive]`; start from the
        // upstream default and override the fields we care about so a
        // future field addition doesn't break our build.
        let mut config = DatabaseConfig::default();
        config.outer_cipher_config = match template.outer_cipher {
            OuterCipher::Aes256 => OuterCipherConfig::AES256,
            OuterCipher::ChaCha20 => OuterCipherConfig::ChaCha20,
            OuterCipher::Twofish => OuterCipherConfig::Twofish,
        };
        config.inner_cipher_config = match template.inner_cipher {
            InnerCipher::Plain => InnerCipherConfig::Plain,
            InnerCipher::Salsa20 => InnerCipherConfig::Salsa20,
            InnerCipher::ChaCha20 => InnerCipherConfig::ChaCha20,
        };
        config.kdf_config = KdfConfig::Argon2id {
            iterations: template.kdf.iterations,
            memory: template.kdf.memory,
            parallelism: template.kdf.parallelism,
            version: argon2::Version::Version13,
        };
        Self {
            inner: keepass::Database::with_config(config),
        }
    }

    /// Add a new entry under the group identified by `path.groups`,
    /// with the title `path.title` and the field values from `draft`.
    /// Intermediate groups must already exist; create them first via
    /// `ensure_group` when introduced.
    pub fn add_entry(&mut self, path: EntryPath<'_>, draft: EntryDraft<'_>) -> Result<()> {
        if path.title.is_empty() || path.groups.iter().any(|g| g.is_empty()) {
            return Err(Error::InvalidPath);
        }
        let group_id = self.resolve_group_id(path.groups)?;
        let mut group = self.inner.group_mut(group_id).ok_or(Error::NotFound)?;
        let mut entry = group.add_entry();
        entry.set_unprotected(fields::TITLE, path.title);
        if let Some(u) = draft.username {
            entry.set_unprotected(fields::USERNAME, u);
        }
        if let Some(p) = draft.password {
            entry.set_protected(fields::PASSWORD, p);
        }
        if let Some(u) = draft.url {
            entry.set_unprotected(fields::URL, u);
        }
        if let Some(n) = draft.notes {
            entry.set_unprotected(fields::NOTES, n);
        }
        Ok(())
    }

    /// Edit a single field on an entry, recording the prior version
    /// of the entry into its `History`. Routes through upstream
    /// `EntryMut::edit_tracking`, which also stamps
    /// `times.last_modification`.
    pub fn set_entry_field(
        &mut self,
        path: EntryPath<'_>,
        field: EntryField<'_>,
        value: EntryFieldValue<'_>,
    ) -> Result<()> {
        let group_id = self.resolve_group_id(path.groups)?;
        let entry_id = self.resolve_entry_id(group_id, path.title)?;
        let mut entry = self.inner.entry_mut(entry_id).ok_or(Error::NotFound)?;
        let key: &str = match field {
            EntryField::Title => fields::TITLE,
            EntryField::Username => fields::USERNAME,
            EntryField::Password => fields::PASSWORD,
            EntryField::Url => fields::URL,
            EntryField::Notes => fields::NOTES,
            EntryField::Custom(k) => k,
        };
        entry.edit_tracking(|t| match value {
            EntryFieldValue::Plain(v) => t.set_unprotected(key, v),
            EntryFieldValue::Protected(v) => t.set_protected(key, v),
        });
        Ok(())
    }

    /// Remove the entry at `path`, registering its UUID in
    /// `deleted_objects` so KeePassXC sync will respect the deletion
    /// rather than resurrecting it on next merge.
    ///
    /// Routes through upstream `EntryTrack::remove`. The plain
    /// `EntryMut::remove` does not populate `deleted_objects`, which
    /// would silently break sync semantics — this wrapper hides that
    /// trap.
    pub fn remove_entry(&mut self, path: EntryPath<'_>) -> Result<()> {
        if path.title.is_empty() {
            return Err(Error::InvalidPath);
        }
        let group_id = self.resolve_group_id(path.groups)?;
        let entry_id = self.resolve_entry_id(group_id, path.title)?;
        let mut entry = self.inner.entry_mut(entry_id).ok_or(Error::NotFound)?;
        entry.track_changes().remove();
        Ok(())
    }

    /// Number of UUIDs in the database's `deleted_objects` registry.
    /// Tests use this to confirm `remove_entry` populated it.
    pub fn deleted_object_count(&self) -> usize {
        self.inner.deleted_objects.len()
    }

    /// Move the entry at `src` to the location described by `dst`.
    /// If `dst.title` differs from `src.title`, the entry is also
    /// renamed. The change is recorded in the entry's history.
    pub fn move_entry(&mut self, src: EntryPath<'_>, dst: EntryPath<'_>) -> Result<()> {
        if src.title.is_empty() || dst.title.is_empty() {
            return Err(Error::InvalidPath);
        }
        let src_group_id = self.resolve_group_id(src.groups)?;
        let entry_id = self.resolve_entry_id(src_group_id, src.title)?;
        let dst_group_id = self.resolve_group_id(dst.groups)?;
        let mut entry = self.inner.entry_mut(entry_id).ok_or(Error::NotFound)?;
        let mut tracker = entry.track_changes();
        if src_group_id != dst_group_id {
            tracker.move_to(dst_group_id).map_err(|_| Error::NotFound)?;
        }
        if !src.title.eq_ignore_ascii_case(dst.title) {
            tracker.set_unprotected(fields::TITLE, dst.title);
        }
        Ok(())
    }

    /// Replace the database's KDF configuration with Argon2id and the
    /// supplied parameters. The next `save` regenerates a fresh KDF
    /// salt (handled internally by upstream) so the on-disk file is
    /// re-derived end-to-end with the new params.
    pub fn set_kdf_params(&mut self, params: Argon2idParams) -> Result<()> {
        use keepass::config::KdfConfig;
        self.inner.config.kdf_config = KdfConfig::Argon2id {
            iterations: params.iterations,
            memory: params.memory,
            parallelism: params.parallelism,
            version: argon2::Version::Version13,
        };
        Ok(())
    }

    /// Ensure every group named in `path.segments` exists, creating
    /// any missing intermediate groups under the root. No-op when the
    /// full path already exists.
    pub fn ensure_group(&mut self, path: GroupPath<'_>) -> Result<()> {
        if path.segments.iter().any(|s| s.is_empty()) {
            return Err(Error::InvalidPath);
        }
        // Walk segment by segment. For each prefix, look up; if
        // missing, create under the parent prefix. O(n²) walks but
        // ensure_group depths are tiny in practice.
        for i in 1..=path.segments.len() {
            let prefix = &path.segments[..i];
            if self.resolve_group_id(prefix).is_ok() {
                continue;
            }
            let parent_id = self.resolve_group_id(&path.segments[..i - 1])?;
            let mut parent = self.inner.group_mut(parent_id).ok_or(Error::NotFound)?;
            let mut new_group = parent.add_group();
            new_group.name = path.segments[i - 1].to_string();
        }
        Ok(())
    }

    /// Walk the given group-name chain from the root and return the
    /// `GroupId` of the final group. Empty input returns the root id.
    /// Returns `Error::NotFound` if any segment misses.
    fn resolve_group_id(&self, segments: &[&str]) -> Result<keepass::db::GroupId> {
        if segments.is_empty() {
            return Ok(self.inner.root().id());
        }
        // `group_by_path` is on `GroupRef`, but `.id()` returns by
        // value so the temp-borrow chain is released immediately.
        Ok(self
            .inner
            .root()
            .group_by_path(segments)
            .ok_or(Error::NotFound)?
            .id())
    }

    /// Look up the `EntryId` of an entry directly under `group_id`
    /// matching `title` (case-insensitive). The borrow chain is
    /// released as soon as the id is read out.
    fn resolve_entry_id(
        &self,
        group_id: keepass::db::GroupId,
        title: &str,
    ) -> Result<keepass::db::EntryId> {
        self.inner
            .iter_all_entries()
            .find(|e| {
                e.parent().id() == group_id
                    && e.get(fields::TITLE)
                        .is_some_and(|t| t.eq_ignore_ascii_case(title))
            })
            .map(|e| e.id())
            .ok_or(Error::NotFound)
    }

    /// Key derivation function and its parameters.
    pub fn kdf(&self) -> Kdf {
        use keepass::config::KdfConfig as K;
        match &self.inner.config.kdf_config {
            K::Aes { rounds } => Kdf::Aes { rounds: *rounds },
            K::Argon2 {
                iterations,
                memory,
                parallelism,
                ..
            } => Kdf::Argon2d {
                iterations: *iterations,
                memory: *memory,
                parallelism: *parallelism,
            },
            K::Argon2id {
                iterations,
                memory,
                parallelism,
                ..
            } => Kdf::Argon2id {
                iterations: *iterations,
                memory: *memory,
                parallelism: *parallelism,
            },
            _ => Kdf::Argon2id {
                iterations: 0,
                memory: 0,
                parallelism: 0,
            },
        }
    }
}

/// Test-only constructor; not part of the stable surface. Audit tests
/// build a `keepass::Database` with weak settings and wrap it here to
/// avoid paying Argon2 cost via the file I/O path.
#[doc(hidden)]
impl Database {
    pub fn __from_keepass(inner: keepass::Database) -> Self {
        Self { inner }
    }
}

/// Read-only view of a single entry. Field accessors return `None` when
/// the field is unset; protected values are unprotected transparently.
pub struct Entry<'a> {
    inner: keepass::db::EntryRef<'a>,
}

impl Entry<'_> {
    pub fn title(&self) -> Option<&str> {
        self.inner.get(fields::TITLE)
    }

    pub fn username(&self) -> Option<&str> {
        self.inner.get(fields::USERNAME)
    }

    pub fn password(&self) -> Option<&str> {
        self.inner.get(fields::PASSWORD)
    }

    pub fn url(&self) -> Option<&str> {
        self.inner.get(fields::URL)
    }

    /// Expiration timestamp for this entry, or `None` if the entry is
    /// not flagged to expire (i.e. KeePass `Times.Expires == False`).
    /// KDBX timestamps are naive UTC at second precision.
    pub fn expires_at(&self) -> Option<chrono::NaiveDateTime> {
        if self.inner.times.expires != Some(true) {
            return None;
        }
        self.inner.times.expiry
    }

    /// Time of the most recent modification recorded for this entry, or
    /// `None` when the database does not record one. KDBX timestamps
    /// are naive UTC at second precision.
    pub fn last_modified_at(&self) -> Option<chrono::NaiveDateTime> {
        self.inner.times.last_modification
    }

    /// Number of historical (prior-version) entries recorded for this
    /// entry. Index 0 is the most recent prior version.
    pub fn history_count(&self) -> usize {
        self.inner
            .history
            .as_ref()
            .map(|h| h.get_entries().len())
            .unwrap_or(0)
    }

    /// Get a historical version of this entry. Index 0 is the most
    /// recent prior version. Returns `None` past the end of history.
    pub fn historical(&self, index: usize) -> Option<Entry<'_>> {
        self.inner.historical(index).map(|inner| Entry { inner })
    }

    /// Sizes (in bytes) of every binary attachment referenced by this
    /// entry. Names are not exposed here because the upstream public
    /// API only iterates attachments by id, not by (name, data).
    pub fn attachment_sizes(&self) -> impl Iterator<Item = usize> + '_ {
        self.inner.attachments().map(|a| a.data.get().len())
    }
}
