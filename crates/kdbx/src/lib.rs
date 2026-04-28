//! KDBX4 file I/O wrapper around the `keepass` crate.
//!
//! Insulates the rest of the workspace from upstream churn per
//! `docs/design.md` §6. The surface here grows test-by-test under the
//! milestone-0 TDD plan.

mod error;
pub mod snapshot;

pub use error::{Error, Result};

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
    /// Open a KDBX file with a passphrase.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let mut file = File::open(path)?;
        let key = DatabaseKey::new().with_password(password);
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

    /// Sizes (in bytes) of every binary attachment referenced by this
    /// entry. Names are not exposed here because the upstream public
    /// API only iterates attachments by id, not by (name, data).
    pub fn attachment_sizes(&self) -> impl Iterator<Item = usize> + '_ {
        self.inner.attachments().map(|a| a.data.get().len())
    }
}
