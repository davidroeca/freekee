//! Lightweight value types used by the mutation surface on
//! [`crate::Database`]. Kept in their own module so the wrapper's
//! method signatures stay readable and so callers can construct paths
//! and drafts without pulling in the upstream `keepass` types.

/// Identifies an entry by its position in the group hierarchy plus its
/// title. `groups` is the chain of group names from the root down to
/// the entry's parent (empty when the entry sits directly under root).
///
/// Titles and group names are matched case-insensitively, matching
/// upstream `keepass-rs` lookup semantics.
#[derive(Debug, Clone, Copy)]
pub struct EntryPath<'a> {
    pub groups: &'a [&'a str],
    pub title: &'a str,
}

/// Identifies a group by its chain of group names from the root.
/// Empty segments mean "the root group itself."
#[derive(Debug, Clone, Copy)]
pub struct GroupPath<'a> {
    pub segments: &'a [&'a str],
}

/// Identifies which field on an entry is being read or written.
/// Standard fields use the upstream KeePass keys; `Custom` carries
/// the literal field name for non-standard fields.
#[derive(Debug, Clone, Copy)]
pub enum EntryField<'a> {
    Title,
    Username,
    Password,
    Url,
    Notes,
    Custom(&'a str),
}

/// A value supplied to a field, marked as either plaintext or
/// protected (i.e. encrypted under the inner stream cipher inside
/// the KDBX file).
#[derive(Debug, Clone, Copy)]
pub enum EntryFieldValue<'a> {
    Plain(&'a str),
    Protected(&'a str),
}

/// Field values supplied when adding or upserting an entry. The entry
/// title is taken from [`EntryPath::title`] so the two cannot diverge.
/// All fields are optional; unset fields are not written.
#[derive(Debug, Default, Clone, Copy)]
pub struct EntryDraft<'a> {
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub url: Option<&'a str>,
    pub notes: Option<&'a str>,
}

/// Argon2id KDF parameters. `memory` is in bytes (matching the
/// upstream `keepass` representation); typical KeePass values are in
/// the range 64 MiB and up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idParams {
    pub memory: u64,
    pub iterations: u64,
    pub parallelism: u32,
}

/// Configuration applied to a freshly-created database via
/// [`crate::Database::new_empty`].
#[derive(Debug, Clone, Copy)]
pub struct NewDatabaseTemplate {
    pub kdf: Argon2idParams,
    pub outer_cipher: crate::OuterCipher,
    pub inner_cipher: crate::InnerCipher,
}
