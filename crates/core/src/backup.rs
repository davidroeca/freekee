//! Backup and atomic-save helpers used by the rotation paths on
//! [`crate::Vault`]. The naming convention is part of the public
//! contract: backups land at `<path>.freekee-bak-<RFC3339-Z>` so
//! they sort lexicographically and survive Windows/Dropbox round-
//! trips (no colons in the filename).

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::error::Result;

/// Compute the backup path for `original` taken at `now`. Replaces
/// the colon between date and time fields with a hyphen so the path
/// is portable to Windows filesystems.
pub fn backup_path(original: &Path, now: DateTime<Utc>) -> PathBuf {
    let stamp = now.format("%Y-%m-%dT%H-%M-%SZ").to_string();
    let mut buf = original.as_os_str().to_owned();
    buf.push(format!(".freekee-bak-{stamp}"));
    PathBuf::from(buf)
}

/// Outcome of a save-with-backup call. Returned from rotation paths
/// so the CLI can tell the user where the backup landed (or that no
/// backup was written).
#[derive(Debug, Clone, Default)]
pub struct BackupOutcome {
    pub backup_path: Option<PathBuf>,
}

/// RAII handle for a backup file taken before a rotation. The
/// backup is **never auto-deleted** on drop — even after `commit()`
/// — because we can't tell whether the user wants to keep it. The
/// `committed` flag is informational, used by callers (e.g. the
/// rollback path) to decide whether the backup is still authoritative.
#[derive(Debug)]
pub struct BackupGuard {
    path: Option<PathBuf>,
    committed: bool,
}

impl BackupGuard {
    /// Copy `original` to `backup_path(original, now)` and return a
    /// guard owning the backup path. Errors from the copy bubble up
    /// as I/O errors; callers should abort the rotation in that case.
    pub fn create_for(original: &Path, now: DateTime<Utc>) -> Result<Self> {
        let backup = backup_path(original, now);
        fs::copy(original, &backup)?;
        Ok(Self {
            path: Some(backup),
            committed: false,
        })
    }

    /// Construct a no-op guard for `--no-backup` callers. The guard
    /// holds no path and `restore` is a no-op.
    pub fn skip() -> Self {
        Self {
            path: None,
            committed: false,
        }
    }

    /// Where the backup file lives. `None` for a `skip()` guard.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Mark the rotation as successful. The backup file is retained;
    /// this just records that no rollback will happen.
    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// True after `commit` has been called.
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// Move the backup back over `original`, undoing the most recent
    /// save. No-op for a `skip()` guard. After a successful restore,
    /// the guard's path is cleared so subsequent calls are no-ops.
    pub fn restore(&mut self, original: &Path) -> Result<()> {
        if let Some(backup) = self.path.take() {
            fs::rename(&backup, original)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn backup_path_uses_rfc3339_with_hyphen_for_colon() {
        let now = Utc.with_ymd_and_hms(2026, 4, 28, 12, 34, 56).unwrap();
        let p = backup_path(Path::new("/tmp/vault.kdbx"), now);
        assert_eq!(
            p,
            PathBuf::from("/tmp/vault.kdbx.freekee-bak-2026-04-28T12-34-56Z")
        );
    }

    #[test]
    fn backup_path_appends_to_basename_not_dirname() {
        let now = Utc.with_ymd_and_hms(2026, 4, 28, 0, 0, 0).unwrap();
        let p = backup_path(Path::new("/var/data/vault.kdbx"), now);
        assert_eq!(
            p,
            PathBuf::from("/var/data/vault.kdbx.freekee-bak-2026-04-28T00-00-00Z")
        );
    }

    #[test]
    fn backup_guard_skip_has_no_path() {
        let g = BackupGuard::skip();
        assert!(g.path().is_none());
    }

    #[test]
    fn backup_guard_create_copies_file_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let orig = tmp.path().join("v.kdbx");
        fs::write(&orig, b"original-bytes").unwrap();
        let g = BackupGuard::create_for(&orig, Utc::now()).unwrap();
        let backup = g.path().expect("backup path present");
        assert!(backup.exists());
        assert_eq!(fs::read(backup).unwrap(), b"original-bytes");
    }

    #[test]
    fn backup_guard_dropped_uncommitted_keeps_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let orig = tmp.path().join("v.kdbx");
        fs::write(&orig, b"x").unwrap();
        let backup_path = {
            let g = BackupGuard::create_for(&orig, Utc::now()).unwrap();
            let p = g.path().unwrap().to_path_buf();
            // `g` drops here without commit().
            p
        };
        assert!(
            backup_path.exists(),
            "backup file must remain after uncommitted Drop — \
             we can't tell whether the user wants to keep it"
        );
    }

    #[test]
    fn backup_guard_restore_moves_backup_back_over_original() {
        let tmp = tempfile::tempdir().unwrap();
        let orig = tmp.path().join("v.kdbx");
        fs::write(&orig, b"original").unwrap();
        let mut g = BackupGuard::create_for(&orig, Utc::now()).unwrap();
        // Simulate a failed save by overwriting the original.
        fs::write(&orig, b"corrupted-by-failed-save").unwrap();
        let backup_path = g.path().unwrap().to_path_buf();
        g.restore(&orig).unwrap();
        assert_eq!(fs::read(&orig).unwrap(), b"original");
        assert!(
            !backup_path.exists(),
            "restore moves the backup back into place; the backup file is consumed"
        );
        // Second restore is a no-op.
        g.restore(&orig).unwrap();
        assert_eq!(fs::read(&orig).unwrap(), b"original");
    }
}
