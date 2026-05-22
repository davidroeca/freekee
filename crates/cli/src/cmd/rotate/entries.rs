//! `freekee rotate entries` - bulk-regenerate passwords for entries
//! flagged by selected audit predicates (weak / stale / reused).
//!
//! No `--print-generated` flag: echoing N freshly-generated passwords
//! to stdout is too easy to leak. Users who want to inspect specific
//! rotated entries can run `freekee get --show <path>` per-entry after.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::{Alphabet, BulkRotateFilter, PasswordPolicy, RotateOpts, Vault};

use super::entry::AlphabetChoice;

#[derive(clap::Args)]
#[command(group(
    clap::ArgGroup::new("predicate")
        .required(true)
        .multiple(true)
        .args(["reused", "stale", "weak"]),
))]
pub struct Args {
    /// Path to the .kdbx file, or set $FREEKEE_DB.
    #[arg(long = "db", env = "FREEKEE_DB")]
    pub path: PathBuf,
    /// Rotate entries that share a password with at least one other entry.
    #[arg(long)]
    pub reused: bool,
    /// Rotate entries whose password is older than the audit threshold
    /// (default: 180 days).
    #[arg(long)]
    pub stale: bool,
    /// Rotate entries whose password strength is below the audit
    /// threshold (default: 50 bits).
    #[arg(long)]
    pub weak: bool,
    /// Length of each generated password. Default: 24.
    #[arg(long)]
    pub length: Option<usize>,
    /// Alphabet to draw characters from. Default: alpha-num-symbol.
    #[arg(long, value_enum)]
    pub alphabet: Option<AlphabetChoice>,
    /// Print the matching entry paths but do not modify the database.
    #[arg(long)]
    pub dry_run: bool,
    /// Skip the timestamped backup. The post-save verify always runs.
    #[arg(long)]
    pub no_backup: bool,
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    #[arg(long)]
    pub pass_stdin: bool,
    /// Overwrite the file even if it changed on disk since open.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = crate::cmd::read_passphrase(args.pass_stdin)?;
    let mut vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    let filter = BulkRotateFilter {
        reused: args.reused,
        stale: args.stale,
        weak: args.weak,
    };
    let policy = PasswordPolicy {
        length: args.length.unwrap_or(PasswordPolicy::default().length),
        alphabet: args
            .alphabet
            .map(Alphabet::from)
            .unwrap_or(Alphabet::AlphaNumSymbol),
    };

    if args.dry_run {
        let preview = vault.bulk_rotate_preview(&filter);
        if preview.is_empty() {
            println!("dry-run: no entries match the selected predicates.");
        } else {
            println!("dry-run: would rotate {} entry(ies):", preview.len());
            for path in &preview {
                println!("  {path}");
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    let (outcome, rotated) = vault.rotate_entries(
        &filter,
        &policy,
        RotateOpts {
            backup: !args.no_backup,
            force: args.force,
        },
    )?;

    if rotated.is_empty() {
        println!("No entries matched the selected predicates.");
    } else {
        println!("Rotated {} entry(ies):", rotated.len());
        for path in &rotated {
            println!("  {path}");
        }
        if let Some(b) = outcome.backup_path {
            println!("Backup at {}", b.display());
        }
    }
    Ok(ExitCode::SUCCESS)
}
