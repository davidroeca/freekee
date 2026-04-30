//! `freekee rotate entry` — generate a fresh password for one entry,
//! save with backup+verify, and (optionally) echo the new value.
//!
//! `core::Vault::rotate_entry` deliberately does not return the
//! generated password (a leak surface); we read it back from the
//! parsed database when `--print-generated` is set.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::{Alphabet, PasswordPolicy, RotateOpts, Vault};
use kdbx::EntryPath;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum AlphabetChoice {
    Alpha,
    AlphaNum,
    AlphaNumSymbol,
}

impl From<AlphabetChoice> for Alphabet {
    fn from(c: AlphabetChoice) -> Self {
        match c {
            AlphabetChoice::Alpha => Alphabet::Alpha,
            AlphabetChoice::AlphaNum => Alphabet::AlphaNum,
            AlphabetChoice::AlphaNumSymbol => Alphabet::AlphaNumSymbol,
        }
    }
}

#[derive(clap::Args)]
pub struct Args {
    pub path: PathBuf,
    /// Slash-separated entry path.
    pub entry: String,
    /// Length of the generated password. Default: 24.
    #[arg(long)]
    pub length: Option<usize>,
    /// Alphabet to draw characters from. Default: alpha-num-symbol.
    #[arg(long, value_enum)]
    pub alphabet: Option<AlphabetChoice>,
    /// Skip the timestamped backup. The post-save verify always runs.
    #[arg(long)]
    pub no_backup: bool,
    /// Echo the new password to stdout. Off by default; the
    /// secret-leakage meta-test enforces silence without this flag.
    #[arg(long)]
    pub print_generated: bool,
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = crate::cmd::read_passphrase(args.pass_stdin)?;
    let mut vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    let segments = super::super::parse_entry_path(&args.entry)?;
    let mut scratch = Vec::new();
    let entry_path: EntryPath<'_> = super::super::entry_path_from(&segments, &mut scratch);

    let policy = PasswordPolicy {
        length: args.length.unwrap_or(PasswordPolicy::default().length),
        alphabet: args
            .alphabet
            .map(Alphabet::from)
            .unwrap_or(Alphabet::AlphaNumSymbol),
    };

    let outcome = vault.rotate_entry(
        entry_path,
        &policy,
        RotateOpts {
            backup: !args.no_backup,
        },
    )?;

    if args.print_generated {
        // Pull the new password back out of the in-memory db. We
        // never logged it to disk in plaintext outside of the KDBX
        // protected stream.
        if let Some(p) = vault
            .db()
            .entry_by_path(entry_path)
            .and_then(|e| e.password().map(str::to_owned))
        {
            println!("{p}");
        }
    } else {
        println!("Rotated entry {}.", args.entry);
    }
    if let Some(b) = outcome.backup_path {
        println!("Backup at {}", b.display());
    }
    Ok(ExitCode::SUCCESS)
}
