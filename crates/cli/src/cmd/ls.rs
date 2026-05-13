//! `freekee ls` - list every entry in the database, sorted by full
//! group/title path. Optional substring filter narrows the output.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::{ListFilter, Vault};

#[derive(clap::Args)]
pub struct Args {
    /// Path to the .kdbx file, or set $FREEKEE_DB.
    #[arg(long = "db", env = "FREEKEE_DB")]
    pub path: PathBuf,
    /// Optional case-insensitive substring; only entries whose full
    /// `<group>/<title>` path contains it are listed.
    pub pattern: Option<String>,
    /// Narrow output to entries whose username contains this
    /// case-insensitive substring. AND-combined with other filters.
    #[arg(long)]
    pub username: Option<String>,
    /// Narrow output to entries whose URL contains this
    /// case-insensitive substring. AND-combined with other filters.
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;
    let vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    let filter = ListFilter {
        path: args.pattern.as_deref(),
        username: args.username.as_deref(),
        url: args.url.as_deref(),
    };
    for line in vault.list(&filter) {
        println!("{line}");
    }
    Ok(ExitCode::SUCCESS)
}
