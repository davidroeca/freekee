//! `freekee ls` - list every entry in the database, sorted by full
//! group/title path. Optional substring filter narrows the output.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::Vault;

#[derive(clap::Args)]
pub struct Args {
    pub path: PathBuf,
    /// Optional case-insensitive substring; only entries whose full
    /// path contains it are listed.
    pub pattern: Option<String>,
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;
    let vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    for line in vault.list(args.pattern.as_deref()) {
        println!("{line}");
    }
    Ok(ExitCode::SUCCESS)
}
