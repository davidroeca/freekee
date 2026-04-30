//! `freekee rotate passphrase` — change the master passphrase.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::{RotateOpts, Vault};

#[derive(clap::Args)]
pub struct Args {
    pub path: PathBuf,
    /// Skip the timestamped backup. The post-save verify always runs.
    #[arg(long)]
    pub no_backup: bool,
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    /// Read the *current* passphrase from the first line of stdin.
    #[arg(long)]
    pub pass_stdin: bool,
    /// Read the *new* passphrase from the next line of stdin.
    #[arg(long)]
    pub new_pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = crate::cmd::read_passphrase(args.pass_stdin)?;
    let new_pass = crate::cmd::read_new_passphrase(args.new_pass_stdin)?;
    let mut vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    let outcome = vault.rotate_passphrase(
        new_pass,
        RotateOpts {
            backup: !args.no_backup,
        },
    )?;

    if let Some(b) = outcome.backup_path {
        println!("Rotated. Backup at {}", b.display());
    } else {
        println!("Rotated.");
    }
    Ok(ExitCode::SUCCESS)
}
