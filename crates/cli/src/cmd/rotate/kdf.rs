//! `freekee rotate kdf` - switch the key derivation function from
//! AES-KDF to Argon2id. No-op when the database already uses Argon2id.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::{RotateOpts, Vault};

#[derive(clap::Args)]
pub struct Args {
    /// Path to the .kdbx file, or set $FREEKEE_DB.
    #[arg(long = "db", env = "FREEKEE_DB")]
    pub path: PathBuf,
    /// Skip the timestamped backup. The post-save verify always runs.
    #[arg(long)]
    pub no_backup: bool,
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = crate::cmd::read_passphrase(args.pass_stdin)?;
    let mut vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    let outcome = vault.rotate_kdf(RotateOpts {
        backup: !args.no_backup,
    })?;

    if outcome.changed {
        if let Some(ref path) = outcome.backup_path {
            println!("Rotated KDF to Argon2id. Backup at {}", path.display());
        } else {
            println!("Rotated KDF to Argon2id.");
        }
    } else {
        println!("Already using Argon2id; no change needed.");
    }
    Ok(ExitCode::SUCCESS)
}
