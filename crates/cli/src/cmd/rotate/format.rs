//! `freekee rotate format` - bring a database up to `keepass-rs`'s
//! current write target (today: KDBX 4). No-op when already at target.
//! Legacy KDF / inner cipher are preserved; chain `rotate kdf` and
//! `rotate cipher` afterward for full modernization.

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

    let outcome = vault.rotate_format(RotateOpts {
        backup: !args.no_backup,
    })?;

    if outcome.changed {
        if let Some(ref path) = outcome.backup_path {
            println!("Rotated format. Backup at {}", path.display());
        } else {
            println!("Rotated format.");
        }
    } else {
        println!("Already at current format; no change needed.");
    }
    Ok(ExitCode::SUCCESS)
}
