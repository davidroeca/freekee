//! `freekee rotate keyfile` - add, replace, or remove the keyfile
//! component of a vault's composite credential. The vault is opened
//! with the **current** credential (passphrase + existing keyfile, via
//! the global `--keyfile` flag); the **new** keyfile is supplied via
//! `--new-keyfile`, and `--remove` drops the keyfile entirely. The two
//! are mutually exclusive.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::{RotateOpts, Vault};

#[derive(clap::Args)]
pub struct Args {
    /// Path to the .kdbx file, or set $FREEKEE_DB.
    #[arg(long = "db", env = "FREEKEE_DB")]
    pub path: PathBuf,
    /// New keyfile to bind to the vault. Mutually exclusive with
    /// `--remove`.
    #[arg(long, conflicts_with = "remove")]
    pub new_keyfile: Option<PathBuf>,
    /// Drop the existing keyfile so the vault is passphrase-only.
    /// Mutually exclusive with `--new-keyfile`.
    #[arg(long)]
    pub remove: bool,
    /// Skip the timestamped backup. The post-save verify always runs.
    #[arg(long)]
    pub no_backup: bool,
    /// Current keyfile required to open the vault (if any).
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    if args.new_keyfile.is_none() && !args.remove {
        anyhow::bail!("pass --new-keyfile <PATH> to add/replace, or --remove to drop");
    }

    let pass = crate::cmd::read_passphrase(args.pass_stdin)?;
    let mut vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    let new_keyfile: Option<&std::path::Path> = if args.remove {
        None
    } else {
        args.new_keyfile.as_deref()
    };

    let outcome = vault.rotate_keyfile(
        new_keyfile,
        RotateOpts {
            backup: !args.no_backup,
        },
    )?;

    if args.remove {
        println!("Rotated. Keyfile removed.");
    } else {
        println!(
            "Rotated. Keyfile bound to {}",
            new_keyfile
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        );
    }
    if let Some(b) = outcome.backup_path {
        println!("Backup at {}", b.display());
    }
    Ok(ExitCode::SUCCESS)
}
