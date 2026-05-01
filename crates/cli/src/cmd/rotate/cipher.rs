//! `freekee rotate cipher` - change the outer and/or inner cipher.
//! At least one of `--to` or `--inner` must be specified.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::{RotateOpts, Vault};
use kdbx::{InnerCipher, OuterCipher};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum OuterCipherChoice {
    Aes256,
    ChaCha20,
    Twofish,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum InnerCipherChoice {
    ChaCha20,
}

#[derive(clap::Args)]
pub struct Args {
    /// Path to the .kdbx file, or set $FREEKEE_DB.
    #[arg(long = "db", env = "FREEKEE_DB")]
    pub path: PathBuf,
    /// Target outer (file-level) cipher.
    #[arg(long, value_enum)]
    pub to: Option<OuterCipherChoice>,
    /// Target inner (protected-field) cipher. Only ChaCha20 is
    /// offered; Salsa20 is a downgrade target.
    #[arg(long, value_enum)]
    pub inner: Option<InnerCipherChoice>,
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

    let outer: Option<OuterCipher> = args.to.map(|c| match c {
        OuterCipherChoice::Aes256 => OuterCipher::Aes256,
        OuterCipherChoice::ChaCha20 => OuterCipher::ChaCha20,
        OuterCipherChoice::Twofish => OuterCipher::Twofish,
    });
    let inner: Option<InnerCipher> = args.inner.map(|_| InnerCipher::ChaCha20);

    let outcome = vault.rotate_cipher(
        outer,
        inner,
        RotateOpts {
            backup: !args.no_backup,
        },
    )?;

    if let Some(b) = outcome.backup_path {
        println!("Rotated cipher. Backup at {}", b.display());
    } else {
        println!("Rotated cipher.");
    }
    Ok(ExitCode::SUCCESS)
}
