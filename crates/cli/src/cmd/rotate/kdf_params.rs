//! `freekee rotate kdf-params` - replace Argon2id parameters in
//! place. Memory is taken in MiB at the CLI; converted to bytes
//! before reaching `core` (KeePass stores memory in bytes).

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::{DEFAULT_TEMPLATE, RotateOpts, Vault};
use kdbx::Argon2idParams;

#[derive(clap::Args)]
pub struct Args {
    pub path: PathBuf,
    /// Argon2id memory in MiB. Defaults to the existing value.
    #[arg(long)]
    pub memory: Option<u64>,
    /// Argon2id iterations. Defaults to the existing value.
    #[arg(long)]
    pub iterations: Option<u64>,
    /// Argon2id parallelism. Defaults to the existing value.
    #[arg(long)]
    pub parallelism: Option<u32>,
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

    // Start from the current params so a single --memory bump doesn't
    // accidentally reset iterations/parallelism. Fall back to the
    // workspace-wide defaults if the file's KDF isn't Argon2id (the
    // audit rules already flag legacy-kdf, so this is best-effort).
    let current = match vault.db().kdf() {
        kdbx::Kdf::Argon2id {
            memory,
            iterations,
            parallelism,
        } => Argon2idParams {
            memory,
            iterations,
            parallelism,
        },
        _ => DEFAULT_TEMPLATE.kdf,
    };

    let next = Argon2idParams {
        memory: args
            .memory
            .map(|mib| mib.saturating_mul(1024 * 1024))
            .unwrap_or(current.memory),
        iterations: args.iterations.unwrap_or(current.iterations),
        parallelism: args.parallelism.unwrap_or(current.parallelism),
    };

    let outcome = vault.rotate_kdf_params(
        next,
        RotateOpts {
            backup: !args.no_backup,
        },
    )?;

    println!(
        "Rotated. Argon2id memory={} bytes, iterations={}, parallelism={}",
        next.memory, next.iterations, next.parallelism
    );
    if let Some(b) = outcome.backup_path {
        println!("Backup at {}", b.display());
    }
    Ok(ExitCode::SUCCESS)
}
