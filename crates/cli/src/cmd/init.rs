//! `freekee init` - create a new KDBX file. Defaults match
//! `core::DEFAULT_TEMPLATE` (AES-256 outer, ChaCha20 inner, Argon2id
//! 64 MiB / 10 iterations / 2 parallelism).

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::{DEFAULT_TEMPLATE, Vault, tune_argon2id};

/// Default `--target-ms` for `--tune`. Matches KeePassXC's benchmark
/// slider default.
const DEFAULT_TUNE_TARGET_MS: u32 = 1000;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum CipherChoice {
    Aes256,
    ChaCha20,
}

#[derive(clap::Args)]
pub struct Args {
    /// Path where the new KDBX file should be written.
    pub path: PathBuf,
    /// Argon2id memory cost in MiB. CLI takes MiB; converted to bytes
    /// before reaching `core` (KeePass stores memory in bytes).
    #[arg(long, conflicts_with = "tune")]
    pub memory: Option<u64>,
    /// Argon2id time cost (iterations).
    #[arg(long, conflicts_with = "tune")]
    pub iterations: Option<u64>,
    /// Argon2id parallelism (lanes).
    #[arg(long, conflicts_with = "tune")]
    pub parallelism: Option<u32>,
    /// Benchmark this host and pick Argon2id iterations so a full
    /// derivation takes approximately `--target-ms`. Memory is held
    /// at 64 MiB and parallelism at min(host CPUs, 4). Mutually
    /// exclusive with `--memory`/`--iterations`/`--parallelism`.
    #[arg(long)]
    pub tune: bool,
    /// Target derivation time in milliseconds for `--tune` (default 1000).
    #[arg(long, requires = "tune")]
    pub target_ms: Option<u32>,
    /// Outer (file-level) cipher.
    #[arg(long, value_enum)]
    pub cipher: Option<CipherChoice>,
    /// Optional keyfile to bind alongside the passphrase. The vault
    /// will require both to reopen.
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    /// Overwrite the destination if it already exists.
    #[arg(long)]
    pub force: bool,
    /// Read passphrase from the first line of stdin.
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;

    let mut template = DEFAULT_TEMPLATE;
    if args.tune {
        template.kdf = tune_argon2id(args.target_ms.unwrap_or(DEFAULT_TUNE_TARGET_MS));
    } else {
        if let Some(mib) = args.memory {
            // CLI argument is MiB; KDBX stores memory in bytes. Saturate
            // on overflow rather than wrap (a 64-bit-MiB value has no
            // physical meaning here).
            template.kdf.memory = mib.saturating_mul(1024 * 1024);
        }
        if let Some(it) = args.iterations {
            template.kdf.iterations = it;
        }
        if let Some(par) = args.parallelism {
            template.kdf.parallelism = par;
        }
    }
    if let Some(c) = args.cipher {
        template.outer_cipher = match c {
            CipherChoice::Aes256 => kdbx::OuterCipher::Aes256,
            CipherChoice::ChaCha20 => kdbx::OuterCipher::ChaCha20,
        };
    }

    let _vault = Vault::create(
        &args.path,
        pass,
        args.keyfile.as_deref(),
        template,
        args.force,
    )?;
    println!("Initialized {}", args.path.display());
    Ok(ExitCode::SUCCESS)
}
