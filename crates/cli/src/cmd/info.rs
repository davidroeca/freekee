use std::path::PathBuf;
use std::process::ExitCode;

use kdbx::{KdbxVersion, Kdf, OuterCipher};

#[derive(clap::Args)]
pub struct Args {
    /// Path to the .kdbx file.
    pub path: PathBuf,
    /// Path to a keyfile (in addition to the passphrase).
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    /// Read passphrase from the first line of stdin.
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;
    let db = kdbx::Database::open(&args.path, &pass, args.keyfile.as_deref())?;

    let version = match db.kdbx_version() {
        KdbxVersion::Kdb1 => "KDBX 1".to_string(),
        KdbxVersion::Kdb2(m) => format!("KDBX 2.{m}"),
        KdbxVersion::Kdb3(m) => format!("KDBX 3.{m}"),
        KdbxVersion::Kdb4(m) => format!("KDBX 4.{m}"),
    };
    let outer = match db.outer_cipher() {
        OuterCipher::Aes256 => "AES-256",
        OuterCipher::Twofish => "Twofish",
        OuterCipher::ChaCha20 => "ChaCha20",
    };
    let kdf = match db.kdf() {
        Kdf::Aes { rounds } => format!("AES-KDF (rounds={rounds})"),
        Kdf::Argon2d {
            iterations,
            memory,
            parallelism,
        } => format!(
            "Argon2d (memory={memory} bytes, iterations={iterations}, parallelism={parallelism})"
        ),
        Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } => format!(
            "Argon2id (memory={memory} bytes, iterations={iterations}, parallelism={parallelism})"
        ),
    };

    println!("Version: {version}");
    println!("Outer cipher: {outer}");
    println!("KDF: {kdf}");
    println!("Root entries: {}", db.root_entry_count());
    println!("Root subgroups: {}", db.root_subgroup_count());
    Ok(ExitCode::SUCCESS)
}
