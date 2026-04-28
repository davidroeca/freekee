use std::path::PathBuf;
use std::process::ExitCode;

#[derive(clap::Args)]
pub struct Args {
    pub path: PathBuf,
    /// Path to a keyfile (in addition to the passphrase).
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;
    // `Database::open` performs the integrity check. If it returns Ok,
    // the file decrypted and the HMAC matched.
    let _db = kdbx::Database::open(&args.path, &pass, args.keyfile.as_deref())?;
    println!("OK");
    Ok(ExitCode::SUCCESS)
}
