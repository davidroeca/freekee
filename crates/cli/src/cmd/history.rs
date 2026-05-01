//! `freekee history` - show how many prior versions exist for an
//! entry, plus the modification timestamp recorded on each one.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::Vault;
use kdbx::EntryPath;

#[derive(clap::Args)]
pub struct Args {
    pub path: PathBuf,
    /// Slash-separated entry path.
    pub entry: String,
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;
    let vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    let segments = super::parse_entry_path(&args.entry)?;
    let mut scratch = Vec::new();
    let entry_path: EntryPath<'_> = super::entry_path_from(&segments, &mut scratch);

    let hv = vault
        .history(entry_path)
        .ok_or_else(|| anyhow::anyhow!("entry not found: {}", args.entry))?;

    println!("history: {}", hv.count);
    for (i, ts) in hv.timestamps.iter().enumerate() {
        let modified = ts
            .map(|t| t.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        println!("  {i}: modified {modified}");
    }
    Ok(ExitCode::SUCCESS)
}
