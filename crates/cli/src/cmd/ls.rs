//! `freekee ls` — list every entry in the database, sorted by full
//! group/title path. Optional substring filter narrows the output.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::Vault;

#[derive(clap::Args)]
pub struct Args {
    pub path: PathBuf,
    /// Optional case-insensitive substring; only entries whose full
    /// path contains it are listed.
    pub pattern: Option<String>,
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;
    let vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    let needle = args.pattern.as_deref().map(str::to_lowercase);

    let mut lines: Vec<String> = vault
        .db()
        .entries()
        .map(|e| {
            let title = e.title().unwrap_or("").to_owned();
            let mut full = e.group_path();
            full.push(title);
            full.join("/")
        })
        .filter(|full| {
            needle
                .as_ref()
                .is_none_or(|n| full.to_lowercase().contains(n))
        })
        .collect();
    lines.sort();
    for line in &lines {
        println!("{line}");
    }
    Ok(ExitCode::SUCCESS)
}
