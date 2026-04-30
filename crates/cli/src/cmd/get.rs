//! `freekee get` — show one entry's fields. The password is omitted
//! by default. `--show` is the **only** subcommand allowed to surface
//! a stored entry password; the secret-leakage meta-test enforces a
//! carve-out specifically for that flag.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::Vault;
use kdbx::EntryPath;

#[derive(clap::Args)]
pub struct Args {
    pub path: PathBuf,
    /// Slash-separated entry path (e.g. `Personal/email`).
    pub entry: String,
    /// Print the stored password to stdout. Off by default.
    #[arg(long)]
    pub show: bool,
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

    let entry = vault
        .db()
        .entry_by_path(entry_path)
        .ok_or_else(|| anyhow::anyhow!("entry not found: {}", args.entry))?;

    println!("Title:    {}", entry.title().unwrap_or(""));
    if let Some(u) = entry.username() {
        println!("Username: {u}");
    }
    if let Some(u) = entry.url() {
        println!("URL:      {u}");
    }
    if args.show {
        // Carve-out: the only path allowed to surface a password.
        if let Some(p) = entry.password() {
            println!("Password: {p}");
        }
    } else {
        println!("Password: <hidden — pass --show to reveal>");
    }
    Ok(ExitCode::SUCCESS)
}
