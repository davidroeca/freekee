//! `freekee get` - show one entry's fields. The password is omitted
//! by default. `--show` is the **only** subcommand allowed to surface
//! a stored entry password in stdout; the secret-leakage meta-test
//! enforces a carve-out specifically for that flag. `--clip` copies
//! the password to the clipboard without printing it.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::Vault;
use kdbx::EntryPath;

#[derive(clap::Args)]
pub struct Args {
    /// Path to the .kdbx file, or set $FREEKEE_DB.
    #[arg(long = "db", env = "FREEKEE_DB")]
    pub path: PathBuf,
    /// Slash-separated entry path (e.g. `Personal/email`).
    pub entry: String,
    /// Print the stored password to stdout. Off by default.
    #[arg(long)]
    pub show: bool,
    /// Copy the stored password to the clipboard. Off by default.
    /// May be combined with `--show` to both copy and print.
    #[arg(long)]
    pub clip: bool,
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

    let view = vault
        .get(entry_path)
        .ok_or_else(|| anyhow::anyhow!("entry not found: {}", args.entry))?;

    println!("Title:    {}", view.title.as_deref().unwrap_or(""));
    if let Some(u) = view.username.as_deref() {
        println!("Username: {u}");
    }
    if let Some(u) = view.url.as_deref() {
        println!("URL:      {u}");
    }
    if args.clip
        && let Some(p) = vault.get_password(entry_path)
    {
        let mut clipboard = arboard::Clipboard::new()
            .map_err(|e| anyhow::anyhow!("clipboard not available: {e}"))?;
        clipboard
            .set_text(p.as_str())
            .map_err(|e| anyhow::anyhow!("failed to copy to clipboard: {e}"))?;
        eprintln!("Copied to clipboard.");
    }
    if args.show {
        // Carve-out: the only path allowed to surface a password in stdout.
        if let Some(p) = vault.get_password(entry_path) {
            println!("Password: {}", p.as_str());
        }
    } else if !args.clip {
        println!("Password: <hidden - pass --show to reveal or --clip to copy>");
    }
    Ok(ExitCode::SUCCESS)
}
