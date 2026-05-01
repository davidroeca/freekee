//! `freekee rm` - delete an entry. Routes through `Vault::remove_entry`,
//! which registers the UUID in `deleted_objects` so KeePassXC sync
//! respects the deletion rather than resurrecting it on next merge.

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
    let mut vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    let segments = super::parse_entry_path(&args.entry)?;
    let mut scratch = Vec::new();
    let entry_path: EntryPath<'_> = super::entry_path_from(&segments, &mut scratch);

    vault.remove_entry(entry_path)?;
    vault.save()?;
    Ok(ExitCode::SUCCESS)
}
