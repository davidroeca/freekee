//! `freekee mv` - relocate or rename an entry. Routes through
//! `Vault::move_entry`; same-group rename and cross-group move share
//! the same path.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::Vault;
use kdbx::EntryPath;

#[derive(clap::Args)]
pub struct Args {
    /// Path to the .kdbx file, or set $FREEKEE_DB.
    #[arg(long = "db", env = "FREEKEE_DB")]
    pub path: PathBuf,
    /// Source entry path (slash-separated).
    pub src: String,
    /// Destination entry path (slash-separated).
    pub dst: String,
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;
    let mut vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    let src_segments = super::parse_entry_path(&args.src)?;
    let dst_segments = super::parse_entry_path(&args.dst)?;
    let mut src_scratch = Vec::new();
    let mut dst_scratch = Vec::new();
    let src_path: EntryPath<'_> = super::entry_path_from(&src_segments, &mut src_scratch);
    let dst_path: EntryPath<'_> = super::entry_path_from(&dst_segments, &mut dst_scratch);

    vault.move_entry(src_path, dst_path)?;
    vault.save()?;
    Ok(ExitCode::SUCCESS)
}
