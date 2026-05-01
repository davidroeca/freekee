//! `freekee rotate <subcommand>` - credential and parameter rotations.
//! Each subcommand routes through `core::Vault::rotate_*`, which runs
//! the shared backup / save / verify / rollback tail.

pub mod entry;
pub mod kdf_params;
pub mod passphrase;

use std::process::ExitCode;

#[derive(clap::Args)]
pub struct Args {
    #[command(subcommand)]
    pub which: RotateCmd,
}

#[derive(clap::Subcommand)]
pub enum RotateCmd {
    /// Re-encrypt the file under a new master passphrase.
    Passphrase(passphrase::Args),
    /// Replace the database's Argon2id parameters.
    KdfParams(kdf_params::Args),
    /// Generate a fresh password for an entry.
    Entry(entry::Args),
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    match args.which {
        RotateCmd::Passphrase(a) => passphrase::run(a),
        RotateCmd::KdfParams(a) => kdf_params::run(a),
        RotateCmd::Entry(a) => entry::run(a),
    }
}
