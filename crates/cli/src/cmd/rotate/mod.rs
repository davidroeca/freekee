//! `freekee rotate <subcommand>` - credential and parameter rotations.
//! Each subcommand routes through `core::Vault::rotate_*`, which runs
//! the shared backup / save / verify / rollback tail.

pub mod cipher;
pub mod entry;
pub mod kdf;
pub mod kdf_params;
pub mod keyfile;
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
    /// Switch the key derivation function to Argon2id.
    Kdf(kdf::Args),
    /// Generate a fresh password for an entry.
    Entry(entry::Args),
    /// Add, replace, or remove the keyfile composite.
    Keyfile(keyfile::Args),
    /// Change the outer and/or inner cipher.
    Cipher(cipher::Args),
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    match args.which {
        RotateCmd::Passphrase(a) => passphrase::run(a),
        RotateCmd::KdfParams(a) => kdf_params::run(a),
        RotateCmd::Kdf(a) => kdf::run(a),
        RotateCmd::Entry(a) => entry::run(a),
        RotateCmd::Keyfile(a) => keyfile::run(a),
        RotateCmd::Cipher(a) => cipher::run(a),
    }
}
