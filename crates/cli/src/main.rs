//! `freekee` CLI entry point. Read-only command surface for milestone 0.

use std::process::ExitCode;

mod cmd;

#[derive(clap::Parser)]
#[command(name = "freekee", version, about = "KDBX4 password manager")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
    /// Create a new KDBX file.
    Init(cmd::init::Args),
    /// Print metadata: KDBX version, cipher, KDF, entry counts.
    Info(cmd::info::Args),
    /// Decrypt and integrity-check the database. Prints OK or an error class.
    Verify(cmd::verify::Args),
    /// Run audit rules and print findings.
    Audit(cmd::audit::Args),
    /// List entries by full group/title path.
    Ls(cmd::ls::Args),
    /// Show one entry's fields (password hidden unless --show).
    Get(cmd::get::Args),
    /// Show how many prior versions an entry has.
    History(cmd::history::Args),
    /// Create or update entry fields.
    Set(cmd::set::Args),
    /// Delete an entry (records a tombstone for sync).
    Rm(cmd::rm::Args),
    /// Relocate or rename an entry.
    Mv(cmd::mv::Args),
    /// Credential and parameter rotations.
    Rotate(cmd::rotate::Args),
}

fn main() -> ExitCode {
    use clap::Parser;

    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Init(args) => cmd::init::run(args),
        Cmd::Info(args) => cmd::info::run(args),
        Cmd::Verify(args) => cmd::verify::run(args),
        Cmd::Audit(args) => cmd::audit::run(args),
        Cmd::Ls(args) => cmd::ls::run(args),
        Cmd::Get(args) => cmd::get::run(args),
        Cmd::History(args) => cmd::history::run(args),
        Cmd::Set(args) => cmd::set::run(args),
        Cmd::Rm(args) => cmd::rm::run(args),
        Cmd::Mv(args) => cmd::mv::run(args),
        Cmd::Rotate(args) => cmd::rotate::run(args),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            // Display only the error class. `kdbx::Error` Display strings
            // are intentionally non-secret; do not embed any user input
            // here.
            eprintln!("freekee: {e}");
            ExitCode::from(2)
        }
    }
}
