//! `freekee` CLI entry point. Read-only command surface for milestone 0.

use std::process::ExitCode;

mod cmd;

#[derive(clap::Parser)]
#[command(name = "freekee", version, about = "KDBX4 password manager")]
pub(crate) struct Cli {
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
    /// Interactively walk audit findings and apply accepted remediations.
    Fix(cmd::fix::Args),
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
    /// Emit a shell completion script for the given shell to stdout.
    Completions(cmd::completions::Args),
}

fn main() -> ExitCode {
    use clap::Parser;

    // Resolve the default database path from the config file before
    // clap parses, so the `#[arg(env = "FREEKEE_DB")]` fallback on each
    // subcommand picks it up. Precedence: CLI arg > $FREEKEE_DB > config.
    // We never overwrite an existing $FREEKEE_DB (the env var wins).
    if std::env::var_os("FREEKEE_DB").is_none()
        && let Some(cfg_path) = freekee_core::Config::default_path()
    {
        match freekee_core::Config::load(&cfg_path) {
            Ok(cfg) => {
                if let Some(db) = cfg.default_db {
                    // SAFETY: this runs before clap parsing and before
                    // any thread spawn, so no other code can be
                    // reading the environment concurrently. `set_var`
                    // is only unsound under concurrent access; the
                    // single-threaded prologue here satisfies its
                    // safety contract.
                    #[allow(unsafe_code)]
                    unsafe {
                        std::env::set_var("FREEKEE_DB", db);
                    }
                }
            }
            Err(e) => {
                eprintln!("freekee: {e}");
                return ExitCode::from(2);
            }
        }
    }

    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Init(args) => cmd::init::run(args),
        Cmd::Info(args) => cmd::info::run(args),
        Cmd::Verify(args) => cmd::verify::run(args),
        Cmd::Audit(args) => cmd::audit::run(args),
        Cmd::Fix(args) => cmd::fix::run(args),
        Cmd::Ls(args) => cmd::ls::run(args),
        Cmd::Get(args) => cmd::get::run(args),
        Cmd::History(args) => cmd::history::run(args),
        Cmd::Set(args) => cmd::set::run(args),
        Cmd::Rm(args) => cmd::rm::run(args),
        Cmd::Mv(args) => cmd::mv::run(args),
        Cmd::Rotate(args) => cmd::rotate::run(args),
        Cmd::Completions(args) => cmd::completions::run(args),
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
