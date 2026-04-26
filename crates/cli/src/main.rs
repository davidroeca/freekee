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
    /// Print metadata: KDBX version, cipher, KDF, entry counts.
    Info(cmd::info::Args),
    /// Decrypt and integrity-check the database. Prints OK or an error class.
    Verify(cmd::verify::Args),
    /// Run audit rules and print findings.
    Audit(cmd::audit::Args),
}

fn main() -> ExitCode {
    use clap::Parser;

    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Info(args) => cmd::info::run(args),
        Cmd::Verify(args) => cmd::verify::run(args),
        Cmd::Audit(args) => cmd::audit::run(args),
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
