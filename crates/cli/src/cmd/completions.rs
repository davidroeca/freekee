//! `freekee completions <SHELL>` - emit a shell completion script for
//! `freekee` on stdout. The user pipes the output to wherever their
//! shell expects completions to live; see the README install snippets.

use std::process::ExitCode;

use clap::CommandFactory;
use clap_complete::Shell;

#[derive(clap::Args)]
pub struct Args {
    /// Target shell. Must be one of `bash`, `zsh`, `fish`, `elvish`,
    /// `powershell`.
    pub shell: Shell,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let mut cmd = crate::Cli::command();
    clap_complete::generate(args.shell, &mut cmd, "freekee", &mut std::io::stdout());
    Ok(ExitCode::SUCCESS)
}
