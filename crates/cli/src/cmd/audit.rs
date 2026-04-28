use std::path::PathBuf;
use std::process::ExitCode;

use ::audit::{AuditConfig, CompositeKeyInfo, Finding, Severity};

#[derive(clap::Args)]
pub struct Args {
    pub path: PathBuf,
    /// Path to a keyfile (in addition to the passphrase).
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    /// Emit findings as a JSON array.
    #[arg(long)]
    pub json: bool,
    /// Exit non-zero if any finding has severity >= Medium.
    #[arg(long)]
    pub strict: bool,
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;
    let composite = if args.keyfile.is_some() {
        CompositeKeyInfo::HasExtraFactor
    } else {
        CompositeKeyInfo::PassphraseOnly
    };
    let db = kdbx::Database::open(&args.path, &pass, args.keyfile.as_deref())?;
    let findings = ::audit::run(&db, &pass, composite, &AuditConfig::default());

    if args.json {
        let buf = serde_json::to_string_pretty(&findings)?;
        println!("{buf}");
    } else {
        print_human(&findings);
    }

    if args.strict && findings.iter().any(|f| f.severity >= Severity::Medium) {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

fn print_human(findings: &[Finding]) {
    if findings.is_empty() {
        println!("no findings");
        return;
    }
    for f in findings {
        println!("[{:?}] {}", f.severity, f.rule);
        println!("  {}", f.message);
        println!("  Source: {}", f.citation);
        println!("  Fix:    {}", f.remediation);
    }
    println!("{} finding(s) total", findings.len());
}
