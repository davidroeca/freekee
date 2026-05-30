use std::path::PathBuf;
use std::process::ExitCode;

use ::audit::{AuditConfig, CompositeKeyInfo, Finding, Severity};

#[derive(clap::Args)]
pub struct Args {
    /// Path to the .kdbx file, or set $FREEKEE_DB.
    #[arg(long = "db", env = "FREEKEE_DB")]
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
    /// Check entry passwords against Have I Been Pwned (k-anonymity:
    /// only the first 5 chars of each password's SHA-1 hash are sent).
    /// Opt-in; off by default. Requires network access.
    #[arg(long)]
    pub hibp: bool,
    #[arg(long)]
    pub pass_stdin: bool,
}

/// HIBP range API base. Overridable so tests can target a local stub.
const HIBP_DEFAULT_BASE_URL: &str = "https://api.pwnedpasswords.com";

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;
    let composite = if args.keyfile.is_some() {
        CompositeKeyInfo::HasExtraFactor
    } else {
        CompositeKeyInfo::PassphraseOnly
    };
    let db = kdbx::Database::open(&args.path, &pass, args.keyfile.as_deref())?;
    let mut findings = ::audit::run(&db, &pass, composite, &AuditConfig::default());

    if args.hibp {
        let base = std::env::var("FREEKEE_HIBP_BASE_URL")
            .unwrap_or_else(|_| HIBP_DEFAULT_BASE_URL.to_owned());
        let client = freekee_core::HttpRangeClient::new(base);
        findings.extend(freekee_core::breached_passwords(&db, &client)?);
    }

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
