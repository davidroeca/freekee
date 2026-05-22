//! `freekee fix` - walk audit findings, prompt per-finding, apply
//! accepted remediations in a single batched save at the end.
//!
//! This command is interactive by design. Use `freekee audit --json`
//! for machine-readable findings; use the `rotate` family for non-
//! interactive bulk operations (`rotate entries --reused/--stale/--weak`,
//! `rotate {cipher,kdf,kdf-params,format,keyfile,passphrase}`).

use std::io::BufRead;
use std::path::PathBuf;
use std::process::ExitCode;

use ::audit::{AuditConfig, CompositeKeyInfo, Finding};
use chrono::Timelike;
use freekee_core::{Alphabet, FixIntent, PasswordPolicy, RotateOpts, Vault};

use super::rotate::entry::AlphabetChoice;

#[derive(clap::Args)]
pub struct Args {
    /// Path to the .kdbx file, or set $FREEKEE_DB.
    #[arg(long = "db", env = "FREEKEE_DB")]
    pub path: PathBuf,
    /// Path to a keyfile (in addition to the passphrase).
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    /// Read passphrase from the first line of stdin. Subsequent stdin
    /// lines feed the per-finding y/N/q prompts.
    #[arg(long)]
    pub pass_stdin: bool,
    /// Length of every regenerated entry password. Default: 24.
    #[arg(long)]
    pub length: Option<usize>,
    /// Alphabet for regenerated entry passwords. Default: alpha-num-symbol.
    #[arg(long, value_enum)]
    pub alphabet: Option<AlphabetChoice>,
    /// Days from now to extend `expired-entry-overdue` entries forward.
    /// Default: 90. Must be >= 1.
    #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(i64).range(1..))]
    pub extend_expiry_days: i64,
    /// Skip the timestamped backup. The post-save verify always runs.
    #[arg(long)]
    pub no_backup: bool,
    /// Overwrite the file even if it changed on disk since open.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;
    let composite = if args.keyfile.is_some() {
        CompositeKeyInfo::HasExtraFactor
    } else {
        CompositeKeyInfo::PassphraseOnly
    };

    let mut vault = Vault::open(&args.path, pass.clone(), args.keyfile.as_deref())?;
    let db = kdbx::Database::open(&args.path, &pass, args.keyfile.as_deref())?;
    let findings = ::audit::run(&db, &pass, composite, &AuditConfig::default());
    drop(db);

    let in_scope: Vec<&Finding> = findings.iter().filter(|f| in_scope(f)).collect();
    if in_scope.is_empty() {
        println!("No in-scope findings to remediate.");
        return Ok(ExitCode::SUCCESS);
    }

    let policy = PasswordPolicy {
        length: args.length.unwrap_or(PasswordPolicy::default().length),
        alphabet: args
            .alphabet
            .map(Alphabet::from)
            .unwrap_or(Alphabet::AlphaNumSymbol),
    };
    let extension_target =
        chrono::Utc::now().naive_utc() + chrono::Duration::days(args.extend_expiry_days);
    // KDBX timestamps have second precision; truncate so a later
    // reopen reads exactly what we wrote.
    let extension_target = extension_target
        .with_nanosecond(0)
        .unwrap_or(extension_target);

    let mut intents: Vec<FixIntent> = Vec::new();
    let mut prompt_lines = StdinLines::new();
    for f in &in_scope {
        print_finding(f);
        match prompt_apply(&mut prompt_lines)? {
            ApplyChoice::Yes => match build_intent(f, &policy, extension_target) {
                Some(intent) => intents.push(intent),
                None => {
                    eprintln!("(internal) cannot build fix intent for this finding; skipping");
                }
            },
            ApplyChoice::No => {}
            ApplyChoice::Quit => {
                println!(
                    "Stopping prompt phase; applying {} accepted fix(es).",
                    intents.len()
                );
                break;
            }
        }
    }

    if intents.is_empty() {
        println!("No fixes accepted; nothing to apply.");
        return Ok(ExitCode::SUCCESS);
    }

    println!("Apply {} fix(es)?", intents.len());
    let confirmed = prompt_yes_no_line(&mut prompt_lines, "Confirm")?;
    if !confirmed {
        println!("Cancelled; nothing applied.");
        return Ok(ExitCode::SUCCESS);
    }

    let report = vault.apply_fix_batch(
        intents,
        RotateOpts {
            backup: !args.no_backup,
            force: args.force,
        },
    )?;
    for line in &report.applied {
        println!("  {line}");
    }
    if let Some(b) = report.outcome.backup_path {
        println!("Backup at {}", b.display());
    }
    Ok(ExitCode::SUCCESS)
}

fn in_scope(f: &Finding) -> bool {
    matches!(
        f.rule,
        "weak-entry-password"
            | "reused-password"
            | "stale-password"
            | "expired-entry-overdue"
            | "weak-outer-cipher"
            | "legacy-stream-cipher"
            | "legacy-kdf"
            | "weak-argon2-params"
            | "legacy-kdbx-version"
    )
}

fn print_finding(f: &Finding) {
    println!("[{:?}] {}", f.severity, f.rule);
    println!("  {}", f.message);
}

#[derive(Debug, Clone, Copy)]
enum ApplyChoice {
    Yes,
    No,
    Quit,
}

/// Read a single y/n/q response (case-insensitive) from `lines`. EOF
/// counts as `No`, matching how non-interactive callers (and `Ctrl-D`)
/// behave. Anything we don't recognize re-prompts up to a small bound.
fn prompt_apply(lines: &mut StdinLines) -> anyhow::Result<ApplyChoice> {
    for _attempt in 0..5 {
        eprint!("Apply this fix? [y/N/q]: ");
        let line = lines.read_line()?;
        let trimmed = line.trim().to_ascii_lowercase();
        match trimmed.as_str() {
            "y" | "yes" => return Ok(ApplyChoice::Yes),
            "" | "n" | "no" => return Ok(ApplyChoice::No),
            "q" | "quit" => return Ok(ApplyChoice::Quit),
            _ => eprintln!("Please answer y, n, or q."),
        }
    }
    anyhow::bail!("too many invalid prompt responses; aborting")
}

fn prompt_yes_no_line(lines: &mut StdinLines, question: &str) -> anyhow::Result<bool> {
    for _attempt in 0..5 {
        eprint!("{question} [y/N]: ");
        let line = lines.read_line()?;
        let trimmed = line.trim().to_ascii_lowercase();
        match trimmed.as_str() {
            "y" | "yes" => return Ok(true),
            "" | "n" | "no" => return Ok(false),
            _ => eprintln!("Please answer y or n."),
        }
    }
    anyhow::bail!("too many invalid prompt responses; aborting")
}

fn build_intent(
    f: &Finding,
    policy: &PasswordPolicy,
    extension_target: chrono::NaiveDateTime,
) -> Option<FixIntent> {
    match f.rule {
        "weak-entry-password" | "reused-password" | "stale-password" => {
            f.entry_path
                .clone()
                .map(|path| FixIntent::RegenerateEntryPassword {
                    path,
                    policy: *policy,
                })
        }
        "expired-entry-overdue" => f
            .entry_path
            .clone()
            .map(|path| FixIntent::ExtendEntryExpiry {
                path,
                until: extension_target,
            }),
        "weak-outer-cipher" => Some(FixIntent::SetOuterCipher(kdbx::OuterCipher::ChaCha20)),
        "legacy-stream-cipher" => Some(FixIntent::SetInnerCipher(kdbx::InnerCipher::ChaCha20)),
        "legacy-kdf" => Some(FixIntent::SetKdfArgon2id),
        "weak-argon2-params" => Some(FixIntent::SetArgon2idParams(
            freekee_core::DEFAULT_TEMPLATE.kdf,
        )),
        "legacy-kdbx-version" => Some(FixIntent::UpgradeFormat),
        _ => None,
    }
}

/// One-line-at-a-time stdin reader used by the prompt loop. Holds the
/// `Stdin` lock for the lifetime of the loop so the y/N/q reader picks
/// up the next line after `read_passphrase` consumed the first.
struct StdinLines {
    stdin: std::io::Stdin,
}

impl StdinLines {
    fn new() -> Self {
        Self {
            stdin: std::io::stdin(),
        }
    }

    fn read_line(&mut self) -> anyhow::Result<String> {
        let mut line = String::new();
        let n = self.stdin.lock().read_line(&mut line)?;
        if n == 0 {
            // EOF - return empty string so the caller can treat it as "No".
            return Ok(String::new());
        }
        Ok(line)
    }
}
