//! `freekee set` - upsert an entry. Field assignments are passed as
//! `key=value` positional arguments. `--gen-password` synthesizes a
//! password via `core::PasswordPolicy`; the value is silent unless
//! `--print-generated` is set.

use std::path::PathBuf;
use std::process::ExitCode;

use freekee_core::{Alphabet, PasswordPolicy, Vault};
use kdbx::{EntryDraft, EntryField, EntryFieldValue, EntryPath};

#[derive(clap::Args)]
pub struct Args {
    pub path: PathBuf,
    /// Slash-separated entry path (e.g. `Personal/email`).
    pub entry: String,
    /// Zero or more `key=value` field assignments.
    /// Standard keys: title, username, password, url, notes; any
    /// other key is stored as a custom field.
    pub assignments: Vec<String>,
    /// Generate a password via `core::PasswordPolicy` and assign it
    /// to the entry. Silent unless `--print-generated` is set.
    #[arg(long)]
    pub gen_password: bool,
    /// Length of the generated password. Default: 24 (matches
    /// `PasswordPolicy::default()`).
    #[arg(long)]
    pub length: Option<usize>,
    /// Echo the generated password to stdout. Off by default.
    #[arg(long)]
    pub print_generated: bool,
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    #[arg(long)]
    pub pass_stdin: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let pass = super::read_passphrase(args.pass_stdin)?;
    let mut vault = Vault::open(&args.path, pass, args.keyfile.as_deref())?;

    let segments = super::parse_entry_path(&args.entry)?;
    let mut scratch = Vec::new();
    let entry_path: EntryPath<'_> = super::entry_path_from(&segments, &mut scratch);

    let mut parsed: Vec<(String, String)> = args
        .assignments
        .iter()
        .map(|a| parse_assignment(a))
        .collect::<anyhow::Result<_>>()?;

    // `field=-` sentinel: replace each "-" value with one line read
    // from stdin, in command-line order. Reads happen after
    // `read_passphrase` so the passphrase consumes line 1 and each
    // sentinel consumes the next line.
    for (_, v) in parsed.iter_mut() {
        if v == "-" {
            let line = super::read_field_value_from_stdin()?;
            *v = line.as_str().to_owned();
        }
    }

    let exists = vault.entry_exists(entry_path);
    if !exists {
        // Insert the entry with the standard fields collected up
        // front. Any unknown keys go in via `set_field` after the
        // entry exists.
        let mut draft = EntryDraft::default();
        for (k, v) in &parsed {
            match k.to_ascii_lowercase().as_str() {
                "username" => draft.username = Some(v.as_str()),
                "password" => draft.password = Some(v.as_str()),
                "url" => draft.url = Some(v.as_str()),
                "notes" => draft.notes = Some(v.as_str()),
                "title" => {} // title comes from the path; ignore here
                _ => {}
            }
        }
        vault.upsert_entry(entry_path, draft)?;
    }

    // Now apply every assignment via set_field so each lands in
    // history (and so custom fields work whether the entry is new or
    // existing).
    for (k, v) in &parsed {
        let (field, value) = field_and_value_for(k, v.as_str());
        vault.set_field(entry_path, field, value)?;
    }

    let mut generated: Option<String> = None;
    if args.gen_password {
        let policy = PasswordPolicy {
            length: args.length.unwrap_or(PasswordPolicy::default().length),
            alphabet: Alphabet::AlphaNumSymbol,
        };
        let pw = policy.generate();
        vault.set_field(
            entry_path,
            EntryField::Password,
            EntryFieldValue::Protected(pw.as_str()),
        )?;
        generated = Some(pw.to_string());
    }

    vault.save()?;

    if args.print_generated
        && let Some(pw) = generated
    {
        println!("{pw}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Split `key=value` into owned strings. Multiple `=` signs leave the
/// remainder in `value` (so `notes=foo=bar` is `notes` -> `foo=bar`).
fn parse_assignment(input: &str) -> anyhow::Result<(String, String)> {
    let (k, v) = input
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("expected key=value, got '{input}'"))?;
    if k.is_empty() {
        anyhow::bail!("empty key in assignment '{input}'");
    }
    Ok((k.to_owned(), v.to_owned()))
}

/// Map a free-form key to an `EntryField` plus a `Plain`/`Protected`
/// value envelope. The password field is treated as protected so it
/// gets the inner-cipher treatment on save.
fn field_and_value_for<'a>(key: &'a str, value: &'a str) -> (EntryField<'a>, EntryFieldValue<'a>) {
    match key.to_ascii_lowercase().as_str() {
        "title" => (EntryField::Title, EntryFieldValue::Plain(value)),
        "username" => (EntryField::Username, EntryFieldValue::Plain(value)),
        "password" => (EntryField::Password, EntryFieldValue::Protected(value)),
        "url" => (EntryField::Url, EntryFieldValue::Plain(value)),
        "notes" => (EntryField::Notes, EntryFieldValue::Plain(value)),
        _ => (EntryField::Custom(key), EntryFieldValue::Plain(value)),
    }
}
