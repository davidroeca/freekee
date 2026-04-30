pub mod audit;
pub mod get;
pub mod history;
pub mod info;
pub mod init;
pub mod ls;
pub mod mv;
pub mod rm;
pub mod rotate;
pub mod set;
pub mod verify;

use std::io::BufRead;
use zeroize::Zeroizing;

use kdbx::EntryPath;

/// Parse a slash-separated entry path (e.g. `Email/Personal/gmail`)
/// into owned segments. Empty input or any empty segment is rejected
/// so callers cannot accidentally address the root or a group rather
/// than an entry.
pub fn parse_entry_path(input: &str) -> anyhow::Result<Vec<String>> {
    let segments: Vec<String> = input.split('/').map(|s| s.to_owned()).collect();
    if segments.is_empty() || segments.iter().any(|s| s.is_empty()) {
        anyhow::bail!(
            "invalid entry path '{input}': must be one or more non-empty slash-separated segments"
        );
    }
    Ok(segments)
}

/// Borrow `segments` as a (groups, title) pair suitable for building
/// an `EntryPath`. The caller owns `segments`; this function only
/// reorganizes references into it.
pub fn entry_path_from<'a>(segments: &'a [String], scratch: &'a mut Vec<&'a str>) -> EntryPath<'a> {
    let (title, groups) = segments
        .split_last()
        .expect("parse_entry_path guarantees non-empty");
    scratch.clear();
    scratch.extend(groups.iter().map(String::as_str));
    EntryPath {
        groups: scratch.as_slice(),
        title: title.as_str(),
    }
}

/// Read a passphrase. Order: `--pass-stdin` (one line of stdin),
/// then `$FREEKEE_PASS`, then prompt with no echo.
pub fn read_passphrase(pass_stdin: bool) -> anyhow::Result<Zeroizing<String>> {
    if pass_stdin {
        let stdin = std::io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        let trimmed = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_owned();
        return Ok(Zeroizing::new(trimmed));
    }
    if let Ok(env) = std::env::var("FREEKEE_PASS") {
        return Ok(Zeroizing::new(env));
    }
    let prompted = rpassword::prompt_password("Passphrase: ")?;
    Ok(Zeroizing::new(prompted))
}

/// Read the *new* passphrase used by `rotate passphrase`. Order:
/// `--new-pass-stdin` (next line of stdin), then `$FREEKEE_NEW_PASS`,
/// then prompt. Kept distinct from `read_passphrase` so a single
/// command can pull both old and new passphrases from stdin in
/// sequence (line 1 = old, line 2 = new).
pub fn read_new_passphrase(new_pass_stdin: bool) -> anyhow::Result<Zeroizing<String>> {
    if new_pass_stdin {
        let stdin = std::io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        let trimmed = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_owned();
        return Ok(Zeroizing::new(trimmed));
    }
    if let Ok(env) = std::env::var("FREEKEE_NEW_PASS") {
        return Ok(Zeroizing::new(env));
    }
    let prompted = rpassword::prompt_password("New passphrase: ")?;
    Ok(Zeroizing::new(prompted))
}
