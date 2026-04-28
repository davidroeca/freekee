//! Emit the deterministic JSON snapshot for a KDBX file. The
//! snapshot is what `expected.json` next to each fixture should
//! contain. Logic lives in `kdbx::snapshot::expected_snapshot`; this
//! binary is a thin CLI wrapper.
//!
//! Usage:
//!   echo "<password>" | dump-expected <path-to-db.kdbx>

use std::io::BufRead;
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            eprintln!("usage: dump-expected <path-to-db.kdbx>");
            return ExitCode::from(2);
        }
    };

    let mut password = String::new();
    if let Err(e) = std::io::stdin().lock().read_line(&mut password) {
        eprintln!("dump-expected: read password from stdin: {e}");
        return ExitCode::from(2);
    }
    let password = password.trim_end_matches('\n').trim_end_matches('\r');

    let db = match kdbx::Database::open(&path, password) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("dump-expected: {e}");
            return ExitCode::from(1);
        }
    };

    let snapshot = kdbx::snapshot::expected_snapshot(&db);
    println!(
        "{}",
        serde_json::to_string_pretty(&snapshot).expect("snapshot is always serializable"),
    );
    ExitCode::SUCCESS
}
