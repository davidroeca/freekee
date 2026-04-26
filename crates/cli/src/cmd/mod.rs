pub mod audit;
pub mod info;
pub mod verify;

use std::io::BufRead;
use zeroize::Zeroizing;

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
