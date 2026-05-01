//! Passphrase / entry-password strength estimation via zxcvbn.

/// Return zxcvbn's guesses estimate converted to bits.
///
/// `bits = log2(guesses)`; zxcvbn exposes only `guesses_log10`, so we
/// scale by `log2(10) ~= 3.321928094887362`.
pub fn passphrase_bits(password: &str) -> f64 {
    let entropy = zxcvbn::zxcvbn(password, &[]);
    entropy.guesses_log10() * std::f64::consts::LOG2_10
}
