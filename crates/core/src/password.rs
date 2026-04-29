//! Random password generator used by `set --gen-password` and
//! `rotate entry`. Uses [`getrandom::fill`] for entropy and uniform
//! rejection sampling over the chosen alphabet to avoid modulo bias.
//!
//! This is glue, not crypto. We do not implement any primitive — see
//! `AGENTS.md` "Never write or modify cryptographic primitives."

use zeroize::Zeroizing;

const ALPHA_BYTES: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ALPHANUM_BYTES: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ALPHANUMSYM_BYTES: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";

/// Character set used by [`PasswordPolicy::generate`].
#[derive(Debug, Clone, Copy)]
pub enum Alphabet {
    /// `A-Za-z` (52 chars).
    Alpha,
    /// `A-Za-z0-9` (62 chars).
    AlphaNum,
    /// `A-Za-z0-9` plus a curated symbol set (88 chars).
    AlphaNumSymbol,
    /// Caller-supplied alphabet. Must be non-empty ASCII; the
    /// generator panics on empty input.
    Custom(&'static str),
}

impl Alphabet {
    fn bytes(&self) -> &'static [u8] {
        match self {
            Alphabet::Alpha => ALPHA_BYTES,
            Alphabet::AlphaNum => ALPHANUM_BYTES,
            Alphabet::AlphaNumSymbol => ALPHANUMSYM_BYTES,
            Alphabet::Custom(s) => s.as_bytes(),
        }
    }
}

/// Length + alphabet for password generation.
#[derive(Debug, Clone, Copy)]
pub struct PasswordPolicy {
    pub length: usize,
    pub alphabet: Alphabet,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 24,
            alphabet: Alphabet::AlphaNumSymbol,
        }
    }
}

impl PasswordPolicy {
    /// Generate a random password of the configured length, sampled
    /// uniformly over the alphabet (rejection-sampled to avoid modulo
    /// bias). The returned string lives in a `Zeroizing<String>` so
    /// the secret is wiped from memory on drop.
    pub fn generate(&self) -> Zeroizing<String> {
        let alphabet = self.alphabet.bytes();
        assert!(!alphabet.is_empty(), "password alphabet must be non-empty");
        let n = alphabet.len() as u32;
        // Largest multiple of `n` that fits in `u32`. Random values
        // at or above this bound are rejected to keep the modulo
        // distribution uniform.
        let max_unbiased = (u32::MAX / n) * n;

        let mut out = String::with_capacity(self.length);
        let mut buf = [0u8; 4];
        while out.len() < self.length {
            getrandom::fill(&mut buf).expect("OS CSPRNG must be available");
            let r = u32::from_le_bytes(buf);
            if r < max_unbiased {
                out.push(alphabet[(r % n) as usize] as char);
            }
        }
        Zeroizing::new(out)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn password_policy_generate_uses_requested_alphabet_and_length() {
        let policy = PasswordPolicy {
            length: 24,
            alphabet: Alphabet::AlphaNum,
        };
        let pw = policy.generate();
        assert_eq!(pw.len(), 24);
        assert!(
            pw.chars().all(|c| c.is_ascii_alphanumeric()),
            "all chars must be in the requested alphabet, got {pw:?}"
        );

        // Two independent generations must differ at this length
        // (probability of collision over 62^24 alphabet is negligible).
        let pw2 = policy.generate();
        assert_ne!(*pw, *pw2);
    }

    #[test]
    fn password_policy_respects_custom_alphabet() {
        let policy = PasswordPolicy {
            length: 100,
            alphabet: Alphabet::Custom("xy"),
        };
        let pw = policy.generate();
        assert_eq!(pw.len(), 100);
        assert!(pw.chars().all(|c| c == 'x' || c == 'y'));
    }

    #[test]
    fn password_policy_default_is_24_alphanumsymbol() {
        let p = PasswordPolicy::default();
        assert_eq!(p.length, 24);
        assert!(matches!(p.alphabet, Alphabet::AlphaNumSymbol));
        let pw = p.generate();
        assert_eq!(pw.len(), 24);
    }

    #[test]
    fn password_policy_zero_length_is_empty() {
        let p = PasswordPolicy {
            length: 0,
            alphabet: Alphabet::AlphaNum,
        };
        assert!(p.generate().is_empty());
    }
}
