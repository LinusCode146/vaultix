//! Random password generation from the OS CSPRNG.

use rand::Rng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&*+-.:=?@^_~";
/// Characters that are easy to misread when typing a password from a screen.
const AMBIGUOUS: &str = "Il1O0o";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordOptions {
    pub length: usize,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        PasswordOptions { length: 20, uppercase: true, digits: true, symbols: true, avoid_ambiguous: true }
    }
}

/// Generate a password containing at least one character from every enabled
/// class. Retries instead of forcing characters into positions, so the result
/// stays uniformly distributed over all valid passwords.
pub fn generate_password(opts: &PasswordOptions) -> String {
    let mut classes: Vec<Vec<char>> = vec![chars(LOWER, opts)];
    if opts.uppercase {
        classes.push(chars(UPPER, opts));
    }
    if opts.digits {
        classes.push(chars(DIGITS, opts));
    }
    if opts.symbols {
        classes.push(chars(SYMBOLS, opts));
    }
    let alphabet: Vec<char> = classes.concat();
    let length = opts.length.clamp(classes.len().max(4), 128);

    loop {
        let candidate: String = (0..length).map(|_| alphabet[OsRng.gen_range(0..alphabet.len())]).collect();
        if classes.iter().all(|class| candidate.chars().any(|c| class.contains(&c))) {
            return candidate;
        }
    }
}

fn chars(set: &str, opts: &PasswordOptions) -> Vec<char> {
    set.chars().filter(|c| !opts.avoid_ambiguous || !AMBIGUOUS.contains(*c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_options() {
        let opts = PasswordOptions { length: 32, ..Default::default() };
        for _ in 0..50 {
            let p = generate_password(&opts);
            assert_eq!(p.chars().count(), 32);
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn letters_only() {
        let opts = PasswordOptions { length: 16, uppercase: false, digits: false, symbols: false, avoid_ambiguous: false };
        assert!(generate_password(&opts).chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn length_is_clamped() {
        let opts = PasswordOptions { length: 1, ..Default::default() };
        assert_eq!(generate_password(&opts).len(), 4);
    }
}
