//! Password strength, estimated as the number of guesses an attacker would
//! need (zxcvbn: dictionaries, common patterns, keyboard walks, dates, and
//! words from the item itself such as the username or site name).

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StrengthLabel {
    Terrible,
    Weak,
    Fair,
    Good,
    VeryGood,
    Excellent,
    Fantastic,
}

impl StrengthLabel {
    pub const ALL: [StrengthLabel; 7] = [
        StrengthLabel::Terrible,
        StrengthLabel::Weak,
        StrengthLabel::Fair,
        StrengthLabel::Good,
        StrengthLabel::VeryGood,
        StrengthLabel::Excellent,
        StrengthLabel::Fantastic,
    ];

    /// By log10(guesses). Each step is 100× harder to crack than the one below.
    fn from_guesses_log10(g: f64) -> Self {
        match g {
            g if g < 6.0 => StrengthLabel::Terrible,
            g if g < 8.0 => StrengthLabel::Weak,
            g if g < 10.0 => StrengthLabel::Fair,
            g if g < 12.0 => StrengthLabel::Good,
            g if g < 14.0 => StrengthLabel::VeryGood,
            g if g < 17.0 => StrengthLabel::Excellent,
            _ => StrengthLabel::Fantastic,
        }
    }

    /// Watchtower flags anything below Good.
    pub fn is_weak(self) -> bool {
        self < StrengthLabel::Good
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    pub label: StrengthLabel,
    pub guesses_log10: f64,
    /// 0..=1, for meters and rings (10^20 guesses counts as full).
    pub fraction: f64,
}

/// Estimate a password's strength. `context` holds words an attacker could
/// know about this login (username, item title, site name); passwords built
/// from them score lower.
pub fn estimate(password: &str, context: &[&str]) -> Strength {
    // Pattern matching gets slow on very long input; past 128 characters a
    // password can only get stronger, so rating the start is enough.
    let head: String = password.chars().take(128).collect();
    let g = if head.is_empty() { 0.0 } else { zxcvbn::zxcvbn(&head, context).guesses_log10() };
    Strength { label: StrengthLabel::from_guesses_log10(g), guesses_log10: g, fraction: (g / 20.0).clamp(0.0, 1.0) }
}

/// Minimum length for a master password, on top of the strength check.
pub const MASTER_PASSWORD_MIN_CHARS: usize = 12;
/// The master password is the only thing protecting a stolen vault folder.
pub const MASTER_PASSWORD_MIN_STRENGTH: StrengthLabel = StrengthLabel::VeryGood;

/// Why a master password is not acceptable, or `None` if it is.
pub fn master_password_problem(password: &str) -> Option<String> {
    let len = password.trim().chars().count();
    if len < MASTER_PASSWORD_MIN_CHARS {
        return Some(format!("Use at least {MASTER_PASSWORD_MIN_CHARS} characters ({len} so far)."));
    }
    if estimate(password, &[]).label < MASTER_PASSWORD_MIN_STRENGTH {
        return Some("Too easy to guess. Add more words or characters, or use a random passphrase.".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::{PasswordOptions, generate_password};

    #[test]
    fn common_passwords_are_terrible() {
        for pw in ["password", "123456", "qwerty123", "iloveyou"] {
            assert_eq!(estimate(pw, &[]).label, StrengthLabel::Terrible, "{pw}");
        }
    }

    #[test]
    fn generated_passwords_are_fantastic() {
        let pw = generate_password(&PasswordOptions::default());
        assert_eq!(estimate(&pw, &[]).label, StrengthLabel::Fantastic, "{pw}");
    }

    #[test]
    fn long_random_passphrases_score_well() {
        let s = estimate("correct horse battery staple orbit", &[]);
        assert!(s.label >= StrengthLabel::VeryGood, "{s:?}");
    }

    #[test]
    fn context_words_lower_the_score() {
        let without = estimate("burgir_ohne_tomaten", &[]);
        let with = estimate("burgir_ohne_tomaten", &["Burgir_ohne_Tomaten"]);
        assert!(with.guesses_log10 < without.guesses_log10);
    }

    #[test]
    fn master_password_rules() {
        assert!(master_password_problem("short").unwrap().contains("12"));
        assert!(master_password_problem("password1234").is_some());
        assert!(master_password_problem("aaaaaaaaaaaaaaaa").is_some());
        assert_eq!(master_password_problem("tulip orbit canyon velvet marble"), None);
    }

    #[test]
    fn labels_are_ordered_and_empty_is_terrible() {
        assert!(StrengthLabel::ALL.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(estimate("", &[]).label, StrengthLabel::Terrible);
        assert!(StrengthLabel::Fair.is_weak() && !StrengthLabel::Good.is_weak());
    }
}
