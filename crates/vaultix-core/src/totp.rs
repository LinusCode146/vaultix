//! RFC 6238 time-based one-time passwords, configured from `otpauth://` URIs.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Error, Result};

macro_rules! hmac_bytes {
    ($digest:ty, $key:expr, $msg:expr) => {{
        let mut mac = <Hmac<$digest> as Mac>::new_from_slice($key).expect("HMAC accepts keys of any length");
        mac.update($msg);
        mac.finalize().into_bytes().to_vec()
    }};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totp {
    /// Base32 secret exactly as shown by the site (normalized: uppercase, no padding).
    pub secret: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
}

impl Totp {
    /// Accepts either a full `otpauth://totp/...` URI (from a QR code) or a
    /// bare base32 secret (from "can't scan? enter this code").
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.to_ascii_lowercase().starts_with("otpauth://") {
            Self::from_uri(input)
        } else {
            let totp = Totp { secret: normalize_secret(input), algorithm: TotpAlgorithm::Sha1, digits: 6, period: 30 };
            totp.secret_bytes()?;
            Ok(totp)
        }
    }

    fn from_uri(uri: &str) -> Result<Self> {
        let url = Url::parse(uri).map_err(|e| Error::InvalidTotp(e.to_string()))?;
        if url.host_str().map(|h| h.to_ascii_lowercase()) != Some("totp".into()) {
            return Err(Error::InvalidTotp("only totp (not hotp) is supported".into()));
        }
        let mut totp = Totp { secret: String::new(), algorithm: TotpAlgorithm::Sha1, digits: 6, period: 30 };
        for (k, v) in url.query_pairs() {
            match k.to_ascii_lowercase().as_str() {
                "secret" => totp.secret = normalize_secret(&v),
                "algorithm" => {
                    totp.algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        other => return Err(Error::InvalidTotp(format!("algorithm {other}"))),
                    }
                }
                "digits" => {
                    totp.digits = v.parse().ok().filter(|d| (6..=8).contains(d)).ok_or_else(|| Error::InvalidTotp(format!("digits {v}")))?
                }
                "period" => totp.period = v.parse().ok().filter(|p| *p > 0).ok_or_else(|| Error::InvalidTotp(format!("period {v}")))?,
                _ => {}
            }
        }
        if totp.secret.is_empty() {
            return Err(Error::InvalidTotp("missing secret".into()));
        }
        totp.secret_bytes()?;
        Ok(totp)
    }

    fn secret_bytes(&self) -> Result<Vec<u8>> {
        BASE32_NOPAD.decode(self.secret.as_bytes()).map_err(|_| Error::InvalidTotp("secret is not valid base32".into()))
    }

    /// The code valid at `unix_seconds`.
    pub fn code_at(&self, unix_seconds: u64) -> Result<String> {
        let counter = (unix_seconds / self.period).to_be_bytes();
        let key = self.secret_bytes()?;
        let mac = match self.algorithm {
            TotpAlgorithm::Sha1 => hmac_bytes!(sha1::Sha1, &key, &counter),
            TotpAlgorithm::Sha256 => hmac_bytes!(sha2::Sha256, &key, &counter),
            TotpAlgorithm::Sha512 => hmac_bytes!(sha2::Sha512, &key, &counter),
        };
        // RFC 4226 dynamic truncation.
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes([mac[offset] & 0x7f, mac[offset + 1], mac[offset + 2], mac[offset + 3]]);
        let code = bin % 10u32.pow(self.digits);
        Ok(format!("{:0width$}", code, width = self.digits as usize))
    }

    /// The `otpauth://` form, so the editor can show and round-trip the full
    /// configuration (not just the secret).
    pub fn to_uri(&self) -> String {
        let algorithm = match self.algorithm {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        };
        format!("otpauth://totp/Vaultix?secret={}&algorithm={algorithm}&digits={}&period={}", self.secret, self.digits, self.period)
    }

    /// Seconds until the current code expires, for the countdown ring in the UI.
    pub fn seconds_remaining(&self, unix_seconds: u64) -> u64 {
        self.period - (unix_seconds % self.period)
    }
}

fn normalize_secret(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace() && *c != '=' && *c != '-').map(|c| c.to_ascii_uppercase()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(s: &[u8]) -> String {
        BASE32_NOPAD.encode(s)
    }

    /// Test vectors from RFC 6238 Appendix B.
    #[test]
    fn rfc6238_vectors() {
        let cases = [
            (TotpAlgorithm::Sha1, &b"12345678901234567890"[..]),
            (TotpAlgorithm::Sha256, &b"12345678901234567890123456789012"[..]),
            (TotpAlgorithm::Sha512, &b"1234567890123456789012345678901234567890123456789012345678901234"[..]),
        ];
        let expected = [
            (59u64, ["94287082", "46119246", "90693936"]),
            (1111111109, ["07081804", "68084774", "25091201"]),
            (1234567890, ["89005924", "91819424", "93441116"]),
            (20000000000, ["65353130", "77737706", "47863826"]),
        ];
        for (time, codes) in expected {
            for (i, (alg, secret)) in cases.iter().enumerate() {
                let totp = Totp { secret: b32(secret), algorithm: *alg, digits: 8, period: 30 };
                assert_eq!(totp.code_at(time).unwrap(), codes[i], "{alg:?} at {time}");
            }
        }
    }

    #[test]
    fn parses_otpauth_uri() {
        let t = Totp::parse(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(t.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(t.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(t.digits, 8);
        assert_eq!(t.period, 60);
    }

    #[test]
    fn parses_bare_secret_with_spaces() {
        let t = Totp::parse("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(t.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(t.code_at(0).unwrap().len(), 6);
    }

    #[test]
    fn uri_roundtrip() {
        let t = Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&period=60").unwrap();
        assert_eq!(Totp::parse(&t.to_uri()).unwrap(), t);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(Totp::parse("otpauth://totp/x?issuer=a").is_err());
        assert!(Totp::parse("not base32!").is_err());
    }
}
