//! A device's TLS identity: a self-signed certificate and its key, made once
//! and kept by the app. Peers know each other by the certificate's SHA-256
//! fingerprint.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    /// DER certificate, base64.
    cert: String,
    /// PKCS#8 private key, base64.
    key: String,
}

impl Identity {
    pub fn generate() -> Identity {
        let made = rcgen::generate_simple_self_signed(vec![crate::tls::SERVER_NAME.into()]).expect("generate certificate");
        Identity {
            cert: B64.encode(made.cert.der()),
            key: B64.encode(made.signing_key.serialize_der()),
        }
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.cert_der())
    }

    pub(crate) fn cert_der(&self) -> Vec<u8> {
        B64.decode(&self.cert).unwrap_or_default()
    }

    pub(crate) fn key_der(&self) -> Vec<u8> {
        B64.decode(&self.key).unwrap_or_default()
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", self.fingerprint())
    }
}

/// Lowercase hex SHA-256 of a DER certificate.
pub(crate) fn fingerprint(cert_der: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(cert_der))
}
