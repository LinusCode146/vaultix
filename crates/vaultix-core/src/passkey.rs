//! A software WebAuthn authenticator (synced passkeys, ES256 only).
//!
//! The browser extension intercepts `navigator.credentials.create/get`, builds
//! `clientDataJSON`, and asks the desktop app to run [`Passkey::create`] /
//! [`Passkey::assert`]. The private key never leaves the app.
//!
//! Like other synced passkey providers we set the backup flags (BE|BS), use a
//! "none" attestation and keep the signature counter at 0.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::Value;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto::random_bytes;
use crate::error::{Error, Result};
use crate::origin::rp_id_valid_for_origin;

/// Identifies this authenticator model to relying parties.
pub const AAGUID: [u8; 16] = [0x6c, 0x0c, 0x6b, 0x0e, 0x5a, 0x3f, 0x4c, 0x1d, 0x9e, 0x2b, 0x7f, 0x43, 0x81, 0xd5, 0x2a, 0x10];
/// COSE algorithm identifier for ES256.
pub const COSE_ALG_ES256: i64 = -7;

const FLAG_UP: u8 = 0x01; // user present
const FLAG_UV: u8 = 0x04; // user verified (app is unlocked + user approved)
const FLAG_BE: u8 = 0x08; // backup eligible
const FLAG_BS: u8 = 0x10; // backed up (synced)
const FLAG_AT: u8 = 0x40; // attested credential data included

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Passkey {
    #[serde(with = "b64")]
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    #[serde(with = "b64")]
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    /// PKCS#8 DER. Only ever stored inside the encrypted vault.
    #[serde(with = "b64")]
    private_key: Vec<u8>,
    pub created_at: i64,
}

impl Drop for Passkey {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl std::fmt::Debug for Passkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkey")
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("credential_id", &URL_SAFE_NO_PAD.encode(&self.credential_id))
            .finish_non_exhaustive()
    }
}

/// Everything the extension needs to build a `PublicKeyCredential` for `create()`.
#[derive(Debug, Clone, Serialize)]
pub struct Registration {
    #[serde(with = "b64")]
    pub credential_id: Vec<u8>,
    #[serde(with = "b64")]
    pub attestation_object: Vec<u8>,
    #[serde(with = "b64")]
    pub authenticator_data: Vec<u8>,
    /// SubjectPublicKeyInfo DER, for `AuthenticatorAttestationResponse.getPublicKey()`.
    #[serde(with = "b64")]
    pub public_key_spki: Vec<u8>,
    pub public_key_algorithm: i64,
}

/// Everything the extension needs to build a `PublicKeyCredential` for `get()`.
#[derive(Debug, Clone, Serialize)]
pub struct Assertion {
    #[serde(with = "b64")]
    pub credential_id: Vec<u8>,
    #[serde(with = "b64")]
    pub authenticator_data: Vec<u8>,
    /// DER-encoded ECDSA signature, as WebAuthn expects.
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
    #[serde(with = "b64")]
    pub user_handle: Vec<u8>,
}

impl Passkey {
    /// A passkey brought over from another password manager, with its private
    /// key as PKCS#8 DER. Fails unless it's a P-256 key, the only kind Vaultix
    /// signs with.
    pub fn imported(
        credential_id: Vec<u8>,
        rp_id: String,
        user_handle: Vec<u8>,
        user_name: String,
        mut private_key: Vec<u8>,
        created_at: i64,
    ) -> Result<Passkey> {
        if SigningKey::from_pkcs8_der(&private_key).is_err() {
            private_key.zeroize();
            return Err(Error::Passkey("not a P-256 key".into()));
        }
        if credential_id.is_empty() || rp_id.is_empty() {
            return Err(Error::Passkey("no credential ID or RP ID".into()));
        }
        Ok(Passkey { credential_id, rp_id, user_handle, user_display_name: user_name.clone(), user_name, private_key, created_at })
    }

    /// Create a new credential (`navigator.credentials.create`).
    ///
    /// With "none" attestation nothing is signed at registration, so the
    /// client data hash isn't needed here.
    ///
    /// `origin` is the page origin as seen by the browser, used to enforce the
    /// RP ID rules so a page can't mint credentials for another site.
    pub fn create(
        rp_id: &str,
        origin: &str,
        user_handle: &[u8],
        user_name: &str,
        user_display_name: &str,
        now_ms: i64,
    ) -> Result<(Passkey, Registration)> {
        if !rp_id_valid_for_origin(rp_id, origin) {
            return Err(Error::Passkey(format!("RP ID {rp_id:?} not allowed for {origin}")));
        }
        let signing_key = SigningKey::random(&mut OsRng);
        let private_key = signing_key.to_pkcs8_der().map_err(|e| Error::Passkey(e.to_string()))?.as_bytes().to_vec();
        let credential_id = random_bytes::<16>().to_vec();

        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let cose_key = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),              // kty: EC2
            (Value::Integer(3.into()), Value::Integer(COSE_ALG_ES256.into())), // alg
            (Value::Integer((-1).into()), Value::Integer(1.into())),           // crv: P-256
            (Value::Integer((-2).into()), Value::Bytes(point.x().unwrap().to_vec())),
            (Value::Integer((-3).into()), Value::Bytes(point.y().unwrap().to_vec())),
        ]);

        let mut attested = Vec::new();
        attested.extend_from_slice(&AAGUID);
        attested.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        attested.extend_from_slice(&credential_id);
        attested.extend_from_slice(&cbor(&cose_key)?);

        let flags = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT;
        let authenticator_data = authenticator_data(rp_id, flags, &attested);
        let attestation_object = cbor(&Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(authenticator_data.clone())),
        ]))?;

        let public_key_spki = verifying_key.to_public_key_der().map_err(|e| Error::Passkey(e.to_string()))?.as_bytes().to_vec();

        let passkey = Passkey {
            credential_id: credential_id.clone(),
            rp_id: rp_id.to_ascii_lowercase(),
            user_handle: user_handle.to_vec(),
            user_name: user_name.to_string(),
            user_display_name: user_display_name.to_string(),
            private_key,
            created_at: now_ms,
        };
        let registration =
            Registration { credential_id, attestation_object, authenticator_data, public_key_spki, public_key_algorithm: COSE_ALG_ES256 };
        Ok((passkey, registration))
    }

    /// Sign in with this credential (`navigator.credentials.get`).
    pub fn assert(&self, origin: &str, client_data_hash: &[u8; 32]) -> Result<Assertion> {
        if !rp_id_valid_for_origin(&self.rp_id, origin) {
            return Err(Error::Passkey(format!("passkey for {:?} not usable on {origin}", self.rp_id)));
        }
        let signing_key = SigningKey::from_pkcs8_der(&self.private_key).map_err(|e| Error::Passkey(e.to_string()))?;
        let flags = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;
        let authenticator_data = authenticator_data(&self.rp_id, flags, &[]);

        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(client_data_hash);
        let signature: Signature = signing_key.sign(&signed);

        Ok(Assertion {
            credential_id: self.credential_id.clone(),
            authenticator_data,
            signature: signature.to_der().as_bytes().to_vec(),
            user_handle: self.user_handle.clone(),
        })
    }
}

/// Builds `clientDataJSON` in the field order browsers use, since some relying
/// parties verify it byte-wise per the spec's "limited verification algorithm".
pub fn client_data_json(kind: &str, challenge: &[u8], origin: &str) -> String {
    format!(
        r#"{{"type":{},"challenge":{},"origin":{},"crossOrigin":false}}"#,
        serde_json::to_string(kind).unwrap(),
        serde_json::to_string(&URL_SAFE_NO_PAD.encode(challenge)).unwrap(),
        serde_json::to_string(origin).unwrap(),
    )
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn authenticator_data(rp_id: &str, flags: u8, attested: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(37 + attested.len());
    out.extend_from_slice(&sha256(rp_id.to_ascii_lowercase().as_bytes()));
    out.push(flags);
    out.extend_from_slice(&0u32.to_be_bytes()); // sign count: always 0 for synced passkeys
    out.extend_from_slice(attested);
    out
}

fn cbor(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| Error::Passkey(e.to_string()))?;
    Ok(out)
}

mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        URL_SAFE_NO_PAD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePublicKey;

    const ORIGIN: &str = "https://login.example.com";

    fn make() -> (Passkey, Registration) {
        Passkey::create("example.com", ORIGIN, b"user-1", "alice", "Alice", 0).unwrap()
    }

    #[test]
    fn registration_is_well_formed() {
        let (pk, reg) = make();
        let ad = &reg.authenticator_data;
        assert_eq!(&ad[..32], &sha256(b"example.com"));
        assert_eq!(ad[32], FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT);
        assert_eq!(&ad[37..53], &AAGUID);
        let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        assert_eq!(&ad[55..55 + id_len], pk.credential_id.as_slice());

        // The COSE key in authData must be the same key as the SPKI.
        let cose: Value = ciborium::from_reader(&ad[55 + id_len..]).unwrap();
        let spki = VerifyingKey::from_public_key_der(&reg.public_key_spki).unwrap();
        let point = spki.to_encoded_point(false);
        let map = cose.as_map().unwrap();
        let get = |k: i64| map.iter().find(|(key, _)| key == &Value::Integer(k.into())).map(|(_, v)| v.clone());
        assert_eq!(get(-2).unwrap().as_bytes().unwrap().as_slice(), point.x().unwrap().as_slice());
        assert_eq!(get(-3).unwrap().as_bytes().unwrap().as_slice(), point.y().unwrap().as_slice());

        let att: Value = ciborium::from_reader(reg.attestation_object.as_slice()).unwrap();
        let att = att.as_map().unwrap();
        assert_eq!(att[0], (Value::Text("fmt".into()), Value::Text("none".into())));
    }

    #[test]
    fn assertion_verifies_against_registered_key() {
        let (pk, reg) = make();
        let cdj = client_data_json("webauthn.get", b"challenge-2", ORIGIN);
        let hash = sha256(cdj.as_bytes());
        let assertion = pk.assert(ORIGIN, &hash).unwrap();

        let vk = VerifyingKey::from_public_key_der(&reg.public_key_spki).unwrap();
        let sig = Signature::from_der(&assertion.signature).unwrap();
        let mut signed = assertion.authenticator_data.clone();
        signed.extend_from_slice(&hash);
        vk.verify(&signed, &sig).unwrap();
        assert_eq!(assertion.user_handle, b"user-1");
    }

    #[test]
    fn refuses_wrong_origins() {
        let hash = [0u8; 32];
        assert!(Passkey::create("example.com", "https://evil.com", b"u", "a", "A", 0).is_err());
        let (pk, _) = make();
        assert!(pk.assert("https://example.com.evil.com", &hash).is_err());
    }

    #[test]
    fn survives_serialization() {
        let (pk, _) = make();
        let json = serde_json::to_string(&pk).unwrap();
        let back: Passkey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pk);
        assert!(back.assert(ORIGIN, &[1u8; 32]).is_ok());
    }

    #[test]
    fn client_data_json_field_order() {
        let j = client_data_json("webauthn.get", &[0xff], "https://a.com");
        assert_eq!(j, r#"{"type":"webauthn.get","challenge":"_w","origin":"https://a.com","crossOrigin":false}"#);
    }
}
