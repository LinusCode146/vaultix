//! Symmetric primitives and key derivation from the master password.
//!
//! Key hierarchy:
//!
//! ```text
//! master password ──Argon2id(salt)──► KEK ──wraps──► vault key ──encrypts──► log entries
//! ```
//!
//! The master password is the only secret: anyone holding the synced folder can
//! try to guess it offline, so Argon2id's cost is what makes each guess
//! expensive. Keep the parameters high and the password long.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// A 256-bit symmetric key that is wiped from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub fn random() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Key(bytes)
    }

    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Key(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// Argon2id cost parameters, stored in `vault.meta` so they can be raised later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// 256 MiB, 4 passes, 4 lanes: about 0.5 s per unlock on an M-series Mac
    /// (`cargo run --release --example kdf_bench`), and 256 MiB of memory per
    /// guess for anyone trying to crack a stolen vault.json.
    fn default() -> Self {
        KdfParams { m_cost: 256 * 1024, t_cost: 4, p_cost: 4 }
    }
}

impl KdfParams {
    /// Cheap parameters for tests only. Never use these for a real vault.
    pub fn insecure_fast() -> Self {
        KdfParams { m_cost: 64, t_cost: 1, p_cost: 1 }
    }

    /// Whether these are cheaper than `target` in memory or passes.
    pub fn weaker_than(&self, target: &KdfParams) -> bool {
        self.m_cost < target.m_cost || self.t_cost < target.t_cost
    }
}

/// Derive the key-encryption key from the master password.
pub fn derive_kek(password: &str, salt: &[u8], params: KdfParams) -> Result<Key> {
    // Normalize so the same password typed on different keyboards/OSes matches.
    let mut normalized: String = password.trim().nfkd().collect();

    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN)).map_err(|e| Error::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut kek = [0u8; KEY_LEN];
    let hashed = argon.hash_password_into(normalized.as_bytes(), salt, &mut kek);
    normalized.zeroize();
    if let Err(e) = hashed {
        kek.zeroize();
        return Err(Error::Kdf(e.to_string()));
    }
    Ok(Key(kek))
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Encrypt with XChaCha20-Poly1305. Output is `nonce || ciphertext+tag`.
///
/// `aad` is authenticated but not encrypted; use it to bind ciphertext to its
/// context (vault, device, purpose) so it can't be replayed elsewhere.
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory buffers");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

pub fn open(key: &Key, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN {
        return Err(Error::Decrypt);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad }).map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = Key::random();
        let sealed = seal(&key, b"hello", b"ctx");
        assert_eq!(open(&key, &sealed, b"ctx").unwrap(), b"hello");
    }

    #[test]
    fn open_rejects_wrong_aad_and_tampering() {
        let key = Key::random();
        let mut sealed = seal(&key, b"hello", b"ctx");
        assert!(open(&key, &sealed, b"other").is_err());
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(&key, &sealed, b"ctx").is_err());
    }

    #[test]
    fn kek_depends_on_password_and_salt() {
        let p = KdfParams::insecure_fast();
        let a = derive_kek("pw", &[7u8; 16], p).unwrap();
        let b = derive_kek("pw", &[8u8; 16], p).unwrap();
        let c = derive_kek("pw2", &[7u8; 16], p).unwrap();
        let a2 = derive_kek("  pw ", &[7u8; 16], p).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
        assert_eq!(a.as_bytes(), a2.as_bytes(), "surrounding whitespace is ignored");
    }
}
