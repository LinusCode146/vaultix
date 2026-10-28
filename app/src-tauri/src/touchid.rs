//! Unlocking with Touch ID instead of the master password.
//!
//! The vault key is wrapped with a 32-byte key that only the Secure Enclave
//! can recompute, after a Touch ID match (see swift/TouchID.swift). The
//! wrapped key, the enclave's key blob and the public half of the one-off key
//! are kept in `touch-id.json` on this Mac only; none of it is useful
//! elsewhere, or without a fingerprint.
//!
//! The master password is still required every [`PASSWORD_EVERY`], so it
//! isn't forgotten, and whenever the enrolled fingers change.

use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vaultix_core::Vault;
use zeroize::Zeroizing;

pub const PASSWORD_EVERY: Duration = Duration::from_secs(14 * 24 * 3600);
const FILE: &str = "touch-id.json";

unsafe extern "C" {
    fn vx_touchid_available() -> bool;
    fn vx_touchid_enroll(blob_out: *mut u8, blob_capacity: usize, blob_len: *mut usize, public_out: *mut u8, key_out: *mut u8) -> i32;
    fn vx_touchid_derive(blob: *const u8, blob_len: usize, public_key: *const u8, reason: *const std::ffi::c_char, key_out: *mut u8) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchIdError {
    /// The user dismissed the prompt.
    Cancelled,
    /// No Touch ID sensor, no fingers enrolled, or no Secure Enclave.
    Unavailable,
    /// The enrolled fingers changed since Touch ID was turned on.
    Invalidated,
    /// Too many failed attempts; macOS wants the login password first.
    Lockout,
    Failed,
}

impl TouchIdError {
    fn from_status(status: i32) -> Self {
        match status {
            1 => Self::Cancelled,
            2 => Self::Unavailable,
            3 => Self::Invalidated,
            4 => Self::Lockout,
            _ => Self::Failed,
        }
    }

    /// Short codes the UI and extension switch on.
    pub fn code(self) -> &'static str {
        match self {
            Self::Cancelled => "touch-id-cancelled",
            Self::Unavailable => "touch-id-unavailable",
            Self::Invalidated => "touch-id-invalidated",
            Self::Lockout => "touch-id-lockout",
            Self::Failed => "touch-id-failed",
        }
    }
}

pub fn available() -> bool {
    unsafe { vx_touchid_available() }
}

/// What's stored on disk. `wanted` survives invalidation, so Touch ID is set
/// up again automatically at the next master password unlock.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Enrollment {
    pub vault_id: Uuid,
    pub wanted: bool,
    #[serde(default)]
    enclave_key: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    wrapped_vault_key: String,
    /// Unix seconds of the last unlock with the master password.
    pub password_at: u64,
}

impl Enrollment {
    pub fn path(config_dir: &Path) -> PathBuf {
        config_dir.join(FILE)
    }

    pub fn load(config_dir: &Path) -> Option<Enrollment> {
        serde_json::from_slice(&fs::read(Self::path(config_dir)).ok()?).ok()
    }

    pub fn save(&self, config_dir: &Path) -> std::io::Result<()> {
        let path = Self::path(config_dir);
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        fs::rename(tmp, path)
    }

    pub fn remove(config_dir: &Path) {
        let _ = fs::remove_file(Self::path(config_dir));
    }

    /// Set up (or redo) Touch ID for an unlocked vault.
    pub fn create(vault: &Vault, password_at: u64) -> Result<Enrollment, TouchIdError> {
        let mut blob = vec![0u8; 4096];
        let mut blob_len = 0usize;
        let mut public_key = [0u8; 65];
        let mut key = Zeroizing::new([0u8; 32]);
        let status = unsafe {
            vx_touchid_enroll(blob.as_mut_ptr(), blob.len(), &mut blob_len, public_key.as_mut_ptr(), key.as_mut_ptr())
        };
        if status != 0 {
            return Err(TouchIdError::from_status(status));
        }
        blob.truncate(blob_len);
        Ok(Enrollment {
            vault_id: vault.vault_id(),
            wanted: true,
            enclave_key: B64.encode(&blob),
            public_key: B64.encode(public_key),
            wrapped_vault_key: B64.encode(vault.wrap_for_device(&key)),
            password_at,
        })
    }

    pub fn has_key(&self) -> bool {
        !self.enclave_key.is_empty()
    }

    /// Whether Touch ID can be offered right now (it may still fail or be cancelled).
    pub fn usable(&self, vault_id: Uuid) -> bool {
        self.wanted && self.vault_id == vault_id && self.has_key() && !self.password_due()
    }

    pub fn password_due(&self) -> bool {
        now_secs().saturating_sub(self.password_at) >= PASSWORD_EVERY.as_secs()
    }

    /// Ask for a fingerprint and unlock. Blocks until the user responds.
    pub fn unlock(&self, dir: &Path, device_id: Uuid, reason: &str) -> Result<Vault, TouchIdError> {
        let blob = B64.decode(&self.enclave_key).map_err(|_| TouchIdError::Invalidated)?;
        let public_key = B64.decode(&self.public_key).map_err(|_| TouchIdError::Invalidated)?;
        let wrapped = B64.decode(&self.wrapped_vault_key).map_err(|_| TouchIdError::Invalidated)?;
        if public_key.len() != 65 {
            return Err(TouchIdError::Invalidated);
        }
        let reason = CString::new(reason).unwrap_or_default();
        let mut key = Zeroizing::new([0u8; 32]);
        let status = unsafe {
            vx_touchid_derive(blob.as_ptr(), blob.len(), public_key.as_ptr(), reason.as_ptr(), key.as_mut_ptr())
        };
        if status != 0 {
            return Err(TouchIdError::from_status(status));
        }
        Vault::unlock_with_device_key(dir, device_id, &key, &wrapped).map_err(|_| TouchIdError::Invalidated)
    }

    /// Keep the wish for Touch ID but drop the dead key (fingers changed).
    pub fn invalidate(&mut self) {
        self.enclave_key.clear();
        self.public_key.clear();
        self.wrapped_vault_key.clear();
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_is_required_every_two_weeks() {
        let mut e = Enrollment { wanted: true, enclave_key: "x".into(), password_at: now_secs(), ..Default::default() };
        assert!(e.usable(Uuid::nil()));
        e.password_at = now_secs() - PASSWORD_EVERY.as_secs() - 1;
        assert!(!e.usable(Uuid::nil()));
    }

    #[test]
    fn invalidated_or_other_vault_is_not_offered() {
        let mut e = Enrollment { wanted: true, enclave_key: "x".into(), password_at: now_secs(), ..Default::default() };
        assert!(!e.usable(Uuid::new_v4()));
        e.invalidate();
        assert!(!e.usable(Uuid::nil()));
        assert!(e.wanted);
    }

    /// Creates a real Secure Enclave key (no prompt): `cargo test -p vaultix-app -- --ignored`.
    #[test]
    #[ignore]
    fn enrolls_with_the_secure_enclave() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_with_params(dir.path(), "pw", Uuid::new_v4(), vaultix_core::crypto::KdfParams::insecure_fast()).unwrap();
        assert!(available());
        let e = Enrollment::create(&vault, now_secs()).unwrap();
        assert!(e.usable(vault.vault_id()));
        assert_eq!(B64.decode(&e.public_key).unwrap().len(), 65);
    }
}
