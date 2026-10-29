//! Unlocking with Touch ID (macOS), Windows Hello or a fingerprint / face
//! (Android) instead of the master password.
//!
//! The vault key is wrapped with a 32-byte key that only this computer's
//! security chip can recompute, after the user confirms: on a Mac, the Secure
//! Enclave after a Touch ID match (see swift/TouchID.swift); on Windows, the
//! TPM after Windows Hello (see `windows.rs`); on Android, the Keystore after
//! a strong biometric match (see `android.rs`). The wrapped key and the key
//! material the chip needs are kept in `touch-id.json` on this computer only;
//! none of it is useful elsewhere, or without the user.
//!
//! The master password is still required every [`PASSWORD_EVERY`], so it
//! isn't forgotten, and whenever the enrolled fingers change.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vaultix_core::Vault;

pub const PASSWORD_EVERY: Duration = Duration::from_secs(14 * 24 * 3600);
const FILE: &str = "touch-id.json";

#[cfg_attr(target_os = "macos", path = "touchid/macos.rs")]
#[cfg_attr(windows, path = "touchid/windows.rs")]
#[cfg_attr(target_os = "android", path = "touchid/android.rs")]
#[cfg_attr(not(any(target_os = "macos", windows, target_os = "android")), path = "touchid/other.rs")]
mod backend;
#[cfg(target_os = "android")]
pub use backend::plugin;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchIdError {
    /// The user dismissed the prompt.
    Cancelled,
    /// No Touch ID sensor, no fingers enrolled, or no Secure Enclave (or no
    /// Windows Hello set up).
    Unavailable,
    /// The enrolled fingers changed since Touch ID was turned on.
    Invalidated,
    /// Too many failed attempts; the system wants the login password first.
    Lockout,
    Failed,
}

impl TouchIdError {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
    backend::available()
}

/// Whether setting up asks the user. Touch ID doesn't, so it is set up again
/// silently after the fingers change; Windows Hello and Android do, so it isn't.
pub const SETUP_PROMPTS: bool = cfg!(any(windows, target_os = "android"));

/// A new key for [`Enrollment::create`]. May show a prompt and block until
/// the user responds; call it without holding the vault.
pub fn new_key() -> Result<NewKey, TouchIdError> {
    backend::enroll().map(|(blob, public_key, key)| NewKey { blob, public_key, key })
}

pub struct NewKey {
    blob: Vec<u8>,
    public_key: Vec<u8>,
    key: zeroize::Zeroizing<[u8; 32]>,
}

/// What the UI calls it: "touch-id", "windows-hello", or `None` without one.
pub fn kind() -> Option<&'static str> {
    if cfg!(target_os = "macos") {
        Some("touch-id")
    } else if cfg!(windows) {
        Some("windows-hello")
    } else if cfg!(target_os = "android") {
        Some("android-biometric")
    } else {
        None
    }
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
    pub fn create(vault: &Vault, new: NewKey, password_at: u64) -> Enrollment {
        let NewKey { blob, public_key, key } = new;
        Enrollment {
            vault_id: vault.vault_id(),
            wanted: true,
            enclave_key: B64.encode(&blob),
            public_key: B64.encode(public_key),
            wrapped_vault_key: B64.encode(vault.wrap_for_device(&key)),
            password_at,
        }
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
        let key = backend::derive(&blob, &public_key, reason)?;
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
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore]
    fn enrolls_with_the_secure_enclave() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_with_params(dir.path(), "pw", Uuid::new_v4(), vaultix_core::crypto::KdfParams::insecure_fast()).unwrap();
        assert!(available());
        let e = Enrollment::create(&vault, new_key().unwrap(), now_secs());
        assert!(e.usable(vault.vault_id()));
        assert_eq!(B64.decode(&e.public_key).unwrap().len(), 65);
    }
}
