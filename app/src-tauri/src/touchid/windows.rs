//! Windows Hello: a key pair in the TPM that signs only after the user
//! confirms with a fingerprint, face or PIN.
//!
//! RSA PKCS#1 v1.5 signatures are deterministic, so signing the same random
//! challenge always gives the same signature; its SHA-256 is the unlock key.
//! The challenge is stored in the enrollment; it isn't secret, the TPM's key is.

use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};
use windows::core::{Array, HSTRING, w};
use zeroize::{Zeroize, Zeroizing};

use super::TouchIdError;

/// One Windows Hello key per user account; a new enrollment replaces it.
const CREDENTIAL: &str = "Vaultix";

pub fn available() -> bool {
    KeyCredentialManager::IsSupportedAsync().and_then(|op| op.join()).unwrap_or(false)
}

/// A new TPM key: the challenge it signs, nothing public, and the unlock key.
pub fn enroll() -> Result<(Vec<u8>, Vec<u8>, Zeroizing<[u8; 32]>), TouchIdError> {
    let challenge: Vec<u8> = [uuid::Uuid::new_v4(), uuid::Uuid::new_v4()].iter().flat_map(|u| *u.as_bytes()).collect();
    focus_prompt();
    let result = KeyCredentialManager::RequestCreateAsync(&HSTRING::from(CREDENTIAL), KeyCredentialCreationOption::ReplaceExisting)
        .and_then(|op| op.join())
        .map_err(|_| TouchIdError::Failed)?;
    check(result.Status().map_err(|_| TouchIdError::Failed)?)?;
    let credential = result.Credential().map_err(|_| TouchIdError::Failed)?;
    // Creating asks once; signing right after doesn't ask again.
    let key = sign(&credential, &challenge)?;
    Ok((challenge, Vec::new(), key))
}

/// Ask for Windows Hello and recompute the unlock key. Blocks until the user responds.
pub fn derive(challenge: &[u8], _public: &[u8], _reason: &str) -> Result<Zeroizing<[u8; 32]>, TouchIdError> {
    let result = KeyCredentialManager::OpenAsync(&HSTRING::from(CREDENTIAL))
        .and_then(|op| op.join())
        .map_err(|_| TouchIdError::Failed)?;
    check(result.Status().map_err(|_| TouchIdError::Failed)?)?;
    let credential = result.Credential().map_err(|_| TouchIdError::Failed)?;
    focus_prompt();
    sign(&credential, challenge)
}

fn sign(credential: &KeyCredential, challenge: &[u8]) -> Result<Zeroizing<[u8; 32]>, TouchIdError> {
    let buffer = CryptographicBuffer::CreateFromByteArray(challenge).map_err(|_| TouchIdError::Failed)?;
    let result = credential.RequestSignAsync(&buffer).and_then(|op| op.join()).map_err(|_| TouchIdError::Failed)?;
    check(result.Status().map_err(|_| TouchIdError::Failed)?)?;
    let signature = result.Result().map_err(|_| TouchIdError::Failed)?;
    let mut bytes = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&signature, &mut bytes).map_err(|_| TouchIdError::Failed)?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&Sha256::digest(&bytes[..]));
    bytes[..].zeroize();
    Ok(key)
}

fn check(status: KeyCredentialStatus) -> Result<(), TouchIdError> {
    match status {
        KeyCredentialStatus::Success => Ok(()),
        KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => Err(TouchIdError::Cancelled),
        // The key was removed, or Windows Hello was reset.
        KeyCredentialStatus::NotFound => Err(TouchIdError::Invalidated),
        KeyCredentialStatus::SecurityDeviceLocked => Err(TouchIdError::Lockout),
        _ => Err(TouchIdError::Failed),
    }
}

/// A desktop app's Windows Hello prompt opens behind the app's window. Bring
/// it to the front once it appears (KeePassXC does the same).
fn focus_prompt() {
    thread::spawn(|| {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            // SAFETY: plain Win32 calls with constant, NUL-terminated strings.
            unsafe {
                if let Ok(window) = FindWindowW(w!("Credential Dialog Xaml Host"), None)
                    && !window.is_invalid()
                {
                    let _ = SetForegroundWindow(window);
                    return;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
}
