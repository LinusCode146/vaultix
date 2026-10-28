//! Touch ID: a Secure Enclave key, through swift/TouchID.swift.

use std::ffi::CString;

use zeroize::Zeroizing;

use super::TouchIdError;

unsafe extern "C" {
    fn vx_touchid_available() -> bool;
    fn vx_touchid_enroll(blob_out: *mut u8, blob_capacity: usize, blob_len: *mut usize, public_out: *mut u8, key_out: *mut u8) -> i32;
    fn vx_touchid_derive(blob: *const u8, blob_len: usize, public_key: *const u8, reason: *const std::ffi::c_char, key_out: *mut u8) -> i32;
}

pub fn available() -> bool {
    unsafe { vx_touchid_available() }
}

/// A new enclave key: its blob, the public half of the one-off key, and the unlock key.
pub fn enroll() -> Result<(Vec<u8>, Vec<u8>, Zeroizing<[u8; 32]>), TouchIdError> {
    let mut blob = vec![0u8; 4096];
    let mut blob_len = 0usize;
    let mut public_key = vec![0u8; 65];
    let mut key = Zeroizing::new([0u8; 32]);
    let status =
        unsafe { vx_touchid_enroll(blob.as_mut_ptr(), blob.len(), &mut blob_len, public_key.as_mut_ptr(), key.as_mut_ptr()) };
    if status != 0 {
        return Err(TouchIdError::from_status(status));
    }
    blob.truncate(blob_len);
    Ok((blob, public_key, key))
}

/// Ask for a fingerprint and recompute the unlock key.
pub fn derive(blob: &[u8], public_key: &[u8], reason: &str) -> Result<Zeroizing<[u8; 32]>, TouchIdError> {
    if public_key.len() != 65 {
        return Err(TouchIdError::Invalidated);
    }
    let reason = CString::new(reason).unwrap_or_default();
    let mut key = Zeroizing::new([0u8; 32]);
    let status =
        unsafe { vx_touchid_derive(blob.as_ptr(), blob.len(), public_key.as_ptr(), reason.as_ptr(), key.as_mut_ptr()) };
    if status != 0 {
        return Err(TouchIdError::from_status(status));
    }
    Ok(key)
}
