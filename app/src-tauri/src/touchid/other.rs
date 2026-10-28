//! No biometric unlock on this system: the master password only.

use zeroize::Zeroizing;

use super::TouchIdError;

pub fn available() -> bool {
    false
}

pub fn enroll() -> Result<(Vec<u8>, Vec<u8>, Zeroizing<[u8; 32]>), TouchIdError> {
    Err(TouchIdError::Unavailable)
}

pub fn derive(_blob: &[u8], _public: &[u8], _reason: &str) -> Result<Zeroizing<[u8; 32]>, TouchIdError> {
    Err(TouchIdError::Unavailable)
}
