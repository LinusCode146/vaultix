//! Fingerprint or face unlock on Android, through the Kotlin plugin in
//! `gen/android/.../BiometricKeyPlugin.kt`.
//!
//! A random 32-byte key is encrypted with an AES key in the Android Keystore
//! that can only be used right after a strong biometric match, and is
//! destroyed when fingerprints or faces are added. The encrypted key (with its
//! IV) is the blob; decrypting it needs the user's finger or face.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
use tauri::Wry;
use zeroize::Zeroizing;

use super::TouchIdError;

static HANDLE: OnceLock<PluginHandle<Wry>> = OnceLock::new();

/// Register the Kotlin side. Add it to the app builder.
pub fn plugin() -> TauriPlugin<Wry> {
    Builder::new("biometric-key")
        .setup(|_app, api| {
            let _ = HANDLE.set(api.register_android_plugin("app.vaultix.android", "BiometricKeyPlugin")?);
            Ok(())
        })
        .build()
}

#[derive(Deserialize)]
struct Status {
    available: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Seal<'a> {
    data: String,
    reason: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Open<'a> {
    sealed: String,
    reason: &'a str,
}

#[derive(Deserialize)]
struct Data {
    data: String,
}

fn call<T: serde::de::DeserializeOwned>(command: &str, payload: impl Serialize) -> Result<T, TouchIdError> {
    let handle = HANDLE.get().ok_or(TouchIdError::Unavailable)?;
    handle.run_mobile_plugin(command, payload).map_err(|e| {
        // The Kotlin side rejects with the same codes the UI uses.
        match e.to_string() {
            s if s.contains("touch-id-cancelled") => TouchIdError::Cancelled,
            s if s.contains("touch-id-unavailable") => TouchIdError::Unavailable,
            s if s.contains("touch-id-invalidated") => TouchIdError::Invalidated,
            s if s.contains("touch-id-lockout") => TouchIdError::Lockout,
            s => {
                eprintln!("[vaultix] biometric: {s}");
                TouchIdError::Failed
            }
        }
    })
}

pub fn available() -> bool {
    call::<Status>("status", ()).is_ok_and(|s| s.available)
}

pub fn enroll() -> Result<(Vec<u8>, Vec<u8>, Zeroizing<[u8; 32]>), TouchIdError> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(&mut key[..]);
    let data = Zeroizing::new(B64.encode(&key[..]));
    let sealed: Data = call("seal", Seal { data: data.to_string(), reason: "Turn on fingerprint unlock for Vaultix" })?;
    let blob = B64.decode(sealed.data).map_err(|_| TouchIdError::Failed)?;
    Ok((blob, Vec::new(), key))
}

pub fn derive(blob: &[u8], _public: &[u8], reason: &str) -> Result<Zeroizing<[u8; 32]>, TouchIdError> {
    let opened: Data = call("open", Open { sealed: B64.encode(blob), reason })?;
    let bytes = Zeroizing::new(B64.decode(&opened.data).map_err(|_| TouchIdError::Failed)?);
    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| TouchIdError::Failed)?;
    Ok(Zeroizing::new(key))
}
