//! System events and services: locking when the computer is left, the Trash,
//! and reading two-factor QR codes. One implementation per OS, below.

use std::sync::OnceLock;

use tauri::{AppHandle, Emitter, Manager};

use crate::commands::AppState;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{Process, SignatureError, check_code, own_team_id, scan_image_qr, scan_screen_qr, trash};

#[cfg(not(target_os = "macos"))]
mod portable;
#[cfg(not(target_os = "macos"))]
pub use portable::{scan_image_qr, scan_screen_qr, trash};

#[cfg(windows)]
#[path = "system/windows.rs"]
mod os;
#[cfg(target_os = "linux")]
#[path = "system/linux.rs"]
mod os;
#[cfg(target_os = "macos")]
use macos as os;

static APP: OnceLock<AppHandle> = OnceLock::new();

/// Lock when the computer sleeps, its screen locks or another user switches
/// in (unless turned off in Settings). Call once, on the main thread.
pub fn lock_when_away(app: &AppHandle) {
    if APP.set(app.clone()).is_ok() {
        os::watch_away(on_away);
    }
}

fn on_away() {
    let Some(app) = APP.get() else { return };
    let state = app.state::<AppState>();
    if state.settings().lock_on_sleep && state.is_unlocked() {
        state.lock();
        let _ = app.emit("locked", ());
    }
}
