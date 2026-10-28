//! macOS events and services, through swift/System.swift.

use std::ffi::CString;
use std::path::Path;
use std::sync::OnceLock;

use tauri::{AppHandle, Emitter, Manager};

use crate::commands::AppState;

unsafe extern "C" {
    fn vx_watch_away(callback: extern "C" fn(i32));
    fn vx_trash(path: *const std::ffi::c_char) -> i32;
    fn vx_scan_screen_qr(out: *mut std::ffi::c_char, cap: usize) -> i32;
    fn vx_scan_image_qr(data: *const u8, len: usize, out: *mut std::ffi::c_char, cap: usize) -> i32;
    fn vx_check_code(pid: i32, token: *const u8, token_len: usize, requirement: *const std::ffi::c_char) -> i32;
    fn vx_own_team_id(out: *mut std::ffi::c_char, cap: usize);
}

static APP: OnceLock<AppHandle> = OnceLock::new();

/// Lock when the Mac sleeps, its screen locks or another user switches in
/// (unless turned off in Settings). Call once, on the main thread.
pub fn lock_when_away(app: &AppHandle) {
    if APP.set(app.clone()).is_ok() {
        unsafe { vx_watch_away(on_away) };
    }
}

extern "C" fn on_away(_reason: i32) {
    let Some(app) = APP.get() else { return };
    let state = app.state::<AppState>();
    if state.settings().lock_on_sleep && state.is_unlocked() {
        state.lock();
        let _ = app.emit("locked", ());
    }
}

/// Move a file to the Trash, where the user can still get it back.
pub fn trash(path: &Path) -> Result<(), String> {
    let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| "bad path")?;
    match unsafe { vx_trash(c.as_ptr()) } {
        0 => Ok(()),
        _ => Err(format!("Couldn't move {} to the Trash.", path.display())),
    }
}

/// The `otpauth://` URI in a two-factor QR code on screen. Blocks while the
/// screen is captured; call it off the main thread.
pub fn scan_screen_qr() -> Result<String, String> {
    scan(|out, cap| unsafe { vx_scan_screen_qr(out, cap) })
}

/// The `otpauth://` URI in a QR code in an image (PNG, JPEG, …).
pub fn scan_image_qr(image: &[u8]) -> Result<String, String> {
    scan(|out, cap| unsafe { vx_scan_image_qr(image.as_ptr(), image.len(), out, cap) })
}

fn scan(f: impl FnOnce(*mut std::ffi::c_char, usize) -> i32) -> Result<String, String> {
    let mut out = vec![0u8; 4096];
    let status = f(out.as_mut_ptr().cast(), out.len());
    match status {
        0 => {
            let end = out.iter().position(|&b| b == 0).unwrap_or(out.len());
            Ok(String::from_utf8_lossy(&out[..end]).into_owned())
        }
        // Short codes the UI switches on.
        1 => Err("qr-none".into()),
        2 => Err("qr-permission".into()),
        3 => Err("qr-not-totp".into()),
        4 => Err("qr-migration".into()),
        _ => Err("qr-failed".into()),
    }
}

/// A running process, for checking its code signature.
pub enum Process {
    Pid(i32),
    /// From the kernel: can't be confused with a later process reusing the pid.
    AuditToken([u8; 32]),
}

#[derive(Debug, PartialEq)]
pub enum SignatureError {
    /// Not signed the way the requirement asks.
    NotMet,
    /// Updated on disk since it started: it must be restarted.
    ChangedOnDisk,
    /// Couldn't be checked (e.g. the process ended).
    Unknown,
}

/// Whether `process` is validly signed and meets `requirement`, a code
/// requirement such as `anchor apple generic and certificate leaf[subject.OU] = "TEAMID"`.
pub fn check_code(process: &Process, requirement: &str) -> Result<(), SignatureError> {
    let requirement = CString::new(requirement).map_err(|_| SignatureError::Unknown)?;
    let status = match process {
        Process::Pid(pid) => unsafe { vx_check_code(*pid, std::ptr::null(), 0, requirement.as_ptr()) },
        Process::AuditToken(token) => unsafe { vx_check_code(0, token.as_ptr(), token.len(), requirement.as_ptr()) },
    };
    match status {
        0 => Ok(()),
        1 => Err(SignatureError::NotMet),
        3 => Err(SignatureError::ChangedOnDisk),
        _ => Err(SignatureError::Unknown),
    }
}

/// The Apple team this app is signed by; `None` in development builds.
pub fn own_team_id() -> Option<String> {
    static TEAM: OnceLock<Option<String>> = OnceLock::new();
    TEAM.get_or_init(|| {
        let mut out = vec![0u8; 64];
        unsafe { vx_own_team_id(out.as_mut_ptr().cast(), out.len()) };
        let end = out.iter().position(|&b| b == 0).unwrap_or(0);
        Some(String::from_utf8_lossy(&out[..end]).into_owned()).filter(|t| !t.is_empty())
    })
    .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_two_factor_qr_codes_from_images() {
        let uri = scan_image_qr(include_bytes!("../test-fixtures/totp-qr.png")).unwrap();
        assert_eq!(uri, "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example");
        assert_eq!(scan_image_qr(include_bytes!("../test-fixtures/url-qr.png")), Err("qr-not-totp".into()));
        assert_eq!(scan_image_qr(b"not an image"), Err("qr-failed".into()));
    }

    #[test]
    fn checks_code_signatures_of_running_processes() {
        let mut child = std::process::Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let pid = Process::Pid(child.id() as i32);
        // /bin/sleep is part of macOS, signed by Apple, not by a developer team.
        assert_eq!(check_code(&pid, "anchor apple"), Ok(()));
        assert_eq!(check_code(&pid, r#"anchor apple generic and certificate leaf[subject.OU] = "EQHXZ8M8AV""#), Err(SignatureError::NotMet));
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(check_code(&pid, "anchor apple"), Err(SignatureError::Unknown), "a process that ended");
        // Test binaries are ad-hoc signed by the linker.
        assert_eq!(own_team_id(), None);
    }
}
