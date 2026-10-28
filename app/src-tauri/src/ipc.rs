//! Local socket the native messaging host connects to.
//!
//! ```text
//! extension ──native messaging──► vaultix-native-host ──unix socket──► this server
//!            (browser spawns it)   (dumb pipe + hello)                 (vault access)
//! ```
//!
//! Who may connect is checked three ways before any request is answered:
//! 1. the socket file is only accessible to this user (0600, or the user's
//!    private AppData folder on Windows);
//! 2. the connecting process must be our own `vaultix-native-host` binary;
//! 3. that process's parent must be an installed browser that its maker
//!    signed (or, on Linux, that only root can change), and the browser must
//!    have launched it for our extension ID (reported in the hello message).
//!
//! How 2 and 3 are checked differs per OS: see `ipc/macos.rs`, `ipc/windows.rs`
//! and `ipc/linux.rs`. Windows 10 and later have Unix sockets too.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;

use serde::Deserialize;
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};

use crate::commands::{AppState, copy_with_auto_clear};
use crate::native::{Effects, Envelope, Request, Response, handle, pending_fill};

#[cfg(target_os = "macos")]
#[path = "ipc/macos.rs"]
mod os;
#[cfg(target_os = "linux")]
#[path = "ipc/linux.rs"]
mod os;
#[cfg(windows)]
#[path = "ipc/windows.rs"]
mod os;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use uds_windows::{UnixListener, UnixStream};

/// The browser the native host runs in.
#[derive(Debug)]
pub struct Browser {
    /// The `.app` bundle on macOS, the executable elsewhere: what Open & Fill opens.
    pub path: PathBuf,
    /// "Microsoft Edge", for prompts.
    pub name: String,
}

pub const HOST_NAME: &str = "app.vaultix.native";
pub const HOST_BINARY: &str = "vaultix-native-host";
pub const SOCKET_FILE: &str = "native.sock";
/// Fixed by the public key in the extension's manifest.json.
pub const EXTENSION_ORIGINS: &[&str] = &["chrome-extension://aenaphgdphjgffnmeijbgjfdnkackjke/"];
const MAX_FRAME: usize = 1024 * 1024;

/// The host binary ships next to the app binary (target/debug in development,
/// Contents/MacOS in the app bundle, the install folder on Windows, /usr/bin on Linux).
pub fn host_binary_path() -> Option<PathBuf> {
    let path = std::env::current_exe().ok()?.parent()?.join(HOST_BINARY).with_extension(std::env::consts::EXE_EXTENSION);
    let path = path.canonicalize().ok()?;
    // canonicalize() gives a \\?\ path on Windows, which browsers can't run.
    #[cfg(windows)]
    let path = PathBuf::from(path.to_string_lossy().trim_start_matches(r"\\?\"));
    Some(path)
}

pub use os::browser_name;

/// Register the native host with every installed Chromium browser.
pub fn install_manifests(host_path: &Path) -> Vec<PathBuf> {
    let manifest = json!({
        "name": HOST_NAME,
        "description": "Vaultix password manager",
        "path": host_path,
        "type": "stdio",
        "allowed_origins": EXTENSION_ORIGINS,
    });
    os::install_manifests(&manifest)
}

/// Start listening. Runs for the lifetime of the app.
pub fn start(app: AppHandle, socket_path: PathBuf, host_path: PathBuf) -> io::Result<()> {
    if let Some(dir) = socket_path.parent() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    }
    // A socket left over from a crash would make bind() fail.
    let _ = fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    #[cfg(unix)]
    fs::set_permissions(&socket_path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;

    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let app = app.clone();
            let host_path = host_path.clone();
            thread::spawn(move || {
                if let Err(e) = serve(&app, stream, &host_path) {
                    eprintln!("[vaultix] native connection closed: {e}");
                }
            });
        }
    });
    Ok(())
}

#[derive(Deserialize)]
struct Hello {
    origin: String,
}

fn serve(app: &AppHandle, mut stream: UnixStream, host_path: &Path) -> io::Result<()> {
    let browser = match os::verify_peer(&stream, host_path) {
        Ok(browser) => browser,
        Err(reason) => {
            write_frame(&mut stream, &json!({ "type": "rejected", "error": reason }))?;
            return Err(io::Error::other(reason));
        }
    };
    let hello: Hello = serde_json::from_slice(&read_frame(&mut stream)?)?;
    if !EXTENSION_ORIGINS.contains(&hello.origin.as_str()) {
        write_frame(&mut stream, &json!({ "type": "rejected", "error": "unknown extension" }))?;
        return Err(io::Error::other(format!("unknown extension origin {}", hello.origin)));
    }
    write_frame(&mut stream, &json!({ "type": "ready" }))?;
    let browser_name = browser.name;
    app.state::<AppState>().remember_browser(browser.path);

    loop {
        let frame = read_frame(&mut stream)?;
        let response = match serde_json::from_slice::<Envelope>(&frame) {
            Err(e) => {
                let id = serde_json::from_slice::<serde_json::Value>(&frame)
                    .ok()
                    .and_then(|v| v["id"].as_u64())
                    .unwrap_or(0);
                Response::err(id, format!("bad request: {e}"))
            }
            Ok(Envelope { id, request }) => {
                let mut effects = Effects::default();
                let state = app.state::<AppState>();
                let result = match request {
                    // Blocks until the user responds to the prompt; the vault
                    // must not be locked meanwhile, so this happens out here.
                    Request::UnlockTouchId => state
                        .unlock_with_touch_id(&format!("unlock your vault to fill a password in {browser_name}"))
                        .map(|()| {
                            let _ = app.emit("unlocked", ());
                            json!({})
                        }),
                    Request::PendingFill { url, password_step } => {
                        let vault = state.vault.lock().unwrap();
                        let mut pending = state.pending_fill.lock().unwrap();
                        pending_fill(vault.as_ref(), &mut pending, &url, password_step, &mut effects)
                    }
                    Request::Status => {
                        let locked = state.vault.lock().unwrap().is_none();
                        Ok(json!({ "locked": locked, "touchId": locked && state.touch_id_usable() }))
                    }
                    request => {
                        let is_logins = matches!(request, Request::LoginsForPage { .. });
                        let result = {
                            let mut vault = state.vault.lock().unwrap();
                            handle(vault.as_mut(), request, &mut effects)
                        };
                        if is_logins { result.map(|logins| with_icons(&state, logins)) } else { result }
                    }
                };
                apply(app, effects);
                match result {
                    Ok(value) => Response::ok(id, value),
                    Err(error) => Response::err(id, error),
                }
            }
        };
        write_frame(&mut stream, &serde_json::to_value(&response)?)?;
    }
}

/// Native messages are limited to 1 MB; leave room for everything else.
const MAX_ICON_BYTES: usize = 96 * 1024;
const MAX_ICONS_TOTAL: usize = 512 * 1024;

/// Add each login's website icon, if the app already has it cached (the
/// extension's menu shows it instead of letters). Never fetches anything.
fn with_icons(state: &AppState, mut logins: serde_json::Value) -> serde_json::Value {
    let Some(list) = logins.as_array_mut() else { return logins };
    let mut total = 0;
    for login in list {
        let url = {
            let vault = state.vault.lock().unwrap();
            let id = login["id"].as_str().and_then(|s| uuid::Uuid::parse_str(s).ok());
            vault.as_ref().zip(id).and_then(|(v, id)| v.get(id)).and_then(|i| i.urls.first().cloned())
        };
        let icon = url
            .and_then(|u| state.icons.cached(&state.vault, &u))
            .filter(|i| i.len() <= MAX_ICON_BYTES && total + i.len() <= MAX_ICONS_TOTAL);
        total += icon.as_ref().map_or(0, String::len);
        login["icon"] = icon.map_or(serde_json::Value::Null, serde_json::Value::String);
    }
    logins
}

fn apply(app: &AppHandle, effects: Effects) {
    if effects.show_app
        && let Some(window) = app.get_webview_window("main")
    {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
    if effects.vault_changed {
        let _ = app.emit("vault-changed", ());
    }
    if let Some(code) = effects.copy_totp {
        let _ = copy_with_auto_clear(app, code);
    }
}

// ---------- Framing: u32 little-endian length + JSON (same as native messaging on x86 and ARM) ----------

pub fn read_frame(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::other("frame too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_frame(stream: &mut impl Write, value: &serde_json::Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_limit() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &json!({ "a": 1 })).unwrap();
        assert_eq!(read_frame(&mut buf.as_slice()).unwrap(), br#"{"a":1}"#);

        let mut huge = (MAX_FRAME as u32 + 1).to_le_bytes().to_vec();
        huge.extend([0u8; 8]);
        assert!(read_frame(&mut huge.as_slice()).is_err());
    }
}
