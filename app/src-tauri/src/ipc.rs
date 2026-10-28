//! Local socket the native messaging host connects to.
//!
//! ```text
//! extension ──native messaging──► vaultix-native-host ──unix socket──► this server
//!            (browser spawns it)   (dumb pipe + hello)                 (vault access)
//! ```
//!
//! Who may connect is checked three ways before any request is answered:
//! 1. the socket file is only accessible to this user (0600);
//! 2. the connecting process must be our own `vaultix-native-host` binary, by
//!    path and by code signature: in a signed release, signed by the same Apple
//!    team as this app; in a development build, at least unmodified;
//! 3. that process's parent must be an installed browser, signed by its
//!    maker's Apple team, and the browser must have launched it for our
//!    extension ID (reported in the hello message).

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;

use serde::Deserialize;
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};

use crate::commands::{AppState, copy_with_auto_clear};
use crate::native::{Effects, Envelope, Request, Response, handle, pending_fill};
use crate::system::{Process, SignatureError, check_code, own_team_id};

pub const HOST_NAME: &str = "app.vaultix.native";
pub const HOST_BINARY: &str = "vaultix-native-host";
pub const SOCKET_FILE: &str = "native.sock";
/// Fixed by the public key in the extension's manifest.json.
pub const EXTENSION_ORIGINS: &[&str] = &["chrome-extension://aenaphgdphjgffnmeijbgjfdnkackjke/"];
const MAX_FRAME: usize = 1024 * 1024;

/// Browsers allowed to launch the host: app bundle name, and the Apple team
/// that signs it (`codesign -dv <app>` shows it as TeamIdentifier). Chromium
/// itself is unsigned, so it can't be told apart from an impostor and isn't here.
const BROWSER_BUNDLES: &[(&str, &str)] = &[
    ("Google Chrome.app", "EQHXZ8M8AV"),
    ("Google Chrome Beta.app", "EQHXZ8M8AV"),
    ("Google Chrome Canary.app", "EQHXZ8M8AV"),
    ("Microsoft Edge.app", "UBF8T346G9"),
    ("Microsoft Edge Beta.app", "UBF8T346G9"),
    ("Brave Browser.app", "KL8N8XSYF4"),
    ("Arc.app", "S6N382Y83G"),
    ("Vivaldi.app", "4XF3XNRN6Y"),
];

/// Where each browser looks for native messaging host manifests, relative to
/// `~/Library/Application Support`. A manifest is only written for browsers
/// whose profile folder already exists.
const BROWSER_HOST_DIRS: &[(&str, &str)] = &[
    ("Google/Chrome", "NativeMessagingHosts"),
    ("Google/Chrome Beta", "NativeMessagingHosts"),
    ("Google/Chrome Canary", "NativeMessagingHosts"),
    ("Microsoft Edge", "NativeMessagingHosts"),
    ("Microsoft Edge Beta", "NativeMessagingHosts"),
    ("BraveSoftware/Brave-Browser", "NativeMessagingHosts"),
    ("Arc/User Data", "NativeMessagingHosts"),
    ("Vivaldi", "NativeMessagingHosts"),
];

/// The host binary ships next to the app binary (target/debug in development,
/// Contents/MacOS in the app bundle).
pub fn host_binary_path() -> Option<PathBuf> {
    let path = std::env::current_exe().ok()?.parent()?.join(HOST_BINARY);
    path.canonicalize().ok()
}

/// Register the native host with every installed Chromium browser.
pub fn install_manifests(host_path: &Path) -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return vec![] };
    let support = home.join("Library/Application Support");
    let manifest = json!({
        "name": HOST_NAME,
        "description": "Vaultix password manager",
        "path": host_path,
        "type": "stdio",
        "allowed_origins": EXTENSION_ORIGINS,
    });
    let mut written = Vec::new();
    for (browser_dir, hosts_dir) in BROWSER_HOST_DIRS {
        let browser = support.join(browser_dir);
        if !browser.is_dir() {
            continue;
        }
        let dir = browser.join(hosts_dir);
        let file = dir.join(format!("{HOST_NAME}.json"));
        let ok = fs::create_dir_all(&dir).is_ok()
            && fs::write(&file, serde_json::to_vec_pretty(&manifest).unwrap()).is_ok();
        if ok {
            written.push(file);
        }
    }
    written
}

/// Start listening. Runs for the lifetime of the app.
pub fn start(app: AppHandle, socket_path: PathBuf, host_path: PathBuf) -> io::Result<()> {
    if let Some(dir) = socket_path.parent() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    // A socket left over from a crash would make bind() fail.
    let _ = fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

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
    let browser = match verify_peer(&stream, host_path) {
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
    let browser_name = browser.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "your browser".into());
    app.state::<AppState>().remember_browser(browser);

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

// ---------- Framing: u32 little-endian length + JSON (same as native messaging on macOS) ----------

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

// ---------- Peer verification (macOS) ----------

/// Check the caller, and return the `.app` bundle of the browser it runs in.
fn verify_peer(stream: &UnixStream, host_path: &Path) -> Result<PathBuf, String> {
    let pid = peer_pid(stream).map_err(|e| format!("can't identify caller: {e}"))?;
    let path = pid_path(pid).ok_or("can't identify caller")?;
    if path.canonicalize().ok().as_deref() != Some(host_path) {
        return Err(format!("caller {} is not the Vaultix native host", path.display()));
    }
    let token = peer_audit_token(stream).map_err(|e| format!("can't identify caller: {e}"))?;
    let host_requirement = match own_team_id() {
        Some(team) => signed_by(&team),
        // Development build: nothing to compare with, but the running host
        // must still be the file at `host_path`, unmodified.
        None => "always".to_string(),
    };
    check_code(&Process::AuditToken(token), &host_requirement)
        .map_err(|e| format!("the native host's code signature isn't valid ({e:?})"))?;

    let parent_pid = parent_pid(pid).ok_or("can't identify the host's browser")?;
    let parent = pid_path(parent_pid).ok_or("can't identify the host's browser")?;
    let (bundle, team) = browser_bundle(&parent, code_sign_clone_dir().as_deref())
        .ok_or_else(|| format!("{} is not a supported browser", parent.display()))?;
    let name = bundle.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    match check_code(&Process::Pid(parent_pid), &signed_by(team)) {
        Ok(()) => Ok(bundle),
        Err(SignatureError::ChangedOnDisk) => Err(format!("{name} was updated while running; restart it to use Vaultix")),
        Err(e) => Err(format!("{name} isn't signed by its maker ({e:?})")),
    }
}

/// A code requirement: signed with an Apple-issued certificate of `team`.
fn signed_by(team: &str) -> String {
    format!(r#"anchor apple generic and certificate leaf[subject.OU] = "{team}""#)
}

fn app_roots() -> Vec<PathBuf> {
    let home_apps = std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Applications"));
    [Some(PathBuf::from("/Applications")), home_apps].into_iter().flatten().collect()
}

/// The installed `.app` bundle of a supported browser, and its maker's team, given its executable.
///
/// Chromium browsers updated in the background run from a copy of themselves
/// until restarted, at `<clones>/com.vendor.code_sign_clone/code_sign_clone.XXXXXX/Name.app.bundle/...`.
/// That copy counts as the installed browser of the same name.
fn browser_bundle(exe: &Path, clones: Option<&Path>) -> Option<(PathBuf, &'static str)> {
    let roots = app_roots();
    for root in &roots {
        if let Some((bundle, team)) = BROWSER_BUNDLES.iter().find(|(b, _)| exe.starts_with(root.join(b))) {
            return Some((root.join(bundle), team));
        }
    }
    let rel = exe.strip_prefix(clones?).ok()?;
    let mut parts = rel.components().map(|c| c.as_os_str().to_string_lossy());
    let (vendor, clone, copy) = (parts.next()?, parts.next()?, parts.next()?);
    if !vendor.ends_with(".code_sign_clone") || !clone.starts_with("code_sign_clone.") {
        return None;
    }
    let (bundle, team) = BROWSER_BUNDLES.iter().find(|(b, _)| copy == format!("{b}.bundle"))?;
    roots.iter().map(|r| r.join(bundle)).find(|p| p.is_dir()).map(|p| (p, *team))
}

/// Where macOS keeps code-sign clones: the `X` folder next to this user's temp
/// folder (`/private/var/folders/xx/yyyy/X`), private to the user.
fn code_sign_clone_dir() -> Option<PathBuf> {
    let mut buf = vec![0u8; 1024];
    // SAFETY: confstr writes at most `buf.len()` bytes, NUL-terminated.
    let len = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr().cast(), buf.len()) };
    if len == 0 || len > buf.len() {
        return None;
    }
    buf.truncate(len - 1);
    let temp = PathBuf::from(String::from_utf8(buf).ok()?).canonicalize().ok()?;
    Some(temp.parent()?.join("X"))
}

fn peer_pid(stream: &UnixStream) -> io::Result<libc::pid_t> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `pid`.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    if rc == 0 { Ok(pid) } else { Err(io::Error::last_os_error()) }
}

/// The kernel's audit token for the peer: identifies the process exactly,
/// unlike its pid, which a new process could take over.
fn peer_audit_token(stream: &UnixStream) -> io::Result<[u8; 32]> {
    let mut token = [0u8; 32];
    let mut len = token.len() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `token`.
    let rc = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_LOCAL, libc::LOCAL_PEERTOKEN, token.as_mut_ptr().cast(), &mut len)
    };
    if rc == 0 && len as usize == token.len() { Ok(token) } else { Err(io::Error::last_os_error()) }
}

fn pid_path(pid: libc::pid_t) -> Option<PathBuf> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: proc_pidpath writes at most `buf.len()` bytes.
    let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if len <= 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(PathBuf::from(String::from_utf8(buf).ok()?))
}

fn parent_pid(pid: libc::pid_t) -> Option<libc::pid_t> {
    // SAFETY: proc_bsdinfo is plain old data; proc_pidinfo fills at most `size` bytes.
    unsafe {
        let mut info: libc::proc_bsdinfo = std::mem::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let rc = libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size);
        (rc == size).then_some(info.pbi_ppid as libc::pid_t)
    }
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

    #[test]
    fn browser_allowlist() {
        let allowed = |p: &str| browser_bundle(Path::new(p), None);
        assert_eq!(
            allowed("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            Some((PathBuf::from("/Applications/Microsoft Edge.app"), "UBF8T346G9"))
        );
        assert!(allowed("/Applications/Chromium.app/Contents/MacOS/Chromium").is_none(), "unsigned");
        assert!(allowed("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome").is_some());
        assert!(allowed("/Applications/Google Chrome.app.evil/x").is_none());
        assert!(allowed("/tmp/Google Chrome.app/Contents/MacOS/Google Chrome").is_none());
        assert!(allowed("/bin/zsh").is_none());
    }

    #[test]
    fn browser_running_from_code_sign_clone() {
        let clones = Path::new("/private/var/folders/ab/cd/X");
        let exe = clones.join("com.example.code_sign_clone/code_sign_clone.Ab12Cd/Fake.app.bundle/Contents/MacOS/Fake");
        // Not a supported browser name.
        assert!(browser_bundle(&exe, Some(clones)).is_none());
        // Outside the clones folder.
        let elsewhere = Path::new("/tmp/com.microsoft.edgemac.code_sign_clone/code_sign_clone.x/Microsoft Edge.app.bundle/e");
        assert!(browser_bundle(elsewhere, Some(clones)).is_none());
        // Wrong layout.
        let flat = clones.join("Microsoft Edge.app.bundle/Contents/MacOS/Microsoft Edge");
        assert!(browser_bundle(&flat, Some(clones)).is_none());
        // A real clone maps to the installed browser, if there is one.
        let edge = clones.join("com.microsoft.edgemac.code_sign_clone/code_sign_clone.UJy7y6/Microsoft Edge.app.bundle/Contents/MacOS/Microsoft Edge");
        let installed = Path::new("/Applications/Microsoft Edge.app");
        assert_eq!(browser_bundle(&edge, Some(clones)).map(|(b, _)| b).as_deref(), installed.is_dir().then_some(installed));
        assert!(code_sign_clone_dir().is_some_and(|d| d.ends_with("X")));
    }

    #[test]
    fn rejects_connections_from_other_processes() {
        // The test binary is not the native host, so the server must refuse it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (server_side, _) = listener.accept().unwrap();
        let err = verify_peer(&server_side, Path::new("/nonexistent/vaultix-native-host")).unwrap_err();
        assert!(err.contains("is not the Vaultix native host"), "{err}");
        // But the caller was correctly identified as this very process.
        assert_eq!(peer_pid(&server_side).unwrap(), std::process::id() as libc::pid_t);
        let token = peer_audit_token(&server_side).unwrap();
        assert_eq!(check_code(&Process::AuditToken(token), "always"), Ok(()), "the test binary is validly (ad-hoc) signed");
    }

    #[test]
    fn installed_browsers_are_signed_by_the_listed_team() {
        // Checks the table against the browsers on this Mac (statically, from disk).
        for (bundle, team) in BROWSER_BUNDLES {
            let path = Path::new("/Applications").join(bundle);
            if !path.is_dir() {
                continue;
            }
            let out = std::process::Command::new("codesign").arg("-dv").arg(&path).output().unwrap();
            let info = String::from_utf8_lossy(&out.stderr);
            assert!(info.contains(&format!("TeamIdentifier={team}")), "{bundle}: {info}");
        }
    }
}
