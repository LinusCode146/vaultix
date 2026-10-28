//! Linux: host manifests in each browser's config folder, and callers
//! checked through /proc.
//!
//! Linux has no code signatures to check. Instead, the browser must be one
//! installed system-wide by the package manager: an allowlisted path where the
//! file and every folder above it belong to root and can't be written by
//! anyone else, so nothing running as this user can have replaced it.
//! Snap and Flatpak browsers can't start native hosts at all.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{Browser, HOST_NAME};

/// Browser executables allowed to launch the host, and their names.
const BROWSERS: &[(&str, &str)] = &[
    ("/opt/google/chrome/chrome", "Google Chrome"),
    ("/opt/google/chrome-beta/chrome", "Google Chrome Beta"),
    ("/opt/google/chrome-unstable/chrome", "Google Chrome Dev"),
    ("/opt/microsoft/msedge/msedge", "Microsoft Edge"),
    ("/opt/microsoft/msedge-beta/msedge", "Microsoft Edge Beta"),
    ("/opt/brave.com/brave/brave", "Brave"),
    ("/opt/vivaldi/vivaldi-bin", "Vivaldi"),
    ("/usr/lib/chromium/chromium", "Chromium"),
    ("/usr/lib/chromium-browser/chromium-browser", "Chromium"),
    ("/usr/lib64/chromium-browser/chromium-browser", "Chromium"),
];

/// Where each browser looks for native messaging host manifests, relative to
/// `~/.config`. A manifest is only written for browsers whose folder exists.
const BROWSER_HOST_DIRS: &[&str] = &[
    "google-chrome",
    "google-chrome-beta",
    "google-chrome-unstable",
    "microsoft-edge",
    "microsoft-edge-beta",
    "BraveSoftware/Brave-Browser",
    "vivaldi",
    "chromium",
];

pub fn install_manifests(manifest: &Value) -> Vec<PathBuf> {
    let Some(config) = config_home() else { return vec![] };
    let mut written = Vec::new();
    for browser_dir in BROWSER_HOST_DIRS {
        let browser = config.join(browser_dir);
        if !browser.is_dir() {
            continue;
        }
        let dir = browser.join("NativeMessagingHosts");
        let file = dir.join(format!("{HOST_NAME}.json"));
        let ok = fs::create_dir_all(&dir).is_ok() && fs::write(&file, serde_json::to_vec_pretty(manifest).unwrap()).is_ok();
        if ok {
            written.push(file);
        }
    }
    written
}

fn config_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
}

/// What the UI calls the browser at `path` (an executable).
pub fn browser_name(path: &Path) -> Option<String> {
    BROWSERS.iter().find(|(p, _)| Path::new(p) == path).map(|(_, n)| n.to_string())
}

/// Check the caller, and return the executable of the browser it runs in.
pub fn verify_peer(stream: &UnixStream, host_path: &Path) -> Result<Browser, String> {
    let cred = peer_cred(stream).map_err(|e| format!("can't identify caller: {e}"))?;
    // SAFETY: getuid can't fail.
    if cred.uid != unsafe { libc::getuid() } {
        return Err("caller runs as another user".into());
    }
    let path = exe(cred.pid as u32).ok_or("can't identify caller")?;
    if path.canonicalize().ok().as_deref() != Some(host_path) {
        return Err(format!("caller {} is not the Vaultix native host", path.display()));
    }
    let parent_pid = parent_pid(cred.pid as u32).ok_or("can't identify the host's browser")?;
    let parent = exe(parent_pid).ok_or("can't identify the host's browser")?;
    browser(&parent)
}

/// Whether `exe` is an allowed browser that only root can change.
fn browser(exe: &Path) -> Result<Browser, String> {
    let shown = exe.to_string_lossy();
    // The kernel marks an executable replaced since it started.
    if let Some(original) = shown.strip_suffix(" (deleted)") {
        let name = browser_name(Path::new(original)).unwrap_or_else(|| "Your browser".into());
        return Err(format!("{name} was updated while running; restart it to use Vaultix"));
    }
    let name = browser_name(exe).ok_or_else(|| format!("{} is not a supported browser", exe.display()))?;
    if !root_owned(exe) {
        return Err(format!("{name} at {} can be changed by other users, so Vaultix doesn't trust it", exe.display()));
    }
    Ok(Browser { path: exe.to_path_buf(), name })
}

/// `path` and every folder above it are owned by root and not writable by group or others.
fn root_owned(path: &Path) -> bool {
    path.ancestors().all(|p| fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0))
}

fn peer_cred(stream: &UnixStream) -> io::Result<libc::ucred> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`.
    let rc = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len)
    };
    if rc == 0 { Ok(cred) } else { Err(io::Error::last_os_error()) }
}

fn exe(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

fn parent_pid(pid: u32) -> Option<u32> {
    // The command name (field 2) is in parentheses and may contain spaces.
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 2..];
    rest.split(' ').nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn browser_allowlist() {
        assert!(browser(Path::new("/tmp/chrome")).unwrap_err().contains("not a supported browser"));
        assert!(browser(Path::new("/opt/google/chrome/chrome (deleted)")).unwrap_err().contains("restart it"));
        assert_eq!(browser_name(Path::new("/opt/microsoft/msedge/msedge")).as_deref(), Some("Microsoft Edge"));
        assert!(root_owned(Path::new("/usr/bin")) || unsafe { libc::getuid() } == 0);
        let dir = tempfile::tempdir().unwrap();
        assert!(!root_owned(dir.path()) || unsafe { libc::getuid() } == 0, "a user's folder isn't root-owned");
    }

    #[test]
    fn rejects_connections_from_other_processes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (server_side, _) = listener.accept().unwrap();
        let err = verify_peer(&server_side, Path::new("/nonexistent/vaultix-native-host")).unwrap_err();
        assert!(err.contains("is not the Vaultix native host"), "{err}");
        assert_eq!(peer_cred(&server_side).unwrap().pid as u32, std::process::id());
        assert_eq!(parent_pid(std::process::id()), Some(std::os::unix::process::parent_id()));
    }
}
