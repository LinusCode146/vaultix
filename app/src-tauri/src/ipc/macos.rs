//! macOS: host manifests in each browser's Application Support folder, and
//! callers checked by their code signatures.

use std::fs;
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{Browser, HOST_NAME};
use crate::system::{Process, SignatureError, check_code, own_team_id};

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

/// Register the native host with every installed Chromium browser.
pub fn install_manifests(manifest: &Value) -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return vec![] };
    let support = home.join("Library/Application Support");
    let mut written = Vec::new();
    for (browser_dir, hosts_dir) in BROWSER_HOST_DIRS {
        let browser = support.join(browser_dir);
        if !browser.is_dir() {
            continue;
        }
        let dir = browser.join(hosts_dir);
        let file = dir.join(format!("{HOST_NAME}.json"));
        let ok = fs::create_dir_all(&dir).is_ok()
            && fs::write(&file, serde_json::to_vec_pretty(manifest).unwrap()).is_ok();
        if ok {
            written.push(file);
        }
    }
    written
}

/// What the UI calls the browser at `path` (an `.app` bundle).
pub fn browser_name(path: &Path) -> Option<String> {
    path.file_stem().map(|s| s.to_string_lossy().into_owned())
}

/// Check the caller, and return the `.app` bundle of the browser it runs in.
pub fn verify_peer(stream: &UnixStream, host_path: &Path) -> Result<Browser, String> {
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
        Ok(()) => Ok(Browser { path: bundle, name }),
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
    use std::os::unix::net::UnixListener;

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
