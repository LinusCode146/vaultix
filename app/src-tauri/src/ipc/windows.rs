//! Windows: host manifests registered under HKCU, and callers checked by
//! process path and Authenticode signature.

use std::ffi::c_void;
use std::fs;
use std::io;
use std::os::windows::io::AsRawSocket;
use std::path::{Path, PathBuf};

use serde_json::Value;
use uds_windows::UnixStream;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Networking::WinSock::{SOCKET, WSAIoctl};
use windows::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
use windows::core::{PCWSTR, PWSTR};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

use super::{Browser, HOST_NAME};

/// Browsers allowed to launch the host: executable name, display name, and
/// the publisher their Authenticode certificate is issued to.
const BROWSERS: &[(&str, &str, &str)] = &[
    ("chrome.exe", "Google Chrome", "Google LLC"),
    ("msedge.exe", "Microsoft Edge", "Microsoft Corporation"),
    ("brave.exe", "Brave", "Brave Software, Inc."),
    ("vivaldi.exe", "Vivaldi", "Vivaldi Technologies AS"),
];

/// Registry keys (under HKCU\Software) where Chromium browsers look for hosts.
const BROWSER_KEYS: &[&str] = &[
    r"Google\Chrome",
    r"Chromium",
    r"Microsoft\Edge",
    r"BraveSoftware\Brave-Browser",
    r"Vivaldi",
];

/// `SIO_AF_UNIX_GETPEERPID`: the pid of the other end of a Unix socket.
const SIO_AF_UNIX_GETPEERPID: u32 = 0x5800_0100;

pub fn install_manifests(manifest: &Value) -> Vec<PathBuf> {
    let Some(dir) = std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("app.vaultix.desktop")) else { return vec![] };
    let file = dir.join(format!("{HOST_NAME}.json"));
    if fs::create_dir_all(&dir).is_err() || fs::write(&file, serde_json::to_vec_pretty(manifest).unwrap()).is_err() {
        return vec![];
    }
    let software = RegKey::predef(HKEY_CURRENT_USER);
    let mut written = Vec::new();
    for browser in BROWSER_KEYS {
        let key = format!(r"Software\{browser}\NativeMessagingHosts\{HOST_NAME}");
        let ok = software.create_subkey(&key).and_then(|(k, _)| k.set_value("", &file.to_string_lossy().into_owned())).is_ok();
        if ok {
            written.push(PathBuf::from(format!(r"HKCU\{key}")));
        }
    }
    written
}

/// What the UI calls the browser at `path` (an executable).
pub fn browser_name(path: &Path) -> Option<String> {
    let file = path.file_name()?.to_string_lossy().to_lowercase();
    BROWSERS.iter().find(|(exe, _, _)| *exe == file).map(|(_, name, _)| name.to_string())
}

/// Check the caller, and return the executable of the browser it runs in.
pub fn verify_peer(stream: &UnixStream, host_path: &Path) -> Result<Browser, String> {
    let pid = peer_pid(stream).map_err(|e| format!("can't identify caller: {e}"))?;
    let path = exe(pid).ok_or("can't identify caller")?;
    if !same_file(&path, host_path) {
        return Err(format!("caller {} is not the Vaultix native host", path.display()));
    }
    let mut parent_pid = parent_pid(pid).ok_or("can't identify the host's browser")?;
    let mut parent = exe(parent_pid).ok_or("can't identify the host's browser")?;
    // Chrome starts native hosts through cmd.exe.
    if parent.file_name().is_some_and(|n| n.eq_ignore_ascii_case("cmd.exe")) {
        parent_pid = self::parent_pid(parent_pid).ok_or("can't identify the host's browser")?;
        parent = exe(parent_pid).ok_or("can't identify the host's browser")?;
    }
    browser(&parent)
}

fn browser(exe: &Path) -> Result<Browser, String> {
    let file = exe.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let (_, name, publisher) =
        BROWSERS.iter().find(|(e, _, _)| *e == file).ok_or_else(|| format!("{} is not a supported browser", exe.display()))?;
    match signer(exe) {
        Some(signer) if signer == *publisher => Ok(Browser { path: exe.to_path_buf(), name: name.to_string() }),
        Some(signer) => Err(format!("{name} is signed by {signer}, not {publisher}")),
        None => Err(format!("{name} isn't signed by its maker")),
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| p.to_string_lossy().trim_start_matches(r"\\?\").to_lowercase();
    norm(a) == norm(b)
}

fn peer_pid(stream: &UnixStream) -> io::Result<u32> {
    let mut pid = 0u32;
    let mut returned = 0u32;
    // SAFETY: WSAIoctl writes at most size_of::<u32>() bytes into `pid`.
    let rc = unsafe {
        WSAIoctl(
            SOCKET(stream.as_raw_socket() as usize),
            SIO_AF_UNIX_GETPEERPID,
            None,
            0,
            Some((&mut pid as *mut u32).cast()),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
            None,
            None,
        )
    };
    if rc == 0 { Ok(pid) } else { Err(io::Error::last_os_error()) }
}

fn exe(pid: u32) -> Option<PathBuf> {
    // SAFETY: the handle is closed below; the buffer size is passed along.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).is_ok();
        let _ = CloseHandle(process);
        ok.then(|| PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
    }
}

fn parent_pid(pid: u32) -> Option<u32> {
    // SAFETY: a process snapshot, walked with correctly sized entries, then closed.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut found = None;
        let mut ok = Process32FirstW(snapshot, &mut entry).is_ok();
        while ok {
            if entry.th32ProcessID == pid {
                found = Some(entry.th32ParentProcessID);
                break;
            }
            ok = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
        found
    }
}

/// Who signed `file`, if its Authenticode signature is valid: the subject
/// name of the signing certificate, such as "Google LLC".
fn signer(file: &Path) -> Option<String> {
    let path: Vec<u16> = file.as_os_str().encode_wide_nul();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file_info },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` and `file_info` outlive both calls; the state is closed at the end.
    unsafe {
        let valid = WinVerifyTrust(HWND::default(), &mut action, (&mut data as *mut WINTRUST_DATA).cast::<c_void>()) == 0;
        let name = valid.then(|| signer_name(data.hWVTStateData)).flatten();
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(HWND::default(), &mut action, (&mut data as *mut WINTRUST_DATA).cast::<c_void>());
        name
    }
}

/// SAFETY: `state` must come from a successful WinVerifyTrust, not yet closed.
unsafe fn signer_name(state: HANDLE) -> Option<String> {
    unsafe {
        let provider = WTHelperProvDataFromStateData(state);
        if provider.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
        if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
            return None;
        }
        let cert = (*(*signer).pasCertChain).pCert;
        let mut buf = vec![0u16; 256];
        let len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
        (len > 1).then(|| String::from_utf16_lossy(&buf[..len as usize - 1]))
    }
}

trait EncodeWideNul {
    fn encode_wide_nul(&self) -> Vec<u16>;
}

impl EncodeWideNul for std::ffi::OsStr {
    fn encode_wide_nul(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(Some(0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uds_windows::UnixListener;

    #[test]
    fn installed_browsers_are_signed_by_the_listed_publisher() {
        // GitHub's Windows runners come with Chrome and Edge.
        let installed = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ];
        for exe in installed.iter().map(Path::new).filter(|p| p.exists()) {
            assert!(browser(exe).is_ok(), "{}: {:?}", exe.display(), browser(exe).err());
        }
        let unsigned = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(signer(unsigned.path()), None);
    }

    #[test]
    fn browser_allowlist() {
        assert!(browser(Path::new(r"C:\Temp\evil.exe")).unwrap_err().contains("not a supported browser"));
        let fake = tempfile::tempdir().unwrap();
        let chrome = fake.path().join("chrome.exe");
        fs::write(&chrome, b"MZ").unwrap();
        assert!(browser(&chrome).unwrap_err().contains("isn't signed"));
        assert_eq!(browser_name(Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe")).as_deref(), Some("Google Chrome"));
    }

    #[test]
    fn rejects_connections_from_other_processes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (server_side, _) = listener.accept().unwrap();
        let err = verify_peer(&server_side, Path::new(r"C:\nonexistent\vaultix-native-host.exe")).unwrap_err();
        assert!(err.contains("is not the Vaultix native host"), "{err}");
        assert_eq!(peer_pid(&server_side).unwrap(), std::process::id());
        assert!(parent_pid(std::process::id()).is_some());
    }
}
