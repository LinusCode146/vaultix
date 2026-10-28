//! Native messaging host for the Vaultix browser extension.
//!
//! The browser starts this program when the extension connects, and talks to
//! it over stdin/stdout. It holds no secrets and makes no decisions: it
//! connects to the running Vaultix app's socket, introduces the extension
//! (the browser passes the extension's origin as the first argument), and then
//! passes frames through in both directions. The app checks who is calling.
//!
//! If the app isn't running, the host says `{"type":"not-running"}` and waits
//! for the extension to answer `{"type":"launch"}` (it then starts the app)
//! or anything else (it gives up). Background checks, such as "is an Open &
//! Fill waiting for this page?", must not start the app on every page.
//!
//! Both sides use the same framing: a u32 length (native byte order, which is
//! little-endian on every supported computer) followed by that many bytes of JSON.

use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
#[cfg(windows)]
use uds_windows::UnixStream;

const APP_BUNDLE_ID: &str = "app.vaultix.desktop";
const MAX_FRAME: usize = 1024 * 1024;

fn main() {
    let origin = std::env::args().nth(1).unwrap_or_default();
    let mut stdout = io::stdout().lock();

    let mut socket = match connect(&mut stdout) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vaultix-native-host: {e}");
            let _ = write_frame(&mut stdout, &json!({ "type": "error", "error": "app-not-running" }));
            return;
        }
    };

    let hello = json!({ "type": "hello", "origin": origin, "version": 1 });
    if let Err(e) = write_frame(&mut socket, &hello) {
        eprintln!("vaultix-native-host: {e}");
        return;
    }

    // Extension → app. Raw byte copy: the framing is identical on both sides.
    let mut to_app = socket.try_clone().expect("clone socket");
    thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut to_app);
        // Browser closed the port: end the connection so the app side cleans up.
        let _ = to_app.shutdown(std::net::Shutdown::Both);
    });

    // App → extension, frame by frame so each one is flushed promptly.
    while let Ok(frame) = read_frame(&mut socket) {
        if pass_frame(&mut stdout, &frame).is_err() {
            break;
        }
    }
}

/// The app's config folder, as Tauri picks it: ~/Library/Application Support
/// on macOS, %APPDATA% on Windows, $XDG_CONFIG_HOME or ~/.config on Linux.
fn socket_path() -> PathBuf {
    dirs::config_dir().unwrap_or_default().join(APP_BUNDLE_ID).join("native.sock")
}

/// Connect to the app; if it isn't running, launch it when the extension asks to.
fn connect(stdout: &mut impl Write) -> io::Result<UnixStream> {
    let path = socket_path();
    if let Ok(s) = UnixStream::connect(&path) {
        return Ok(s);
    }
    write_frame(stdout, &json!({ "type": "not-running" }))?;
    let answer: Value = serde_json::from_slice(&read_frame(&mut io::stdin().lock())?).unwrap_or_default();
    if answer["type"] != "launch" {
        return Err(io::Error::other("app not running, and not asked to launch it"));
    }
    launch_app();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match UnixStream::connect(&path) {
            Ok(s) => return Ok(s),
            Err(e) if Instant::now() > deadline => return Err(e),
            Err(_) => thread::sleep(Duration::from_millis(250)),
        }
    }
}

/// Start the app in the background. On macOS, only works for the installed app
/// bundle, not for `tauri dev` builds.
#[cfg(target_os = "macos")]
fn launch_app() {
    let _ = Command::new("/usr/bin/open").args(["-g", "-b", APP_BUNDLE_ID]).status();
}

/// Start the app, installed next to this program, detached from the browser:
/// its own process group, and none of the browser's pipes.
#[cfg(not(target_os = "macos"))]
fn launch_app() {
    use std::process::Stdio;
    let Some(app) = std::env::current_exe().ok().and_then(|exe| Some(exe.parent()?.join(APP_BINARY))) else { return };
    let mut command = Command::new(app);
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        // Out of the browser's job, so closing the browser doesn't end the app;
        // if the job doesn't allow that, start it anyway.
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB);
        if command.spawn().is_ok() {
            return;
        }
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    let _ = command.spawn();
}

#[cfg(not(target_os = "macos"))]
const APP_BINARY: &str = if cfg!(windows) { "vaultix.exe" } else { "vaultix" };

fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::other("frame too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn pass_frame(w: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    w.write_all(&(frame.len() as u32).to_le_bytes())?;
    w.write_all(frame)?;
    w.flush()
}

fn write_frame(w: &mut impl Write, value: &Value) -> io::Result<()> {
    pass_frame(w, &serde_json::to_vec(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &json!({ "type": "hello" })).unwrap();
        assert_eq!(&buf[..4], &16u32.to_le_bytes());
        assert_eq!(read_frame(&mut buf.as_slice()).unwrap(), br#"{"type":"hello"}"#);
    }

    #[test]
    fn rejects_oversized_frames() {
        let bytes = (MAX_FRAME as u32 + 1).to_le_bytes();
        assert!(read_frame(&mut bytes.as_slice()).is_err());
    }
}
