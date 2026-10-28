//! Windows: lock on sleep, screen lock and user switch, from a hidden window
//! that receives session and power notifications.

use std::sync::OnceLock;
use std::thread;

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::RemoteDesktop::{NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, MSG, PBT_APMSUSPEND, RegisterClassW, TranslateMessage,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WNDCLASSW, WTS_CONSOLE_DISCONNECT,
    WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK,
};
use windows::core::w;

static CALLBACK: OnceLock<fn()> = OnceLock::new();

/// Call `on_away` when Windows suspends, the screen locks (Win+L) or another
/// user switches in.
pub fn watch_away(on_away: fn()) {
    if CALLBACK.set(on_away).is_err() {
        return;
    }
    thread::spawn(|| {
        if let Err(e) = run() {
            eprintln!("[vaultix] can't watch for sleep and screen lock: {e}");
        }
    });
}

fn run() -> windows::core::Result<()> {
    // SAFETY: standard window-class registration and message loop, on this
    // thread only. A top-level (not message-only) window, since only those
    // receive WM_POWERBROADCAST; it is never shown.
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class = WNDCLASSW { lpfnWndProc: Some(window_proc), hInstance: instance.into(), lpszClassName: w!("VaultixAway"), ..Default::default() };
        RegisterClassW(&class);
        let window = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("VaultixAway"),
            w!("Vaultix"),
            WINDOW_STYLE::default(),
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance.into()),
            None,
        )?;
        WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION)?;
        let mut message = MSG::default();
        while GetMessageW(&mut message, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    Ok(())
}

unsafe extern "system" fn window_proc(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let away = match message {
        WM_WTSSESSION_CHANGE => matches!(wparam.0 as u32, WTS_SESSION_LOCK | WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT),
        WM_POWERBROADCAST => wparam.0 as u32 == PBT_APMSUSPEND,
        _ => false,
    };
    if away && let Some(f) = CALLBACK.get() {
        f();
    }
    // SAFETY: forwarding the message we were given.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}
