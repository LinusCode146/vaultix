//! Quick search: ⌘⇧Space (Ctrl+Shift+Space on Windows and Linux) opens a small window over whatever app is in front,
//! to copy a password, username or one-time code without opening Vaultix.
//! Copies happen here, so passwords don't pass through the webview.

use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

use crate::commands::{AppState, copy_with_auto_clear};

pub const LABEL: &str = "quick";

fn shortcut() -> Shortcut {
    // Win+Shift+Space switches keyboard layouts on Windows.
    let modifier = if cfg!(target_os = "macos") { Modifiers::SUPER } else { Modifiers::CONTROL };
    Shortcut::new(Some(modifier | Modifiers::SHIFT), Code::Space)
}

pub fn plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri_plugin_global_shortcut::Builder::new()
        .with_handler(|app, pressed, event| {
            if *pressed == shortcut() && event.state == ShortcutState::Pressed {
                toggle(app);
            }
        })
        .build()
}

/// Create the (hidden) window and register the shortcut if it's turned on.
pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html".into()))
        .title("Vaultix")
        .inner_size(640.0, 420.0)
        .resizable(false)
        .decorations(false)
        // Transparent, so the page can draw rounded corners (needs macOSPrivateApi
        // on macOS, and a compositor on Linux).
        .transparent(true)
        .shadow(true)
        .always_on_top(true)
        .visible_on_all_workspaces(true)
        .skip_taskbar(true)
        .visible(false)
        .center()
        .build()?;
    set_enabled(app, app.state::<AppState>().settings().quick_search);
    Ok(())
}

/// Turn the shortcut on or off (from Settings).
pub fn set_enabled(app: &AppHandle, enabled: bool) {
    let shortcuts = app.global_shortcut();
    let registered = shortcuts.is_registered(shortcut());
    let result = match (enabled, registered) {
        (true, false) => shortcuts.register(shortcut()),
        (false, true) => shortcuts.unregister(shortcut()),
        _ => Ok(()),
    };
    if let Err(e) = result {
        eprintln!("[vaultix] couldn't {} the quick search shortcut: {e}", if enabled { "register" } else { "unregister" });
    }
}

pub fn toggle(app: &AppHandle) {
    let Some(window) = app.get_webview_window(LABEL) else { return };
    if window.is_visible().unwrap_or(false) && window.is_focused().unwrap_or(false) {
        let _ = window.hide();
        return;
    }
    let _ = window.center();
    let _ = window.show();
    let _ = window.set_focus();
    let _ = app.emit_to(LABEL, "quick-opened", ());
}

/// Hide the window. `give_back_focus`: also step Vaultix aside, so the app
/// the user came from is in front again, ready for a paste.
#[tauri::command]
pub async fn quick_hide(app: AppHandle, give_back_focus: bool) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(LABEL) {
        let _ = window.hide();
    }
    // Elsewhere, hiding the window already returns focus to the previous one.
    #[cfg(target_os = "macos")]
    if give_back_focus && !app.get_webview_window("main").is_some_and(|w| w.is_visible().unwrap_or(false)) {
        app.hide().map_err(|e| e.to_string())?;
    }
    let _ = give_back_focus;
    Ok(())
}

/// Copy an item's password, username or current one-time code, then hide.
#[tauri::command]
pub async fn quick_copy(app: AppHandle, state: State<'_, AppState>, id: String, what: String) -> Result<(), String> {
    let id = uuid::Uuid::parse_str(&id).map_err(|_| "invalid id")?;
    let text = {
        let guard = state.vault.lock().unwrap();
        let item = guard.as_ref().ok_or("locked")?.get(id).ok_or("item not found")?;
        match what.as_str() {
            "password" => item.password.clone(),
            "username" => item.username.clone(),
            "totp" => {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                item.totp.as_ref().ok_or("no one-time password")?.code_at(now).map_err(|e| e.to_string())?
            }
            _ => return Err("unknown field".into()),
        }
    };
    if text.is_empty() {
        return Err(format!("This item has no {what}."));
    }
    copy_with_auto_clear(&app, text)?;
    quick_hide(app, true).await
}
