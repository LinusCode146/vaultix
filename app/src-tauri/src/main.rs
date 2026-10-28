// No console window behind the app on Windows (release builds).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod backup;
mod commands;
mod config;
mod icons;
mod ipc;
mod native;
mod quick;
mod sites;
mod system;
mod touchid;
mod tray;
mod watch;

#[cfg(target_os = "macos")]
use tauri::RunEvent;
use tauri::{Manager, WindowEvent};

use commands::AppState;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(quick::plugin())
        .setup(|app| {
            let config_dir = app.path().app_config_dir()?;
            let sites = sites::SiteLists::start(config_dir.clone());
            app.manage(AppState::load(config_dir.join("config.json"), sites)?);

            // Browser extension support. The app works without it, so failures
            // here are logged, not fatal.
            match ipc::host_binary_path() {
                Some(host) => {
                    let manifests = ipc::install_manifests(&host);
                    eprintln!("[vaultix] native host registered with {} browser(s)", manifests.len());
                    if let Err(e) = ipc::start(app.handle().clone(), config_dir.join(ipc::SOCKET_FILE), host) {
                        eprintln!("[vaultix] browser extension socket unavailable: {e}");
                    }
                }
                None => eprintln!("[vaultix] {} not found next to the app; browser extension disabled", ipc::HOST_BINARY),
            }
            tray::create(app.handle())?;
            system::lock_when_away(app.handle());
            quick::setup(app.handle())?;
            watch::watch(app.handle(), app.state::<AppState>().vault_dir());
            Ok(())
        })
        // Closing the window keeps Vaultix running in the menu bar (system
        // tray), so the browser extension can still reach it. Quit from there.
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::create_vault,
            commands::join_vault,
            commands::unlock,
            commands::lock,
            commands::app_settings,
            commands::set_app_settings,
            commands::forget_vault,
            commands::list_items,
            commands::get_item,
            commands::save_item,
            commands::delete_item,
            commands::sync_vault,
            commands::import_preview,
            commands::import_commit,
            commands::import_cancel,
            commands::trash_imported_file,
            commands::backups,
            commands::backup_now,
            commands::reveal_backups,
            commands::backup_changes,
            commands::restore_from_backup,
            commands::totp_code,
            commands::check_totp,
            commands::scan_totp_qr,
            commands::scan_totp_qr_image,
            commands::generate_password,
            commands::password_strength,
            commands::master_password_check,
            commands::watchtower,
            commands::attach_file,
            commands::export_file,
            commands::site_icon,
            commands::touch_id_status,
            commands::set_touch_id,
            commands::unlock_touch_id,
            commands::open_and_fill,
            commands::copy_secret,
            quick::quick_hide,
            quick::quick_copy,
        ])
        .build(tauri::generate_context!())
        .expect("error while building Vaultix")
        .run(|_app, _event| {
            // Clicking the Dock icon while the window is hidden.
            #[cfg(target_os = "macos")]
            if let RunEvent::Reopen { has_visible_windows: false, .. } = _event {
                tray::show_window(_app);
            }
        });
}
