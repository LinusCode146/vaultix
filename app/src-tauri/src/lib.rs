//! The Vaultix app: the desktop app (`main.rs`) and the Android app share
//! everything here. Desktop-only parts (tray, browser extension, quick
//! search, serving phones) are under `cfg(desktop)`.

// Some shared code only serves desktop features (Open & Fill, the menu bar).
#![cfg_attr(mobile, allow(dead_code, unused_variables))]

mod backup;
mod commands;
mod config;
mod icons;
#[cfg(desktop)]
mod ipc;
#[cfg(desktop)]
mod link;
#[cfg(desktop)]
mod native;
#[cfg(mobile)]
mod phone;
#[cfg(desktop)]
mod quick;
mod sites;
mod system;
mod touchid;
#[cfg(desktop)]
mod tray;
#[cfg(desktop)]
mod watch;

#[cfg(target_os = "macos")]
use tauri::RunEvent;
use tauri::{Manager, WindowEvent};

use commands::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init());
    #[cfg(desktop)]
    let builder = builder.plugin(quick::plugin());
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    #[cfg(target_os = "android")]
    let builder = builder.plugin(touchid::plugin());
    builder
        .setup(|app| {
            let config_dir = app.path().app_config_dir()?;
            let sites = sites::SiteLists::start(config_dir.clone());
            app.manage(AppState::load(config_dir.join("config.json"), sites)?);
            #[cfg(desktop)]
            setup_desktop(app, &config_dir)?;
            #[cfg(mobile)]
            app.manage(phone::PhoneLink::load(&config_dir, app.path().app_data_dir()?));
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
            commands::copy_secret,
            #[cfg(desktop)]
            commands::open_and_fill,
            #[cfg(desktop)]
            link::phones,
            #[cfg(desktop)]
            link::add_phone,
            #[cfg(desktop)]
            link::cancel_add_phone,
            #[cfg(desktop)]
            link::remove_phone,
            #[cfg(desktop)]
            quick::quick_hide,
            #[cfg(desktop)]
            quick::quick_copy,
            #[cfg(mobile)]
            phone::link_status,
            #[cfg(mobile)]
            phone::pair_with_computer,
            #[cfg(mobile)]
            phone::sync_with_computer,
            #[cfg(mobile)]
            phone::unpair,
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

/// The menu bar icon, the browser extension, quick search, locking when the
/// computer is left, watching the vault folder, and serving phones.
#[cfg(desktop)]
fn setup_desktop(app: &mut tauri::App, config_dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    app.manage(link::Link::load(config_dir.join("link.json")));

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
    link::start(app.handle());
    Ok(())
}
