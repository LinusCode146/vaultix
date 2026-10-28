//! The menu-bar icon: Vaultix keeps running there after its window is closed.

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager};

use crate::commands::AppState;

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Vaultix", true, None::<&str>)?;
    // Shown with ⌘⇧Space next to it, but that shortcut is global, not a menu one.
    let quick = MenuItem::with_id(app, "quick", "Quick Search", true, Some("CmdOrCtrl+Shift+Space"))?;
    let lock = MenuItem::with_id(app, "lock", "Lock", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Vaultix", true, Some("CmdOrCtrl+Q"))?;
    let menu = Menu::with_items(app, &[&open, &quick, &lock, &PredefinedMenuItem::separator(app)?, &quit])?;

    TrayIconBuilder::with_id("main")
        .icon(icon())
        .icon_as_template(true)
        .tooltip("Vaultix")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_window(app),
            "quick" => crate::quick::toggle(app),
            "lock" => {
                app.state::<AppState>().lock();
                let _ = app.emit("locked", ());
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

pub fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// The logo's dial (ring, three spokes, hub) in black on transparent, drawn
/// here rather than shipped as a file. As a template image, macOS colors it to
/// match the menu bar.
fn icon() -> Image<'static> {
    const SIZE: usize = 36; // 18 pt at 2x
    let c = SIZE as f32 / 2.0;
    let spokes = [90f32, 210.0, 330.0].map(|deg| {
        let a = deg.to_radians();
        (a.cos(), -a.sin())
    });
    let mut rgba = vec![0u8; SIZE * SIZE * 4];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let (px, py) = (x as f32 + 0.5 - c, y as f32 + 0.5 - c);
            let r = (px * px + py * py).sqrt();
            // Distance to the nearest stroke; negative inside it.
            let ring = (r - 14.5).abs() - 1.6;
            let hub = r - 3.4;
            let spoke = spokes
                .iter()
                .map(|(dx, dy)| {
                    let t = (px * dx + py * dy).clamp(0.0, 9.5);
                    ((px - t * dx).powi(2) + (py - t * dy).powi(2)).sqrt() - 1.4
                })
                .fold(f32::MAX, f32::min);
            let d = ring.min(hub).min(spoke);
            let alpha = (0.5 - d).clamp(0.0, 1.0);
            rgba[(y * SIZE + x) * 4 + 3] = (alpha * 255.0).round() as u8;
        }
    }
    Image::new_owned(rgba, SIZE as u32, SIZE as u32)
}
