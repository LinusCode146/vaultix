//! Sync as soon as another Mac's changes arrive in the vault folder, instead of
//! waiting for the next periodic sync. macOS reports the folder's changes
//! through FSEvents; a burst of them (a sync service writing several files)
//! leads to one sync once the folder has been quiet for a moment.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use tauri::{AppHandle, Emitter, Manager};

use crate::commands::AppState;

/// How long the folder must be quiet before syncing.
const SETTLE: Duration = Duration::from_millis(400);

static WATCHER: Mutex<Option<RecommendedWatcher>> = Mutex::new(None);

/// Watch the vault folder (`None`: stop watching, e.g. after "Use a different vault").
pub fn watch(app: &AppHandle, dir: Option<PathBuf>) {
    let mut current = WATCHER.lock().unwrap();
    *current = None;
    let Some(dir) = dir else { return };
    let own_log = format!("{}.log", app.state::<AppState>().device_id());
    let (tx, rx) = mpsc::channel::<()>();
    let handler = move |event: notify::Result<Event>| {
        if let Ok(event) = event
            && event.paths.iter().any(|p| from_elsewhere(p, &own_log))
        {
            let _ = tx.send(());
        }
    };
    let mut watcher = match notify::recommended_watcher(handler) {
        Ok(w) => w,
        Err(e) => return eprintln!("[vaultix] can't watch the vault folder: {e}"),
    };
    if let Err(e) = watcher.watch(&dir, RecursiveMode::Recursive) {
        return eprintln!("[vaultix] can't watch {}: {e}", dir.display());
    }
    *current = Some(watcher);

    let app = app.clone();
    std::thread::spawn(move || {
        // Ends when the watcher (and with it the sender) is dropped.
        while rx.recv().is_ok() {
            loop {
                match rx.recv_timeout(SETTLE) {
                    Ok(()) => continue,
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            }
            sync(&app);
        }
    });
}

/// This Mac's own writes (its log, temporary files) don't need a sync.
fn from_elsewhere(path: &Path, own_log: &str) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name != own_log && !name.ends_with(".tmp") && !name.starts_with('.')
}

fn sync(app: &AppHandle) {
    let state = app.state::<AppState>();
    let changed = {
        let mut guard = state.vault.lock().unwrap();
        let Some(vault) = guard.as_mut() else { return };
        match vault.sync() {
            Ok(report) => report.changed_items,
            Err(e) => return eprintln!("[vaultix] sync after a folder change failed: {e}"),
        }
    };
    if changed > 0 {
        let _ = app.emit("vault-changed", ());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_this_macs_own_writes() {
        let own = "a1.log";
        assert!(!from_elsewhere(Path::new("/v/devices/a1.log"), own));
        assert!(!from_elsewhere(Path::new("/v/vault.json.tmp"), own));
        assert!(!from_elsewhere(Path::new("/v/devices/.b2.log.icloud"), own));
        assert!(from_elsewhere(Path::new("/v/devices/b2.log"), own));
        assert!(from_elsewhere(Path::new("/v/files/c3.bin"), own));
        assert!(from_elsewhere(Path::new("/v/vault.json"), own));
    }
}
