//! The phone's side of Wi-Fi sync: pairing with a computer by scanning its
//! QR code, and syncing with it (see `vaultix_link`). The vault folder lives
//! in the app's private storage; only the paired computer ever sees it.

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use vaultix_link::{Identity, Invite, Pairing};

use crate::commands::{AppState, CmdResult};
use crate::config::VaultLocation;

/// How long to look for the computer on the network when its last known
/// addresses don't answer.
const FIND_TIMEOUT: Duration = Duration::from_secs(3);

pub struct PhoneLink {
    path: PathBuf,
    vault_dir: PathBuf,
    stored: Mutex<Stored>,
    /// Held while syncing, so syncs don't overlap.
    syncing: Mutex<()>,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    identity: Identity,
    pairing: Option<Pairing>,
    #[serde(default)]
    last_sync: Option<u64>,
    #[serde(default)]
    last_error: Option<String>,
}

impl PhoneLink {
    pub fn load(config_dir: &std::path::Path, data_dir: PathBuf) -> PhoneLink {
        let path = config_dir.join("link.json");
        let stored = fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| Stored { identity: Identity::generate(), pairing: None, last_sync: None, last_error: None });
        let link = PhoneLink { path, vault_dir: data_dir.join("Vaultix Vault"), stored: Mutex::new(stored), syncing: Mutex::new(()) };
        link.save();
        link
    }

    fn save(&self) {
        let stored = self.stored.lock().unwrap();
        let tmp = self.path.with_extension("json.tmp");
        let written = fs::write(&tmp, serde_json::to_vec_pretty(&*stored).unwrap_or_default()).and_then(|()| fs::rename(&tmp, &self.path));
        if let Err(e) = written {
            eprintln!("[vaultix] can't save {}: {e}", self.path.display());
        }
    }
}

/// Short codes the UI switches on.
fn code(e: &vaultix_link::Error) -> String {
    match e {
        vaultix_link::Error::Unreachable => "link-unreachable".into(),
        vaultix_link::Error::Refused(r) => format!("link-{r}"),
        vaultix_link::Error::BadInvite => "link-bad-invite".into(),
        other => {
            eprintln!("[vaultix] sync failed: {other}");
            "link-failed".into()
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn device_name() -> String {
    "Android phone".into()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkStatus {
    paired: bool,
    computer_name: Option<String>,
    last_sync: Option<u64>,
    /// The last sync's error code, cleared by the next successful one.
    last_error: Option<String>,
}

#[tauri::command]
pub fn link_status(link: State<'_, PhoneLink>) -> LinkStatus {
    let stored = link.stored.lock().unwrap();
    LinkStatus {
        paired: stored.pairing.is_some(),
        computer_name: stored.pairing.as_ref().map(|p| p.name.clone()),
        last_sync: stored.last_sync,
        last_error: stored.last_error.clone(),
    }
}

/// Pair with the computer whose QR code was scanned and fetch the vault.
/// Afterwards the vault is set up but locked: unlock it with the master password.
#[tauri::command]
pub async fn pair_with_computer(app: AppHandle, invite: String) -> CmdResult<()> {
    let invite = Invite::parse(&invite).map_err(|e| code(&e))?;
    let task = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let link = task.state::<PhoneLink>();
        let state = task.state::<AppState>();
        let _syncing = link.syncing.lock().unwrap();
        let identity = link.stored.lock().unwrap().identity.clone();
        // A fresh folder: whatever an earlier, abandoned pairing left goes.
        let _ = fs::remove_dir_all(&link.vault_dir);
        fs::create_dir_all(&link.vault_dir).map_err(|e| e.to_string())?;
        let (pairing, _) = vaultix_link::pair(&invite, &identity, &device_name(), &link.vault_dir, state.device_id()).map_err(|e| code(&e))?;
        let vault_id = pairing.vault_id;
        {
            let mut stored = link.stored.lock().unwrap();
            stored.pairing = Some(pairing);
            stored.last_sync = Some(now_ms());
            stored.last_error = None;
        }
        link.save();
        state.set_vault_location(Some(VaultLocation { dir: link.vault_dir.clone(), vault_id }))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Swap changes with the paired computer, then re-read the vault if it's
/// unlocked. Returns the status; errors are reported in it, not thrown.
#[tauri::command]
pub async fn sync_with_computer(app: AppHandle) -> CmdResult<LinkStatus> {
    let task = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let link = task.state::<PhoneLink>();
        let state = task.state::<AppState>();
        let Ok(_syncing) = link.syncing.try_lock() else {
            return; // Already syncing.
        };
        let (identity, pairing) = {
            let stored = link.stored.lock().unwrap();
            (stored.identity.clone(), stored.pairing.clone())
        };
        let Some(mut pairing) = pairing else { return };

        let mut result = vaultix_link::sync(&mut pairing, &identity, &link.vault_dir, state.device_id());
        if matches!(result, Err(vaultix_link::Error::Unreachable)) {
            // The computer may have a new address.
            let found = vaultix_link::find(&pairing.fingerprint, FIND_TIMEOUT);
            if !found.is_empty() {
                pairing.addrs = found;
                result = vaultix_link::sync(&mut pairing, &identity, &link.vault_dir, state.device_id());
            }
        }
        {
            let mut stored = link.stored.lock().unwrap();
            match &result {
                Ok(_) => {
                    stored.last_sync = Some(now_ms());
                    stored.last_error = None;
                    stored.pairing = Some(pairing);
                }
                Err(e) => stored.last_error = Some(code(e)),
            }
        }
        link.save();

        if let Ok(received) = result
            && received.any()
        {
            let changed = state.vault.lock().unwrap().as_mut().and_then(|v| v.sync().ok()).is_some_and(|r| r.changed_items > 0);
            if changed {
                let _ = task.emit("vault-changed", ());
            }
        }
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(link_status(app.state::<PhoneLink>()))
}

/// Forget the computer and the vault copy on this phone.
#[tauri::command]
pub async fn unpair(app: AppHandle) -> CmdResult<()> {
    let link = app.state::<PhoneLink>();
    let state = app.state::<AppState>();
    state.lock();
    {
        let mut stored = link.stored.lock().unwrap();
        stored.pairing = None;
        stored.last_sync = None;
        stored.last_error = None;
    }
    link.save();
    let _ = fs::remove_dir_all(&link.vault_dir);
    state.set_vault_location(None)
}
