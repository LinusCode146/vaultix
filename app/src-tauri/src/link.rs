//! Phones: pairing with the Android app and syncing with it over the local
//! network (see `vaultix_link`). The listener only runs while a phone is
//! paired or being added; it serves the vault folder as it is on disk, so
//! phones can sync while Vaultix is locked.
//!
//! What the phones send lands in the vault folder, where `watch.rs` sees it
//! like any other device's changes.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use vaultix_link::{Advertiser, Event, INVITE_TTL, Identity, PORT, Phone, Server};

use crate::commands::{AppState, CmdResult};

pub struct Link {
    path: PathBuf,
    stored: Mutex<Stored>,
    running: Mutex<Option<Running>>,
}

struct Running {
    server: Server,
    _advertiser: Option<Advertiser>,
}

/// `link.json`: this computer's certificate and key, and the paired phones.
#[derive(Serialize, Deserialize)]
struct Stored {
    identity: Identity,
    #[serde(default)]
    phones: Vec<Phone>,
}

impl Link {
    pub fn load(path: PathBuf) -> Link {
        let stored = fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| Stored { identity: Identity::generate(), phones: vec![] });
        let link = Link { path, stored: Mutex::new(stored), running: Mutex::new(None) };
        link.save();
        link
    }

    fn save(&self) {
        let stored = self.stored.lock().unwrap();
        let tmp = self.path.with_extension("json.tmp");
        let written = fs::write(&tmp, serde_json::to_vec_pretty(&*stored).unwrap_or_default()).and_then(|()| {
            // Holds the key that proves to phones this is their computer.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
            }
            fs::rename(&tmp, &self.path)
        });
        if let Err(e) = written {
            eprintln!("[vaultix] can't save {}: {e}", self.path.display());
        }
    }

    fn ensure_running(&self, app: &AppHandle) -> Result<u16, String> {
        let mut running = self.running.lock().unwrap();
        if let Some(r) = running.as_ref() {
            return Ok(r.server.port());
        }
        let (identity, phones) = {
            let stored = self.stored.lock().unwrap();
            (stored.identity.clone(), stored.phones.clone())
        };
        let state = app.state::<AppState>();
        let events = app.clone();
        let on_event = move |e: Event| events.state::<Link>().on_event(&events, e);
        let server = Server::start(identity.clone(), &computer_name(), state.device_id(), phones.clone(), SocketAddr::from(([0, 0, 0, 0], PORT)), on_event.clone())
            .or_else(|_| Server::start(identity.clone(), &computer_name(), state.device_id(), phones, SocketAddr::from(([0, 0, 0, 0], 0)), on_event))
            .map_err(|e| format!("Couldn't listen for phones: {e}"))?;
        server.set_vault_dir(state.vault_dir());
        let advertiser = Advertiser::start(&identity.fingerprint(), server.port())
            .inspect_err(|e| eprintln!("[vaultix] can't announce on the local network: {e}"))
            .ok();
        let port = server.port();
        *running = Some(Running { server, _advertiser: advertiser });
        Ok(port)
    }

    /// Stop listening when no phone is paired and none is being added.
    fn stop_if_idle(&self) {
        let mut running = self.running.lock().unwrap();
        if running.as_ref().is_some_and(|r| r.server.phones().is_empty() && !r.server.inviting()) {
            *running = None;
        }
    }

    fn on_event(&self, app: &AppHandle, event: Event) {
        {
            let mut stored = self.stored.lock().unwrap();
            match &event {
                Event::Paired(phone) => stored.phones.push(phone.clone()),
                Event::Synced { phone, .. } => {
                    if let Some(p) = stored.phones.iter_mut().find(|p| p.fingerprint == phone.fingerprint) {
                        p.last_sync = phone.last_sync;
                    }
                }
            }
        }
        self.save();
        let _ = app.emit("phones-changed", ());
    }
}

/// Start listening if a phone is paired. Call once at startup.
pub fn start(app: &AppHandle) {
    let link = app.state::<Link>();
    if !link.stored.lock().unwrap().phones.is_empty()
        && let Err(e) = link.ensure_running(app)
    {
        eprintln!("[vaultix] {e}");
    }
}

/// The vault folder changed (created, joined or forgotten).
pub fn set_vault_dir(app: &AppHandle, dir: Option<PathBuf>) {
    if let Some(r) = app.state::<Link>().running.lock().unwrap().as_ref() {
        r.server.set_vault_dir(dir);
    }
}

/// The name phones show for this computer.
fn computer_name() -> String {
    #[cfg(target_os = "macos")]
    if let Ok(out) = std::process::Command::new("/usr/sbin/scutil").args(["--get", "ComputerName"]).output()
        && out.status.success()
    {
        let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !name.is_empty() {
            return name;
        }
    }
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    host.trim_end_matches(".local").to_string()
}

fn millis(secs: u64) -> u64 {
    secs * 1000
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhoneView {
    id: String,
    name: String,
    paired_at: u64,
    last_sync: Option<u64>,
}

#[tauri::command]
pub fn phones(link: State<'_, Link>) -> Vec<PhoneView> {
    link.stored
        .lock()
        .unwrap()
        .phones
        .iter()
        .map(|p| PhoneView { id: p.fingerprint.clone(), name: p.name.clone(), paired_at: millis(p.paired_at), last_sync: p.last_sync.map(millis) })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteView {
    /// The QR code, as an SVG document.
    qr: String,
    /// What the QR code says, for phones that can't scan it.
    uri: String,
    expires_at: u64,
    computer_name: String,
}

/// Show a QR code for the phone to scan. Errors: "no-vault", "no-network".
#[tauri::command]
pub fn add_phone(app: AppHandle, link: State<'_, Link>, state: State<'_, AppState>) -> CmdResult<InviteView> {
    if state.vault_dir().is_none() {
        return Err("no-vault".into());
    }
    let port = link.ensure_running(&app)?;
    let addrs = vaultix_link::local_addrs(port);
    if addrs.is_empty() {
        link.stop_if_idle();
        return Err("no-network".into());
    }
    let running = link.running.lock().unwrap();
    let invite = running.as_ref().ok_or("not running")?.server.invite(addrs, INVITE_TTL);
    let qr = qrcode::QrCode::new(invite.to_uri().as_bytes()).map_err(|e| e.to_string())?;
    let svg = qr
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    let expires = SystemTime::now() + INVITE_TTL;
    Ok(InviteView {
        qr: svg,
        uri: invite.to_uri(),
        expires_at: expires.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_millis() as u64,
        computer_name: invite.name,
    })
}

#[tauri::command]
pub fn cancel_add_phone(link: State<'_, Link>) {
    if let Some(r) = link.running.lock().unwrap().as_ref() {
        r.server.cancel_invite();
    }
    link.stop_if_idle();
}

#[tauri::command]
pub fn remove_phone(app: AppHandle, link: State<'_, Link>, id: String) {
    link.stored.lock().unwrap().phones.retain(|p| p.fingerprint != id);
    link.save();
    if let Some(r) = link.running.lock().unwrap().as_ref() {
        r.server.remove_phone(&id);
    }
    link.stop_if_idle();
    let _ = app.emit("phones-changed", ());
}
