//! The IPC surface the web UI may call. Everything crossing it is a DTO:
//! passkey private keys and the vault key never reach the webview.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vaultix_core::generator::{PasswordOptions, generate_password as generate};
use vaultix_core::import::Imported;
use vaultix_core::crypto::KdfParams;
use vaultix_core::strength::{Strength, StrengthLabel, master_password_problem};
use vaultix_core::watchtower::{Report, analyze, item_strength, label_text};
use vaultix_core::{BackupChange, Category, Error, Field, FieldKind, FileRef, Item, Totp, Vault};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use uuid::Uuid;

use crate::backup::{self, BackupInfo};
use crate::config::{Config, Settings, VaultLocation};
use crate::touchid::{Enrollment, TouchIdError};
use crate::icons::Icons;
use crate::sites::SiteLists;

/// Name of the folder created inside the folder the user picks.
const VAULT_FOLDER: &str = "Vaultix Vault";
/// Stored files no item refers to (e.g. picked, then the edit was cancelled)
/// are deleted once they are this old.
const ORPHAN_FILE_AGE: Duration = Duration::from_secs(30 * 24 * 3600);
/// Copied secrets are wiped from the clipboard after this long.
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

pub struct AppState {
    config_path: PathBuf,
    config: Mutex<Config>,
    pub(crate) vault: Mutex<Option<Vault>>,
    sites: SiteLists,
    pub(crate) icons: Icons,
    /// Held while a Touch ID prompt is up, so only one shows at a time.
    touch_id_busy: Mutex<()>,
    /// Set by "Open & Fill"; the extension collects it when the site shows a login form.
    pub(crate) pending_fill: Mutex<Option<PendingFill>>,
    /// An export read by [`import_preview`], waiting for [`import_commit`].
    pending_import: Mutex<Option<PendingImport>>,
    /// The last export imported, offered for moving to the Trash.
    imported_file: Mutex<Option<PathBuf>>,
}

struct PendingImport {
    path: PathBuf,
    /// Items not in the vault already.
    items: Vec<Imported>,
}

/// A login to fill (and submit) as soon as its website shows a login form.
#[derive(Debug, Clone)]
pub struct PendingFill {
    pub item_id: Uuid,
    pub expires_at: SystemTime,
}

/// How long "Open & Fill" waits for the site to show a login form.
const OPEN_AND_FILL_WINDOW: Duration = Duration::from_secs(120);

impl AppState {
    pub fn load(config_path: PathBuf, sites: SiteLists) -> std::io::Result<Self> {
        let config = Config::load_or_init(&config_path)?;
        let icons = Icons::new(config_path.with_file_name("icons"));
        Ok(AppState {
            config_path,
            config: Mutex::new(config),
            vault: Mutex::new(None),
            sites,
            icons,
            touch_id_busy: Mutex::new(()),
            pending_fill: Mutex::new(None),
            pending_import: Mutex::new(None),
            imported_file: Mutex::new(None),
        })
    }

    fn config_dir(&self) -> PathBuf {
        self.config_path.parent().map(Path::to_path_buf).unwrap_or_default()
    }

    /// Remember which browser the extension runs in, for "Open & Fill".
    /// Dropping the vault zeroizes the vault key and decrypted items.
    pub fn lock(&self) {
        *self.vault.lock().unwrap() = None;
        self.icons.forget_memory();
    }

    pub fn device_id(&self) -> Uuid {
        self.config.lock().unwrap().device_id
    }

    /// The vault folder this Mac is set up for.
    pub fn vault_dir(&self) -> Option<PathBuf> {
        self.config.lock().unwrap().vault.as_ref().map(|v| v.dir.clone())
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.lock().unwrap().is_some()
    }

    pub fn backup_dir(&self) -> PathBuf {
        self.settings().backup_dir.unwrap_or_else(|| backup::default_dir(&self.config_dir()))
    }

    pub fn settings(&self) -> Settings {
        self.config.lock().unwrap().settings.clone()
    }

    pub fn remember_browser(&self, app_bundle: PathBuf) {
        let mut config = self.config.lock().unwrap();
        if config.browser_app.as_ref() != Some(&app_bundle) {
            config.browser_app = Some(app_bundle);
            let _ = config.save(&self.config_path);
        }
    }

    /// Whether the extension may offer Touch ID (it may still be cancelled).
    pub fn touch_id_usable(&self) -> bool {
        let vault_id = self.config.lock().unwrap().vault.as_ref().map(|v| v.vault_id);
        match (vault_id, Enrollment::load(&self.config_dir())) {
            (Some(id), Some(e)) => e.usable(id) && crate::touchid::available(),
            _ => false,
        }
    }

    /// Show the Touch ID prompt and unlock. Used by the unlock screen and by
    /// the browser extension. Errors are short codes (`touch-id-cancelled`, …)
    /// or `password-required`.
    pub fn unlock_with_touch_id(&self, reason: &str) -> Result<(), String> {
        if self.vault.lock().unwrap().is_some() {
            return Ok(());
        }
        let _busy = self.touch_id_busy.try_lock().map_err(|_| "touch-id-busy".to_string())?;
        let (location, device_id) = {
            let config = self.config.lock().unwrap();
            (config.vault.clone().ok_or("No vault is set up on this Mac.")?, config.device_id)
        };
        let dir = self.config_dir();
        let mut enrollment = Enrollment::load(&dir).ok_or("password-required")?;
        if !enrollment.usable(location.vault_id) {
            return Err("password-required".into());
        }
        match enrollment.unlock(&location.dir, device_id, reason) {
            Ok(vault) => {
                *self.vault.lock().unwrap() = Some(vault);
                Ok(())
            }
            Err(TouchIdError::Invalidated) if crate::touchid::SETUP_PROMPTS => {
                // Windows Hello was reset: turn it off, to be turned on again in Settings.
                Enrollment::remove(&dir);
                Err(TouchIdError::Invalidated.code().into())
            }
            Err(TouchIdError::Invalidated) => {
                // Set up again at the next master password unlock.
                enrollment.invalidate();
                let _ = enrollment.save(&dir);
                Err(TouchIdError::Invalidated.code().into())
            }
            Err(e) => Err(e.code().into()),
        }
    }

    pub(crate) fn set_vault_location(&self, location: Option<VaultLocation>) -> Result<(), String> {
        let mut config = self.config.lock().unwrap();
        config.vault = location;
        config.save(&self.config_path).map_err(|e| e.to_string())
    }

    fn with_vault<T>(&self, f: impl FnOnce(&mut Vault) -> vaultix_core::Result<T>) -> Result<T, String> {
        let mut guard = self.vault.lock().unwrap();
        let vault = guard.as_mut().ok_or("locked")?;
        f(vault).map_err(|e| e.to_string())
    }
}

pub(crate) type CmdResult<T> = Result<T, String>;

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn parse_id(id: &str) -> CmdResult<Uuid> {
    Uuid::parse_str(id).map_err(|_| "invalid item id".to_string())
}

// ---------- DTOs ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// "setup" (no vault on this Mac yet), "locked" or "unlocked".
    stage: &'static str,
    vault_dir: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    id: Uuid,
    category: Category,
    title: String,
    username: String,
    /// Second line in the item list, e.g. "Visa •••• 4242".
    subtitle: String,
    url: Option<String>,
    favorite: bool,
    has_totp: bool,
    passkey_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyView {
    credential_id: String,
    rp_id: String,
    user_name: String,
    created_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrengthView {
    label: StrengthLabel,
    /// "Very good", for display.
    text: &'static str,
    /// 0..=1, for the ring.
    fraction: f64,
}

impl From<Strength> for StrengthView {
    fn from(s: Strength) -> Self {
        StrengthView { label: s.label, text: label_text(s.label), fraction: s.fraction }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemView {
    id: Uuid,
    category: Category,
    title: String,
    username: String,
    password: String,
    strength: Option<StrengthView>,
    urls: Vec<String>,
    notes: String,
    totp_uri: Option<String>,
    passkeys: Vec<PasskeyView>,
    fields: Vec<FieldDto>,
    files: Vec<FileRef>,
    tags: Vec<String>,
    favorite: bool,
    /// Previous passwords, newest first.
    password_history: Vec<PasswordChangeView>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChangeView {
    password: String,
    changed_at: i64,
}

#[derive(Serialize, Deserialize)]
pub struct FieldDto {
    id: String,
    label: String,
    kind: FieldKind,
    value: String,
}

impl From<&Field> for FieldDto {
    fn from(f: &Field) -> Self {
        FieldDto { id: f.id.clone(), label: f.label.clone(), kind: f.kind, value: f.value.clone() }
    }
}

impl From<&Item> for ItemView {
    fn from(item: &Item) -> Self {
        ItemView {
            id: item.id,
            category: item.category,
            title: item.title.clone(),
            username: item.username.clone(),
            password: item.password.clone(),
            strength: (!item.password.is_empty()).then(|| item_strength(item).into()),
            urls: item.urls.clone(),
            notes: item.notes.clone(),
            totp_uri: item.totp.as_ref().map(Totp::to_uri),
            passkeys: item
                .passkeys
                .iter()
                .map(|p| PasskeyView {
                    credential_id: URL_SAFE_NO_PAD.encode(&p.credential_id),
                    rp_id: p.rp_id.clone(),
                    user_name: p.user_name.clone(),
                    created_at: p.created_at,
                })
                .collect(),
            fields: item.fields.iter().map(FieldDto::from).collect(),
            files: item.files.clone(),
            tags: item.tags.clone(),
            favorite: item.favorite,
            password_history: item
                .password_history
                .iter()
                .map(|c| PasswordChangeView { password: c.password.clone(), changed_at: c.changed_at })
                .collect(),
            created_at: item.created_at,
            updated_at: item.updated_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemInput {
    /// `None` creates a new item.
    id: Option<String>,
    /// Only used for new items: an item keeps its category.
    category: Category,
    title: String,
    username: String,
    password: String,
    urls: Vec<String>,
    notes: String,
    /// An `otpauth://` URI or a bare base32 secret; empty removes TOTP.
    totp: String,
    /// Passkeys to keep (by credential ID). Passkeys can be removed here but
    /// only created by a website, through the browser extension.
    passkey_ids: Vec<String>,
    fields: Vec<FieldDto>,
    /// Files from [`attach_file`] or already on the item.
    files: Vec<FileRef>,
    tags: Vec<String>,
    favorite: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    code: String,
    remaining: u64,
    period: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResult {
    devices: usize,
    entries: usize,
    skipped_lines: usize,
}

// ---------- Setup and unlock ----------

#[tauri::command]
pub async fn status(state: State<'_, AppState>) -> CmdResult<Status> {
    let config = state.config.lock().unwrap().clone();
    let unlocked = state.vault.lock().unwrap().is_some();
    Ok(match config.vault {
        None => Status { stage: "setup", vault_dir: None },
        Some(loc) => Status {
            stage: if unlocked { "unlocked" } else { "locked" },
            vault_dir: Some(loc.dir.display().to_string()),
        },
    })
}

/// Create a new vault inside `parent_dir` (e.g. a folder in iCloud Drive).
#[tauri::command]
pub async fn create_vault(app: AppHandle, state: State<'_, AppState>, parent_dir: String, password: String) -> CmdResult<()> {
    if let Some(problem) = master_password_problem(&password) {
        return Err(problem);
    }
    let dir = Path::new(&parent_dir).join(VAULT_FOLDER);
    let device_id = state.config.lock().unwrap().device_id;
    let vault = Vault::create(&dir, &password, device_id).map_err(|e| e.to_string())?;
    state.set_vault_location(Some(VaultLocation { dir, vault_id: vault.vault_id() }))?;
    *state.vault.lock().unwrap() = Some(vault);
    #[cfg(desktop)]
    crate::watch::watch(&app, state.vault_dir());
    #[cfg(desktop)]
    crate::link::set_vault_dir(&app, state.vault_dir());
    Ok(())
}

/// Set up this Mac for a vault created on another Mac.
#[tauri::command]
pub async fn join_vault(app: AppHandle, state: State<'_, AppState>, dir: String, password: String) -> CmdResult<()> {
    let dir = find_vault_dir(Path::new(&dir))
        .ok_or("No Vaultix vault in that folder. Pick the folder that contains vault.json.")?;
    let device_id = state.config.lock().unwrap().device_id;
    let vault = Vault::unlock(&dir, &password, device_id).map_err(|e| e.to_string())?;
    state.set_vault_location(Some(VaultLocation { dir, vault_id: vault.vault_id() }))?;
    *state.vault.lock().unwrap() = Some(vault);
    #[cfg(desktop)]
    crate::watch::watch(&app, state.vault_dir());
    #[cfg(desktop)]
    crate::link::set_vault_dir(&app, state.vault_dir());
    Ok(())
}

fn find_vault_dir(picked: &Path) -> Option<PathBuf> {
    [picked.to_path_buf(), picked.join(VAULT_FOLDER)]
        .into_iter()
        .find(|d| d.join("vault.json").is_file())
}

#[tauri::command]
pub async fn unlock(app: AppHandle, state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let (location, device_id) = {
        let config = state.config.lock().unwrap();
        (config.vault.clone().ok_or("No vault is set up on this Mac.")?, config.device_id)
    };
    let mut vault = Vault::unlock(&location.dir, &password, device_id).map_err(|e| match e {
        Error::Io(_) => format!("Can't read the vault folder at {}. Is it still there?", location.dir.display()),
        other => other.to_string(),
    })?;
    // Vaults created with older, cheaper settings get today's on the next unlock.
    if let Err(e) = vault.upgrade_kdf(&password, KdfParams::default()) {
        eprintln!("[vaultix] couldn't upgrade key derivation settings: {e}");
    }
    if let Err(e) = vault.sweep_files(ORPHAN_FILE_AGE) {
        eprintln!("[vaultix] couldn't clean up unused files: {e}");
    }
    // The master password was just entered: restart the two-week clock, and
    // set Touch ID up again if the enrolled fingers had changed.
    let dir = state.config_dir();
    if let Some(enrollment) = Enrollment::load(&dir).filter(|e| e.wanted && e.vault_id == vault.vault_id()) {
        let now = crate::touchid::now_secs();
        let updated = match enrollment.has_key() {
            true => None,
            false if !crate::touchid::SETUP_PROMPTS => crate::touchid::new_key().ok().map(|k| Enrollment::create(&vault, k, now)),
            false => None,
        }
        .unwrap_or_else(|| {
            let mut e = enrollment;
            e.password_at = now;
            e
        });
        let _ = updated.save(&dir);
    }
    *state.vault.lock().unwrap() = Some(vault);
    // The other window (main or quick search) follows.
    let _ = app.emit("unlocked", ());
    Ok(())
}

#[tauri::command]
pub async fn lock(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    state.lock();
    let _ = app.emit("locked", ());
    Ok(())
}

#[tauri::command]
pub async fn app_settings(state: State<'_, AppState>) -> CmdResult<Settings> {
    Ok(state.settings())
}

#[tauri::command]
pub async fn set_app_settings(app: AppHandle, settings: Settings) -> CmdResult<()> {
    #[cfg(desktop)]
    crate::quick::set_enabled(&app, settings.quick_search);
    let state = app.state::<AppState>();
    let mut config = state.config.lock().unwrap();
    config.settings = settings;
    config.save(&state.config_path).map_err(|e| e.to_string())
}

/// Disconnect this Mac from its vault (files in the synced folder are kept).
#[tauri::command]
pub async fn forget_vault(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    #[cfg(desktop)]
    crate::watch::watch(&app, None);
    #[cfg(desktop)]
    crate::link::set_vault_dir(&app, None);
    *state.vault.lock().unwrap() = None;
    Enrollment::remove(&state.config_dir());
    state.icons.forget_memory();
    state.set_vault_location(None)
}

// ---------- Touch ID ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TouchIdStatus {
    /// "touch-id" or "windows-hello"; `None` on systems without either.
    kind: Option<&'static str>,
    /// Touch ID with at least one finger enrolled, or Windows Hello set up.
    available: bool,
    /// The user turned it on.
    enabled: bool,
    /// It can be used to unlock right now.
    usable: bool,
    /// Turned on, but the master password is needed first: it's been two
    /// weeks, or the enrolled fingers changed.
    password_required: bool,
}

#[tauri::command]
pub async fn touch_id_status(state: State<'_, AppState>) -> CmdResult<TouchIdStatus> {
    let available = crate::touchid::available();
    let vault_id = state.config.lock().unwrap().vault.as_ref().map(|v| v.vault_id);
    let enrollment = Enrollment::load(&state.config_dir()).filter(|e| Some(e.vault_id) == vault_id && e.wanted);
    let usable = available && enrollment.as_ref().zip(vault_id).is_some_and(|(e, id)| e.usable(id));
    Ok(TouchIdStatus { kind: crate::touchid::kind(), available, enabled: enrollment.is_some(), usable, password_required: enrollment.is_some() && !usable })
}

/// Turn Touch ID unlock on or off. Turning it on needs the vault unlocked.
#[tauri::command]
pub async fn set_touch_id(state: State<'_, AppState>, enabled: bool) -> CmdResult<()> {
    let dir = state.config_dir();
    if !enabled {
        Enrollment::remove(&dir);
        return Ok(());
    }
    if !state.is_unlocked() {
        return Err("locked".into());
    }
    // Windows Hello asks the user here; don't hold the vault meanwhile.
    let key = tauri::async_runtime::spawn_blocking(crate::touchid::new_key).await.map_err(|e| e.to_string())?.map_err(|e| e.code().to_string())?;
    let guard = state.vault.lock().unwrap();
    let vault = guard.as_ref().ok_or("locked")?;
    // Keep the two-week clock from the last master password entry, if known.
    let password_at = Enrollment::load(&dir)
        .filter(|e| e.vault_id == vault.vault_id())
        .map(|e| e.password_at)
        .unwrap_or_else(crate::touchid::now_secs);
    let enrollment = Enrollment::create(vault, key, password_at);
    enrollment.save(&dir).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn unlock_touch_id(app: AppHandle) -> CmdResult<()> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || handle.state::<AppState>().unlock_with_touch_id("unlock your vault"))
        .await
        .map_err(|e| e.to_string())??;
    let _ = app.emit("unlocked", ());
    Ok(())
}

// ---------- Items ----------

#[tauri::command]
pub async fn list_items(state: State<'_, AppState>) -> CmdResult<Vec<ItemSummary>> {
    state.with_vault(|v| {
        Ok(v.items()
            .into_iter()
            .map(|i| ItemSummary {
                id: i.id,
                category: i.category,
                title: i.title.clone(),
                username: i.username.clone(),
                subtitle: subtitle(i),
                url: i.urls.first().cloned(),
                favorite: i.favorite,
                has_totp: i.totp.is_some(),
                passkey_count: i.passkeys.len(),
            })
            .collect())
    })
}

#[tauri::command]
pub async fn get_item(state: State<'_, AppState>, id: String) -> CmdResult<ItemView> {
    let id = parse_id(&id)?;
    state.with_vault(|v| v.get(id).map(ItemView::from).ok_or_else(|| Error::InvalidVault("item not found".into())))
}

#[tauri::command]
pub async fn save_item(state: State<'_, AppState>, input: ItemInput) -> CmdResult<ItemView> {
    let totp = match input.totp.trim() {
        "" => None,
        s => Some(Totp::parse(s).map_err(|e| e.to_string())?),
    };
    let existing_id = input.id.as_deref().map(parse_id).transpose()?;
    state.with_vault(|v| {
        let mut item = match existing_id {
            Some(id) => v.get(id).cloned().ok_or_else(|| Error::InvalidVault("item not found".into()))?,
            None => Item::new("", now_ms()).with_category(input.category),
        };
        item.title = input.title.trim().to_string();
        item.username = input.username;
        item.password = input.password;
        item.urls = input.urls.into_iter().map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect();
        item.notes = input.notes;
        item.totp = totp;
        item.passkeys.retain(|p| input.passkey_ids.contains(&URL_SAFE_NO_PAD.encode(&p.credential_id)));
        item.fields = input
            .fields
            .into_iter()
            .filter(|f| !f.value.trim().is_empty())
            .map(|f| Field { id: f.id, label: f.label, kind: f.kind, value: f.value })
            .collect();
        item.files = input.files;
        item.tags = input.tags;
        item.favorite = input.favorite;
        let id = item.id;
        v.put(item)?;
        Ok(ItemView::from(v.get(id).expect("just saved")))
    })
}

#[tauri::command]
pub async fn delete_item(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let id = parse_id(&id)?;
    state.with_vault(|v| v.delete(id))
}

/// Runs every few minutes while the vault is open; also makes the daily backup.
#[tauri::command]
pub async fn sync_vault(state: State<'_, AppState>) -> CmdResult<SyncResult> {
    let backup_dir = state.backup_dir();
    state.with_vault(|v| {
        let r = v.sync()?;
        backup::auto(v, &backup_dir);
        Ok(SyncResult { devices: r.devices, entries: r.entries, skipped_lines: r.skipped_lines })
    })
}

// ---------- Import ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    source: &'static str,
    file_name: String,
    /// New items per category.
    counts: Vec<(Category, usize)>,
    /// Items left out because the vault has them already.
    duplicates: usize,
    files: usize,
    warnings: Vec<String>,
}

/// Read an export and say what importing it would add. Nothing is saved yet.
/// A KeePass database needs its `password` (and `key_file`, if it has one):
/// without it this fails with `kdbx-password`, with a wrong one `kdbx-wrong-key`.
#[tauri::command]
pub async fn import_preview(
    state: State<'_, AppState>,
    path: String,
    password: Option<String>,
    key_file: Option<String>,
) -> CmdResult<ImportPreview> {
    use vaultix_core::import;
    use zeroize::Zeroize;

    let path = PathBuf::from(path);
    let mut bytes = std::fs::read(&path).map_err(|e| format!("Can't read {}: {e}", path.display()))?;
    let parsed = if import::is_kdbx(&bytes) {
        let Some(mut password) = password else {
            bytes.zeroize();
            return Err("kdbx-password".into());
        };
        let key = match key_file.map(std::fs::read).transpose() {
            Ok(key) => key,
            Err(e) => {
                bytes.zeroize();
                password.zeroize();
                return Err(format!("Can't read the key file: {e}"));
            }
        };
        let parsed = import::parse_kdbx(&bytes, &password, key.as_deref(), now_ms());
        password.zeroize();
        parsed
    } else {
        import::parse(&bytes, now_ms())
    };
    bytes.zeroize();
    let parsed = parsed.map_err(|e| e.to_string())?;

    let (items, duplicates) = state.with_vault(|v| {
        let existing = v.items();
        let (dupes, new): (Vec<Imported>, Vec<Imported>) =
            parsed.items.into_iter().partition(|i| existing.iter().any(|e| same_item(e, &i.item)));
        Ok((new, dupes.len()))
    })?;
    let mut counts: Vec<(Category, usize)> = Vec::new();
    for i in &items {
        match counts.iter_mut().find(|(c, _)| *c == i.item.category) {
            Some((_, n)) => *n += 1,
            None => counts.push((i.item.category, 1)),
        }
    }
    let preview = ImportPreview {
        source: parsed.source,
        file_name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        counts,
        duplicates,
        files: items.iter().map(|i| i.files.len()).sum(),
        warnings: parsed.warnings,
    };
    *state.pending_import.lock().unwrap() = Some(PendingImport { path, items });
    Ok(preview)
}

/// Save what [`import_preview`] read. The vault is backed up first, so an
/// import can be undone from Settings → Backups.
#[tauri::command]
pub async fn import_commit(state: State<'_, AppState>) -> CmdResult<usize> {
    let pending = state.pending_import.lock().unwrap().take().ok_or("Choose a file to import first.")?;
    let backup_dir = state.backup_dir();
    let imported = state.with_vault(|v| {
        if !v.items().is_empty()
            && let Err(e) = backup::backup_now(v, &backup_dir)
        {
            return Err(Error::Import(format!("Didn't import, because the vault couldn't be backed up first. {e}")));
        }
        let mut count = 0;
        for Imported { mut item, files } in pending.items {
            for f in &files {
                item.files.push(v.add_file(&f.name, &f.contents)?);
            }
            v.put(item)?;
            count += 1;
        }
        Ok(count)
    })?;
    *state.imported_file.lock().unwrap() = Some(pending.path);
    Ok(imported)
}

#[tauri::command]
pub async fn import_cancel(state: State<'_, AppState>) -> CmdResult<()> {
    *state.pending_import.lock().unwrap() = None;
    Ok(())
}

/// Move the export just imported to the Trash: it holds every password in plain text.
#[tauri::command]
pub async fn trash_imported_file(state: State<'_, AppState>) -> CmdResult<()> {
    let path = state.imported_file.lock().unwrap().take().ok_or("Nothing was imported.")?;
    crate::system::trash(&path)
}

/// Whether `new` is already in the vault as `existing`, so importing the same
/// export twice adds nothing.
fn same_item(existing: &Item, new: &Item) -> bool {
    if existing.category != new.category {
        return false;
    }
    if new.category == Category::Login {
        let same_site = new.urls.is_empty() && existing.urls.is_empty()
            || new.urls.iter().any(|u| existing.urls.iter().any(|e| vaultix_core::origin::login_matches_page(e, u)));
        return same_site && existing.username == new.username && existing.password == new.password;
    }
    existing.title == new.title && existing.notes == new.notes && existing.fields == new.fields
}

// ---------- Backups ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Backups {
    dir: String,
    /// Newest first.
    backups: Vec<BackupInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupItem {
    id: String,
    title: String,
    subtitle: String,
    category: Category,
    change: BackupChange,
    /// When it was last changed before the backup (Unix milliseconds).
    updated_at: i64,
}

#[tauri::command]
pub async fn backups(state: State<'_, AppState>) -> CmdResult<Backups> {
    let dir = state.backup_dir();
    Ok(Backups { backups: backup::list(&dir), dir: dir.display().to_string() })
}

#[tauri::command]
pub async fn backup_now(state: State<'_, AppState>) -> CmdResult<BackupInfo> {
    let dir = state.backup_dir();
    let guard = state.vault.lock().unwrap();
    backup::backup_now(guard.as_ref().ok_or("locked")?, &dir)
}

#[tauri::command]
pub async fn reveal_backups(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    use tauri_plugin_opener::OpenerExt;
    let dir = state.backup_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    app.opener().open_path(dir.to_string_lossy(), None::<&str>).map_err(|e| e.to_string())
}

/// Items in a backup that were deleted or edited since it was made.
#[tauri::command]
pub async fn backup_changes(state: State<'_, AppState>, id: String) -> CmdResult<Vec<BackupItem>> {
    let dir = state.backup_dir().join(backup_id(&id)?);
    state.with_vault(|v| {
        let backup = v.open_backup(&dir)?;
        let mut items: Vec<BackupItem> = v
            .changes_since(&backup)
            .into_iter()
            .filter_map(|(id, change)| {
                let item = backup.get(id)?;
                Some(BackupItem {
                    id: id.to_string(),
                    title: item.title.clone(),
                    subtitle: subtitle(item),
                    category: item.category,
                    change,
                    updated_at: item.updated_at,
                })
            })
            .collect();
        items.sort_by_key(|i| i.title.to_lowercase());
        Ok(items)
    })
}

#[tauri::command]
pub async fn restore_from_backup(state: State<'_, AppState>, id: String, item_ids: Vec<String>) -> CmdResult<usize> {
    let dir = state.backup_dir().join(backup_id(&id)?);
    let ids = item_ids.iter().map(|i| parse_id(i)).collect::<CmdResult<Vec<Uuid>>>()?;
    state.with_vault(|v| {
        let backup = v.open_backup(&dir)?;
        v.restore_from(&backup, &ids)
    })
}

/// A backup folder name from the UI, refused if it could point elsewhere.
fn backup_id(id: &str) -> CmdResult<&str> {
    if id.is_empty() || id.contains(['/', '\\']) || id.starts_with('.') {
        return Err("invalid backup".into());
    }
    Ok(id)
}

/// The list's second line: what tells two items of the same kind apart.
fn subtitle(item: &Item) -> String {
    match item.category {
        Category::Login => {
            if !item.username.is_empty() {
                item.username.clone()
            } else {
                item.urls.first().cloned().unwrap_or_default()
            }
        }
        Category::SecureNote => item.notes.lines().find(|l| !l.trim().is_empty()).unwrap_or("").chars().take(60).collect(),
        Category::CreditCard => {
            let digits: String = item.field("number").unwrap_or("").chars().filter(char::is_ascii_digit).collect();
            let last4 = &digits[digits.len().saturating_sub(4)..];
            match (card_brand(&digits), last4.is_empty()) {
                (_, true) => item.field("cardholder").unwrap_or("").to_string(),
                (Some(brand), false) => format!("{brand} •••• {last4}"),
                (None, false) => format!("•••• {last4}"),
            }
        }
        Category::Identity => ["first_name", "last_name"]
            .iter()
            .filter_map(|id| item.field(id))
            .collect::<Vec<_>>()
            .join(" "),
        Category::ApiCredential => item.field("hostname").or(item.field("username")).unwrap_or("").to_string(),
        Category::Document => item.files.first().map(|f| f.name.clone()).unwrap_or_default(),
    }
}

/// Card network from the number's prefix (for display only).
fn card_brand(digits: &str) -> Option<&'static str> {
    let prefix = |n: usize| digits.get(..n).and_then(|p| p.parse::<u32>().ok());
    if digits.starts_with('4') {
        Some("Visa")
    } else if prefix(2).is_some_and(|p| (51..=55).contains(&p)) || prefix(4).is_some_and(|p| (2221..=2720).contains(&p)) {
        Some("Mastercard")
    } else if prefix(2).is_some_and(|p| p == 34 || p == 37) {
        Some("Amex")
    } else if digits.starts_with("6011") || digits.starts_with("65") {
        Some("Discover")
    } else if prefix(4).is_some_and(|p| (3528..=3589).contains(&p)) {
        Some("JCB")
    } else {
        None
    }
}

// ---------- Open & Fill ----------

#[cfg(desktop)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedIn {
    /// "Microsoft Edge", or `None` if it went to the default browser
    /// (the extension may not be installed there).
    browser: Option<String>,
}

/// Open one of a login's websites in the browser where the Vaultix extension
/// runs; the extension then fills and submits the login form when it appears.
#[cfg(desktop)]
#[tauri::command]
pub async fn open_and_fill(app: AppHandle, state: State<'_, AppState>, id: String, url: String) -> CmdResult<OpenedIn> {
    let id = parse_id(&id)?;
    let parsed = url::Url::parse(&url).or_else(|_| url::Url::parse(&format!("https://{url}"))).map_err(|_| "That isn't a web address.")?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err("Only web addresses can be opened.".into());
    }
    state.with_vault(|v| {
        let item = v.get(id).ok_or_else(|| Error::InvalidVault("item not found".into()))?;
        if !item.urls.iter().any(|u| u.trim() == url.trim()) {
            return Err(Error::InvalidVault("that website isn't on this login".into()));
        }
        Ok(())
    })?;
    *state.pending_fill.lock().unwrap() = Some(PendingFill { item_id: id, expires_at: SystemTime::now() + OPEN_AND_FILL_WINDOW });

    let browser = state.config.lock().unwrap().browser_app.clone().filter(|p| p.exists());
    open_in(&app, browser.as_deref(), parsed.as_str()).map_err(|_| "Couldn't open the website.")?;
    Ok(OpenedIn { browser: browser.as_deref().and_then(crate::ipc::browser_name) })
}

/// Open `url` in `browser` (an `.app` bundle on macOS, an executable
/// elsewhere), or in the default browser.
#[cfg(desktop)]
fn open_in(app: &AppHandle, browser: Option<&Path>, url: &str) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let Some(browser) = browser else {
        return app.opener().open_url(url, None::<&str>).map_err(|e| e.to_string());
    };
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("/usr/bin/open").arg("-a").arg(browser).arg(url).status();
    // A Chromium browser started with a URL hands it to the running instance.
    #[cfg(not(target_os = "macos"))]
    let status = std::process::Command::new(browser).arg(url).spawn().map(|_| std::process::ExitStatus::default());
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => Err("couldn't start the browser".into()),
    }
}

// ---------- Files ----------

/// Encrypt a file the user picked into the vault folder. The returned
/// reference is stored on the item when it is saved.
#[tauri::command]
pub async fn attach_file(state: State<'_, AppState>, path: String) -> CmdResult<FileRef> {
    let path = PathBuf::from(path);
    let size = std::fs::metadata(&path).map_err(|e| e.to_string())?.len();
    if size > vaultix_core::vault::MAX_FILE_SIZE {
        return Err(format!("Files can be at most {} MB.", vaultix_core::vault::MAX_FILE_SIZE / 1024 / 1024));
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
    let mut contents = std::fs::read(&path).map_err(|e| e.to_string())?;
    let result = state.with_vault(|v| v.add_file(&name, &contents));
    zeroize::Zeroize::zeroize(&mut contents);
    result
}

/// Decrypt one of an item's files to a place the user picked.
#[tauri::command]
pub async fn export_file(state: State<'_, AppState>, item_id: String, file_id: String, dest: String) -> CmdResult<()> {
    let item_id = parse_id(&item_id)?;
    let file_id = parse_id(&file_id)?;
    let mut contents = state.with_vault(|v| {
        let file = v
            .get(item_id)
            .and_then(|i| i.files.iter().find(|f| f.id == file_id))
            .ok_or_else(|| Error::InvalidVault("file not found".into()))?;
        v.read_file(file)
    })?;
    let result = std::fs::write(&dest, &contents).map_err(|e| e.to_string());
    zeroize::Zeroize::zeroize(&mut contents);
    result
}

/// The website's icon for a login, as a `data:` URI; `None` when the site
/// has none (the UI then shows letters).
#[tauri::command]
pub async fn site_icon(app: AppHandle, url: String) -> CmdResult<Option<String>> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        if state.vault.lock().unwrap().is_none() {
            return Err("locked".to_string());
        }
        Ok(state.icons.get(&state.vault, &url))
    })
    .await
    .map_err(|e| e.to_string())?
}

// ---------- Helpers for the editor ----------

#[tauri::command]
pub async fn totp_code(state: State<'_, AppState>, id: String) -> CmdResult<Option<TotpCode>> {
    let id = parse_id(&id)?;
    let now = now_secs();
    state.with_vault(|v| {
        let Some(totp) = v.get(id).and_then(|i| i.totp.as_ref()) else { return Ok(None) };
        Ok(Some(TotpCode { code: totp.code_at(now)?, remaining: totp.seconds_remaining(now), period: totp.period }))
    })
}

/// Check TOTP input while the user types/pastes it, without saving.
#[tauri::command]
pub async fn check_totp(input: String) -> CmdResult<TotpCode> {
    let totp = Totp::parse(&input).map_err(|e| e.to_string())?;
    let now = now_secs();
    Ok(TotpCode { code: totp.code_at(now).map_err(|e| e.to_string())?, remaining: totp.seconds_remaining(now), period: totp.period })
}

/// Strength of a password as it would be judged for an item with these details.
/// Find a two-factor QR code on screen and return its `otpauth://` URI.
/// Errors are short codes: `qr-none`, `qr-permission`, `qr-not-totp`, …
#[tauri::command]
pub async fn scan_totp_qr() -> CmdResult<String> {
    let uri = tauri::async_runtime::spawn_blocking(crate::system::scan_screen_qr).await.map_err(|e| e.to_string())??;
    checked_totp_uri(uri)
}

/// The same for an image: a file the user picked (`path`), or one pasted or
/// dropped into the editor (`base64`).
#[tauri::command]
pub async fn scan_totp_qr_image(path: Option<String>, base64: Option<String>) -> CmdResult<String> {
    let image = match (path, base64) {
        (Some(path), _) => std::fs::read(&path).map_err(|e| e.to_string())?,
        (None, Some(b64)) => base64::engine::general_purpose::STANDARD.decode(b64).map_err(|_| "qr-failed")?,
        (None, None) => return Err("qr-failed".into()),
    };
    let uri = tauri::async_runtime::spawn_blocking(move || crate::system::scan_image_qr(&image)).await.map_err(|e| e.to_string())??;
    checked_totp_uri(uri)
}

fn checked_totp_uri(uri: String) -> CmdResult<String> {
    Totp::parse(&uri).map_err(|_| "qr-not-totp".to_string())?;
    Ok(uri)
}

#[tauri::command]
pub async fn password_strength(password: String, username: String, title: String, urls: Vec<String>) -> CmdResult<StrengthView> {
    let mut probe = Item::new(title, 0);
    probe.username = username;
    probe.password = password;
    probe.urls = urls;
    Ok(item_strength(&probe).into())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordCheck {
    strength: StrengthView,
    /// Why it can't be used yet, if it can't.
    problem: Option<String>,
}

#[tauri::command]
pub async fn master_password_check(password: String) -> CmdResult<MasterPasswordCheck> {
    Ok(MasterPasswordCheck {
        strength: vaultix_core::strength::estimate(&password, &[]).into(),
        problem: master_password_problem(&password),
    })
}

#[tauri::command]
pub async fn watchtower(state: State<'_, AppState>) -> CmdResult<Report> {
    let sites = state.sites.current();
    state.with_vault(|v| Ok(analyze(v.items(), &sites)))
}

#[tauri::command]
pub async fn generate_password(options: PasswordOptions) -> CmdResult<String> {
    Ok(generate(&options))
}

/// Copy a secret and wipe it from the clipboard after 30 s, unless the user
/// has copied something else in the meantime.
#[tauri::command]
pub async fn copy_secret(app: AppHandle, text: String) -> CmdResult<()> {
    copy_with_auto_clear(&app, text)
}

pub fn copy_with_auto_clear(app: &AppHandle, text: String) -> CmdResult<()> {
    app.clipboard().write_text(text.clone()).map_err(|e| e.to_string())?;
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(CLIPBOARD_CLEAR_AFTER);
        if app.clipboard().read_text().ok().as_deref() == Some(text.as_str()) {
            let _ = app.clipboard().write_text(String::new());
        }
        let mut text = text;
        zeroize::Zeroize::zeroize(&mut text);
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_fields(category: Category, fields: &[(&str, &str)]) -> Item {
        let mut item = Item::new("x", 0).with_category(category);
        item.fields = fields
            .iter()
            .map(|(id, value)| Field { id: id.to_string(), label: id.to_string(), kind: FieldKind::Text, value: value.to_string() })
            .collect();
        item
    }

    #[test]
    fn card_subtitle_shows_brand_and_last_four_only() {
        let card = with_fields(Category::CreditCard, &[("number", "4242 4242 4242 4242"), ("cardholder", "A Schmidt")]);
        assert_eq!(subtitle(&card), "Visa •••• 4242");
        let mc = with_fields(Category::CreditCard, &[("number", "2223003122003222")]);
        assert_eq!(subtitle(&mc), "Mastercard •••• 3222");
        let no_number = with_fields(Category::CreditCard, &[("cardholder", "A Schmidt")]);
        assert_eq!(subtitle(&no_number), "A Schmidt");
    }

    #[test]
    fn identity_subtitle_is_the_name() {
        let id = with_fields(Category::Identity, &[("first_name", "Alice"), ("last_name", "Schmidt")]);
        assert_eq!(subtitle(&id), "Alice Schmidt");
    }
}
