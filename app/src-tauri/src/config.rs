//! Non-secret, per-Mac settings in `~/Library/Application Support/<app id>/config.json`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Identifies this Mac's log file in the synced folder. Never changes.
    pub device_id: Uuid,
    /// The vault this Mac is set up for, if any.
    pub vault: Option<VaultLocation>,
    /// The browser the extension last connected from (its `.app` bundle):
    /// "Open & Fill" opens websites there.
    #[serde(default)]
    pub browser_app: Option<PathBuf>,
    #[serde(default)]
    pub settings: Settings,
}

/// Choices from the Settings screen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Lock when the Mac sleeps, the screen locks or another user switches in.
    pub lock_on_sleep: bool,
    /// ⌘⇧Space opens the quick search window.
    pub quick_search: bool,
    /// Where backups go; `None` is the app's own folder on this Mac.
    pub backup_dir: Option<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { lock_on_sleep: true, quick_search: true, backup_dir: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultLocation {
    pub dir: PathBuf,
    pub vault_id: Uuid,
}

impl Config {
    pub fn load_or_init(path: &Path) -> std::io::Result<Config> {
        if let Ok(bytes) = fs::read(path)
            && let Ok(config) = serde_json::from_slice(&bytes)
        {
            return Ok(config);
        }
        let config = Config { device_id: Uuid::new_v4(), vault: None, browser_app: None, settings: Settings::default() };
        config.save(path)?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        fs::rename(tmp, path)
    }
}
