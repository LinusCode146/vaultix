//! Public lists of sites that support two-factor codes and passkeys
//! (2fa.directory), for Watchtower. The whole list is downloaded and matched
//! locally, so no request ever reveals which sites are in the vault.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use vaultix_core::watchtower::SiteDirectory;

const TOTP_URL: &str = "https://api.2fa.directory/v3/totp.json";
const PASSKEYS_URL: &str = "https://passkeys-api.2fa.directory/v1/supported.json";
const REFRESH_AFTER: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone)]
pub struct SiteLists {
    dir: PathBuf,
    current: Arc<RwLock<SiteDirectory>>,
}

impl SiteLists {
    /// Load the cached lists (if any) and refresh them in the background when
    /// they are missing or older than a week.
    pub fn start(cache_dir: PathBuf) -> SiteLists {
        let lists = SiteLists { dir: cache_dir, current: Arc::default() };
        if let Some(directory) = lists.load_cached() {
            *lists.current.write().unwrap() = directory;
        }
        if lists.is_stale() {
            let background = lists.clone();
            std::thread::spawn(move || {
                if let Err(e) = background.refresh() {
                    eprintln!("[vaultix] couldn't update site lists: {e}");
                }
            });
        }
        lists
    }

    pub fn current(&self) -> SiteDirectory {
        self.current.read().unwrap().clone()
    }

    fn totp_path(&self) -> PathBuf {
        self.dir.join("sites-totp.json")
    }

    fn passkeys_path(&self) -> PathBuf {
        self.dir.join("sites-passkeys.json")
    }

    fn load_cached(&self) -> Option<SiteDirectory> {
        let totp = fs::read_to_string(self.totp_path()).ok()?;
        let passkeys = fs::read_to_string(self.passkeys_path()).ok()?;
        SiteDirectory::from_json(&totp, &passkeys).ok()
    }

    fn is_stale(&self) -> bool {
        modified_age(&self.totp_path()).is_none_or(|age| age > REFRESH_AFTER)
    }

    fn refresh(&self) -> Result<(), String> {
        let totp = download(TOTP_URL)?;
        let passkeys = download(PASSKEYS_URL)?;
        // Only replace the cache with lists that actually parse.
        let directory = SiteDirectory::from_json(&totp, &passkeys).map_err(|e| e.to_string())?;
        fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        fs::write(self.totp_path(), totp).map_err(|e| e.to_string())?;
        fs::write(self.passkeys_path(), passkeys).map_err(|e| e.to_string())?;
        *self.current.write().unwrap() = directory;
        Ok(())
    }
}

fn download(url: &str) -> Result<String, String> {
    let mut response = ureq::get(url).call().map_err(|e| format!("{url}: {e}"))?;
    response.body_mut().read_to_string().map_err(|e| format!("{url}: {e}"))
}

fn modified_age(path: &Path) -> Option<Duration> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified).ok()
}
