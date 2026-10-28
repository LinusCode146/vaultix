//! Automatic backups of the vault folder, kept on this Mac (or a folder the
//! user picks), outside the synced folder, so a sync problem or a deleted
//! vault folder can't take them along. Backups are the vault's own encrypted
//! files: nothing is decrypted to make one.
//!
//! ```text
//! <backups>/
//! ├── 2026-10-28_091502/      ← vault.json, devices/*.log, files/*.bin
//! └── 2026-10-27_083011/
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use vaultix_core::Vault;

/// At most one automatic backup per this long.
const AUTO_EVERY: Duration = Duration::from_secs(24 * 3600);
/// The newest backups are all kept…
const KEEP_RECENT: usize = 14;
/// …and of older ones, the newest of each month, for this many months.
const KEEP_MONTHS: usize = 12;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfo {
    /// The folder name, e.g. `2026-10-28_091502`.
    pub id: String,
    /// Unix milliseconds.
    pub created_at: i64,
}

/// Backups in `dir`, newest first.
pub fn list(dir: &Path) -> Vec<BackupInfo> {
    let mut backups: Vec<(BackupInfo, SystemTime)> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().join("vault.json").is_file())
        .filter_map(|e| {
            let id = e.file_name().to_str()?.to_string();
            parse_name(&id)?;
            let modified = e.metadata().ok()?.modified().ok()?;
            Some((BackupInfo { created_at: ms(modified), id }, modified))
        })
        .collect();
    backups.sort_by(|a, b| b.0.id.cmp(&a.0.id));
    backups.into_iter().map(|(b, _)| b).collect()
}

/// Back up now, then delete backups the retention rules no longer keep.
pub fn backup_now(vault: &Vault, dir: &Path) -> Result<BackupInfo, String> {
    fs::create_dir_all(dir).map_err(|e| format!("Can't create the backup folder: {e}"))?;
    let previous = list(dir).into_iter().next().map(|b| dir.join(b.id));
    let mut id = folder_name(SystemTime::now());
    if dir.join(&id).exists() {
        id.push_str("-2");
    }
    vault.backup_to(&dir.join(&id), previous.as_deref()).map_err(|e| format!("Backup failed: {e}"))?;
    prune(dir);
    Ok(BackupInfo { id, created_at: ms(SystemTime::now()) })
}

/// Back up if the last backup is a day old and the vault changed since.
/// Cheap when there's nothing to do, so it can run on every sync.
pub fn auto(vault: &Vault, dir: &Path) {
    let newest = list(dir).into_iter().next();
    if let Some(b) = &newest {
        let age = ms(SystemTime::now()) - b.created_at;
        if age < AUTO_EVERY.as_millis() as i64 || log_sizes(&dir.join(&b.id)) == log_sizes(vault.dir()) {
            return;
        }
    }
    match backup_now(vault, dir) {
        Ok(b) => eprintln!("[vaultix] backed up the vault to {}", dir.join(b.id).display()),
        Err(e) => eprintln!("[vaultix] {e}"),
    }
}

/// Logs only ever grow, so equal sizes mean nothing changed.
fn log_sizes(vault_dir: &Path) -> BTreeMap<String, u64> {
    fs::read_dir(vault_dir.join("devices"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| Some((e.file_name().to_str()?.to_string(), e.metadata().ok()?.len())))
        .filter(|(name, _)| name.ends_with(".log"))
        .collect()
}

fn prune(dir: &Path) {
    let ids: Vec<String> = list(dir).into_iter().map(|b| b.id).collect();
    for id in to_prune(&ids) {
        if let Err(e) = fs::remove_dir_all(dir.join(&id)) {
            eprintln!("[vaultix] couldn't remove old backup {id}: {e}");
        }
    }
}

/// Of backup folder names (newest first), the ones to delete.
fn to_prune(ids: &[String]) -> Vec<String> {
    let mut months: Vec<&str> = Vec::new();
    let mut doomed = Vec::new();
    for id in ids.iter().skip(KEEP_RECENT) {
        let month = &id[..7]; // YYYY-MM
        if months.len() < KEEP_MONTHS && !months.contains(&month) {
            months.push(month);
        } else {
            doomed.push(id.clone());
        }
    }
    doomed
}

/// `YYYY-MM-DD_HHMMSS` in local time, so it reads naturally in Finder.
fn folder_name(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&secs, &mut tm) };
    format!(
        "{:04}-{:02}-{:02}_{:02}{:02}{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// `YYYY-MM-DD_HHMMSS`, or with `-2` added for a second backup in the same second.
fn parse_name(id: &str) -> Option<()> {
    let b = id.as_bytes();
    let digits = |s: &[u8]| !s.is_empty() && s.iter().all(u8::is_ascii_digit);
    let stamp = b.len() >= 17
        && digits(&b[0..4])
        && b[4] == b'-'
        && digits(&b[5..7])
        && b[7] == b'-'
        && digits(&b[8..10])
        && b[10] == b'_'
        && digits(&b[11..17]);
    let rest = b.get(17..).unwrap_or_default();
    (stamp && (rest.is_empty() || (rest[0] == b'-' && digits(&rest[1..])))).then_some(())
}

fn ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn default_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("backups")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_two_weeks_then_one_per_month_for_a_year() {
        // A daily backup for 500 days, newest first.
        let start = SystemTime::now();
        let ids: Vec<String> = (0..500).map(|d| folder_name(start - Duration::from_secs(d * 86_400))).collect();
        let doomed = to_prune(&ids);
        let kept: Vec<&String> = ids.iter().filter(|id| !doomed.contains(id)).collect();
        assert_eq!(&kept[..KEEP_RECENT], &ids.iter().take(KEEP_RECENT).collect::<Vec<_>>()[..]);
        let older = &kept[KEEP_RECENT..];
        assert_eq!(older.len(), KEEP_MONTHS);
        let mut months: Vec<&str> = older.iter().map(|id| &id[..7]).collect();
        months.dedup();
        assert_eq!(months.len(), older.len(), "one per month");
    }

    #[test]
    fn folder_names_parse() {
        assert!(parse_name(&folder_name(SystemTime::now())).is_some());
        assert!(parse_name("2026-10-28_091502-2").is_some());
        assert!(parse_name("notes").is_none());
        assert!(parse_name("2026-10-28_091502.partial").is_none());
    }

    #[test]
    fn auto_backs_up_once_until_a_day_passes() {
        let (vault_dir, backups) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut v = Vault::create_with_params(
            vault_dir.path(),
            "correct horse battery staple",
            uuid::Uuid::new_v4(),
            vaultix_core::crypto::KdfParams::insecure_fast(),
        )
        .unwrap();
        v.put(vaultix_core::Item::new("x", 0)).unwrap();
        auto(&v, backups.path());
        auto(&v, backups.path());
        assert_eq!(list(backups.path()).len(), 1);
    }
}
