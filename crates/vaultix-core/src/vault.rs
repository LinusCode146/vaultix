//! The vault on disk, and folder-based sync between devices.
//!
//! ```text
//! <vault folder>/                  ← lives in iCloud Drive / Dropbox / Syncthing
//! ├── vault.json                   ← KDF params, salt, wrapped vault key
//! ├── devices/
//! │   ├── <device-uuid-A>.log      ← only device A ever writes this file
//! │   └── <device-uuid-B>.log
//! └── files/
//!     └── <file-uuid>.bin          ← one encrypted attachment, written once, never changed
//! ```
//!
//! Each line of a log is one encrypted change (put or delete of one item).
//! Because every file has a single writer, the sync service never has to merge
//! a file, so there are no "conflicted copy" files. Each device replays all
//! logs and keeps, per item, the change with the highest [`Hlc`] timestamp.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::crypto::{self, KEY_LEN, KdfParams, Key};
use crate::error::{Error, Result};
use crate::hlc::Hlc;
use crate::item::{FileRef, Item};
use crate::passkey::Passkey;

const META_FILE: &str = "vault.json";
const DEVICES_DIR: &str = "devices";
const FILES_DIR: &str = "files";
/// Largest file that can be stored in an item. Files are encrypted in memory
/// in one piece, and every Mac downloads every file through the sync service.
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;
/// 2: master password only (1 also required a Secret Key).
const FORMAT_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultMeta {
    format: u32,
    vault_id: Uuid,
    kdf: KdfParams,
    salt: String,
    wrapped_vault_key: String,
}

#[derive(Serialize, Deserialize)]
struct LogEntry {
    hlc: Hlc,
    item_id: Uuid,
    /// `None` is a tombstone: the item was deleted.
    item: Option<Item>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub devices: usize,
    pub entries: usize,
    /// Lines that could not be read: usually a log that is still mid-upload by
    /// the sync service, otherwise corruption or tampering.
    pub skipped_lines: usize,
    /// Items added, changed or deleted by this sync (0 when nothing new arrived).
    pub changed_items: usize,
}

pub struct Vault {
    dir: PathBuf,
    meta: VaultMeta,
    vault_key: Key,
    device_id: Uuid,
    clock: Hlc,
    state: BTreeMap<Uuid, (Hlc, Option<Item>)>,
    /// A backup opened with [`Vault::open_backup`]: never written to.
    read_only: bool,
}

/// How an item in a backup differs from the vault today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BackupChange {
    /// Deleted since the backup.
    Deleted,
    /// Edited since the backup.
    Changed,
}

impl Vault {
    /// Create a new vault in an empty (or new) folder.
    pub fn create(dir: &Path, password: &str, device_id: Uuid) -> Result<Vault> {
        Self::create_with_params(dir, password, device_id, KdfParams::default())
    }

    pub fn create_with_params(dir: &Path, password: &str, device_id: Uuid, kdf: KdfParams) -> Result<Vault> {
        if dir.join(META_FILE).exists() {
            return Err(Error::InvalidVault("a vault already exists in this folder".into()));
        }
        fs::create_dir_all(dir.join(DEVICES_DIR))?;

        let vault_id = Uuid::new_v4();
        let vault_key = Key::random();
        let meta = wrap_meta(vault_id, &vault_key, password, kdf)?;
        write_meta(dir, &meta)?;

        let vault = Vault {
            dir: dir.to_path_buf(),
            meta,
            vault_key,
            device_id,
            clock: Hlc::zero(device_id),
            state: BTreeMap::new(),
            read_only: false,
        };
        Ok(vault)
    }

    /// Unlock an existing vault (also how a new Mac joins: point it at the
    /// synced folder and enter the master password).
    pub fn unlock(dir: &Path, password: &str, device_id: Uuid) -> Result<Vault> {
        let meta = read_meta(dir)?;
        let salt = B64.decode(&meta.salt).map_err(|_| Error::InvalidVault("bad salt".into()))?;
        let wrapped = B64.decode(&meta.wrapped_vault_key).map_err(|_| Error::InvalidVault("bad wrapped key".into()))?;

        let kek = crypto::derive_kek(password, &salt, meta.kdf)?;
        let raw = crypto::open(&kek, &wrapped, &key_aad(&meta.vault_id)).map_err(|_| Error::WrongPassword)?;
        Self::open_with_key(dir, meta, raw, device_id)
    }

    /// Wrap the vault key for unlocking on this Mac without the master
    /// password (Touch ID): `device_key` comes from the Secure Enclave and
    /// never leaves this Mac. The result must stay on this Mac too.
    pub fn wrap_for_device(&self, device_key: &[u8; KEY_LEN]) -> Vec<u8> {
        let key = Key::from_bytes(*device_key);
        crypto::seal(&key, self.vault_key.as_bytes(), &device_aad(&self.meta.vault_id, &self.device_id))
    }

    /// Unlock with a vault key wrapped by [`Vault::wrap_for_device`].
    pub fn unlock_with_device_key(dir: &Path, device_id: Uuid, device_key: &[u8; KEY_LEN], wrapped: &[u8]) -> Result<Vault> {
        let meta = read_meta(dir)?;
        let key = Key::from_bytes(*device_key);
        let raw = crypto::open(&key, wrapped, &device_aad(&meta.vault_id, &device_id)).map_err(|_| Error::Decrypt)?;
        Self::open_with_key(dir, meta, raw, device_id)
    }

    fn open_with_key(dir: &Path, meta: VaultMeta, raw: Vec<u8>, device_id: Uuid) -> Result<Vault> {
        let mut raw = raw;
        let bytes: Option<[u8; KEY_LEN]> = raw.as_slice().try_into().ok();
        zeroize::Zeroize::zeroize(&mut raw);
        let raw = bytes.ok_or_else(|| Error::InvalidVault("bad vault key length".into()))?;

        fs::create_dir_all(dir.join(DEVICES_DIR))?;
        let mut vault = Vault {
            dir: dir.to_path_buf(),
            meta,
            vault_key: Key::from_bytes(raw),
            device_id,
            clock: Hlc::zero(device_id),
            state: BTreeMap::new(),
            read_only: false,
        };
        vault.sync()?;
        Ok(vault)
    }

    pub fn vault_id(&self) -> Uuid {
        self.meta.vault_id
    }

    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    // ---------- Backups ----------

    /// Copy the vault folder's files, all of them still encrypted, into
    /// `dest`, which must not exist yet. Stored files never change, so those
    /// already in `previous` (an earlier backup) are hard-linked from there
    /// instead of copied again. The copy is made under a temporary name and
    /// renamed when complete, so `dest` is never a partial backup.
    pub fn backup_to(&self, dest: &Path, previous: Option<&Path>) -> Result<()> {
        if dest.exists() {
            return Err(Error::InvalidVault(format!("{} already exists", dest.display())));
        }
        let partial = dest.with_extension("partial");
        if partial.exists() {
            fs::remove_dir_all(&partial)?;
        }
        fs::create_dir_all(partial.join(DEVICES_DIR))?;
        fs::copy(self.dir.join(META_FILE), partial.join(META_FILE))?;
        for entry in fs::read_dir(self.dir.join(DEVICES_DIR))? {
            let path = entry?.path();
            if log_device_id(&path).is_some() {
                fs::copy(&path, partial.join(DEVICES_DIR).join(path.file_name().expect("has a name")))?;
            }
        }
        if let Ok(files) = fs::read_dir(self.dir.join(FILES_DIR)) {
            fs::create_dir_all(partial.join(FILES_DIR))?;
            for entry in files {
                let path = entry?.path();
                if path.extension().is_none_or(|e| e != "bin") {
                    continue;
                }
                let name = path.file_name().expect("has a name");
                let target = partial.join(FILES_DIR).join(name);
                let linked = previous
                    .map(|p| p.join(FILES_DIR).join(name))
                    .filter(|old| old.is_file())
                    .is_some_and(|old| fs::hard_link(old, &target).is_ok());
                if !linked {
                    fs::copy(&path, &target)?;
                }
            }
        }
        fs::rename(&partial, dest)?;
        Ok(())
    }

    /// Open a backup made by [`Vault::backup_to`], read-only, with this
    /// vault's key. The vault key never changes (a new master password only
    /// re-wraps it), so no password is needed, however old the backup.
    pub fn open_backup(&self, dir: &Path) -> Result<Vault> {
        let meta = read_meta(dir)?;
        if meta.vault_id != self.meta.vault_id {
            return Err(Error::InvalidVault("This backup is of a different vault.".into()));
        }
        let mut backup = Vault {
            dir: dir.to_path_buf(),
            meta,
            vault_key: self.vault_key.clone(),
            device_id: self.device_id,
            clock: Hlc::zero(self.device_id),
            state: BTreeMap::new(),
            read_only: true,
        };
        backup.sync()?;
        Ok(backup)
    }

    /// Items in `backup` that were deleted or edited since, by item ID.
    pub fn changes_since(&self, backup: &Vault) -> Vec<(Uuid, BackupChange)> {
        backup
            .state
            .iter()
            .filter_map(|(id, (then, item))| {
                item.as_ref()?;
                match self.state.get(id) {
                    None | Some((_, None)) => Some((*id, BackupChange::Deleted)),
                    Some((now, Some(_))) if now != then => Some((*id, BackupChange::Changed)),
                    _ => None,
                }
            })
            .collect()
    }

    /// Bring items back from `backup` as they were then. They are saved as
    /// new changes, so they win on every Mac; a password that differs goes
    /// into the item's history. Files the vault no longer has are copied back.
    pub fn restore_from(&mut self, backup: &Vault, ids: &[Uuid]) -> Result<usize> {
        let mut restored = 0;
        for id in ids {
            let Some(item) = backup.get(*id).cloned() else {
                continue;
            };
            for file in &item.files {
                let (from, to) = (backup.file_path(file.id), self.file_path(file.id));
                if !to.exists() && from.exists() {
                    fs::create_dir_all(self.dir.join(FILES_DIR))?;
                    fs::copy(from, to)?;
                }
            }
            self.put(item)?;
            restored += 1;
        }
        Ok(restored)
    }

    /// Re-read every device's log and rebuild the item set. Call on unlock,
    /// on a timer, and when the folder changes (FSEvents).
    pub fn sync(&mut self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        let mut state: BTreeMap<Uuid, (Hlc, Option<Item>)> = BTreeMap::new();
        let mut max_seen = self.clock;

        for entry in fs::read_dir(self.dir.join(DEVICES_DIR))? {
            let path = entry?.path();
            let Some(device) = log_device_id(&path) else {
                continue;
            };
            report.devices += 1;

            let contents = fs::read_to_string(&path)?;
            for line in contents.lines().filter(|l| !l.is_empty()) {
                match self.decode_line(line, device) {
                    Some(e) => {
                        report.entries += 1;
                        max_seen = max_seen.max(e.hlc);
                        let newer = state.get(&e.item_id).is_none_or(|(h, _)| e.hlc > *h);
                        if newer {
                            state.insert(e.item_id, (e.hlc, e.item));
                        }
                    }
                    None => report.skipped_lines += 1,
                }
            }
        }

        report.changed_items = state
            .keys()
            .chain(self.state.keys())
            .collect::<HashSet<_>>()
            .into_iter()
            .filter(|id| state.get(id).map(|(h, _)| h) != self.state.get(id).map(|(h, _)| h))
            .count();
        self.state = state;
        self.clock = max_seen;
        Ok(report)
    }

    /// All live items, sorted by title.
    pub fn items(&self) -> Vec<&Item> {
        let mut items: Vec<&Item> = self.state.values().filter_map(|(_, i)| i.as_ref()).collect();
        items.sort_by_key(|i| i.title.to_lowercase());
        items
    }

    pub fn get(&self, id: Uuid) -> Option<&Item> {
        self.state.get(&id).and_then(|(_, i)| i.as_ref())
    }

    /// Logins to offer for autofill on `page_url`.
    pub fn items_for_page(&self, page_url: &str) -> Vec<&Item> {
        self.items().into_iter().filter(|i| i.matches_page(page_url)).collect()
    }

    /// Passkeys for a relying party, for `navigator.credentials.get`.
    pub fn passkeys_for_rp(&self, rp_id: &str) -> Vec<(&Item, &Passkey)> {
        let rp_id = rp_id.to_ascii_lowercase();
        self.items().into_iter().flat_map(|i| i.passkeys.iter().map(move |p| (i, p))).filter(|(_, p)| p.rp_id == rp_id).collect()
    }

    /// Insert or replace an item. A replaced password goes into the item's
    /// password history, however the item was edited.
    pub fn put(&mut self, mut item: Item) -> Result<()> {
        let hlc = Hlc::tick(self.clock, now_ms(), self.device_id);
        if let Some(previous) = self.get(item.id) {
            let previous = previous.password.clone();
            item.remember_password(&previous, hlc.wall_ms);
        }
        item.updated_at = hlc.wall_ms;
        let id = item.id;
        self.append(&LogEntry { hlc, item_id: id, item: Some(item.clone()) })?;
        self.clock = hlc;
        self.state.insert(id, (hlc, Some(item)));
        Ok(())
    }

    pub fn delete(&mut self, id: Uuid) -> Result<()> {
        let hlc = Hlc::tick(self.clock, now_ms(), self.device_id);
        self.append(&LogEntry { hlc, item_id: id, item: None })?;
        self.clock = hlc;
        self.state.insert(id, (hlc, None));
        Ok(())
    }

    /// Encrypt a file into the vault folder and return the reference to store
    /// on an item. Until an item that references it is saved, the file is an
    /// orphan and [`Vault::sweep_files`] eventually removes it.
    pub fn add_file(&self, name: &str, contents: &[u8]) -> Result<FileRef> {
        if contents.len() as u64 > MAX_FILE_SIZE {
            return Err(Error::File(format!("Files can be at most {} MB.", MAX_FILE_SIZE / 1024 / 1024)));
        }
        let id = Uuid::new_v4();
        let sealed = crypto::seal(&self.vault_key, contents, &file_aad(&self.meta.vault_id, &id));
        let dir = self.dir.join(FILES_DIR);
        fs::create_dir_all(&dir)?;
        let tmp = dir.join(format!("{id}.tmp"));
        fs::write(&tmp, sealed)?;
        fs::rename(tmp, dir.join(format!("{id}.bin")))?;
        Ok(FileRef { id, name: name.to_string(), size: contents.len() as u64 })
    }

    /// Decrypt a stored file. The caller should zeroize the result when done.
    pub fn read_file(&self, file: &FileRef) -> Result<Vec<u8>> {
        let sealed = match fs::read(self.file_path(file.id)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::File("This file hasn't synced to this Mac yet. Try again in a moment.".into()));
            }
            Err(e) => return Err(e.into()),
        };
        crypto::open(&self.vault_key, &sealed, &file_aad(&self.meta.vault_id, &file.id))
    }

    /// Delete stored files that no live item references and that are older
    /// than `min_age`. The age check leaves time for the log entry that
    /// references a new file to arrive from another Mac. Returns how many were removed.
    pub fn sweep_files(&self, min_age: Duration) -> Result<usize> {
        let dir = self.dir.join(FILES_DIR);
        let Ok(entries) = fs::read_dir(&dir) else {
            return Ok(0);
        };
        let referenced: HashSet<Uuid> = self.items().iter().flat_map(|i| i.files.iter().map(|f| f.id)).collect();
        let mut removed = 0;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let Some(id) = path.file_stem().and_then(|s| s.to_str()).and_then(|s| Uuid::parse_str(s).ok()) else {
                continue;
            };
            if referenced.contains(&id) {
                continue;
            }
            let old_enough = entry.metadata()?.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|age| age >= min_age);
            if old_enough {
                fs::remove_file(&path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn file_path(&self, id: Uuid) -> PathBuf {
        self.dir.join(FILES_DIR).join(format!("{id}.bin"))
    }

    /// Encrypt data that stays on this Mac, such as cached website icons.
    /// `purpose` is bound to the ciphertext, so data sealed for one use can't
    /// be passed off as another.
    pub fn seal_local(&self, purpose: &str, data: &[u8]) -> Vec<u8> {
        crypto::seal(&self.vault_key, data, &local_aad(&self.meta.vault_id, purpose))
    }

    pub fn open_local(&self, purpose: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        crypto::open(&self.vault_key, sealed, &local_aad(&self.meta.vault_id, purpose))
    }

    /// A file name for `value` that doesn't reveal it: without the vault key,
    /// "github.com" can't be recovered from it, or even guessed and checked.
    pub fn private_name(&self, purpose: &str, value: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.vault_key.as_bytes()).expect("any key length works");
        mac.update(b"vaultix/private-name/v1/");
        mac.update(purpose.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        data_encoding::HEXLOWER.encode(&mac.finalize().into_bytes()[..16])
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.meta.kdf
    }

    /// Re-wrap the vault key with stronger key-derivation settings, if the
    /// vault was created with weaker ones. Needs the (correct) password, so
    /// call it right after a successful unlock. Returns whether it upgraded.
    pub fn upgrade_kdf(&mut self, password: &str, target: KdfParams) -> Result<bool> {
        if !self.meta.kdf.weaker_than(&target) {
            return Ok(false);
        }
        let meta = wrap_meta(self.meta.vault_id, &self.vault_key, password, target)?;
        write_meta(&self.dir, &meta)?;
        self.meta = meta;
        Ok(true)
    }

    /// Change the master password. Only the vault key is re-wrapped (with a
    /// fresh salt); item data is untouched. Other devices pick this up on
    /// their next unlock.
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        let meta = wrap_meta(self.meta.vault_id, &self.vault_key, new_password, self.meta.kdf)?;
        write_meta(&self.dir, &meta)?;
        self.meta = meta;
        Ok(())
    }

    fn log_path(&self) -> PathBuf {
        self.dir.join(DEVICES_DIR).join(format!("{}.log", self.device_id))
    }

    fn append(&self, entry: &LogEntry) -> Result<()> {
        if self.read_only {
            return Err(Error::InvalidVault("backups can't be changed".into()));
        }
        let mut plaintext = serde_json::to_vec(entry)?;
        let sealed = crypto::seal(&self.vault_key, &plaintext, &log_aad(&self.meta.vault_id, &self.device_id));
        zeroize::Zeroize::zeroize(&mut plaintext);

        let mut file = OpenOptions::new().create(true).read(true).append(true).open(self.log_path())?;
        // If a previous write was cut off, start on a fresh line so this entry
        // isn't glued onto the broken one.
        let len = file.metadata()?.len();
        let mut prefix = "";
        if len > 0 {
            let mut last = [0u8; 1];
            file.seek(SeekFrom::Start(len - 1))?;
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                prefix = "\n";
            }
        }
        file.write_all(format!("{prefix}{}\n", B64.encode(sealed)).as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    fn decode_line(&self, line: &str, device: Uuid) -> Option<LogEntry> {
        let sealed = B64.decode(line.trim()).ok()?;
        let plain = crypto::open(&self.vault_key, &sealed, &log_aad(&self.meta.vault_id, &device)).ok()?;
        let entry: LogEntry = serde_json::from_slice(&plain).ok()?;
        // A device may only author entries in its own log.
        (entry.hlc.device == device).then_some(entry)
    }
}

fn wrap_meta(vault_id: Uuid, vault_key: &Key, password: &str, kdf: KdfParams) -> Result<VaultMeta> {
    let salt: [u8; 16] = crypto::random_bytes();
    let kek = crypto::derive_kek(password, &salt, kdf)?;
    let wrapped = crypto::seal(&kek, vault_key.as_bytes(), &key_aad(&vault_id));
    Ok(VaultMeta { format: FORMAT_VERSION, vault_id, kdf, salt: B64.encode(salt), wrapped_vault_key: B64.encode(wrapped) })
}

/// Write via a temp file + rename so a crash never leaves a half-written meta file.
fn write_meta(dir: &Path, meta: &VaultMeta) -> Result<()> {
    let tmp = dir.join(format!("{META_FILE}.tmp"));
    fs::write(&tmp, serde_json::to_vec_pretty(meta)?)?;
    fs::rename(tmp, dir.join(META_FILE))?;
    Ok(())
}

fn key_aad(vault_id: &Uuid) -> Vec<u8> {
    [b"vaultix/vault-key/v1/".as_slice(), vault_id.as_bytes()].concat()
}

fn log_aad(vault_id: &Uuid, device: &Uuid) -> Vec<u8> {
    [b"vaultix/log/v1/".as_slice(), vault_id.as_bytes(), device.as_bytes()].concat()
}

fn read_meta(dir: &Path) -> Result<VaultMeta> {
    let meta: VaultMeta = serde_json::from_slice(&fs::read(dir.join(META_FILE))?)?;
    if meta.format != FORMAT_VERSION {
        return Err(Error::InvalidVault(format!("unsupported format {}", meta.format)));
    }
    Ok(meta)
}

fn device_aad(vault_id: &Uuid, device: &Uuid) -> Vec<u8> {
    [b"vaultix/device-unlock/v1/".as_slice(), vault_id.as_bytes(), device.as_bytes()].concat()
}

fn local_aad(vault_id: &Uuid, purpose: &str) -> Vec<u8> {
    [b"vaultix/local/v1/".as_slice(), vault_id.as_bytes(), purpose.as_bytes()].concat()
}

fn file_aad(vault_id: &Uuid, file_id: &Uuid) -> Vec<u8> {
    [b"vaultix/file/v1/".as_slice(), vault_id.as_bytes(), file_id.as_bytes()].concat()
}

fn log_device_id(path: &Path) -> Option<Uuid> {
    if path.extension()? != "log" {
        return None;
    }
    Uuid::parse_str(path.file_stem()?.to_str()?).ok()
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
