//! Two "Macs" share one folder, standing in for iCloud Drive / Dropbox.
//! Not calling `sync()` on a device is the same as that device being offline.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

use uuid::Uuid;
use vaultix_core::crypto::KdfParams;
use vaultix_core::passkey::Passkey;
use vaultix_core::{Error, Item, Totp, Vault};

const PW: &str = "correct horse battery staple";

fn new_vault(dir: &Path) -> Vault {
    Vault::create_with_params(dir, PW, Uuid::new_v4(), KdfParams::insecure_fast()).unwrap()
}

fn login(title: &str, url: &str, password: &str) -> Item {
    let mut item = Item::new(title, 0);
    item.username = "alice".into();
    item.password = password.into();
    item.urls = vec![url.into()];
    item
}

/// Make sure consecutive changes land in different milliseconds, so the test
/// controls which one is "later".
fn tick() {
    sleep(Duration::from_millis(5));
}

#[test]
fn create_lock_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    let device = a.device_id();
    let item = login("GitHub", "https://github.com", "s3cret");
    let id = item.id;
    a.put(item).unwrap();
    drop(a); // lock

    let a = Vault::unlock(dir.path(), PW, device).unwrap();
    assert_eq!(a.get(id).unwrap().password, "s3cret");
}

#[test]
fn wrong_password_fails() {
    let dir = tempfile::tempdir().unwrap();
    new_vault(dir.path());
    assert!(matches!(Vault::unlock(dir.path(), "nope", Uuid::new_v4()), Err(Error::WrongPassword)));
    assert!(Vault::unlock(dir.path(), PW, Uuid::new_v4()).is_ok());
}

#[test]
fn nothing_readable_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    a.put(login("Bank", "https://bank.example", "hunter2-very-secret")).unwrap();
    for entry in walk(dir.path()) {
        let bytes = fs::read(&entry).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("hunter2") && !text.contains("Bank") && !text.contains("bank.example"));
    }
}

#[test]
fn second_device_joins_and_syncs() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    a.put(login("GitHub", "https://github.com", "one")).unwrap();

    let mut b = Vault::unlock(dir.path(), PW, Uuid::new_v4()).unwrap();
    assert_eq!(b.items().len(), 1);

    b.put(login("Mail", "https://mail.example", "two")).unwrap();
    assert_eq!(a.items().len(), 1, "A hasn't synced yet");
    let report = a.sync().unwrap();
    assert_eq!(a.items().len(), 2);
    assert_eq!(report.devices, 2);
    assert_eq!(report.skipped_lines, 0);
}

#[test]
fn concurrent_offline_edits_converge_on_latest() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    let item = login("GitHub", "https://github.com", "original");
    let id = item.id;
    a.put(item).unwrap();
    let mut b = Vault::unlock(dir.path(), PW, Uuid::new_v4()).unwrap();

    // Both edit while "offline"; B's edit is later.
    tick();
    let mut on_a = a.get(id).unwrap().clone();
    on_a.password = "from-a".into();
    a.put(on_a).unwrap();
    tick();
    let mut on_b = b.get(id).unwrap().clone();
    on_b.password = "from-b".into();
    b.put(on_b).unwrap();

    a.sync().unwrap();
    b.sync().unwrap();
    assert_eq!(a.get(id).unwrap().password, "from-b");
    assert_eq!(b.get(id).unwrap().password, "from-b");
}

#[test]
fn deletes_are_not_resurrected_by_older_edits() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    let item = login("Old", "https://old.example", "x");
    let id = item.id;
    a.put(item).unwrap();
    let mut b = Vault::unlock(dir.path(), PW, Uuid::new_v4()).unwrap();

    tick();
    let mut edited = b.get(id).unwrap().clone();
    edited.notes = "edited on B".into();
    b.put(edited).unwrap();
    tick();
    a.delete(id).unwrap(); // later than B's edit

    a.sync().unwrap();
    b.sync().unwrap();
    assert!(a.get(id).is_none());
    assert!(b.get(id).is_none());
}

#[test]
fn edit_after_seeing_remote_change_wins_even_with_a_slow_clock() {
    // B's clock can't be faked here, but after syncing, B's next change must
    // sort after everything it has seen, which the HLC guarantees.
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    let item = login("X", "https://x.example", "1");
    let id = item.id;
    a.put(item).unwrap();
    let mut b = Vault::unlock(dir.path(), PW, Uuid::new_v4()).unwrap();
    let mut edit = b.get(id).unwrap().clone();
    edit.password = "2".into();
    b.put(edit).unwrap(); // possibly the same millisecond as A's put
    a.sync().unwrap();
    assert_eq!(a.get(id).unwrap().password, "2");
}

#[test]
fn half_uploaded_log_line_is_skipped_and_log_still_appendable() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    let device = a.device_id();
    a.put(login("One", "https://one.example", "1")).unwrap();

    let log = dir.path().join("devices").join(format!("{device}.log"));
    let mut f = OpenOptions::new().append(true).open(&log).unwrap();
    f.write_all(b"dGhpcyBpcyBub3QgYSB2YWxpZC").unwrap(); // truncated, no newline
    drop(f);

    let mut a = Vault::unlock(dir.path(), PW, device).unwrap();
    assert_eq!(a.items().len(), 1);
    a.put(login("Two", "https://two.example", "2")).unwrap();
    let report = a.sync().unwrap();
    assert_eq!(a.items().len(), 2);
    assert_eq!(report.skipped_lines, 1);
}

#[test]
fn entries_cannot_be_moved_between_device_logs() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    a.put(login("One", "https://one.example", "1")).unwrap();
    let a_log = dir.path().join("devices").join(format!("{}.log", a.device_id()));
    let forged = dir.path().join("devices").join(format!("{}.log", Uuid::new_v4()));
    fs::copy(&a_log, &forged).unwrap();

    let report = a.sync().unwrap();
    assert_eq!(report.skipped_lines, 1);
}

#[test]
fn change_password() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    a.put(login("One", "https://one.example", "1")).unwrap();
    a.change_password("new password").unwrap();

    assert!(matches!(Vault::unlock(dir.path(), PW, Uuid::new_v4()), Err(Error::WrongPassword)));
    let b = Vault::unlock(dir.path(), "new password", Uuid::new_v4()).unwrap();
    assert_eq!(b.items().len(), 1);
}

#[test]
fn autofill_and_passkey_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());

    let mut gh = login("GitHub", "https://github.com", "pw");
    gh.totp = Some(Totp::parse("JBSWY3DPEHPK3PXP").unwrap());
    let (pk, _) = Passkey::create("github.com", "https://github.com", b"uid", "alice", "Alice", 0).unwrap();
    gh.passkeys.push(pk);
    a.put(gh).unwrap();
    a.put(login("Evil lookalike", "https://github.com.evil.net", "pw")).unwrap();

    // Syncs to another device with passkey and TOTP intact.
    let b = Vault::unlock(dir.path(), PW, Uuid::new_v4()).unwrap();
    let matches = b.items_for_page("https://github.com/login");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].title, "GitHub");
    assert_eq!(matches[0].totp.as_ref().unwrap().code_at(0).unwrap().len(), 6);

    let passkeys = b.passkeys_for_rp("github.com");
    assert_eq!(passkeys.len(), 1);
    assert!(passkeys[0].1.assert("https://github.com", &[0u8; 32]).is_ok());
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[test]
fn weak_kdf_settings_are_upgraded_after_unlock() {
    let dir = tempfile::tempdir().unwrap();
    new_vault(dir.path()); // created with insecure_fast()
    let target = KdfParams { m_cost: 128, t_cost: 2, p_cost: 1 };
    let mut a = Vault::unlock(dir.path(), PW, Uuid::new_v4()).unwrap();
    assert!(a.upgrade_kdf(PW, target).unwrap());
    assert_eq!(a.kdf_params(), target);
    assert!(!a.upgrade_kdf(PW, target).unwrap(), "already strong enough");

    // Still opens with the same password, now with the new settings.
    let b = Vault::unlock(dir.path(), PW, Uuid::new_v4()).unwrap();
    assert_eq!(b.kdf_params(), target);
}

#[test]
fn files_are_encrypted_and_readable_on_another_mac() {
    let dir = tempfile::tempdir().unwrap();
    let a = new_vault(dir.path());
    let secret = b"passport scan: P1234567";
    let file = a.add_file("passport.pdf", secret).unwrap();
    assert_eq!(file.size, secret.len() as u64);

    let on_disk = fs::read(dir.path().join("files").join(format!("{}.bin", file.id))).unwrap();
    assert!(!on_disk.windows(8).any(|w| w == b"P1234567"));

    let b = Vault::unlock(dir.path(), PW, Uuid::new_v4()).unwrap();
    assert_eq!(b.read_file(&file).unwrap(), secret);

    // A stored file can't be passed off as a different one.
    let other = a.add_file("other.txt", b"x").unwrap();
    fs::copy(dir.path().join("files").join(format!("{}.bin", file.id)), dir.path().join("files").join(format!("{}.bin", other.id)))
        .unwrap();
    assert!(matches!(b.read_file(&other), Err(Error::Decrypt)));
}

#[test]
fn missing_file_reports_not_synced() {
    let dir = tempfile::tempdir().unwrap();
    let a = new_vault(dir.path());
    let file = a.add_file("a.txt", b"hello").unwrap();
    fs::remove_file(dir.path().join("files").join(format!("{}.bin", file.id))).unwrap();
    assert!(matches!(a.read_file(&file), Err(Error::File(msg)) if msg.contains("synced")));
}

#[test]
fn sweep_removes_only_old_unreferenced_files() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    let kept = a.add_file("kept.txt", b"kept").unwrap();
    let orphan = a.add_file("orphan.txt", b"orphan").unwrap();
    let mut doc = Item::new("Doc", 0).with_category(vaultix_core::Category::Document);
    doc.files = vec![kept.clone()];
    a.put(doc).unwrap();

    // Too young: nothing goes.
    assert_eq!(a.sweep_files(Duration::from_secs(3600)).unwrap(), 0);
    assert_eq!(a.sweep_files(Duration::ZERO).unwrap(), 1);
    assert!(a.read_file(&kept).is_ok());
    assert!(a.read_file(&orphan).is_err());
}

#[test]
fn files_over_the_limit_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let a = new_vault(dir.path());
    let big = vec![0u8; vaultix_core::vault::MAX_FILE_SIZE as usize + 1];
    assert!(matches!(a.add_file("big.bin", &big), Err(Error::File(_))));
}

#[test]
fn local_data_is_bound_to_its_purpose_and_names_are_private() {
    let dir = tempfile::tempdir().unwrap();
    let a = new_vault(dir.path());
    let sealed = a.seal_local("icon", b"png bytes");
    assert_eq!(a.open_local("icon", &sealed).unwrap(), b"png bytes");
    assert!(a.open_local("other", &sealed).is_err());

    let name = a.private_name("icon", "github.com");
    assert_eq!(name, a.private_name("icon", "github.com"));
    assert_ne!(name, a.private_name("icon", "gitlab.com"));
    assert!(!name.contains("github"));
    // Another vault names the same site differently.
    let other_dir = tempfile::tempdir().unwrap();
    assert_ne!(name, new_vault(other_dir.path()).private_name("icon", "github.com"));
}

#[test]
fn device_key_unlocks_only_this_vault_on_this_mac() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    a.put(login("GitHub", "https://github.com", "s3cret")).unwrap();
    let device = a.device_id();
    let device_key = [7u8; 32];
    let wrapped = a.wrap_for_device(&device_key);

    let b = Vault::unlock_with_device_key(dir.path(), device, &device_key, &wrapped).unwrap();
    assert_eq!(b.items().len(), 1);

    // Wrong key, or the wrapped key copied to another Mac: refused.
    assert!(Vault::unlock_with_device_key(dir.path(), device, &[8u8; 32], &wrapped).is_err());
    assert!(Vault::unlock_with_device_key(dir.path(), Uuid::new_v4(), &device_key, &wrapped).is_err());
    // Or used against a different vault.
    let other = tempfile::tempdir().unwrap();
    new_vault(other.path());
    assert!(Vault::unlock_with_device_key(other.path(), device, &device_key, &wrapped).is_err());
}

#[test]
fn replaced_passwords_go_into_history_whoever_edits() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    let mut item = login("GitHub", "https://github.com", "first");
    a.put(item.clone()).unwrap();
    item.notes = "only the notes changed".into();
    a.put(item.clone()).unwrap();
    assert!(a.get(item.id).unwrap().password_history.is_empty());

    tick();
    item.password = "second".into();
    a.put(item.clone()).unwrap();
    let saved = a.get(item.id).unwrap();
    assert_eq!(saved.password_history.len(), 1);
    assert_eq!(saved.password_history[0].password, "first");

    // Another Mac sees it, and its own edit keeps the history going.
    let mut b = Vault::unlock(dir.path(), PW, Uuid::new_v4()).unwrap();
    let mut on_b = b.get(item.id).unwrap().clone();
    tick();
    on_b.password = "third".into();
    b.put(on_b).unwrap();
    a.sync().unwrap();
    let old: Vec<String> = a.get(item.id).unwrap().password_history.iter().map(|c| c.password.clone()).collect();
    assert_eq!(old, ["second", "first"]);
}

#[test]
fn backup_restores_deleted_and_changed_items() {
    let vault_dir = tempfile::tempdir().unwrap();
    let backups = tempfile::tempdir().unwrap();
    let mut v = new_vault(vault_dir.path());
    let kept = login("Kept", "https://kept.example", "same");
    let mut edited = login("Edited", "https://edited.example", "before");
    let mut gone = login("Gone", "https://gone.example", "pw");
    gone.files = vec![v.add_file("note.txt", b"attached").unwrap()];
    for i in [&kept, &edited, &gone] {
        v.put(i.clone()).unwrap();
    }

    let first = backups.path().join("one");
    v.backup_to(&first, None).unwrap();
    assert!(!walk(&first).iter().any(|p| p.extension().is_some_and(|e| e == "partial")));
    assert!(v.backup_to(&first, None).is_err(), "never overwrites a backup");

    tick();
    edited.password = "after".into();
    v.put(edited.clone()).unwrap();
    v.delete(gone.id).unwrap();
    v.sweep_files(Duration::ZERO).unwrap();

    // A second backup links the unchanged file instead of copying it.
    let second = backups.path().join("two");
    v.backup_to(&second, Some(&first)).unwrap();

    let backup = v.open_backup(&first).unwrap();
    let mut changes = v.changes_since(&backup);
    changes.sort_by_key(|(id, _)| backup.get(*id).unwrap().title.clone());
    assert_eq!(changes, vec![(edited.id, vaultix_core::BackupChange::Changed), (gone.id, vaultix_core::BackupChange::Deleted)]);

    // A backup can't be written to.
    let mut backup_mut = v.open_backup(&first).unwrap();
    assert!(backup_mut.put(login("x", "https://x.example", "x")).is_err());

    assert_eq!(v.restore_from(&backup, &[edited.id, gone.id]).unwrap(), 2);
    assert_eq!(v.get(edited.id).unwrap().password, "before");
    assert_eq!(v.get(edited.id).unwrap().password_history[0].password, "after");
    let back = v.get(gone.id).unwrap().clone();
    assert_eq!(v.read_file(&back.files[0]).unwrap(), b"attached");
    // Restored items are new changes, so they now count as edited since the backup.
    assert!(v.changes_since(&backup).iter().all(|(_, c)| *c == vaultix_core::BackupChange::Changed));

    // Restored changes reach other Macs.
    let other = Vault::unlock(vault_dir.path(), PW, Uuid::new_v4()).unwrap();
    assert_eq!(other.get(gone.id).unwrap().title, "Gone");
}

#[test]
fn backups_of_another_vault_are_refused() {
    let (d1, d2, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let v1 = new_vault(d1.path());
    let v2 = new_vault(d2.path());
    v2.backup_to(&b.path().join("x"), None).unwrap();
    assert!(v1.open_backup(&b.path().join("x")).is_err());
}

#[test]
fn sync_reports_what_changed() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = new_vault(dir.path());
    let mut b = Vault::unlock(dir.path(), PW, Uuid::new_v4()).unwrap();
    assert_eq!(a.sync().unwrap().changed_items, 0);

    let item = login("GitHub", "https://github.com", "pw");
    a.put(item.clone()).unwrap();
    assert_eq!(a.sync().unwrap().changed_items, 0, "its own change is already known");
    assert_eq!(b.sync().unwrap().changed_items, 1);
    assert_eq!(b.sync().unwrap().changed_items, 0);

    a.delete(item.id).unwrap();
    assert_eq!(b.sync().unwrap().changed_items, 1);
}
