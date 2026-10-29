//! A computer and a phone, each with its own vault folder, syncing over
//! localhost.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use uuid::Uuid;
use vaultix_core::crypto::KdfParams;
use vaultix_core::item::Item;
use vaultix_core::vault::Vault;
use vaultix_link::{Error, Event, Identity, Invite, INVITE_TTL, Pairing, Server};

const PASSWORD: &str = "correct horse battery";

struct Computer {
    server: Server,
    vault: Vault,
    events: mpsc::Receiver<Event>,
    _dir: tempfile::TempDir,
}

impl Computer {
    fn new() -> Computer {
        let dir = tempfile::tempdir().unwrap();
        let device = Uuid::new_v4();
        let vault = Vault::create_with_params(dir.path(), PASSWORD, device, KdfParams::insecure_fast()).unwrap();
        let (tx, events) = mpsc::channel();
        let server = Server::start(Identity::generate(), "Test Mac", device, vec![], localhost(0), move |e| {
            let _ = tx.send(e);
        })
        .unwrap();
        server.set_vault_dir(Some(dir.path().to_path_buf()));
        Computer { server, vault, events, _dir: dir }
    }

    fn invite(&self) -> Invite {
        self.server.invite(vec![localhost(self.server.port())], INVITE_TTL)
    }

    fn reload(&mut self) {
        self.vault.sync().unwrap();
    }

    fn titles(&self) -> Vec<String> {
        self.vault.items().iter().map(|i| i.title.clone()).collect()
    }
}

struct PhoneSide {
    identity: Identity,
    device: Uuid,
    dir: tempfile::TempDir,
}

impl PhoneSide {
    fn new() -> PhoneSide {
        PhoneSide { identity: Identity::generate(), device: Uuid::new_v4(), dir: tempfile::tempdir().unwrap() }
    }

    fn pair(&self, invite: &Invite) -> vaultix_link::Result<Pairing> {
        vaultix_link::pair(invite, &self.identity, "Test Phone", self.dir.path(), self.device).map(|(p, _)| p)
    }

    fn sync(&self, pairing: &mut Pairing) -> vaultix_link::Received {
        vaultix_link::sync(pairing, &self.identity, self.dir.path(), self.device).unwrap()
    }

    fn unlock(&self, password: &str) -> Vault {
        Vault::unlock(self.dir.path(), password, self.device).unwrap()
    }
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn titles(vault: &Vault) -> Vec<String> {
    vault.items().iter().map(|i| i.title.clone()).collect()
}

fn add(vault: &mut Vault, title: &str) -> Uuid {
    let item = Item::new(title, 0);
    let id = item.id;
    vault.put(item).unwrap();
    id
}

fn wait_synced(computer: &Computer) -> vaultix_link::Received {
    loop {
        match computer.events.recv_timeout(Duration::from_secs(5)).expect("a sync event") {
            Event::Synced { received, .. } => return received,
            Event::Paired(_) => {}
        }
    }
}

#[test]
fn a_new_phone_pairs_and_gets_the_vault() {
    let mut computer = Computer::new();
    add(&mut computer.vault, "GitHub");
    let phone = PhoneSide::new();

    let pairing = phone.pair(&computer.invite()).unwrap();
    assert_eq!(pairing.name, "Test Mac");
    assert_eq!(pairing.fingerprint, computer.server.fingerprint());
    assert!(matches!(computer.events.recv().unwrap(), Event::Paired(p) if p.name == "Test Phone"));
    wait_synced(&computer);
    assert_eq!(computer.server.phones().len(), 1);
    assert!(computer.server.phones()[0].last_sync.is_some());

    assert_eq!(titles(&phone.unlock(PASSWORD)), ["GitHub"]);
}

#[test]
fn edits_and_deletes_on_both_sides_meet() {
    let mut computer = Computer::new();
    let gone = add(&mut computer.vault, "Old bank");
    let phone = PhoneSide::new();
    let mut pairing = phone.pair(&computer.invite()).unwrap();
    wait_synced(&computer);

    let mut on_phone = phone.unlock(PASSWORD);
    add(&mut on_phone, "Added on phone");
    add(&mut computer.vault, "Added on Mac");
    computer.vault.delete(gone).unwrap();

    let got = phone.sync(&mut pairing);
    assert_eq!(got.logs, 1, "the Mac's log grew");
    assert_eq!(wait_synced(&computer).logs, 1, "the phone's log arrived");

    on_phone.sync().unwrap();
    computer.reload();
    assert_eq!(titles(&on_phone), ["Added on Mac", "Added on phone"]);
    assert_eq!(computer.titles(), ["Added on Mac", "Added on phone"]);

    // Nothing new: nothing moves.
    assert!(!phone.sync(&mut pairing).any());
    assert!(!wait_synced(&computer).any());
}

#[test]
fn attachments_come_across() {
    let mut computer = Computer::new();
    let phone = PhoneSide::new();
    let mut pairing = phone.pair(&computer.invite()).unwrap();
    wait_synced(&computer);

    let mut on_phone = phone.unlock(PASSWORD);
    let file = on_phone.add_file("scan.pdf", b"%PDF passport scan").unwrap();
    let mut item = Item::new("Passport", 0);
    item.files.push(file.clone());
    on_phone.put(item).unwrap();

    phone.sync(&mut pairing);
    let got = wait_synced(&computer);
    assert_eq!((got.files, got.logs), (1, 1));
    computer.reload();
    let on_mac = computer.vault.items()[0].files[0].clone();
    assert_eq!(computer.vault.read_file(&on_mac).unwrap(), b"%PDF passport scan");
}

#[test]
fn a_password_change_travels_and_the_computer_wins_a_tie() {
    let mut computer = Computer::new();
    let phone = PhoneSide::new();
    let mut pairing = phone.pair(&computer.invite()).unwrap();
    wait_synced(&computer);

    // Changed on the phone: the computer takes it.
    phone.unlock(PASSWORD).change_password("new phone password").unwrap();
    phone.sync(&mut pairing);
    assert!(wait_synced(&computer).meta);
    Vault::unlock(computer._dir.path(), "new phone password", Uuid::new_v4()).unwrap();

    // Changed on both: the computer's wins.
    computer.vault = Vault::unlock(computer._dir.path(), "new phone password", computer.vault.device_id()).unwrap();
    computer.vault.change_password("mac password").unwrap();
    phone.unlock("new phone password").change_password("other phone password").unwrap();
    assert!(phone.sync(&mut pairing).meta, "the phone takes the computer's");
    wait_synced(&computer);
    phone.unlock("mac password");
}

#[test]
fn only_the_paired_computer_and_phones_get_in() {
    let computer = Computer::new();
    let invite = computer.invite();

    // A wrong code, and a phone that never paired.
    let stranger = PhoneSide::new();
    let wrong = Invite { code: "AAAAAAAAAAAAAAAA".into(), ..invite.clone() };
    assert!(matches!(stranger.pair(&wrong), Err(Error::Refused(r)) if r == "bad-code"));
    let mut forged = Pairing { addrs: invite.addrs.clone(), fingerprint: invite.fingerprint.clone(), name: String::new(), vault_id: Uuid::nil(), meta_synced: None };
    assert!(matches!(vaultix_link::sync(&mut forged, &stranger.identity, stranger.dir.path(), stranger.device), Err(Error::Refused(r)) if r == "not-paired"));

    // A computer with a different certificate than the QR code said.
    let imposter = Invite { fingerprint: "00".repeat(32), ..invite.clone() };
    assert!(matches!(stranger.pair(&imposter), Err(Error::Io(_) | Error::Tls(_))));

    // The right code works once.
    stranger.pair(&invite).unwrap();
    let late = PhoneSide::new();
    assert!(matches!(late.pair(&invite), Err(Error::Refused(r)) if r == "bad-code"));
    assert!(!dir_has_files(late.dir.path()));
}

#[test]
fn invites_expire_and_give_up_after_wrong_codes() {
    let computer = Computer::new();
    let phone = PhoneSide::new();
    let expired = computer.server.invite(vec![localhost(computer.server.port())], Duration::ZERO);
    assert!(matches!(phone.pair(&expired), Err(Error::Refused(r)) if r == "bad-code"));

    let invite = computer.invite();
    let wrong = Invite { code: "WRONG".into(), ..invite.clone() };
    for _ in 0..5 {
        assert!(phone.pair(&wrong).is_err());
    }
    assert!(!computer.server.inviting());
    assert!(matches!(phone.pair(&invite), Err(Error::Refused(r)) if r == "bad-code"));
}

#[test]
fn removed_phones_are_shut_out() {
    let computer = Computer::new();
    let phone = PhoneSide::new();
    let mut pairing = phone.pair(&computer.invite()).unwrap();
    computer.server.remove_phone(&phone.identity.fingerprint());
    assert!(matches!(vaultix_link::sync(&mut pairing, &phone.identity, phone.dir.path(), phone.device), Err(Error::Refused(r)) if r == "not-paired"));
}

#[test]
fn a_phone_with_another_vault_is_refused() {
    let computer = Computer::new();
    let phone = PhoneSide::new();
    Vault::create_with_params(phone.dir.path(), PASSWORD, phone.device, KdfParams::insecure_fast()).unwrap();
    assert!(matches!(phone.pair(&computer.invite()), Err(Error::Refused(r)) if r == "wrong-vault"));
}

fn dir_has_files(dir: &Path) -> bool {
    std::fs::read_dir(dir).unwrap().next().is_some()
}
