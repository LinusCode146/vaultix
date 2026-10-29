//! Sync between a phone and a computer over the local network, without a
//! cloud folder in between.
//!
//! The vault folder makes this simple (see `vaultix_core::vault`): every
//! device appends only to its own `devices/<id>.log`, attachments in `files/`
//! are written once, and everything is already encrypted with the vault key.
//! So a sync is two folders swapping what the other lacks: missing files and
//! the new tail of each log. Nothing is merged or decrypted on the way, which
//! is why the computer can serve the folder while it's locked.
//!
//! The computer runs a [`Server`]; the phone pairs with it once by scanning an
//! [`Invite`] (a QR code), then calls [`sync`] whenever it wants. Both sides
//! talk TLS 1.3 with self-signed certificates and accept only each other's
//! pinned certificate.

mod discovery;
mod identity;
mod proto;
mod server;
mod tls;

pub use discovery::{Advertiser, find};
pub use identity::Identity;
pub use proto::Received;
pub use server::{Event, Phone, Server};

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use proto::{Msg, PairRequest};

/// Default port the computer listens on.
pub const PORT: u16 = 47811;
/// How long an invite's code can be used.
pub const INVITE_TTL: Duration = Duration::from_secs(5 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// None of the computer's addresses answered.
    #[error("couldn't reach the computer")]
    Unreachable,
    /// The computer said no; the code is one of `not-paired`, `bad-code`,
    /// `no-vault`, `wrong-vault`, `version`.
    #[error("refused: {0}")]
    Refused(String),
    #[error("invalid invite")]
    BadInvite,
    #[error("{0}")]
    Protocol(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Tls(#[from] rustls::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// What the computer's QR code holds: where to find it, its certificate, and
/// a one-time code proving the phone was shown the QR code.
#[derive(Debug, Clone, PartialEq)]
pub struct Invite {
    pub addrs: Vec<SocketAddr>,
    pub fingerprint: String,
    pub code: String,
    pub name: String,
}

impl Invite {
    pub fn to_uri(&self) -> String {
        let mut url = url::Url::parse("vaultix://pair").unwrap();
        let addrs: Vec<String> = self.addrs.iter().map(|a| a.to_string()).collect();
        url.query_pairs_mut()
            .append_pair("v", &VERSION.to_string())
            .append_pair("h", &addrs.join(","))
            .append_pair("fp", &self.fingerprint)
            .append_pair("c", &self.code)
            .append_pair("n", &self.name);
        url.into()
    }

    pub fn parse(uri: &str) -> Result<Invite> {
        let url = url::Url::parse(uri.trim()).map_err(|_| Error::BadInvite)?;
        if url.scheme() != "vaultix" || url.host_str() != Some("pair") {
            return Err(Error::BadInvite);
        }
        let get = |key: &str| url.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned());
        if get("v").as_deref() != Some("1") {
            return Err(Error::BadInvite);
        }
        let addrs: Vec<SocketAddr> = get("h")
            .unwrap_or_default()
            .split(',')
            .filter_map(|a| a.parse().ok())
            .collect();
        let fingerprint = get("fp").filter(|f| f.len() == 64 && f.bytes().all(|b| b.is_ascii_hexdigit()));
        match (fingerprint, get("c"), get("n")) {
            (Some(fingerprint), Some(code), Some(name)) if !addrs.is_empty() && !code.is_empty() => {
                Ok(Invite { addrs, fingerprint: fingerprint.to_ascii_lowercase(), code, name })
            }
            _ => Err(Error::BadInvite),
        }
    }
}

/// The phone's record of the computer it's paired with. The phone saves it,
/// and passes it back to [`sync`] each time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pairing {
    /// Last known addresses; [`find`] can look for new ones.
    pub addrs: Vec<SocketAddr>,
    pub fingerprint: String,
    pub name: String,
    pub vault_id: Uuid,
    /// Hash of `vault.json` after the last sync, to tell which side changed
    /// it (a password change) since.
    #[serde(default)]
    pub meta_synced: Option<String>,
}

/// Pair with the computer that showed `invite`, then sync. `dir` is the
/// phone's vault folder, empty the first time.
pub fn pair(invite: &Invite, identity: &Identity, my_name: &str, dir: &Path, own_device: Uuid) -> Result<(Pairing, Received)> {
    let mut pairing = Pairing {
        addrs: invite.addrs.clone(),
        fingerprint: invite.fingerprint.clone(),
        name: invite.name.clone(),
        vault_id: Uuid::nil(),
        meta_synced: None,
    };
    let request = PairRequest { code: invite.code.clone(), name: my_name.into() };
    let received = run(&mut pairing, identity, dir, own_device, Some(request))?;
    Ok((pairing, received))
}

/// Swap changes with the paired computer. Updates `pairing` (save it after).
pub fn sync(pairing: &mut Pairing, identity: &Identity, dir: &Path, own_device: Uuid) -> Result<Received> {
    run(pairing, identity, dir, own_device, None)
}

fn run(pairing: &mut Pairing, identity: &Identity, dir: &Path, own_device: Uuid, pair: Option<PairRequest>) -> Result<Received> {
    let local_vault = proto::vault_id(dir);
    if let Some(id) = local_vault
        && pair.is_none()
        && id != pairing.vault_id
    {
        return Err(Error::Refused("wrong-vault".into()));
    }

    let tcp = connect(&pairing.addrs)?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))?;
    let config = tls::client_config(identity, &pairing.fingerprint);
    let conn = rustls::ClientConnection::new(Arc::new(config), tls::server_name())?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);

    proto::send(&mut stream, &Msg::Hello { version: VERSION, vault_id: local_vault, pair })?;
    let vault_id = match proto::recv(&mut stream)? {
        Msg::Welcome { vault_id, name } => {
            pairing.name = name;
            vault_id
        }
        Msg::Refused { reason } => return Err(Error::Refused(reason)),
        other => return Err(proto::unexpected(&other)),
    };
    if local_vault.is_some_and(|id| id != vault_id) {
        return Err(Error::Refused("wrong-vault".into()));
    }
    pairing.vault_id = vault_id;

    let mut mine = proto::Manifest::of(dir)?;
    mine.meta_synced = pairing.meta_synced.clone();
    proto::send(&mut stream, &Msg::Manifest(mine.clone()))?;
    let theirs = match proto::recv(&mut stream)? {
        Msg::Manifest(m) => m,
        other => return Err(proto::unexpected(&other)),
    };

    let winner = proto::meta_winner(&mine, &theirs);
    proto::send_changes(&mut stream, dir, &mine, &theirs, winner == proto::Side::Client)?;
    let received = proto::receive_changes(&mut stream, dir, own_device)?;
    pairing.meta_synced = proto::Manifest::of(dir)?.meta;
    stream.conn.send_close_notify();
    let _ = std::io::Write::flush(&mut stream);
    Ok(received)
}

fn connect(addrs: &[SocketAddr]) -> Result<TcpStream> {
    addrs
        .iter()
        .find_map(|a| TcpStream::connect_timeout(a, CONNECT_TIMEOUT).ok())
        .ok_or(Error::Unreachable)
}

/// This computer's IPv4 addresses on the local network, for the invite.
pub fn local_addrs(port: u16) -> Vec<SocketAddr> {
    let mut addrs: Vec<SocketAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| match i.ip() {
            std::net::IpAddr::V4(ip) if !ip.is_link_local() => Some(SocketAddr::from((ip, port))),
            _ => None,
        })
        .collect();
    addrs.sort();
    addrs.dedup();
    addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invites_round_trip_through_uris() {
        let invite = Invite {
            addrs: vec!["192.168.1.5:47811".parse().unwrap(), "10.0.0.2:47811".parse().unwrap()],
            fingerprint: "ab".repeat(32),
            code: "K7QW2M9XPA".into(),
            name: "Linus's MacBook Pro".into(),
        };
        let uri = invite.to_uri();
        assert!(uri.starts_with("vaultix://pair?v=1&"), "{uri}");
        assert_eq!(Invite::parse(&uri).unwrap(), invite);
        assert!(Invite::parse("https://pair?v=1").is_err());
        assert!(Invite::parse(&uri.replace("fp=abab", "fp=zz")).is_err());
        assert!(Invite::parse(&uri.replace("v=1", "v=2")).is_err());
    }
}
