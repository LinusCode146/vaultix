//! The computer's side: listens for paired phones and for one that's pairing.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::identity::Identity;
use crate::proto::{self, Manifest, Msg, Received, Side};
use crate::{Error, IO_TIMEOUT, Invite, Result, VERSION, tls};

/// Wrong codes allowed before an invite stops working.
const MAX_TRIES: u32 = 5;

/// A paired phone, as the computer remembers it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Phone {
    pub fingerprint: String,
    pub name: String,
    /// Unix seconds.
    pub paired_at: u64,
    pub last_sync: Option<u64>,
}

#[derive(Debug)]
pub enum Event {
    /// A phone paired; save [`Server::phones`].
    Paired(Phone),
    /// A phone synced and sent `received`; save [`Server::phones`], and
    /// re-read the vault if anything came in.
    Synced { phone: Phone, received: Received },
}

struct Offer {
    code: String,
    expires: Instant,
    tries: u32,
}

struct State {
    dir: Option<PathBuf>,
    phones: Vec<Phone>,
    offer: Option<Offer>,
}

struct Inner {
    identity: Identity,
    config: Arc<rustls::ServerConfig>,
    name: String,
    own_device: Uuid,
    state: Mutex<State>,
    on_event: Box<dyn Fn(Event) + Send + Sync>,
    stopped: AtomicBool,
}

pub struct Server {
    inner: Arc<Inner>,
    addr: SocketAddr,
}

impl Server {
    /// Listen on `bind` (port 0: any free port). `name` is shown on the phone;
    /// `own_device` is this computer's device id, whose log only it writes.
    pub fn start(
        identity: Identity,
        name: &str,
        own_device: Uuid,
        phones: Vec<Phone>,
        bind: SocketAddr,
        on_event: impl Fn(Event) + Send + Sync + 'static,
    ) -> std::io::Result<Server> {
        let listener = TcpListener::bind(bind)?;
        let addr = listener.local_addr()?;
        let inner = Arc::new(Inner {
            config: Arc::new(tls::server_config(&identity)),
            identity,
            name: name.into(),
            own_device,
            state: Mutex::new(State { dir: None, phones, offer: None }),
            on_event: Box::new(on_event),
            stopped: AtomicBool::new(false),
        });
        let accepting = inner.clone();
        std::thread::spawn(move || {
            for tcp in listener.incoming() {
                if accepting.stopped.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(tcp) = tcp else { continue };
                let inner = accepting.clone();
                std::thread::spawn(move || {
                    if let Err(e) = inner.serve(tcp) {
                        eprintln!("[vaultix] phone sync: {e}");
                    }
                });
            }
        });
        Ok(Server { inner, addr })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn fingerprint(&self) -> String {
        self.inner.identity.fingerprint()
    }

    /// The vault folder to serve; `None` while there's no vault.
    pub fn set_vault_dir(&self, dir: Option<PathBuf>) {
        self.inner.state.lock().unwrap().dir = dir;
    }

    /// A new invite for the QR code, replacing any earlier one.
    pub fn invite(&self, addrs: Vec<SocketAddr>, ttl: Duration) -> Invite {
        let code = data_encoding::BASE32_NOPAD.encode(&rand::thread_rng().r#gen::<[u8; 10]>());
        self.inner.state.lock().unwrap().offer = Some(Offer { code: code.clone(), expires: Instant::now() + ttl, tries: 0 });
        Invite { addrs, fingerprint: self.fingerprint(), code, name: self.inner.name.clone() }
    }

    pub fn cancel_invite(&self) {
        self.inner.state.lock().unwrap().offer = None;
    }

    /// Whether an invite is still waiting for its phone.
    pub fn inviting(&self) -> bool {
        self.inner.state.lock().unwrap().offer.as_ref().is_some_and(|o| o.expires > Instant::now())
    }

    pub fn phones(&self) -> Vec<Phone> {
        self.inner.state.lock().unwrap().phones.clone()
    }

    pub fn remove_phone(&self, fingerprint: &str) {
        self.inner.state.lock().unwrap().phones.retain(|p| p.fingerprint != fingerprint);
    }

    pub fn stop(self) {}
}

impl Drop for Server {
    fn drop(&mut self) {
        self.inner.stopped.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the flag.
        let wake = SocketAddr::from(([127, 0, 0, 1], self.addr.port()));
        let _ = TcpStream::connect_timeout(&wake, Duration::from_millis(200));
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Inner {
    fn serve(&self, tcp: TcpStream) -> Result<()> {
        if self.stopped.load(Ordering::SeqCst) {
            return Ok(());
        }
        tcp.set_read_timeout(Some(IO_TIMEOUT))?;
        tcp.set_write_timeout(Some(IO_TIMEOUT))?;
        let conn = rustls::ServerConnection::new(self.config.clone())?;
        let mut stream = rustls::StreamOwned::new(conn, tcp);

        let hello = proto::recv(&mut stream)?;
        let peer = tls::peer_fingerprint(stream.conn.peer_certificates()).ok_or_else(|| Error::Protocol("no certificate".into()))?;
        let refuse = |stream: &mut _, reason: &str| -> Result<()> {
            proto::send(stream, &Msg::Refused { reason: reason.into() })?;
            Err(Error::Refused(reason.into()))
        };
        let Msg::Hello { version, vault_id, pair } = hello else {
            return Err(proto::unexpected(&hello));
        };
        if version != VERSION {
            return refuse(&mut stream, "version");
        }

        let Some(dir) = self.state.lock().unwrap().dir.clone() else {
            return refuse(&mut stream, "no-vault");
        };
        let Some(our_vault) = proto::vault_id(&dir) else {
            return refuse(&mut stream, "no-vault");
        };
        if vault_id.is_some_and(|v| v != our_vault) {
            return refuse(&mut stream, "wrong-vault");
        }

        let mut phone = {
            let mut state = self.state.lock().unwrap();
            match (state.phones.iter().find(|p| p.fingerprint == peer).cloned(), pair) {
                (Some(phone), _) => phone,
                (None, Some(request)) => {
                    let ok = match &mut state.offer {
                        Some(offer) if offer.expires > Instant::now() => {
                            offer.tries += 1;
                            offer.code == request.code
                        }
                        _ => false,
                    };
                    if !ok {
                        if state.offer.as_ref().is_some_and(|o| o.tries >= MAX_TRIES) {
                            state.offer = None;
                        }
                        drop(state);
                        return refuse(&mut stream, "bad-code");
                    }
                    state.offer = None;
                    let name: String = request.name.chars().take(64).collect();
                    let phone = Phone { fingerprint: peer.clone(), name, paired_at: now(), last_sync: None };
                    state.phones.push(phone.clone());
                    drop(state);
                    (self.on_event)(Event::Paired(phone.clone()));
                    phone
                }
                (None, None) => {
                    drop(state);
                    return refuse(&mut stream, "not-paired");
                }
            }
        };

        proto::send(&mut stream, &Msg::Welcome { vault_id: our_vault, name: self.name.clone() })?;
        let theirs = match proto::recv(&mut stream)? {
            Msg::Manifest(m) => m,
            other => return Err(proto::unexpected(&other)),
        };
        let mine = Manifest::of(&dir)?;
        proto::send(&mut stream, &Msg::Manifest(mine.clone()))?;
        let winner = proto::meta_winner(&theirs, &mine);
        let received = proto::receive_changes(&mut stream, &dir, self.own_device)?;
        // Send from the manifest taken before receiving: what the phone just
        // sent doesn't need to go back.
        proto::send_changes(&mut stream, &dir, &mine, &theirs, winner == Side::Server)?;

        phone.last_sync = Some(now());
        if let Some(p) = self.state.lock().unwrap().phones.iter_mut().find(|p| p.fingerprint == peer) {
            p.last_sync = phone.last_sync;
        }
        (self.on_event)(Event::Synced { phone, received });
        Ok(())
    }
}
