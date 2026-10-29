//! The messages, and copying the vault folder's files across.
//!
//! A sync: the phone says Hello, the computer Welcome; both send a
//! [`Manifest`]; then the phone sends what the computer lacks, ending with
//! Done, and the computer does the same. Data follows its message as a raw
//! frame. Frames are a little-endian u32 length and the bytes, as in the
//! browser extension's native messaging.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Error, Result};

const META_FILE: &str = "vault.json";
const DEVICES_DIR: &str = "devices";
const FILES_DIR: &str = "files";
/// Attachments are at most 100 MiB (`vaultix_core::vault::MAX_FILE_SIZE`),
/// plus encryption overhead.
const MAX_FRAME: usize = 128 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Msg {
    Hello { version: u32, vault_id: Option<Uuid>, pair: Option<PairRequest> },
    Welcome { vault_id: Uuid, name: String },
    Refused { reason: String },
    Manifest(Manifest),
    /// The bytes of `device`'s log from `offset` on (whole lines).
    Log { device: Uuid, offset: u64 },
    File { id: Uuid },
    Meta,
    Done,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PairRequest {
    pub code: String,
    pub name: String,
}

/// What one side has.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Manifest {
    /// Length of each device's log, up to its last complete line.
    pub logs: BTreeMap<Uuid, u64>,
    pub files: BTreeSet<Uuid>,
    /// SHA-256 of `vault.json`.
    pub meta: Option<String>,
    /// The phone only: the hash of `vault.json` after the last sync.
    pub meta_synced: Option<String>,
}

impl Manifest {
    pub fn of(dir: &Path) -> io::Result<Manifest> {
        let mut m = Manifest::default();
        for (id, path) in entries(&dir.join(DEVICES_DIR), "log")? {
            m.logs.insert(id, complete_len(&fs::read(path)?) as u64);
        }
        m.files = entries(&dir.join(FILES_DIR), "bin")?.into_iter().map(|(id, _)| id).collect();
        m.meta = match fs::read(dir.join(META_FILE)) {
            Ok(bytes) => Some(data_encoding::HEXLOWER.encode(&Sha256::digest(&bytes))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        Ok(m)
    }
}

/// `<uuid>.<ext>` files in `dir`. Anything else (temp files, stray files) is
/// ignored, and names from the other side are only ever built from UUIDs, so
/// a peer can't write outside the vault folder.
fn entries(dir: &Path, ext: &str) -> io::Result<Vec<(Uuid, PathBuf)>> {
    let read = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let mut out = vec![];
    for entry in read {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some(ext) {
            continue;
        }
        if let Some(id) = path.file_stem().and_then(|s| s.to_str()).and_then(|s| Uuid::parse_str(s).ok()) {
            out.push((id, path));
        }
    }
    Ok(out)
}

/// Length up to and including the last newline: a line still being written
/// isn't sent until it's complete.
fn complete_len(log: &[u8]) -> usize {
    log.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1)
}

/// The vault this folder holds, if any.
pub(crate) fn vault_id(dir: &Path) -> Option<Uuid> {
    let bytes = fs::read(dir.join(META_FILE)).ok()?;
    let meta: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Uuid::parse_str(meta.get("vault_id")?.as_str()?).ok()
}

#[derive(Debug, PartialEq)]
pub(crate) enum Side {
    Neither,
    Client,
    Server,
}

/// Whose `vault.json` wins. It only changes with a password change: the side
/// that changed it since the last sync wins; if both did, the computer does.
pub(crate) fn meta_winner(client: &Manifest, server: &Manifest) -> Side {
    match (&client.meta, &server.meta) {
        (_, None) => Side::Neither,
        (None, Some(_)) => Side::Server,
        (Some(c), Some(s)) if c == s => Side::Neither,
        (Some(c), Some(s)) => {
            let synced = client.meta_synced.as_ref();
            if synced == Some(s) && synced != Some(c) { Side::Client } else { Side::Server }
        }
    }
}

/// Send what `theirs` lacks: attachments first, so the log lines that refer
/// to them never arrive before them.
pub(crate) fn send_changes(stream: &mut (impl Read + Write), dir: &Path, mine: &Manifest, theirs: &Manifest, send_meta: bool) -> Result<()> {
    for id in mine.files.difference(&theirs.files) {
        let data = fs::read(dir.join(FILES_DIR).join(format!("{id}.bin")))?;
        send(stream, &Msg::File { id: *id })?;
        write_frame(stream, &data)?;
    }
    if send_meta {
        let data = fs::read(dir.join(META_FILE))?;
        send(stream, &Msg::Meta)?;
        write_frame(stream, &data)?;
    }
    for (device, &len) in &mine.logs {
        let offset = theirs.logs.get(device).copied().unwrap_or(0);
        if len <= offset {
            continue;
        }
        let log = fs::read(dir.join(DEVICES_DIR).join(format!("{device}.log")))?;
        let end = complete_len(&log);
        if (offset as usize) >= end {
            continue;
        }
        send(stream, &Msg::Log { device: *device, offset })?;
        write_frame(stream, &log[offset as usize..end])?;
    }
    send(stream, &Msg::Done)?;
    stream.flush()?;
    Ok(())
}

/// What a sync brought in.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Received {
    /// Devices whose logs grew.
    pub logs: usize,
    pub files: usize,
    /// `vault.json` was replaced (the password changed elsewhere).
    pub meta: bool,
}

impl Received {
    pub fn any(&self) -> bool {
        self.logs > 0 || self.files > 0 || self.meta
    }
}

/// Write what the other side sends until Done. Never touches `own_device`'s
/// log: only this device writes it.
pub(crate) fn receive_changes(stream: &mut impl Read, dir: &Path, own_device: Uuid) -> Result<Received> {
    let mut received = Received::default();
    loop {
        match recv(stream)? {
            Msg::Done => return Ok(received),
            Msg::File { id } => {
                let data = read_frame(stream)?;
                let path = dir.join(FILES_DIR).join(format!("{id}.bin"));
                if !path.exists() {
                    write_atomic(&path, &data)?;
                    received.files += 1;
                }
            }
            Msg::Meta => {
                let data = read_frame(stream)?;
                if serde_json::from_slice::<serde_json::Value>(&data).is_err() {
                    return Err(Error::Protocol("invalid vault.json".into()));
                }
                write_atomic(&dir.join(META_FILE), &data)?;
                received.meta = true;
            }
            Msg::Log { device, offset } => {
                let data = read_frame(stream)?;
                if device != own_device && append_log(&dir.join(DEVICES_DIR).join(format!("{device}.log")), offset, &data)? {
                    received.logs += 1;
                }
            }
            other => return Err(unexpected(&other)),
        }
    }
}

/// Append `data` (whole lines) to a copy of another device's log, if it
/// continues where our copy ends. A line left half-written by an earlier,
/// interrupted sync is cut off first: the other side resends it in full.
fn append_log(path: &Path, offset: u64, data: &[u8]) -> io::Result<bool> {
    if data.is_empty() || data.last() != Some(&b'\n') {
        return Ok(false);
    }
    fs::create_dir_all(path.parent().unwrap())?;
    // Not opened for appending: Windows refuses to truncate such a file.
    let mut file = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(path)?;
    let mut current = vec![];
    file.read_to_end(&mut current)?;
    let complete = complete_len(&current) as u64;
    if complete != offset {
        // Our copy moved on since the manifest (another sync), or is shorter
        // than the sender thinks: skip, the next sync sorts it out.
        return Ok(false);
    }
    if (current.len() as u64) > complete {
        file.set_len(complete)?;
    }
    file.seek(SeekFrom::Start(complete))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(true)
}

/// Write to a temp file and rename it into place, so an interrupted sync never
/// leaves half a file under the real name.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    fs::create_dir_all(path.parent().unwrap())?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

pub(crate) fn send(stream: &mut impl Write, msg: &Msg) -> Result<()> {
    write_frame(stream, &serde_json::to_vec(msg).map_err(|e| Error::Protocol(e.to_string()))?)
}

pub(crate) fn recv(stream: &mut impl Read) -> Result<Msg> {
    let bytes = read_frame(stream)?;
    serde_json::from_slice(&bytes).map_err(|e| Error::Protocol(format!("bad message: {e}")))
}

pub(crate) fn unexpected(msg: &Msg) -> Error {
    Error::Protocol(format!("unexpected message: {msg:?}"))
}

fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_FRAME {
        return Err(Error::Protocol("too large".into()));
    }
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(Error::Protocol("too large".into()));
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(msgs: &[(Msg, Option<&[u8]>)]) -> Vec<u8> {
        let mut out = vec![];
        for (msg, data) in msgs {
            send(&mut out, msg).unwrap();
            if let Some(d) = data {
                write_frame(&mut out, d).unwrap();
            }
        }
        out
    }

    #[test]
    fn an_interrupted_transfer_leaves_no_partial_files() {
        let dir = tempfile::tempdir().unwrap();
        let (file, device) = (Uuid::new_v4(), Uuid::new_v4());
        let mut stream = frames(&[(Msg::File { id: file }, Some(b"sealed attachment")), (Msg::Log { device, offset: 0 }, Some(b"line 1\nline 2\n"))]);
        stream.truncate(stream.len() - 5);
        assert!(receive_changes(&mut stream.as_slice(), dir.path(), Uuid::nil()).is_err());
        // The attachment came in whole; the log didn't, so nothing of it was written.
        assert_eq!(fs::read(dir.path().join(format!("files/{file}.bin"))).unwrap(), b"sealed attachment");
        assert!(!dir.path().join(format!("devices/{device}.log")).exists());
        assert_eq!(Manifest::of(dir.path()).unwrap().files, BTreeSet::from([file]));
    }

    #[test]
    fn logs_only_ever_grow_by_whole_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices/x.log");
        assert!(append_log(&path, 0, b"a\nb\n").unwrap());
        assert!(!append_log(&path, 0, b"a\n").unwrap(), "already have it");
        assert!(!append_log(&path, 4, b"c").unwrap(), "not a whole line");
        // A half-written line from an interrupted write is replaced.
        fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"c-par").unwrap();
        assert!(append_log(&path, 4, b"c\n").unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"a\nb\nc\n");
    }

    #[test]
    fn never_writes_its_own_log() {
        let dir = tempfile::tempdir().unwrap();
        let me = Uuid::new_v4();
        let stream = frames(&[(Msg::Log { device: me, offset: 0 }, Some(b"forged\n")), (Msg::Done, None)]);
        assert_eq!(receive_changes(&mut stream.as_slice(), dir.path(), me).unwrap(), Received::default());
        assert!(!dir.path().join(format!("devices/{me}.log")).exists());
    }

    #[test]
    fn ignores_names_that_are_not_uuids() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("files")).unwrap();
        fs::write(dir.path().join("files/notes.bin"), b"x").unwrap();
        let id = Uuid::new_v4();
        fs::write(dir.path().join(format!("files/{id}.bin.tmp")), b"x").unwrap();
        assert!(Manifest::of(dir.path()).unwrap().files.is_empty());
    }

    #[test]
    fn the_side_that_changed_the_password_wins() {
        let m = |meta: &str, synced: Option<&str>| Manifest { meta: Some(meta.into()), meta_synced: synced.map(Into::into), ..Default::default() };
        assert_eq!(meta_winner(&m("a", Some("a")), &m("a", None)), Side::Neither);
        assert_eq!(meta_winner(&m("a", Some("a")), &m("b", None)), Side::Server, "changed on the computer");
        assert_eq!(meta_winner(&m("b", Some("a")), &m("a", None)), Side::Client, "changed on the phone");
        assert_eq!(meta_winner(&m("b", Some("a")), &m("c", None)), Side::Server, "changed on both");
        assert_eq!(meta_winner(&Manifest::default(), &m("a", None)), Side::Server, "a new phone");
    }
}
