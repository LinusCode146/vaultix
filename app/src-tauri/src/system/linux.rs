//! Linux: lock on suspend and screen lock, as reported by systemd-logind.

use std::thread;

use zbus::blocking::{Connection, MessageIterator};
use zbus::MatchRule;

/// Call `on_away` when the computer is about to suspend, or the session is
/// locked or switched away from. Without logind (no D-Bus system bus), nothing happens.
pub fn watch_away(on_away: fn()) {
    thread::spawn(move || {
        if let Err(e) = watch(on_away) {
            eprintln!("[vaultix] can't watch for sleep and screen lock: {e}");
        }
    });
}

fn watch(on_away: fn()) -> zbus::Result<()> {
    let bus = Connection::system()?;
    let rule = |member: &'static str, interface: &'static str| {
        MatchRule::builder().msg_type(zbus::message::Type::Signal).sender("org.freedesktop.login1")?.interface(interface)?.member(member).map(|b| b.build())
    };
    // PrepareForSleep(true) before suspend; Lock when `loginctl lock-session`
    // or the desktop locks the screen; PropertiesChanged for LockedHint and Active.
    let rules = [
        rule("PrepareForSleep", "org.freedesktop.login1.Manager")?,
        rule("Lock", "org.freedesktop.login1.Session")?,
        rule("PropertiesChanged", "org.freedesktop.DBus.Properties")?,
    ];
    let session = session_path(&bus).ok();
    let mut iterators = Vec::new();
    for rule in rules {
        iterators.push(MessageIterator::for_match_rule(rule, &bus, Some(16))?);
    }
    // One thread per signal kind; each blocks on its own stream.
    let mut handles = Vec::new();
    for messages in iterators {
        let session = session.clone();
        handles.push(thread::spawn(move || {
            for message in messages.flatten() {
                let header = message.header();
                let member = header.member().map(|m| m.as_str().to_owned()).unwrap_or_default();
                let path = header.path().map(|p| p.as_str().to_owned()).unwrap_or_default();
                let ours = session.as_deref().is_none_or(|s| s == path);
                let away = match member.as_str() {
                    "PrepareForSleep" => message.body().deserialize::<bool>().unwrap_or(false),
                    "Lock" => ours,
                    "PropertiesChanged" => ours && session_left(&message),
                    _ => false,
                };
                if away {
                    on_away();
                }
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

/// Our logind session's object path.
fn session_path(bus: &Connection) -> zbus::Result<String> {
    let reply = bus.call_method(
        Some("org.freedesktop.login1"),
        "/org/freedesktop/login1",
        Some("org.freedesktop.login1.Manager"),
        "GetSessionByPID",
        &(std::process::id()),
    )?;
    let path: zbus::zvariant::OwnedObjectPath = reply.body().deserialize()?;
    Ok(path.as_str().to_owned())
}

/// A session PropertiesChanged that says it got locked or became inactive.
fn session_left(message: &zbus::Message) -> bool {
    use std::collections::HashMap;
    use zbus::zvariant::OwnedValue;
    let Ok((interface, changed, _)) = message.body().deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>() else {
        return false;
    };
    if interface != "org.freedesktop.login1.Session" {
        return false;
    }
    let flag = |name: &str| changed.get(name).and_then(|v| bool::try_from(v).ok());
    flag("LockedHint") == Some(true) || flag("Active") == Some(false)
}
