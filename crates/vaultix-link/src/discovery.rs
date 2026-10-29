//! Finding the computer again when its address changed: it announces itself
//! on the local network over mDNS (Bonjour), under its certificate's
//! fingerprint.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

const SERVICE: &str = "_vaultix._tcp.local.";

/// Keeps the announcement up until dropped.
pub struct Advertiser {
    daemon: ServiceDaemon,
}

impl Advertiser {
    pub fn start(fingerprint: &str, port: u16) -> Result<Advertiser, mdns_sd::Error> {
        let daemon = ServiceDaemon::new()?;
        let instance = &fingerprint[..16.min(fingerprint.len())];
        let host = format!("vaultix-{instance}.local.");
        let info = ServiceInfo::new(SERVICE, instance, &host, "", port, &[("fp", fingerprint)][..])?.enable_addr_auto();
        daemon.register(info)?;
        Ok(Advertiser { daemon })
    }
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        let _ = self.daemon.shutdown();
    }
}

/// Addresses of the computer with `fingerprint`, waiting up to `timeout`.
/// On Android, hold a Wi-Fi multicast lock while this runs.
pub fn find(fingerprint: &str, timeout: Duration) -> Vec<SocketAddr> {
    let Ok(daemon) = ServiceDaemon::new() else { return vec![] };
    let Ok(events) = daemon.browse(SERVICE) else { return vec![] };
    let deadline = Instant::now() + timeout;
    let mut found = vec![];
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match events.recv_timeout(left) {
            Ok(ServiceEvent::ServiceResolved(info)) if info.get_property_val_str("fp") == Some(fingerprint) => {
                found = info.get_addresses().iter().map(|ip| SocketAddr::new(ip.to_ip_addr(), info.get_port())).collect();
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.shutdown();
    found
}
