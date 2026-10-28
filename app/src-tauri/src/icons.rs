//! Website icons for logins.
//!
//! Icons are fetched straight from each website (never through a third-party
//! icon service, which would learn every site in the vault), and cached on
//! this Mac encrypted with the vault key, under names that don't reveal the
//! site. A site only learns that you have a login there, which visiting it
//! already tells it.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use ureq::ResponseExt;
use url::Url;
use vaultix_core::Vault;

const PURPOSE: &str = "site-icon";
/// Found icons are fetched again after this long, in case the site changed its logo.
const REFRESH_FOUND: Duration = Duration::from_secs(30 * 24 * 3600);
/// Sites without a usable icon are tried again after this long.
const RETRY_MISSING: Duration = Duration::from_secs(7 * 24 * 3600);
const MAX_PAGE: u64 = 512 * 1024;
const MAX_ICON: u64 = 256 * 1024;
/// At most this many sites are contacted at once.
const MAX_PARALLEL: usize = 6;

pub struct Icons {
    dir: PathBuf,
    /// host → data URI (None: the site has no usable icon). Cleared on lock.
    memory: Mutex<HashMap<String, Option<String>>>,
    running: Mutex<usize>,
    slot_free: Condvar,
}

#[derive(Serialize, Deserialize)]
struct Cached {
    fetched_at: u64,
    data_uri: Option<String>,
}

impl Icons {
    pub fn new(dir: PathBuf) -> Self {
        Icons { dir, memory: Mutex::default(), running: Mutex::new(0), slot_free: Condvar::new() }
    }

    pub fn forget_memory(&self) {
        self.memory.lock().unwrap().clear();
    }

    /// The icon for a login's website as a `data:` URI, or `None`. Blocks
    /// while fetching, so call it off the main thread. The vault is only
    /// locked briefly, for the encrypted cache, never during a download.
    pub fn get(&self, vault: &Mutex<Option<Vault>>, url: &str) -> Option<String> {
        self.lookup(vault, url, true)
    }

    /// Like [`Icons::get`], but only from the cache: never contacts the
    /// site, so it's quick enough to answer the browser extension with.
    pub fn cached(&self, vault: &Mutex<Option<Vault>>, url: &str) -> Option<String> {
        self.lookup(vault, url, false)
    }

    fn lookup(&self, vault: &Mutex<Option<Vault>>, url: &str, fetch: bool) -> Option<String> {
        let host = icon_host(url)?;
        if let Some(hit) = self.memory.lock().unwrap().get(&host) {
            return hit.clone();
        }

        let path = self.dir.join(with_unlocked(vault, |v| v.private_name(PURPOSE, &host))?);
        let cached: Option<Cached> = fs::read(&path)
            .ok()
            .and_then(|sealed| with_unlocked(vault, |v| v.open_local(PURPOSE, &sealed).ok()).flatten())
            .and_then(|plain| serde_json::from_slice(&plain).ok());
        let max_age = match &cached {
            Some(Cached { data_uri: Some(_), .. }) => REFRESH_FOUND,
            _ => RETRY_MISSING,
        };
        if let Some(c) = &cached
            && (!fetch || now_secs().saturating_sub(c.fetched_at) < max_age.as_secs())
        {
            self.remember(&host, c.data_uri.clone());
            return c.data_uri.clone();
        }
        if !fetch {
            return None;
        }

        let fetched = self.limited(|| fetch_icon(&host));
        let data_uri = match (fetched, cached) {
            (Some((mime, bytes)), _) => Some(format!("data:{mime};base64,{}", B64.encode(bytes))),
            // Offline or the site is down: keep showing the old icon.
            (None, Some(Cached { data_uri: Some(old), .. })) => Some(old),
            (None, _) => None,
        };
        let record = serde_json::to_vec(&Cached { fetched_at: now_secs(), data_uri: data_uri.clone() }).ok()?;
        if let Some(sealed) = with_unlocked(vault, |v| v.seal_local(PURPOSE, &record)) {
            let _ = fs::create_dir_all(&self.dir).and_then(|_| fs::write(&path, sealed));
        }
        self.remember(&host, data_uri.clone());
        data_uri
    }

    fn remember(&self, host: &str, data_uri: Option<String>) {
        self.memory.lock().unwrap().insert(host.to_string(), data_uri);
    }

    fn limited<T>(&self, f: impl FnOnce() -> T) -> T {
        let mut running = self.slot_free.wait_while(self.running.lock().unwrap(), |n| *n >= MAX_PARALLEL).unwrap();
        *running += 1;
        drop(running);
        let result = f();
        *self.running.lock().unwrap() -= 1;
        self.slot_free.notify_one();
        result
    }
}

/// Run `f` if the vault is unlocked (it may have been locked mid-fetch).
fn with_unlocked<T>(vault: &Mutex<Option<Vault>>, f: impl FnOnce(&Vault) -> T) -> Option<T> {
    vault.lock().unwrap().as_ref().map(f)
}

/// The host to fetch an icon for, if it's a public website. Addresses and
/// local names (routers, NAS boxes, `localhost`) are never contacted.
pub fn icon_host(url: &str) -> Option<String> {
    let with_scheme = if url.contains("://") { url.to_string() } else { format!("https://{url}") };
    let parsed = Url::parse(&with_scheme).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
        return None;
    }
    // Needs a real public suffix with a name in front: rules out "localhost",
    // "nas.local", "printer" and bare suffixes like "co.uk".
    let suffix = psl::suffix(host.as_bytes())?;
    if !suffix.is_known() || psl::domain(host.as_bytes()).is_none() {
        return None;
    }
    Some(host.strip_prefix("www.").filter(|h| h.contains('.')).unwrap_or(&host).to_string())
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(8)))
        .https_only(true)
        .max_redirects(5)
        .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15")
        .build()
        .into()
}

/// Fetch the best icon a site offers: what its home page declares, then the
/// conventional locations. Tries the parent domain if a subdomain has none
/// (`accounts.example.com` → `example.com`).
fn fetch_icon(host: &str) -> Option<(&'static str, Vec<u8>)> {
    let agent = agent();
    let mut hosts = vec![host.to_string()];
    if let Some(domain) = psl::domain_str(host)
        && domain != host
    {
        hosts.push(domain.to_string());
    }
    for h in hosts {
        let mut candidates = declared_icons(&agent, &h);
        for fallback in ["apple-touch-icon.png", "favicon.ico"] {
            if let Ok(u) = Url::parse(&format!("https://{h}/{fallback}")) {
                candidates.push(u);
            }
        }
        for url in candidates.into_iter().take(6) {
            if let Some(icon) = download_image(&agent, url.as_str()) {
                return Some(icon);
            }
        }
    }
    None
}

/// Icon links on the home page, best first.
fn declared_icons(agent: &ureq::Agent, host: &str) -> Vec<Url> {
    let Ok(mut response) = agent.get(&format!("https://{host}/")).call() else { return vec![] };
    let base = Url::parse(&response.get_uri().to_string()).ok();
    let mut page = Vec::new();
    if response.body_mut().as_reader().take(MAX_PAGE).read_to_end(&mut page).is_err() {
        return vec![];
    }
    let Some(base) = base else { return vec![] };
    let html = String::from_utf8_lossy(&page);
    let mut links: Vec<(u32, Url)> = parse_icon_links(&html)
        .into_iter()
        .filter_map(|link| Some((link.score(), base.join(&link.href).ok()?)))
        .filter(|(_, u)| u.scheme() == "https")
        .collect();
    links.sort_by(|a, b| b.0.cmp(&a.0));
    links.into_iter().map(|(_, u)| u).collect()
}

#[derive(Debug, PartialEq)]
struct IconLink {
    rel: String,
    href: String,
    size: u32,
    svg: bool,
}

impl IconLink {
    /// Prefer large, square, full-bleed icons: they look best as a tile.
    fn score(&self) -> u32 {
        let touch = self.rel.contains("apple-touch-icon");
        let size = if self.svg { 256 } else if self.size > 0 { self.size } else if touch { 180 } else { 16 };
        // Anything from 64 px up is sharp enough; beyond that, size matters less than style.
        size.min(256) + if touch { 64 } else { 0 }
    }
}

/// `<link rel="icon" ...>` and friends. A tolerant scan, not a full HTML parser.
fn parse_icon_links(html: &str) -> Vec<IconLink> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(start) = lower[pos..].find("<link").map(|i| pos + i) {
        let end = lower[start..].find('>').map(|i| start + i).unwrap_or(lower.len());
        let tag = &html[start..end];
        pos = end;
        let attrs = parse_attributes(tag);
        let rel = attrs.get("rel").map(|r| r.to_ascii_lowercase()).unwrap_or_default();
        let is_icon = rel.split_whitespace().any(|r| matches!(r, "icon" | "apple-touch-icon" | "apple-touch-icon-precomposed"));
        let Some(href) = attrs.get("href").filter(|h| !h.is_empty() && !h.starts_with("data:")) else { continue };
        if !is_icon {
            continue;
        }
        let size = attrs
            .get("sizes")
            .and_then(|s| s.split_whitespace().filter_map(|wh| wh.split(['x', 'X']).next()?.parse().ok()).max())
            .unwrap_or(0);
        let svg = attrs.get("type").is_some_and(|t| t.contains("svg")) || href.to_ascii_lowercase().split('?').next().is_some_and(|p| p.ends_with(".svg"));
        out.push(IconLink { rel, href: html_unescape(href), size, svg });
    }
    out
}

fn parse_attributes(tag: &str) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    let bytes = tag.as_bytes();
    let mut i = 5; // past "<link"
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' && bytes[i] != b'/' {
            i += 1;
        }
        let name = tag[name_start..i].to_ascii_lowercase();
        if name.is_empty() {
            break;
        }
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                let start = i + 1;
                i = start;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                value = tag[start..i.min(tag.len())].to_string();
                i += 1;
            } else {
                let start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                value = tag[start..i].to_string();
            }
        }
        attrs.entry(name).or_insert(value);
    }
    attrs
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&").replace("&#38;", "&").replace("&quot;", "\"").replace("&#x2F;", "/")
}

fn download_image(agent: &ureq::Agent, url: &str) -> Option<(&'static str, Vec<u8>)> {
    let mut response = agent.get(url).call().ok()?;
    let mut bytes = Vec::new();
    response.body_mut().as_reader().take(MAX_ICON + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_ICON {
        return None;
    }
    Some((sniff_image(&bytes)?, bytes))
}

/// The image type, judged from the bytes themselves: servers often send
/// wrong content types, or an HTML error page with status 200.
fn sniff_image(b: &[u8]) -> Option<&'static str> {
    if b.len() < 24 {
        return None;
    }
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if b.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if b.starts_with(b"GIF8") {
        Some("image/gif")
    } else if b.starts_with(b"RIFF") && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else if b.starts_with(&[0, 0, 1, 0]) {
        Some("image/x-icon")
    } else {
        // SVG: shown through <img>, where scripts and external loads don't run.
        let head = String::from_utf8_lossy(&b[..b.len().min(1024)]).to_ascii_lowercase();
        let head = head.trim_start_matches('\u{feff}').trim_start();
        (head.starts_with("<svg") || (head.starts_with("<?xml") && head.contains("<svg"))).then_some("image/svg+xml")
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_sites_get_icons() {
        assert_eq!(icon_host("https://www.github.com/login").as_deref(), Some("github.com"));
        assert_eq!(icon_host("lichess.org").as_deref(), Some("lichess.org"));
        assert_eq!(icon_host("https://accounts.google.com").as_deref(), Some("accounts.google.com"));
        for local in ["http://192.168.1.1", "https://[::1]/", "http://localhost:3000", "nas.local", "printer", "ftp://example.com", "https://router.internal"] {
            assert_eq!(icon_host(local), None, "{local}");
        }
    }

    #[test]
    fn finds_and_ranks_declared_icons() {
        let html = r#"<head>
            <LINK REL="shortcut icon" href="/favicon.ico">
            <link rel="icon" type="image/png" sizes="32x32" href="/icon-32.png">
            <link rel=apple-touch-icon sizes="180x180" href="/touch.png?v=2&amp;x=1">
            <link rel="stylesheet" href="/site.css">
            <link rel="icon" href="data:image/png;base64,AAAA">
        </head>"#;
        let links = parse_icon_links(html);
        assert_eq!(links.len(), 3);
        let best = links.iter().max_by_key(|l| l.score()).unwrap();
        assert_eq!(best.href, "/touch.png?v=2&x=1");
        assert_eq!(links.iter().find(|l| l.href == "/icon-32.png").unwrap().size, 32);
    }

    /// Talks to real websites: `cargo test -p vaultix-app -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn fetches_icons_from_real_sites() {
        for host in ["lichess.org", "github.com", "amazon.com", "accounts.google.com", "login.microsoftonline.com", "bol.com"] {
            let icon = fetch_icon(host);
            println!("{host}: {:?}", icon.as_ref().map(|(mime, b)| (mime, b.len())));
            assert!(icon.is_some(), "{host}");
        }
    }

    #[test]
    fn recognises_images_and_rejects_error_pages() {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.resize(64, 0);
        assert_eq!(sniff_image(&png), Some("image/png"));
        let svg = br#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"></svg>"#;
        assert_eq!(sniff_image(svg), Some("image/svg+xml"));
        assert_eq!(sniff_image(b"<!doctype html><html><body>Not found</body></html>"), None);
    }
}
