//! Watchtower: a security report over the whole vault. Everything is computed
//! locally; the site lists (which sites support two-factor codes or passkeys)
//! are public lists downloaded whole, so nobody learns which sites you use.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::item::{Category, Item};
use crate::strength::{Strength, StrengthLabel, estimate};

// ---------- Site directory ----------

/// Registrable domain → setup instructions URL (if the list has one).
type SiteMap = HashMap<String, Option<String>>;

#[derive(Debug, Default, Clone)]
pub struct SiteDirectory {
    totp: SiteMap,
    passkeys: SiteMap,
}

#[derive(Deserialize)]
struct SiteEntry {
    domain: Option<String>,
    #[serde(rename = "additional-domains", default)]
    additional_domains: Vec<String>,
    documentation: Option<String>,
}

impl SiteDirectory {
    /// From 2fa.directory's `v3/totp.json` (a list of `[name, entry]`) and its
    /// passkeys list `v1/supported.json` (a map of domain → entry).
    pub fn from_json(totp_json: &str, passkeys_json: &str) -> serde_json::Result<Self> {
        let mut dir = SiteDirectory::default();
        for (_, entry) in serde_json::from_str::<Vec<(String, SiteEntry)>>(totp_json)? {
            add(&mut dir.totp, entry.domain.as_deref(), &entry);
        }
        for (domain, entry) in serde_json::from_str::<HashMap<String, SiteEntry>>(passkeys_json)? {
            add(&mut dir.passkeys, Some(&domain), &entry);
        }
        Ok(dir)
    }

    pub fn is_empty(&self) -> bool {
        self.totp.is_empty() && self.passkeys.is_empty()
    }

    fn find<'a>(map: &'a SiteMap, item: &Item) -> Option<&'a Option<String>> {
        item.urls.iter().filter_map(|u| site_of(u)).find_map(|site| map.get(&site))
    }
}

fn add(map: &mut SiteMap, domain: Option<&str>, entry: &SiteEntry) {
    for d in domain.into_iter().chain(entry.additional_domains.iter().map(String::as_str)) {
        let d = d.trim().to_ascii_lowercase();
        let site = psl::domain_str(&d).unwrap_or(&d).to_string();
        map.entry(site).or_insert_with(|| entry.documentation.clone());
    }
}

/// "https://accounts.google.com/x" → "google.com". Accepts URLs without a scheme.
fn site_of(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok().filter(|u| u.has_host()).or_else(|| Url::parse(&format!("https://{url}")).ok())?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    Some(psl::domain_str(&host).unwrap_or(&host).to_string())
}

// ---------- Report ----------

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub item_id: Uuid,
    /// Short explanation shown next to the item ("Also used by 2 other items").
    pub detail: String,
    /// Where to set something up (two-factor, passkeys), if known.
    pub help_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrengthCount {
    pub label: StrengthLabel,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// 0–1000, `None` for a vault without passwords.
    pub score: Option<u32>,
    pub score_label: &'static str,
    pub password_count: usize,
    pub strength_counts: Vec<StrengthCount>,
    pub reused: Vec<Issue>,
    pub weak: Vec<Issue>,
    pub unsecured: Vec<Issue>,
    pub two_factor_available: Vec<Issue>,
    pub passkeys_available: Vec<Issue>,
    /// False when the site lists couldn't be loaded (the last two are then empty).
    pub site_lists_loaded: bool,
}

/// Strength of an item's password, judged with the words an attacker would
/// try first for this login.
pub fn item_strength(item: &Item) -> Strength {
    let sites: Vec<String> = item.urls.iter().filter_map(|u| site_of(u)).collect();
    let mut context: Vec<&str> = vec![item.username.as_str(), item.title.as_str()];
    for site in &sites {
        context.push(site);
        // "github.com" → also "github"
        if let Some(name) = site.split('.').next() {
            context.push(name);
        }
    }
    context.retain(|w| !w.is_empty());
    estimate(&item.password, &context)
}

pub fn analyze<'a>(items: impl IntoIterator<Item = &'a Item>, sites: &SiteDirectory) -> Report {
    // Only logins: other categories have no website password to judge.
    let items: Vec<&Item> = items.into_iter().filter(|i| i.category == Category::Login).collect();
    let with_password: Vec<&Item> = items.iter().copied().filter(|i| !i.password.is_empty()).collect();

    // Group by a hash of the password, so no extra plaintext copies are kept around.
    let mut by_password: HashMap<[u8; 32], Vec<Uuid>> = HashMap::new();
    for item in &with_password {
        by_password.entry(Sha256::digest(item.password.as_bytes()).into()).or_default().push(item.id);
    }

    let mut report = Report {
        score: None,
        score_label: "No passwords yet",
        password_count: with_password.len(),
        strength_counts: StrengthLabel::ALL.iter().map(|&label| StrengthCount { label, count: 0 }).collect(),
        reused: vec![],
        weak: vec![],
        unsecured: vec![],
        two_factor_available: vec![],
        passkeys_available: vec![],
        site_lists_loaded: !sites.is_empty(),
    };
    let mut health_total = 0.0;

    for item in &with_password {
        let strength = item_strength(item);
        report.strength_counts[strength.label as usize].count += 1;
        let mut health = (strength.guesses_log10 / 16.0).min(1.0);

        let shared = by_password[&<[u8; 32]>::from(Sha256::digest(item.password.as_bytes()))].len();
        if shared > 1 {
            let others = shared - 1;
            report.reused.push(issue(item, format!("Also used by {others} other item{}", if others == 1 { "" } else { "s" }), None));
            health *= 0.5;
        }
        if strength.label.is_weak() {
            report.weak.push(issue(item, label_text(strength.label).to_string(), None));
        }
        if let Some(url) = item.urls.iter().find(|u| is_unsecured(u)) {
            report.unsecured.push(issue(item, url.clone(), None));
            health *= 0.8;
        }
        if item.totp.is_some() || !item.passkeys.is_empty() {
            health = (health + 0.1).min(1.0);
        }
        health_total += health;
    }

    for item in &items {
        if item.totp.is_none()
            && let Some(doc) = SiteDirectory::find(&sites.totp, item)
        {
            report.two_factor_available.push(issue(item, "Supports two-factor codes".into(), doc.clone()));
        }
        if item.passkeys.is_empty()
            && let Some(doc) = SiteDirectory::find(&sites.passkeys, item)
        {
            report.passkeys_available.push(issue(item, "Supports passkeys".into(), doc.clone()));
        }
    }

    if !with_password.is_empty() {
        let score = (1000.0 * health_total / with_password.len() as f64).round() as u32;
        report.score = Some(score);
        report.score_label = match score {
            0..300 => "Poor",
            300..500 => "Fair",
            500..700 => "Good",
            700..850 => "Very good",
            850..950 => "Excellent",
            _ => "Fantastic",
        };
    }
    report
}

fn issue(item: &Item, detail: String, help_url: Option<String>) -> Issue {
    Issue { item_id: item.id, detail, help_url }
}

fn is_unsecured(url: &str) -> bool {
    Url::parse(url).map(|u| u.scheme() == "http" && !matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))).unwrap_or(false)
}

pub fn label_text(label: StrengthLabel) -> &'static str {
    match label {
        StrengthLabel::Terrible => "Terrible",
        StrengthLabel::Weak => "Weak",
        StrengthLabel::Fair => "Fair",
        StrengthLabel::Good => "Good",
        StrengthLabel::VeryGood => "Very good",
        StrengthLabel::Excellent => "Excellent",
        StrengthLabel::Fantastic => "Fantastic",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Totp;

    fn login(title: &str, url: &str, password: &str) -> Item {
        let mut item = Item::new(title, 0);
        item.username = "alice".into();
        item.password = password.into();
        item.urls = vec![url.into()];
        item
    }

    fn directory() -> SiteDirectory {
        let totp = r#"[["GitHub", {"domain": "github.com", "tfa": ["totp"], "documentation": "https://docs.github.com/2fa"}],
                       ["Google", {"domain": "google.com", "additional-domains": ["youtube.com"], "tfa": ["totp"]}]]"#;
        let passkeys = r#"{"github.com": {"documentation": "https://docs.github.com/passkeys"}}"#;
        SiteDirectory::from_json(totp, passkeys).unwrap()
    }

    #[test]
    fn finds_reused_weak_and_unsecured() {
        let items = [
            login("A", "https://a.example", "shared-Pa55word-xyz!"),
            login("B", "https://b.example", "shared-Pa55word-xyz!"),
            login("C", "http://c.example", "password"),
            login("D", "https://d.example", "Kv7#mQ2!xLp9@Rt4zW8$"),
        ];
        let r = analyze(&items, &SiteDirectory::default());
        assert_eq!(r.password_count, 4);
        assert_eq!(r.reused.len(), 2);
        assert_eq!(r.reused[0].detail, "Also used by 1 other item");
        assert_eq!(r.weak.iter().map(|i| i.item_id).collect::<Vec<_>>(), vec![items[2].id]);
        assert_eq!(r.unsecured.len(), 1);
        assert!(!r.site_lists_loaded);
        assert_eq!(r.strength_counts.iter().map(|c| c.count).sum::<usize>(), 4);
    }

    #[test]
    fn site_lists_match_by_registrable_domain() {
        let mut gh = login("GitHub", "https://github.com/login", "x");
        let yt = login("YouTube", "www.youtube.com", "x");
        let other = login("Other", "https://example.org", "x");
        let r = analyze([&gh, &yt, &other], &directory());
        assert_eq!(r.two_factor_available.len(), 2);
        assert_eq!(r.two_factor_available[0].help_url.as_deref(), Some("https://docs.github.com/2fa"));
        assert_eq!(r.passkeys_available.len(), 1);

        // Already set up: no longer flagged.
        gh.totp = Some(Totp::parse("JBSWY3DPEHPK3PXP").unwrap());
        let r = analyze([&gh, &yt, &other], &directory());
        assert_eq!(r.two_factor_available.len(), 1);
    }

    #[test]
    fn score_rewards_strong_unique_passwords() {
        let strong = [login("A", "https://a.example", "Kv7#mQ2!xLp9@Rt4zW8$"), login("B", "https://b.example", "Zq3!vN8@pW2#tL6$yR9%")];
        let weak = [login("A", "https://a.example", "password1"), login("B", "https://b.example", "password1")];
        let s = analyze(&strong, &SiteDirectory::default()).score.unwrap();
        let w = analyze(&weak, &SiteDirectory::default()).score.unwrap();
        assert!(s >= 950 && w < 300, "strong {s}, weak {w}");
        assert_eq!(analyze(&[] as &[Item], &SiteDirectory::default()).score, None);
    }

    #[test]
    fn context_makes_username_based_passwords_weak() {
        let mut item = login("Burger shop", "https://burger.example", "Burgir_ohne_Tomaten1");
        item.username = "Burgir_ohne_Tomaten".into();
        assert!(item_strength(&item).label.is_weak());
    }
}
