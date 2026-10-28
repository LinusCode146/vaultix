//! Origin checks shared by autofill and passkeys. These are the phishing
//! defenses: the browser extension never decides what matches, the core does.

use url::Url;

/// The host of a URL, lowercased, if it is a web URL we are willing to fill on.
fn web_host(url: &Url) -> Option<String> {
    match url.scheme() {
        "https" => url.host_str().map(|h| h.to_ascii_lowercase()),
        // Plain http only for local development.
        "http" if is_localhost(url) => url.host_str().map(|h| h.to_ascii_lowercase()),
        _ => None,
    }
}

fn is_localhost(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// The registrable domain ("eTLD+1"): `accounts.google.co.uk` → `google.co.uk`.
/// Hosts without one (IP addresses, `localhost`) are their own site.
fn site(host: &str) -> String {
    psl::domain_str(host).unwrap_or(host).to_string()
}

/// Whether a saved login URL should be offered on the page at `page_url`.
///
/// Matches on registrable domain, so a login saved for `example.com` is offered
/// on `login.example.com`, but never on `example.com.evil.net`. An `https`
/// login is never offered on an `http` page.
pub fn login_matches_page(saved_url: &str, page_url: &str) -> bool {
    let Ok(page) = Url::parse(page_url) else {
        return false;
    };
    let Some(page_host) = web_host(&page) else {
        return false;
    };

    // People often save URLs without a scheme ("github.com").
    let saved = Url::parse(saved_url).ok().filter(|u| u.has_host()).or_else(|| Url::parse(&format!("https://{saved_url}")).ok());
    let Some(saved) = saved else { return false };
    let Some(saved_host) = saved.host_str().map(|h| h.to_ascii_lowercase()) else {
        return false;
    };
    if saved.scheme() == "https" && page.scheme() != "https" {
        return false;
    }
    site(&saved_host) == site(&page_host)
}

/// WebAuthn rule: the RP ID must equal the page's host or be a parent domain
/// of it, and must not be a public suffix (`com`, `github.io`, ...).
pub fn rp_id_valid_for_origin(rp_id: &str, origin: &str) -> bool {
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    let Some(host) = web_host(&url) else {
        return false;
    };
    let rp_id = rp_id.to_ascii_lowercase();
    if rp_id.is_empty() {
        return false;
    }
    if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
        return false;
    }
    host == rp_id || psl::suffix_str(&rp_id) != Some(rp_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_matching() {
        assert!(login_matches_page("https://example.com/login", "https://example.com/"));
        assert!(login_matches_page("https://example.com", "https://auth.example.com/x"));
        assert!(login_matches_page("github.com", "https://github.com/session"));
        assert!(login_matches_page("https://bbc.co.uk", "https://account.bbc.co.uk"));

        assert!(!login_matches_page("https://example.com", "https://example.com.evil.net"));
        assert!(!login_matches_page("https://example.com", "https://notexample.com"));
        assert!(!login_matches_page("https://example.com", "http://example.com"));
        assert!(!login_matches_page("https://a.co.uk", "https://b.co.uk"));
        assert!(!login_matches_page("https://alice.github.io", "https://mallory.github.io"));
        assert!(!login_matches_page("https://example.com", "file:///etc/passwd"));
    }

    #[test]
    fn rp_id_rules() {
        assert!(rp_id_valid_for_origin("example.com", "https://example.com"));
        assert!(rp_id_valid_for_origin("example.com", "https://login.example.com"));
        assert!(rp_id_valid_for_origin("localhost", "http://localhost:3000"));

        assert!(!rp_id_valid_for_origin("example.com", "https://example.org"));
        assert!(!rp_id_valid_for_origin("ample.com", "https://example.com"));
        assert!(!rp_id_valid_for_origin("com", "https://example.com"));
        assert!(!rp_id_valid_for_origin("github.io", "https://alice.github.io"));
        assert!(!rp_id_valid_for_origin("example.com", "http://example.com"));
        assert!(!rp_id_valid_for_origin("", "https://example.com"));
    }
}
