//! What the browser extension may ask the app, and the answers.
//!
//! The extension never names the site itself: the URL in each request is the
//! frame URL that the *browser* reports for the sender (not something page
//! JavaScript can set), and every answer is filtered here through the core's
//! origin matching. A page on `evil.com` can therefore only ever receive
//! logins saved for `evil.com`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::commands::PendingFill;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vaultix_core::generator::{PasswordOptions, generate_password};
use vaultix_core::passkey::{COSE_ALG_ES256, client_data_json, sha256};
use vaultix_core::{Item, Passkey, Vault};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct Envelope {
    pub id: u64,
    #[serde(flatten)]
    pub request: Request,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Status,
    /// Logins to offer on a page. Never includes passwords.
    LoginsForPage { url: String },
    /// Credentials for one item, only if it matches `url`.
    Fill { item_id: Uuid, url: String },
    /// Whether submitted credentials are new, changed or already saved.
    CheckLogin { url: String, username: String, password: String },
    /// Save submitted credentials (after the user clicked "Save" or "Update").
    SaveLogin { url: String, username: String, password: String },
    /// Bring the app window to the front, e.g. so the user can unlock.
    ShowApp,
    /// Show the Touch ID prompt and unlock (handled in `ipc`, which owns the app state).
    UnlockTouchId,
    /// A page shows a login form: is there an "Open & Fill" waiting for it?
    /// `password_step` is false on a username-only step (the fill then stays
    /// pending for the password page).
    PendingFill { url: String, password_step: bool },
    /// Passkeys this page may sign in with. Never includes keys.
    /// `allow` is the page's `allowCredentials` (base64url IDs; empty: any).
    PasskeysForPage {
        url: String,
        rp_id: String,
        #[serde(default)]
        allow: Vec<String>,
    },
    /// `navigator.credentials.create`, after the user chose to save it in Vaultix.
    /// Binary values are base64url.
    CreatePasskey {
        url: String,
        rp_id: String,
        user_id: String,
        user_name: String,
        user_display_name: String,
        challenge: String,
        /// COSE algorithms the site accepts (`pubKeyCredParams`).
        algorithms: Vec<i64>,
        /// The site's `excludeCredentials`: passkeys it already has for this account.
        #[serde(default)]
        exclude: Vec<String>,
        /// The login the user chose to save it to (one of `PasskeyTargets`).
        /// Neither this nor `new_login`: the suggested one.
        #[serde(default)]
        item_id: Option<Uuid>,
        #[serde(default)]
        new_login: bool,
    },
    /// Where a new passkey can go: this site's logins, and which one fits best.
    PasskeyTargets { url: String, rp_id: String, user_id: String, user_name: String },
    /// `navigator.credentials.get`, after the user picked one of `PasskeysForPage`.
    UsePasskey { url: String, rp_id: String, credential_id: String, challenge: String },
    /// A strong password for a sign-up or change-password form. Works while
    /// locked: it doesn't touch the vault.
    GeneratePassword,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ok(id: u64, result: Value) -> Self {
        Response { id, ok: true, result: Some(result), error: None }
    }

    pub fn err(id: u64, error: impl Into<String>) -> Self {
        Response { id, ok: false, result: None, error: Some(error.into()) }
    }
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LoginSummary {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub has_totp: bool,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyTarget {
    pub id: Uuid,
    pub title: String,
    pub username: String,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PasskeySummary {
    pub credential_id: String,
    pub title: String,
    pub user_name: String,
}

/// Side effects the handler asks the caller to perform (things that need the
/// Tauri runtime, which the handler itself stays free of so it can be tested).
#[derive(Debug, Default, PartialEq)]
pub struct Effects {
    pub show_app: bool,
    /// The vault changed; tell the UI to reload.
    pub vault_changed: bool,
    /// Put this one-time code on the clipboard (auto-cleared).
    pub copy_totp: Option<String>,
}

/// Handle one request. `vault` is `None` while the app is locked.
pub fn handle(vault: Option<&mut Vault>, request: Request, effects: &mut Effects) -> Result<Value, String> {
    if let Request::UnlockTouchId | Request::PendingFill { .. } = request {
        return Err("not handled here".into());
    }
    if let Request::ShowApp = request {
        effects.show_app = true;
        return Ok(json!({}));
    }
    if let Request::Status = request {
        return Ok(json!({ "locked": vault.is_none() }));
    }
    if let Request::GeneratePassword = request {
        return Ok(json!({ "password": generate_password(&PasswordOptions::default()) }));
    }
    let vault = vault.ok_or("locked")?;

    match request {
        Request::Status | Request::ShowApp | Request::UnlockTouchId | Request::PendingFill { .. } | Request::GeneratePassword => {
            unreachable!("handled above")
        }

        Request::LoginsForPage { url } => {
            let logins: Vec<LoginSummary> = vault
                .items_for_page(&url)
                .into_iter()
                .filter(|i| !i.password.is_empty() || i.totp.is_some())
                .map(|i| LoginSummary {
                    id: i.id,
                    title: i.title.clone(),
                    username: i.username.clone(),
                    has_totp: i.totp.is_some(),
                })
                .collect();
            Ok(serde_json::to_value(logins).unwrap())
        }

        Request::Fill { item_id, url } => fill(vault, item_id, &url, effects),

        Request::CheckLogin { url, username, password } => {
            validate_submission(&url, &password)?;
            let status = match find_login(vault, &url, &username) {
                None => "new",
                Some(item) if item.password == password => "same",
                Some(_) => "update",
            };
            Ok(json!({ "status": status }))
        }

        Request::SaveLogin { url, username, password } => {
            validate_submission(&url, &password)?;
            let existing = find_login(vault, &url, &username).cloned();
            let created = existing.is_none();
            let mut item = match existing {
                Some(item) => item,
                None => {
                    let mut item = Item::new(site_title(&url), now_ms());
                    item.username = username;
                    item.urls = vec![origin_of(&url)];
                    item
                }
            };
            item.password = password;
            let id = item.id;
            vault.put(item).map_err(|e| e.to_string())?;
            effects.vault_changed = true;
            Ok(json!({ "itemId": id, "created": created }))
        }

        Request::PasskeysForPage { url, rp_id, allow } => {
            let allow = allow.iter().map(|id| from_b64(id)).collect::<Result<Vec<_>, _>>()?;
            let origin = origin_of(&url);
            let passkeys: Vec<PasskeySummary> = vault
                .passkeys_for_rp(&rp_id)
                .into_iter()
                .filter(|(_, p)| vaultix_core::origin::rp_id_valid_for_origin(&p.rp_id, &origin))
                .filter(|(_, p)| allow.is_empty() || allow.contains(&p.credential_id))
                .map(|(item, p)| PasskeySummary {
                    credential_id: to_b64(&p.credential_id),
                    title: item.title.clone(),
                    user_name: if p.user_name.is_empty() { p.user_display_name.clone() } else { p.user_name.clone() },
                })
                .collect();
            Ok(serde_json::to_value(passkeys).unwrap())
        }

        Request::PasskeyTargets { url, rp_id, user_id, user_name } => {
            let user_handle = from_b64(&user_id)?;
            let logins: Vec<PasskeyTarget> = vault
                .items_for_page(&url)
                .into_iter()
                .map(|i| PasskeyTarget { id: i.id, title: i.title.clone(), username: i.username.clone() })
                .collect();
            let suggested = suggested_login(vault, &url, &rp_id, &user_handle, &user_name).map(|i| i.id);
            Ok(json!({ "logins": logins, "suggested": suggested }))
        }

        Request::CreatePasskey {
            url,
            rp_id,
            user_id,
            user_name,
            user_display_name,
            challenge,
            algorithms,
            exclude,
            item_id,
            new_login,
        } => {
            if !algorithms.contains(&COSE_ALG_ES256) {
                return Err("unsupported-algorithm".into());
            }
            let exclude = exclude.iter().map(|id| from_b64(id)).collect::<Result<Vec<_>, _>>()?;
            if vault.passkeys_for_rp(&rp_id).iter().any(|(_, p)| exclude.contains(&p.credential_id)) {
                return Err("excluded".into());
            }
            let (user_handle, challenge) = (from_b64(&user_id)?, from_b64(&challenge)?);
            let origin = origin_of(&url);
            let (passkey, registration) =
                Passkey::create(&rp_id, &origin, &user_handle, &user_name, &user_display_name, now_ms()).map_err(|_| "rp-id-not-allowed")?;
            let client_data = client_data_json("webauthn.create", &challenge, &origin);

            let target = match (item_id, new_login) {
                (_, true) => None,
                // Only one of this site's logins, whatever the page asks for.
                (Some(id), false) => Some(vault.get(id).filter(|i| i.matches_page(&url)).ok_or("no matching login for this page")?),
                (None, false) => suggested_login(vault, &url, &rp_id, &user_handle, &user_name),
            };
            let mut item = target.cloned().unwrap_or_else(|| {
                let mut item = Item::new(site_title(&url), now_ms());
                item.username = user_name.clone();
                item.urls = vec![origin.clone()];
                item
            });

            // Re-registering an account replaces its passkey, wherever it was.
            // A login left holding nothing at all (one made just for that
            // passkey) goes too.
            let same_account = |p: &Passkey| p.rp_id == passkey.rp_id && p.user_handle == user_handle;
            let elsewhere: Vec<Item> = vault
                .items()
                .into_iter()
                .filter(|i| i.id != item.id && i.passkeys.iter().any(same_account))
                .cloned()
                .collect();
            for mut other in elsewhere {
                other.passkeys.retain(|p| !same_account(p));
                let empty = other.password.is_empty()
                    && other.totp.is_none()
                    && other.passkeys.is_empty()
                    && other.notes.is_empty()
                    && other.fields.iter().all(|f| f.value.is_empty())
                    && other.files.is_empty();
                if empty { vault.delete(other.id) } else { vault.put(other) }.map_err(|e| e.to_string())?;
            }
            item.passkeys.retain(|p| !same_account(p));
            item.passkeys.push(passkey);
            let title = item.title.clone();
            vault.put(item).map_err(|e| e.to_string())?;
            effects.vault_changed = true;
            Ok(json!({
                "credentialId": to_b64(&registration.credential_id),
                "clientDataJSON": to_b64(client_data.as_bytes()),
                "attestationObject": to_b64(&registration.attestation_object),
                "authenticatorData": to_b64(&registration.authenticator_data),
                "publicKey": to_b64(&registration.public_key_spki),
                "publicKeyAlgorithm": registration.public_key_algorithm,
                "title": title,
            }))
        }

        Request::UsePasskey { url, rp_id, credential_id, challenge } => {
            let credential_id = from_b64(&credential_id)?;
            let challenge = from_b64(&challenge)?;
            let (_, passkey) = vault
                .passkeys_for_rp(&rp_id)
                .into_iter()
                .find(|(_, p)| p.credential_id == credential_id)
                .ok_or("no such passkey")?;
            let origin = origin_of(&url);
            let client_data = client_data_json("webauthn.get", &challenge, &origin);
            // Refuses passkeys for other sites, whatever the page claims as its RP ID.
            let assertion = passkey.assert(&origin, &sha256(client_data.as_bytes())).map_err(|_| "rp-id-not-allowed")?;
            Ok(json!({
                "credentialId": to_b64(&assertion.credential_id),
                "clientDataJSON": to_b64(client_data.as_bytes()),
                "authenticatorData": to_b64(&assertion.authenticator_data),
                "signature": to_b64(&assertion.signature),
                "userHandle": to_b64(&assertion.user_handle),
            }))
        }
    }
}

fn to_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn from_b64(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).map_err(|_| "bad base64".to_string())
}

fn fill(vault: &Vault, item_id: Uuid, url: &str, effects: &mut Effects) -> Result<Value, String> {
    let item = vault.get(item_id).filter(|i| i.matches_page(url)).ok_or("no matching login for this page")?;
    let totp = match &item.totp {
        Some(t) => Some(t.code_at(now_secs()).map_err(|e| e.to_string())?),
        None => None,
    };
    effects.copy_totp = totp.clone();
    Ok(json!({ "username": item.username, "password": item.password, "totp": totp }))
}

/// Credentials for a waiting "Open & Fill", if `url` is that login's site;
/// otherwise `null`. Used up once the password step has been filled.
pub fn pending_fill(
    vault: Option<&Vault>,
    pending: &mut Option<PendingFill>,
    url: &str,
    password_step: bool,
    effects: &mut Effects,
) -> Result<Value, String> {
    if pending.as_ref().is_some_and(|p| p.expires_at < SystemTime::now()) {
        *pending = None;
    }
    let (Some(vault), Some(p)) = (vault, pending.as_ref()) else { return Ok(Value::Null) };
    // Only for the login's own site: anything else (an ad frame, a redirect
    // elsewhere) gets nothing and leaves the fill waiting.
    let Ok(credentials) = fill(vault, p.item_id, url, effects) else { return Ok(Value::Null) };
    if password_step {
        *pending = None;
    }
    Ok(credentials)
}

/// The login a new passkey most likely belongs to, if any: a real login (with a
/// password or one-time code) that already has this account's passkey, else
/// the one with this username, else the site's only real login (unless that
/// one holds another account's passkey), else wherever the account's passkey is.
///
/// Sites often name the account differently from how it was saved: GitHub
/// sends the username for a login saved under the email address.
fn suggested_login<'a>(vault: &'a Vault, url: &str, rp_id: &str, user_handle: &[u8], user_name: &str) -> Option<&'a Item> {
    let rp_id = rp_id.to_ascii_lowercase();
    let has = |i: &Item, same: bool| i.passkeys.iter().any(|p| p.rp_id == rp_id && (p.user_handle == user_handle) == same);
    let real = |i: &&Item| !i.password.is_empty() || i.totp.is_some();
    let logins = vault.items_for_page(url);
    let this_account = || logins.iter().copied().find(|i| has(i, true));
    this_account()
        .filter(real)
        .or_else(|| find_login(vault, url, user_name).filter(real))
        .or_else(|| match logins.iter().copied().filter(real).collect::<Vec<_>>().as_slice() {
            [only] if !has(only, false) => Some(*only),
            _ => None,
        })
        .or_else(this_account)
}

/// The saved login for this site and username (usernames compare
/// case-insensitively, since most sites treat them that way).
fn find_login<'a>(vault: &'a Vault, url: &str, username: &str) -> Option<&'a Item> {
    let username = username.trim().to_lowercase();
    vault
        .items_for_page(url)
        .into_iter()
        .find(|i| i.username.trim().to_lowercase() == username)
}

fn validate_submission(url: &str, password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("empty password".into());
    }
    let parsed = url::Url::parse(url).map_err(|_| "invalid page URL")?;
    if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() {
        return Err("logins can only be saved for web pages".into());
    }
    Ok(())
}

fn origin_of(url: &str) -> String {
    url::Url::parse(url).map(|u| u.origin().ascii_serialization()).unwrap_or_else(|_| url.to_string())
}

/// "accounts.example.com" → "example.com", "www.github.com" → "github.com".
fn site_title(url: &str) -> String {
    let host = url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    psl::domain_str(&host).unwrap_or(&host).to_string()
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaultix_core::Totp;
    use vaultix_core::crypto::KdfParams;

    fn vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::create_with_params(dir.path(), "pw", Uuid::new_v4(), KdfParams::insecure_fast()).unwrap();
        let mut gh = Item::new("GitHub", 0);
        gh.username = "alice".into();
        gh.password = "gh-pass".into();
        gh.urls = vec!["https://github.com".into()];
        gh.totp = Some(Totp::parse("JBSWY3DPEHPK3PXP").unwrap());
        v.put(gh).unwrap();
        let mut bank = Item::new("Bank", 0);
        bank.username = "alice".into();
        bank.password = "bank-pass".into();
        bank.urls = vec!["https://bank.example".into()];
        v.put(bank).unwrap();
        (dir, v)
    }

    fn call(v: &mut Vault, req: Request) -> Result<Value, String> {
        handle(Some(v), req, &mut Effects::default())
    }

    fn id_of(v: &Vault, title: &str) -> Uuid {
        v.items().into_iter().find(|i| i.title == title).unwrap().id
    }

    fn create_passkey(v: &mut Vault, url: &str, rp_id: &str, user: &str, exclude: Vec<String>) -> Result<Value, String> {
        create_passkey_in(v, url, rp_id, user, exclude, None, false)
    }

    fn create_passkey_in(
        v: &mut Vault,
        url: &str,
        rp_id: &str,
        user: &str,
        exclude: Vec<String>,
        item_id: Option<Uuid>,
        new_login: bool,
    ) -> Result<Value, String> {
        call(v, Request::CreatePasskey {
            url: url.into(),
            rp_id: rp_id.into(),
            user_id: to_b64(format!("id-{user}").as_bytes()),
            user_name: user.into(),
            user_display_name: user.into(),
            challenge: to_b64(b"challenge-1"),
            algorithms: vec![-8, -7, -257],
            exclude,
            item_id,
            new_login,
        })
    }

    fn passkeys(v: &mut Vault, url: &str, rp_id: &str) -> Vec<Value> {
        let r = call(v, Request::PasskeysForPage { url: url.into(), rp_id: rp_id.into(), allow: vec![] }).unwrap();
        r.as_array().unwrap().clone()
    }

    #[test]
    fn passkey_is_added_to_the_existing_login_and_used_to_sign_in() {
        let (_d, mut v) = vault();
        let mut fx = Effects::default();
        let req = Request::CreatePasskey {
            url: "https://github.com/settings/security".into(),
            rp_id: "github.com".into(),
            user_id: to_b64(b"user-42"),
            user_name: "Alice".into(),
            user_display_name: "Alice A.".into(),
            challenge: to_b64(b"register-me"),
            algorithms: vec![-7],
            exclude: vec![],
            item_id: None,
            new_login: false,
        };
        let created = handle(Some(&mut v), req, &mut fx).unwrap();
        assert!(fx.vault_changed);
        assert_eq!(created["title"], "GitHub");
        let client_data: Value = serde_json::from_slice(&from_b64(created["clientDataJSON"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(client_data["type"], "webauthn.create");
        assert_eq!(client_data["origin"], "https://github.com");
        assert_eq!(client_data["challenge"], to_b64(b"register-me"));
        // Attached to the GitHub login (usernames match case-insensitively), not a new item.
        assert_eq!(v.items().len(), 2);
        let gh = v.get(id_of(&v, "GitHub")).unwrap();
        assert_eq!(gh.passkeys.len(), 1);
        assert_eq!(gh.password, "gh-pass");

        let list = passkeys(&mut v, "https://github.com/login", "github.com");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["credentialId"], created["credentialId"]);
        assert_eq!(list[0]["userName"], "Alice");

        let used = call(&mut v, Request::UsePasskey {
            url: "https://github.com/login".into(),
            rp_id: "github.com".into(),
            credential_id: created["credentialId"].as_str().unwrap().into(),
            challenge: to_b64(b"sign-in"),
        })
        .unwrap();
        assert_eq!(from_b64(used["userHandle"].as_str().unwrap()).unwrap(), b"user-42");
        let client_data: Value = serde_json::from_slice(&from_b64(used["clientDataJSON"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(client_data["type"], "webauthn.get");
        assert!(!used["signature"].as_str().unwrap().is_empty());

        // Another user ID is another account on the site: a second passkey, same login.
        create_passkey(&mut v, "https://github.com/", "github.com", "Alice", vec![]).unwrap();
        assert_eq!(passkeys(&mut v, "https://github.com/", "github.com").len(), 2);
        // The same account registering again replaces its passkey.
        create_passkey(&mut v, "https://github.com/", "github.com", "Alice", vec![]).unwrap();
        assert_eq!(passkeys(&mut v, "https://github.com/", "github.com").len(), 2);
        assert_eq!(v.items().len(), 2);
    }

    #[test]
    fn passkey_goes_to_the_sites_only_login_whatever_its_username() {
        let (_d, mut v) = vault();
        // Saved as "alice"; the site calls the account "alice-gh".
        create_passkey(&mut v, "https://github.com/settings/security", "github.com", "alice-gh", vec![]).unwrap();
        assert_eq!(v.items().len(), 2);
        let gh = v.get(id_of(&v, "GitHub")).unwrap();
        assert_eq!((gh.username.as_str(), gh.passkeys.len()), ("alice", 1));

        // A second account: the only login already has the first account's passkey.
        let created = create_passkey(&mut v, "https://github.com/", "github.com", "bob", vec![]).unwrap();
        assert_eq!(created["title"], "github.com");
        assert_eq!(v.items().len(), 3);
        assert_eq!(v.get(id_of(&v, "GitHub")).unwrap().passkeys.len(), 1);
    }

    #[test]
    fn passkey_moves_from_a_passkey_only_login_to_the_real_one() {
        // GitHub saved under the email; an earlier passkey went to its own
        // login under the GitHub username.
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::create_with_params(dir.path(), "pw", Uuid::new_v4(), KdfParams::insecure_fast()).unwrap();
        let mut gh = Item::new("GitHub", 0);
        gh.username = "me@example.com".into();
        gh.password = "gh-pass".into();
        gh.urls = vec!["https://github.com".into()];
        v.put(gh).unwrap();
        create_passkey_in(&mut v, "https://github.com/", "github.com", "octo", vec![], None, true).unwrap();
        assert_eq!(v.items().len(), 2);

        let targets = call(&mut v, Request::PasskeyTargets {
            url: "https://github.com/settings/security".into(),
            rp_id: "github.com".into(),
            user_id: to_b64(b"id-octo"),
            user_name: "octo".into(),
        })
        .unwrap();
        assert_eq!(targets["logins"].as_array().unwrap().len(), 2);
        let github = id_of(&v, "GitHub");
        assert_eq!(targets["suggested"], json!(github));

        // Registering again (the site forgot the old one): it moves, and the
        // login that only held it is removed.
        create_passkey_in(&mut v, "https://github.com/", "github.com", "octo", vec![], None, false).unwrap();
        assert_eq!(v.items().len(), 1);
        let gh = v.get(github).unwrap();
        assert_eq!((gh.passkeys.len(), gh.password.as_str()), (1, "gh-pass"));
    }

    #[test]
    fn passkey_goes_where_the_user_chose() {
        let (_d, mut v) = vault();
        let bank = id_of(&v, "Bank");
        // Another site's login can't be chosen.
        assert!(create_passkey_in(&mut v, "https://github.com/", "github.com", "alice", vec![], Some(bank), false).is_err());
        create_passkey_in(&mut v, "https://github.com/", "github.com", "alice", vec![], None, true).unwrap();
        assert_eq!(v.items().len(), 3);
        assert!(v.get(id_of(&v, "GitHub")).unwrap().passkeys.is_empty());
    }

    #[test]
    fn passkey_for_a_new_site_gets_its_own_login() {
        let (_d, mut v) = vault();
        let created = create_passkey(&mut v, "https://www.example.org/signup", "example.org", "bob", vec![]).unwrap();
        assert_eq!(created["title"], "example.org");
        let item = v.items().into_iter().find(|i| i.title == "example.org").unwrap();
        assert_eq!(item.username, "bob");
        assert_eq!(item.urls, vec!["https://www.example.org".to_string()]);
        assert!(item.password.is_empty());
    }

    #[test]
    fn passkeys_stay_on_their_own_site() {
        let (_d, mut v) = vault();
        let created = create_passkey(&mut v, "https://github.com/", "github.com", "alice", vec![]).unwrap();
        let id = created["credentialId"].as_str().unwrap().to_string();

        // Another site can't create passkeys for github.com, list them or use them.
        assert!(create_passkey(&mut v, "https://evil.example/", "github.com", "alice", vec![]).is_err());
        assert!(create_passkey(&mut v, "https://github.com/", "com", "alice", vec![]).is_err());
        assert!(passkeys(&mut v, "https://github.com.evil.net/", "github.com").is_empty());
        let stolen = call(&mut v, Request::UsePasskey {
            url: "https://evil.example/".into(),
            rp_id: "github.com".into(),
            credential_id: id.clone(),
            challenge: to_b64(b"x"),
        });
        assert!(stolen.is_err());

        // The site already has this passkey: creating another is refused.
        assert_eq!(create_passkey(&mut v, "https://github.com/", "github.com", "alice", vec![id]).unwrap_err(), "excluded");
        // Only ES256 keys.
        let r = call(&mut v, Request::CreatePasskey {
            url: "https://github.com/".into(),
            rp_id: "github.com".into(),
            user_id: to_b64(b"u"),
            user_name: "alice".into(),
            user_display_name: String::new(),
            challenge: to_b64(b"c"),
            algorithms: vec![-257],
            exclude: vec![],
            item_id: None,
            new_login: false,
        });
        assert_eq!(r.unwrap_err(), "unsupported-algorithm");
        // Locked: nothing.
        let r = handle(None, Request::PasskeysForPage { url: "https://github.com/".into(), rp_id: "github.com".into(), allow: vec![] }, &mut Effects::default());
        assert_eq!(r.unwrap_err(), "locked");
    }

    #[test]
    fn locked_vault_reveals_nothing() {
        let mut fx = Effects::default();
        assert_eq!(handle(None, Request::Status, &mut fx).unwrap(), json!({ "locked": true }));
        let generated = handle(None, Request::GeneratePassword, &mut fx).unwrap();
        assert_eq!(generated["password"].as_str().unwrap().chars().count(), 20);
        let r = handle(None, Request::LoginsForPage { url: "https://github.com".into() }, &mut fx);
        assert_eq!(r.unwrap_err(), "locked");
    }

    #[test]
    fn logins_for_page_only_lists_matching_items_without_passwords() {
        let (_d, mut v) = vault();
        let r = call(&mut v, Request::LoginsForPage { url: "https://github.com/login".into() }).unwrap();
        let list = r.as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["title"], "GitHub");
        assert_eq!(list[0]["hasTotp"], true);
        assert!(!r.to_string().contains("gh-pass"));

        let r = call(&mut v, Request::LoginsForPage { url: "https://github.com.evil.net/".into() }).unwrap();
        assert!(r.as_array().unwrap().is_empty());
    }

    #[test]
    fn fill_refuses_items_for_other_sites() {
        let (_d, mut v) = vault();
        let bank = id_of(&v, "Bank");
        // A compromised github.com page asking for the bank login by ID gets nothing.
        let r = call(&mut v, Request::Fill { item_id: bank, url: "https://github.com/".into() });
        assert!(r.is_err());

        let mut fx = Effects::default();
        let gh = id_of(&v, "GitHub");
        let r = handle(Some(&mut v), Request::Fill { item_id: gh, url: "https://github.com/login".into() }, &mut fx).unwrap();
        assert_eq!(r["password"], "gh-pass");
        assert_eq!(r["totp"].as_str().unwrap().len(), 6);
        assert_eq!(fx.copy_totp.as_deref(), r["totp"].as_str());
    }

    #[test]
    fn check_and_save_new_login() {
        let (_d, mut v) = vault();
        let url = "https://accounts.example.org/signin?next=/";
        let check = |v: &mut Vault, pw: &str| {
            call(v, Request::CheckLogin { url: url.into(), username: "Bob".into(), password: pw.into() }).unwrap()["status"].clone()
        };
        assert_eq!(check(&mut v, "p1"), "new");

        let mut fx = Effects::default();
        let r = handle(
            Some(&mut v),
            Request::SaveLogin { url: url.into(), username: "Bob".into(), password: "p1".into() },
            &mut fx,
        )
        .unwrap();
        assert_eq!(r["created"], true);
        assert!(fx.vault_changed);
        let saved = v.get(r["itemId"].as_str().unwrap().parse().unwrap()).unwrap();
        assert_eq!(saved.title, "example.org");
        assert_eq!(saved.urls, vec!["https://accounts.example.org"]);

        assert_eq!(check(&mut v, "p1"), "same");
        assert_eq!(check(&mut v, "p2"), "update");
    }

    #[test]
    fn save_updates_existing_login_and_keeps_other_fields() {
        let (_d, mut v) = vault();
        let gh = id_of(&v, "GitHub");
        let r = call(
            &mut v,
            Request::SaveLogin { url: "https://github.com/session".into(), username: "ALICE".into(), password: "new".into() },
        )
        .unwrap();
        assert_eq!(r["created"], false);
        let item = v.get(gh).unwrap();
        assert_eq!(item.password, "new");
        assert!(item.totp.is_some());
        assert_eq!(v.items().len(), 2);
    }

    #[test]
    fn rejects_bad_submissions() {
        let (_d, mut v) = vault();
        for (url, pw) in [("https://a.com", ""), ("file:///etc/passwd", "x"), ("not a url", "x")] {
            assert!(call(&mut v, Request::SaveLogin { url: url.into(), username: "u".into(), password: pw.into() }).is_err());
        }
    }

    #[test]
    fn envelope_parses() {
        let e: Envelope = serde_json::from_str(r#"{"id":7,"type":"logins_for_page","url":"https://x.com"}"#).unwrap();
        assert_eq!(e.id, 7);
        assert!(matches!(e.request, Request::LoginsForPage { .. }));
        assert!(serde_json::from_str::<Envelope>(r#"{"id":1,"type":"dump_everything"}"#).is_err());
    }
}

#[cfg(test)]
mod pending_fill_tests {
    use std::time::Duration;

    use super::*;
    use vaultix_core::crypto::KdfParams;

    fn setup() -> (tempfile::TempDir, Vault, Uuid) {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::create_with_params(dir.path(), "pw", Uuid::new_v4(), KdfParams::insecure_fast()).unwrap();
        let mut item = Item::new("GitHub", 0);
        item.username = "alice".into();
        item.password = "s3cret".into();
        item.urls = vec!["https://github.com".into()];
        let id = item.id;
        v.put(item).unwrap();
        (dir, v, id)
    }

    fn waiting(id: Uuid, secs: i64) -> Option<PendingFill> {
        let now = SystemTime::now();
        let expires_at = if secs >= 0 { now + Duration::from_secs(secs as u64) } else { now - Duration::from_secs((-secs) as u64) };
        Some(PendingFill { item_id: id, expires_at })
    }

    #[test]
    fn other_sites_get_nothing_and_the_fill_keeps_waiting() {
        let (_d, v, id) = setup();
        let mut pending = waiting(id, 60);
        let r = pending_fill(Some(&v), &mut pending, "https://evil.example/login", true, &mut Effects::default()).unwrap();
        assert!(r.is_null());
        assert!(pending.is_some());
    }

    #[test]
    fn username_step_keeps_it_password_step_uses_it_up() {
        let (_d, v, id) = setup();
        let mut pending = waiting(id, 60);
        let r = pending_fill(Some(&v), &mut pending, "https://github.com/login", false, &mut Effects::default()).unwrap();
        assert_eq!(r["username"], "alice");
        assert!(pending.is_some());
        let r = pending_fill(Some(&v), &mut pending, "https://github.com/session", true, &mut Effects::default()).unwrap();
        assert_eq!(r["password"], "s3cret");
        assert!(pending.is_none());
    }

    #[test]
    fn expired_or_locked_gives_nothing() {
        let (_d, v, id) = setup();
        let mut pending = waiting(id, -1);
        assert!(pending_fill(Some(&v), &mut pending, "https://github.com/login", true, &mut Effects::default()).unwrap().is_null());
        assert!(pending.is_none());
        let mut pending = waiting(id, 60);
        assert!(pending_fill(None, &mut pending, "https://github.com/login", true, &mut Effects::default()).unwrap().is_null());
    }
}
