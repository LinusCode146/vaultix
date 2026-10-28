//! Reading other password managers' exports: 1Password's `.1pux`, and the
//! CSV files of 1Password, Chrome/Edge/Brave, Firefox, Safari/Apple Passwords
//! and Bitwarden. Parsing only builds items; the caller decides what to save.

use std::collections::HashMap;
use std::io::{Cursor, Read};

use serde_json::Value;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::item::{Category, Field, FieldKind, Item, PasswordChange};
use crate::totp::Totp;

/// One item to import, with the attachments to store for it. The items'
/// [`Item::files`] are empty: store each file with [`crate::Vault::add_file`]
/// and add the references.
pub struct Imported {
    pub item: Item,
    pub files: Vec<ImportedFile>,
}

pub struct ImportedFile {
    pub name: String,
    pub contents: Vec<u8>,
}

impl Drop for ImportedFile {
    fn drop(&mut self) {
        self.contents.zeroize();
    }
}

pub struct ImportResult {
    pub source: &'static str,
    pub items: Vec<Imported>,
    /// Things the user should know, e.g. what couldn't be brought over.
    pub warnings: Vec<String>,
}

/// Read an export, telling the format from its contents.
pub fn parse(bytes: &[u8], now_ms: i64) -> Result<ImportResult> {
    if bytes.starts_with(b"PK") { parse_1pux(bytes, now_ms) } else { parse_csv(bytes, now_ms) }
}

// ---------- 1Password (.1pux) ----------

/// A `.1pux` is a zip with `export.data` (JSON: accounts → vaults → items)
/// and attachments under `files/<documentId>__<file name>`.
pub fn parse_1pux(bytes: &[u8], now_ms: i64) -> Result<ImportResult> {
    let bad = |what: &str| Error::Import(format!("This doesn't look like a 1Password export ({what})."));
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| bad("not a zip file"))?;
    let mut data = String::new();
    zip.by_name("export.data").map_err(|_| bad("no export.data"))?.read_to_string(&mut data)?;
    let export: Value = serde_json::from_str(&data).map_err(|_| bad("unreadable export.data"))?;
    data.zeroize();

    // Attachments by document ID.
    let mut attachments: HashMap<String, String> = HashMap::new();
    for name in zip.file_names().flatten() {
        if let Some((id, _)) = name.strip_prefix("files/").and_then(|n| n.split_once("__")) {
            attachments.insert(id.to_string(), name.to_string());
        }
    }
    let mut read_attachment = |document_id: &str, file_name: &str| -> Option<ImportedFile> {
        let path = attachments.get(document_id)?;
        let mut contents = Vec::new();
        zip.by_name(path).ok()?.read_to_end(&mut contents).ok()?;
        Some(ImportedFile { name: file_name.to_string(), contents })
    };

    let mut items = Vec::new();
    let (mut archived, mut passkeys, mut other_kinds, mut missing_files) = (0, 0, 0, 0);
    let vaults = export["accounts"].as_array().into_iter().flatten().flat_map(|a| a["vaults"].as_array().into_iter().flatten());
    for vault in vaults {
        for raw in vault["items"].as_array().into_iter().flatten() {
            if raw["state"].as_str() == Some("archived") {
                archived += 1;
                continue;
            }
            let details = &raw["details"];
            let overview = &raw["overview"];
            let category_code = raw["categoryUuid"].as_str().unwrap_or("");
            let category = match category_code {
                "001" | "005" => Category::Login,
                "002" => Category::CreditCard,
                "003" => Category::SecureNote,
                "004" => Category::Identity,
                "006" => Category::Document,
                "112" => Category::ApiCredential,
                _ => {
                    other_kinds += 1;
                    Category::SecureNote
                }
            };
            let created = raw["createdAt"].as_i64().map_or(now_ms, |s| s * 1000);
            let mut item = Item::new(str_of(&overview["title"]), created).with_category(category);
            item.updated_at = raw["updatedAt"].as_i64().map_or(now_ms, |s| s * 1000);
            item.favorite = raw["favIndex"].as_i64().is_some_and(|i| i > 0);
            item.notes = str_of(&details["notesPlain"]);
            item.tags = overview["tags"].as_array().into_iter().flatten().filter_map(|t| t.as_str().map(String::from)).collect();
            item.urls = overview["urls"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|u| u["url"].as_str())
                .chain(overview["url"].as_str())
                .map(String::from)
                .filter(|u| !u.is_empty())
                .fold(Vec::new(), |mut urls, u| {
                    if !urls.contains(&u) {
                        urls.push(u);
                    }
                    urls
                });
            for f in details["loginFields"].as_array().into_iter().flatten() {
                match f["designation"].as_str() {
                    Some("username") => item.username = str_of(&f["value"]),
                    Some("password") => item.password = str_of(&f["value"]),
                    _ => {}
                }
            }
            if category_code == "005" {
                item.password = str_of(&details["password"]);
            }
            item.password_history = details["passwordHistory"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|h| {
                    Some(PasswordChange { password: h["value"].as_str()?.to_string(), changed_at: h["time"].as_i64().unwrap_or(0) * 1000 })
                })
                .filter(|h| !h.password.is_empty() && h.password != item.password)
                .take(crate::item::PASSWORD_HISTORY_LEN)
                .collect();
            if details.get("passkey").is_some_and(|p| !p.is_null()) {
                passkeys += 1;
            }

            let mut files = Vec::new();
            let mut want_file =
                |document_id: &str, file_name: &str, files: &mut Vec<ImportedFile>| match read_attachment(document_id, file_name) {
                    Some(f) => files.push(f),
                    None => missing_files += 1,
                };
            if let (Some(id), Some(name)) =
                (details["documentAttributes"]["documentId"].as_str(), details["documentAttributes"]["fileName"].as_str())
            {
                want_file(id, name, &mut files);
            }

            for section in details["sections"].as_array().into_iter().flatten() {
                for f in section["fields"].as_array().into_iter().flatten() {
                    let value = &f["value"];
                    if let (Some(id), Some(name)) = (value["file"]["documentId"].as_str(), value["file"]["fileName"].as_str()) {
                        want_file(id, name, &mut files);
                        continue;
                    }
                    if let Some(uri) = value["totp"].as_str() {
                        match Totp::parse(uri) {
                            Ok(totp) if item.totp.is_none() => {
                                item.totp = Some(totp);
                                continue;
                            }
                            _ => {}
                        }
                    }
                    let source_id = f["id"].as_str().unwrap_or("");
                    let title = f["title"].as_str().unwrap_or("");
                    for (id, label, kind, v) in convert_field(category, source_id, title, value) {
                        if !v.is_empty() {
                            push_field(&mut item, id, label, kind, v);
                        }
                    }
                }
            }
            if item.title.is_empty() {
                item.title = item.urls.first().map(|u| host_of(u)).unwrap_or_else(|| "Untitled".into());
            }
            items.push(Imported { item, files });
        }
    }

    let mut warnings = Vec::new();
    if archived > 0 {
        warnings.push(format!("{archived} archived item{} left out.", plural(archived)));
    }
    if other_kinds > 0 {
        warnings.push(format!(
            "{other_kinds} item{} of other kinds (bank accounts, licences, …) became Secure Notes with all their fields.",
            plural(other_kinds)
        ));
    }
    if passkeys > 0 {
        warnings.push(format!(
            "{passkeys} passkey{} can't be exported from 1Password. Their logins are imported; add the passkeys again on those sites.",
            plural(passkeys)
        ));
    }
    if missing_files > 0 {
        warnings.push(format!("{missing_files} attachment{} missing from the export.", plural(missing_files)));
    }
    Ok(ImportResult { source: "1Password", items, warnings })
}

/// A 1Password section field as Vaultix fields: `(id, label, kind, value)`.
/// Fields Vaultix has a place for keep its IDs, so they show in the editor's
/// usual spots; others keep 1Password's label. Addresses become several fields.
fn convert_field(category: Category, id: &str, title: &str, value: &Value) -> Vec<(String, String, FieldKind, String)> {
    let known = |vaultix_id: &str, label: &str| (vaultix_id.to_string(), label.to_string());
    let target = match (category, id) {
        (Category::CreditCard, "cardholder") => Some(known("cardholder", "cardholder name")),
        (Category::CreditCard, "ccnum") => Some(known("number", "number")),
        (Category::CreditCard, "expiry") => Some(known("expiry", "expiry date")),
        (Category::CreditCard, "cvv") => Some(known("cvv", "verification number")),
        (Category::CreditCard, "pin") => Some(known("pin", "PIN")),
        (Category::CreditCard, "bank") => Some(known("bank", "issuing bank")),
        (Category::CreditCard, "phoneLocal" | "phoneTollFree" | "phoneIntl") => Some(known("phone", "customer service")),
        (Category::Identity, "firstname") => Some(known("first_name", "first name")),
        (Category::Identity, "initial") => Some(known("middle_name", "middle name")),
        (Category::Identity, "lastname") => Some(known("last_name", "last name")),
        (Category::Identity, "birthdate") => Some(known("birth_date", "birth date")),
        (Category::Identity, "email") => Some(known("email", "email")),
        (Category::Identity, "defphone" | "cellphone" | "homephone") => Some(known("phone", "phone")),
        (Category::Identity, "website") => Some(known("website", "website")),
        (Category::Identity, "company") => Some(known("company", "company")),
        (Category::Identity, "jobtitle") => Some(known("job_title", "job title")),
        (Category::ApiCredential, "username" | "credential" | "type" | "hostname" | "expires") => Some(known(id, id)),
        (Category::ApiCredential, "validFrom") => Some(known("valid_from", "valid from")),
        _ => None,
    };

    if let Some(address) = value.get("address").filter(|a| a.is_object()) {
        let part = |k: &str| str_of(&address[k]);
        if category == Category::Identity {
            return vec![
                ("street".into(), "street".into(), FieldKind::Text, part("street")),
                ("city".into(), "city".into(), FieldKind::Text, part("city")),
                ("zip".into(), "postal code".into(), FieldKind::Text, part("zip")),
                ("state".into(), "state".into(), FieldKind::Text, part("state")),
                ("country".into(), "country".into(), FieldKind::Text, part("country")),
            ];
        }
        let joined = ["street", "city", "zip", "state", "country"].map(part).into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>();
        return vec![(field_id(id, title), label_of(id, title), FieldKind::Multiline, joined.join("\n"))];
    }

    let (kind, text) = match value.as_object().and_then(|o| o.iter().next()) {
        Some((k, v)) => match k.as_str() {
            "concealed" | "creditCardNumber" | "totp" => (FieldKind::Concealed, str_of(v)),
            "email" => (FieldKind::Email, v["email_address"].as_str().map(String::from).unwrap_or_else(|| str_of(v))),
            "phone" => (FieldKind::Phone, str_of(v)),
            "url" => (FieldKind::Url, str_of(v)),
            "date" => (FieldKind::Date, v.as_i64().map(date_of).unwrap_or_default()),
            "monthYear" => (FieldKind::MonthYear, v.as_i64().map(|ym| format!("{:02}/{:04}", ym % 100, ym / 100)).unwrap_or_default()),
            "string" | "menu" | "creditCardType" | "gender" => {
                let s = str_of(v);
                (if s.contains('\n') { FieldKind::Multiline } else { FieldKind::Text }, s)
            }
            "sshKey" => (FieldKind::Multiline, v["privateKey"].as_str().map(String::from).unwrap_or_default()),
            _ => (FieldKind::Text, str_of(v)),
        },
        None => (FieldKind::Text, String::new()),
    };
    // Card numbers and similar stay hidden even when filed under a known ID.
    let kind = match target.as_ref().map(|(i, _)| i.as_str()) {
        Some("number" | "cvv" | "pin" | "credential") => FieldKind::Concealed,
        Some("expiry") => FieldKind::MonthYear,
        _ => kind,
    };
    let (id, label) = target.unwrap_or_else(|| (field_id(id, title), label_of(id, title)));
    vec![(id, label, kind, text)]
}

fn push_field(item: &mut Item, id: String, label: String, kind: FieldKind, value: String) {
    // Several 1Password fields can land on one Vaultix field (e.g. phones):
    // the first one wins, the others keep their own IDs.
    let id = if item.fields.iter().any(|f| f.id == id) { format!("{id}_{}", item.fields.len()) } else { id };
    item.fields.push(Field { id, label, kind, value });
}

fn field_id(id: &str, title: &str) -> String {
    let base = if id.is_empty() { title } else { id };
    format!("1p_{}", base.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect::<String>())
}

fn label_of(id: &str, title: &str) -> String {
    if title.is_empty() { id.to_string() } else { title.to_string() }
}

/// 1Password stores dates as Unix seconds at noon UTC.
fn date_of(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

// ---------- CSV ----------

/// The columns each app uses, matched by header name (case-insensitive).
const TITLE: &[&str] = &["title", "name"];
const URL: &[&str] = &["url", "login_uri", "website", "web site"];
const USERNAME: &[&str] = &["username", "login_username", "login name", "email"];
const PASSWORD: &[&str] = &["password", "login_password"];
const NOTES: &[&str] = &["notes", "note", "extra"];
const TOTP: &[&str] = &["otpauth", "login_totp", "totp", "one-time password"];
const TAGS: &[&str] = &["tags"];
const FAVORITE: &[&str] = &["favorite"];
const ARCHIVED: &[&str] = &["archived"];
const KIND: &[&str] = &["type"];

pub fn parse_csv(bytes: &[u8], now_ms: i64) -> Result<ImportResult> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Import("The file isn't text (UTF-8).".into()))?;
    let text = text.trim_start_matches('\u{feff}');
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(text.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(|_| Error::Import("Couldn't read the file's first line.".into()))?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let col = |names: &[&str]| headers.iter().position(|h| names.contains(&h.as_str()));
    let (url, password) = (col(URL), col(PASSWORD));
    if url.is_none() || password.is_none() {
        return Err(Error::Import(
            "This isn't a password export Vaultix knows. Export from 1Password (1PUX or CSV), Chrome, Edge, Firefox, Safari or Bitwarden."
                .into(),
        ));
    }
    let source = match () {
        _ if headers.iter().any(|h| h == "login_uri") => "Bitwarden",
        _ if headers.iter().any(|h| h == "httprealm") => "Firefox",
        _ if headers.iter().any(|h| h == "archived") => "1Password",
        _ if headers.first().is_some_and(|h| h == "title") => "Safari",
        _ => "your browser",
    };
    let (title, username, notes, totp, tags, favorite, archived, kind) =
        (col(TITLE), col(USERNAME), col(NOTES), col(TOTP), col(TAGS), col(FAVORITE), col(ARCHIVED), col(KIND));

    let mut items = Vec::new();
    let (mut skipped_archived, mut bad_totp, mut unsupported) = (0, 0, 0);
    for record in reader.records() {
        let record = record.map_err(|e| Error::Import(format!("Line {} can't be read.", e.position().map_or(0, |p| p.line()))))?;
        let get = |c: Option<usize>| c.and_then(|c| record.get(c)).unwrap_or("").trim().to_string();
        if matches!(get(archived).to_lowercase().as_str(), "true" | "1" | "yes") {
            skipped_archived += 1;
            continue;
        }
        let category = match get(kind).to_lowercase().as_str() {
            "" | "login" | "1" => Category::Login,
            "note" | "2" => Category::SecureNote,
            _ => {
                unsupported += 1;
                continue;
            }
        };
        let mut item = Item::new(get(title), now_ms).with_category(category);
        item.username = get(username);
        item.password = get(password);
        item.notes = get(notes);
        item.urls = get(url).split(',').map(str::trim).filter(|u| !u.is_empty()).map(String::from).collect();
        item.tags = get(tags).split([',', ';']).map(str::trim).filter(|t| !t.is_empty()).map(String::from).collect();
        item.favorite = matches!(get(favorite).to_lowercase().as_str(), "true" | "1" | "yes");
        let otp = get(totp);
        if !otp.is_empty() {
            match Totp::parse(&otp) {
                Ok(t) => item.totp = Some(t),
                Err(_) => bad_totp += 1,
            }
        }
        if item.title.is_empty() {
            item.title = item.urls.first().map(|u| host_of(u)).unwrap_or_else(|| "Untitled".into());
        }
        if item.password.is_empty() && item.username.is_empty() && item.notes.is_empty() && item.urls.is_empty() {
            continue;
        }
        items.push(Imported { item, files: Vec::new() });
    }

    let mut warnings = Vec::new();
    if skipped_archived > 0 {
        warnings.push(format!("{skipped_archived} archived item{} left out.", plural(skipped_archived)));
    }
    if unsupported > 0 {
        warnings.push(format!(
            "{unsupported} card{} or identit{} left out: CSV exports only carry logins and notes well.",
            plural(unsupported),
            if unsupported == 1 { "y" } else { "ies" }
        ));
    }
    if bad_totp > 0 {
        warnings.push(format!("{bad_totp} one-time password secret{} couldn't be read and were left out.", plural(bad_totp)));
    }
    Ok(ImportResult { source, items, warnings })
}

fn str_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn host_of(url: &str) -> String {
    let with_scheme = if url.contains("://") { url.to_string() } else { format!("https://{url}") };
    url::Url::parse(&with_scheme)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_start_matches("www.").to_string()))
        .unwrap_or_else(|| url.to_string())
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn pux(export: Value, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file("export.attributes", SimpleFileOptions::default()).unwrap();
        zip.write_all(br#"{"version":3}"#).unwrap();
        zip.start_file("export.data", SimpleFileOptions::default()).unwrap();
        zip.write_all(export.to_string().as_bytes()).unwrap();
        for (name, contents) in files {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(contents).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    fn by_title<'a>(r: &'a ImportResult, title: &str) -> &'a Item {
        &r.items.iter().find(|i| i.item.title == title).unwrap_or_else(|| panic!("no {title}")).item
    }

    #[test]
    fn reads_a_1password_export() {
        let export = serde_json::json!({ "accounts": [{ "vaults": [{ "attrs": { "name": "Private" }, "items": [
            {
                "uuid": "a", "favIndex": 1, "createdAt": 1600000000, "updatedAt": 1700000000, "state": "active", "categoryUuid": "001",
                "overview": { "title": "GitHub", "url": "https://github.com", "urls": [{ "url": "https://github.com" }, { "url": "https://gist.github.com" }], "tags": ["dev"] },
                "details": {
                    "loginFields": [
                        { "value": "alice", "designation": "username" },
                        { "value": "s3cret", "designation": "password" },
                        { "value": "on", "name": "remember" }
                    ],
                    "notesPlain": "work account",
                    "passwordHistory": [{ "value": "older", "time": 1650000000 }],
                    "passkey": { "credentialId": "x", "rpId": "github.com" },
                    "sections": [{ "fields": [
                        { "title": "one-time password", "id": "TOTP_1", "value": { "totp": "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP" } },
                        { "title": "recovery code", "id": "rc", "value": { "concealed": "1a2b-3c4d" } },
                        { "title": "backup.txt", "id": "f", "value": { "file": { "fileName": "backup.txt", "documentId": "doc1", "decryptedSize": 5 } } }
                    ]}]
                }
            },
            {
                "uuid": "b", "createdAt": 1600000000, "updatedAt": 1600000000, "state": "active", "categoryUuid": "002",
                "overview": { "title": "Visa" },
                "details": { "sections": [{ "fields": [
                    { "title": "cardholder name", "id": "cardholder", "value": { "string": "Alice Schmidt" } },
                    { "title": "number", "id": "ccnum", "value": { "creditCardNumber": "4242424242424242" } },
                    { "title": "expiry date", "id": "expiry", "value": { "monthYear": 202808 } },
                    { "title": "verification number", "id": "cvv", "value": { "concealed": "123" } }
                ]}]}
            },
            {
                "uuid": "c", "createdAt": 1600000000, "updatedAt": 1600000000, "state": "active", "categoryUuid": "004",
                "overview": { "title": "Me" },
                "details": { "sections": [{ "fields": [
                    { "title": "first name", "id": "firstname", "value": { "string": "Alice" } },
                    { "title": "birth date", "id": "birthdate", "value": { "date": 631195200 } },
                    { "title": "address", "id": "address", "value": { "address": { "street": "Main St 1", "city": "Amsterdam", "zip": "1000 AA", "state": "", "country": "nl" } } },
                    { "title": "email", "id": "email", "value": { "email": { "email_address": "alice@example.com", "provider": null } } }
                ]}]}
            },
            {
                "uuid": "d", "createdAt": 1600000000, "updatedAt": 1600000000, "state": "active", "categoryUuid": "006",
                "overview": { "title": "Passport scan" },
                "details": { "documentAttributes": { "fileName": "passport.pdf", "documentId": "doc2", "decryptedSize": 3 } }
            },
            {
                "uuid": "e", "createdAt": 1600000000, "updatedAt": 1600000000, "state": "active", "categoryUuid": "101",
                "overview": { "title": "Savings" },
                "details": { "sections": [{ "fields": [ { "title": "account number", "id": "accountNo", "value": { "string": "NL00BANK0123" } } ] }] }
            },
            {
                "uuid": "f", "createdAt": 1600000000, "updatedAt": 1600000000, "state": "archived", "categoryUuid": "001",
                "overview": { "title": "Old" }, "details": {}
            },
            {
                "uuid": "g", "createdAt": 1600000000, "updatedAt": 1600000000, "state": "active", "categoryUuid": "005",
                "overview": { "title": "Router" }, "details": { "password": "router-pw" }
            }
        ]}]}]});
        let bytes = pux(export, &[("files/doc1__backup.txt", b"hello"), ("files/doc2__passport.pdf", b"pdf")]);
        let r = parse(&bytes, 0).unwrap();
        assert_eq!(r.source, "1Password");
        assert_eq!(r.items.len(), 6, "the archived item is left out");

        let gh = by_title(&r, "GitHub");
        assert_eq!((gh.username.as_str(), gh.password.as_str()), ("alice", "s3cret"));
        assert_eq!(gh.urls, ["https://github.com", "https://gist.github.com"]);
        assert!(gh.favorite && gh.totp.is_some());
        assert_eq!(gh.tags, ["dev"]);
        assert_eq!(gh.password_history[0].password, "older");
        assert_eq!(gh.created_at, 1_600_000_000_000);
        let rc = gh.fields.iter().find(|f| f.label == "recovery code").unwrap();
        assert_eq!((rc.kind, rc.value.as_str()), (FieldKind::Concealed, "1a2b-3c4d"));
        let gh_files = &r.items.iter().find(|i| i.item.title == "GitHub").unwrap().files;
        assert_eq!((gh_files[0].name.as_str(), gh_files[0].contents.as_slice()), ("backup.txt", b"hello".as_slice()));

        let card = by_title(&r, "Visa");
        assert_eq!(card.category, Category::CreditCard);
        assert_eq!(card.field("number"), Some("4242424242424242"));
        assert_eq!(card.field("expiry"), Some("08/2028"));
        assert_eq!(card.fields.iter().find(|f| f.id == "number").unwrap().kind, FieldKind::Concealed);

        let me = by_title(&r, "Me");
        assert_eq!(me.field("first_name"), Some("Alice"));
        assert_eq!(me.field("birth_date"), Some("1990-01-01"));
        assert_eq!(me.field("city"), Some("Amsterdam"));
        assert_eq!(me.field("email"), Some("alice@example.com"));

        let doc = &r.items.iter().find(|i| i.item.title == "Passport scan").unwrap();
        assert_eq!(doc.item.category, Category::Document);
        assert_eq!(doc.files[0].contents, b"pdf");

        let savings = by_title(&r, "Savings");
        assert_eq!(savings.category, Category::SecureNote);
        assert_eq!(savings.fields[0].value, "NL00BANK0123");

        assert_eq!(by_title(&r, "Router").password, "router-pw");
        assert!(r.warnings.iter().any(|w| w.contains("archived")));
        assert!(r.warnings.iter().any(|w| w.contains("passkey")));
        assert!(r.warnings.iter().any(|w| w.contains("Secure Notes")));
    }

    #[test]
    fn reads_browser_and_password_manager_csvs() {
        let chrome =
            "name,url,username,password,note\ngithub.com,https://github.com/login,alice,pw1,\n,https://www.example.com/,bob,pw2,hi\n";
        let r = parse(chrome.as_bytes(), 0).unwrap();
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.items[1].item.title, "example.com");
        assert_eq!(r.items[1].item.notes, "hi");

        let firefox = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\"\n\"https://a.example\",\"al\",\"pw\",,\"\",\"{1}\"\n";
        let r = parse(firefox.as_bytes(), 0).unwrap();
        assert_eq!((r.source, r.items[0].item.username.as_str()), ("Firefox", "al"));

        let safari = "Title,URL,Username,Password,Notes,OTPAuth\nBank,https://bank.example,me,pw,\"multi\nline\",otpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP\n";
        let r = parse(safari.as_bytes(), 0).unwrap();
        assert_eq!(r.source, "Safari");
        assert!(r.items[0].item.totp.is_some());
        assert_eq!(r.items[0].item.notes, "multi\nline");

        let bitwarden = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                         ,1,login,Mail,,,0,\"https://mail.example,https://webmail.example\",me,pw,JBSWY3DPEHPK3PXP\n\
                         ,,note,Wifi,the code is 42,,0,,,,\n\
                         ,,card,Visa,,,0,,,,\n";
        let r = parse(bitwarden.as_bytes(), 0).unwrap();
        assert_eq!(r.source, "Bitwarden");
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.items[0].item.urls.len(), 2);
        assert!(r.items[0].item.favorite && r.items[0].item.totp.is_some());
        assert_eq!(r.items[1].item.category, Category::SecureNote);
        assert!(r.warnings.iter().any(|w| w.contains("left out")));

        let one_password = "\u{feff}Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nA,https://a.example,u,p,,false,false,\"x,y\",\nB,https://b.example,u,p,,false,true,,\n";
        let r = parse(one_password.as_bytes(), 0).unwrap();
        assert_eq!((r.source, r.items.len()), ("1Password", 1));
        assert_eq!(r.items[0].item.tags, ["x", "y"]);
    }

    #[test]
    fn unknown_files_are_refused_with_a_clear_message() {
        assert!(matches!(parse(b"a,b,c\n1,2,3\n", 0), Err(Error::Import(_))));
        assert!(matches!(parse(b"PK\x03\x04garbage", 0), Err(Error::Import(_))));
        assert!(matches!(parse(&[0xff, 0xfe, 0x00], 0), Err(Error::Import(_))));
    }
}
