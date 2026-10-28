//! Reading other password managers' exports: 1Password's `.1pux`, KeePass
//! databases (`.kdbx`), and the CSV files of 1Password, Chrome/Edge/Brave,
//! Firefox, Safari/Apple Passwords and Bitwarden. Parsing only builds items;
//! the caller decides what to save.

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

// ---------- KeePass (.kdbx) ----------

/// The error [`parse_kdbx`] returns for a wrong password or key file.
pub const KDBX_WRONG_KEY: &str = "kdbx-wrong-key";

/// Whether the file is a KeePass database, which needs its password to read.
pub fn is_kdbx(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x03, 0xd9, 0xa2, 0x9a])
}

/// Read a KeePass 2 or KeePassXC database (KDBX 3.1 or 4) with its password
/// and, if it has one, its key file. Groups become tags, and entries in the
/// recycle bin are left out. KeePassXC's passkeys come along.
pub fn parse_kdbx(bytes: &[u8], password: &str, key_file: Option<&[u8]>, now_ms: i64) -> Result<ImportResult> {
    use keepass::db::{DatabaseOpenError, fields};

    let mut key = keepass::DatabaseKey::new();
    if !password.is_empty() {
        key = key.with_password(password);
    }
    if let Some(mut file) = key_file {
        key = key.with_keyfile(&mut file).map_err(|_| Error::Import("The key file can't be read.".into()))?;
    }
    let db = keepass::Database::parse(bytes, key).map_err(|e| match e {
        DatabaseOpenError::Key(_) => Error::Import(KDBX_WRONG_KEY.into()),
        DatabaseOpenError::UnsupportedVersion => {
            Error::Import("This is a KeePass 1 database. Open it in KeePassXC, save it as KDBX 4, then import that.".into())
        }
        e => Error::Import(format!("This KeePass database can't be read ({e}).")),
    })?;

    let ms = |t: Option<chrono::NaiveDateTime>| t.map(|t| t.and_utc().timestamp_millis());
    let recycle_bin = db.recycle_bin().map(|g| g.id());
    let templates = db.meta.entry_templates_group;

    let mut items = Vec::new();
    let (mut binned, mut bad_totp, mut bad_passkeys) = (0, 0, 0);
    let mut groups = vec![(db.root().id(), String::new())];
    while let Some((group_id, path)) = groups.pop() {
        let Some(group) = db.group(group_id) else { continue };
        for child_id in group.group_ids() {
            let Some(child) = db.group(child_id) else { continue };
            if Some(child_id) == recycle_bin || Some(child_id.uuid()) == templates {
                binned += if Some(child_id) == recycle_bin { count_kdbx_entries(&db, child_id) } else { 0 };
                continue;
            }
            groups.push((child_id, if path.is_empty() { child.name.clone() } else { format!("{path}/{}", child.name) }));
        }

        for entry_id in group.entry_ids() {
            let Some(entry) = db.entry(entry_id) else { continue };
            let get = |k: &str| entry.get(k).unwrap_or("").trim().to_string();
            let mut item = Item::new(get(fields::TITLE), now_ms);
            item.username = get(fields::USERNAME);
            item.password = entry.get(fields::PASSWORD).unwrap_or("").to_string();
            item.notes = entry.get(fields::NOTES).unwrap_or("").trim_end().to_string();
            item.urls = Some(get(fields::URL)).into_iter().filter(|u| !u.is_empty()).collect();
            item.tags = entry.tags.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
            if !path.is_empty() && !item.tags.contains(&path) {
                item.tags.push(path.clone());
            }
            item.created_at = ms(entry.times.creation).unwrap_or(now_ms);
            item.updated_at = ms(entry.times.last_modification).unwrap_or(item.created_at);

            let mut names: Vec<&String> = entry.fields.keys().collect();
            names.sort();
            let mut passkey: HashMap<&str, String> = HashMap::new();
            for name in names {
                let value = &entry.fields[name];
                let text = value.get().trim().to_string();
                if fields::KNOWN_FIELDS.contains(&name.as_str()) || text.is_empty() {
                    continue;
                }
                if let Some(part) = name.strip_prefix("KPEX_PASSKEY_") {
                    passkey.insert(part, text);
                    continue;
                }
                if name.starts_with("TimeOtp-") && name != "TimeOtp-Secret-Base32" {
                    continue; // read with the secret below
                }
                let otp = match name.as_str() {
                    "otp" => Some(text.clone()),
                    "TimeOtp-Secret-Base32" => Some(kdbx_otpauth(&text, &entry)),
                    _ => None,
                };
                if let Some(otp) = &otp {
                    match Totp::parse(otp) {
                        Ok(t) if item.totp.is_none() => {
                            item.totp = Some(t);
                            continue;
                        }
                        Ok(_) => {}
                        Err(_) => bad_totp += 1,
                    }
                }
                if name.starts_with("KP2A_URL") || name.eq_ignore_ascii_case("url") {
                    item.urls.push(text);
                    continue;
                }
                let kind = match () {
                    _ if value.is_protected() || otp.is_some() => FieldKind::Concealed,
                    _ if text.contains('\n') => FieldKind::Multiline,
                    _ => FieldKind::Text,
                };
                let id = format!("kp_{}", name.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect::<String>());
                push_field(&mut item, id, name.clone(), kind, text);
            }
            if !passkey.is_empty() {
                match kdbx_passkey(&passkey, &item) {
                    Some(p) => item.passkeys.push(p),
                    None => bad_passkeys += 1,
                }
                for value in passkey.values_mut() {
                    value.zeroize();
                }
            }

            // KeePass keeps whole earlier versions; walk them newest first.
            if let Some(history) = &entry.history {
                let mut versions: Vec<&keepass::db::Entry> = history.get_entries().iter().collect();
                versions.sort_by_key(|v| std::cmp::Reverse(v.times.last_modification));
                let (mut later, mut later_at) = (item.password.clone(), item.updated_at);
                for version in versions {
                    let password = version.get(fields::PASSWORD).unwrap_or("");
                    if !password.is_empty() && password != later {
                        item.password_history.push(PasswordChange { password: password.to_string(), changed_at: later_at });
                    }
                    later.zeroize();
                    later = password.to_string();
                    later_at = ms(version.times.last_modification).unwrap_or(later_at);
                }
                later.zeroize();
                item.password_history.truncate(20);
            }

            let files: Vec<ImportedFile> = entry
                .attachments_named()
                .map(|(name, attachment)| ImportedFile { name: name.to_string(), contents: attachment.data.get().clone() })
                .collect();

            let is_login = !item.username.is_empty() || !item.password.is_empty() || !item.urls.is_empty() || !item.passkeys.is_empty();
            if !is_login && item.notes.is_empty() && item.fields.is_empty() && files.is_empty() && item.totp.is_none() {
                continue;
            }
            if !is_login {
                item.category = Category::SecureNote;
            }
            if item.title.is_empty() {
                item.title = item.urls.first().map(|u| host_of(u)).unwrap_or_else(|| "Untitled".into());
            }
            items.push(Imported { item, files });
        }
    }

    let mut warnings = Vec::new();
    if binned > 0 {
        warnings.push(format!("{binned} item{} in the recycle bin left out.", plural(binned)));
    }
    if bad_totp > 0 {
        warnings.push(format!("{bad_totp} one-time password setting{} couldn't be read and were kept as fields.", plural(bad_totp)));
    }
    if bad_passkeys > 0 {
        warnings.push(format!(
            "{bad_passkeys} passkey{} couldn't be read. Their logins are imported; add the passkeys again on those sites.",
            plural(bad_passkeys)
        ));
    }
    Ok(ImportResult { source: "KeePass", items, warnings })
}

fn count_kdbx_entries(db: &keepass::Database, group: keepass::db::GroupId) -> usize {
    db.group(group).map_or(0, |g| g.entry_ids().count() + g.group_ids().map(|child| count_kdbx_entries(db, child)).sum::<usize>())
}

/// KeePass 2.47+ keeps TOTP settings in separate `TimeOtp-*` fields.
fn kdbx_otpauth(secret: &str, entry: &keepass::db::Entry) -> String {
    let mut uri = format!("otpauth://totp/?secret={}", secret.replace(' ', ""));
    for (field, param) in [("TimeOtp-Period", "period"), ("TimeOtp-Length", "digits"), ("TimeOtp-Algorithm", "algorithm")] {
        if let Some(v) = entry.get(field).map(str::trim).filter(|v| !v.is_empty()) {
            // KeePass writes the algorithm as "HMAC-SHA-256".
            uri.push_str(&format!("&{param}={}", v.replace("HMAC-", "").replace('-', "")));
        }
    }
    uri
}

/// A KeePassXC passkey, from its `KPEX_PASSKEY_*` fields.
fn kdbx_passkey(fields: &HashMap<&str, String>, item: &Item) -> Option<crate::passkey::Passkey> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    // KeePassXC writes IDs as base64url; be lenient about padding and alphabet.
    let b64url = |s: &str| URL_SAFE_NO_PAD.decode(s.trim().trim_end_matches('=').replace('+', "-").replace('/', "_")).ok();
    let pem = fields.get("PRIVATE_KEY_PEM")?;
    let der: String = pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect();
    let private_key = STANDARD.decode(der).ok()?;
    crate::passkey::Passkey::imported(
        b64url(fields.get("CREDENTIAL_ID")?)?,
        fields.get("RELYING_PARTY")?.clone(),
        fields.get("USER_HANDLE").and_then(|h| b64url(h)).unwrap_or_default(),
        fields.get("USERNAME").cloned().unwrap_or_else(|| item.username.clone()),
        private_key,
        item.created_at,
    )
    .ok()
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

    fn at(secs: i64) -> Option<chrono::NaiveDateTime> {
        chrono::DateTime::from_timestamp(secs, 0).map(|t| t.naive_utc())
    }

    /// A small KeePassXC-style database, saved as a real KDBX 4 file.
    fn kdbx(password: &str) -> Vec<u8> {
        use keepass::config::KdfConfig;
        use keepass::db::{History, Value as KpValue};
        use p256::pkcs8::EncodePrivateKey;

        let mut db = keepass::Database::new();
        db.config.kdf_config = KdfConfig::Aes { rounds: 10 }; // fast, for tests
        let bin = {
            let mut root = db.root_mut();
            let mut bin = root.add_group();
            bin.name = "Recycle Bin".into();
            bin.add_entry().set_unprotected("Title", "Deleted");
            bin.id()
        };
        db.meta.recyclebin_uuid = Some(bin.uuid());

        let mut root = db.root_mut();
        let mut banking = root.add_group();
        banking.name = "Banking".into();
        let mut bank = banking.add_entry();
        bank.set_unprotected("Title", "Bank");
        bank.set_unprotected("UserName", "me");
        bank.set_protected("Password", "oldest");
        bank.times.last_modification = at(1_000);
        let mut history = History::default();
        history.add_entry((*bank).clone());
        bank.set_protected("Password", "old");
        bank.times.last_modification = at(2_000);
        history.add_entry((*bank).clone());
        bank.set_protected("Password", "current");
        bank.times.last_modification = at(3_000);
        bank.history = Some(history);
        bank.set_unprotected("URL", "https://bank.example");
        bank.set_unprotected("KP2A_URL_1", "https://app.bank.example");
        bank.set_protected("otp", "otpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP");
        bank.set_protected("PIN", "1234");
        bank.set_unprotected("Branch", "Main street");
        bank.tags = vec!["money".into()];
        bank.add_attachment("statement.pdf", KpValue::unprotected(b"%PDF".to_vec()));

        let mut site = root.add_entry();
        site.set_unprotected("Title", "Passkey site");
        site.set_unprotected("UserName", "alice");
        site.set_unprotected("URL", "https://passkey.example");
        let der = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng).to_pkcs8_der().unwrap();
        use base64::Engine;
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", base64::engine::general_purpose::STANDARD.encode(der.as_bytes()));
        site.set_protected("KPEX_PASSKEY_PRIVATE_KEY_PEM", pem);
        site.set_protected("KPEX_PASSKEY_CREDENTIAL_ID", "AQIDBA");
        site.set_protected("KPEX_PASSKEY_USER_HANDLE", "dXNlcg");
        site.set_unprotected("KPEX_PASSKEY_RELYING_PARTY", "passkey.example");
        site.set_unprotected("KPEX_PASSKEY_USERNAME", "alice");

        let mut note = root.add_entry();
        note.set_unprotected("Title", "Wifi");
        note.set_unprotected("Notes", "the code is 42");
        note.set_protected("Password", "");

        let mut legacy = root.add_entry();
        legacy.set_unprotected("Title", "KeePass 2 TOTP");
        legacy.set_unprotected("UserName", "bob");
        legacy.set_protected("TimeOtp-Secret-Base32", "JBSW Y3DP EHPK 3PXP");
        legacy.set_unprotected("TimeOtp-Algorithm", "HMAC-SHA-256");
        legacy.set_unprotected("TimeOtp-Length", "8");

        let mut out = Vec::new();
        db.save(&mut out, keepass::DatabaseKey::new().with_password(password)).unwrap();
        out
    }

    #[test]
    fn imports_a_keepass_database() {
        let bytes = kdbx("hunter2-but-longer");
        assert!(is_kdbx(&bytes) && !is_kdbx(b"PK\x03\x04"));
        let wrong = parse_kdbx(&bytes, "nope", None, 0).err().unwrap();
        assert_eq!(wrong.to_string(), KDBX_WRONG_KEY);

        let r = parse_kdbx(&bytes, "hunter2-but-longer", None, 0).unwrap();
        assert_eq!(r.source, "KeePass");
        let find = |t: &str| r.items.iter().find(|i| i.item.title == t).unwrap_or_else(|| panic!("no {t}"));
        assert!(r.items.iter().all(|i| i.item.title != "Deleted"));
        assert!(r.warnings.iter().any(|w| w.contains("1 item in the recycle bin")), "{:?}", r.warnings);

        let bank = find("Bank");
        let b = &bank.item;
        assert_eq!((b.category, b.username.as_str(), b.password.as_str()), (Category::Login, "me", "current"));
        assert_eq!(b.urls, ["https://bank.example", "https://app.bank.example"]);
        assert!(b.totp.is_some());
        assert_eq!(b.tags, ["money", "Banking"]);
        let history: Vec<(&str, i64)> = b.password_history.iter().map(|h| (h.password.as_str(), h.changed_at)).collect();
        assert_eq!(history, [("old", 3_000_000), ("oldest", 2_000_000)]);
        assert_eq!(b.updated_at, 3_000_000);
        let field = |id: &str| b.fields.iter().find(|f| f.id == id).map(|f| (f.kind, f.value.as_str()));
        assert_eq!(field("kp_PIN"), Some((FieldKind::Concealed, "1234")));
        assert_eq!(field("kp_Branch"), Some((FieldKind::Text, "Main street")));
        assert_eq!(bank.files.len(), 1);
        assert_eq!((bank.files[0].name.as_str(), bank.files[0].contents.as_slice()), ("statement.pdf", b"%PDF".as_slice()));

        let site = &find("Passkey site").item;
        assert_eq!(site.passkeys.len(), 1);
        let p = &site.passkeys[0];
        assert_eq!((p.rp_id.as_str(), p.credential_id.as_slice(), p.user_handle.as_slice()), ("passkey.example", [1, 2, 3, 4].as_slice(), b"user".as_slice()));
        assert!(site.fields.is_empty(), "passkey fields shouldn't show as fields");

        assert_eq!(find("Wifi").item.category, Category::SecureNote);

        let legacy = &find("KeePass 2 TOTP").item;
        let totp = legacy.totp.as_ref().expect("TimeOtp fields read");
        assert_eq!(totp.code_at(0).unwrap().len(), 8);
        assert!(legacy.fields.is_empty());
    }

    #[test]
    fn unknown_files_are_refused_with_a_clear_message() {
        assert!(matches!(parse(b"a,b,c\n1,2,3\n", 0), Err(Error::Import(_))));
        assert!(matches!(parse(b"PK\x03\x04garbage", 0), Err(Error::Import(_))));
        assert!(matches!(parse(&[0xff, 0xfe, 0x00], 0), Err(Error::Import(_))));
    }
}
