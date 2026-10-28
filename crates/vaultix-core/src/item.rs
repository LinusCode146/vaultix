use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::origin::login_matches_page;
use crate::passkey::Passkey;
use crate::totp::Totp;

/// What kind of thing an item is. Logins use the dedicated username,
/// password, URL, TOTP and passkey fields; the other categories keep their
/// details in [`Item::fields`] (the UI decides which fields each one has).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Category {
    #[default]
    Login,
    SecureNote,
    CreditCard,
    Identity,
    ApiCredential,
    Document,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldKind {
    Text,
    /// Hidden until revealed: card numbers, CVVs, PINs, API secrets.
    Concealed,
    Email,
    Phone,
    Url,
    /// `YYYY-MM-DD`.
    Date,
    /// `MM/YYYY`, for card expiry.
    MonthYear,
    Multiline,
}

/// One labelled value of a non-login item, e.g. a card's expiry date.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    /// Stable within a category ("number", "expiry"), so data survives label changes.
    pub id: String,
    pub label: String,
    pub kind: FieldKind,
    pub value: String,
}

impl Drop for Field {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// A file stored encrypted in the vault folder (see [`crate::Vault::add_file`]).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileRef {
    pub id: Uuid,
    pub name: String,
    pub size: u64,
}

/// A password the item had before, kept so a change that didn't stick on the
/// website can be undone.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PasswordChange {
    pub password: String,
    /// Unix milliseconds: when it stopped being the item's password.
    pub changed_at: i64,
}

impl Drop for PasswordChange {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// How many previous passwords an item keeps.
pub const PASSWORD_HISTORY_LEN: usize = 20;

/// One vault entry. A login can carry a password, a TOTP secret and any number
/// of passkeys, the way 1Password groups them. New fields must be
/// `#[serde(default)]` so older log entries still deserialize.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    #[serde(default)]
    pub category: Category,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub totp: Option<Totp>,
    #[serde(default)]
    pub passkeys: Vec<Passkey>,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub files: Vec<FileRef>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    /// Previous passwords, newest first. Kept up to date by [`crate::Vault::put`].
    #[serde(default)]
    pub password_history: Vec<PasswordChange>,
    /// Unix milliseconds.
    pub created_at: i64,
    pub updated_at: i64,
}

impl Item {
    pub fn new(title: impl Into<String>, now_ms: i64) -> Self {
        Item {
            id: Uuid::new_v4(),
            category: Category::Login,
            title: title.into(),
            username: String::new(),
            password: String::new(),
            urls: Vec::new(),
            notes: String::new(),
            totp: None,
            passkeys: Vec::new(),
            fields: Vec::new(),
            files: Vec::new(),
            tags: Vec::new(),
            favorite: false,
            password_history: Vec::new(),
            created_at: now_ms,
            updated_at: now_ms,
        }
    }

    pub fn with_category(mut self, category: Category) -> Self {
        self.category = category;
        self
    }

    /// Whether autofill should offer this item on `page_url`.
    pub fn matches_page(&self, page_url: &str) -> bool {
        self.category == Category::Login && self.urls.iter().any(|u| login_matches_page(u, page_url))
    }

    /// Record `previous` as an old password if this item's password differs
    /// from it. Called with the password the item had before an edit.
    pub fn remember_password(&mut self, previous: &str, at_ms: i64) {
        if previous.is_empty() || previous == self.password {
            return;
        }
        self.password_history.retain(|c| c.password != previous && c.password != self.password);
        self.password_history.insert(0, PasswordChange { password: previous.to_string(), changed_at: at_ms });
        self.password_history.truncate(PASSWORD_HISTORY_LEN);
    }

    pub fn field(&self, id: &str) -> Option<&str> {
        self.fields.iter().find(|f| f.id == id).map(|f| f.value.as_str()).filter(|v| !v.is_empty())
    }
}

impl Drop for Item {
    fn drop(&mut self) {
        self.password.zeroize();
        self.notes.zeroize();
    }
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("category", &self.category)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("urls", &self.urls)
            .field("passkeys", &self.passkeys)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_secrets() {
        let mut item = Item::new("Bank", 0);
        item.password = "hunter2".into();
        item.notes = "PIN 1234".into();
        item.fields.push(Field { id: "cvv".into(), label: "CVV".into(), kind: FieldKind::Concealed, value: "987".into() });
        let s = format!("{item:?}");
        assert!(!s.contains("hunter2") && !s.contains("1234") && !s.contains("987"));
    }

    #[test]
    fn old_entries_without_new_fields_deserialize() {
        let id = Uuid::new_v4();
        let json = format!(r#"{{"id":"{id}","title":"x","created_at":1,"updated_at":2}}"#);
        let item: Item = serde_json::from_str(&json).unwrap();
        assert_eq!(item.title, "x");
        assert!(item.passkeys.is_empty());
        assert_eq!(item.category, Category::Login);
    }

    #[test]
    fn previous_passwords_are_kept_newest_first() {
        let mut item = Item::new("Bank", 0);
        item.password = "two".into();
        item.remember_password("one", 1);
        item.password = "three".into();
        item.remember_password("two", 2);
        let old: Vec<&str> = item.password_history.iter().map(|c| c.password.as_str()).collect();
        assert_eq!(old, ["two", "one"]);

        // Unchanged or previously empty: nothing to remember.
        item.remember_password("three", 3);
        item.remember_password("", 3);
        assert_eq!(item.password_history.len(), 2);

        // Going back to an old password takes it out of the history.
        item.password = "one".into();
        item.remember_password("three", 4);
        let old: Vec<&str> = item.password_history.iter().map(|c| c.password.as_str()).collect();
        assert_eq!(old, ["three", "two"]);

        for i in 0..30 {
            let previous = std::mem::replace(&mut item.password, format!("p{i}"));
            item.remember_password(&previous, 10 + i);
        }
        assert_eq!(item.password_history.len(), PASSWORD_HISTORY_LEN);
        assert_eq!(item.password_history[0].password, "p28");
    }

    #[test]
    fn only_logins_match_pages() {
        let mut login = Item::new("Shop", 0);
        login.urls = vec!["https://shop.example".into()];
        assert!(login.matches_page("https://shop.example/login"));
        let card = login.clone().with_category(Category::CreditCard);
        assert!(!card.matches_page("https://shop.example/login"));
    }
}
