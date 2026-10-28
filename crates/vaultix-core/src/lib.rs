//! Vaultix core: everything security-relevant lives here, so the desktop UI
//! and the browser extension stay thin and never handle raw key material.

pub mod crypto;
pub mod error;
pub mod generator;
pub mod hlc;
pub mod import;
pub mod item;
pub mod origin;
pub mod passkey;
pub mod strength;
pub mod totp;
pub mod vault;
pub mod watchtower;

pub use error::{Error, Result};
pub use item::{Category, Field, FieldKind, FileRef, Item, PasswordChange};
pub use passkey::Passkey;
pub use totp::Totp;
pub use vault::{BackupChange, SyncReport, Vault};
