use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("wrong master password")]
    WrongPassword,

    #[error("decryption failed (data corrupted or tampered with)")]
    Decrypt,

    #[error("invalid vault: {0}")]
    InvalidVault(String),

    #[error("invalid TOTP configuration: {0}")]
    InvalidTotp(String),

    #[error("passkey error: {0}")]
    Passkey(String),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("{0}")]
    File(String),

    /// A file to import that can't be read; the message is for the user.
    #[error("{0}")]
    Import(String),
}

pub type Result<T> = std::result::Result<T, Error>;
