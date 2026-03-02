use std::error::Error;
use std::fmt::{Display, Formatter};

pub type Result<T> = std::result::Result<T, DeviceKeyStoreError>;

#[derive(Debug)]
pub enum DeviceKeyStoreError {
    InvalidInput(&'static str),
    InvalidConfig(&'static str),
    KeyNotFound(String),
    Backend(String),
    Unsupported(&'static str),
    AttestationUnavailable,
}

impl Display for DeviceKeyStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Self::KeyNotFound(key_id) => write!(f, "key not found for key_id '{key_id}'"),
            Self::Backend(msg) => write!(f, "backend error: {msg}"),
            Self::Unsupported(msg) => write!(f, "unsupported: {msg}"),
            Self::AttestationUnavailable => write!(f, "attestation unavailable in this backend"),
        }
    }
}

impl Error for DeviceKeyStoreError {}
