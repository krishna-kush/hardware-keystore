use crate::config;
use crate::core::error::{DeviceKeyStoreError, Result};
use sha2::{Digest as Sha2Digest, Sha256};

#[macro_export]
macro_rules! first_present_source {
    ($($source:expr => $expr:expr),+ $(,)?) => {{
        let mut selected = None;
        $(
            if selected.is_none() {
                if let Some(value) = $expr {
                    selected = Some(($source.to_string(), value));
                }
            }
        )+
        selected
    }};
}

pub fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty() {
        return Err(DeviceKeyStoreError::InvalidInput("empty key_id"));
    }
    Ok(())
}

pub fn validate_payload(payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Err(DeviceKeyStoreError::InvalidInput("empty payload"));
    }
    Ok(())
}

pub fn key_label(key_id: &str) -> String {
    config::key_label_for(key_id)
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn stable_u32_slot(label: &str, span: u32) -> u32 {
    let hash = Sha256::digest(label.as_bytes());
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % (span + 1)
}

pub fn backend_error<E: std::fmt::Display>(context: &'static str, err: E) -> DeviceKeyStoreError {
    DeviceKeyStoreError::Backend(format!("{context}: {err}"))
}
