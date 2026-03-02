use std::sync::OnceLock;

use crate::core::error::{DeviceKeyStoreError, Result};

#[derive(Debug, Clone)]
pub struct HardwareKeystoreConfig {
    pub key_label_prefix: String,
    pub probe_hardware_on_init: bool,
}

impl Default for HardwareKeystoreConfig {
    fn default() -> Self {
        Self {
            key_label_prefix: "device.signing".to_string(),
            probe_hardware_on_init: false,
        }
    }
}

static CONFIG: OnceLock<HardwareKeystoreConfig> = OnceLock::new();

pub fn init(config: HardwareKeystoreConfig) -> Result<()> {
    if config.key_label_prefix.trim().is_empty() {
        return Err(DeviceKeyStoreError::InvalidConfig(
            "key_label_prefix cannot be empty",
        ));
    }

    let _ = CONFIG.get_or_init(|| config);
    Ok(())
}

pub fn get() -> &'static HardwareKeystoreConfig {
    CONFIG.get_or_init(HardwareKeystoreConfig::default)
}

fn sanitize_key_id(key_id: &str) -> String {
    key_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub fn key_label_for(key_id: &str) -> String {
    format!("{}.{}", get().key_label_prefix, sanitize_key_id(key_id))
}
