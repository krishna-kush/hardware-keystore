mod codec;
mod config;
mod core;
mod platforms;
mod service;

pub use config::HardwareKeystoreConfig;
pub use core::error::{DeviceKeyStoreError, Result};
pub use core::model::{
    ANDROID_KEY_ATTESTATION_FORMAT_V1, APPLE_SECURE_ENCLAVE_ATTESTATION_FORMAT_V1, BackendKind,
    HardwareProtection, HardwareSecurityStatus, KEY_ATTESTATION_VERSION_V1, KeyAlgorithm,
    KeyAttestationDescriptor, TPM2_KEY_ATTESTATION_FORMAT_V1, WINDOWS_PCP_ATTESTATION_FORMAT_V1,
};
pub use core::traits::DeviceKeyStore;

#[cfg(target_os = "android")]
use platforms::android::AndroidHardwareKeyStore;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use platforms::apple::AppleSecureEnclaveKeyStore;
#[cfg(target_os = "linux")]
use platforms::linux::Tpm2KeyStore;
#[cfg(target_os = "windows")]
use platforms::windows::WindowsPlatformCryptoProviderKeyStore;

/// Create platform-default hardware keystore.
pub fn new_default() -> Box<dyn DeviceKeyStore> {
    #[cfg(target_os = "android")]
    {
        return Box::new(AndroidHardwareKeyStore::new());
    }

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        return Box::new(AppleSecureEnclaveKeyStore::new());
    }

    #[cfg(target_os = "linux")]
    {
        return Box::new(Tpm2KeyStore::new());
    }

    #[cfg(target_os = "windows")]
    {
        return Box::new(WindowsPlatformCryptoProviderKeyStore::new());
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    )))]
    panic!("Unsupported target for hardware-keystore");
}

/// Initialize library-level configuration.
///
/// Call this once near app startup before using `new_default()`.
pub fn init(config: HardwareKeystoreConfig) -> Result<()> {
    config::init(config.clone())?;
    if config.probe_hardware_on_init {
        let keystore = new_default();
        keystore.initialize()?;
        let _ = keystore.is_hardware_security_available()?;
    }
    Ok(())
}

/// Probe hardware security status for the current platform backend.
pub fn hardware_security_status() -> Result<HardwareSecurityStatus> {
    let keystore = new_default();
    keystore.initialize()?;
    let available = keystore.is_hardware_security_available()?;
    Ok(if available {
        HardwareSecurityStatus::Available
    } else {
        HardwareSecurityStatus::Unavailable
    })
}

/// Convenience boolean probe for hardware security availability.
pub fn is_hardware_security_available() -> Result<bool> {
    Ok(matches!(
        hardware_security_status()?,
        HardwareSecurityStatus::Available
    ))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub fn set_apple_managed_attestation_chain(chain_der_b64: Option<Vec<String>>) -> Result<()> {
    platforms::apple::set_managed_attestation_chain_override(chain_der_b64);
    Ok(())
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
pub fn set_apple_managed_attestation_chain(_chain_der_b64: Option<Vec<String>>) -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub fn set_apple_managed_attestation_identity_label(label: Option<String>) -> Result<()> {
    platforms::apple::set_managed_attestation_identity_label_override(label);
    Ok(())
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
pub fn set_apple_managed_attestation_identity_label(_label: Option<String>) -> Result<()> {
    Ok(())
}
