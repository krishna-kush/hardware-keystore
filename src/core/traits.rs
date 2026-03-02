use crate::core::error::DeviceKeyStoreError;
use crate::core::error::Result;
use crate::core::model::{
    ANDROID_KEY_ATTESTATION_FORMAT_V1, APPLE_SECURE_ENCLAVE_ATTESTATION_FORMAT_V1, BackendKind,
    HardwareProtection, KEY_ATTESTATION_VERSION_V1, KeyAlgorithm, KeyAttestationDescriptor,
    TPM2_KEY_ATTESTATION_FORMAT_V1, WINDOWS_PCP_ATTESTATION_FORMAT_V1,
};

/// Hardware-backed device keystore abstraction.
///
/// Implementations must avoid exporting private key material.
pub trait DeviceKeyStore: Send + Sync {
    /// Backend-specific setup hook.
    fn initialize(&self) -> Result<()> {
        Ok(())
    }

    fn backend_kind(&self) -> BackendKind;
    fn hardware_protection(&self) -> HardwareProtection;
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::EcP256Sha256
    }

    /// Create or reuse a non-exportable hardware key bound to `key_id`.
    fn ensure_signing_key(&self, key_id: &str) -> Result<()>;

    /// Return the public key (DER/SubjectPublicKeyInfo when available).
    fn public_key_der(&self, key_id: &str) -> Result<Vec<u8>>;

    /// Sign `payload` with the hardware key.
    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>>;

    /// Delete signing key material bound to `key_id` from backend keystore.
    fn delete_signing_key(&self, _key_id: &str) -> Result<()> {
        Err(DeviceKeyStoreError::Unsupported(
            "delete_signing_key not implemented for this backend",
        ))
    }

    /// Probe whether hardware security is actually usable on this device/runtime.
    fn is_hardware_security_available(&self) -> Result<bool>;

    /// Descriptor for backend-specific key attestation evidence.
    fn attestation_descriptor(&self) -> Result<Option<KeyAttestationDescriptor>> {
        let descriptor = match self.backend_kind() {
            BackendKind::AndroidHardwareKeystore => Some(KeyAttestationDescriptor {
                format: ANDROID_KEY_ATTESTATION_FORMAT_V1.to_string(),
                version: KEY_ATTESTATION_VERSION_V1,
            }),
            BackendKind::AppleSecureEnclave => Some(KeyAttestationDescriptor {
                format: APPLE_SECURE_ENCLAVE_ATTESTATION_FORMAT_V1.to_string(),
                version: KEY_ATTESTATION_VERSION_V1,
            }),
            BackendKind::Tpm2 => Some(KeyAttestationDescriptor {
                format: TPM2_KEY_ATTESTATION_FORMAT_V1.to_string(),
                version: KEY_ATTESTATION_VERSION_V1,
            }),
            BackendKind::WindowsPlatformCryptoProvider => Some(KeyAttestationDescriptor {
                format: WINDOWS_PCP_ATTESTATION_FORMAT_V1.to_string(),
                version: KEY_ATTESTATION_VERSION_V1,
            }),
        };
        Ok(descriptor)
    }

    /// Optional hardware attestation evidence.
    fn attestation(&self, _key_id: &str, _challenge: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}
