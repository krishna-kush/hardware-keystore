use serde::{Deserialize, Serialize};

pub const ANDROID_KEY_ATTESTATION_FORMAT_V1: &str = "android_key_attestation_v1";
pub const APPLE_SECURE_ENCLAVE_ATTESTATION_FORMAT_V1: &str = "apple_secure_enclave_attestation_v1";
pub const TPM2_KEY_ATTESTATION_FORMAT_V1: &str = "tpm2_key_attestation_v1";
pub const WINDOWS_PCP_ATTESTATION_FORMAT_V1: &str = "windows_pcp_attestation_v1";
pub const KEY_ATTESTATION_VERSION_V1: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    EcP256Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    AppleSecureEnclave,
    AndroidHardwareKeystore,
    Tpm2,
    WindowsPlatformCryptoProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareProtection {
    HardwareBacked,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareSecurityStatus {
    Available,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyAttestationDescriptor {
    pub format: String,
    pub version: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidKeyAttestationEvidenceV1 {
    pub version: u16,
    pub public_key_der_b64: String,
    pub certificate_chain_der_b64: Vec<String>,
    pub challenge_signature_der_b64: String,
    pub hardware_backed: bool,
    pub strongbox_backed: Option<bool>,
    pub key_security_level: Option<String>,
    pub attestation_security_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppleSecureEnclaveAttestationEvidenceV1 {
    pub version: u16,
    pub public_key_der_b64: String,
    pub challenge_signature_der_b64: String,
    pub hardware_backed: bool,
    pub secure_enclave_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_attestation_chain_der_b64: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_attestation_chain_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tpm2KeyAttestationEvidenceV1 {
    pub version: u16,
    pub public_key_der_b64: String,
    pub challenge_signature_der_b64: String,
    pub tpm_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_digest_sha256_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certified_attest_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certified_signature_der_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_public_key_der_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_key_name_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_key_name_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ek_certificate_der_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ek_certificate_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsPcpKeyAttestationEvidenceV1 {
    pub version: u16,
    pub public_key_der_b64: String,
    pub challenge_signature_der_b64: String,
    pub provider: String,
    pub pcp_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_digest_sha256_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_attestation_blob_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ek_certificate_der_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ek_certificate_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intermediate_ca_ek_certificate_der_b64: Option<String>,
}
