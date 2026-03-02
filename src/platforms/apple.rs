use crate::config;
use crate::core::error::{DeviceKeyStoreError, Result};
use crate::core::model::{
    AppleSecureEnclaveAttestationEvidenceV1, BackendKind, HardwareProtection,
    KEY_ATTESTATION_VERSION_V1,
};
use crate::core::traits::DeviceKeyStore;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use security_framework::identity::SecIdentity;
use security_framework::item::{ItemClass, ItemSearchOptions, Location, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework::policy::SecPolicy;
use security_framework::trust::SecTrust;
use std::env;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Default)]
pub struct AppleSecureEnclaveKeyStore;

static MANAGED_ATTESTATION_CHAIN_OVERRIDE: OnceLock<Mutex<Option<Vec<String>>>> = OnceLock::new();
static MANAGED_ATTESTATION_IDENTITY_LABEL_OVERRIDE: OnceLock<Mutex<Option<String>>> =
    OnceLock::new();

pub(crate) fn set_managed_attestation_chain_override(chain: Option<Vec<String>>) {
    let lock = MANAGED_ATTESTATION_CHAIN_OVERRIDE.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = lock.lock() {
        *guard = chain;
    }
}

pub(crate) fn set_managed_attestation_identity_label_override(label: Option<String>) {
    let lock = MANAGED_ATTESTATION_IDENTITY_LABEL_OVERRIDE.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = lock.lock() {
        *guard = label.and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
    }
}

impl AppleSecureEnclaveKeyStore {
    pub fn new() -> Self {
        Self
    }

    fn label_for(key_id: &str) -> String {
        config::key_label_for(key_id)
    }

    fn probe_key_id() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("probe_{nanos}")
    }

    fn find_private_key(&self, key_id: &str) -> Result<Option<SecKey>> {
        let label = Self::label_for(key_id);
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::key())
            .label(&label)
            .load_refs(true)
            .limit(1);

        let results = query
            .search()
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        for result in results {
            if let SearchResult::Ref(Reference::Key(key)) = result {
                return Ok(Some(key));
            }
        }

        Ok(None)
    }

    fn managed_attestation_identity_label() -> Option<String> {
        if let Some(lock) = MANAGED_ATTESTATION_IDENTITY_LABEL_OVERRIDE.get()
            && let Ok(guard) = lock.lock()
            && let Some(label) = guard.as_ref()
        {
            return Some(label.clone());
        }

        let raw = env::var("TARF_APPLE_MANAGED_ATTESTATION_IDENTITY_LABEL").ok()?;
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }

    fn find_managed_identity(&self) -> Result<Option<SecIdentity>> {
        let Some(label) = Self::managed_attestation_identity_label() else {
            return Ok(None);
        };

        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::identity())
            .label(&label)
            .load_refs(true)
            .limit(1);

        let results = query
            .search()
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        for result in results {
            if let SearchResult::Ref(Reference::Identity(identity)) = result {
                return Ok(Some(identity));
            }
        }

        Ok(None)
    }

    fn resolve_signing_private_key(&self, key_id: &str) -> Result<SecKey> {
        if let Some(label) = Self::managed_attestation_identity_label() {
            let identity = self.find_managed_identity()?.ok_or_else(|| {
                DeviceKeyStoreError::Backend(format!(
                    "managed attestation identity not found: {}",
                    label
                ))
            })?;
            return identity
                .private_key()
                .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()));
        }

        self.find_private_key(key_id)?
            .ok_or_else(|| DeviceKeyStoreError::KeyNotFound(key_id.to_string()))
    }

    fn managed_attestation_chain_from_identity(identity: &SecIdentity) -> Result<Vec<String>> {
        let leaf = identity
            .certificate()
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        let policy = SecPolicy::create_x509();
        let mut trust = SecTrust::create_with_certificates(&[leaf.clone()], &[policy])
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        // Allow system trust to resolve intermediates from AIA/cached sources.
        let _ = trust.set_network_fetch_allowed(true);
        let _ = trust.evaluate();

        let mut chain_der_b64 = Vec::new();
        #[allow(deprecated)]
        {
            let mut index: isize = 0;
            while let Some(cert) = trust.certificate_at_index(index) {
                chain_der_b64.push(STANDARD.encode(cert.to_der()));
                index += 1;
            }
        }

        if chain_der_b64.is_empty() {
            chain_der_b64.push(STANDARD.encode(leaf.to_der()));
        }

        Ok(chain_der_b64)
    }

    fn managed_attestation_chain_from_identity_if_configured(&self) -> Result<Option<Vec<String>>> {
        if Self::managed_attestation_identity_label().is_none() {
            return Ok(None);
        }

        let identity = self.find_managed_identity()?.ok_or_else(|| {
            DeviceKeyStoreError::Backend(
                "managed attestation identity configured but unavailable".to_string(),
            )
        })?;

        Self::managed_attestation_chain_from_identity(&identity).map(Some)
    }

    fn managed_attestation_chain_and_source(
        &self,
    ) -> Result<(Option<Vec<String>>, Option<String>)> {
        let from_identity = self.managed_attestation_chain_from_identity_if_configured()?;
        let selected = crate::first_present_source!(
            "managed_identity" => from_identity,
            "override_or_env" => Self::managed_attestation_chain_from_env(),
        );
        Ok(match selected {
            Some((source, chain)) => (Some(chain), Some(source)),
            None => (None, None),
        })
    }

    fn managed_attestation_chain_from_env() -> Option<Vec<String>> {
        if let Some(lock) = MANAGED_ATTESTATION_CHAIN_OVERRIDE.get()
            && let Ok(guard) = lock.lock()
            && let Some(chain) = guard.as_ref()
        {
            return Some(chain.clone());
        }

        let raw = env::var("TARF_APPLE_MANAGED_ATTESTATION_CHAIN_DER_B64").ok()?;
        let chain = raw
            .split(',')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(|part| part.to_string())
            .collect::<Vec<_>>();

        if chain.is_empty() { None } else { Some(chain) }
    }
}

impl DeviceKeyStore for AppleSecureEnclaveKeyStore {
    fn initialize(&self) -> Result<()> {
        Ok(())
    }

    fn backend_kind(&self) -> BackendKind {
        BackendKind::AppleSecureEnclave
    }

    fn hardware_protection(&self) -> HardwareProtection {
        HardwareProtection::HardwareBacked
    }

    fn ensure_signing_key(&self, key_id: &str) -> Result<()> {
        if key_id.is_empty() {
            return Err(DeviceKeyStoreError::InvalidInput("empty key_id"));
        }

        if Self::managed_attestation_identity_label().is_some() {
            let _ = self.resolve_signing_private_key(key_id)?;
            return Ok(());
        }

        if self.find_private_key(key_id)?.is_some() {
            return Ok(());
        }

        let label = Self::label_for(key_id);
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_label(label)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain);

        let _ = SecKey::new(&options).map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        Ok(())
    }

    fn public_key_der(&self, key_id: &str) -> Result<Vec<u8>> {
        let private_key = self.resolve_signing_private_key(key_id)?;

        let public_key = private_key.public_key().ok_or_else(|| {
            DeviceKeyStoreError::Backend("failed to derive public key".to_string())
        })?;

        let bytes = public_key.external_representation().ok_or_else(|| {
            DeviceKeyStoreError::Backend("failed to export public key representation".to_string())
        })?;

        Ok(bytes.to_vec())
    }

    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let private_key = self.resolve_signing_private_key(key_id)?;

        private_key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, payload)
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))
    }

    fn delete_signing_key(&self, key_id: &str) -> Result<()> {
        if key_id.is_empty() {
            return Err(DeviceKeyStoreError::InvalidInput("empty key_id"));
        }

        // Managed identities are externally provisioned and must not be deleted by app logic.
        if Self::managed_attestation_identity_label().is_some() {
            return Ok(());
        }

        let private_key = match self.find_private_key(key_id)? {
            Some(key) => key,
            None => return Ok(()),
        };

        private_key
            .delete()
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        Ok(())
    }

    fn is_hardware_security_available(&self) -> Result<bool> {
        if Self::managed_attestation_identity_label().is_some() {
            return Ok(self
                .resolve_signing_private_key("managed-attestation")
                .is_ok());
        }

        let probe_key_id = Self::probe_key_id();
        let label = Self::label_for(&probe_key_id);

        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_label(label)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain);

        match SecKey::new(&options) {
            Ok(key) => {
                let _ = key.delete();
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    fn attestation(&self, key_id: &str, challenge: &[u8]) -> Result<Option<Vec<u8>>> {
        if key_id.is_empty() {
            return Err(DeviceKeyStoreError::InvalidInput("empty key_id"));
        }
        if challenge.is_empty() {
            return Err(DeviceKeyStoreError::InvalidInput("empty challenge"));
        }

        self.ensure_signing_key(key_id)?;
        let public_key_der = self.public_key_der(key_id)?;
        let challenge_signature_der = self.sign(key_id, challenge)?;
        let secure_enclave_available = self.is_hardware_security_available()?;
        let (managed_attestation_chain_der_b64, managed_attestation_chain_source) =
            self.managed_attestation_chain_and_source()?;

        let evidence = AppleSecureEnclaveAttestationEvidenceV1 {
            version: KEY_ATTESTATION_VERSION_V1,
            public_key_der_b64: STANDARD.encode(public_key_der),
            challenge_signature_der_b64: STANDARD.encode(challenge_signature_der),
            hardware_backed: true,
            secure_enclave_available,
            managed_attestation_chain_der_b64,
            managed_attestation_chain_source,
        };

        let encoded = serde_json::to_vec(&evidence)
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        Ok(Some(encoded))
    }
}
