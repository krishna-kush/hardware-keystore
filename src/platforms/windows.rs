use crate::codec::der::{ecc_xy_to_spki_der, ecdsa_rs_to_der};
use crate::core::error::{DeviceKeyStoreError, Result};
use crate::core::model::{
    BackendKind, HardwareProtection, KEY_ATTESTATION_VERSION_V1, WindowsPcpKeyAttestationEvidenceV1,
};
use crate::core::traits::DeviceKeyStore;
use crate::service::{backend_error, key_label, sha256, validate_key_id, validate_payload};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::ffi::OsStr;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::Win32::Foundation::{NTE_BAD_KEYSET, NTE_NO_KEY};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_ECDSA_PUBLIC_P256_MAGIC, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_KEY_HANDLE,
    NCRYPT_PCP_ECC_EKCERT_PROPERTY, NCRYPT_PCP_EKCERT_PROPERTY, NCRYPT_PCP_EKNVCERT_PROPERTY,
    NCRYPT_PCP_INTERMEDIATE_CA_EKCERT_PROPERTY, NCRYPT_PCP_KEYATTESTATION_PROPERTY,
    NCRYPT_PCP_RSA_EKCERT_PROPERTY, NCRYPT_PCP_RSA_EKNVCERT_PROPERTY, NCRYPT_PROV_HANDLE,
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSignHash,
};

#[derive(Debug, Default)]
pub struct WindowsPlatformCryptoProviderKeyStore;

impl WindowsPlatformCryptoProviderKeyStore {
    pub fn new() -> Self {
        Self
    }

    fn to_wide_null(input: &str) -> Vec<u16> {
        OsStr::new(input)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn open_provider(&self) -> Result<ProviderHandle> {
        let mut provider: NCRYPT_PROV_HANDLE = 0;
        let status =
            unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
        if status < 0 {
            return Err(backend_error(
                "failed to open Microsoft Platform Crypto Provider",
                format!("HRESULT=0x{:08X}", status as u32),
            ));
        }

        Ok(ProviderHandle(provider))
    }

    fn open_key(
        &self,
        provider: &ProviderHandle,
        key_name: &[u16],
    ) -> std::result::Result<KeyHandle, i32> {
        let mut key: NCRYPT_KEY_HANDLE = 0;
        let status = unsafe { NCryptOpenKey(provider.0, &mut key, key_name.as_ptr(), 0, 0) };
        if status < 0 {
            return Err(status);
        }

        Ok(KeyHandle(key))
    }

    fn open_existing_key(&self, key_id: &str) -> Result<(ProviderHandle, KeyHandle)> {
        let provider = self.open_provider()?;
        let key_name = Self::to_wide_null(&key_label(key_id));
        let key = self
            .open_key(&provider, &key_name)
            .map_err(|_| DeviceKeyStoreError::KeyNotFound(key_id.to_string()))?;
        Ok((provider, key))
    }

    fn read_property_bytes(handle: usize, property: windows_sys::core::PCWSTR) -> Option<Vec<u8>> {
        let mut output_len: u32 = 0;
        let status =
            unsafe { NCryptGetProperty(handle, property, ptr::null_mut(), 0, &mut output_len, 0) };
        if status < 0 || output_len == 0 {
            return None;
        }

        let mut out = vec![0u8; output_len as usize];
        let status = unsafe {
            NCryptGetProperty(
                handle,
                property,
                out.as_mut_ptr(),
                output_len,
                &mut output_len,
                0,
            )
        };
        if status < 0 {
            return None;
        }
        out.truncate(output_len as usize);
        if out.is_empty() { None } else { Some(out) }
    }
}

struct ProviderHandle(NCRYPT_PROV_HANDLE);
impl Drop for ProviderHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

struct KeyHandle(NCRYPT_KEY_HANDLE);
impl Drop for KeyHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

impl DeviceKeyStore for WindowsPlatformCryptoProviderKeyStore {
    fn initialize(&self) -> Result<()> {
        let _ = self.open_provider()?;
        Ok(())
    }

    fn backend_kind(&self) -> BackendKind {
        BackendKind::WindowsPlatformCryptoProvider
    }

    fn hardware_protection(&self) -> HardwareProtection {
        HardwareProtection::HardwareBacked
    }

    fn ensure_signing_key(&self, key_id: &str) -> Result<()> {
        validate_key_id(key_id)?;

        let provider = self.open_provider()?;
        let key_name = Self::to_wide_null(&key_label(key_id));

        match self.open_key(&provider, &key_name) {
            Ok(_) => return Ok(()),
            Err(status) if status == NTE_BAD_KEYSET || status == NTE_NO_KEY => {}
            Err(status) => {
                return Err(backend_error(
                    "failed to open existing key in PCP provider",
                    format!("HRESULT=0x{:08X}", status as u32),
                ));
            }
        }

        let mut key: NCRYPT_KEY_HANDLE = 0;
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut key,
                BCRYPT_ECDSA_P256_ALGORITHM,
                key_name.as_ptr(),
                0,
                0,
            )
        };
        if status < 0 {
            return Err(backend_error(
                "failed to create persisted PCP key",
                format!("HRESULT=0x{:08X}", status as u32),
            ));
        }
        let key = KeyHandle(key);

        let status = unsafe { NCryptFinalizeKey(key.0, 0) };
        if status < 0 {
            return Err(backend_error(
                "failed to finalize PCP key",
                format!("HRESULT=0x{:08X}", status as u32),
            ));
        }

        Ok(())
    }

    fn public_key_der(&self, key_id: &str) -> Result<Vec<u8>> {
        validate_key_id(key_id)?;

        self.ensure_signing_key(key_id)?;
        let (_provider, key) = self.open_existing_key(key_id)?;

        let mut blob_size: u32 = 0;
        let status = unsafe {
            NCryptExportKey(
                key.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                ptr::null_mut(),
                0,
                &mut blob_size,
                0,
            )
        };
        if status < 0 {
            return Err(backend_error(
                "failed to query exported ECC public blob size",
                format!("HRESULT=0x{:08X}", status as u32),
            ));
        }

        let mut blob = vec![0u8; blob_size as usize];
        let status = unsafe {
            NCryptExportKey(
                key.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                blob.as_mut_ptr(),
                blob_size,
                &mut blob_size,
                0,
            )
        };
        if status < 0 {
            return Err(backend_error(
                "failed to export ECC public blob",
                format!("HRESULT=0x{:08X}", status as u32),
            ));
        }
        blob.truncate(blob_size as usize);

        if blob.len() < size_of::<BCRYPT_ECCKEY_BLOB>() {
            return Err(DeviceKeyStoreError::Backend(
                "invalid ECC public blob size".to_string(),
            ));
        }

        let header = unsafe { ptr::read_unaligned(blob.as_ptr().cast::<BCRYPT_ECCKEY_BLOB>()) };
        if header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC {
            return Err(DeviceKeyStoreError::Backend(
                "unexpected ECC blob magic for P-256 public key".to_string(),
            ));
        }

        let cb_key = header.cbKey as usize;
        let offset = size_of::<BCRYPT_ECCKEY_BLOB>();
        let expected = offset + (2 * cb_key);
        if blob.len() < expected {
            return Err(DeviceKeyStoreError::Backend(
                "truncated ECC public blob".to_string(),
            ));
        }

        let x = &blob[offset..offset + cb_key];
        let y = &blob[offset + cb_key..offset + (2 * cb_key)];
        ecc_xy_to_spki_der(x, y)
    }

    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
        validate_key_id(key_id)?;
        validate_payload(payload)?;

        self.ensure_signing_key(key_id)?;
        let (_provider, key) = self.open_existing_key(key_id)?;

        let digest = sha256(payload);
        let mut sig_size: u32 = 0;

        let status = unsafe {
            NCryptSignHash(
                key.0,
                ptr::null(),
                digest.as_ptr(),
                digest.len() as u32,
                ptr::null_mut(),
                0,
                &mut sig_size,
                0,
            )
        };
        if status < 0 {
            return Err(backend_error(
                "failed to query PCP ECDSA signature size",
                format!("HRESULT=0x{:08X}", status as u32),
            ));
        }

        let mut signature = vec![0u8; sig_size as usize];
        let status = unsafe {
            NCryptSignHash(
                key.0,
                ptr::null(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_mut_ptr(),
                sig_size,
                &mut sig_size,
                0,
            )
        };
        if status < 0 {
            return Err(backend_error(
                "failed to sign hash with PCP key",
                format!("HRESULT=0x{:08X}", status as u32),
            ));
        }
        signature.truncate(sig_size as usize);

        if signature.len() % 2 != 0 {
            return Err(DeviceKeyStoreError::Backend(
                "unexpected ECDSA signature blob length".to_string(),
            ));
        }
        let half = signature.len() / 2;
        ecdsa_rs_to_der(&signature[..half], &signature[half..])
    }

    fn delete_signing_key(&self, key_id: &str) -> Result<()> {
        validate_key_id(key_id)?;

        let provider = self.open_provider()?;
        let key_name = Self::to_wide_null(&key_label(key_id));
        let key = match self.open_key(&provider, &key_name) {
            Ok(key) => key,
            Err(status) if status == NTE_BAD_KEYSET || status == NTE_NO_KEY => return Ok(()),
            Err(status) => {
                return Err(backend_error(
                    "failed to open existing key in PCP provider for deletion",
                    format!("HRESULT=0x{:08X}", status as u32),
                ));
            }
        };

        let status = unsafe { NCryptDeleteKey(key.0, 0) };
        if status < 0 {
            return Err(backend_error(
                "failed to delete persisted PCP key",
                format!("HRESULT=0x{:08X}", status as u32),
            ));
        }

        Ok(())
    }

    fn is_hardware_security_available(&self) -> Result<bool> {
        Ok(self.open_provider().is_ok())
    }

    fn attestation(&self, key_id: &str, challenge: &[u8]) -> Result<Option<Vec<u8>>> {
        validate_key_id(key_id)?;
        validate_payload(challenge)?;

        self.ensure_signing_key(key_id)?;
        let public_key_der = self.public_key_der(key_id)?;
        let challenge_signature_der = self.sign(key_id, challenge)?;
        let pcp_available = self.is_hardware_security_available()?;
        let challenge_digest = sha256(challenge);

        let (provider, key) = self.open_existing_key(key_id)?;
        let key_attestation_blob =
            Self::read_property_bytes(key.0 as usize, NCRYPT_PCP_KEYATTESTATION_PROPERTY);
        let (ek_certificate_der, ek_certificate_source) = match crate::first_present_source!(
            "pcp_ecc_ekcert_property" =>
                Self::read_property_bytes(provider.0 as usize, NCRYPT_PCP_ECC_EKCERT_PROPERTY),
            "pcp_rsa_ekcert_property" =>
                Self::read_property_bytes(provider.0 as usize, NCRYPT_PCP_RSA_EKCERT_PROPERTY),
            "pcp_ekcert_property" =>
                Self::read_property_bytes(provider.0 as usize, NCRYPT_PCP_EKCERT_PROPERTY),
            "pcp_eknvcert_property" =>
                Self::read_property_bytes(provider.0 as usize, NCRYPT_PCP_EKNVCERT_PROPERTY),
            "pcp_rsa_eknvcert_property" =>
                Self::read_property_bytes(provider.0 as usize, NCRYPT_PCP_RSA_EKNVCERT_PROPERTY),
        ) {
            Some((source, cert)) => (Some(cert), Some(source)),
            None => (None, None),
        };
        let intermediate_ca_ek_certificate_der = Self::read_property_bytes(
            provider.0 as usize,
            NCRYPT_PCP_INTERMEDIATE_CA_EKCERT_PROPERTY,
        );

        let evidence = WindowsPcpKeyAttestationEvidenceV1 {
            version: KEY_ATTESTATION_VERSION_V1,
            public_key_der_b64: STANDARD.encode(public_key_der),
            challenge_signature_der_b64: STANDARD.encode(challenge_signature_der),
            provider: "MicrosoftPlatformCryptoProvider".to_string(),
            pcp_available,
            challenge_digest_sha256_b64: Some(STANDARD.encode(challenge_digest)),
            key_attestation_blob_b64: key_attestation_blob.map(|v| STANDARD.encode(v)),
            ek_certificate_der_b64: ek_certificate_der.map(|v| STANDARD.encode(v)),
            ek_certificate_source,
            intermediate_ca_ek_certificate_der_b64: intermediate_ca_ek_certificate_der
                .map(|v| STANDARD.encode(v)),
        };
        let encoded = serde_json::to_vec(&evidence)
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        Ok(Some(encoded))
    }
}
