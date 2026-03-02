# hardware-keystore

Cross-platform hardware-backed keystore for device signing keys with attestation.

It creates or reuses a non-exportable device key in platform hardware security, returns the public key, and signs payloads without exposing the private key.

## Platform Hardware Model

`new_default()` selects one backend per target OS:

| Platform | Backend | Hardware model used |
| --- | --- | --- |
| iOS / macOS | Apple Secure Enclave (`BackendKind::AppleSecureEnclave`) | Secure Enclave key in Keychain (`Token::SecureEnclave`) |
| Android | Android Hardware Keystore (`BackendKind::AndroidHardwareKeystore`) | Android Keystore key, StrongBox-backed when available (API 28+ with `android.hardware.strongbox_keystore`), otherwise TEE-backed Keystore |
| Linux | TPM 2.0 (`BackendKind::Tpm2`) | TPM 2.0 persistent ECC P-256 signing key via TSS ESAPI |
| Windows | Windows Platform Crypto Provider (`BackendKind::WindowsPlatformCryptoProvider`) | Microsoft Platform Crypto Provider (CNG/NCrypt), typically TPM-backed |

Apple managed-attestation integration note:
- `AppleSecureEnclaveKeyStore::attestation()` can include managed attestation certificate chain evidence from `TARF_APPLE_MANAGED_ATTESTATION_CHAIN_DER_B64` (comma-separated DER/base64 certificates), used by server strict verification mode.
- Runtime override is also available in Rust via `hardware_keystore::set_apple_managed_attestation_chain(...)`.
- Managed identity-backed mode is supported via `TARF_APPLE_MANAGED_ATTESTATION_IDENTITY_LABEL` (or runtime override `hardware_keystore::set_apple_managed_attestation_identity_label(...)`):
  - signing/public-key operations use that identity's private key
  - attestation chain is resolved from that identity via `SecTrust` and embedded automatically

## Attestation Status

| Platform | Key Attestation | Tested |
| --- | --- | --- |
| Android | Completed | No |
| iOS | Completed | No |
| macOS | Completed | No |
| Linux | Completed | No |
| Windows | Completed | No |

## Hardware Keystore Tested Platforms

| Platform | Tested |
| --- | --- |
| Linux | Yes |
| Android | Yes |
| iOS | No |
| macOS | No |
| Windows | No |

## Example
```rust
use hardware_keystore::{HardwareKeystoreConfig, DeviceKeyStore};

fn demo() -> Result<(), String> {
    hardware_keystore::init(HardwareKeystoreConfig::default()).map_err(|e| e.to_string())?;

    let keystore = hardware_keystore::new_default();
    keystore.ensure_signing_key("device:abc").map_err(|e| e.to_string())?;

    let pubkey_der = keystore.public_key_der("device:abc").map_err(|e| e.to_string())?;
    let sig_der = keystore.sign("device:abc", b"payload").map_err(|e| e.to_string())?;

    let descriptor = keystore
        .attestation_descriptor()
        .map_err(|e| e.to_string())?;
    let evidence = keystore
        .attestation("device:abc", b"server-challenge")
        .map_err(|e| e.to_string())?;

    let _ = (pubkey_der, sig_der, descriptor, evidence);
    Ok(())
}
```
