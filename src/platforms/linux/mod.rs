use crate::codec::der::{ecc_xy_to_spki_der, ecdsa_rs_to_der};
use crate::core::error::{DeviceKeyStoreError, Result};
use crate::core::model::{
    BackendKind, HardwareProtection, Tpm2KeyAttestationEvidenceV1, KEY_ATTESTATION_VERSION_V1,
};
use crate::core::traits::DeviceKeyStore;
use crate::service::{
    backend_error, key_label, sha256, stable_u32_slot, validate_key_id, validate_payload,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::convert::{TryFrom, TryInto};
use std::fs::OpenOptions;
use std::str::FromStr;
use tss_esapi::abstraction::{ak, ek, AsymmetricAlgorithmSelection, DefaultKey};
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, Data, Digest, EccScheme, HashScheme, Public, Signature, SignatureScheme,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::Marshall;
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::utils::create_unrestricted_signing_ecc_public;
use tss_esapi::Context;

// Keep owner-managed persistent handles in an owner-safe range.
// Using a wider span can produce handles rejected by EvictControl(Owner, ...).
const TPM_PERSISTENT_BASE: u32 = 0x8101_0000;
const TPM_PERSISTENT_MAX: u32 = 0x817F_FFFF;
const TPM_PERSISTENT_SPAN: u32 = TPM_PERSISTENT_MAX - TPM_PERSISTENT_BASE;

mod ek_certificate;
mod manufacturer;

#[derive(Debug, Default)]
pub struct Tpm2KeyStore;

impl Tpm2KeyStore {
    pub fn new() -> Self {
        Self
    }

    fn tcti_candidates() -> Vec<(String, TctiNameConf)> {
        if let Ok(tcti) = TctiNameConf::from_environment_variable() {
            return vec![("env(TPM2TOOLS_TCTI/TCTI/TEST_TCTI)".to_string(), tcti)];
        }

        let mut candidates = Vec::new();
        if let Ok(tcti) = TctiNameConf::from_str("device:/dev/tpmrm0") {
            candidates.push(("device:/dev/tpmrm0".to_string(), tcti));
        }
        if let Ok(tcti) = TctiNameConf::from_str("device:/dev/tpm0") {
            candidates.push(("device:/dev/tpm0".to_string(), tcti));
        }
        if let Ok(tcti) = TctiNameConf::from_str("tabrmd") {
            candidates.push(("tabrmd".to_string(), tcti));
        }
        candidates
    }

    fn tpm_permission_hint() -> Option<String> {
        let device_paths = ["/dev/tpmrm0", "/dev/tpm0"];
        let has_nodes = device_paths
            .iter()
            .any(|path| std::path::Path::new(path).exists());
        if !has_nodes {
            return None;
        }

        for path in device_paths {
            if !std::path::Path::new(path).exists() {
                continue;
            }
            if let Err(err) = OpenOptions::new().read(true).write(true).open(path) {
                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    return Some(
                        "TPM device exists but access is denied. Add the runtime user to the `tss` group or update TPM udev permissions.".to_string(),
                    );
                }
            }
        }

        None
    }

    fn open_context(&self) -> Result<Context> {
        let candidates = Self::tcti_candidates();
        let mut attempts = Vec::new();

        for (label, tcti) in candidates {
            match Context::new(tcti) {
                Ok(ctx) => return Ok(ctx),
                Err(err) => attempts.push(format!("{label}: {err}")),
            }
        }

        let hint = Self::tpm_permission_hint()
            .map(|h| format!(" Hint: {h}"))
            .unwrap_or_default();
        Err(DeviceKeyStoreError::Backend(format!(
            "failed to connect to TPM context. {}{}",
            attempts.join(" | "),
            hint
        )))
    }

    fn probe_tpm_context(&self) -> bool {
        self.open_context().is_ok()
    }

    fn with_context<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Context) -> Result<T>,
    {
        let mut ctx = self.open_context()?;
        f(&mut ctx)
    }

    fn persistent_handle_for_key_id(&self, key_id: &str) -> Result<PersistentTpmHandle> {
        let label = key_label(key_id);
        let slot = stable_u32_slot(&label, TPM_PERSISTENT_SPAN);
        let raw_handle = TPM_PERSISTENT_BASE + slot;
        PersistentTpmHandle::new(raw_handle)
            .map_err(|e| backend_error("failed to derive persistent TPM handle for key_id", e))
    }

    fn signing_key_template(&self) -> Result<Public> {
        create_unrestricted_signing_ecc_public(
            EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
            EccCurve::NistP256,
        )
        .map_err(|e| backend_error("failed to build TPM signing key template", e))
    }

    fn try_load_persistent_object(
        &self,
        ctx: &mut Context,
        persistent_handle: PersistentTpmHandle,
    ) -> std::result::Result<ObjectHandle, tss_esapi::Error> {
        ctx.execute_without_session(|c| {
            c.tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))
        })
    }

    fn close_object_handle(&self, ctx: &mut Context, mut handle: ObjectHandle) {
        let _ = ctx.execute_without_session(|c| c.tr_close(&mut handle));
    }

    fn load_key_handle(
        &self,
        ctx: &mut Context,
        key_id: &str,
        persistent_handle: PersistentTpmHandle,
    ) -> Result<(ObjectHandle, KeyHandle)> {
        let object = self
            .try_load_persistent_object(ctx, persistent_handle)
            .map_err(|_| DeviceKeyStoreError::KeyNotFound(key_id.to_string()))?;
        Ok((object, KeyHandle::from(object)))
    }

    fn evict_persistent_object_if_present(
        &self,
        ctx: &mut Context,
        persistent_handle: PersistentTpmHandle,
    ) -> Result<()> {
        let existing = match self.try_load_persistent_object(ctx, persistent_handle) {
            Ok(handle) => handle,
            Err(_) => return Ok(()),
        };

        ctx.tr_set_auth(Hierarchy::Owner.into(), Auth::default())
            .map_err(|e| backend_error("failed to set owner auth for evict_control", e))?;

        let persistent = Persistent::Persistent(persistent_handle);
        ctx.execute_with_session(Some(AuthSession::Password), |c| {
            c.evict_control(Provision::Owner, existing, persistent)
        })
        .map_err(|e| backend_error("failed to evict existing persistent key", e))?;

        if !existing.is_none() {
            self.close_object_handle(ctx, existing);
        }

        Ok(())
    }

    fn create_and_persist_signing_key(
        &self,
        ctx: &mut Context,
        persistent_handle: PersistentTpmHandle,
    ) -> Result<()> {
        self.evict_persistent_object_if_present(ctx, persistent_handle)?;

        let template = self.signing_key_template()?;

        ctx.tr_set_auth(Hierarchy::Owner.into(), Auth::default())
            .map_err(|e| backend_error("failed to set owner auth before key creation", e))?;

        let created = ctx
            .execute_with_session(Some(AuthSession::Password), |c| {
                c.create_primary(Hierarchy::Owner, template, None, None, None, None)
            })
            .map_err(|e| backend_error("failed to create transient TPM signing key", e))?;

        let transient_key = created.key_handle;
        let persistent = Persistent::Persistent(persistent_handle);

        let persistent_object = ctx
            .execute_with_session(Some(AuthSession::Password), |c| {
                c.evict_control(Provision::Owner, transient_key.into(), persistent)
            })
            .map_err(|e| backend_error("failed to persist TPM signing key", e))?;

        ctx.flush_context(transient_key.into())
            .map_err(|e| backend_error("failed to flush transient TPM key", e))?;

        if !persistent_object.is_none() {
            self.close_object_handle(ctx, persistent_object);
        }

        Ok(())
    }

    fn ecdsa_signature_to_der(signature: &Signature) -> Result<Vec<u8>> {
        let Signature::EcDsa(ecc) = signature else {
            return Err(DeviceKeyStoreError::Backend(
                "TPM returned non-ECDSA signature for ECC key".to_string(),
            ));
        };

        ecdsa_rs_to_der(ecc.signature_r().value(), ecc.signature_s().value())
    }

    fn ecc_public_to_spki_der(public: Public) -> Result<Vec<u8>> {
        let Public::Ecc { unique, .. } = public else {
            return Err(DeviceKeyStoreError::Backend(
                "TPM key template mismatch: expected ECC public key".to_string(),
            ));
        };

        ecc_xy_to_spki_der(unique.x().value(), unique.y().value())
    }

    fn retrieve_ek_certificate_der(
        ctx: &mut Context,
        ek_public: &Public,
    ) -> (Option<Vec<u8>>, Option<String>) {
        ek_certificate::retrieve_with_fallback(ctx, ek_public)
    }
}

impl DeviceKeyStore for Tpm2KeyStore {
    fn initialize(&self) -> Result<()> {
        let _ = self.open_context()?;
        Ok(())
    }

    fn backend_kind(&self) -> BackendKind {
        BackendKind::Tpm2
    }

    fn hardware_protection(&self) -> HardwareProtection {
        HardwareProtection::Unknown
    }

    fn ensure_signing_key(&self, key_id: &str) -> Result<()> {
        validate_key_id(key_id)?;

        self.with_context(|ctx| {
            let persistent_handle = self.persistent_handle_for_key_id(key_id)?;
            if self
                .try_load_persistent_object(ctx, persistent_handle)
                .is_ok()
            {
                return Ok(());
            }

            self.create_and_persist_signing_key(ctx, persistent_handle)?;

            let loaded = self
                .try_load_persistent_object(ctx, persistent_handle)
                .map_err(|e| backend_error("failed to verify persisted TPM key", e))?;
            self.close_object_handle(ctx, loaded);
            Ok(())
        })
    }

    fn public_key_der(&self, key_id: &str) -> Result<Vec<u8>> {
        validate_key_id(key_id)?;

        self.ensure_signing_key(key_id)?;
        self.with_context(|ctx| {
            let persistent_handle = self.persistent_handle_for_key_id(key_id)?;
            let (object_handle, key_handle) =
                self.load_key_handle(ctx, key_id, persistent_handle)?;

            let result = ctx
                .read_public(key_handle)
                .map_err(|e| backend_error("failed to read TPM public key", e))
                .and_then(|(public, _, _)| Self::ecc_public_to_spki_der(public));

            self.close_object_handle(ctx, object_handle);
            result
        })
    }

    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
        validate_key_id(key_id)?;
        validate_payload(payload)?;

        self.ensure_signing_key(key_id)?;
        self.with_context(|ctx| {
            let persistent_handle = self.persistent_handle_for_key_id(key_id)?;
            let (object_handle, key_handle) =
                self.load_key_handle(ctx, key_id, persistent_handle)?;

            let digest = Digest::try_from(sha256(payload))
                .map_err(|e| backend_error("failed to construct TPM digest", e))?;

            let validation = TPMT_TK_HASHCHECK {
                tag: TPM2_ST_HASHCHECK,
                hierarchy: TPM2_RH_NULL,
                digest: Default::default(),
            };

            let result = (|| -> Result<Vec<u8>> {
                ctx.tr_set_auth(key_handle.into(), Auth::default())
                    .map_err(|e| backend_error("failed to set key auth for signing", e))?;

                let hashcheck_ticket = validation
                    .try_into()
                    .map_err(|e| backend_error("invalid TPM hashcheck ticket", e))?;

                let signature = ctx
                    .execute_with_session(Some(AuthSession::Password), |c| {
                        c.sign(key_handle, digest, SignatureScheme::Null, hashcheck_ticket)
                    })
                    .map_err(|e| backend_error("failed to sign digest with TPM key", e))?;

                Self::ecdsa_signature_to_der(&signature)
            })();

            self.close_object_handle(ctx, object_handle);
            result
        })
    }

    fn delete_signing_key(&self, key_id: &str) -> Result<()> {
        validate_key_id(key_id)?;

        self.with_context(|ctx| {
            let persistent_handle = self.persistent_handle_for_key_id(key_id)?;
            self.evict_persistent_object_if_present(ctx, persistent_handle)
        })
    }

    fn is_hardware_security_available(&self) -> Result<bool> {
        Ok(self.probe_tpm_context())
    }

    fn attestation(&self, key_id: &str, challenge: &[u8]) -> Result<Option<Vec<u8>>> {
        validate_key_id(key_id)?;
        validate_payload(challenge)?;

        self.ensure_signing_key(key_id)?;

        let evidence = self.with_context(|ctx| {
            let persistent_handle = self.persistent_handle_for_key_id(key_id)?;
            let (subject_object_handle, subject_key_handle) =
                self.load_key_handle(ctx, key_id, persistent_handle)?;

            let result = (|| -> Result<Tpm2KeyAttestationEvidenceV1> {
                let (subject_public, subject_name, _) = ctx
                    .read_public(subject_key_handle)
                    .map_err(|e| backend_error("failed to read TPM subject key public area", e))?;
                let public_key_der = Self::ecc_public_to_spki_der(subject_public)?;

                let digest = Digest::try_from(sha256(challenge)).map_err(|e| {
                    backend_error("failed to build challenge digest for attestation", e)
                })?;
                let validation = TPMT_TK_HASHCHECK {
                    tag: TPM2_ST_HASHCHECK,
                    hierarchy: TPM2_RH_NULL,
                    digest: Default::default(),
                };
                let hashcheck_ticket = validation.try_into().map_err(|e| {
                    backend_error("invalid TPM hashcheck ticket for attestation", e)
                })?;
                ctx.tr_set_auth(subject_key_handle.into(), Auth::default())
                    .map_err(|e| {
                        backend_error("failed to set subject key auth for attestation", e)
                    })?;
                let challenge_signature = ctx
                    .execute_with_session(Some(AuthSession::Password), |c| {
                        c.sign(
                            subject_key_handle,
                            digest,
                            SignatureScheme::Null,
                            hashcheck_ticket,
                        )
                    })
                    .map_err(|e| backend_error("failed to sign challenge with subject key", e))?;
                let challenge_signature_der = Self::ecdsa_signature_to_der(&challenge_signature)?;
                let challenge_digest = sha256(challenge);
                let qualifying_data = Data::try_from(challenge_digest.to_vec())
                    .map_err(|e| backend_error("failed to build attestation qualifying data", e))?;

                let ek_handle = ek::create_ek_object_2(
                    ctx,
                    AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
                    None::<DefaultKey>,
                )
                .map_err(|e| backend_error("failed to create EK object for attestation", e))?;

                let ak_creation = ak::create_ak_2(
                    ctx,
                    ek_handle,
                    HashingAlgorithm::Sha256,
                    AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
                    SignatureSchemeAlgorithm::EcDsa,
                    None,
                    None::<DefaultKey>,
                )
                .map_err(|e| backend_error("failed to create AK for attestation", e))?;

                let ak_handle = ak::load_ak(
                    ctx,
                    ek_handle,
                    None,
                    ak_creation.out_private,
                    ak_creation.out_public,
                )
                .map_err(|e| backend_error("failed to load AK for attestation", e))?;

                let (certified_attest, certified_signature) = ctx
                    .execute_with_sessions(
                        (
                            Some(AuthSession::Password),
                            Some(AuthSession::Password),
                            None,
                        ),
                        |c| {
                            c.certify(
                                subject_key_handle.into(),
                                ak_handle,
                                qualifying_data,
                                SignatureScheme::Null,
                            )
                        },
                    )
                    .map_err(|e| backend_error("failed to certify signing key with AK", e))?;

                let certified_attest_raw = certified_attest
                    .marshall()
                    .map_err(|e| backend_error("failed to marshal certified attest blob", e))?;
                let certified_signature_der = Self::ecdsa_signature_to_der(&certified_signature)?;

                let (ak_public, _, ak_qualified_name) = ctx
                    .read_public(ak_handle)
                    .map_err(|e| backend_error("failed to read AK public area", e))?;
                let ak_public_der = Self::ecc_public_to_spki_der(ak_public)?;
                let (ek_public, _, _) = ctx
                    .read_public(ek_handle)
                    .map_err(|e| backend_error("failed to read EK public area", e))?;
                let (ek_certificate_der, ek_certificate_source) =
                    Self::retrieve_ek_certificate_der(ctx, &ek_public);

                let _ = ctx.flush_context(ak_handle.into());
                let _ = ctx.flush_context(ek_handle.into());

                Ok(Tpm2KeyAttestationEvidenceV1 {
                    version: KEY_ATTESTATION_VERSION_V1,
                    public_key_der_b64: STANDARD.encode(public_key_der),
                    challenge_signature_der_b64: STANDARD.encode(challenge_signature_der),
                    tpm_available: true,
                    challenge_digest_sha256_b64: Some(STANDARD.encode(challenge_digest)),
                    certified_attest_b64: Some(STANDARD.encode(certified_attest_raw)),
                    certified_signature_der_b64: Some(STANDARD.encode(certified_signature_der)),
                    attestation_public_key_der_b64: Some(STANDARD.encode(ak_public_der)),
                    attestation_key_name_b64: Some(STANDARD.encode(ak_qualified_name.value())),
                    subject_key_name_b64: Some(STANDARD.encode(subject_name.value())),
                    ek_certificate_der_b64: ek_certificate_der.map(|v| STANDARD.encode(v)),
                    ek_certificate_source,
                })
            })();

            self.close_object_handle(ctx, subject_object_handle);
            result
        })?;

        let encoded = serde_json::to_vec(&evidence)
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        Ok(Some(encoded))
    }
}
