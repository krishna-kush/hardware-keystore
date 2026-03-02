use crate::config;
use crate::core::error::{DeviceKeyStoreError, Result};
use crate::core::model::{
    AndroidKeyAttestationEvidenceV1, BackendKind, HardwareProtection, KEY_ATTESTATION_VERSION_V1,
};
use crate::core::traits::DeviceKeyStore;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString, JValue};
use jni::JNIEnv;
use sha2::{Digest, Sha256};

const ANDROID_KEYSTORE: &str = "AndroidKeyStore";
const EC_ALGORITHM: &str = "EC";
const EC_CURVE_P256: &str = "secp256r1";
const SIGNATURE_ALGORITHM: &str = "SHA256withECDSA";
const PROBE_KEY_ID: &str = "hardware_probe";

#[derive(Debug, Default)]
pub struct AndroidHardwareKeyStore;

impl AndroidHardwareKeyStore {
    pub fn new() -> Self {
        Self
    }

    fn key_alias(key_id: &str) -> String {
        config::key_label_for(key_id)
    }

    fn with_env_activity<T, F>(&self, f: F) -> Result<T>
    where
        F: for<'local> FnOnce(&mut JNIEnv<'local>, JObject<'local>) -> Result<T>,
    {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let activity = unsafe { JObject::from_raw(ctx.context().cast()) };
        f(&mut env, activity)
    }

    fn jstring<'a>(&self, env: &mut JNIEnv<'a>, value: &str) -> Result<JString<'a>> {
        env.new_string(value)
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))
    }

    fn get_static_int<'a>(
        &self,
        env: &mut JNIEnv<'a>,
        class_name: &str,
        field_name: &str,
    ) -> Result<i32> {
        let class = env
            .find_class(class_name)
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        env.get_static_field(class, field_name, "I")
            .and_then(|v| v.i())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))
    }

    fn get_sdk_int<'a>(&self, env: &mut JNIEnv<'a>) -> Result<i32> {
        self.get_static_int(env, "android/os/Build$VERSION", "SDK_INT")
    }

    fn has_system_feature<'a>(
        &self,
        env: &mut JNIEnv<'a>,
        activity: &JObject<'a>,
        feature: &str,
    ) -> Result<bool> {
        let pm = env
            .call_method(
                activity,
                "getPackageManager",
                "()Landroid/content/pm/PackageManager;",
                &[],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let feature_j = self.jstring(env, feature)?;
        let feature_obj: JObject = feature_j.into();

        env.call_method(
            pm,
            "hasSystemFeature",
            "(Ljava/lang/String;)Z",
            &[JValue::Object(&feature_obj)],
        )
        .and_then(|v| v.z())
        .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))
    }

    fn load_keystore<'a>(&self, env: &mut JNIEnv<'a>) -> Result<JObject<'a>> {
        let keystore_class = env
            .find_class("java/security/KeyStore")
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let provider = self.jstring(env, ANDROID_KEYSTORE)?;
        let provider_obj: JObject = provider.into();

        let keystore = env
            .call_static_method(
                keystore_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyStore;",
                &[JValue::Object(&provider_obj)],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let null_param = JObject::null();
        env.call_method(
            &keystore,
            "load",
            "(Ljava/security/KeyStore$LoadStoreParameter;)V",
            &[JValue::Object(&null_param)],
        )
        .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        Ok(keystore)
    }

    fn contains_alias<'a>(&self, env: &mut JNIEnv<'a>, alias: &str) -> Result<bool> {
        let keystore = self.load_keystore(env)?;
        let alias_j = self.jstring(env, alias)?;
        let alias_obj: JObject = alias_j.into();

        env.call_method(
            &keystore,
            "containsAlias",
            "(Ljava/lang/String;)Z",
            &[JValue::Object(&alias_obj)],
        )
        .and_then(|v| v.z())
        .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))
    }

    fn generate_signing_key<'a>(
        &self,
        env: &mut JNIEnv<'a>,
        activity: &JObject<'a>,
        alias: &str,
        attestation_challenge: Option<&[u8]>,
    ) -> Result<()> {
        let kpg_class = env
            .find_class("java/security/KeyPairGenerator")
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let algorithm = self.jstring(env, EC_ALGORITHM)?;
        let provider = self.jstring(env, ANDROID_KEYSTORE)?;
        let algorithm_obj: JObject = algorithm.into();
        let provider_obj: JObject = provider.into();

        let kpg = env
            .call_static_method(
                kpg_class,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
                &[
                    JValue::Object(&algorithm_obj),
                    JValue::Object(&provider_obj),
                ],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let keyprops = env
            .find_class("android/security/keystore/KeyProperties")
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let purpose_sign = env
            .get_static_field(&keyprops, "PURPOSE_SIGN", "I")
            .and_then(|v| v.i())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        let purpose_verify = env
            .get_static_field(&keyprops, "PURPOSE_VERIFY", "I")
            .and_then(|v| v.i())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        let purposes = purpose_sign | purpose_verify;

        let builder_class = env
            .find_class("android/security/keystore/KeyGenParameterSpec$Builder")
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let alias_j = self.jstring(env, alias)?;
        let alias_obj: JObject = alias_j.into();

        let mut builder = env
            .new_object(
                builder_class,
                "(Ljava/lang/String;I)V",
                &[JValue::Object(&alias_obj), JValue::Int(purposes)],
            )
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let digest_sha256 = env
            .get_static_field(&keyprops, "DIGEST_SHA256", "Ljava/lang/String;")
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let string_class = env
            .find_class("java/lang/String")
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        let digest_array = env
            .new_object_array(1, string_class, JObject::null())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        env.set_object_array_element(&digest_array, 0, digest_sha256)
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let digest_array_obj: JObject = digest_array.into();
        builder = env
            .call_method(
                &builder,
                "setDigests",
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::Object(&digest_array_obj)],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let ec_spec_class = env
            .find_class("java/security/spec/ECGenParameterSpec")
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        let curve_name = self.jstring(env, EC_CURVE_P256)?;
        let curve_name_obj: JObject = curve_name.into();
        let ec_spec = env
            .new_object(
                ec_spec_class,
                "(Ljava/lang/String;)V",
                &[JValue::Object(&curve_name_obj)],
            )
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        builder = env
            .call_method(
                &builder,
                "setAlgorithmParameterSpec",
                "(Ljava/security/spec/AlgorithmParameterSpec;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::Object(&ec_spec)],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        builder = env
            .call_method(
                &builder,
                "setUserAuthenticationRequired",
                "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::Bool(0)],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let sdk_int = self.get_sdk_int(env)?;
        if let Some(challenge) = attestation_challenge {
            if !challenge.is_empty() {
                if sdk_int < 24 {
                    return Err(DeviceKeyStoreError::Backend(
                        "android api level does not support key attestation challenge".to_string(),
                    ));
                }
                let challenge_j = env
                    .byte_array_from_slice(challenge)
                    .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
                let challenge_obj: JObject = challenge_j.into();
                builder = env
                    .call_method(
                        &builder,
                        "setAttestationChallenge",
                        "([B)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                        &[JValue::Object(&challenge_obj)],
                    )
                    .and_then(|v| v.l())
                    .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
            }
        }

        if sdk_int >= 28
            && self.has_system_feature(env, activity, "android.hardware.strongbox_keystore")?
        {
            let maybe_builder = env.call_method(
                &builder,
                "setIsStrongBoxBacked",
                "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::Bool(1)],
            );

            if let Ok(next) = maybe_builder.and_then(|v| v.l()) {
                builder = next;
            }
        }

        let spec = env
            .call_method(
                &builder,
                "build",
                "()Landroid/security/keystore/KeyGenParameterSpec;",
                &[],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        env.call_method(
            &kpg,
            "initialize",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[JValue::Object(&spec)],
        )
        .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        env.call_method(&kpg, "generateKeyPair", "()Ljava/security/KeyPair;", &[])
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        Ok(())
    }

    fn ensure_key_inner<'a>(
        &self,
        env: &mut JNIEnv<'a>,
        activity: &JObject<'a>,
        alias: &str,
    ) -> Result<()> {
        if self.contains_alias(env, alias)? {
            return Ok(());
        }

        self.generate_signing_key(env, activity, alias, None)?;

        if self.contains_alias(env, alias)? {
            Ok(())
        } else {
            Err(DeviceKeyStoreError::Backend(
                "key generation completed but alias not found".to_string(),
            ))
        }
    }

    fn delete_alias_inner<'a>(&self, env: &mut JNIEnv<'a>, alias: &str) -> Result<()> {
        if !self.contains_alias(env, alias)? {
            return Ok(());
        }

        let keystore = self.load_keystore(env)?;
        let alias_j = self.jstring(env, alias)?;
        let alias_obj: JObject = alias_j.into();
        env.call_method(
            &keystore,
            "deleteEntry",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&alias_obj)],
        )
        .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        Ok(())
    }

    fn get_certificate_public_key_der<'a>(
        &self,
        env: &mut JNIEnv<'a>,
        alias: &str,
    ) -> Result<Vec<u8>> {
        let keystore = self.load_keystore(env)?;
        let alias_j = self.jstring(env, alias)?;
        let alias_obj: JObject = alias_j.into();

        let cert = env
            .call_method(
                &keystore,
                "getCertificate",
                "(Ljava/lang/String;)Ljava/security/cert/Certificate;",
                &[JValue::Object(&alias_obj)],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        if cert.is_null() {
            return Err(DeviceKeyStoreError::Backend(
                "no certificate found for alias".to_string(),
            ));
        }

        let public_key = env
            .call_method(&cert, "getPublicKey", "()Ljava/security/PublicKey;", &[])
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        if public_key.is_null() {
            return Err(DeviceKeyStoreError::Backend(
                "no public key found in certificate".to_string(),
            ));
        }

        let encoded = env
            .call_method(&public_key, "getEncoded", "()[B", &[])
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        if encoded.is_null() {
            return Err(DeviceKeyStoreError::Backend(
                "public key encoding returned null".to_string(),
            ));
        }

        let encoded_bytes = JByteArray::from(encoded);
        env.convert_byte_array(encoded_bytes)
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))
    }

    fn get_private_key<'a>(&self, env: &mut JNIEnv<'a>, alias: &str) -> Result<JObject<'a>> {
        let keystore = self.load_keystore(env)?;
        let alias_j = self.jstring(env, alias)?;
        let alias_obj: JObject = alias_j.into();
        let null_protection = JObject::null();

        let entry = env
            .call_method(
                &keystore,
                "getEntry",
                "(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;",
                &[JValue::Object(&alias_obj), JValue::Object(&null_protection)],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        if entry.is_null() {
            return Err(DeviceKeyStoreError::Backend(
                "keystore entry returned null".to_string(),
            ));
        }

        let private_key = env
            .call_method(&entry, "getPrivateKey", "()Ljava/security/PrivateKey;", &[])
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        if private_key.is_null() {
            return Err(DeviceKeyStoreError::Backend(
                "private key returned null".to_string(),
            ));
        }

        Ok(private_key)
    }

    fn get_certificate_chain_der<'a>(
        &self,
        env: &mut JNIEnv<'a>,
        alias: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let keystore = self.load_keystore(env)?;
        let alias_j = self.jstring(env, alias)?;
        let alias_obj: JObject = alias_j.into();

        let chain = env
            .call_method(
                &keystore,
                "getCertificateChain",
                "(Ljava/lang/String;)[Ljava/security/cert/Certificate;",
                &[JValue::Object(&alias_obj)],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        if chain.is_null() {
            return Err(DeviceKeyStoreError::Backend(
                "certificate chain returned null".to_string(),
            ));
        }

        let chain_array = JObjectArray::from(chain);
        let len = env
            .get_array_length(&chain_array)
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let mut certificates = Vec::with_capacity(len as usize);
        for idx in 0..len {
            let cert = env
                .get_object_array_element(&chain_array, idx)
                .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

            if cert.is_null() {
                return Err(DeviceKeyStoreError::Backend(
                    "certificate chain contains null element".to_string(),
                ));
            }

            let encoded = env
                .call_method(&cert, "getEncoded", "()[B", &[])
                .and_then(|v| v.l())
                .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

            if encoded.is_null() {
                return Err(DeviceKeyStoreError::Backend(
                    "certificate encoding returned null".to_string(),
                ));
            }

            let encoded_bytes = JByteArray::from(encoded);
            let bytes = env
                .convert_byte_array(encoded_bytes)
                .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
            certificates.push(bytes);
        }

        Ok(certificates)
    }

    fn sign_inner<'a>(&self, env: &mut JNIEnv<'a>, alias: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let private_key = self.get_private_key(env, alias)?;

        let signature_class = env
            .find_class("java/security/Signature")
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        let sig_alg = self.jstring(env, SIGNATURE_ALGORITHM)?;
        let sig_alg_obj: JObject = sig_alg.into();

        let signer = env
            .call_static_method(
                signature_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/Signature;",
                &[JValue::Object(&sig_alg_obj)],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        env.call_method(
            &signer,
            "initSign",
            "(Ljava/security/PrivateKey;)V",
            &[JValue::Object(&private_key)],
        )
        .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let payload_j = env
            .byte_array_from_slice(payload)
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        let payload_obj: JObject = payload_j.into();

        env.call_method(&signer, "update", "([B)V", &[JValue::Object(&payload_obj)])
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let signature = env
            .call_method(&signer, "sign", "()[B", &[])
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        if signature.is_null() {
            return Err(DeviceKeyStoreError::Backend(
                "signature returned null".to_string(),
            ));
        }

        let signature_bytes = JByteArray::from(signature);
        env.convert_byte_array(signature_bytes)
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))
    }

    fn get_key_info<'a>(
        &self,
        env: &mut JNIEnv<'a>,
        private_key: &JObject<'a>,
    ) -> Result<JObject<'a>> {
        let key_factory_class = env
            .find_class("java/security/KeyFactory")
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let ec_alg = self.jstring(env, EC_ALGORITHM)?;
        let provider = self.jstring(env, ANDROID_KEYSTORE)?;
        let ec_alg_obj: JObject = ec_alg.into();
        let provider_obj: JObject = provider.into();

        let key_factory = env
            .call_static_method(
                key_factory_class,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyFactory;",
                &[JValue::Object(&ec_alg_obj), JValue::Object(&provider_obj)],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let key_info_class: JClass = env
            .find_class("android/security/keystore/KeyInfo")
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
        let key_info_class_obj: JObject = key_info_class.into();

        let key_info = env
            .call_method(
                &key_factory,
                "getKeySpec",
                "(Ljava/security/Key;Ljava/lang/Class;)Ljava/security/spec/KeySpec;",
                &[
                    JValue::Object(private_key),
                    JValue::Object(&key_info_class_obj),
                ],
            )
            .and_then(|v| v.l())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        if key_info.is_null() {
            return Err(DeviceKeyStoreError::Backend(
                "KeyInfo retrieval returned null".to_string(),
            ));
        }

        Ok(key_info)
    }

    fn optional_key_info_int_method<'a>(
        &self,
        env: &mut JNIEnv<'a>,
        key_info: &JObject<'a>,
        method_name: &str,
    ) -> Option<i32> {
        match env
            .call_method(key_info, method_name, "()I", &[])
            .and_then(|v| v.i())
        {
            Ok(value) => Some(value),
            Err(_) => {
                // Optional KeyInfo APIs differ across Android API levels/OEM builds.
                // Clear pending Java exception before any subsequent JNI call.
                if env.exception_check().ok() == Some(true) {
                    let _ = env.exception_clear();
                }
                None
            }
        }
    }

    fn security_level_label<'a>(&self, env: &mut JNIEnv<'a>, level: i32) -> Result<String> {
        let level_software = self.get_static_int(
            env,
            "android/security/keystore/KeyProperties",
            "SECURITY_LEVEL_SOFTWARE",
        )?;
        let level_tee = self.get_static_int(
            env,
            "android/security/keystore/KeyProperties",
            "SECURITY_LEVEL_TRUSTED_ENVIRONMENT",
        )?;
        let level_strongbox = self.get_static_int(
            env,
            "android/security/keystore/KeyProperties",
            "SECURITY_LEVEL_STRONGBOX",
        )?;

        let label = if level == level_software {
            "software"
        } else if level == level_tee {
            "trusted_environment"
        } else if level == level_strongbox {
            "strongbox"
        } else {
            "unknown"
        };
        Ok(label.to_string())
    }

    fn key_security_claims<'a>(
        &self,
        env: &mut JNIEnv<'a>,
        private_key: &JObject<'a>,
    ) -> Result<(Option<bool>, Option<String>, Option<String>)> {
        let sdk_int = self.get_sdk_int(env)?;
        if sdk_int < 31 {
            return Ok((None, None, None));
        }

        let key_info = self.get_key_info(env, private_key)?;
        let key_level = env
            .call_method(&key_info, "getSecurityLevel", "()I", &[])
            .and_then(|v| v.i())
            .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

        let level_strongbox = self.get_static_int(
            env,
            "android/security/keystore/KeyProperties",
            "SECURITY_LEVEL_STRONGBOX",
        )?;
        let strongbox_backed = Some(key_level == level_strongbox);
        let key_level_label = Some(self.security_level_label(env, key_level)?);

        let attestation_level = if sdk_int >= 33 {
            self.optional_key_info_int_method(env, &key_info, "getAttestationSecurityLevel")
        } else {
            None
        };
        let attestation_level_label = match attestation_level {
            Some(level) => Some(self.security_level_label(env, level)?),
            None => None,
        };

        Ok((strongbox_backed, key_level_label, attestation_level_label))
    }

    fn key_is_hardware_backed<'a>(
        &self,
        env: &mut JNIEnv<'a>,
        private_key: &JObject<'a>,
    ) -> Result<bool> {
        let key_info = self.get_key_info(env, private_key)?;

        let sdk_int = self.get_sdk_int(env)?;

        if sdk_int >= 31 {
            let level = env
                .call_method(&key_info, "getSecurityLevel", "()I", &[])
                .and_then(|v| v.i())
                .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;

            let level_tee = self.get_static_int(
                env,
                "android/security/keystore/KeyProperties",
                "SECURITY_LEVEL_TRUSTED_ENVIRONMENT",
            )?;
            let level_strongbox = self.get_static_int(
                env,
                "android/security/keystore/KeyProperties",
                "SECURITY_LEVEL_STRONGBOX",
            )?;

            Ok(level == level_tee || level == level_strongbox)
        } else {
            env.call_method(&key_info, "isInsideSecureHardware", "()Z", &[])
                .and_then(|v| v.z())
                .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))
        }
    }

    fn check_jvm_access(&self) -> Result<()> {
        self.with_env_activity(|env, activity| {
            let _ = env
                .call_method(activity, "getPackageName", "()Ljava/lang/String;", &[])
                .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }
}

impl DeviceKeyStore for AndroidHardwareKeyStore {
    fn initialize(&self) -> Result<()> {
        self.check_jvm_access()
    }

    fn backend_kind(&self) -> BackendKind {
        BackendKind::AndroidHardwareKeystore
    }

    fn hardware_protection(&self) -> HardwareProtection {
        HardwareProtection::Unknown
    }

    fn ensure_signing_key(&self, key_id: &str) -> Result<()> {
        if key_id.is_empty() {
            return Err(DeviceKeyStoreError::InvalidInput("empty key_id"));
        }

        let alias = Self::key_alias(key_id);
        self.with_env_activity(|env, activity| self.ensure_key_inner(env, &activity, &alias))
    }

    fn public_key_der(&self, key_id: &str) -> Result<Vec<u8>> {
        if key_id.is_empty() {
            return Err(DeviceKeyStoreError::InvalidInput("empty key_id"));
        }

        let alias = Self::key_alias(key_id);
        self.with_env_activity(|env, activity| {
            self.ensure_key_inner(env, &activity, &alias)?;
            self.get_certificate_public_key_der(env, &alias)
        })
    }

    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
        if key_id.is_empty() {
            return Err(DeviceKeyStoreError::InvalidInput("empty key_id"));
        }

        let alias = Self::key_alias(key_id);
        self.with_env_activity(|env, activity| {
            self.ensure_key_inner(env, &activity, &alias)?;
            self.sign_inner(env, &alias, payload)
        })
    }

    fn delete_signing_key(&self, key_id: &str) -> Result<()> {
        if key_id.is_empty() {
            return Err(DeviceKeyStoreError::InvalidInput("empty key_id"));
        }

        let alias = Self::key_alias(key_id);
        self.with_env_activity(|env, _activity| self.delete_alias_inner(env, &alias))
    }

    fn is_hardware_security_available(&self) -> Result<bool> {
        let alias = Self::key_alias(PROBE_KEY_ID);
        self.with_env_activity(|env, activity| {
            // Some OEM Android builds do not advertise keystore capability through
            // PackageManager features even though Android Keystore + TEE are usable.
            // Probe by creating/reading a key and checking its hardware security level.
            self.ensure_key_inner(env, &activity, &alias)?;
            let private_key = self.get_private_key(env, &alias)?;
            self.key_is_hardware_backed(env, &private_key)
        })
    }

    fn attestation(&self, key_id: &str, challenge: &[u8]) -> Result<Option<Vec<u8>>> {
        if key_id.is_empty() {
            return Err(DeviceKeyStoreError::InvalidInput("empty key_id"));
        }
        if challenge.is_empty() {
            return Err(DeviceKeyStoreError::InvalidInput("empty challenge"));
        }

        let alias = Self::key_alias(key_id);
        self.with_env_activity(|env, activity| {
            // Android keymaster providers can reject long attestation challenges.
            // Bind the cert extension challenge to the canonical payload digest.
            let attestation_challenge = Sha256::digest(challenge).to_vec();

            // Regenerate key with attestation challenge so leaf cert extension
            // cryptographically binds to the server nonce payload.
            self.delete_alias_inner(env, &alias)?;
            self.generate_signing_key(
                env,
                &activity,
                &alias,
                Some(attestation_challenge.as_slice()),
            )?;
            let private_key = self.get_private_key(env, &alias)?;
            let hardware_backed = self.key_is_hardware_backed(env, &private_key)?;
            let (strongbox_backed, key_security_level, attestation_security_level) =
                self.key_security_claims(env, &private_key)?;
            let public_key_der = self.get_certificate_public_key_der(env, &alias)?;

            let certificate_chain = self.get_certificate_chain_der(env, &alias)?;
            if certificate_chain.is_empty() {
                return Err(DeviceKeyStoreError::Backend(
                    "certificate chain is empty".to_string(),
                ));
            }
            let certificate_chain_der_b64 = certificate_chain
                .into_iter()
                .map(|cert| STANDARD.encode(cert))
                .collect::<Vec<_>>();

            let challenge_signature_der = self.sign_inner(env, &alias, challenge)?;
            let evidence = AndroidKeyAttestationEvidenceV1 {
                version: KEY_ATTESTATION_VERSION_V1,
                public_key_der_b64: STANDARD.encode(public_key_der),
                certificate_chain_der_b64,
                challenge_signature_der_b64: STANDARD.encode(challenge_signature_der),
                hardware_backed,
                strongbox_backed,
                key_security_level,
                attestation_security_level,
            };

            let encoded = serde_json::to_vec(&evidence)
                .map_err(|e| DeviceKeyStoreError::Backend(e.to_string()))?;
            Ok(Some(encoded))
        })
    }
}
