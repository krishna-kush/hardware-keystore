use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::Duration;
use tss_esapi::constants::PropertyTag;
use tss_esapi::structures::Public;
use tss_esapi::Context;

const TPM_MANUFACTURER_AMD: u32 = 0x414D_4400;
const TPM_MANUFACTURER_INTEL: u32 = 0x494E_5443;
const DEFAULT_RSA_EXPONENT: u32 = 65_537;
const HTTP_TIMEOUT_SECS: u64 = 5;
const INTEL_RSA_EXPONENT_DER: [u8; 3] = [0x01, 0x00, 0x01];
const AMD_RSA_HASH_PREFIX: [u8; 4] = [0x00, 0x00, 0x22, 0x22];
const AMD_ECC_HASH_PREFIX: [u8; 4] = [0x00, 0x00, 0x44, 0x44];
const AMD_EK_URL_BASE: &str = "https://ftpm.amd.com/pki/aia/";
const AMD_EK_URL_DER_SUFFIX: &str = ".cer";
const INTEL_EK_URL_INTEL_BASE: &str = "https://ekop.intel.com/ekcertservice/Intel/";
const INTEL_EK_URL_ONDIE_BASE: &str = "https://ekop.intel.com/ekcertservice/OnDieCA/";

static HTTP_CLIENT: OnceLock<Option<Client>> = OnceLock::new();

enum Manufacturer {
    Amd,
    Intel,
}

fn http_client() -> Option<&'static Client> {
    HTTP_CLIENT
        .get_or_init(|| {
            Client::builder()
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
                .build()
                .ok()
        })
        .as_ref()
}

fn detect_manufacturer(ctx: &mut Context) -> Option<Manufacturer> {
    let manufacturer = ctx
        .get_tpm_property(PropertyTag::Manufacturer)
        .ok()
        .flatten()?;
    match manufacturer {
        TPM_MANUFACTURER_AMD => Some(Manufacturer::Amd),
        TPM_MANUFACTURER_INTEL => Some(Manufacturer::Intel),
        _ => None,
    }
}

fn normalize_rsa_exponent(raw: u32) -> u32 {
    if raw == 0 {
        DEFAULT_RSA_EXPONENT
    } else {
        raw
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn intel_uri(public: &Public) -> Option<String> {
    let digest = match public {
        Public::Rsa {
            parameters, unique, ..
        } => {
            let exponent = normalize_rsa_exponent(parameters.exponent().value());
            if exponent != DEFAULT_RSA_EXPONENT {
                return None;
            }
            let mut buffer = Vec::with_capacity(unique.value().len() + 3);
            buffer.extend_from_slice(unique.value());
            buffer.extend_from_slice(INTEL_RSA_EXPONENT_DER.as_ref());
            sha256(buffer.as_slice())
        }
        Public::Ecc { unique, .. } => {
            let mut buffer =
                Vec::with_capacity(unique.x().value().len() + unique.y().value().len());
            buffer.extend_from_slice(unique.x().value());
            buffer.extend_from_slice(unique.y().value());
            sha256(buffer.as_slice())
        }
        _ => return None,
    };

    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_slice()))
}

fn amd_uri(public: &Public) -> Option<String> {
    let digest = match public {
        Public::Rsa {
            parameters, unique, ..
        } => {
            let exponent = normalize_rsa_exponent(parameters.exponent().value());
            let mut buffer = Vec::with_capacity(4 + 4 + unique.value().len());
            buffer.extend_from_slice(AMD_RSA_HASH_PREFIX.as_ref());
            buffer.extend_from_slice(exponent.to_be_bytes().as_ref());
            buffer.extend_from_slice(unique.value());
            sha256(buffer.as_slice())
        }
        Public::Ecc { unique, .. } => {
            let mut buffer =
                Vec::with_capacity(4 + unique.x().value().len() + unique.y().value().len());
            buffer.extend_from_slice(AMD_ECC_HASH_PREFIX.as_ref());
            buffer.extend_from_slice(unique.x().value());
            buffer.extend_from_slice(unique.y().value());
            sha256(buffer.as_slice())
        }
        _ => return None,
    };

    let truncated = digest.get(..16)?;
    Some(encode_hex_lower(truncated))
}

fn manufacturer_urls(public: &Public, manufacturer: Manufacturer) -> Option<Vec<String>> {
    match manufacturer {
        Manufacturer::Amd => {
            let uri = amd_uri(public)?;
            Some(vec![
                format!("{AMD_EK_URL_BASE}{uri}"),
                format!("{AMD_EK_URL_BASE}{uri}{AMD_EK_URL_DER_SUFFIX}"),
            ])
        }
        Manufacturer::Intel => {
            let uri = intel_uri(public)?;
            Some(vec![
                format!("{INTEL_EK_URL_INTEL_BASE}{uri}"),
                format!("{INTEL_EK_URL_ONDIE_BASE}{uri}"),
            ])
        }
    }
}

fn maybe_decode_pem_certificate(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.contains("-----BEGIN CERTIFICATE-----") {
        return None;
    }
    let body = text
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<String>();
    if body.is_empty() {
        return None;
    }
    STANDARD.decode(body.as_bytes()).ok()
}

fn fetch_first_available(urls: &[String]) -> Option<Vec<u8>> {
    let client = http_client()?;

    for url in urls {
        let response = match client.get(url).send() {
            Ok(resp) => resp,
            Err(_) => continue,
        };
        if !response.status().is_success() {
            continue;
        }
        let body = match response.bytes() {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => continue,
        };
        if body.is_empty() {
            continue;
        }
        if let Some(der) = maybe_decode_pem_certificate(body.as_slice()) {
            if !der.is_empty() {
                return Some(der);
            }
        }
        return Some(body);
    }

    None
}

pub(super) fn retrieve(ctx: &mut Context, ek_public: &Public) -> Option<Vec<u8>> {
    let manufacturer = detect_manufacturer(ctx)?;
    let urls = manufacturer_urls(ek_public, manufacturer)?;
    fetch_first_available(urls.as_slice())
}
