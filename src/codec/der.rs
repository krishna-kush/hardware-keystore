use crate::core::error::{DeviceKeyStoreError, Result};

fn encode_der_length(len: usize) -> Result<Vec<u8>> {
    if len < 0x80 {
        return Ok(vec![len as u8]);
    }

    let mut bytes = Vec::new();
    let mut value = len;
    while value > 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    bytes.reverse();

    if bytes.len() > 4 {
        return Err(DeviceKeyStoreError::Backend(
            "DER length encoding overflow".to_string(),
        ));
    }

    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(0x80 | (bytes.len() as u8));
    out.extend_from_slice(&bytes);
    Ok(out)
}

fn encode_der_tlv(tag: u8, value: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 5 + value.len());
    out.push(tag);
    out.extend(encode_der_length(value.len())?);
    out.extend_from_slice(value);
    Ok(out)
}

fn encode_der_integer(value: &[u8]) -> Result<Vec<u8>> {
    let mut trimmed = value;
    while trimmed.len() > 1 && trimmed[0] == 0 {
        trimmed = &trimmed[1..];
    }

    let mut encoded = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.is_empty() {
        encoded.push(0);
    } else {
        if trimmed[0] & 0x80 != 0 {
            encoded.push(0);
        }
        encoded.extend_from_slice(trimmed);
    }

    encode_der_tlv(0x02, &encoded)
}

pub fn ecdsa_rs_to_der(r: &[u8], s: &[u8]) -> Result<Vec<u8>> {
    let r = encode_der_integer(r)?;
    let s = encode_der_integer(s)?;
    let mut seq = Vec::with_capacity(r.len() + s.len());
    seq.extend_from_slice(&r);
    seq.extend_from_slice(&s);
    encode_der_tlv(0x30, &seq)
}

pub fn ecc_xy_to_spki_der(x: &[u8], y: &[u8]) -> Result<Vec<u8>> {
    let mut uncompressed = Vec::with_capacity(1 + x.len() + y.len());
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(x);
    uncompressed.extend_from_slice(y);

    let mut algorithm = Vec::new();
    algorithm.extend(encode_der_tlv(
        0x06,
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01],
    )?);
    algorithm.extend(encode_der_tlv(
        0x06,
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    )?);
    let algorithm_seq = encode_der_tlv(0x30, &algorithm)?;

    let mut subject_key_value = Vec::with_capacity(1 + uncompressed.len());
    subject_key_value.push(0x00);
    subject_key_value.extend_from_slice(&uncompressed);
    let subject_key = encode_der_tlv(0x03, &subject_key_value)?;

    let mut spki = Vec::with_capacity(algorithm_seq.len() + subject_key.len());
    spki.extend_from_slice(&algorithm_seq);
    spki.extend_from_slice(&subject_key);
    encode_der_tlv(0x30, &spki)
}
