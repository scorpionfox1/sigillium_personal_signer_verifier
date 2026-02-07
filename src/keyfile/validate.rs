// src/keyfile/validate.rs

use crate::crypto as app_crypto;
use crate::keyfile::crypto::decode_nonce12_b64;
use crate::keyfile::fs::read_json;
use crate::keyfile::types::KeyfileData;
use crate::notices::{AppNotice, AppResult};
use crate::types::KeyId;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashSet;
use std::path::Path;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub fn validate_keyfile_structure_on_disk(path: &Path) -> AppResult<()> {
    let data = read_json(path)?;
    validate_keyfile_structure(&data)
}

pub fn verify_keyfile_mac_on_disk(path: &Path, master_key: &[u8; 32]) -> AppResult<()> {
    let data = read_json(path)?;
    validate_keyfile_structure(&data)?;

    let mac_b64 = data
        .file_mac_b64
        .as_deref()
        .ok_or(AppNotice::KeyfileMacMissing)?;

    verify_file_mac(&data, master_key, mac_b64)
}

pub(crate) fn validate_keyfile_structure(data: &KeyfileData) -> AppResult<()> {
    // salt must decode to 16 bytes
    decode_b64_exact_len(&data.salt, 16, AppNotice::KeyfileStructCorrupted)?;

    // if present, mac must decode to 32 bytes
    if let Some(mac_b64) = &data.file_mac_b64 {
        decode_b64_exact_len(mac_b64, 32, AppNotice::KeyfileMacInvalid)?;
    }

    // key ids must be unique; key material fields must decode with expected lengths.
    let mut seen_ids: HashSet<KeyId> = HashSet::new();
    for k in data.keys.iter() {
        if !seen_ids.insert(k.id) {
            return Err(AppNotice::KeyfileStructCorrupted);
        }

        app_crypto::decode_public_key_hex(&k.public_key_hex)?;

        // nonce is always 12 bytes for ChaCha20-Poly1305
        decode_nonce12_b64(&k.key_nonce_b64)?;

        // ciphertext must be base64 decodable (length can vary)
        decode_b64(&k.encrypted_private_key_b64)?;

        // associated_key_id is required now
        decode_nonce12_b64(&k.associated_key_id.nonce_b64)?;
        decode_b64(&k.associated_key_id.ciphertext_b64)?;

        // label is required too (keep if you already validate it elsewhere; if not, add similarly)
        decode_nonce12_b64(&k.label.nonce_b64)?;
        decode_b64(&k.label.ciphertext_b64)?;
    }

    Ok(())
}

pub(crate) fn set_file_mac_in_place(
    data: &mut KeyfileData,
    master_key: &[u8; 32],
) -> AppResult<()> {
    let mac = compute_file_mac_bytes(data, master_key)?;
    data.file_mac_b64 = Some(general_purpose::STANDARD.encode(mac));
    Ok(())
}

pub(crate) fn verify_file_mac(
    data: &KeyfileData,
    master_key: &[u8; 32],
    expected_b64: &str,
) -> AppResult<()> {
    let expected_vec = decode_b64_exact_len(expected_b64, 32, AppNotice::KeyfileMacInvalid)?;
    let expected = to_arr32(&expected_vec);

    let actual = compute_file_mac_bytes(data, master_key)?;

    if expected.ct_eq(&actual).unwrap_u8() == 0 {
        return Err(AppNotice::KeyfileMacInvalid);
    }

    Ok(())
}

fn decode_b64(value: &str) -> AppResult<Vec<u8>> {
    general_purpose::STANDARD
        .decode(value)
        .map_err(|e| AppNotice::InvalidCiphertextBase64(e.to_string()))
}

fn decode_b64_exact_len(value: &str, len: usize, err: AppNotice) -> AppResult<Vec<u8>> {
    let decoded = decode_b64(value)?;
    if decoded.len() != len {
        return Err(err);
    }
    Ok(decoded)
}

fn to_arr32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

fn mac_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(master_key).expect("hmac key length invariant");
    mac.update(b"sigillium-keyfile-mac");
    let out = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out[..32]);
    k
}

fn compute_file_mac_bytes(data: &KeyfileData, master_key: &[u8; 32]) -> AppResult<[u8; 32]> {
    // mac is computed over canonical JSON without file_mac_b64 set
    let tmp = KeyfileData {
        version: data.version,
        format: data.format.clone(),
        app: data.app.clone(),
        salt: data.salt.clone(),
        file_mac_b64: None,
        keys: data.keys.clone(),
    };

    let canon = serde_json::to_vec(&tmp).map_err(|e| AppNotice::InvalidJson(e.to_string()))?;

    let mac_key = mac_key_from_master(master_key);
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&mac_key).map_err(|_| AppNotice::CryptoInitFailed)?;
    mac.update(&canon);
    let out = mac.finalize().into_bytes();

    let mut r = [0u8; 32];
    r.copy_from_slice(&out[..32]);
    Ok(r)
}
