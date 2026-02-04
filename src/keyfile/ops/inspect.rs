// src/keyfile/ops/inspect.rs

use std::path::Path;

use crate::{
    crypto as app_crypto,
    error::{AppError, AppResult},
    keyfile::{
        crypto::{
            aad_for_associated_key_id, aad_for_private_key, decode_nonce12_b64,
            decrypt_bytes_with_aad,
        },
        fs::read_json,
        validate::{validate_keyfile_structure, verify_file_mac},
        KeyEntry, KeyfileData,
    },
    types::{KeyId, KeyMeta},
};

use base64::{engine::general_purpose, Engine};
use zeroize::{Zeroize, Zeroizing};

use super::{aad_for_label, decrypt_string_with_aad};

pub fn list_key_meta(path: &Path, master_key: &[u8; 32]) -> AppResult<Vec<KeyMeta>> {
    let data = read_json_verified_optional_mac(&path, master_key)?;

    let master_key_z = Zeroizing::new(*master_key);
    let mut out = Vec::with_capacity(data.keys.len());

    for k in &data.keys {
        let pk = app_crypto::decode_public_key_hex(&k.public_key_hex)?;

        let aad = aad_for_label(&data, k.id, &k.domain, &k.public_key_hex);
        let label = decrypt_string_with_aad(
            &master_key_z,
            &aad,
            &k.label.nonce_b64,
            &k.label.ciphertext_b64,
        )?;

        out.push(KeyMeta {
            id: k.id,
            domain: k.domain.clone(),
            public_key: pk,
            label,
        });
    }

    Ok(out)
}

pub fn decrypt_key_material(
    path: &Path,
    master_key: &[u8; 32],
    key_id: KeyId,
) -> AppResult<([u8; 32], String)> {
    let data = read_json_verified_optional_mac(path, master_key)?;
    let entry = data
        .keys
        .iter()
        .find(|k| k.id == key_id)
        .ok_or(AppError::KeyfileKeyIdNotFound)?;

    let master_key_z = Zeroizing::new(*master_key);

    let privkey = decrypt_private_key_field(&data, entry, &master_key_z)?;

    let associated = decrypt_string_with_aad(
        &master_key_z,
        &aad_for_associated_key_id(&data, entry.id, &entry.domain, &entry.public_key_hex),
        &entry.associated_key_id.nonce_b64,
        &entry.associated_key_id.ciphertext_b64,
    )?
    .to_string();

    Ok((privkey, associated))
}

fn decrypt_private_key_field(
    data: &KeyfileData,
    entry: &KeyEntry,
    master_key: &Zeroizing<[u8; 32]>,
) -> AppResult<[u8; 32]> {
    let nonce = decode_nonce12_b64(&entry.key_nonce_b64)?;
    let ct = general_purpose::STANDARD
        .decode(&entry.encrypted_private_key_b64)
        .map_err(|e| AppError::InvalidCiphertextBase64(e.to_string()))?;

    let mut pt = decrypt_bytes_with_aad(
        master_key,
        &aad_for_private_key(data, entry.id, &entry.domain, &entry.public_key_hex),
        &nonce,
        &ct,
    )?;

    if pt.len() != 32 {
        pt.zeroize();
        return Err(AppError::KeyfileCorrupt);
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&pt);
    pt.zeroize();
    Ok(out)
}

pub fn inspect_keyfile(path: &Path) -> AppResult<()> {
    if !path.exists() {
        return Err(AppError::KeyfileMissing);
    }

    let data = read_json(path)?;
    validate_keyfile_structure(&data)?;
    Ok(())
}

pub fn read_json_verified_optional_mac(
    path: &Path,
    master_key: &[u8; 32],
) -> AppResult<KeyfileData> {
    let data = read_json(path)?;
    validate_keyfile_structure(&data)?;
    verify_optional_mac(&data, master_key)?;
    Ok(data)
}

// ======================================================
// Internal Helpers
// ======================================================

fn verify_optional_mac(data: &KeyfileData, master_key: &[u8; 32]) -> AppResult<()> {
    if let Some(mac_b64) = &data.file_mac_b64 {
        verify_file_mac(data, master_key, mac_b64)?;
    }
    Ok(())
}
