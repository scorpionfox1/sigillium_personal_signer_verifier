// src/keyfile/ops/inspect.rs

use std::path::Path;

use crate::{
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
    types::{KeyId, KeyMeta, KeyfileState},
};

use base64::{engine::general_purpose, Engine};
use hex;
use zeroize::{Zeroize, Zeroizing};

use super::{aad_for_label, decrypt_string_with_aad};

pub fn list_key_meta(path: &Path, master_key: &[u8; 32]) -> AppResult<Vec<KeyMeta>> {
    let data = read_json_verified_optional_mac(&path, master_key)?;

    let master_key_z = Zeroizing::new(*master_key);
    let mut out = Vec::with_capacity(data.keys.len());

    for k in &data.keys {
        let pk_bytes = hex::decode(&k.public_key_hex).map_err(|_| AppError::InvalidPublicKeyHex)?;
        if pk_bytes.len() != 32 {
            return Err(AppError::InvalidPublicKeyLength);
        }

        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);

        let aad = aad_for_label(&data, k.id, &k.domain, &k.public_key_hex);
        let label = decrypt_string_with_aad(
            &master_key_z,
            &aad,
            &k.label.nonce_b64,
            &k.label.ciphertext_b64,
        )?
        .to_string();

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

pub fn check_keyfile_state(path: &Path) -> Result<KeyfileState, AppError> {
    if !path.exists() {
        return Ok(KeyfileState::Missing);
    }

    let data = read_json(&path)?;
    validate_keyfile_structure(&data)?;

    Ok(KeyfileState::NotCorrupted)
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

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyfile::ops::test_support::{mk_fixture, mk_fixture_one_key};
    use crate::keyfile::{fs, validate::set_file_mac_in_place};

    #[test]
    fn check_keyfile_state_missing_valid_and_corrupt() {
        // Missing
        let fx = mk_fixture("passphrase").unwrap();
        let missing = fx.dir.join("does_not_exist.json");
        assert!(matches!(
            check_keyfile_state(&missing).unwrap(),
            KeyfileState::Missing
        ));

        // Valid
        assert!(matches!(
            check_keyfile_state(&fx.path).unwrap(),
            KeyfileState::NotCorrupted
        ));

        // Corrupt (invalid JSON)
        std::fs::write(&fx.path, b"{not-json").unwrap();
        assert!(check_keyfile_state(&fx.path).is_err());
    }

    #[test]
    fn list_key_meta_returns_expected_label_and_public_key() {
        let f1 = mk_fixture_one_key("passphrase", "assoc-123").unwrap();

        let metas = list_key_meta(&f1.fx.path, &f1.fx.master_key).unwrap();
        assert_eq!(metas.len(), 1);

        let m = &metas[0];
        assert_eq!(m.id, f1.key_id);
        assert_eq!(m.domain, f1.domain);
        assert_eq!(m.public_key, f1.public);
        assert_eq!(m.label, f1.label);
    }

    #[test]
    fn decrypt_key_material_returns_private_and_associated_id() {
        let f1 = mk_fixture_one_key("passphrase", "assoc-123").unwrap();

        let (privk, assoc) =
            decrypt_key_material(&f1.fx.path, &f1.fx.master_key, f1.key_id).unwrap();

        assert_eq!(privk, f1.private);
        assert_eq!(assoc, "assoc-123");
    }

    #[test]
    fn read_json_verified_optional_mac_rejects_tampered_file_when_mac_present() {
        let f1 = mk_fixture_one_key("passphrase", "assoc-123").unwrap();

        // Ensure a MAC is present (append_key normally sets it, but make explicit)
        let mut data = fs::read_json(&f1.fx.path).unwrap();
        set_file_mac_in_place(&mut data, &f1.fx.master_key).unwrap();
        fs::write_json(&f1.fx.path, &data).unwrap();

        // Tamper with JSON content without updating MAC
        let mut tampered = fs::read_json(&f1.fx.path).unwrap();
        tampered.keys[0].domain = "tampered.example".to_string();
        fs::write_json(&f1.fx.path, &tampered).unwrap();

        let res = read_json_verified_optional_mac(&f1.fx.path, &f1.fx.master_key);
        assert!(res.is_err());
    }
}
