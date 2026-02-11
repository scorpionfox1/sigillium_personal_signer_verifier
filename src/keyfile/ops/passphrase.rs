// src/keyfile/ops/passphrase.rs

use std::path::Path;

use crate::{
    keyfile::{
        crypto::*,
        fs::write_json,
        types::{AadBytes, EncryptedString, KeyEntry, KeyfileData},
        validate::set_file_mac_in_place,
    },
    notices::{AppNotice, AppResult},
};

use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use super::read_json_verified_optional_mac;

pub fn change_passphrase(
    path: &Path,
    old_master_key: &[u8; 32],
    new_passphrase: &str,
) -> AppResult<[u8; 32]> {
    let mut data = read_json_verified_optional_mac(&path, old_master_key)?;

    let mut new_salt = [0u8; 16];
    OsRng.fill_bytes(&mut new_salt);
    let new_master = derive_encryption_key(new_passphrase, &new_salt)?;

    reencrypt_all_keys(&mut data, old_master_key, &new_master)?;

    data.salt = general_purpose::STANDARD.encode(new_salt);
    set_file_mac_in_place(&mut data, &new_master)?;
    write_json(&path, &data)?;
    Ok(new_master)
}

// ======================================================
// Internal helpers
// ======================================================

fn reencrypt_all_keys(
    data: &mut KeyfileData,
    old_master: &[u8; 32],
    new_master: &[u8; 32],
) -> AppResult<()> {
    let old_z = Zeroizing::new(*old_master);
    let new_z = Zeroizing::new(*new_master);

    for i in 0..data.keys.len() {
        // --- immutable phase: snapshot fields + build AADs ---
        let (id, domain, pk_hex) = {
            let k = &data.keys[i];
            (k.id, k.domain.clone(), k.public_key_hex.clone())
        };

        let aad_priv = aad_for_private_key(data, id, &domain, &pk_hex);
        let aad_assoc = aad_for_associated_key_id(data, id, &domain, &pk_hex);
        let aad_label = aad_for_label(data, id, &domain, &pk_hex);

        // --- mutable phase: mutate the entry ---
        let k = &mut data.keys[i];

        reencrypt_private_key(k, &aad_priv, &old_z, &new_z)?;
        reencrypt_string(&mut k.associated_key_id, &aad_assoc, &old_z, &new_z)?;
        reencrypt_string(&mut k.label, &aad_label, &old_z, &new_z)?;
    }

    Ok(())
}

fn reencrypt_private_key(
    k: &mut KeyEntry,
    aad_priv: &AadBytes,
    old_z: &Zeroizing<[u8; 32]>,
    new_z: &Zeroizing<[u8; 32]>,
) -> AppResult<()> {
    let nonce = decode_nonce12_b64(&k.key_nonce_b64)?;
    let ct = general_purpose::STANDARD
        .decode(&k.encrypted_private_key_b64)
        .map_err(|e| AppNotice::InvalidCiphertextBase64(e.to_string()))?;

    let mut pt = decrypt_bytes_with_aad(old_z, aad_priv, &nonce, &ct)?;

    let (n, ct) = encrypt_bytes_with_aad(new_z, aad_priv, &pt)?;
    pt.zeroize();

    k.key_nonce_b64 = general_purpose::STANDARD.encode(n);
    k.encrypted_private_key_b64 = general_purpose::STANDARD.encode(ct);
    Ok(())
}

fn reencrypt_string(
    field: &mut EncryptedString,
    aad: &AadBytes,
    old_z: &Zeroizing<[u8; 32]>,
    new_z: &Zeroizing<[u8; 32]>,
) -> AppResult<()> {
    let plain = decrypt_string_with_aad(old_z, aad, &field.nonce_b64, &field.ciphertext_b64)?;
    let (n, ct) = encrypt_string_with_aad(new_z, aad, &plain)?;
    field.nonce_b64 = n;
    field.ciphertext_b64 = ct;
    Ok(())
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyfile::{
        fs,
        ops::{
            inspect::{decrypt_key_material, list_key_meta, read_json_verified_optional_mac},
            test_support::mk_fixture_one_key,
        },
    };

    #[test]
    fn change_passphrase_preserves_key_material_and_label_and_rotates_salt_and_mac() {
        let f1 = mk_fixture_one_key("old-pass", "assoc-123").unwrap();

        // Snapshot pre-change facts
        let data_before = fs::read_json(&f1.fx.path).unwrap();
        let salt_before = data_before.salt.clone();

        let metas_before = list_key_meta(&f1.fx.path, &f1.fx.master_key).unwrap();
        assert_eq!(metas_before.len(), 1);
        let label_before = metas_before[0].label.clone();

        let (priv_before, assoc_before) =
            decrypt_key_material(&f1.fx.path, &f1.fx.master_key, f1.key_id).unwrap();
        assert_eq!(priv_before, f1.private);
        assert_eq!(assoc_before, "assoc-123");

        // Change passphrase
        let new_master = change_passphrase(&f1.fx.path, &f1.fx.master_key, "new-pass").unwrap();

        // Salt should rotate
        let data_after = fs::read_json(&f1.fx.path).unwrap();
        assert_ne!(data_after.salt, salt_before);

        // Old master should no longer verify/read when MAC is present
        assert!(read_json_verified_optional_mac(&f1.fx.path, &f1.fx.master_key).is_err());

        // New master should decrypt everything back to the same meaning
        let metas_after = list_key_meta(&f1.fx.path, &new_master).unwrap();
        assert_eq!(metas_after.len(), 1);
        assert_eq!(metas_after[0].label, label_before);

        let (priv_after, assoc_after) =
            decrypt_key_material(&f1.fx.path, &new_master, f1.key_id).unwrap();
        assert_eq!(priv_after, f1.private);
        assert_eq!(assoc_after, "assoc-123");
    }
}
