// src/keyfile/ops/mutation.rs

use std::path::Path;

use crate::{
    keyfile::{
        crypto::*,
        fs::write_json,
        types::{EncryptedString, KeyEntry},
        validate::set_file_mac_in_place,
    },
    notices::{AppNotice, AppResult},
    types::KeyId,
};

use base64::{engine::general_purpose, Engine as _};
use zeroize::Zeroizing;

use super::read_json_verified_optional_mac;

pub fn append_key(
    path: &Path,
    master_key: &[u8; 32],
    domain: &str,
    label: &str,
    private_key: &[u8; 32],
    public_key: &[u8; 32],
    associated_key_id: &str,
) -> AppResult<()> {
    let mut data = read_json_verified_optional_mac(&path, master_key)?;

    let next_id = data.keys.iter().map(|k| k.id).max().unwrap_or(0) + 1;
    let public_key_hex = hex::encode(public_key);
    let master_key_z = Zeroizing::new(*master_key);

    let label_enc = encrypt_string_with_aad(
        &master_key_z,
        &aad_for_label(&data, next_id, domain, &public_key_hex),
        &Zeroizing::new(label.to_owned()),
    )?;

    let (nonce_bytes, ciphertext) = encrypt_bytes_with_aad(
        &master_key_z,
        &aad_for_private_key(&data, next_id, domain, &public_key_hex),
        &Zeroizing::new(private_key.to_vec()),
    )?;

    let enc = encrypt_string_with_aad(
        &master_key_z,
        &aad_for_associated_key_id(&data, next_id, domain, &public_key_hex),
        &Zeroizing::new(associated_key_id.to_owned()), // may be ""
    )?;

    let associated = EncryptedString {
        nonce_b64: enc.0,
        ciphertext_b64: enc.1,
    };

    data.keys.push(KeyEntry {
        id: next_id,
        domain: domain.to_string(),
        public_key_hex,
        key_nonce_b64: general_purpose::STANDARD.encode(nonce_bytes),
        encrypted_private_key_b64: general_purpose::STANDARD.encode(ciphertext),
        associated_key_id: associated,
        label: EncryptedString {
            nonce_b64: label_enc.0,
            ciphertext_b64: label_enc.1,
        },
    });

    set_file_mac_in_place(&mut data, master_key)?;
    write_json(&path, &data)
}

pub fn remove_key(path: &Path, master_key: &[u8; 32], key_id: KeyId) -> AppResult<()> {
    let mut data = read_json_verified_optional_mac(&path, master_key)?;

    let before = data.keys.len();
    data.keys.retain(|k| k.id != key_id);
    if before == data.keys.len() {
        return Err(AppNotice::KeyfileKeyIdNotFound);
    }

    set_file_mac_in_place(&mut data, master_key)?;
    write_json(&path, &data)
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyfile::ops::test_support::{mk_fixture, mk_fixture_one_key};
    use crate::notices::AppNotice;
    use base64::engine::general_purpose;
    use zeroize::Zeroizing;

    fn max_id(data: &crate::keyfile::types::KeyfileData) -> u64 {
        data.keys.iter().map(|k| k.id as u64).max().unwrap_or(0)
    }

    #[test]
    fn id_max_changes_with_deletions_and_next_id_is_max_plus_one() {
        let fx = mk_fixture("passphrase").unwrap();

        // Add 3 keys => ids 1,2,3
        append_key(
            &fx.path,
            &fx.master_key,
            "k1.com",
            "K1",
            &[1u8; 32],
            &[1u8; 32],
            "",
        )
        .unwrap();
        append_key(
            &fx.path,
            &fx.master_key,
            "k2.com",
            "K2",
            &[2u8; 32],
            &[2u8; 32],
            "",
        )
        .unwrap();
        append_key(
            &fx.path,
            &fx.master_key,
            "k3.com",
            "K3",
            &[3u8; 32],
            &[3u8; 32],
            "",
        )
        .unwrap();

        let data = read_json_verified_optional_mac(&fx.path, &fx.master_key).unwrap();
        assert_eq!(max_id(&data), 3);

        // Delete 2 => remaining 1,3 => max still 3
        remove_key(&fx.path, &fx.master_key, 2).unwrap();
        let data = read_json_verified_optional_mac(&fx.path, &fx.master_key).unwrap();
        assert_eq!(max_id(&data), 3);

        // Delete 3 => remaining 1 => max now 1
        remove_key(&fx.path, &fx.master_key, 3).unwrap();
        let data = read_json_verified_optional_mac(&fx.path, &fx.master_key).unwrap();
        assert_eq!(max_id(&data), 1);

        // Next append => id should be 2 (max+1)
        append_key(
            &fx.path,
            &fx.master_key,
            "k4.com",
            "K4",
            &[4u8; 32],
            &[4u8; 32],
            "",
        )
        .unwrap();

        let data = read_json_verified_optional_mac(&fx.path, &fx.master_key).unwrap();
        let k4 = data.keys.iter().find(|k| k.domain == "k4.com").unwrap();
        assert_eq!(k4.id, 2);
    }

    #[test]
    fn append_encrypts_label_and_private_key_decryptable() {
        let f1 = mk_fixture_one_key("passphrase", "assoc-123").unwrap();
        let fx = &f1.fx;

        let data = read_json_verified_optional_mac(&fx.path, &fx.master_key).unwrap();
        let k = data.keys.iter().find(|k| k.id == f1.key_id).unwrap();

        let mkz = Zeroizing::new(fx.master_key);

        // label decrypt
        let label_pt = decrypt_string_with_aad(
            &mkz,
            &aad_for_label(&data, k.id, &k.domain, &k.public_key_hex),
            &k.label.nonce_b64,
            &k.label.ciphertext_b64,
        )
        .unwrap();
        assert_eq!(label_pt.as_str(), f1.label.as_str());

        // private decrypt
        let nonce12 = decode_nonce12_b64(&k.key_nonce_b64).unwrap();
        let ct = general_purpose::STANDARD
            .decode(&k.encrypted_private_key_b64)
            .unwrap();

        let pt = decrypt_bytes_with_aad(
            &mkz,
            &aad_for_private_key(&data, k.id, &k.domain, &k.public_key_hex),
            &nonce12,
            &ct,
        )
        .unwrap();

        assert_eq!(pt.as_slice(), f1.private.as_slice());
    }

    #[test]
    fn remove_key_errors_if_missing() {
        let fx = mk_fixture("passphrase").unwrap();
        let err = remove_key(&fx.path, &fx.master_key, 999).unwrap_err();
        assert!(matches!(err, AppNotice::KeyfileKeyIdNotFound));
    }
}
