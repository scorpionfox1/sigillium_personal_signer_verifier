// src/keyfile/ops/lifecycle.rs

use crate::{
    context::APP_ID,
    keyfile::{
        crypto::*,
        fs::{read_json, write_json},
        types::{KeyfileData, KEYFILE_FORMAT, KEYFILE_VERSION},
    },
    notices::{AppNotice, AppResult},
};

use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::Path;

pub fn write_blank_keyfile(path: &Path) -> AppResult<()> {
    if path.exists() {
        return Err(AppNotice::KeyfileAlreadyExists);
    }

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let data = KeyfileData {
        version: KEYFILE_VERSION,
        format: KEYFILE_FORMAT.to_string(),
        app: APP_ID.to_string(),
        salt: general_purpose::STANDARD.encode(salt),
        file_mac_b64: None,
        keys: vec![],
    };

    write_json(&path, &data)
}

pub fn read_master_key(path: &Path, passphrase: &str) -> AppResult<[u8; 32]> {
    let data = read_json(&path)?;
    let salt = general_purpose::STANDARD
        .decode(&data.salt)
        .map_err(|e| AppNotice::InvalidCiphertextBase64(e.to_string()))?;

    if salt.len() != 16 {
        return Err(AppNotice::InvalidSaltLength { len: salt.len() });
    }

    let mut salt_arr = [0u8; 16];
    salt_arr.copy_from_slice(&salt);

    derive_encryption_key(passphrase, &salt_arr)
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::APP_ID;
    use crate::keyfile::KEYFILE_FILENAME;
    use crate::keyfile::{fs, types::KeyfileData, types::KEYFILE_FORMAT, types::KEYFILE_VERSION};
    use base64::engine::general_purpose;

    #[test]
    fn write_blank_keyfile_creates_once_and_has_expected_shape() {
        let dir = std::env::temp_dir().join(format!(
            "sigillium-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(KEYFILE_FILENAME);

        write_blank_keyfile(&path).unwrap();

        // Second create should fail
        let err = write_blank_keyfile(&path).unwrap_err();
        assert!(matches!(err, AppNotice::KeyfileAlreadyExists));

        // Shape sanity
        let data = fs::read_json(&path).unwrap();
        assert_eq!(data.version, KEYFILE_VERSION);
        assert_eq!(data.format, KEYFILE_FORMAT.to_string());
        assert_eq!(data.app, APP_ID.to_string());
        assert!(data.file_mac_b64.is_none());
        assert!(data.keys.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_master_key_rejects_invalid_salt_length() {
        let dir = std::env::temp_dir().join(format!(
            "sigillium-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(KEYFILE_FILENAME);

        // 15 bytes instead of 16
        let bad_salt = [0u8; 15];

        let data = KeyfileData {
            version: KEYFILE_VERSION,
            format: KEYFILE_FORMAT.to_string(),
            app: APP_ID.to_string(),
            salt: general_purpose::STANDARD.encode(bad_salt),
            file_mac_b64: None,
            keys: vec![],
        };

        fs::write_json(&path, &data).unwrap();

        let err = read_master_key(&path, "passphrase").unwrap_err();
        assert!(matches!(err, AppNotice::InvalidSaltLength { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
