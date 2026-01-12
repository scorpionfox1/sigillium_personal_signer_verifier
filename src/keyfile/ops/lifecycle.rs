// src/keyfile/ops/lifecycle.rs

use crate::{
    context::APP_ID,
    error::{AppError, AppResult},
    keyfile::{
        crypto::*,
        fs::{read_json, write_json},
        types::{KeyfileData, KEYFILE_FORMAT, KEYFILE_VERSION},
    },
};

use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::Path;

pub fn write_blank_keyfile(path: &Path) -> AppResult<()> {
    if path.exists() {
        return Err(AppError::KeyfileAlreadyExists);
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
        .map_err(|e| AppError::InvalidCiphertextBase64(e.to_string()))?;

    if salt.len() != 16 {
        return Err(AppError::InvalidSaltLength { len: salt.len() });
    }

    let mut salt_arr = [0u8; 16];
    salt_arr.copy_from_slice(&salt);

    derive_encryption_key(passphrase, &salt_arr)
}

// Best-effort self-destruct of a tombstoned keyfile.
//
// This owns the *mechanics* (fsync + secure delete),
// while the command layer owns logging and policy.
pub fn self_destruct_best_effort(
    tombstone: &Path,
    parent_dir: &Path,
) -> (Result<(), String>, Vec<crate::platform::BestEffortFailure>) {
    let mut warns = Vec::new();

    if let Some(w) = crate::platform::fsync_dir_best_effort(parent_dir) {
        warns.push(w);
    }

    let (res, mut w) = crate::platform::secure_delete_best_effort(tombstone);
    warns.append(&mut w);

    (res, warns)
}

pub fn cleanup_delete_tombstones(dir: &Path) -> AppResult<Vec<crate::platform::BestEffortFailure>> {
    use std::fs;

    let mut warns: Vec<crate::platform::BestEffortFailure> = Vec::new();

    if !dir.exists() {
        return Ok(warns);
    }

    let rd = fs::read_dir(dir).map_err(|e| AppError::KeyfileFsReadFailed(e.to_string()))?;

    for ent in rd {
        let ent = ent.map_err(|e| AppError::KeyfileFsReadFailed(e.to_string()))?;
        let path = ent.path();

        if !path.is_file() {
            continue;
        }

        let name = ent.file_name();
        let name = name.to_string_lossy();

        if !name.starts_with(".delete-") && !name.starts_with(".keyfile.deleted.") {
            continue;
        }

        let (res, w) = crate::platform::secure_delete_best_effort(&path);
        warns.extend(w);

        if res.is_err() {
            warns.push(crate::platform::BestEffortFailure {
                kind: "cleanup_secure_delete_failed",
                errno: None,
                msg: "cleanup secure_delete_best_effort failed; will retry later",
            });
        }
    }

    Ok(warns)
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::APP_ID;
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
        let path = dir.join("keyfile.json");

        write_blank_keyfile(&path).unwrap();

        // Second create should fail
        let err = write_blank_keyfile(&path).unwrap_err();
        assert!(matches!(err, AppError::KeyfileAlreadyExists));

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
        let path = dir.join("keyfile.json");

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
        assert!(matches!(err, AppError::InvalidSaltLength { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_delete_tombstones_does_not_touch_normal_files() {
        let dir = std::env::temp_dir().join(format!(
            "sigillium-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let normal = dir.join("normal.txt");
        let tomb1 = dir.join(".delete-abc");
        let tomb2 = dir.join(".keyfile.deleted.xyz");

        std::fs::write(&normal, b"ok").unwrap();
        std::fs::write(&tomb1, b"tomb").unwrap();
        std::fs::write(&tomb2, b"tomb").unwrap();

        let _warns = cleanup_delete_tombstones(&dir).unwrap();

        // Normal file must remain.
        assert!(normal.exists());

        // Tombstones may or may not be removed depending on platform best-effort behavior.
        // We don't assert on their existence here.

        let _ = std::fs::remove_dir_all(&dir);
    }
}
