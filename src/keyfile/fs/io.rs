// src/keyfile/fs/io.rs

use crate::context::APP_ID;
use crate::error::{AppError, AppResult};
use crate::keyfile::types::{KeyfileData, KEYFILE_FORMAT, KEYFILE_VERSION};

use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const KEYFILE_MAX_BYTES: u64 = 1 * 1024 * 1024;

pub(crate) fn read_json(path: &Path) -> AppResult<KeyfileData> {
    let meta = fs::metadata(path).map_err(|e| AppError::KeyfileFsReadFailed(e.to_string()))?;

    let bytes = meta.len();
    if bytes > KEYFILE_MAX_BYTES {
        return Err(AppError::KeyfileFsTooLarge {
            bytes,
            max: KEYFILE_MAX_BYTES,
        });
    }

    let text =
        fs::read_to_string(path).map_err(|e| AppError::KeyfileFsReadFailed(e.to_string()))?;

    let data: KeyfileData =
        serde_json::from_str(&text).map_err(|e| AppError::KeyfileFsInvalidJson(e.to_string()))?;

    if data.version != KEYFILE_VERSION {
        return Err(AppError::KeyfileFsUnsupportedVersion {
            got: data.version,
            expected: KEYFILE_VERSION,
        });
    }

    if data.format != KEYFILE_FORMAT || data.app != APP_ID {
        return Err(AppError::KeyfileFsMarkerMismatch);
    }

    Ok(data)
}

pub(crate) fn write_json(path: &Path, data: &KeyfileData) -> AppResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::KeyfileFsWriteFailed("invalid keyfile path".to_string()))?;

    let json = serde_json::to_vec_pretty(data)
        .map_err(|e| AppError::KeyfileFsWriteFailed(e.to_string()))?;

    let mut rnd = [0u8; 12];
    OsRng.fill_bytes(&mut rnd);
    let tmp = parent.join(format!(".keyfile.{}.tmp", hex::encode(rnd)));

    debug_assert_eq!(
        tmp.parent(),
        path.parent(),
        "temp file must be in same directory for atomic rename"
    );

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }

    let mut f = opts
        .open(&tmp)
        .map_err(|e| AppError::KeyfileFsWriteFailed(e.to_string()))?;

    let write_res: AppResult<()> = (|| {
        f.write_all(&json)
            .map_err(|e| AppError::KeyfileFsWriteFailed(e.to_string()))?;

        f.flush()
            .map_err(|e| AppError::KeyfileFsSyncFailed(e.to_string()))?;
        f.sync_all()
            .map_err(|e| AppError::KeyfileFsSyncFailed(e.to_string()))?;

        crate::platform::rename_replace(&tmp, path)
            .map_err(|e| AppError::KeyfileFsRenameFailed(e.to_string()))?;

        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp);
    }

    write_res?;

    Ok(())
}

pub fn backup_keyfile_with_quarantine_prefix(keyfile_path: &Path) -> AppResult<PathBuf> {
    let parent = keyfile_path
        .parent()
        .ok_or_else(|| AppError::KeyfileFsBackupFailed("invalid keyfile path".to_string()))?;

    if !keyfile_path.exists() {
        return Err(AppError::KeyfileMissingOrCorrupted);
    }

    let fname = keyfile_path
        .file_name()
        .ok_or_else(|| AppError::KeyfileFsBackupFailed("invalid keyfile path".to_string()))?
        .to_string_lossy()
        .to_string();

    for i in 0u32..10_000u32 {
        let candidate_name = if i == 0 {
            format!("quarantine.{fname}")
        } else {
            format!("quarantine.{i}.{fname}")
        };

        let candidate_path = parent.join(candidate_name);

        if candidate_path.exists() {
            continue;
        }

        match fs::rename(keyfile_path, &candidate_path) {
            Ok(()) => {
                // Best-effort parent dir sync (do not fail if it doesn't work).
                if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
                    let _ = dir.sync_all();
                }
                return Ok(candidate_path);
            }
            Err(e) => {
                if candidate_path.exists() {
                    continue;
                }
                return Err(AppError::KeyfileFsBackupFailed(e.to_string()));
            }
        }
    }

    Err(AppError::KeyfileFsBackupExhausted)
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::APP_ID;
    use crate::error::AppError;
    use crate::keyfile::types::{KeyfileData, KEYFILE_FORMAT, KEYFILE_VERSION};
    use crate::keyfile::KEYFILE_FILENAME;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn mk_temp_dir(tag: &str) -> PathBuf {
        let mut rnd = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut rnd);
        let dir = std::env::temp_dir().join(format!("sigillium_test_{}_{}", tag, hex::encode(rnd)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mk_min_keyfile_data() -> KeyfileData {
        KeyfileData {
            version: KEYFILE_VERSION,
            format: KEYFILE_FORMAT.to_string(),
            app: APP_ID.to_string(),
            // base64(16) all-zeros
            salt: "AAAAAAAAAAAAAAAAAAAAAA==".to_string(),
            file_mac_b64: None,
            keys: vec![],
        }
    }

    fn list_tmp_keyfile_files(dir: &Path) -> Vec<PathBuf> {
        let mut out = vec![];
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    if name.starts_with(".keyfile.") && name.ends_with(".tmp") {
                        out.push(p);
                    }
                }
            }
        }
        out
    }

    #[test]
    fn write_then_read_roundtrip_ok() {
        let dir = mk_temp_dir("io_roundtrip");
        let path = dir.join(KEYFILE_FILENAME);

        let data = mk_min_keyfile_data();
        write_json(&path, &data).unwrap();

        let got = read_json(&path).unwrap();
        assert_eq!(got.version, KEYFILE_VERSION);
        assert_eq!(got.format, KEYFILE_FORMAT);
        assert_eq!(got.app, APP_ID);
        assert_eq!(got.salt, data.salt);
        assert!(got.keys.is_empty());
    }

    #[test]
    fn read_rejects_unsupported_version() {
        let dir = mk_temp_dir("io_bad_version");
        let path = dir.join(KEYFILE_FILENAME);

        let mut data = mk_min_keyfile_data();
        data.version = KEYFILE_VERSION + 1;

        fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();

        let err = read_json(&path).unwrap_err();
        assert!(matches!(err, AppError::KeyfileFsUnsupportedVersion { .. }));
    }

    #[test]
    fn read_rejects_marker_mismatch() {
        let dir = mk_temp_dir("io_marker_mismatch");
        let path = dir.join(KEYFILE_FILENAME);

        let mut data = mk_min_keyfile_data();
        data.format = "not-the-format".to_string();

        fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();

        let err = read_json(&path).unwrap_err();
        assert!(matches!(err, AppError::KeyfileFsMarkerMismatch));
    }

    #[test]
    fn read_rejects_too_large_file() {
        let dir = mk_temp_dir("io_too_large");
        let path = dir.join(KEYFILE_FILENAME);

        // KEYFILE_MAX_BYTES is 1 MiB in the module under test.
        let too_big = (1 * 1024 * 1024) + 1;
        let payload = "x".repeat(too_big);
        fs::write(&path, payload).unwrap();

        let err = read_json(&path).unwrap_err();
        assert!(matches!(err, AppError::KeyfileFsTooLarge { .. }));
    }

    #[test]
    fn write_json_replaces_existing_file_atomically_from_callers_pov() {
        let dir = mk_temp_dir("io_replace");
        let path = dir.join(KEYFILE_FILENAME);

        let mut data1 = mk_min_keyfile_data();
        data1.salt = "BBBBBBBBBBBBBBBBBBBBBB==".to_string();
        write_json(&path, &data1).unwrap();

        let mut data2 = mk_min_keyfile_data();
        data2.salt = "CCCCCCCCCCCCCCCCCCCCCC==".to_string();
        write_json(&path, &data2).unwrap();

        let got = read_json(&path).unwrap();
        assert_eq!(got.salt, data2.salt);
    }

    #[test]
    fn write_json_cleans_up_tmp_file_on_rename_failure() {
        let dir = mk_temp_dir("io_tmp_cleanup");

        // Force rename failure by making the destination path be a directory.
        let dest_dir = dir.join("dest_is_dir");
        fs::create_dir_all(&dest_dir).unwrap();

        // Ensure no leftovers before.
        assert!(list_tmp_keyfile_files(&dir).is_empty());

        let data = mk_min_keyfile_data();
        let res = write_json(&dest_dir, &data);
        assert!(res.is_err());

        // Temp file should be best-effort cleaned up.
        let leftovers = list_tmp_keyfile_files(&dir);
        assert!(leftovers.is_empty());
    }

    #[test]
    fn backup_keyfile_moves_to_quarantine_prefix() {
        let dir = mk_temp_dir("io_backup_basic");
        let path = dir.join(KEYFILE_FILENAME);

        fs::write(&path, b"hello").unwrap();
        assert!(path.exists());

        let backup = backup_keyfile_with_quarantine_prefix(&path).unwrap();

        assert!(!path.exists());
        assert!(backup.exists());

        let fname = Path::new(KEYFILE_FILENAME)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        let name = backup.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(name, format!("quarantine.{fname}"));
    }

    #[test]
    fn backup_keyfile_uses_increment_suffix_on_collision() {
        let dir = mk_temp_dir("io_backup_collision");
        let path = dir.join(KEYFILE_FILENAME);

        let fname = Path::new(KEYFILE_FILENAME)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        // Pre-create the first candidate so it collides.
        let colliding = dir.join(format!("quarantine.{fname}"));
        fs::write(&colliding, b"already-here").unwrap();
        assert!(colliding.exists());

        fs::write(&path, b"hello").unwrap();
        let backup = backup_keyfile_with_quarantine_prefix(&path).unwrap();

        assert!(!path.exists());
        assert!(backup.exists());

        let name = backup.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(name, format!("quarantine.1.{fname}"));
    }

    #[test]
    fn backup_keyfile_errors_if_missing() {
        let dir = mk_temp_dir("io_backup_missing");
        let path = dir.join(KEYFILE_FILENAME);

        let err = backup_keyfile_with_quarantine_prefix(&path).unwrap_err();
        assert!(matches!(err, AppError::KeyfileMissingOrCorrupted));
    }
}
