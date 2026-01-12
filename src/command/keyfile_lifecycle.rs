// src/command/keyfile_lifecycle.rs

use crate::command::keyfile_inspect::refresh_keyfile_state;
use crate::context::AppCtx;
use crate::error::{AppError, AppResult};
use crate::fs_hardening::enforce_keyfile_perms_best_effort;
use crate::security_log::{record_best_effort_platform_failure, record_intentional_security_event};
use crate::types::{AppState, KeyfileState};
use crate::{command_state::*, keyfile};
use zeroize::Zeroizing;

pub fn create_keyfile(passphrase: &str, state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    let passphrase = Zeroizing::new(passphrase.to_owned());
    super::validate_passphrase(&passphrase).map_err(AppError::Msg)?;

    let ks = {
        let g = state
            .keyfile_state
            .lock()
            .map_err(|_| AppError::StateLockPoisoned)?;
        *g
    };

    match ks {
        KeyfileState::NotCorrupted => {
            return Err(AppError::KeyfileAlreadyExists);
        }
        KeyfileState::Corrupted => {
            quarantine_corrupted_keyfile_inner(state, ctx)?;

            record_intentional_security_event(
                state,
                "create_keyfile",
                "KeyfileQuarantined",
                "Corrupted keyfile quarantined",
            );
        }
        KeyfileState::Missing => {}
    }

    let result: AppResult<()> = (|| {
        keyfile::write_blank_keyfile(&ctx.keyfile_path)?;

        enforce_keyfile_perms_best_effort(
            state,
            &ctx.keyfile_path,
            &ctx.app_data_dir,
            "create_keyfile",
        );

        // NEW: stamp file MAC immediately so unlock_app doesn't reject a fresh keyfile.
        let mk = keyfile::read_master_key(&ctx.keyfile_path, passphrase.as_str())?;
        let mut data = keyfile::fs::read_json(&ctx.keyfile_path)?;
        keyfile::validate::set_file_mac_in_place(&mut data, &mk)?;
        keyfile::fs::write_json(&ctx.keyfile_path, &data)?;
        // END NEW

        lock_app_inner_if_unlocked(state, "create_keyfile").map_err(AppError::Msg)?;

        let _ = refresh_keyfile_state(state, ctx)?;
        Ok(())
    })();

    result
}

pub fn self_destruct_keyfile(state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    lock_app_inner_if_unlocked(state, "self_destruct").map_err(AppError::Msg)?;

    if !ctx.keyfile_path.exists() {
        return Err(AppError::KeyfileMissing);
    }

    // Rename-away first so the keyfile path disappears atomically.
    let parent = ctx
        .keyfile_path
        .parent()
        .ok_or_else(|| AppError::KeyfileFsWriteFailed("invalid keyfile path".to_string()))?;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let tombstone = parent.join(format!(".keyfile.deleted.{}.{}", std::process::id(), nonce));

    std::fs::rename(&ctx.keyfile_path, &tombstone)
        .map_err(|e| AppError::KeyfileFsWriteFailed(e.to_string()))?;

    let (res, warns) = keyfile::ops::lifecycle::self_destruct_best_effort(&tombstone, parent);

    for w in warns {
        record_best_effort_platform_failure(state, "self_destruct", w);
    }

    res.map_err(|e| AppError::KeyfileFsWriteFailed(e.to_string()))?;

    record_intentional_security_event(
        state,
        "self_destruct",
        "KeyfileSelfDestructed",
        "Keyfile securely deleted",
    );

    let _ = refresh_keyfile_state(state, ctx)?;
    Ok(())
}

fn quarantine_corrupted_keyfile_inner(state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    let ks = state
        .keyfile_state
        .lock()
        .map_err(|_| AppError::StateLockPoisoned)
        .map(|ks| *ks)?;

    if ks != KeyfileState::Corrupted {
        return Err(AppError::KeyfileCorrupt);
    }

    if ctx.keyfile_path.exists() {
        keyfile::backup_keyfile_with_corrupt_prefix(&ctx.keyfile_path)?;
    }

    let _ = refresh_keyfile_state(state, ctx)?;
    Ok(())
}

pub fn quarantine_keyfile_now(state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    keyfile::fs::backup_keyfile_with_corrupt_prefix(&ctx.keyfile_path)?;
    let _ = crate::command::keyfile_inspect::refresh_keyfile_state(state, ctx);
    lock_app_inner_if_unlocked(state, "keyfile integrity failure").map_err(AppError::Msg)?;
    Ok(())
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{context::AppCtx, types::KeyfileState};
    use std::fs;

    const PASSPHRASE_OK: &str = "correct horse battery staple"; // len >= 15

    fn set_keyfile_state(state: &AppState, ks: KeyfileState) {
        let mut g = state
            .keyfile_state
            .lock()
            .expect("keyfile_state lock poisoned in test");
        *g = ks;
    }

    fn get_keyfile_state(state: &AppState) -> KeyfileState {
        *state
            .keyfile_state
            .lock()
            .expect("keyfile_state lock poisoned in test")
    }

    fn dir_has_corrupt_backup(dir: &std::path::Path) -> bool {
        fs::read_dir(dir)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("corrupt."))
    }

    #[test]
    fn create_keyfile_from_missing_creates_and_refreshes_state() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");
        let ctx = AppCtx::new(td_keyfile.path().to_path_buf());

        set_keyfile_state(&state, KeyfileState::Missing);
        assert!(!ctx.keyfile_path.exists());

        create_keyfile(PASSPHRASE_OK, &state, &ctx).expect("create_keyfile");

        assert!(ctx.keyfile_path.exists());
        assert_eq!(get_keyfile_state(&state), KeyfileState::NotCorrupted);
    }

    #[test]
    fn create_keyfile_when_state_not_corrupted_returns_already_exists() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");

        // Create a valid keyfile fixture so the filesystem matches the state.
        let fx = crate::keyfile::ops::test_support::mk_fixture(PASSPHRASE_OK).expect("mk_fixture");
        let mut ctx = AppCtx::new(td_keyfile.path().to_path_buf());
        ctx.keyfile_path = fx.path.clone();

        set_keyfile_state(&state, KeyfileState::NotCorrupted);

        let e = create_keyfile(PASSPHRASE_OK, &state, &ctx).unwrap_err();
        assert!(matches!(e, AppError::KeyfileAlreadyExists));
    }

    #[test]
    fn create_keyfile_when_state_corrupted_quarantines_then_creates_new() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");
        let ctx = AppCtx::new(td_keyfile.path().to_path_buf());

        // Put a junk file at the keyfile path and mark state as Corrupted.
        fs::write(&ctx.keyfile_path, b"{}").expect("write junk keyfile");
        assert!(ctx.keyfile_path.exists());
        set_keyfile_state(&state, KeyfileState::Corrupted);

        create_keyfile(PASSPHRASE_OK, &state, &ctx).expect("create_keyfile from Corrupted");

        // Original should have been renamed to corrupt.* and a fresh keyfile created at canonical path.
        assert!(ctx.keyfile_path.exists());
        assert!(dir_has_corrupt_backup(&ctx.app_data_dir));

        // Fresh file should validate to NotCorrupted after refresh.
        assert_eq!(get_keyfile_state(&state), KeyfileState::NotCorrupted);
    }

    #[test]
    fn self_destruct_keyfile_missing_returns_error() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");
        let ctx = AppCtx::new(td_keyfile.path().to_path_buf());

        assert!(!ctx.keyfile_path.exists());

        let e = self_destruct_keyfile(&state, &ctx).unwrap_err();
        assert!(matches!(e, AppError::KeyfileMissing));
    }

    #[test]
    fn self_destruct_keyfile_removes_keyfile_and_refreshes_state() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");
        let ctx = AppCtx::new(td_keyfile.path().to_path_buf());

        set_keyfile_state(&state, KeyfileState::Missing);
        create_keyfile(PASSPHRASE_OK, &state, &ctx).expect("create_keyfile");

        assert!(ctx.keyfile_path.exists());
        assert_eq!(get_keyfile_state(&state), KeyfileState::NotCorrupted);

        self_destruct_keyfile(&state, &ctx).expect("self_destruct_keyfile");

        assert!(!ctx.keyfile_path.exists());
        assert_eq!(get_keyfile_state(&state), KeyfileState::Missing);

        // Best effort: most platforms should remove the tombstone too.
        // If it ever flakes on some environment, we can drop this assertion.
        let any_tombstone = fs::read_dir(&ctx.app_data_dir)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".keyfile.deleted.")
            });
        assert!(!any_tombstone);
    }

    #[test]
    fn avoid_quarantine_now_renames_keyfile_and_locks_app() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");
        let ctx = AppCtx::new(td_keyfile.path().to_path_buf());

        // A file must exist or backup_keyfile_with_corrupt_prefix should error.
        fs::write(&ctx.keyfile_path, b"junk").expect("write junk keyfile");
        assert!(ctx.keyfile_path.exists());

        quarantine_keyfile_now(&state, &ctx).expect("quarantine_keyfile_now");

        assert!(!ctx.keyfile_path.exists());
        assert!(dir_has_corrupt_backup(&ctx.app_data_dir));

        // refresh_keyfile_state is invoked (result ignored), but it should still update state.
        assert_eq!(get_keyfile_state(&state), KeyfileState::Missing);
    }
}
