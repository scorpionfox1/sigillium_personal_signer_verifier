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

    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    let result: AppResult<()> = (|| {
        keyfile::write_blank_keyfile(&keyfile_path)?;

        enforce_keyfile_perms_best_effort(
            state,
            &keyfile_path,
            &ctx.app_data_dir,
            "create_keyfile",
        );

        // NEW: stamp file MAC immediately so unlock_app doesn't reject a fresh keyfile.
        let mk = keyfile::read_master_key(&keyfile_path, passphrase.as_str())?;
        let mut data = keyfile::fs::read_json(&keyfile_path)?;
        keyfile::validate::set_file_mac_in_place(&mut data, &mk)?;
        keyfile::fs::write_json(&keyfile_path, &data)?;
        // END NEW

        lock_app_inner_if_unlocked(state, "create_keyfile").map_err(AppError::Msg)?;

        let _ = refresh_keyfile_state(state, ctx)?;
        Ok(())
    })();

    result
}

pub fn self_destruct_keyfile(state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    lock_app_inner_if_unlocked(state, "self_destruct").map_err(AppError::Msg)?;

    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    if !keyfile_path.exists() {
        return Err(AppError::KeyfileMissing);
    }

    // Rename-away first so the keyfile path disappears atomically.
    let parent = keyfile_path
        .parent()
        .ok_or_else(|| AppError::KeyfileFsWriteFailed("invalid keyfile path".to_string()))?;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let tombstone = parent.join(format!(".keyfile.deleted.{}.{}", std::process::id(), nonce));

    std::fs::rename(&keyfile_path, &tombstone)
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

    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    if keyfile_path.exists() {
        keyfile::backup_keyfile_with_corrupt_prefix(&keyfile_path)?;
    }

    let _ = refresh_keyfile_state(state, ctx)?;
    Ok(())
}

pub fn quarantine_keyfile_now(state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    keyfile::fs::backup_keyfile_with_corrupt_prefix(&keyfile_path)?;
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
    const FIXED_KEYFILE_NAME: &str = "sigillium.keyfile.json";

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

    fn mk_ctx_with_empty_dir(root: &std::path::Path, name: &str) -> (AppCtx, std::path::PathBuf) {
        let kdir = root.join(name);
        fs::create_dir_all(&kdir).expect("mkdir keyfile dir");

        let mut ctx = AppCtx::new(root.to_path_buf());
        ctx.selected_keyfile_dir = Some(kdir.clone());

        (ctx, kdir)
    }

    fn keyfile_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join(FIXED_KEYFILE_NAME)
    }

    #[test]
    fn create_keyfile_from_missing_creates_and_refreshes_state() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");
        let (ctx, kdir) = mk_ctx_with_empty_dir(td_keyfile.path(), "k1");

        set_keyfile_state(&state, KeyfileState::Missing);
        assert!(!keyfile_path(&kdir).exists());

        create_keyfile(PASSPHRASE_OK, &state, &ctx).expect("create_keyfile");

        assert!(keyfile_path(&kdir).exists());
        assert_eq!(get_keyfile_state(&state), KeyfileState::NotCorrupted);
    }

    #[test]
    fn create_keyfile_when_state_not_corrupted_returns_already_exists() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");

        let fx = crate::keyfile::ops::test_support::mk_fixture(PASSPHRASE_OK).expect("mk_fixture");
        let (ctx, kdir) = mk_ctx_with_empty_dir(td_keyfile.path(), "k1");
        fs::copy(&fx.path, keyfile_path(&kdir)).expect("copy fixture");

        set_keyfile_state(&state, KeyfileState::NotCorrupted);

        let e = create_keyfile(PASSPHRASE_OK, &state, &ctx).unwrap_err();
        assert!(matches!(e, AppError::KeyfileAlreadyExists));
    }

    #[test]
    fn create_keyfile_when_state_corrupted_quarantines_then_creates_new() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");
        let (ctx, kdir) = mk_ctx_with_empty_dir(td_keyfile.path(), "k1");

        fs::write(keyfile_path(&kdir), b"{}").expect("write junk keyfile");
        assert!(keyfile_path(&kdir).exists());
        set_keyfile_state(&state, KeyfileState::Corrupted);

        create_keyfile(PASSPHRASE_OK, &state, &ctx).expect("create_keyfile from Corrupted");

        assert!(keyfile_path(&kdir).exists());
        assert!(dir_has_corrupt_backup(td_keyfile.path()));
        assert_eq!(get_keyfile_state(&state), KeyfileState::NotCorrupted);
    }

    #[test]
    fn self_destruct_keyfile_missing_returns_error() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");
        let (ctx, kdir) = mk_ctx_with_empty_dir(td_keyfile.path(), "k1");

        assert!(!keyfile_path(&kdir).exists());

        let e = self_destruct_keyfile(&state, &ctx).unwrap_err();
        assert!(matches!(e, AppError::KeyfileMissing));
    }

    #[test]
    fn self_destruct_keyfile_removes_keyfile_and_refreshes_state() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");
        let (ctx, kdir) = mk_ctx_with_empty_dir(td_keyfile.path(), "k1");

        set_keyfile_state(&state, KeyfileState::Missing);
        create_keyfile(PASSPHRASE_OK, &state, &ctx).expect("create_keyfile");

        assert!(keyfile_path(&kdir).exists());
        assert_eq!(get_keyfile_state(&state), KeyfileState::NotCorrupted);

        self_destruct_keyfile(&state, &ctx).expect("self_destruct_keyfile");

        assert!(!keyfile_path(&kdir).exists());
        assert_eq!(get_keyfile_state(&state), KeyfileState::Missing);

        let any_tombstone = fs::read_dir(td_keyfile.path())
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
        let (ctx, kdir) = mk_ctx_with_empty_dir(td_keyfile.path(), "k1");

        fs::write(keyfile_path(&kdir), b"junk").expect("write junk keyfile");
        assert!(keyfile_path(&kdir).exists());

        quarantine_keyfile_now(&state, &ctx).expect("quarantine_keyfile_now");

        assert!(!keyfile_path(&kdir).exists());
        assert!(dir_has_corrupt_backup(td_keyfile.path()));
        assert_eq!(get_keyfile_state(&state), KeyfileState::Missing);
    }
}
