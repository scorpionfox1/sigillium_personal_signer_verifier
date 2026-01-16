// src/command/session.rs

use crate::command::keyfile_inspect::refresh_keyfile_state;
use crate::command_state::*;
use crate::context::AppCtx;
use crate::error::{AppError, AppResult};
use crate::keyfile;
use crate::keyfile::{lock_private_key32_best_effort, unlock_private_key32_best_effort};
use crate::security_log::record_best_effort_platform_failures;
use crate::types::{AppState, KeyId, KeyfileState, SecretsState};
use std::thread;
use std::time::Duration;
use zeroize::Zeroizing;

pub fn get_status(state: &AppState) -> AppResult<bool> {
    let session = lock_session(state).map_err(|_| AppError::InternalStateLockFailed)?;
    Ok(session.unlocked)
}

pub fn select_active_key(
    key_id: KeyId,
    state: &AppState,
    ctx: &AppCtx,
) -> (crate::types::KeyfileState, AppResult<()>) {
    let keyfile_path = match ctx.current_keyfile_path() {
        Some(p) => p,
        None => {
            let ks =
                refresh_keyfile_state(state, ctx).unwrap_or(crate::types::KeyfileState::Corrupted);
            return (ks, Err(AppError::Msg("No keyfile selected".into())));
        }
    };

    let key_res = with_master_key(state, |mk| {
        keyfile::decrypt_key_material(&keyfile_path, &*mk, key_id)
    });

    let (privk, associated_s) = match key_res {
        Ok(k) => k,
        Err(e) => match e {
            AppError::KeyfileMacInvalid
            | AppError::KeyfileMacMissing
            | AppError::KeyfileStructCorrupted
            | AppError::KeyfileCorrupt
            | AppError::KeyfileMissingOrCorrupted => {
                let dir_name = ctx
                    .selected_keyfile_dir()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                    .unwrap_or_else(|| "<unknown>".to_string());

                let _ = crate::command::keyfile_lifecycle::quarantine_keyfile_now(state, ctx);
                let _ = refresh_keyfile_state(state, ctx);

                return (
                    crate::types::KeyfileState::Missing,
                    Err(AppError::KeyfileQuarantined { dir_name }),
                );
            }
            _ => {
                let ks = refresh_keyfile_state(state, ctx)
                    .unwrap_or(crate::types::KeyfileState::Missing);
                return (ks, Err(e));
            }
        },
    };

    let res: AppResult<()> = (|| {
        let fail = {
            let mut secrets_guard =
                lock_secrets(state).map_err(|_| AppError::InternalStateLockFailed)?;
            let secrets = secrets_guard.as_mut().ok_or(AppError::AppLocked)?;

            secrets.active_private = Some(Zeroizing::new(privk));

            secrets
                .active_private
                .as_mut()
                .and_then(|k| lock_private_key32_best_effort(&mut **k))
        };

        {
            let mut session = lock_session(state).map_err(|_| AppError::InternalStateLockFailed)?;
            if !session.unlocked {
                return Err(AppError::AppLocked);
            }
            session.active_key_id = Some(key_id);
            session.active_associated_key_id = Some(associated_s);
        }

        record_best_effort_platform_failures(state, "select_active_key", fail.into_iter());
        Ok(())
    })();

    let ks = refresh_keyfile_state(state, ctx).unwrap_or(crate::types::KeyfileState::Missing);
    (ks, res)
}

pub fn clear_active_key(state: &AppState) -> AppResult<()> {
    // secrets: unlock + clear active private
    let fail = {
        let mut secrets_guard =
            lock_secrets(state).map_err(|_| AppError::InternalStateLockFailed)?;
        let secrets = secrets_guard.as_mut().ok_or(AppError::AppLocked)?;

        let fail = secrets
            .active_private
            .as_mut()
            .and_then(|k| unlock_private_key32_best_effort(&mut **k));

        secrets.active_private = None;
        fail
    };

    // session: clear active id
    {
        let mut session = lock_session(state).map_err(|_| AppError::InternalStateLockFailed)?;
        session.active_key_id = None;
        session.active_associated_key_id = None;
    }

    record_best_effort_platform_failures(state, "clear_active_key", fail.into_iter());
    Ok(())
}

pub fn unlock_app(passphrase: &str, state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    lock_app_inner_if_unlocked(state, "unlock_cleanup").map_err(AppError::Msg)?;

    let passphrase = Zeroizing::new(passphrase.to_owned());
    super::validate_passphrase_for_unlock(&passphrase).map_err(AppError::Msg)?;

    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    let master_key = match keyfile::read_master_key(&keyfile_path, &passphrase) {
        Ok(k) => k,
        Err(_) => {
            let dir_name = ctx
                .selected_keyfile_dir()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| "<unknown>".to_string());

            let _ = crate::command::keyfile_lifecycle::quarantine_keyfile_now(state, ctx);
            let _ = refresh_keyfile_state(state, ctx);

            thread::sleep(Duration::from_millis(250));
            return Err(AppError::KeyfileQuarantined { dir_name });
        }
    };

    // Validate integrity. Any failure is treated as tamper/corruption.
    if let Err(_e) = keyfile::validate_keyfile_structure_on_disk(&keyfile_path)
        .and_then(|_| keyfile::verify_keyfile_mac_on_disk(&keyfile_path, &master_key))
    {
        lock_app_inner_if_unlocked(state, "unlock_integrity_failure").map_err(AppError::Msg)?;

        let dir_name = ctx
            .selected_keyfile_dir()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "<unknown>".to_string());

        let _ = crate::command::keyfile_lifecycle::quarantine_keyfile_now(state, ctx);
        let _ = refresh_keyfile_state(state, ctx);

        thread::sleep(Duration::from_millis(250));
        return Err(AppError::KeyfileQuarantined { dir_name });
    }

    // secrets
    {
        let mut secrets_guard =
            lock_secrets(state).map_err(|_| AppError::InternalStateLockFailed)?;
        *secrets_guard = Some(SecretsState {
            master_key: Zeroizing::new(master_key),
            active_private: None,
        });
    }

    // session
    {
        let mut session = lock_session(state).map_err(|_| AppError::InternalStateLockFailed)?;
        session.unlocked = true;
        session.active_key_id = None;
        session.active_associated_key_id = None;
    }

    lock_master_key_best_effort(state, "unlock_app");
    super::refresh_key_meta_cache(state, ctx)?;
    Ok(())
}

pub fn secure_prepare_for_quit(state: &AppState) -> AppResult<()> {
    lock_app_inner_if_unlocked(state, "lock_and_quit").map_err(AppError::Msg)
}

pub fn select_keyfile_dir(
    state: &AppState,
    ctx: &AppCtx,
    dir_name: &str,
) -> AppResult<KeyfileState> {
    let dir = ctx.keyfiles_root().join(dir_name);
    ctx.set_selected_keyfile_dir(Some(dir));

    // Force locked + clear secrets
    lock_app_inner_if_unlocked(state, "select_keyfile").map_err(AppError::Msg)?;

    // Inspect keyfile.json state
    let ks = match ctx.current_keyfile_path() {
        Some(p) => crate::keyfile::check_keyfile_state(&p).unwrap_or(KeyfileState::Corrupted),
        None => KeyfileState::Missing,
    };

    if let Ok(mut g) = state.keyfile_state.lock() {
        *g = ks;
    }

    Ok(ks)
}
