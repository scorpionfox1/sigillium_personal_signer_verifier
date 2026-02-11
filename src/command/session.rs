// src/command/session.rs

use crate::command_state::*;
use crate::context::AppCtx;
use crate::keyfile;
use crate::keyfile::inspect::inspect_keyfile;
use crate::keyfile::{lock_private_key32_best_effort, unlock_private_key32_best_effort};
use crate::notices::{AppNotice, AppResult};
use crate::security_log::record_best_effort_platform_failures;
use crate::types::{AppState, KeyId, SecretsState};
use zeroize::Zeroizing;

pub fn get_status(state: &AppState) -> AppResult<bool> {
    let session = lock_session(state).map_err(|_| AppNotice::InternalStateLockFailed)?;
    Ok(session.unlocked)
}

pub fn select_active_key(key_id: KeyId, state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppNotice::Msg("No keyfile selected".into()))?;

    let key_res = with_master_key(state, |mk| {
        keyfile::decrypt_key_material(&keyfile_path, &*mk, key_id)
    });

    let (privk, associated_s) = match key_res {
        Ok(k) => k,
        Err(e) => match e {
            AppNotice::KeyfileMacInvalid
            | AppNotice::KeyfileMacMissing
            | AppNotice::KeyfileStructCorrupted
            | AppNotice::KeyfileCorrupt
            | AppNotice::KeyfileMissingOrCorrupted => {
                let dir_name = ctx
                    .selected_keyfile_dir()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                    .unwrap_or_else(|| "<unknown>".to_string());

                let _ = crate::command::keyfile_lifecycle::quarantine_keyfile_now(state, ctx);

                return Err(AppNotice::KeyfileQuarantined { dir_name });
            }
            _ => return Err(e),
        },
    };

    (|| {
        let fail = {
            let mut secrets_guard =
                lock_secrets(state).map_err(|_| AppNotice::InternalStateLockFailed)?;
            let secrets = secrets_guard.as_mut().ok_or(AppNotice::AppLocked)?;

            secrets.active_private = Some(Zeroizing::new(privk));

            secrets
                .active_private
                .as_mut()
                .and_then(|k| lock_private_key32_best_effort(&mut **k))
        };

        {
            let mut session =
                lock_session(state).map_err(|_| AppNotice::InternalStateLockFailed)?;
            if !session.unlocked {
                return Err(AppNotice::AppLocked);
            }
            session.active_key_id = Some(key_id);
            session.active_associated_key_id = Some(associated_s);
        }

        record_best_effort_platform_failures(state, "select_active_key", fail.into_iter());
        Ok(())
    })()
}

pub fn clear_active_key(state: &AppState) -> AppResult<()> {
    // secrets: unlock + clear active private
    let fail = {
        let mut secrets_guard =
            lock_secrets(state).map_err(|_| AppNotice::InternalStateLockFailed)?;
        let secrets = secrets_guard.as_mut().ok_or(AppNotice::AppLocked)?;

        let fail = secrets
            .active_private
            .as_mut()
            .and_then(|k| unlock_private_key32_best_effort(&mut **k));

        secrets.active_private = None;
        fail
    };

    // session: clear active id
    {
        let mut session = lock_session(state).map_err(|_| AppNotice::InternalStateLockFailed)?;
        session.active_key_id = None;
        session.active_associated_key_id = None;
    }

    record_best_effort_platform_failures(state, "clear_active_key", fail.into_iter());
    Ok(())
}

pub fn unlock_app(passphrase: &str, state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    use std::thread;
    use std::time::{Duration, Instant};

    const MIN_UNLOCK_TIME: Duration = Duration::from_millis(250);
    let start = Instant::now();

    let res: AppResult<()> = (|| {
        lock_app_inner_if_unlocked(state, "unlock_cleanup").map_err(AppNotice::Msg)?;

        let passphrase = Zeroizing::new(passphrase.to_owned());
        super::validate_passphrase_for_unlock(&passphrase)?;

        let keyfile_path = ctx
            .current_keyfile_path()
            .ok_or_else(|| AppNotice::Msg("No keyfile selected".into()))?;

        let master_key = match keyfile::read_master_key(&keyfile_path, &passphrase) {
            Ok(k) => k,
            Err(_) => {
                let dir_name = ctx
                    .selected_keyfile_dir()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                    .unwrap_or_else(|| "<unknown>".to_string());

                let _ = crate::command::keyfile_lifecycle::quarantine_keyfile_now(state, ctx);
                return Err(AppNotice::KeyfileQuarantined { dir_name });
            }
        };

        if let Err(_e) = keyfile::validate_keyfile_structure_on_disk(&keyfile_path) {
            lock_app_inner_if_unlocked(state, "unlock_integrity_failure")
                .map_err(AppNotice::Msg)?;

            let dir_name = ctx
                .selected_keyfile_dir()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| "<unknown>".to_string());

            let _ = crate::command::keyfile_lifecycle::quarantine_keyfile_now(state, ctx);
            return Err(AppNotice::KeyfileQuarantined { dir_name });
        }

        if let Err(_e) = keyfile::verify_keyfile_mac_on_disk(&keyfile_path, &master_key) {
            return Err(AppNotice::KeyfilePassphraseBad);
        }

        {
            let mut secrets_guard =
                lock_secrets(state).map_err(|_| AppNotice::InternalStateLockFailed)?;
            *secrets_guard = Some(SecretsState {
                master_key: Zeroizing::new(master_key),
                active_private: None,
            });
        }

        {
            let mut session =
                lock_session(state).map_err(|_| AppNotice::InternalStateLockFailed)?;
            session.unlocked = true;
            session.active_key_id = None;
            session.active_associated_key_id = None;
        }

        lock_master_key_best_effort(state, "unlock_app");
        super::refresh_key_meta_cache(state, ctx)?;
        Ok(())
    })();

    // enforce minimum time for *all* outcomes
    let elapsed = start.elapsed();
    if elapsed < MIN_UNLOCK_TIME {
        thread::sleep(MIN_UNLOCK_TIME - elapsed);
    }

    res
}

pub fn secure_prepare_for_quit(state: &AppState) -> AppResult<()> {
    lock_app_inner_if_unlocked(state, "lock_and_quit").map_err(AppNotice::Msg)
}

pub fn select_keyfile_dir(state: &AppState, ctx: &AppCtx, dir_name: &str) -> AppResult<()> {
    let dir = ctx.keyfiles_root().join(dir_name);
    ctx.set_selected_keyfile_dir(Some(dir));

    // Force locked + clear secrets
    lock_app_inner_if_unlocked(state, "select_keyfile").map_err(AppNotice::Msg)?;

    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppNotice::Msg("No keyfile selected".into()))?;

    if let Err(_e) = inspect_keyfile(&keyfile_path) {
        let dir_name = dir_name.to_string();
        let _ = crate::command::keyfile_lifecycle::quarantine_keyfile_now(state, ctx);
        return Err(AppNotice::KeyfileQuarantined { dir_name });
    }

    Ok(())
}

// ======================================================
// Unit Tests
// ======================================================
