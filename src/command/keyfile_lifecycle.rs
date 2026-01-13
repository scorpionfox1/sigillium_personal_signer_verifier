// src/command/keyfile_lifecycle.rs

use crate::command::keyfile_inspect::refresh_keyfile_state;
use crate::context::AppCtx;
use crate::error::{AppError, AppResult};
use crate::fs_hardening::enforce_keyfile_perms_best_effort;
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
