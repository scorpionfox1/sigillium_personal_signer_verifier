// src/command/keyfile_lifecycle.rs

use crate::command::keyfile_inspect::refresh_keyfile_state;
use crate::context::AppCtx;
use crate::error::{AppError, AppResult};
use crate::fs_hardening::enforce_keyfile_perms_best_effort;
use crate::keyfile::fs::backup_keyfile_with_quarantine_prefix;
use crate::types::AppState;
use crate::{command_state::*, keyfile};
use zeroize::Zeroizing;

pub fn create_keyfile(passphrase: &str, state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    let passphrase = Zeroizing::new(passphrase.to_owned());
    super::validate_passphrase(&passphrase).map_err(AppError::Msg)?;

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

pub fn quarantine_keyfile_now(state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    backup_keyfile_with_quarantine_prefix(&keyfile_path)?;
    let _ = refresh_keyfile_state(state, ctx);
    lock_app_inner_if_unlocked(state, "keyfile integrity failure").map_err(AppError::Msg)?;
    Ok(())
}

// ======================================================
// Unit Tests
// ======================================================
