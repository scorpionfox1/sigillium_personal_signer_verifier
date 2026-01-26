// src/command/mod.rs

use crate::context::AppCtx;
use crate::{keyfile, types::AppState};

pub mod document_wizard;
pub mod json_ops;
pub mod keyfile_lifecycle;
pub mod keyfile_mutation;
pub mod session;
pub mod sign_verify;

// --- Public façade (same function names as before) ---

use crate::error::{AppError, AppResult};
pub use json_ops::validate_json_2020_12;
pub use keyfile_lifecycle::create_keyfile;
pub use keyfile_mutation::{change_passphrase, install_key, uninstall_active_key};
pub use session::{clear_active_key, get_status, select_active_key, unlock_app};
pub use sign_verify::{sign_payload, verify_payload};

// --- Shared helpers (kept private to the command module) ---

pub(super) fn validate_passphrase(pass: &str) -> Result<(), String> {
    if pass.len() < 15 {
        Err("Passphrase too short".to_string())
    } else {
        Ok(())
    }
}

pub(super) fn refresh_key_meta_cache(state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    let metas = crate::command_state::with_master_key(state, |k| {
        keyfile::list_key_meta(&keyfile_path, &*k)
    })?;

    let mut keys = state
        .keys
        .lock()
        .map_err(|_| AppError::InternalStateLockFailed)?;

    *keys = metas;

    Ok(())
}

// Unlock-time sanity checks (NOT strength policy).
pub(super) fn validate_passphrase_for_unlock(pass: &str) -> Result<(), String> {
    if pass.trim().is_empty() {
        return Err("Passphrase required".to_string());
    }

    // Prevent ridiculous inputs / DoS-y KDF cost.
    const MAX_LEN: usize = 4096;
    if pass.len() > MAX_LEN {
        return Err("Passphrase too long".to_string());
    }

    Ok(())
}
