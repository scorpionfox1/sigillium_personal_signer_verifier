// src/command/keyfile_inspect.rs

use crate::{
    context::AppCtx,
    error::{AppError, AppResult},
    types::AppState,
};

use crate::keyfile::ops::inspect::inspect_keyfile;

pub fn inspect_selected_keyfile(state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    match inspect_keyfile(&keyfile_path) {
        Ok(()) => Ok(()),
        Err(_e) => {
            let dir_name = ctx
                .selected_keyfile_dir()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| "<unknown>".to_string());

            let _ = crate::command::keyfile_lifecycle::quarantine_keyfile_now(state, ctx);

            Err(AppError::KeyfileQuarantined { dir_name })
        }
    }
}
