// src/fs_hardening.rs

use std::path::Path;

use crate::context::AppCtx;
use crate::platform;
use crate::security_log::{
    record_best_effort_platform_failure, record_best_effort_platform_failures,
};
use crate::types::AppState;

pub fn startup_hardening_best_effort(state: &AppState, ctx: &AppCtx) {
    record_best_effort_platform_failures(state, "startup", platform::harden_process_best_effort());

    if let Some(keyfile_path) = ctx.current_keyfile_path() {
        enforce_keyfile_perms_best_effort(state, &keyfile_path, &ctx.app_data_dir, "startup");
    }
}

pub fn enforce_keyfile_perms_best_effort(
    state: &AppState,
    keyfile_path: &Path,
    app_data_dir: &Path,
    context: &str,
) {
    // Always restrict the app data directory perms; the directory matters even when no keyfile exists.
    if let Some(fail) = platform::restrict_dir_perms_best_effort(app_data_dir) {
        record_best_effort_platform_failure(state, context, fail);
    }

    // Only restrict the keyfile if it exists (so callers can safely call this pre-op).
    if keyfile_path.exists() {
        if let Some(fail) = platform::restrict_file_perms_best_effort(keyfile_path) {
            record_best_effort_platform_failure(state, context, fail);
        }
    }
}
