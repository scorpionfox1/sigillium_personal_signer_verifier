// src/lib.rs

pub mod command;
pub mod command_state;
pub mod context;
pub mod crypto;
pub mod fs_hardening;
pub mod json_canon;
pub mod keyfile;
pub mod keyfile_store;
pub mod notices;
pub mod platform;
pub mod security_log;
pub mod template;
pub mod types;

use crate::security_log::SecurityLog;
use crate::types::{AppState, SessionState, SignOutputMode, SignVerifyMode};
use std::path::Path;
use std::sync::Mutex;

pub fn init_state(app_data_dir: &Path) -> Result<AppState, String> {
    std::fs::create_dir_all(app_data_dir)
        .map_err(|e| format!("Failed to create app data dir: {e}"))?;

    let security_log = SecurityLog::init(app_data_dir)?;

    Ok(AppState {
        session: Mutex::new(SessionState {
            unlocked: false,
            active_key_id: None,
            active_associated_key_id: None,
        }),
        secrets: Mutex::new(None),

        keys: Mutex::new(Vec::new()),
        sign_verify_mode: Mutex::new(SignVerifyMode::Text),
        sign_output_mode: Mutex::new(SignOutputMode::Signature),
        sign_resolve_tag_mode: Mutex::new(true),

        security_log: Mutex::new(security_log),
    })
}

impl AppState {
    pub fn new_for_tests(app_data_dir: &std::path::Path) -> Result<Self, String> {
        crate::init_state(app_data_dir)
    }
}
