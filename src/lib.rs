// src/lib.rs

pub mod command;
pub mod command_state;
pub mod context;
pub mod crypto;
pub mod error;
pub mod fs_hardening;
pub mod json_canon;
pub mod keyfile;
pub mod platform;
pub mod security_log;
pub mod types;

use crate::security_log::SecurityLog;
use crate::types::{AppState, KeyfileState, SessionState, SignVerifyMode};
use std::path::Path;
use std::sync::Mutex;

pub fn init_state(app_data_dir: &Path) -> Result<AppState, String> {
    std::fs::create_dir_all(app_data_dir)
        .map_err(|e| format!("Failed to create app data dir: {e}"))?;

    let security_log = SecurityLog::init(app_data_dir)?;

    //let keyfile_path = app_data_dir.join(KEYFILE_NAME);
    let keyfile_state = KeyfileState::NotCorrupted; // starting state, can be overwrriten immediately by ui check

    Ok(AppState {
        session: Mutex::new(SessionState {
            unlocked: false,
            active_key_id: None,
            active_associated_key_id: None,
        }),
        secrets: Mutex::new(None),

        keys: Mutex::new(Vec::new()),
        sign_verify_mode: Mutex::new(SignVerifyMode::Text),

        // computed at startup (detection only; no side-effects)
        keyfile_state: Mutex::new(keyfile_state),

        security_log: Mutex::new(security_log),
    })
}

impl AppState {
    pub fn new_for_tests(app_data_dir: &std::path::Path) -> Result<Self, String> {
        crate::init_state(app_data_dir)
    }
}
