// src/main.rs

// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ui;

use directories::ProjectDirs;
use sigillium_personal_signer_verifier_lib::context::{AppCtx, APP_ID, APP_ORG, APP_QUALIFIER};
use sigillium_personal_signer_verifier_lib::fs_hardening;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

fn main() -> eframe::Result<()> {
    let app_data_dir: PathBuf = if let Ok(p) = env::var("SIGILLIUM_DATA_DIR") {
        PathBuf::from(p)
    } else if cfg!(debug_assertions) {
        // dev-only sandbox
        let home = env::var("HOME").expect("HOME not set");
        PathBuf::from(home).join(".local/share/sigillium-dev")
    } else {
        let proj = ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_ID)
            .expect("Could not determine app data dir");
        proj.data_dir().to_path_buf()
    };

    std::fs::create_dir_all(&app_data_dir).expect("Could not create app data dir");

    let state = sigillium_personal_signer_verifier_lib::init_state(&app_data_dir)
        .expect("failed to init app state");
    let state = Arc::new(state);

    let ctx = AppCtx::new(app_data_dir.clone());
    let ctx = Arc::new(ctx);

    fs_hardening::startup_hardening_best_effort(state.as_ref(), ctx.as_ref());

    eframe::run_native(
        "Sigillium Personal Signer / Verifier",
        eframe::NativeOptions::default(),
        Box::new(move |_cc| Ok(Box::new(ui::UiApp::new(state.clone(), ctx.clone())))),
    )
}
