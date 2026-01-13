// src/context.rs

use std::path::PathBuf;

pub const APP_QUALIFIER: &str = "org";
pub const APP_ORG: &str = "sigillium";
pub const APP_ID: &str = "sigillium-personal-signer-verifier";

pub const KEYFILE_NAME: &str = "sigillium.keyfile.json";
pub const KEYFILES_DIR: &str = "keyfiles";

#[derive(Clone, Debug)]
pub struct AppCtx {
    pub app_data_dir: PathBuf,
    pub selected_keyfile_dir: Option<PathBuf>,
    pub debug_ui: bool,
}

impl AppCtx {
    pub fn new(app_data_dir: PathBuf) -> Self {
        let debug_ui = std::env::var("SIGILLIUM_DEBUG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            app_data_dir,
            selected_keyfile_dir: None,
            debug_ui,
        }
    }

    /// <app_data>/keyfiles
    pub fn keyfiles_root(&self) -> PathBuf {
        self.app_data_dir.join(KEYFILES_DIR)
    }

    /// <selected>/sigillium.keyfile.json
    pub fn current_keyfile_path(&self) -> Option<PathBuf> {
        self.selected_keyfile_dir
            .as_ref()
            .map(|dir| dir.join(KEYFILE_NAME))
    }
}
