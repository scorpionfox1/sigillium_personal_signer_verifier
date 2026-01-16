// src/context.rs

use std::path::PathBuf;
use std::sync::Mutex;

pub const APP_QUALIFIER: &str = "org";
pub const APP_ORG: &str = "sigillium";
pub const APP_ID: &str = "sigillium-personal-signer-verifier";

pub const KEYFILE_NAME: &str = "sigillium.keyfile.json";
pub const KEYFILES_DIR: &str = "keyfiles";

#[derive(Debug)]
pub struct AppCtx {
    pub app_data_dir: PathBuf,
    selected_keyfile_dir: Mutex<Option<PathBuf>>,
    pub debug_ui: bool,
}

impl AppCtx {
    pub fn new(app_data_dir: PathBuf) -> Self {
        let debug_ui = std::env::var("SIGILLIUM_DEBUG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            app_data_dir,
            selected_keyfile_dir: Mutex::new(None),
            debug_ui,
        }
    }

    /// <app_data>/keyfiles
    pub fn keyfiles_root(&self) -> PathBuf {
        self.app_data_dir.join(KEYFILES_DIR)
    }

    pub fn is_keyfile_selected(&self) -> bool {
        self.selected_keyfile_dir
            .lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    pub fn set_selected_keyfile_dir(&self, dir: Option<PathBuf>) {
        if let Ok(mut g) = self.selected_keyfile_dir.lock() {
            *g = dir;
        }
    }

    pub fn selected_keyfile_dir(&self) -> Option<PathBuf> {
        self.selected_keyfile_dir
            .lock()
            .ok()
            .and_then(|g| g.clone())
    }

    /// <selected>/sigillium.keyfile.json
    pub fn current_keyfile_path(&self) -> Option<PathBuf> {
        self.selected_keyfile_dir()
            .map(|dir| dir.join(KEYFILE_NAME))
    }

    #[cfg(test)]
    pub fn set_selected_keyfile_dir_for_tests(&mut self, dir: PathBuf) {
        self.selected_keyfile_dir = Some(dir).into();
    }
}
