// src/context.rs

use std::path::PathBuf;

pub const APP_QUALIFIER: &str = "org";
pub const APP_ORG: &str = "sigillium";
pub const APP_ID: &str = "sigillium-personal-signer-verifier";

pub const KEYFILE_NAME: &str = "sigillium.keyfile.json";

#[derive(Clone, Debug)]
pub struct AppCtx {
    pub app_data_dir: PathBuf,
    pub keyfile_path: PathBuf,
    pub debug_ui: bool,
}

impl AppCtx {
    pub fn new(app_data_dir: PathBuf) -> Self {
        let keyfile_path = app_data_dir.join(KEYFILE_NAME);
        let debug_ui = std::env::var("SIGILLIUM_DEBUG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self {
            app_data_dir,
            keyfile_path,
            debug_ui,
        }
    }
}
