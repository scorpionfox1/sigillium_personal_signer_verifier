// src/ui/widgets.rs

use eframe::egui;
use sigillum_personal_signer_verifier_lib::{
    command,
    command_state::lock_session,
    context::AppCtx,
    error::AppError,
    types::{AppState, KeyId, KeyMeta},
};

pub fn copy_icon_button(ui: &mut egui::Ui, enabled: bool, hover: &str) -> bool {
    ui.add_enabled(enabled, egui::Button::new("⧉"))
        .on_hover_text(hover)
        .clicked()
}

/// Standard Active Key selector used across panels.
/// - Shows None + installed keys.
/// - Selecting None clears active key.
/// - Selecting a key sets it active.
/// - Returns Err(String) if command layer rejects the change.
pub fn active_key_selector(
    ui: &mut egui::Ui,
    state: &AppState,
    ctx: &AppCtx,
    route: &mut super::Route,
    id_salt: &'static str,
    metas: &[KeyMeta],
) -> Result<Option<KeyId>, AppError> {
    let current_active_id: Option<KeyId> = lock_session(state).ok().and_then(|g| g.active_key_id);

    let mut choice: Option<KeyId> = current_active_id;

    let selected_text = match choice.and_then(|id| metas.iter().find(|k| k.id == id)) {
        Some(k) => format!("{} ({})", k.label, k.domain),
        None => "None".to_string(),
    };

    egui::ComboBox::from_id_salt(id_salt)
        .selected_text(selected_text)
        .show_ui(ui, |ui| {
            ui.selectable_value(&mut choice, None, "None");
            ui.separator();
            for k in metas.iter() {
                ui.selectable_value(
                    &mut choice,
                    Some(k.id),
                    format!("{} ({})", k.label, k.domain),
                );
            }
        });

    if choice != current_active_id {
        match choice {
            Some(id) => {
                let (ks, res) = command::select_active_key(id, state, ctx);

                // persist keyfile state
                if let Ok(mut g) = state.keyfile_state.lock() {
                    *g = ks;
                }

                // if missing/corrupted, clear active key + route to CreateKeyfile
                if ks != sigillum_personal_signer_verifier_lib::types::KeyfileState::NotCorrupted {
                    let _ = command::clear_active_key(state);
                    *route = super::Route::CreateKeyfile;
                }

                res.map(|_| Some(id)).map_err(|e| e)
            }
            None => command::clear_active_key(state)
                .map(|_| None)
                .map_err(|e| e),
        }
    } else {
        Ok(choice)
    }
}
